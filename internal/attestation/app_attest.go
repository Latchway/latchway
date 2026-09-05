package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

const (
	appAttestProvider                = "app_attest"
	appAttestEvidenceDomain          = "latchway/app-attest-evidence/v1"
	maxAppAttestAttestationBytes     = 46 << 10
	maxAppAttestAssertionBytes       = 8 << 10
	defaultAppAttestResultLifetime   = 10 * time.Minute
	maximumAppAttestResultLifetime   = 30 * 24 * time.Hour
	maximumAppAttestBundleVersions   = 64
	maximumAppAttestBundleVersionLen = 128
)

var (
	// ErrAppAttestKeyStore is returned without the underlying storage error so
	// provider evidence, database details, and key material cannot escape into
	// a client-facing problem or log line.
	ErrAppAttestKeyStore = errors.New("app attest key store is unavailable")

	appAttestAppIDPrefixPattern   = regexp.MustCompile(`^[A-Z0-9]{1,64}$`)
	appAttestBundleIDPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
	appAttestBundleVersionPattern = regexp.MustCompile(
		`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?$`,
	)
)

// AppAttestEnvironment selects the Apple trust environment. Development and
// production keys are intentionally not interchangeable.
type AppAttestEnvironment string

const (
	AppAttestDevelopment AppAttestEnvironment = "development"
	AppAttestProduction  AppAttestEnvironment = "production"
)

// AppAttestStoredKey is the minimum durable state needed to authenticate an
// assertion and reject counter replay. ExtensionsPresent distinguishes iOS 27
// metadata from valid legacy authenticator data; when false, category and
// bundle version must be zero values. Store implementations must deep-copy
// PublicKeyX963 at their boundary. Formatting is deliberately redacted.
type AppAttestStoredKey struct {
	PublicKeyX963          []byte
	AppIDHash              [sha256.Size]byte
	AttestationEnvironment AppAttestEnvironment
	ApplicationID          string
	EnvironmentID          string
	Platform               string
	PrincipalID            string
	DPoPJKT                string
	Counter                uint32
	// LastAssertionHash binds the current counter to the exact assertion bytes
	// and challenge binding that advanced it. A same-counter retry is accepted
	// only when this digest matches, which recovers safely from a later session
	// transaction failure without accepting a different assertion replay.
	LastAssertionHash  [sha256.Size]byte
	ExtensionsPresent  bool
	ValidationCategory uint32
	BundleVersion      string
	AttestedAt         time.Time
}

func (AppAttestStoredKey) String() string   { return "[REDACTED]" }
func (AppAttestStoredKey) GoString() string { return "attestation.AppAttestStoredKey{[REDACTED]}" }
func (AppAttestStoredKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (AppAttestStoredKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// AppAttestKeyTransaction receives an owned snapshot. Returning nil commits
// the returned state; returning an error must leave the stored state unchanged.
type AppAttestKeyTransaction func(current AppAttestStoredKey, exists bool) (next AppAttestStoredKey, err error)

// AppAttestKeyStore serializes operations for one credential ID. It must call
// transact exactly once while holding the key's transaction/lock, atomically
// persist the returned state before reporting success, and make no change when
// the callback fails or the context is canceled before commit. Cancellation
// observed after the durable commit must return nil so the verifier can return
// the sealed success that corresponds to the committed state. Both callback
// input and persisted output must be defensive deep copies.
type AppAttestKeyStore interface {
	TransactAppAttestKey(context.Context, [sha256.Size]byte, AppAttestKeyTransaction) error
}

// AppAttestConfig contains only server-owned values. The Apple App ID is the
// App ID prefix joined to the bundle identifier with a period. Extension
// policies are mandatory. The server may explicitly allow all well-formed build
// versions with the sole entry "*"; validation categories remain allowlisted.
// Valid legacy authenticator data has neither extension.
type AppAttestConfig struct {
	ApplicationID               string
	EnvironmentID               string
	AppIDPrefix                 string
	BundleID                    string
	AttestationEnvironment      AppAttestEnvironment
	AllowedValidationCategories []uint32
	AllowedBundleVersions       []string
	Store                       AppAttestKeyStore
	Now                         func() time.Time
	ResultLifetime              time.Duration
}

type AppAttestVerifier struct {
	applicationID          string
	environmentID          string
	attestationEnvironment AppAttestEnvironment
	appIDHash              [sha256.Size]byte
	allowedCategories      map[uint32]struct{}
	allowedBundleVersions  map[string]struct{}
	store                  AppAttestKeyStore
	roots                  *x509.CertPool
	now                    func() time.Time
	resultLifetime         time.Duration
}

// NewAppAttestVerifier constructs a verifier pinned to Apple's App Attestation
// root CA. Clients cannot add or replace trust anchors. The attestation receipt
// is required and bounded as part of Apple's wire shape, and the evidence hash
// covers it, but this verifier neither stores it nor claims it was assessed.
// Receipt validation and refresh belong to Apple's separately authenticated
// server-to-server fraud-risk flow.
func NewAppAttestVerifier(config AppAttestConfig) (*AppAttestVerifier, error) {
	roots, err := appleAppAttestationRoots()
	if err != nil {
		return nil, ErrConfiguration
	}
	return newAppAttestVerifier(config, roots)
}

func newAppAttestVerifier(config AppAttestConfig, roots *x509.CertPool) (*AppAttestVerifier, error) {
	if appAttestCBORModeError != nil || appAttestCBORMode == nil ||
		!applicationPattern.MatchString(config.ApplicationID) ||
		!environmentPattern.MatchString(config.EnvironmentID) ||
		!appAttestAppIDPrefixPattern.MatchString(config.AppIDPrefix) ||
		!validAppAttestBundleID(config.BundleID) ||
		(config.AttestationEnvironment != AppAttestDevelopment && config.AttestationEnvironment != AppAttestProduction) ||
		nilPlayIntegrityDependency(config.Store) || roots == nil {
		return nil, ErrConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ResultLifetime == 0 {
		config.ResultLifetime = defaultAppAttestResultLifetime
	}
	if config.ResultLifetime < time.Minute || config.ResultLifetime > maximumAppAttestResultLifetime {
		return nil, ErrConfiguration
	}

	categories := make(map[uint32]struct{}, len(config.AllowedValidationCategories))
	for _, category := range config.AllowedValidationCategories {
		if !validAppAttestValidationCategory(category) {
			return nil, ErrConfiguration
		}
		if _, duplicate := categories[category]; duplicate {
			return nil, ErrConfiguration
		}
		categories[category] = struct{}{}
	}
	if len(categories) == 0 {
		return nil, ErrConfiguration
	}

	versions := make(map[string]struct{}, len(config.AllowedBundleVersions))
	if len(config.AllowedBundleVersions) == 0 || len(config.AllowedBundleVersions) > maximumAppAttestBundleVersions {
		return nil, ErrConfiguration
	}
	for _, version := range config.AllowedBundleVersions {
		if version == "*" && len(config.AllowedBundleVersions) == 1 {
			versions[version] = struct{}{}
			continue
		}
		if !validAppAttestBundleVersion(version) {
			return nil, ErrConfiguration
		}
		if _, duplicate := versions[version]; duplicate {
			return nil, ErrConfiguration
		}
		versions[version] = struct{}{}
	}

	appID := config.AppIDPrefix + "." + config.BundleID
	return &AppAttestVerifier{
		applicationID: config.ApplicationID, environmentID: config.EnvironmentID,
		attestationEnvironment: config.AttestationEnvironment,
		appIDHash:              sha256.Sum256([]byte(appID)), allowedCategories: categories,
		allowedBundleVersions: versions, store: config.Store, roots: roots.Clone(),
		now: config.Now, resultLifetime: config.ResultLifetime,
	}, nil
}

func (*AppAttestVerifier) ID() string { return appAttestProvider }

func (verifier *AppAttestVerifier) Verify(ctx context.Context, evidence Evidence, binding Binding) (Result, error) {
	if verifier == nil {
		return Result{}, ErrUnsupported
	}
	if evidence.provider != appAttestProvider {
		return Result{}, appAttestFailure(AppAttestFailurePhaseRequest, ErrUnsupported)
	}
	if ctx == nil {
		return Result{}, appAttestFailure(AppAttestFailurePhaseRequest, invalid("app attest context"))
	}
	if err := ctx.Err(); err != nil {
		return Result{}, appAttestFailure(AppAttestFailurePhaseContext, err)
	}
	if err := verifier.validateBinding(binding); err != nil {
		return Result{}, appAttestFailure(AppAttestFailurePhaseBinding, err)
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		return Result{}, appAttestFailure(AppAttestFailurePhaseBinding, err)
	}
	keyID, encodedObject, evidenceKind, err := decodeAppAttestEvidence(evidence.payload, bindingHash)
	if err != nil {
		return Result{}, appAttestFailure(AppAttestFailurePhaseEvidence, err)
	}
	now := verifier.now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return Result{}, appAttestFailure(AppAttestFailurePhaseClock, ErrConfiguration)
	}

	var state AppAttestStoredKey
	switch evidenceKind {
	case "attestation":
		state, err = verifier.verifyAndRegisterAttestation(ctx, keyID, encodedObject, binding, bindingHash, now)
	case "assertion":
		state, err = verifier.verifyAndConsumeAssertion(ctx, keyID, encodedObject, binding, bindingHash)
	default:
		err = appAttestFailure(AppAttestFailurePhaseEvidence, invalid("app attest evidence shape"))
	}
	if err != nil {
		return Result{}, err
	}
	evidenceHash := appAttestEvidenceHash(evidenceKind, keyID, encodedObject)
	signals := map[string]any{
		"evidence_type":                 evidenceKind,
		"app_attest_environment":        string(state.AttestationEnvironment),
		"app_attest_extensions_present": state.ExtensionsPresent,
		"assertion_counter":             int64(state.Counter),
	}
	if state.ExtensionsPresent {
		signals["validation_category"] = int64(state.ValidationCategory)
		signals["bundle_version"] = state.BundleVersion
	}
	result, err := newResultWithAppAttestKeyID(
		appAttestProvider, "app_verified", now, now.Add(verifier.resultLifetime),
		signals, evidenceHash, bindingHash, keyID,
	)
	if err != nil {
		return Result{}, appAttestFailure(AppAttestFailurePhaseResult, err)
	}
	return result, nil
}

// AppAttestKeyID returns the Apple credential identifier only from a valid,
// sealed App Attest result. Session persistence uses this narrow accessor to
// link the pre-session key row to the exact installation without trusting a
// caller-controlled signal map.
func (result Result) AppAttestKeyID() ([sha256.Size]byte, bool) {
	var keyID [sha256.Size]byte
	if result.Provider != appAttestProvider || result.validate() != nil {
		return keyID, false
	}
	return result.appAttestKeyID, true
}

func (verifier *AppAttestVerifier) validateBinding(binding Binding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if binding.ApplicationID != verifier.applicationID || binding.Environment != verifier.environmentID ||
		!validAppAttestPlatform(binding.Platform) {
		return invalid("app attest binding scope")
	}
	return nil
}

func (verifier *AppAttestVerifier) verifyAndRegisterAttestation(
	ctx context.Context,
	keyID [sha256.Size]byte,
	object []byte,
	binding Binding,
	bindingHash [sha256.Size]byte,
	now time.Time,
) (AppAttestStoredKey, error) {
	parsed, err := parseAppAttestationObject(object)
	if err != nil {
		return AppAttestStoredKey{}, appAttestFailure(AppAttestFailurePhaseAttestationObject, err)
	}
	leaf, err := verifyAppAttestCertificateChain(parsed.certificates, verifier.roots, now)
	if err != nil {
		return AppAttestStoredKey{}, appAttestFailure(AppAttestFailurePhaseCertificateChain, err)
	}
	if err := ctx.Err(); err != nil {
		return AppAttestStoredKey{}, appAttestFailure(AppAttestFailurePhaseContext, err)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseCertificateChain, invalid("app attest credential certificate key"),
		)
	}
	publicKeyX963, err := publicKey.Bytes()
	if err != nil || len(publicKeyX963) != 65 || publicKeyX963[0] != 4 {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseCertificateChain, invalid("app attest credential certificate key"),
		)
	}
	publicKeyHash := sha256.Sum256(publicKeyX963)
	if subtle.ConstantTimeCompare(publicKeyHash[:], keyID[:]) != 1 ||
		subtle.ConstantTimeCompare(parsed.authenticator.credentialID[:], keyID[:]) != 1 ||
		subtle.ConstantTimeCompare(parsed.authenticator.publicKeyX963, publicKeyX963) != 1 {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseCredentialBinding, invalid("app attest credential binding"),
		)
	}
	if subtle.ConstantTimeCompare(parsed.authenticator.rpIDHash[:], verifier.appIDHash[:]) != 1 || parsed.authenticator.counter != 0 {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseAttestationAuthenticator, invalid("app attest authenticator data"),
		)
	}
	if !appAttestAAGUIDMatches(parsed.authenticator.aaguid, verifier.attestationEnvironment) {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseAttestationEnvironment, invalid("app attest environment"),
		)
	}
	if !verifier.extensionsAllowed(parsed.authenticator.extensions) {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseAttestationExtensions, invalid("app attest extensions"),
		)
	}

	nonceInput := make([]byte, 0, len(parsed.authenticatorData)+sha256.Size)
	nonceInput = append(nonceInput, parsed.authenticatorData...)
	nonceInput = append(nonceInput, bindingHash[:]...)
	expectedNonce := sha256.Sum256(nonceInput)
	certificateNonce, err := appAttestCertificateNonce(leaf)
	if err != nil || subtle.ConstantTimeCompare(certificateNonce, expectedNonce[:]) != 1 {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseAttestationNonce, invalid("app attest nonce"),
		)
	}

	next := AppAttestStoredKey{
		PublicKeyX963: append([]byte(nil), publicKeyX963...), AppIDHash: verifier.appIDHash,
		AttestationEnvironment: verifier.attestationEnvironment,
		ApplicationID:          binding.ApplicationID, EnvironmentID: binding.Environment,
		Platform: binding.Platform, PrincipalID: binding.PrincipalID, DPoPJKT: binding.DPoPJKT,
		Counter: 0, ExtensionsPresent: parsed.authenticator.extensions.present,
		ValidationCategory: parsed.authenticator.extensions.validationCategory,
		BundleVersion:      parsed.authenticator.extensions.bundleVersion, AttestedAt: now,
	}
	if err := validateAppAttestStoredKey(keyID, next); err != nil {
		return AppAttestStoredKey{}, appAttestFailure(AppAttestFailurePhaseKeyStore, ErrConfiguration)
	}

	var callbackErr error
	callbackCount := 0
	storeErr := verifier.store.TransactAppAttestKey(ctx, keyID, func(current AppAttestStoredKey, exists bool) (AppAttestStoredKey, error) {
		callbackCount++
		if callbackCount != 1 {
			callbackErr = ErrAppAttestKeyStore
			return AppAttestStoredKey{}, callbackErr
		}
		if err := ctx.Err(); err != nil {
			callbackErr = err
			return AppAttestStoredKey{}, err
		}
		if exists {
			current = cloneAppAttestStoredKey(current)
			if validateAppAttestStoredKey(keyID, current) == nil &&
				sameAppAttestRegistration(current, next) {
				// Registration is durably committed before the surrounding session
				// transaction begins. An equivalent verified registration for the
				// same unused key and immutable scope is therefore a no-op, allowing
				// recovery from a transient later session failure without abandoning
				// the Apple key. Preserve its original timestamp and never reset a
				// used counter.
				return current, nil
			}
			callbackErr = invalid("app attest key registration")
			return AppAttestStoredKey{}, callbackErr
		}
		return cloneAppAttestStoredKey(next), nil
	})
	if err := normalizeAppAttestStoreError(ctx, storeErr, callbackErr, callbackCount); err != nil {
		phase := AppAttestFailurePhaseRegistration
		if errors.Is(err, ErrAppAttestKeyStore) {
			phase = AppAttestFailurePhaseKeyStore
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			phase = AppAttestFailurePhaseContext
		}
		return AppAttestStoredKey{}, appAttestFailure(phase, err)
	}
	return cloneAppAttestStoredKey(next), nil
}

func sameAppAttestRegistration(current, candidate AppAttestStoredKey) bool {
	return current.Counter == 0 && candidate.Counter == 0 &&
		current.LastAssertionHash == ([sha256.Size]byte{}) &&
		candidate.LastAssertionHash == ([sha256.Size]byte{}) &&
		bytes.Equal(current.PublicKeyX963, candidate.PublicKeyX963) &&
		subtle.ConstantTimeCompare(current.AppIDHash[:], candidate.AppIDHash[:]) == 1 &&
		current.AttestationEnvironment == candidate.AttestationEnvironment &&
		current.ApplicationID == candidate.ApplicationID &&
		current.EnvironmentID == candidate.EnvironmentID &&
		current.Platform == candidate.Platform &&
		current.PrincipalID == candidate.PrincipalID &&
		current.DPoPJKT == candidate.DPoPJKT &&
		current.ExtensionsPresent == candidate.ExtensionsPresent &&
		current.ValidationCategory == candidate.ValidationCategory &&
		current.BundleVersion == candidate.BundleVersion
}

func (verifier *AppAttestVerifier) verifyAndConsumeAssertion(
	ctx context.Context,
	keyID [sha256.Size]byte,
	object []byte,
	binding Binding,
	bindingHash [sha256.Size]byte,
) (AppAttestStoredKey, error) {
	parsed, err := parseAppAttestAssertionObject(object)
	if err != nil {
		return AppAttestStoredKey{}, appAttestFailure(AppAttestFailurePhaseAssertionObject, err)
	}
	if subtle.ConstantTimeCompare(parsed.rpIDHash[:], verifier.appIDHash[:]) != 1 || !verifier.extensionsAllowed(parsed.extensions) {
		return AppAttestStoredKey{}, appAttestFailure(
			AppAttestFailurePhaseAssertionAuthenticator, invalid("app attest assertion authenticator data"),
		)
	}
	assertionHash := appAttestAssertionReplayHash(keyID, object, bindingHash)

	var committed AppAttestStoredKey
	var callbackErr error
	var callbackPhase AppAttestFailurePhase
	callbackCount := 0
	storeErr := verifier.store.TransactAppAttestKey(ctx, keyID, func(current AppAttestStoredKey, exists bool) (AppAttestStoredKey, error) {
		callbackCount++
		if callbackCount != 1 {
			callbackPhase = AppAttestFailurePhaseKeyStore
			callbackErr = ErrAppAttestKeyStore
			return AppAttestStoredKey{}, callbackErr
		}
		if err := ctx.Err(); err != nil {
			callbackPhase = AppAttestFailurePhaseContext
			callbackErr = err
			return AppAttestStoredKey{}, err
		}
		if !exists {
			callbackPhase = AppAttestFailurePhaseAssertionKey
			callbackErr = invalid("app attest assertion key")
			return AppAttestStoredKey{}, callbackErr
		}
		current = cloneAppAttestStoredKey(current)
		if err := validateAppAttestStoredKey(keyID, current); err != nil {
			callbackPhase = AppAttestFailurePhaseKeyStore
			callbackErr = ErrAppAttestKeyStore
			return AppAttestStoredKey{}, callbackErr
		}
		if current.ApplicationID != binding.ApplicationID || current.EnvironmentID != binding.Environment ||
			current.Platform != binding.Platform || current.PrincipalID != binding.PrincipalID ||
			current.DPoPJKT != binding.DPoPJKT ||
			current.AttestationEnvironment != verifier.attestationEnvironment ||
			subtle.ConstantTimeCompare(current.AppIDHash[:], verifier.appIDHash[:]) != 1 {
			callbackPhase = AppAttestFailurePhaseAssertionScope
			callbackErr = invalid("app attest assertion scope")
			return AppAttestStoredKey{}, callbackErr
		}
		if parsed.counter == 0 || parsed.counter < current.Counter {
			callbackPhase = AppAttestFailurePhaseAssertionCounter
			callbackErr = invalid("app attest assertion counter")
			return AppAttestStoredKey{}, callbackErr
		}
		publicKey, err := parseAppAttestPublicKey(current.PublicKeyX963)
		if err != nil {
			callbackPhase = AppAttestFailurePhaseKeyStore
			callbackErr = ErrAppAttestKeyStore
			return AppAttestStoredKey{}, callbackErr
		}
		nonceInput := make([]byte, 0, len(parsed.authenticatorData)+sha256.Size)
		nonceInput = append(nonceInput, parsed.authenticatorData...)
		nonceInput = append(nonceInput, bindingHash[:]...)
		nonce := sha256.Sum256(nonceInput)
		// Apple defines nonce as SHA-256(authenticatorData || clientDataHash),
		// then signs that nonce with ECDSA-SHA256. Signature APIs that accept a
		// message hash the 32-byte nonce once more before the ECDSA primitive.
		// Go's VerifyASN1 accepts the primitive digest directly, so perform that
		// algorithm hash explicitly. A physical iOS 27 assertion locks this
		// otherwise easy-to-miss distinction alongside deterministic vectors.
		signatureDigest := sha256.Sum256(nonce[:])
		if !ecdsa.VerifyASN1(publicKey, signatureDigest[:], parsed.signature) {
			callbackPhase = AppAttestFailurePhaseAssertionSignature
			callbackErr = invalid("app attest assertion signature")
			return AppAttestStoredKey{}, callbackErr
		}
		if parsed.counter == current.Counter {
			if current.LastAssertionHash == ([sha256.Size]byte{}) ||
				subtle.ConstantTimeCompare(current.LastAssertionHash[:], assertionHash[:]) != 1 ||
				current.ExtensionsPresent != parsed.extensions.present ||
				current.ValidationCategory != parsed.extensions.validationCategory ||
				current.BundleVersion != parsed.extensions.bundleVersion {
				callbackPhase = AppAttestFailurePhaseAssertionCounter
				callbackErr = invalid("app attest assertion counter")
				return AppAttestStoredKey{}, callbackErr
			}
			// The exact assertion and binding already advanced the durable counter.
			// Return the stored snapshot without a write so the still-unconsumed
			// session challenge can recover from a later transactional failure.
			committed = cloneAppAttestStoredKey(current)
			return cloneAppAttestStoredKey(current), nil
		}
		current.Counter = parsed.counter
		current.LastAssertionHash = assertionHash
		current.ExtensionsPresent = parsed.extensions.present
		current.ValidationCategory = parsed.extensions.validationCategory
		current.BundleVersion = parsed.extensions.bundleVersion
		committed = cloneAppAttestStoredKey(current)
		return cloneAppAttestStoredKey(current), nil
	})
	if err := normalizeAppAttestStoreError(ctx, storeErr, callbackErr, callbackCount); err != nil {
		phase := callbackPhase
		if !validAppAttestFailurePhase(phase) || errors.Is(err, ErrAppAttestKeyStore) {
			phase = AppAttestFailurePhaseKeyStore
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			phase = AppAttestFailurePhaseContext
		}
		return AppAttestStoredKey{}, appAttestFailure(phase, err)
	}
	return committed, nil
}

func (verifier *AppAttestVerifier) extensionsAllowed(extensions appAttestExtensions) bool {
	if !extensions.present {
		return true
	}
	_, categoryAllowed := verifier.allowedCategories[extensions.validationCategory]
	_, versionAllowed := verifier.allowedBundleVersions[extensions.bundleVersion]
	_, anyVersionAllowed := verifier.allowedBundleVersions["*"]
	return categoryAllowed && validAppAttestBundleVersion(extensions.bundleVersion) && (versionAllowed || anyVersionAllowed)
}

func decodeAppAttestEvidence(
	payload map[string]any,
	expectedClientDataHash [sha256.Size]byte,
) ([sha256.Size]byte, []byte, string, error) {
	if payload == nil || len(payload) != 3 {
		return [sha256.Size]byte{}, nil, "", invalid("app attest evidence shape")
	}
	// DCAppAttestService.generateKey returns the key identifier already encoded
	// as padded standard Base64. Latchway encodes the binary object and binding
	// hash as unpadded Base64url, matching the sibling Swift SDK.
	keyIDText, ok := payload["key_id"].(string)
	if !ok {
		return [sha256.Size]byte{}, nil, "", invalid("app attest key identifier")
	}
	keyIDBytes, err := decodeCanonicalAppAttestBase64(keyIDText, sha256.Size)
	if err != nil || len(keyIDBytes) != sha256.Size {
		return [sha256.Size]byte{}, nil, "", invalid("app attest key identifier")
	}
	var keyID [sha256.Size]byte
	copy(keyID[:], keyIDBytes)
	if keyID == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, nil, "", invalid("app attest key identifier")
	}
	clientDataHashText, ok := payload["client_data_hash"].(string)
	if !ok {
		return [sha256.Size]byte{}, nil, "", invalid("app attest client data hash")
	}
	clientDataHash, err := decodeCanonicalAppAttestBase64URL(clientDataHashText, sha256.Size)
	if err != nil || len(clientDataHash) != sha256.Size ||
		subtle.ConstantTimeCompare(clientDataHash, expectedClientDataHash[:]) != 1 {
		return [sha256.Size]byte{}, nil, "", invalid("app attest client data hash")
	}

	if text, exists := payload["attestation_object"]; exists {
		if _, assertionExists := payload["assertion_object"]; assertionExists {
			return [sha256.Size]byte{}, nil, "", invalid("app attest evidence shape")
		}
		encoded, ok := text.(string)
		if !ok {
			return [sha256.Size]byte{}, nil, "", invalid("app attest attestation encoding")
		}
		object, err := decodeCanonicalAppAttestBase64URL(encoded, maxAppAttestAttestationBytes)
		if err != nil || len(object) == 0 {
			return [sha256.Size]byte{}, nil, "", invalid("app attest attestation encoding")
		}
		return keyID, object, "attestation", nil
	}
	if text, exists := payload["assertion_object"]; exists {
		encoded, ok := text.(string)
		if !ok {
			return [sha256.Size]byte{}, nil, "", invalid("app attest assertion encoding")
		}
		object, err := decodeCanonicalAppAttestBase64URL(encoded, maxAppAttestAssertionBytes)
		if err != nil || len(object) == 0 {
			return [sha256.Size]byte{}, nil, "", invalid("app attest assertion encoding")
		}
		return keyID, object, "assertion", nil
	}
	return [sha256.Size]byte{}, nil, "", invalid("app attest evidence shape")
}

func decodeCanonicalAppAttestBase64URL(value string, maximumBytes int) ([]byte, error) {
	if value == "" || maximumBytes <= 0 || len(value) > base64.RawURLEncoding.EncodedLen(maximumBytes) {
		return nil, ErrInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func decodeCanonicalAppAttestBase64(value string, maximumBytes int) ([]byte, error) {
	if value == "" || maximumBytes <= 0 || len(value) > base64.StdEncoding.EncodedLen(maximumBytes) {
		return nil, ErrInvalid
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumBytes || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func appAttestEvidenceHash(kind string, keyID [sha256.Size]byte, object []byte) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte(appAttestEvidenceDomain))
	digest.Write([]byte{0})
	digest.Write([]byte(kind))
	digest.Write([]byte{0})
	digest.Write(keyID[:])
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(object)))
	digest.Write(length[:])
	digest.Write(object)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func appAttestAssertionReplayHash(
	keyID [sha256.Size]byte,
	object []byte,
	bindingHash [sha256.Size]byte,
) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte("latchway/app-attest-assertion-retry/v1"))
	digest.Write([]byte{0})
	digest.Write(keyID[:])
	digest.Write(bindingHash[:])
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(object)))
	digest.Write(length[:])
	digest.Write(object)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func normalizeAppAttestStoreError(ctx context.Context, storeErr, callbackErr error, callbackCount int) error {
	if storeErr == nil {
		if callbackCount != 1 || callbackErr != nil {
			return ErrAppAttestKeyStore
		}
		return nil
	}
	if callbackErr != nil && errors.Is(storeErr, callbackErr) {
		return callbackErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(storeErr, ctxErr) {
		return ctxErr
	}
	return ErrAppAttestKeyStore
}

func validateAppAttestStoredKey(keyID [sha256.Size]byte, key AppAttestStoredKey) error {
	if len(key.PublicKeyX963) != 65 || key.PublicKeyX963[0] != 4 ||
		key.AppIDHash == ([sha256.Size]byte{}) ||
		(key.AttestationEnvironment != AppAttestDevelopment && key.AttestationEnvironment != AppAttestProduction) ||
		!applicationPattern.MatchString(key.ApplicationID) || !environmentPattern.MatchString(key.EnvironmentID) ||
		!validAppAttestPlatform(key.Platform) || !principalPattern.MatchString(key.PrincipalID) ||
		validateBase64URL(key.DPoPJKT, sha256.Size, sha256.Size) != nil ||
		(key.Counter == 0) != (key.LastAssertionHash == ([sha256.Size]byte{})) ||
		!validAppAttestStoredExtensions(key) ||
		key.AttestedAt.IsZero() {
		return ErrInvalid
	}
	publicKey, err := parseAppAttestPublicKey(key.PublicKeyX963)
	if err != nil {
		return ErrInvalid
	}
	canonical, err := publicKey.Bytes()
	if err != nil || len(canonical) != 65 || canonical[0] != 4 {
		return ErrInvalid
	}
	publicKeyHash := sha256.Sum256(canonical)
	if subtle.ConstantTimeCompare(publicKeyHash[:], keyID[:]) != 1 {
		return ErrInvalid
	}
	return nil
}

func validAppAttestStoredExtensions(key AppAttestStoredKey) bool {
	if !key.ExtensionsPresent {
		return key.ValidationCategory == 0 && key.BundleVersion == ""
	}
	return validAppAttestValidationCategory(key.ValidationCategory) && validAppAttestBundleVersion(key.BundleVersion)
}

func validAppAttestPlatform(platform string) bool {
	return platform == "ios" || platform == "react_native_ios" || platform == "watchos"
}

func parseAppAttestPublicKey(encoded []byte) (*ecdsa.PublicKey, error) {
	if len(encoded) != 65 || encoded[0] != 4 {
		return nil, ErrInvalid
	}
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		return nil, ErrInvalid
	}
	return publicKey, nil
}

func cloneAppAttestStoredKey(key AppAttestStoredKey) AppAttestStoredKey {
	key.PublicKeyX963 = append([]byte(nil), key.PublicKeyX963...)
	key.AttestedAt = key.AttestedAt.UTC()
	return key
}

func validAppAttestBundleID(bundleID string) bool {
	return len(bundleID) <= 255 && appAttestBundleIDPattern.MatchString(bundleID) &&
		!strings.Contains(bundleID, "..") && !strings.Contains(bundleID, ".-") && !strings.Contains(bundleID, "-.")
}

func validAppAttestBundleVersion(version string) bool {
	return len(version) <= maximumAppAttestBundleVersionLen && appAttestBundleVersionPattern.MatchString(version) &&
		!strings.Contains(version, "..")
}

func validAppAttestValidationCategory(category uint32) bool {
	switch category {
	case 1, 2, 3, 4, 5, 6, 10:
		return true
	default:
		return false
	}
}

func appAttestAAGUIDMatches(aaguid [16]byte, environment AppAttestEnvironment) bool {
	production := [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't'}
	developmentLegacy := [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'}
	developmentSandbox := [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 's', 'a', 'n', 'd', 'b', 'o', 'x'}
	switch environment {
	case AppAttestProduction:
		return subtle.ConstantTimeCompare(aaguid[:], production[:]) == 1
	case AppAttestDevelopment:
		return subtle.ConstantTimeCompare(aaguid[:], developmentLegacy[:]) == 1 ||
			subtle.ConstantTimeCompare(aaguid[:], developmentSandbox[:]) == 1
	default:
		return false
	}
}

func appleAppAttestationRoots() (*x509.CertPool, error) {
	block, rest := pem.Decode([]byte(appleAppAttestationRootCAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrConfiguration
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return roots, nil
}

const appleAppAttestationRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

var _ Verifier = (*AppAttestVerifier)(nil)
