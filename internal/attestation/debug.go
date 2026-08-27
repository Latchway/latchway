package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const debugMessageDomain = "latchway/debug-attestation/v1"

var debugKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)

type DebugConfig struct {
	Enabled                    bool
	EnvironmentKind            string
	DangerousAllowInProduction bool
	PublicKeys                 map[string]ed25519.PublicKey
	Now                        func() time.Time
	MaximumEvidenceLifetime    time.Duration
	ClockSkew                  time.Duration
}

type DebugVerifier struct {
	keys        map[string]ed25519.PublicKey
	now         func() time.Time
	maxLifetime time.Duration
	clockSkew   time.Duration
}

func NewDebugVerifier(config DebugConfig) (*DebugVerifier, error) {
	if !config.Enabled || (config.EnvironmentKind != "development" && config.EnvironmentKind != "staging" && config.EnvironmentKind != "production") || (config.EnvironmentKind == "production" && !config.DangerousAllowInProduction) || len(config.PublicKeys) == 0 || len(config.PublicKeys) > 16 {
		return nil, ErrConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaximumEvidenceLifetime == 0 {
		config.MaximumEvidenceLifetime = 10 * time.Minute
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = time.Minute
	}
	if config.MaximumEvidenceLifetime < time.Minute || config.MaximumEvidenceLifetime > time.Hour || config.ClockSkew < 0 || config.ClockSkew > 5*time.Minute {
		return nil, ErrConfiguration
	}
	keys := make(map[string]ed25519.PublicKey, len(config.PublicKeys))
	for keyID, publicKey := range config.PublicKeys {
		if !debugKeyIDPattern.MatchString(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrConfiguration
		}
		keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &DebugVerifier{keys: keys, now: config.Now, maxLifetime: config.MaximumEvidenceLifetime, clockSkew: config.ClockSkew}, nil
}

func (*DebugVerifier) ID() string { return "debug" }

func (verifier *DebugVerifier) Verify(_ context.Context, evidence Evidence, binding Binding) (Result, error) {
	if verifier == nil || evidence.provider != "debug" {
		return Result{}, ErrUnsupported
	}
	if err := binding.Validate(); err != nil {
		return Result{}, err
	}
	if len(evidence.payload) != 4 {
		return Result{}, invalid("debug evidence shape")
	}
	keyID, keyOK := evidence.payload["key_id"].(string)
	bindingHash, hashOK := evidence.payload["binding_hash"].(string)
	signatureText, signatureOK := evidence.payload["signature"].(string)
	expiresAtUnix, expiresOK := integerClaim(evidence.payload["expires_at"])
	if !keyOK || !debugKeyIDPattern.MatchString(keyID) || !hashOK || !signatureOK || !expiresOK {
		return Result{}, invalid("debug evidence fields")
	}
	publicKey, exists := verifier.keys[keyID]
	if !exists {
		return Result{}, invalid("debug signing key")
	}
	expectedHash, err := binding.Hash()
	if err != nil {
		return Result{}, err
	}
	providedHash, err := base64.RawURLEncoding.Strict().DecodeString(bindingHash)
	if err != nil || len(providedHash) != sha256.Size || base64.RawURLEncoding.EncodeToString(providedHash) != bindingHash || subtle.ConstantTimeCompare(providedHash, expectedHash[:]) != 1 {
		return Result{}, invalid("debug binding hash")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return Result{}, invalid("debug signature encoding")
	}
	now := verifier.now().UTC()
	expiresAt := time.Unix(expiresAtUnix, 0).UTC()
	if !expiresAt.After(now.Add(-verifier.clockSkew)) || expiresAt.After(now.Add(verifier.maxLifetime)) {
		return Result{}, invalid("debug evidence expiry")
	}
	message := DebugSigningMessage(expectedHash, expiresAtUnix)
	if !ed25519.Verify(publicKey, message, signature) {
		return Result{}, invalid("debug signature")
	}
	encodedEvidence, err := canonicalDebugEvidence(keyID, bindingHash, expiresAtUnix, signatureText)
	if err != nil {
		return Result{}, ErrInvalid
	}
	result := Result{
		Provider: "debug", TrustLevel: "debug", VerifiedAt: now, ExpiresAt: expiresAt,
		NormalizedSignals: map[string]any{"deterministic_test_evidence": true},
		EvidenceHash:      sha256.Sum256(encodedEvidence),
	}
	if err := result.validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// DebugSigningMessage is exported for conformance fixtures. Production code
// must retain private debug keys outside the gateway and outside client builds.
func DebugSigningMessage(bindingHash [sha256.Size]byte, expiresAt int64) []byte {
	message := make([]byte, 0, len(debugMessageDomain)+1+sha256.Size+8)
	message = append(message, debugMessageDomain...)
	message = append(message, 0)
	message = append(message, bindingHash[:]...)
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(expiresAt))
	message = append(message, expiry[:]...)
	return message
}

func integerClaim(value any) (int64, bool) {
	var number json.Number
	switch typed := value.(type) {
	case json.Number:
		number = typed
	case float64:
		number = json.Number(fmt.Sprintf("%v", typed))
	default:
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil && parsed > 0
}

func canonicalDebugEvidence(keyID, bindingHash string, expiresAt int64, signature string) ([]byte, error) {
	if strings.ContainsAny(keyID+bindingHash+signature, `"\\`) {
		return nil, errors.New("debug evidence contains unsafe string characters")
	}
	return []byte(fmt.Sprintf(`{"binding_hash":"%s","expires_at":%d,"key_id":"%s","signature":"%s"}`, bindingHash, expiresAt, keyID, signature)), nil
}
