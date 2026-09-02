package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
)

var (
	ErrChallengeInvalid  = errors.New("session challenge is invalid")
	ErrChallengeExpired  = errors.New("session challenge is expired")
	ErrChallengeConsumed = errors.New("session challenge was already consumed")
	ErrSessionScope      = errors.New("client session scope is unavailable")
)

type ChallengeStoreConfig struct {
	Pool          *pgxpool.Pool
	Configuration *configuration.Store
	Now           func() time.Time
	Random        io.Reader
}

type ChallengeStore struct {
	pool          *pgxpool.Pool
	configuration *configuration.Store
	now           func() time.Time
	random        io.Reader
}

// newChallengeStore is deliberately package-private. Raw identity and key
// assertions must only reach challenge persistence through the session
// coordinator that verifies them; other packages cannot construct this store.
func newChallengeStore(config ChallengeStoreConfig) (*ChallengeStore, error) {
	if config.Pool == nil || config.Configuration == nil {
		return nil, errors.New("challenge store dependency is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &ChallengeStore{
		pool: config.Pool, configuration: config.Configuration,
		now: config.Now, random: config.Random,
	}, nil
}

type ChallengeInput struct {
	OrganizationID          string
	ApplicationID           string
	EnvironmentID           string
	ConfigurationRevisionID string
	EnvironmentSlug         string
	ApplicationUserID       string
	IdentityProvider        string
	IdentityVerifiedAt      time.Time
	IdentityExpiresAt       time.Time
	Platform                string
	Origin                  string
	DPoPJKT                 string
	DPoPPublicJWK           dpop.PublicJWK
	DPoPProofJTI            string
	DPoPHTTPMethod          string
	DPoPRequestURI          *url.URL
}

func (input ChallengeInput) validate() error {
	if validateChallengeIdentity(input) != nil || !validChallengeOrigin(input.Platform, input.Origin) ||
		id.Validate(input.ConfigurationRevisionID, id.ConfigRevision) != nil || !validReplayJTI(input.DPoPProofJTI) ||
		!replayMethodPattern.MatchString(input.DPoPHTTPMethod) || input.DPoPRequestURI == nil {
		return ErrChallengeInvalid
	}
	return nil
}

func validateChallengeIdentity(input ChallengeInput) error {
	if id.Validate(input.OrganizationID, id.Organization) != nil || id.Validate(input.ApplicationID, id.Application) != nil || id.Validate(input.EnvironmentID, id.Environment) != nil || id.Validate(input.ApplicationUserID, id.ApplicationUser) != nil || !sessionIdentifierPattern.MatchString(input.EnvironmentSlug) || !sessionIdentifierPattern.MatchString(input.IdentityProvider) || input.IdentityVerifiedAt.IsZero() || !input.IdentityExpiresAt.After(input.IdentityVerifiedAt) || !platformPattern.MatchString(input.Platform) || !validThumbprint(input.DPoPJKT) {
		return ErrChallengeInvalid
	}
	thumbprint, err := input.DPoPPublicJWK.Thumbprint()
	if err != nil || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(input.DPoPJKT)) != 1 {
		return ErrChallengeInvalid
	}
	return nil
}

var platformPattern = regexp.MustCompile(`^(ios|android|web|react_native_ios|react_native_android|watchos|node)$`)
var configurationIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var secretReferencePattern = regexp.MustCompile(`^secret/[a-z][a-z0-9_-]{0,62}$`)

// ChallengeAttestationPolicy is the exact immutable policy selection bound to
// a challenge. It is safe to return to a client coordinator: it contains no
// secret references or provider verdict details.
type ChallengeAttestationPolicy struct {
	ID                string
	Provider          string
	Mode              string
	MinimumTrustLevel string
	MaximumAge        time.Duration
}

type Challenge struct {
	ID                      string
	Nonce                   string
	Binding                 attestation.Binding
	BindingHash             [sha256.Size]byte
	DPoPPublicJWK           dpop.PublicJWK
	OrganizationID          string
	IdentityProvider        string
	IdentityVerifiedAt      time.Time
	IdentityExpiresAt       time.Time
	EnvironmentID           string
	ConfigurationRevisionID string
	Origin                  string
	Attestation             ChallengeAttestationPolicy
	ExpiresAt               time.Time

	dpopProofJTIHash [sha256.Size]byte
	dpopHTTPMethod   string
	dpopHTTPURIHash  [sha256.Size]byte
}

func challengePolicyFromSnapshot(snapshot configuration.ActiveSnapshot, identityProvider, platform string) (ChallengeAttestationPolicy, error) {
	if id.Validate(snapshot.RevisionID, id.ConfigRevision) != nil ||
		!sessionIdentifierPattern.MatchString(identityProvider) ||
		!platformPattern.MatchString(platform) {
		return ChallengeAttestationPolicy{}, ErrSessionScope
	}
	if _, ok := snapshot.IdentityProvider(identityProvider); !ok {
		return ChallengeAttestationPolicy{}, ErrSessionScope
	}
	policy, selection, ok := snapshot.RequiredAttestationForPlatform(platform)
	if !ok || !configurationIdentifierPattern.MatchString(policy.ID) || policy.MaxAge < time.Minute || policy.MaxAge > 30*24*time.Hour || policy.MaxAge%time.Millisecond != 0 {
		return ChallengeAttestationPolicy{}, ErrSessionScope
	}
	if !validAttestationProvider(selection.Provider) || selection.Mode != "required" ||
		!trustLevelPattern.MatchString(selection.MinimumTrustLevel) ||
		(selection.Provider == "debug" && !secretReferencePattern.MatchString(selection.SecretRef)) {
		return ChallengeAttestationPolicy{}, ErrSessionScope
	}
	return ChallengeAttestationPolicy{
		ID: policy.ID, Provider: selection.Provider, Mode: selection.Mode,
		MinimumTrustLevel: selection.MinimumTrustLevel, MaximumAge: policy.MaxAge,
	}, nil
}

func validAttestationProvider(provider string) bool {
	switch provider {
	case "app_attest", "play_integrity", "firebase_app_check", "turnstile", "debug":
		return true
	default:
		return false
	}
}

func challengeMatchesSnapshot(challenge Challenge, snapshot configuration.ActiveSnapshot) bool {
	if challenge.ConfigurationRevisionID != snapshot.RevisionID || challenge.EnvironmentID != snapshot.EnvironmentID {
		return false
	}
	if !snapshotOriginAllowed(snapshot, challenge.Binding.Platform, challenge.Origin) {
		return false
	}
	expected, err := challengePolicyFromSnapshot(
		snapshot,
		challenge.IdentityProvider,
		challenge.Binding.Platform,
	)
	return err == nil && expected == challenge.Attestation
}

func (store *ChallengeStore) Create(ctx context.Context, input ChallengeInput) (Challenge, error) {
	if err := input.validate(); err != nil {
		return Challenge{}, err
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: input.OrganizationID,
		ApplicationID:  input.ApplicationID,
		EnvironmentID:  input.EnvironmentID,
	})
	if err != nil {
		return Challenge{}, ErrSessionScope
	}
	if snapshot.RevisionID != input.ConfigurationRevisionID {
		return Challenge{}, ErrSessionScope
	}
	policy, err := challengePolicyFromSnapshot(snapshot, input.IdentityProvider, input.Platform)
	if err != nil {
		return Challenge{}, err
	}
	if !snapshotOriginAllowed(snapshot, input.Platform, input.Origin) {
		return Challenge{}, ErrSessionScope
	}
	normalizedDPoPURI, err := dpop.NormalizeHTU(input.DPoPRequestURI)
	if err != nil || !validNormalizedReplayURI(normalizedDPoPURI) {
		return Challenge{}, ErrChallengeInvalid
	}
	challengeID, err := id.New(id.SessionChallenge)
	if err != nil {
		return Challenge{}, fmt.Errorf("generate challenge ID: %w", err)
	}
	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(store.random, nonceBytes); err != nil {
		return Challenge{}, errors.New("generate challenge nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	now := store.now().UTC().Truncate(time.Second)
	if input.IdentityVerifiedAt.After(now.Add(time.Minute)) || !input.IdentityExpiresAt.After(now) {
		return Challenge{}, ErrChallengeInvalid
	}
	expiresAt := now.Add(snapshot.SessionPolicy().ChallengeTTL)
	binding := attestation.Binding{
		Version: 1, ChallengeID: challengeID, ChallengeNonce: nonce,
		ApplicationID: input.ApplicationID, Environment: input.EnvironmentSlug,
		PrincipalID: input.ApplicationUserID, DPoPJKT: input.DPoPJKT,
		Platform: input.Platform, IssuedAt: now.Unix(),
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		return Challenge{}, err
	}
	encodedJWK, err := json.Marshal(input.DPoPPublicJWK)
	if err != nil {
		return Challenge{}, ErrChallengeInvalid
	}
	nonceHash := sha256.Sum256(nonceBytes)
	proofJTIHash := sha256.Sum256([]byte(input.DPoPProofJTI))
	dpopURIHash := sha256.Sum256([]byte(normalizedDPoPURI))
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Challenge{}, fmt.Errorf("begin session challenge creation: %w", err)
	}
	defer rollbackSigning(tx)
	// Disable takes the application lock first and then consumes every challenge
	// in scope. Holding the matching share locks through insertion prevents a
	// challenge from appearing after that revocation scan and becoming usable
	// if the scope is later re-enabled.
	if err := lockActiveCredentialScope(ctx, tx, input.OrganizationID, input.ApplicationID, input.EnvironmentID); err != nil {
		return Challenge{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO session_challenges (
			session_challenge_id, organization_id, application_id, environment_id,
			application_user_id, identity_provider_key, platform, dpop_jkt,
			dpop_public_jwk, nonce_hash, binding_hash, challenge_nonce,
			identity_verified_at, identity_expires_at, created_at, expires_at,
			config_revision_id, attestation_policy_id, attestation_provider,
			attestation_mode, attestation_minimum_trust_level,
			attestation_maximum_age_milliseconds,
			challenge_dpop_proof_jti_hash, challenge_dpop_http_method,
			challenge_dpop_http_uri_hash, browser_origin
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		       $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
		FROM environments e
		JOIN applications a
		  ON a.organization_id = e.organization_id AND a.application_id = e.application_id
		JOIN organizations o ON o.organization_id = e.organization_id
		JOIN application_users u
		  ON u.organization_id = e.organization_id AND u.application_id = e.application_id
		WHERE e.organization_id = $2
		  AND e.application_id = $3
		  AND e.environment_id = $4
		  AND e.slug = $17
		  AND u.application_user_id = $5
		  AND o.status = 'active'
		  AND a.status = 'active'
		  AND e.status = 'active'
		  AND u.status = 'active'
		  AND EXISTS (
		      SELECT 1
		      FROM active_config_revisions active_revision
		      WHERE active_revision.organization_id = e.organization_id
		        AND active_revision.application_id = e.application_id
		        AND active_revision.environment_id = e.environment_id
		        AND active_revision.config_revision_id = $18
		  )
	`, challengeID, input.OrganizationID, input.ApplicationID, input.EnvironmentID, input.ApplicationUserID,
		input.IdentityProvider, input.Platform, input.DPoPJKT, encodedJWK, nonceHash[:],
		bindingHash[:], nonce, input.IdentityVerifiedAt.UTC(), input.IdentityExpiresAt.UTC(), now, expiresAt,
		input.EnvironmentSlug, snapshot.RevisionID, policy.ID, policy.Provider, policy.Mode,
		policy.MinimumTrustLevel, policy.MaximumAge.Milliseconds(), proofJTIHash[:],
		input.DPoPHTTPMethod, dpopURIHash[:], input.Origin)
	if err != nil {
		if isChallengeProofReplay(err) {
			return Challenge{}, ErrDPoPReplayed
		}
		return Challenge{}, fmt.Errorf("store session challenge: %w", err)
	}
	if command.RowsAffected() != 1 {
		return Challenge{}, ErrSessionScope
	}
	if err := tx.Commit(ctx); err != nil {
		return Challenge{}, fmt.Errorf("commit session challenge creation: %w", err)
	}
	return Challenge{
		ID: challengeID, Nonce: nonce, Binding: binding, BindingHash: bindingHash,
		DPoPPublicJWK: input.DPoPPublicJWK, OrganizationID: input.OrganizationID,
		IdentityProvider: input.IdentityProvider, IdentityVerifiedAt: input.IdentityVerifiedAt.UTC(),
		IdentityExpiresAt: input.IdentityExpiresAt.UTC(),
		EnvironmentID:     input.EnvironmentID, ConfigurationRevisionID: snapshot.RevisionID,
		Origin: input.Origin, Attestation: policy, ExpiresAt: expiresAt,
		dpopProofJTIHash: proofJTIHash, dpopHTTPMethod: input.DPoPHTTPMethod,
		dpopHTTPURIHash: dpopURIHash,
	}, nil
}

func (store *ChallengeStore) Get(ctx context.Context, challengeID string) (Challenge, error) {
	if id.Validate(challengeID, id.SessionChallenge) != nil {
		return Challenge{}, ErrChallengeInvalid
	}
	var result Challenge
	var organizationID, applicationID, applicationUserID, environmentSlug, platform string
	var encodedJWK []byte
	var storedNonceHash, storedBindingHash, storedProofJTIHash, storedDPoPURIHash []byte
	var attestationMaximumAgeMilliseconds int64
	var createdAt time.Time
	var identityVerifiedAt, identityExpiresAt *time.Time
	var consumed bool
	err := store.pool.QueryRow(ctx, `
		SELECT c.organization_id, c.application_id, c.environment_id, e.slug,
		       c.application_user_id, c.identity_provider_key, c.platform, c.dpop_jkt,
		       c.dpop_public_jwk, c.nonce_hash, c.binding_hash, c.challenge_nonce,
		       c.identity_verified_at, c.identity_expires_at, c.created_at, c.expires_at,
		       c.config_revision_id, c.attestation_policy_id, c.attestation_provider,
		       c.attestation_mode, c.attestation_minimum_trust_level,
		       c.attestation_maximum_age_milliseconds,
		       c.challenge_dpop_proof_jti_hash, c.challenge_dpop_http_method,
		       c.challenge_dpop_http_uri_hash, c.browser_origin,
		       EXISTS (
		           SELECT 1 FROM session_challenge_consumptions x
		           WHERE x.session_challenge_id = c.session_challenge_id
		       )
		FROM session_challenges c
		JOIN environments e
		  ON e.organization_id = c.organization_id
		 AND e.application_id = c.application_id
		 AND e.environment_id = c.environment_id
		JOIN applications a
		  ON a.organization_id = c.organization_id AND a.application_id = c.application_id
		JOIN organizations o ON o.organization_id = c.organization_id
		JOIN application_users u
		  ON u.organization_id = c.organization_id
		 AND u.application_id = c.application_id
		 AND u.application_user_id = c.application_user_id
		WHERE c.session_challenge_id = $1
		  AND o.status = 'active' AND a.status = 'active' AND e.status = 'active' AND u.status = 'active'
	`, challengeID).Scan(
		&organizationID, &applicationID, &result.EnvironmentID, &environmentSlug,
		&applicationUserID, &result.IdentityProvider, &platform, &result.Binding.DPoPJKT,
		&encodedJWK, &storedNonceHash, &storedBindingHash, &result.Nonce,
		&identityVerifiedAt, &identityExpiresAt, &createdAt, &result.ExpiresAt,
		&result.ConfigurationRevisionID, &result.Attestation.ID, &result.Attestation.Provider,
		&result.Attestation.Mode, &result.Attestation.MinimumTrustLevel,
		&attestationMaximumAgeMilliseconds, &storedProofJTIHash, &result.dpopHTTPMethod,
		&storedDPoPURIHash, &result.Origin, &consumed,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Challenge{}, ErrChallengeInvalid
	}
	if err != nil {
		return Challenge{}, fmt.Errorf("read session challenge: %w", err)
	}
	if identityVerifiedAt == nil || identityExpiresAt == nil {
		return Challenge{}, ErrChallengeInvalid
	}
	result.IdentityVerifiedAt = identityVerifiedAt.UTC()
	result.IdentityExpiresAt = identityExpiresAt.UTC()
	result.OrganizationID = organizationID
	if id.Validate(result.ConfigurationRevisionID, id.ConfigRevision) != nil ||
		!configurationIdentifierPattern.MatchString(result.Attestation.ID) ||
		!validAttestationProvider(result.Attestation.Provider) ||
		result.Attestation.Mode != "required" ||
		!trustLevelPattern.MatchString(result.Attestation.MinimumTrustLevel) ||
		attestationMaximumAgeMilliseconds < int64(time.Minute/time.Millisecond) ||
		attestationMaximumAgeMilliseconds > int64((30*24*time.Hour)/time.Millisecond) ||
		len(storedProofJTIHash) != sha256.Size ||
		!replayMethodPattern.MatchString(result.dpopHTTPMethod) ||
		len(storedDPoPURIHash) != sha256.Size || !validChallengeOrigin(platform, result.Origin) {
		return Challenge{}, ErrChallengeInvalid
	}
	result.Attestation.MaximumAge = time.Duration(attestationMaximumAgeMilliseconds) * time.Millisecond
	copy(result.dpopProofJTIHash[:], storedProofJTIHash)
	copy(result.dpopHTTPURIHash[:], storedDPoPURIHash)
	if consumed {
		return Challenge{}, ErrChallengeConsumed
	}
	if !store.now().UTC().Before(result.ExpiresAt) {
		return Challenge{}, ErrChallengeExpired
	}
	if result.Nonce == "" {
		return Challenge{}, ErrChallengeInvalid
	}
	nonceBytes, err := base64.RawURLEncoding.Strict().DecodeString(result.Nonce)
	if err != nil || len(nonceBytes) != 32 || base64.RawURLEncoding.EncodeToString(nonceBytes) != result.Nonce || len(storedNonceHash) != sha256.Size {
		return Challenge{}, ErrChallengeInvalid
	}
	nonceHash := sha256.Sum256(nonceBytes)
	if subtle.ConstantTimeCompare(storedNonceHash, nonceHash[:]) != 1 {
		return Challenge{}, ErrChallengeInvalid
	}
	result.DPoPPublicJWK, err = decodeStoredDPoPPublicJWK(encodedJWK, result.Binding.DPoPJKT)
	if err != nil {
		return Challenge{}, ErrChallengeInvalid
	}
	result.ID = challengeID
	result.Binding = attestation.Binding{
		Version: 1, ChallengeID: challengeID, ChallengeNonce: result.Nonce,
		ApplicationID: applicationID, Environment: environmentSlug, PrincipalID: applicationUserID,
		DPoPJKT: result.Binding.DPoPJKT, Platform: platform, IssuedAt: createdAt.UTC().Unix(),
	}
	reconstructedHash, err := result.Binding.Hash()
	if err != nil || len(storedBindingHash) != sha256.Size || subtle.ConstantTimeCompare(storedBindingHash, reconstructedHash[:]) != 1 {
		return Challenge{}, ErrChallengeInvalid
	}
	result.BindingHash = reconstructedHash
	if err := validateChallengeIdentity(ChallengeInput{
		OrganizationID: organizationID, ApplicationID: applicationID, EnvironmentID: result.EnvironmentID,
		EnvironmentSlug: environmentSlug, ApplicationUserID: applicationUserID,
		IdentityProvider: result.IdentityProvider, IdentityVerifiedAt: result.IdentityVerifiedAt,
		IdentityExpiresAt: result.IdentityExpiresAt, Platform: platform,
		DPoPJKT: result.Binding.DPoPJKT, DPoPPublicJWK: result.DPoPPublicJWK,
	}); err != nil {
		return Challenge{}, ErrChallengeInvalid
	}
	if store.configuration == nil {
		return Challenge{}, ErrSessionScope
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: organizationID,
		ApplicationID:  applicationID,
		EnvironmentID:  result.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != result.ConfigurationRevisionID {
		return Challenge{}, ErrSessionScope
	}
	if !challengeMatchesSnapshot(result, snapshot) {
		return Challenge{}, ErrChallengeInvalid
	}
	return result, nil
}

func challengeTextMember(members map[string]any, name string) string {
	value, _ := members[name].(string)
	return value
}

func decodeStoredDPoPPublicJWK(encoded []byte, expectedJKT string) (dpop.PublicJWK, error) {
	jwkValue, err := jsonsafe.Decode(encoded)
	if err != nil {
		return dpop.PublicJWK{}, ErrSessionInvalid
	}
	jwkMembers, ok := jwkValue.(map[string]any)
	if !ok || len(jwkMembers) != 4 {
		return dpop.PublicJWK{}, ErrSessionInvalid
	}
	jwk := dpop.PublicJWK{
		Kty: challengeTextMember(jwkMembers, "kty"),
		Crv: challengeTextMember(jwkMembers, "crv"),
		X:   challengeTextMember(jwkMembers, "x"),
		Y:   challengeTextMember(jwkMembers, "y"),
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil || !validThumbprint(expectedJKT) || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(expectedJKT)) != 1 {
		return dpop.PublicJWK{}, ErrSessionInvalid
	}
	return jwk, nil
}

func consumeChallenge(ctx context.Context, tx pgx.Tx, challenge Challenge, now time.Time) error {
	command, err := tx.Exec(ctx, `
		INSERT INTO session_challenge_consumptions (
			organization_id, application_id, environment_id, session_challenge_id, consumed_at
		)
		SELECT organization_id, application_id, environment_id, session_challenge_id, $2
		FROM session_challenges c
		WHERE c.session_challenge_id = $1
		  AND c.binding_hash = $3
		  AND c.config_revision_id = $4
		  AND c.attestation_policy_id = $5
		  AND c.attestation_provider = $6
		  AND c.attestation_mode = $7
		  AND c.attestation_minimum_trust_level = $8
		  AND c.attestation_maximum_age_milliseconds = $9
		  AND c.challenge_dpop_proof_jti_hash = $10
		  AND c.challenge_dpop_http_method = $11
		  AND c.challenge_dpop_http_uri_hash = $12
		  AND c.browser_origin = $13
		  AND c.expires_at > $2
		  AND EXISTS (
		      SELECT 1
		      FROM active_config_revisions active_revision
		      WHERE active_revision.organization_id = c.organization_id
		        AND active_revision.application_id = c.application_id
		        AND active_revision.environment_id = c.environment_id
		        AND active_revision.config_revision_id = c.config_revision_id
		  )
		  AND NOT EXISTS (
		      SELECT 1 FROM session_challenge_consumptions x
		      WHERE x.session_challenge_id = c.session_challenge_id
		  )
	`, challenge.ID, now, challenge.BindingHash[:], challenge.ConfigurationRevisionID,
		challenge.Attestation.ID, challenge.Attestation.Provider, challenge.Attestation.Mode,
		challenge.Attestation.MinimumTrustLevel, challenge.Attestation.MaximumAge.Milliseconds(),
		challenge.dpopProofJTIHash[:], challenge.dpopHTTPMethod, challenge.dpopHTTPURIHash[:],
		challenge.Origin)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrChallengeConsumed
		}
		return fmt.Errorf("consume session challenge: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrChallengeConsumed
	}
	return nil
}

func (store *ChallengeStore) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	cleanupNow := store.now().UTC()
	if cleanupNow.IsZero() || before.IsZero() || before.UTC().After(cleanupNow) || limit < 1 || limit > 10_000 {
		return 0, errors.New("challenge cleanup limit is invalid")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin expired challenge cleanup: %w", err)
	}
	defer rollbackSigning(tx)
	legacyBudget := limit
	if limit > 1 {
		// Reserve capacity for both challenge classes so a sustained root-session
		// backlog cannot starve direct-component challenge cleanup. Any unused
		// component capacity is filled from legacy challenges below.
		legacyBudget = (limit + 1) / 2
	}
	legacyDeleted, err := deleteExpiredSessionChallenges(
		ctx, tx, before.UTC(), cleanupNow, legacyBudget,
	)
	if err != nil {
		return 0, err
	}
	remaining := limit - int(legacyDeleted)
	componentDeleted, err := deleteExpiredComponentAttestationChallenges(
		ctx, tx, before.UTC(), remaining,
	)
	if err != nil {
		return 0, err
	}
	remaining -= int(componentDeleted)
	if remaining > 0 {
		additionalLegacy, deleteErr := deleteExpiredSessionChallenges(
			ctx, tx, before.UTC(), cleanupNow, remaining,
		)
		if deleteErr != nil {
			return 0, deleteErr
		}
		legacyDeleted += additionalLegacy
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit expired challenge cleanup: %w", err)
	}
	return legacyDeleted + componentDeleted, nil
}

func deleteExpiredSessionChallenges(
	ctx context.Context,
	tx pgx.Tx,
	before time.Time,
	cleanupNow time.Time,
	limit int,
) (int64, error) {
	if limit == 0 {
		return 0, nil
	}
	// Challenge rows also hold the pre-installation DPoP replay key. Retain
	// expired rows for the replay window so short challenge TTLs cannot make an
	// otherwise still-acceptable proof reusable after cleanup.
	rows, err := tx.Query(ctx, `
		SELECT session_challenge_id
		FROM session_challenges
		WHERE expires_at < $1
		  AND created_at < $3
		ORDER BY expires_at, session_challenge_id
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, before, limit, cleanupNow.Add(-defaultReplayLifetime))
	if err != nil {
		return 0, fmt.Errorf("select expired session challenges: %w", err)
	}
	challengeIDs := make([]string, 0, limit)
	for rows.Next() {
		var challengeID string
		if err := rows.Scan(&challengeID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired session challenge: %w", err)
		}
		challengeIDs = append(challengeIDs, challengeID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate expired session challenges: %w", err)
	}
	rows.Close()
	if len(challengeIDs) == 0 {
		return 0, nil
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM session_challenge_consumptions
		WHERE session_challenge_id = ANY($1)
	`, challengeIDs); err != nil {
		return 0, fmt.Errorf("delete expired challenge consumptions: %w", err)
	}
	command, err := tx.Exec(ctx, `
		DELETE FROM session_challenges
		WHERE session_challenge_id = ANY($1)
	`, challengeIDs)
	if err != nil {
		return 0, fmt.Errorf("delete expired session challenges: %w", err)
	}
	return command.RowsAffected(), nil
}

func deleteExpiredComponentAttestationChallenges(
	ctx context.Context,
	tx pgx.Tx,
	before time.Time,
	limit int,
) (int64, error) {
	if limit == 0 {
		return 0, nil
	}
	result, err := tx.Exec(ctx, `
		WITH doomed AS (
			SELECT component_attestation_challenge_id
			FROM component_attestation_challenges
			WHERE expires_at < $1
			ORDER BY expires_at, component_attestation_challenge_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM component_attestation_challenges AS challenge
		USING doomed
		WHERE challenge.component_attestation_challenge_id =
		      doomed.component_attestation_challenge_id
	`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired component attestation challenges: %w", err)
	}
	return result.RowsAffected(), nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isChallengeProofReplay(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "session_challenges_dpop_proof_unique"
}
