package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
)

var (
	ErrSessionInvalid            = errors.New("client session exchange is invalid")
	ErrSessionRevoked            = errors.New("client session is revoked")
	ErrInstallationRevoked       = errors.New("client installation is revoked")
	ErrRefreshInvalid            = errors.New("refresh token is invalid")
	ErrRefreshReused             = errors.New("rotated refresh token was reused")
	ErrIdentityRefreshRequired   = errors.New("fresh external identity proof is required")
	ErrAttestationRefreshNeeded  = errors.New("fresh application attestation is required")
	ErrAttestationStepUpRequired = errors.New("current application attestation policy requires step-up")
)

var keyStoragePattern = regexp.MustCompile(`^(unknown|secure_enclave|keychain|strongbox|tee|software|webcrypto|memory)$`)

// PreparedAccessIssuer signs with key material resolved before a session
// transaction begins and therefore performs no database work.
type PreparedAccessIssuer interface {
	IssueFor(AccessIssueInput, time.Duration) (IssuedAccess, error)
	preparedAccessIssuer()
}

// AccessIssuer prepares an access-token signer before session code opens a
// database transaction.
type AccessIssuer interface {
	Prepare(context.Context) (PreparedAccessIssuer, error)
}

type StoreConfig struct {
	Pool          *pgxpool.Pool
	AccessTokens  AccessIssuer
	Configuration *configuration.Store
	Now           func() time.Time
	Random        io.Reader
}

type Store struct {
	pool          *pgxpool.Pool
	accessTokens  AccessIssuer
	configuration *configuration.Store
	replay        *ReplayStore
	now           func() time.Time
	random        io.Reader
}

func NewStore(config StoreConfig) (*Store, error) {
	if config.Pool == nil || config.AccessTokens == nil || config.Configuration == nil {
		return nil, errors.New("session store dependency is nil")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	replay, err := NewReplayStore(ReplayStoreConfig{Pool: config.Pool, Now: config.Now})
	if err != nil {
		return nil, err
	}
	return &Store{
		pool: config.Pool, accessTokens: config.AccessTokens, configuration: config.Configuration,
		replay: replay, now: config.Now, random: config.Random,
	}, nil
}

type RefreshToken struct {
	value string
}

func NewRefreshToken(value string) (RefreshToken, error) {
	if len(value) < 32 || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return RefreshToken{}, ErrRefreshInvalid
	}
	return RefreshToken{value: value}, nil
}

func (RefreshToken) String() string       { return "[REDACTED]" }
func (RefreshToken) GoString() string     { return "session.RefreshToken{[REDACTED]}" }
func (token RefreshToken) Reveal() string { return token.value }

type Installation struct {
	ID         string
	Platform   string
	DPoPJKT    string
	Status     string
	AppVersion string
}

type Trust struct {
	Provider   string
	Level      string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type IssuedSession struct {
	Access           IssuedAccess
	Refresh          RefreshToken
	RefreshID        string
	RefreshFamilyID  string
	RefreshExpiresAt time.Time
	GrantID          string
	Installation     Installation
	Trust            Trust
}

type ExchangeInput struct {
	ChallengeID string
	Attestation attestation.Result
	DPoPProof   DPoPProof
	HTTPMethod  string
	RequestURI  *url.URL
	KeyStorage  string
	AppVersion  string

	challenge        Challenge
	attestation      attestation.Result
	policyRevisionID string
	sessionPolicy    configuration.SessionPolicy
}

func (input ExchangeInput) validate() error {
	appVersionLength := utf8.RuneCountInString(input.AppVersion)
	if id.Validate(input.ChallengeID, id.SessionChallenge) != nil || input.DPoPProof.value == "" || input.HTTPMethod == "" || input.RequestURI == nil || !keyStoragePattern.MatchString(input.KeyStorage) || !utf8.ValidString(input.AppVersion) || appVersionLength < 1 || appVersionLength > 128 || strings.TrimSpace(input.AppVersion) != input.AppVersion {
		return ErrSessionInvalid
	}
	return nil
}

func (store *Store) Exchange(ctx context.Context, input ExchangeInput) (IssuedSession, error) {
	now := store.now().UTC().Truncate(time.Second)
	if err := input.validate(); err != nil {
		return IssuedSession{}, err
	}
	challengeStore := &ChallengeStore{pool: store.pool, configuration: store.configuration, now: store.now}
	challenge, err := challengeStore.Get(ctx, input.ChallengeID)
	if err != nil {
		return IssuedSession{}, err
	}
	if !challenge.IdentityExpiresAt.After(now) {
		return IssuedSession{}, ErrIdentityRefreshRequired
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: challenge.OrganizationID,
		ApplicationID:  challenge.Binding.ApplicationID,
		EnvironmentID:  challenge.EnvironmentID,
	})
	if err != nil {
		return IssuedSession{}, ErrSessionScope
	}
	if !challengeMatchesSnapshot(challenge, snapshot) {
		return IssuedSession{}, ErrSessionScope
	}
	verifiedAttestation, err := input.Attestation.ValidatedSnapshot(challenge.BindingHash, now)
	if err != nil {
		return IssuedSession{}, ErrSessionInvalid
	}
	if !challengeAttestationAllows(challenge.Attestation, verifiedAttestation, now) {
		return IssuedSession{}, ErrSessionInvalid
	}
	if !replayMethodPattern.MatchString(input.HTTPMethod) {
		return IssuedSession{}, ErrSessionInvalid
	}
	validatedProof, err := dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI, ExpectedJKT: challenge.Binding.DPoPJKT,
		Now: now, ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	normalizedURI, err := dpop.NormalizeHTU(input.RequestURI)
	if err != nil {
		return IssuedSession{}, ErrSessionInvalid
	}
	input.challenge = challenge
	input.attestation = verifiedAttestation
	input.policyRevisionID = snapshot.RevisionID
	input.sessionPolicy = snapshot.SessionPolicy()
	installationCandidate, err := id.New(id.Installation)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate installation ID: %w", err)
	}
	grantID, err := id.New(id.SessionGrant)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate session-grant ID: %w", err)
	}
	eventID, err := id.New(id.AttestationEvent)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate attestation-event ID: %w", err)
	}
	refresh, refreshID, familyID, refreshHash, err := store.newRefreshCredential()
	if err != nil {
		return IssuedSession{}, err
	}
	encodedJWK, err := json.Marshal(input.challenge.DPoPPublicJWK)
	if err != nil {
		return IssuedSession{}, ErrSessionInvalid
	}
	encodedSignals, err := json.Marshal(input.attestation.NormalizedSignals)
	if err != nil {
		return IssuedSession{}, ErrSessionInvalid
	}
	preparedAccess, err := store.accessTokens.Prepare(ctx)
	if err != nil {
		return IssuedSession{}, err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin session exchange: %w", err)
	}
	defer rollbackSigning(tx)
	if err := consumeChallenge(ctx, tx, input.challenge, now); err != nil {
		return IssuedSession{}, err
	}
	installation, trustChanged, err := upsertInstallation(ctx, tx, installationCandidate, input, encodedJWK, now)
	if err != nil {
		return IssuedSession{}, err
	}
	if err := linkAppAttestKey(ctx, tx, installation.ID, input, now); err != nil {
		return IssuedSession{}, err
	}
	if trustChanged {
		if err := revokeInstallationSessionsForTrustChange(ctx, tx, installation.ID, now); err != nil {
			return IssuedSession{}, err
		}
	}
	issuedAccess, err := preparedAccess.IssueFor(AccessIssueInput{
		OrganizationID: input.challenge.OrganizationID, ApplicationID: input.challenge.Binding.ApplicationID,
		EnvironmentID: input.challenge.EnvironmentID, ApplicationUserID: input.challenge.Binding.PrincipalID,
		InstallationID: installation.ID, SessionGrantID: grantID,
		IdentityProvider: input.challenge.IdentityProvider, TrustLevel: input.attestation.TrustLevel,
		PolicyRevisionID: input.policyRevisionID, DPoPJKT: input.challenge.Binding.DPoPJKT,
	}, input.sessionPolicy.AccessTokenTTL)
	if err != nil {
		return IssuedSession{}, err
	}
	issuedAt := latestTime(now, issuedAccess.IssuedAt)
	if !issuedAccess.ExpiresAt.After(issuedAt) {
		return IssuedSession{}, ErrSessionInvalid
	}
	if err := insertAttestationEvent(ctx, tx, eventID, installation.ID, input, encodedSignals); err != nil {
		return IssuedSession{}, err
	}
	if err := insertSessionGrant(ctx, tx, grantID, installation.ID, input, issuedAccess, issuedAt); err != nil {
		return IssuedSession{}, err
	}
	if err := store.replay.accept(ctx, tx, ReplayInput{
		OrganizationID: input.challenge.OrganizationID,
		ApplicationID:  input.challenge.Binding.ApplicationID,
		EnvironmentID:  input.challenge.EnvironmentID,
		InstallationID: installation.ID,
		SessionGrantID: grantID,
		ProofJTI:       validatedProof.JTI,
		HTTPMethod:     input.HTTPMethod,
		NormalizedURI:  normalizedURI,
	}); err != nil {
		return IssuedSession{}, err
	}
	refreshExpiresAt := issuedAt.Add(input.sessionPolicy.RefreshTokenTTL)
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (
			refresh_token_id, family_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, session_grant_id, token_hash,
			status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11)
	`, refreshID, familyID, input.challenge.OrganizationID, input.challenge.Binding.ApplicationID,
		input.challenge.EnvironmentID, input.challenge.Binding.PrincipalID, installation.ID, grantID,
		refreshHash[:], issuedAt, refreshExpiresAt); err != nil {
		return IssuedSession{}, fmt.Errorf("store initial refresh token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit session exchange: %w", err)
	}
	return IssuedSession{
		Access: issuedAccess, Refresh: refresh, RefreshID: refreshID, RefreshFamilyID: familyID,
		RefreshExpiresAt: refreshExpiresAt, GrantID: grantID, Installation: installation,
		Trust: Trust{Provider: input.attestation.Provider, Level: input.attestation.TrustLevel, VerifiedAt: input.attestation.VerifiedAt, ExpiresAt: input.attestation.ExpiresAt},
	}, nil
}

// linkAppAttestKey completes the two-phase App Attest lifecycle in the same
// transaction that creates the installation and session grant. The sealed
// verifier result is the only source of provider key identity; every other
// predicate is reconstructed from the authoritative challenge. A key may be
// linked repeatedly only to the exact same installation.
func linkAppAttestKey(ctx context.Context, tx pgx.Tx, installationID string, input ExchangeInput, now time.Time) error {
	if input.attestation.Provider != "app_attest" {
		return nil
	}
	keyID, ok := input.attestation.AppAttestKeyID()
	if !ok || id.Validate(installationID, id.Installation) != nil || now.IsZero() {
		return ErrSessionInvalid
	}
	command, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET installation_id = $1,
		    linked_at = CASE
		        WHEN linked_at IS NULL THEN GREATEST(created_at, transaction_timestamp(), $10)
		        ELSE linked_at
		    END,
		    updated_at = GREATEST(updated_at, transaction_timestamp(), $10)
		WHERE provider = 'app_attest'
		  AND provider_key_hash = $2
		  AND organization_id = $3
		  AND application_id = $4
		  AND environment_id = $5
		  AND application_user_id = $6
		  AND binding_environment = $7
		  AND platform = $8
		  AND dpop_jkt = $9
		  AND status = 'active'
		  AND (
		      (installation_id IS NULL AND linked_at IS NULL)
		      OR (installation_id = $1 AND linked_at IS NOT NULL)
		  )
	`, installationID, keyID[:], input.challenge.OrganizationID,
		input.challenge.Binding.ApplicationID, input.challenge.EnvironmentID,
		input.challenge.Binding.PrincipalID, input.challenge.Binding.Environment,
		input.challenge.Binding.Platform, input.challenge.Binding.DPoPJKT, now)
	if err != nil {
		return fmt.Errorf("link App Attest key to installation: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSessionInvalid
	}
	return nil
}

func challengeAttestationAllows(policy ChallengeAttestationPolicy, result attestation.Result, now time.Time) bool {
	if !validAttestationProvider(policy.Provider) ||
		policy.Mode != "required" ||
		!trustLevelPattern.MatchString(policy.MinimumTrustLevel) ||
		policy.MaximumAge < time.Minute || policy.MaximumAge > 30*24*time.Hour ||
		result.Provider != policy.Provider || now.IsZero() ||
		!result.VerifiedAt.Add(policy.MaximumAge).After(now) {
		return false
	}
	return trustSatisfies(result.TrustLevel, policy.MinimumTrustLevel)
}

// trustSatisfies keeps debug evidence outside the production assurance order.
// The remaining values form the explicit order documented by the trust model;
// unknown values fail closed instead of receiving a default rank.
func trustSatisfies(actual, minimum string) bool {
	if actual == "debug" || minimum == "debug" {
		return actual == minimum
	}
	actualRank, actualOK := trustRank(actual)
	minimumRank, minimumOK := trustRank(minimum)
	return actualOK && minimumOK && actualRank >= minimumRank
}

// TrustSatisfies applies the canonical attestation assurance ordering. Debug
// evidence remains deliberately incomparable with non-debug trust, and every
// unknown value fails closed. Feature-policy enforcement uses this function so
// challenge, refresh and request-time decisions cannot drift apart.
func TrustSatisfies(actual, minimum string) bool {
	return trustSatisfies(actual, minimum)
}

func trustRank(level string) (int, bool) {
	switch level {
	case "none":
		return 0, true
	case "identity_only":
		return 1, true
	case "web_risk_verified":
		return 2, true
	case "app_verified":
		return 3, true
	case "device_verified":
		return 4, true
	case "strong_device_verified":
		return 5, true
	default:
		return 0, false
	}
}

func upsertInstallation(ctx context.Context, tx pgx.Tx, candidate string, input ExchangeInput, encodedJWK []byte, now time.Time) (Installation, bool, error) {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", input.challenge.EnvironmentID+":"+input.challenge.Binding.DPoPJKT); err != nil {
		return Installation{}, false, fmt.Errorf("lock installation DPoP binding: %w", err)
	}
	var previousInstallationID, previousTrustLevel string
	previousExists := true
	if err := tx.QueryRow(ctx, `
		SELECT installation_id, trust_level
		FROM installations
		WHERE environment_id = $1 AND dpop_jkt = $2
		FOR UPDATE
	`, input.challenge.EnvironmentID, input.challenge.Binding.DPoPJKT).Scan(
		&previousInstallationID, &previousTrustLevel,
	); errors.Is(err, pgx.ErrNoRows) {
		previousExists = false
	} else if err != nil {
		return Installation{}, false, fmt.Errorf("lock installation trust state: %w", err)
	}
	var result Installation
	err := tx.QueryRow(ctx, `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id, application_user_id,
			platform, dpop_jkt, dpop_public_jwk, key_storage, trust_level, app_version,
			created_at, updated_at, last_seen_at
		)
		SELECT $1, c.organization_id, c.application_id, c.environment_id, c.application_user_id,
		       c.platform, c.dpop_jkt, $2, $3, $4, $5, $6, $6, $6
		FROM session_challenges c
		JOIN organizations o ON o.organization_id = c.organization_id AND o.status = 'active'
		JOIN applications a ON a.organization_id = c.organization_id AND a.application_id = c.application_id AND a.status = 'active'
		JOIN environments e ON e.organization_id = c.organization_id AND e.application_id = c.application_id AND e.environment_id = c.environment_id AND e.status = 'active'
		JOIN application_users u ON u.organization_id = c.organization_id AND u.application_id = c.application_id AND u.application_user_id = c.application_user_id AND u.status = 'active'
		WHERE c.session_challenge_id = $7 AND c.binding_hash = $8 AND c.dpop_jkt = $9
		ON CONFLICT (environment_id, dpop_jkt) DO UPDATE
		SET dpop_public_jwk = EXCLUDED.dpop_public_jwk,
		    key_storage = EXCLUDED.key_storage,
		    trust_level = EXCLUDED.trust_level,
		    app_version = EXCLUDED.app_version,
		    updated_at = EXCLUDED.updated_at,
		    last_seen_at = EXCLUDED.last_seen_at
		WHERE installations.organization_id = EXCLUDED.organization_id
		  AND installations.application_id = EXCLUDED.application_id
		  AND installations.environment_id = EXCLUDED.environment_id
		  AND installations.application_user_id = EXCLUDED.application_user_id
		  AND installations.platform = EXCLUDED.platform
		  AND installations.status = 'active'
		RETURNING installation_id, platform, dpop_jkt, status, app_version
	`, candidate, encodedJWK, input.KeyStorage, input.attestation.TrustLevel, input.AppVersion, now,
		input.challenge.ID, input.challenge.BindingHash[:], input.challenge.Binding.DPoPJKT).Scan(
		&result.ID, &result.Platform, &result.DPoPJKT, &result.Status, &result.AppVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, false, ErrInstallationRevoked
	}
	if err != nil {
		return Installation{}, false, fmt.Errorf("create or update installation: %w", err)
	}
	trustChanged := previousExists && previousInstallationID == result.ID && previousTrustLevel != input.attestation.TrustLevel
	return result, trustChanged, nil
}

func revokeInstallationSessionsForTrustChange(ctx context.Context, tx pgx.Tx, installationID string, now time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = GREATEST(issued_at, $2)
		WHERE installation_id = $1 AND status IN ('staged', 'active')
	`, installationID, now); err != nil {
		return fmt.Errorf("revoke refresh tokens after installation trust change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = GREATEST(issued_at, $2), revoke_reason = 'attestation_trust_changed'
		WHERE installation_id = $1 AND revoked_at IS NULL
	`, installationID, now); err != nil {
		return fmt.Errorf("revoke session grants after installation trust change: %w", err)
	}
	return nil
}

func insertAttestationEvent(ctx context.Context, tx pgx.Tx, eventID, installationID string, input ExchangeInput, encodedSignals []byte) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO attestation_events (
			attestation_event_id, organization_id, application_id, environment_id,
			installation_id, session_challenge_id, provider, outcome, trust_level,
			evidence_hash, normalized_signals, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'accepted', $8, $9, $10, $11)
	`, eventID, input.challenge.OrganizationID, input.challenge.Binding.ApplicationID,
		input.challenge.EnvironmentID, installationID, input.challenge.ID, input.attestation.Provider,
		input.attestation.TrustLevel, input.attestation.EvidenceHash[:], encodedSignals, input.attestation.VerifiedAt); err != nil {
		return fmt.Errorf("record accepted attestation: %w", err)
	}
	return nil
}

func insertSessionGrant(ctx context.Context, tx pgx.Tx, grantID, installationID string, input ExchangeInput, access IssuedAccess, issuedAt time.Time) error {
	command, err := tx.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
			policy_revision_id, trust_level, identity_provider_key,
			identity_verified_at, identity_expires_at,
			attested_at, attestation_provider, attestation_expires_at,
			issued_at, expires_at
		)
		SELECT $1, c.organization_id, c.application_id, c.environment_id,
		       c.application_user_id, $2, $3, c.dpop_jkt, $4, $5,
		       c.identity_provider_key, $6, $7, $8, $9, $10, $11, $12
		FROM session_challenges c
		JOIN active_config_revisions active_revision
		  ON active_revision.organization_id = c.organization_id
		 AND active_revision.application_id = c.application_id
		 AND active_revision.environment_id = c.environment_id
		 AND active_revision.config_revision_id = $4
		JOIN installations i
		  ON i.organization_id = c.organization_id AND i.application_id = c.application_id
		 AND i.environment_id = c.environment_id AND i.installation_id = $2 AND i.status = 'active'
		JOIN application_users u
		  ON u.organization_id = c.organization_id AND u.application_id = c.application_id
		 AND u.application_user_id = c.application_user_id AND u.status = 'active'
		WHERE c.session_challenge_id = $13
		  AND c.binding_hash = $14
		  AND c.config_revision_id = $4
	`, grantID, installationID, access.JTIHash[:], input.policyRevisionID, input.attestation.TrustLevel,
		notAfter(input.challenge.IdentityVerifiedAt, issuedAt), input.challenge.IdentityExpiresAt,
		notAfter(input.attestation.VerifiedAt, issuedAt),
		input.attestation.Provider, input.attestation.ExpiresAt, issuedAt, access.ExpiresAt,
		input.challenge.ID, input.challenge.BindingHash[:])
	if err != nil {
		return fmt.Errorf("store session grant: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSessionScope
	}
	return nil
}

func (store *Store) newRefreshCredential() (RefreshToken, string, string, [sha256.Size]byte, error) {
	familyID, err := id.New(id.RefreshTokenFamily)
	if err != nil {
		return RefreshToken{}, "", "", [sha256.Size]byte{}, fmt.Errorf("generate refresh-token family ID: %w", err)
	}
	token, refreshID, digest, err := store.newRefreshToken()
	return token, refreshID, familyID, digest, err
}

func (store *Store) newRefreshToken() (RefreshToken, string, [sha256.Size]byte, error) {
	refreshID, err := id.New(id.RefreshToken)
	if err != nil {
		return RefreshToken{}, "", [sha256.Size]byte{}, fmt.Errorf("generate refresh-token ID: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(store.random, secret); err != nil {
		return RefreshToken{}, "", [sha256.Size]byte{}, errors.New("generate refresh-token credential")
	}
	value := base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	token, err := NewRefreshToken(value)
	if err != nil {
		return RefreshToken{}, "", [sha256.Size]byte{}, err
	}
	return token, refreshID, sha256.Sum256([]byte(value)), nil
}

func latestTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value.UTC()
		}
	}
	return latest
}

func notAfter(value, ceiling time.Time) time.Time {
	if value.After(ceiling) {
		return ceiling.UTC()
	}
	return value.UTC()
}
