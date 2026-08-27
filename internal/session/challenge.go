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
	OrganizationID     string
	ApplicationID      string
	EnvironmentID      string
	EnvironmentSlug    string
	ApplicationUserID  string
	IdentityProvider   string
	IdentityVerifiedAt time.Time
	IdentityExpiresAt  time.Time
	Platform           string
	DPoPJKT            string
	DPoPPublicJWK      dpop.PublicJWK
}

func (input ChallengeInput) validate() error {
	if id.Validate(input.OrganizationID, id.Organization) != nil || id.Validate(input.ApplicationID, id.Application) != nil || id.Validate(input.EnvironmentID, id.Environment) != nil || id.Validate(input.ApplicationUserID, id.ApplicationUser) != nil || !sessionIdentifierPattern.MatchString(input.EnvironmentSlug) || !sessionIdentifierPattern.MatchString(input.IdentityProvider) || input.IdentityVerifiedAt.IsZero() || !input.IdentityExpiresAt.After(input.IdentityVerifiedAt) || !platformPattern.MatchString(input.Platform) || !validThumbprint(input.DPoPJKT) {
		return ErrChallengeInvalid
	}
	thumbprint, err := input.DPoPPublicJWK.Thumbprint()
	if err != nil || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(input.DPoPJKT)) != 1 {
		return ErrChallengeInvalid
	}
	return nil
}

var platformPattern = regexp.MustCompile(`^(ios|android|web|react_native_ios|react_native_android|node)$`)

type Challenge struct {
	ID                 string
	Nonce              string
	Binding            attestation.Binding
	BindingHash        [sha256.Size]byte
	DPoPPublicJWK      dpop.PublicJWK
	OrganizationID     string
	IdentityProvider   string
	IdentityVerifiedAt time.Time
	IdentityExpiresAt  time.Time
	EnvironmentID      string
	ExpiresAt          time.Time
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
	command, err := store.pool.Exec(ctx, `
		INSERT INTO session_challenges (
			session_challenge_id, organization_id, application_id, environment_id,
			application_user_id, identity_provider_key, platform, dpop_jkt,
			dpop_public_jwk, nonce_hash, binding_hash, challenge_nonce,
			identity_verified_at, identity_expires_at, created_at, expires_at
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
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
	`, challengeID, input.OrganizationID, input.ApplicationID, input.EnvironmentID, input.ApplicationUserID,
		input.IdentityProvider, input.Platform, input.DPoPJKT, encodedJWK, nonceHash[:],
		bindingHash[:], nonce, input.IdentityVerifiedAt.UTC(), input.IdentityExpiresAt.UTC(), now, expiresAt,
		input.EnvironmentSlug)
	if err != nil {
		return Challenge{}, fmt.Errorf("store session challenge: %w", err)
	}
	if command.RowsAffected() != 1 {
		return Challenge{}, ErrSessionScope
	}
	return Challenge{
		ID: challengeID, Nonce: nonce, Binding: binding, BindingHash: bindingHash,
		DPoPPublicJWK: input.DPoPPublicJWK, OrganizationID: input.OrganizationID,
		IdentityProvider: input.IdentityProvider, IdentityVerifiedAt: input.IdentityVerifiedAt.UTC(),
		IdentityExpiresAt: input.IdentityExpiresAt.UTC(),
		EnvironmentID:     input.EnvironmentID, ExpiresAt: expiresAt,
	}, nil
}

func (store *ChallengeStore) Get(ctx context.Context, challengeID string) (Challenge, error) {
	if id.Validate(challengeID, id.SessionChallenge) != nil {
		return Challenge{}, ErrChallengeInvalid
	}
	var result Challenge
	var organizationID, applicationID, applicationUserID, environmentSlug, platform string
	var encodedJWK []byte
	var storedNonceHash, storedBindingHash []byte
	var createdAt time.Time
	var identityVerifiedAt, identityExpiresAt *time.Time
	var consumed bool
	err := store.pool.QueryRow(ctx, `
		SELECT c.organization_id, c.application_id, c.environment_id, e.slug,
		       c.application_user_id, c.identity_provider_key, c.platform, c.dpop_jkt,
		       c.dpop_public_jwk, c.nonce_hash, c.binding_hash, c.challenge_nonce,
		       c.identity_verified_at, c.identity_expires_at, c.created_at, c.expires_at,
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
		&identityVerifiedAt, &identityExpiresAt, &createdAt, &result.ExpiresAt, &consumed,
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
	if err := (ChallengeInput{
		OrganizationID: organizationID, ApplicationID: applicationID, EnvironmentID: result.EnvironmentID,
		EnvironmentSlug: environmentSlug, ApplicationUserID: applicationUserID,
		IdentityProvider: result.IdentityProvider, IdentityVerifiedAt: result.IdentityVerifiedAt,
		IdentityExpiresAt: result.IdentityExpiresAt, Platform: platform,
		DPoPJKT: result.Binding.DPoPJKT, DPoPPublicJWK: result.DPoPPublicJWK,
	}).validate(); err != nil {
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
		  AND c.expires_at > $2
		  AND NOT EXISTS (
		      SELECT 1 FROM session_challenge_consumptions x
		      WHERE x.session_challenge_id = c.session_challenge_id
		  )
	`, challenge.ID, now, challenge.BindingHash[:])
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
	rows, err := tx.Query(ctx, `
		SELECT session_challenge_id
		FROM session_challenges
		WHERE expires_at < $1
		ORDER BY expires_at, session_challenge_id
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, before.UTC(), limit)
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
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("commit empty challenge cleanup: %w", err)
		}
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
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit expired challenge cleanup: %w", err)
	}
	return command.RowsAffected(), nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
