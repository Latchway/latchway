package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
)

const clientInstallationRevocationReason = "client_installation_revoked"

type Authorization struct {
	OrganizationID       string
	ApplicationID        string
	EnvironmentID        string
	ApplicationUserID    string
	InstallationID       string
	SessionGrantID       string
	PolicyRevisionID     string
	IdentityProvider     string
	DPoPJKT              string
	TrustLevel           string
	AttestationProvider  string
	IdentityExpiresAt    time.Time
	AttestationExpiresAt time.Time
	AccessExpiresAt      time.Time
}

type authorizationState struct {
	Authorization
	grantRevoked       bool
	installationStatus string
	installationTrust  string
	userStatus         string
	applicationStatus  string
	environmentStatus  string
	organizationStatus string
}

func (store *Store) Authorize(ctx context.Context, principal AccessPrincipal) (Authorization, error) {
	now := store.now().UTC()
	if err := validateAccessPrincipal(principal, now); err != nil {
		return Authorization{}, err
	}
	state, err := loadAuthorizationState(ctx, store.pool, principal, "")
	if err != nil {
		return Authorization{}, err
	}
	if err := authorizationStateError(state, now, false); err != nil {
		return Authorization{}, err
	}
	return state.Authorization, nil
}

type authorizationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadAuthorizationState(ctx context.Context, query authorizationQuerier, principal AccessPrincipal, lockClause string) (authorizationState, error) {
	var result authorizationState
	var storedJTIHash []byte
	var grantExpiresAt, identityExpiresAt, attestedAt, attestationExpiresAt *time.Time
	statement := `
		SELECT g.organization_id, g.application_id, g.environment_id, g.application_user_id,
		       g.installation_id, g.session_grant_id, g.policy_revision_id, g.dpop_jkt,
		       g.trust_level, g.identity_provider_key, g.access_token_jti_hash,
		       g.expires_at, g.identity_expires_at,
		       g.attested_at, g.attestation_provider, g.attestation_expires_at,
		       g.revoked_at IS NOT NULL, i.status, i.trust_level,
		       u.status, a.status, e.status, o.status
		FROM session_grants g
		JOIN installations i
		  ON i.organization_id = g.organization_id AND i.application_id = g.application_id
		 AND i.environment_id = g.environment_id AND i.installation_id = g.installation_id
		JOIN application_users u
		  ON u.organization_id = g.organization_id AND u.application_id = g.application_id
		 AND u.application_user_id = g.application_user_id
		JOIN applications a ON a.organization_id = g.organization_id AND a.application_id = g.application_id
		JOIN environments e
		  ON e.organization_id = g.organization_id AND e.application_id = g.application_id
		 AND e.environment_id = g.environment_id
		JOIN organizations o ON o.organization_id = g.organization_id
		WHERE g.session_grant_id = $1
	` + lockClause
	err := query.QueryRow(ctx, statement, principal.SessionGrantID).Scan(
		&result.OrganizationID, &result.ApplicationID, &result.EnvironmentID, &result.ApplicationUserID,
		&result.InstallationID, &result.SessionGrantID, &result.PolicyRevisionID, &result.DPoPJKT,
		&result.TrustLevel, &result.IdentityProvider, &storedJTIHash, &grantExpiresAt, &identityExpiresAt,
		&attestedAt, &result.AttestationProvider, &attestationExpiresAt,
		&result.grantRevoked, &result.installationStatus, &result.installationTrust,
		&result.userStatus, &result.applicationStatus, &result.environmentStatus,
		&result.organizationStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return authorizationState{}, ErrSessionInvalid
	}
	if err != nil {
		return authorizationState{}, fmt.Errorf("authorize client session: %w", err)
	}
	if grantExpiresAt == nil || identityExpiresAt == nil || attestedAt == nil || attestationExpiresAt == nil || len(storedJTIHash) != sha256.Size {
		return authorizationState{}, ErrSessionInvalid
	}
	result.IdentityExpiresAt = identityExpiresAt.UTC()
	result.AttestationExpiresAt = attestationExpiresAt.UTC()
	result.AccessExpiresAt = grantExpiresAt.UTC()
	if validateAuthorizationIDs(result.Authorization) != nil || !sessionIdentifierPattern.MatchString(result.IdentityProvider) || !sessionIdentifierPattern.MatchString(result.AttestationProvider) || !trustLevelPattern.MatchString(result.TrustLevel) || !validThumbprint(result.DPoPJKT) {
		return authorizationState{}, ErrSessionInvalid
	}
	if subtle.ConstantTimeCompare(storedJTIHash, principal.JTIHash[:]) != 1 ||
		result.OrganizationID != principal.OrganizationID || result.ApplicationID != principal.ApplicationID ||
		result.EnvironmentID != principal.EnvironmentID || result.ApplicationUserID != principal.ApplicationUserID ||
		result.InstallationID != principal.InstallationID || result.PolicyRevisionID != principal.PolicyRevisionID ||
		result.DPoPJKT != principal.DPoPJKT || result.TrustLevel != principal.TrustLevel ||
		result.IdentityProvider != principal.IdentityProvider || !result.AccessExpiresAt.Equal(principal.ExpiresAt) {
		return authorizationState{}, ErrSessionInvalid
	}
	return result, nil
}

func authorizationStateError(state authorizationState, now time.Time, allowRevokedInstallation bool) error {
	if state.installationStatus == "revoked" && allowRevokedInstallation {
		return nil
	}
	if state.installationStatus != "active" {
		if state.installationStatus == "revoked" {
			return ErrInstallationRevoked
		}
		return ErrSessionInvalid
	}
	if state.grantRevoked || state.installationTrust != state.TrustLevel || state.userStatus != "active" || state.applicationStatus != "active" || state.environmentStatus != "active" || state.organizationStatus != "active" {
		return ErrSessionRevoked
	}
	if !state.AccessExpiresAt.After(now) || !state.IdentityExpiresAt.After(now) {
		return ErrTokenExpired
	}
	if !state.AttestationExpiresAt.After(now) {
		return ErrAttestationRefreshNeeded
	}
	return nil
}

func validateAccessPrincipal(principal AccessPrincipal, now time.Time) error {
	input := AccessIssueInput{
		OrganizationID: principal.OrganizationID, ApplicationID: principal.ApplicationID,
		EnvironmentID: principal.EnvironmentID, ApplicationUserID: principal.ApplicationUserID,
		InstallationID: principal.InstallationID, SessionGrantID: principal.SessionGrantID,
		IdentityProvider: principal.IdentityProvider, TrustLevel: principal.TrustLevel,
		PolicyRevisionID: principal.PolicyRevisionID, DPoPJKT: principal.DPoPJKT,
	}
	if !accessPrincipalSealValid(principal) || input.validate() != nil ||
		principal.JTIHash == ([sha256.Size]byte{}) || principal.tokenHash == ([sha256.Size]byte{}) ||
		principal.IssuedAt.IsZero() || !principal.ExpiresAt.After(principal.IssuedAt) {
		return ErrSessionInvalid
	}
	if !principal.ExpiresAt.After(now) {
		return ErrTokenExpired
	}
	return nil
}

// AccessRequestInput carries a signature-verified access principal together
// with the exact bearer token and RFC 9449 request proof. The principal seal
// prevents callers from manufacturing or changing signed claims after token
// verification, while the raw token is used only to validate the proof's ath.
type AccessRequestInput struct {
	AccessToken AccessToken
	Principal   AccessPrincipal
	DPoPProof   DPoPProof
	HTTPMethod  string
	RequestURI  *url.URL
}

type accessRequestMutation func(context.Context, pgx.Tx, authorizationState, time.Time) error

// AuthorizeAccess verifies exact method, URI, access-token hash and DPoP-key
// bindings, checks current durable session scope, and accepts the proof replay
// key in the same transaction. It is the reusable authorization primitive for
// protected client operations that do not need an additional database write
// in that transaction.
func (store *Store) AuthorizeAccess(ctx context.Context, input AccessRequestInput) (Authorization, error) {
	state, err := store.authorizeAccess(ctx, input, false, false, nil)
	if err != nil {
		return Authorization{}, err
	}
	return state.Authorization, nil
}

// RevokeCurrentInstallation authenticates the request and atomically records
// its replay key before revoking the bound installation and every live session
// credential beneath it. A still-valid access token with a fresh proof may
// repeat the operation after revocation; mismatched state and replayed proofs
// remain failures.
func (store *Store) RevokeCurrentInstallation(ctx context.Context, input AccessRequestInput) error {
	_, err := store.authorizeAccess(ctx, input, true, true, revokeCurrentInstallation)
	return err
}

func (store *Store) authorizeAccess(ctx context.Context, input AccessRequestInput, allowRevokedInstallation, mutationLock bool, mutation accessRequestMutation) (authorizationState, error) {
	now := store.now().UTC()
	if err := validateAccessPrincipal(input.Principal, now); err != nil {
		return authorizationState{}, err
	}
	if input.AccessToken.value == "" || input.DPoPProof.value == "" ||
		!replayMethodPattern.MatchString(input.HTTPMethod) || input.RequestURI == nil {
		return authorizationState{}, ErrSessionInvalid
	}
	if _, err := NewAccessToken(input.AccessToken.value); err != nil {
		return authorizationState{}, ErrTokenInvalid
	}
	accessTokenHash := sha256.Sum256([]byte(input.AccessToken.value))
	if subtle.ConstantTimeCompare(accessTokenHash[:], input.Principal.tokenHash[:]) != 1 {
		return authorizationState{}, ErrTokenInvalid
	}
	if _, err := NewDPoPProof(input.DPoPProof.value); err != nil {
		return authorizationState{}, err
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: input.Principal.OrganizationID,
		ApplicationID:  input.Principal.ApplicationID,
		EnvironmentID:  input.Principal.EnvironmentID,
	})
	if errors.Is(err, configuration.ErrInvalid) || errors.Is(err, configuration.ErrNotFound) {
		return authorizationState{}, ErrSessionScope
	}
	if err != nil {
		return authorizationState{}, fmt.Errorf("resolve access-request policy: %w", err)
	}
	validatedProof, err := dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI,
		AccessToken: input.AccessToken.value, ExpectedJKT: input.Principal.DPoPJKT,
		Now: now, ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
		RequireAccessHash: true,
	})
	if err != nil {
		return authorizationState{}, err
	}
	normalizedURI, err := dpop.NormalizeHTU(input.RequestURI)
	if err != nil {
		return authorizationState{}, ErrSessionInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return authorizationState{}, fmt.Errorf("begin access authorization: %w", err)
	}
	defer rollbackSigning(tx)
	if err := lockAccessInstallation(ctx, tx, input.Principal, mutationLock); err != nil {
		return authorizationState{}, err
	}
	lockClause := " FOR SHARE OF g, u, a, e, o"
	if mutationLock {
		lockClause = " FOR UPDATE OF g FOR SHARE OF u, a, e, o"
	}
	state, err := loadAuthorizationState(ctx, tx, input.Principal, lockClause)
	if err != nil {
		return authorizationState{}, err
	}
	if err := authorizationStateError(state, now, allowRevokedInstallation); err != nil {
		return authorizationState{}, err
	}
	if err := store.replay.accept(ctx, tx, ReplayInput{
		OrganizationID: state.OrganizationID, ApplicationID: state.ApplicationID,
		EnvironmentID: state.EnvironmentID, InstallationID: state.InstallationID,
		SessionGrantID: state.SessionGrantID, ProofJTI: validatedProof.JTI,
		HTTPMethod: input.HTTPMethod, NormalizedURI: normalizedURI,
	}); err != nil {
		return authorizationState{}, err
	}
	if mutation != nil {
		if err := mutation(ctx, tx, state, now); err != nil {
			return authorizationState{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return authorizationState{}, fmt.Errorf("commit access authorization: %w", err)
	}
	return state, nil
}

func lockAccessInstallation(ctx context.Context, tx pgx.Tx, principal AccessPrincipal, exclusive bool) error {
	lockClause := "FOR SHARE"
	if exclusive {
		lockClause = "FOR UPDATE"
	}
	var storedJKT, status string
	err := tx.QueryRow(ctx, `
		SELECT dpop_jkt, status
		FROM installations
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5
	`+lockClause, principal.OrganizationID, principal.ApplicationID, principal.EnvironmentID,
		principal.ApplicationUserID, principal.InstallationID).Scan(&storedJKT, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionInvalid
	}
	if err != nil {
		return fmt.Errorf("lock access installation: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedJKT), []byte(principal.DPoPJKT)) != 1 || (status != "active" && status != "revoked") {
		return ErrSessionInvalid
	}
	return nil
}

func revokeCurrentInstallation(ctx context.Context, tx pgx.Tx, state authorizationState, now time.Time) error {
	command, err := tx.Exec(ctx, `
		UPDATE installations
		SET status = 'revoked',
		    revoked_at = GREATEST(created_at, updated_at, last_seen_at, $2),
		    revoke_reason = $3,
		    updated_at = GREATEST(created_at, updated_at, last_seen_at, $2),
		    last_seen_at = GREATEST(created_at, updated_at, last_seen_at, $2)
		WHERE organization_id = $4 AND application_id = $5 AND environment_id = $6
		  AND application_user_id = $7 AND installation_id = $1 AND status = 'active'
	`, state.InstallationID, now, clientInstallationRevocationReason,
		state.OrganizationID, state.ApplicationID, state.EnvironmentID, state.ApplicationUserID)
	if err != nil {
		return fmt.Errorf("revoke installation: %w", err)
	}
	if command.RowsAffected() > 1 || (state.installationStatus == "active" && command.RowsAffected() != 1) || (state.installationStatus == "revoked" && command.RowsAffected() != 0) {
		return ErrSessionInvalid
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2)),
		    revoke_reason = COALESCE(revoke_reason, $3)
		WHERE organization_id = $4 AND application_id = $5 AND environment_id = $6
		  AND installation_id = $1 AND revoked_at IS NULL
	`, state.InstallationID, now, clientInstallationRevocationReason,
		state.OrganizationID, state.ApplicationID, state.EnvironmentID); err != nil {
		return fmt.Errorf("revoke installation session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2))
		WHERE organization_id = $3 AND application_id = $4 AND environment_id = $5
		  AND installation_id = $1 AND status IN ('staged', 'active')
	`, state.InstallationID, now, state.OrganizationID, state.ApplicationID, state.EnvironmentID); err != nil {
		return fmt.Errorf("revoke installation refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET status = 'revoked', revoked_at = GREATEST(created_at, $2),
		    updated_at = GREATEST(updated_at, created_at, $2)
		WHERE organization_id = $3 AND application_id = $4 AND environment_id = $5
		  AND installation_id = $1 AND status <> 'revoked'
	`, state.InstallationID, now, state.OrganizationID, state.ApplicationID, state.EnvironmentID); err != nil {
		return fmt.Errorf("revoke installation attestation keys: %w", err)
	}
	return nil
}

func validateAuthorizationIDs(result Authorization) error {
	if id.Validate(result.OrganizationID, id.Organization) != nil || id.Validate(result.ApplicationID, id.Application) != nil || id.Validate(result.EnvironmentID, id.Environment) != nil || id.Validate(result.ApplicationUserID, id.ApplicationUser) != nil || id.Validate(result.InstallationID, id.Installation) != nil || id.Validate(result.SessionGrantID, id.SessionGrant) != nil || id.Validate(result.PolicyRevisionID, id.ConfigRevision) != nil {
		return ErrSessionInvalid
	}
	return nil
}
