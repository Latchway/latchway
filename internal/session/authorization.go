package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/useroverride"
)

const clientInstallationRevocationReason = "client_installation_revoked"

type Authorization struct {
	OrganizationID       string
	ApplicationID        string
	EnvironmentID        string
	EnvironmentKind      string
	ApplicationUserID    string
	InstallationID       string
	InstallationPlatform string
	SessionGrantID       string
	PolicyRevisionID     string
	UserOverrideID       string
	LimitPlanOverride    string
	IdentityProvider     string
	DPoPJKT              string
	TrustLevel           string
	AttestationProvider  string
	NormalizedClaims     map[string]any
	IdentityExpiresAt    time.Time
	AttestedAt           time.Time
	AttestationExpiresAt time.Time
	AccessExpiresAt      time.Time

	seal [sha256.Size]byte
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
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Authorization{}, fmt.Errorf("begin session authorization: %w", err)
	}
	defer rollbackSigning(tx)
	if err := lockAccessInstallation(ctx, tx, principal, false); err != nil {
		return Authorization{}, err
	}
	if err := lockAccessApplicationUser(ctx, tx, principal); err != nil {
		return Authorization{}, err
	}
	state, err := loadAuthorizationState(
		ctx, tx, principal, " FOR SHARE OF g, u, a, e, o",
	)
	if err != nil {
		return Authorization{}, err
	}
	if err := authorizationStateError(state, now, false); err != nil {
		return Authorization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Authorization{}, fmt.Errorf("commit session authorization: %w", err)
	}
	return state.Authorization, nil
}

type authorizationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadAuthorizationState(ctx context.Context, query authorizationQuerier, principal AccessPrincipal, lockClause string) (authorizationState, error) {
	var result authorizationState
	var storedJTIHash, normalizedClaimsJSON []byte
	var grantExpiresAt, identityExpiresAt, attestedAt, attestationExpiresAt *time.Time
	statement := `
		SELECT g.organization_id, g.application_id, g.environment_id, g.application_user_id,
		       g.installation_id, g.session_grant_id, g.policy_revision_id, g.dpop_jkt,
		       g.trust_level, g.identity_provider_key, g.access_token_jti_hash,
		       g.expires_at, g.identity_expires_at,
		       g.attested_at, g.attestation_provider, g.attestation_expires_at,
		       g.revoked_at IS NOT NULL, i.status, i.trust_level, i.platform,
		       u.status, u.normalized_claims, a.status, e.status, e.kind, o.status
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
		&result.grantRevoked, &result.installationStatus, &result.installationTrust, &result.InstallationPlatform,
		&result.userStatus, &normalizedClaimsJSON, &result.applicationStatus, &result.environmentStatus, &result.EnvironmentKind,
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
	result.AttestedAt = attestedAt.UTC()
	result.AttestationExpiresAt = attestationExpiresAt.UTC()
	result.AccessExpiresAt = grantExpiresAt.UTC()
	claims, err := identity.DecodeNormalizedClaims(normalizedClaimsJSON)
	if err != nil {
		return authorizationState{}, ErrSessionInvalid
	}
	result.NormalizedClaims = claims
	override, err := loadActiveUserOverride(ctx, query, result.Authorization)
	if err != nil {
		return authorizationState{}, err
	}
	result.UserOverrideID = override.ID
	result.LimitPlanOverride = override.LimitPlan
	if validateAuthorizationValues(result.Authorization) != nil {
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
	sealed, err := sealAuthorization(result.Authorization)
	if err != nil {
		return authorizationState{}, ErrSessionInvalid
	}
	result.Authorization = sealed
	return result, nil
}

// loadActiveUserOverride reads mutable server-owned policy only after the
// caller has loaded and, on protected paths, share-locked the authoritative
// application-user row. Override writers take the corresponding exclusive
// user lock, so replacement and no-row insertion cannot race this selection.
// A fresh database statement clock after that lock wait is the sole expiry
// authority.
func loadActiveUserOverride(
	ctx context.Context,
	query authorizationQuerier,
	authorization Authorization,
) (useroverride.Selection, error) {
	var selection useroverride.Selection
	var document []byte
	err := query.QueryRow(ctx, `
		SELECT user_override_id, override_document
		FROM user_overrides
		WHERE organization_id = $1
		  AND application_id = $2
		  AND environment_id = $3
		  AND application_user_id = $4
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > statement_timestamp())
	`, authorization.OrganizationID, authorization.ApplicationID,
		authorization.EnvironmentID, authorization.ApplicationUserID).Scan(
		&selection.ID, &document,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return useroverride.Selection{}, nil
	}
	if err != nil {
		return useroverride.Selection{}, fmt.Errorf("load active user override: %w", err)
	}
	decoded, err := useroverride.Decode(document)
	if err != nil {
		return useroverride.Selection{}, fmt.Errorf("decode active user override: %w", err)
	}
	selection.LimitPlan = decoded.LimitPlan
	if err := selection.Validate(); err != nil {
		return useroverride.Selection{}, fmt.Errorf("validate active user override: %w", err)
	}
	return selection, nil
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
	if state.AttestedAt.After(now) {
		return ErrSessionInvalid
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
	Origin      string
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

func (store *Store) authorizeClientDiagnostics(ctx context.Context, input AccessRequestInput) (Authorization, bool, error) {
	refreshAvailable := false
	state, err := store.authorizeAccess(ctx, input, false, false, func(
		ctx context.Context,
		tx pgx.Tx,
		state authorizationState,
		now time.Time,
	) error {
		err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM refresh_tokens
				WHERE organization_id = $1
				  AND application_id = $2
				  AND environment_id = $3
				  AND application_user_id = $4
				  AND installation_id = $5
				  AND session_grant_id = $6
				  AND status = 'active'
				  AND expires_at > $7
				  AND used_at IS NULL
				  AND revoked_at IS NULL
				  AND rotated_to_refresh_token_id IS NULL
			)
		`, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.ApplicationUserID, state.InstallationID, state.SessionGrantID, now,
		).Scan(&refreshAvailable)
		if err != nil {
			return fmt.Errorf("inspect client diagnostics refresh availability: %w", err)
		}
		return nil
	})
	if err != nil {
		return Authorization{}, false, err
	}
	return state.Authorization, refreshAvailable, nil
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
	if err := lockAccessApplicationUser(ctx, tx, input.Principal); err != nil {
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
	if !snapshotOriginAllowed(snapshot, state.InstallationPlatform, input.Origin) {
		return authorizationState{}, ErrSessionInvalid
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

// lockAccessApplicationUser establishes a deterministic user-before-
// environment lock order shared with administrative override replacement.
// This keeps an override selection and its absence linearizable without
// relying on the row-lock order chosen for the later joined state query.
func lockAccessApplicationUser(ctx context.Context, tx pgx.Tx, principal AccessPrincipal) error {
	var locked int
	err := tx.QueryRow(ctx, `
		/* session_authorization_user_lock */
		SELECT 1
		FROM application_users
		WHERE organization_id = $1 AND application_id = $2 AND application_user_id = $3
		FOR SHARE
	`, principal.OrganizationID, principal.ApplicationID, principal.ApplicationUserID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionInvalid
	}
	if err != nil {
		return fmt.Errorf("lock access application user: %w", err)
	}
	return nil
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

// ValidatedSnapshot verifies that the authorization was loaded by this
// package from durable session state, has not been changed by its caller, and
// is still current at now. The returned normalized claims are a defensive deep
// copy suitable for building a server-owned policy activation.
func (authorization Authorization) ValidatedSnapshot(now time.Time) (Authorization, error) {
	if now.IsZero() {
		return Authorization{}, ErrSessionInvalid
	}
	normalized, err := normalizedAuthorization(authorization)
	if err != nil {
		return Authorization{}, err
	}
	digest, err := authorizationSealDigest(normalized)
	if err != nil || subtle.ConstantTimeCompare(authorization.seal[:], digest[:]) != 1 {
		return Authorization{}, ErrSessionInvalid
	}
	if !normalized.AccessExpiresAt.After(now) || !normalized.IdentityExpiresAt.After(now) {
		return Authorization{}, ErrTokenExpired
	}
	if normalized.AttestedAt.After(now) {
		return Authorization{}, ErrSessionInvalid
	}
	if !normalized.AttestationExpiresAt.After(now) {
		return Authorization{}, ErrAttestationRefreshNeeded
	}
	normalized.seal = digest
	return normalized, nil
}

func sealAuthorization(authorization Authorization) (Authorization, error) {
	normalized, err := normalizedAuthorization(authorization)
	if err != nil {
		return Authorization{}, err
	}
	digest, err := authorizationSealDigest(normalized)
	if err != nil {
		return Authorization{}, err
	}
	normalized.seal = digest
	return normalized, nil
}

func normalizedAuthorization(authorization Authorization) (Authorization, error) {
	if validateAuthorizationValues(authorization) != nil {
		return Authorization{}, ErrSessionInvalid
	}
	encodedClaims, err := json.Marshal(authorization.NormalizedClaims)
	if err != nil {
		return Authorization{}, ErrSessionInvalid
	}
	claims, err := identity.DecodeNormalizedClaims(encodedClaims)
	if err != nil {
		return Authorization{}, ErrSessionInvalid
	}
	authorization.NormalizedClaims = claims
	authorization.IdentityExpiresAt = authorization.IdentityExpiresAt.UTC()
	authorization.AttestedAt = authorization.AttestedAt.UTC()
	authorization.AttestationExpiresAt = authorization.AttestationExpiresAt.UTC()
	authorization.AccessExpiresAt = authorization.AccessExpiresAt.UTC()
	authorization.seal = [sha256.Size]byte{}
	return authorization, nil
}

func validateAuthorizationValues(authorization Authorization) error {
	if validateAuthorizationIDs(authorization) != nil ||
		!sessionIdentifierPattern.MatchString(authorization.IdentityProvider) ||
		!validAttestationProvider(authorization.AttestationProvider) ||
		!trustLevelPattern.MatchString(authorization.TrustLevel) ||
		!platformPattern.MatchString(authorization.InstallationPlatform) ||
		!validEnvironmentKind(authorization.EnvironmentKind) ||
		!validThumbprint(authorization.DPoPJKT) ||
		(useroverride.Selection{
			ID: authorization.UserOverrideID, LimitPlan: authorization.LimitPlanOverride,
		}).Validate() != nil ||
		authorization.IdentityExpiresAt.IsZero() || authorization.AttestedAt.IsZero() ||
		authorization.AttestationExpiresAt.IsZero() || authorization.AccessExpiresAt.IsZero() ||
		!authorization.AttestationExpiresAt.After(authorization.AttestedAt) ||
		!authorization.AccessExpiresAt.After(authorization.AttestedAt) ||
		authorization.NormalizedClaims == nil {
		return ErrSessionInvalid
	}
	return nil
}

func validEnvironmentKind(kind string) bool {
	return kind == "development" || kind == "staging" || kind == "production"
}

type authorizationSealPayload struct {
	OrganizationID       string         `json:"organization_id"`
	ApplicationID        string         `json:"application_id"`
	EnvironmentID        string         `json:"environment_id"`
	EnvironmentKind      string         `json:"environment_kind"`
	ApplicationUserID    string         `json:"application_user_id"`
	InstallationID       string         `json:"installation_id"`
	InstallationPlatform string         `json:"installation_platform"`
	SessionGrantID       string         `json:"session_grant_id"`
	PolicyRevisionID     string         `json:"policy_revision_id"`
	UserOverrideID       string         `json:"user_override_id,omitempty"`
	LimitPlanOverride    string         `json:"limit_plan_override,omitempty"`
	IdentityProvider     string         `json:"identity_provider"`
	DPoPJKT              string         `json:"dpop_jkt"`
	TrustLevel           string         `json:"trust_level"`
	AttestationProvider  string         `json:"attestation_provider"`
	NormalizedClaims     map[string]any `json:"normalized_claims"`
	IdentityExpiresAt    time.Time      `json:"identity_expires_at"`
	AttestedAt           time.Time      `json:"attested_at"`
	AttestationExpiresAt time.Time      `json:"attestation_expires_at"`
	AccessExpiresAt      time.Time      `json:"access_expires_at"`
}

func authorizationSealDigest(authorization Authorization) ([sha256.Size]byte, error) {
	payload := authorizationSealPayload{
		OrganizationID: authorization.OrganizationID, ApplicationID: authorization.ApplicationID,
		EnvironmentID: authorization.EnvironmentID, EnvironmentKind: authorization.EnvironmentKind,
		ApplicationUserID: authorization.ApplicationUserID, InstallationID: authorization.InstallationID,
		InstallationPlatform: authorization.InstallationPlatform, SessionGrantID: authorization.SessionGrantID,
		PolicyRevisionID: authorization.PolicyRevisionID, UserOverrideID: authorization.UserOverrideID,
		LimitPlanOverride: authorization.LimitPlanOverride, IdentityProvider: authorization.IdentityProvider,
		DPoPJKT: authorization.DPoPJKT, TrustLevel: authorization.TrustLevel,
		AttestationProvider: authorization.AttestationProvider, NormalizedClaims: authorization.NormalizedClaims,
		IdentityExpiresAt: authorization.IdentityExpiresAt, AttestedAt: authorization.AttestedAt,
		AttestationExpiresAt: authorization.AttestationExpiresAt, AccessExpiresAt: authorization.AccessExpiresAt,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, ErrSessionInvalid
	}
	return sha256.Sum256(encoded), nil
}
