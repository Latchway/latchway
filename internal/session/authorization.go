package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

var revocationReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,99}$`)

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

func (store *Store) Authorize(ctx context.Context, principal AccessPrincipal) (Authorization, error) {
	now := store.now().UTC()
	if validateAccessPrincipal(principal, now) != nil {
		return Authorization{}, ErrSessionInvalid
	}
	var result Authorization
	var storedJTIHash []byte
	var grantExpiresAt, identityExpiresAt, attestedAt, attestationExpiresAt *time.Time
	var grantRevoked bool
	var installationStatus, installationTrustLevel, userStatus, applicationStatus, environmentStatus, organizationStatus string
	err := store.pool.QueryRow(ctx, `
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
	`, principal.SessionGrantID).Scan(
		&result.OrganizationID, &result.ApplicationID, &result.EnvironmentID, &result.ApplicationUserID,
		&result.InstallationID, &result.SessionGrantID, &result.PolicyRevisionID, &result.DPoPJKT,
		&result.TrustLevel, &result.IdentityProvider, &storedJTIHash, &grantExpiresAt, &identityExpiresAt,
		&attestedAt, &result.AttestationProvider, &attestationExpiresAt,
		&grantRevoked, &installationStatus, &installationTrustLevel,
		&userStatus, &applicationStatus, &environmentStatus,
		&organizationStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authorization{}, ErrSessionInvalid
	}
	if err != nil {
		return Authorization{}, fmt.Errorf("authorize client session: %w", err)
	}
	if grantExpiresAt == nil || identityExpiresAt == nil || attestedAt == nil || attestationExpiresAt == nil || len(storedJTIHash) != sha256.Size {
		return Authorization{}, ErrSessionInvalid
	}
	result.IdentityExpiresAt = identityExpiresAt.UTC()
	result.AttestationExpiresAt = attestationExpiresAt.UTC()
	result.AccessExpiresAt = grantExpiresAt.UTC()
	if validateAuthorizationIDs(result) != nil || !sessionIdentifierPattern.MatchString(result.IdentityProvider) || !sessionIdentifierPattern.MatchString(result.AttestationProvider) || !trustLevelPattern.MatchString(result.TrustLevel) || !validThumbprint(result.DPoPJKT) {
		return Authorization{}, ErrSessionInvalid
	}
	if subtle.ConstantTimeCompare(storedJTIHash, principal.JTIHash[:]) != 1 ||
		result.OrganizationID != principal.OrganizationID || result.ApplicationID != principal.ApplicationID ||
		result.EnvironmentID != principal.EnvironmentID || result.ApplicationUserID != principal.ApplicationUserID ||
		result.InstallationID != principal.InstallationID || result.PolicyRevisionID != principal.PolicyRevisionID ||
		result.DPoPJKT != principal.DPoPJKT || result.TrustLevel != principal.TrustLevel ||
		result.IdentityProvider != principal.IdentityProvider || !result.AccessExpiresAt.Equal(principal.ExpiresAt) {
		return Authorization{}, ErrSessionInvalid
	}
	if installationStatus != "active" {
		return Authorization{}, ErrInstallationRevoked
	}
	if grantRevoked || installationTrustLevel != result.TrustLevel || userStatus != "active" || applicationStatus != "active" || environmentStatus != "active" || organizationStatus != "active" {
		return Authorization{}, ErrSessionRevoked
	}
	if !result.AccessExpiresAt.After(now) || !result.IdentityExpiresAt.After(now) {
		return Authorization{}, ErrTokenExpired
	}
	if !result.AttestationExpiresAt.After(now) {
		return Authorization{}, ErrAttestationRefreshNeeded
	}
	return result, nil
}

func validateAccessPrincipal(principal AccessPrincipal, now time.Time) error {
	input := AccessIssueInput{
		OrganizationID: principal.OrganizationID, ApplicationID: principal.ApplicationID,
		EnvironmentID: principal.EnvironmentID, ApplicationUserID: principal.ApplicationUserID,
		InstallationID: principal.InstallationID, SessionGrantID: principal.SessionGrantID,
		IdentityProvider: principal.IdentityProvider, TrustLevel: principal.TrustLevel,
		PolicyRevisionID: principal.PolicyRevisionID, DPoPJKT: principal.DPoPJKT,
	}
	if !accessPrincipalSealValid(principal) || input.validate() != nil || principal.JTIHash == ([sha256.Size]byte{}) || principal.IssuedAt.IsZero() || !principal.ExpiresAt.After(principal.IssuedAt) || !principal.ExpiresAt.After(now) {
		return ErrSessionInvalid
	}
	return nil
}

// RevokeInstallation revokes the installation and every active grant,
// refresh credential, and attestation key beneath it. The caller must first
// verify the access token and its request-bound DPoP proof.
func (store *Store) RevokeInstallation(ctx context.Context, principal AccessPrincipal, reason string) error {
	now := store.now().UTC()
	if validateAccessPrincipal(principal, now) != nil || !revocationReasonPattern.MatchString(reason) {
		return ErrSessionInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin installation revocation: %w", err)
	}
	defer rollbackSigning(tx)
	var storedJKT, status string
	err = tx.QueryRow(ctx, `
		SELECT dpop_jkt, status
		FROM installations
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5
		FOR UPDATE
	`, principal.OrganizationID, principal.ApplicationID, principal.EnvironmentID,
		principal.ApplicationUserID, principal.InstallationID).Scan(&storedJKT, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionInvalid
	}
	if err != nil {
		return fmt.Errorf("lock installation for revocation: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedJKT), []byte(principal.DPoPJKT)) != 1 {
		return ErrSessionInvalid
	}
	if status == "revoked" {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit idempotent installation revocation: %w", err)
		}
		return nil
	}
	if status != "active" {
		return ErrSessionInvalid
	}
	if _, err := tx.Exec(ctx, `
		UPDATE installations
		SET status = 'revoked', revoked_at = $2, revoke_reason = $3,
		    updated_at = $2, last_seen_at = GREATEST(last_seen_at, $2)
		WHERE installation_id = $1 AND status = 'active'
	`, principal.InstallationID, now, reason); err != nil {
		return fmt.Errorf("revoke installation: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, $2), revoke_reason = COALESCE(revoke_reason, $3)
		WHERE installation_id = $1 AND revoked_at IS NULL
	`, principal.InstallationID, now, reason); err != nil {
		return fmt.Errorf("revoke installation session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2)
		WHERE installation_id = $1 AND status IN ('staged', 'active')
	`, principal.InstallationID, now); err != nil {
		return fmt.Errorf("revoke installation refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET status = 'revoked', revoked_at = $2, updated_at = $2
		WHERE installation_id = $1 AND status <> 'revoked'
	`, principal.InstallationID, now); err != nil {
		return fmt.Errorf("revoke installation attestation keys: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit installation revocation: %w", err)
	}
	return nil
}

func validateAuthorizationIDs(result Authorization) error {
	if id.Validate(result.OrganizationID, id.Organization) != nil || id.Validate(result.ApplicationID, id.Application) != nil || id.Validate(result.EnvironmentID, id.Environment) != nil || id.Validate(result.ApplicationUserID, id.ApplicationUser) != nil || id.Validate(result.InstallationID, id.Installation) != nil || id.Validate(result.SessionGrantID, id.SessionGrant) != nil || id.Validate(result.PolicyRevisionID, id.ConfigRevision) != nil {
		return ErrSessionInvalid
	}
	return nil
}
