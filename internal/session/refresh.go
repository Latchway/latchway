package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
)

type RefreshBinding struct {
	RefreshTokenID       string
	RefreshFamilyID      string
	OrganizationID       string
	ApplicationID        string
	EnvironmentID        string
	ApplicationUserID    string
	InstallationID       string
	SessionGrantID       string
	IdentityProvider     string
	PolicyRevisionID     string
	DPoPJKT              string
	DPoPPublicJWK        dpop.PublicJWK
	Status               string
	InstallationStatus   string
	InstallationTrust    string
	Platform             string
	AppVersion           string
	TrustLevel           string
	AttestationProvider  string
	IdentityVerifiedAt   time.Time
	IdentityExpiresAt    time.Time
	AttestedAt           time.Time
	AttestationExpiresAt time.Time
	ExpiresAt            time.Time
	grantRevoked         bool
	userStatus           string
	applicationStatus    string
	environmentStatus    string
	organizationStatus   string
}

func (store *Store) InspectRefresh(ctx context.Context, token RefreshToken) (RefreshBinding, error) {
	if token.value == "" {
		return RefreshBinding{}, ErrRefreshInvalid
	}
	digest := sha256.Sum256([]byte(token.value))
	binding, err := loadRefreshBinding(ctx, store.pool, digest[:], false)
	if err != nil {
		return RefreshBinding{}, err
	}
	return binding, nil
}

type RotateInput struct {
	RefreshToken RefreshToken
	DPoPProof    DPoPProof
	HTTPMethod   string
	RequestURI   *url.URL
}

func (input RotateInput) validate() error {
	if input.RefreshToken.value == "" || input.DPoPProof.value == "" || !replayMethodPattern.MatchString(input.HTTPMethod) || input.RequestURI == nil {
		return ErrRefreshInvalid
	}
	return nil
}

// Rotate cryptographically validates the request-bound proof, then consumes a
// DPoP-bound refresh token exactly once. Stale identity or attestation state
// requires a complete new challenge exchange rather than timestamp injection.
func (store *Store) Rotate(ctx context.Context, input RotateInput) (IssuedSession, error) {
	now := store.now().UTC().Truncate(time.Second)
	if err := input.validate(); err != nil {
		return IssuedSession{}, err
	}
	refreshDigest := sha256.Sum256([]byte(input.RefreshToken.value))
	preflightBinding, err := loadRefreshBinding(ctx, store.pool, refreshDigest[:], false)
	if err != nil {
		return IssuedSession{}, err
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: preflightBinding.OrganizationID,
		ApplicationID:  preflightBinding.ApplicationID,
		EnvironmentID:  preflightBinding.EnvironmentID,
	})
	if err != nil {
		return IssuedSession{}, ErrSessionScope
	}
	policy := snapshot.SessionPolicy()
	validatedProof, err := dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI, ExpectedJKT: preflightBinding.DPoPJKT,
		Now: now, ClockSkew: policy.MaximumClockSkew, ClockSkewSet: true,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	normalizedURI, err := dpop.NormalizeHTU(input.RequestURI)
	if err != nil {
		return IssuedSession{}, ErrRefreshInvalid
	}
	var preparedAccess PreparedAccessIssuer
	if preflightBinding.Status == "active" {
		preparedAccess, err = store.accessTokens.Prepare(ctx)
		if err != nil {
			return IssuedSession{}, err
		}
	}
	newRefresh, newRefreshID, newRefreshHash, err := store.newRefreshToken()
	if err != nil {
		return IssuedSession{}, err
	}
	newGrantID, err := id.New(id.SessionGrant)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate rotated session-grant ID: %w", err)
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer rollbackSigning(tx)
	binding, err := loadRefreshBinding(ctx, tx, refreshDigest[:], true)
	if err != nil {
		return IssuedSession{}, err
	}
	if !sameRefreshScope(preflightBinding, binding) {
		return IssuedSession{}, ErrRefreshInvalid
	}
	validatedProof, err = dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI, ExpectedJKT: binding.DPoPJKT,
		Now: now, ClockSkew: policy.MaximumClockSkew, ClockSkewSet: true,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	switch binding.Status {
	case "rotated", "reused":
		if err := revokeRefreshFamily(ctx, tx, binding.RefreshFamilyID, binding.RefreshTokenID, now, "refresh_token_reuse", true); err != nil {
			return IssuedSession{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return IssuedSession{}, fmt.Errorf("commit refresh-token reuse response: %w", err)
		}
		return IssuedSession{}, ErrRefreshReused
	case "active":
	default:
		return IssuedSession{}, ErrSessionRevoked
	}
	if !binding.ExpiresAt.After(now) {
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens SET status = 'expired', revoked_at = $2
			WHERE refresh_token_id = $1 AND status = 'active'
		`, binding.RefreshTokenID, now); err != nil {
			return IssuedSession{}, fmt.Errorf("expire refresh token: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return IssuedSession{}, fmt.Errorf("commit refresh-token expiry: %w", err)
		}
		return IssuedSession{}, ErrRefreshInvalid
	}
	if binding.InstallationStatus != "active" {
		return store.commitRevokedRefresh(ctx, tx, binding, now, "installation_revoked", ErrInstallationRevoked)
	}
	if binding.InstallationTrust != binding.TrustLevel {
		return store.commitRevokedRefresh(ctx, tx, binding, now, "attestation_trust_changed", ErrSessionRevoked)
	}
	if binding.grantRevoked || binding.userStatus != "active" || binding.applicationStatus != "active" || binding.environmentStatus != "active" || binding.organizationStatus != "active" {
		return store.commitRevokedRefresh(ctx, tx, binding, now, "session_scope_revoked", ErrSessionRevoked)
	}

	if !binding.IdentityExpiresAt.After(now) {
		return IssuedSession{}, ErrIdentityRefreshRequired
	}
	if binding.AttestedAt.IsZero() || !binding.AttestationExpiresAt.After(now) {
		return IssuedSession{}, ErrAttestationRefreshNeeded
	}
	if preparedAccess == nil {
		return IssuedSession{}, ErrRefreshInvalid
	}
	if err := store.replay.accept(ctx, tx, ReplayInput{
		OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID,
		EnvironmentID: binding.EnvironmentID, InstallationID: binding.InstallationID,
		SessionGrantID: binding.SessionGrantID,
		ProofJTI:       validatedProof.JTI, HTTPMethod: input.HTTPMethod, NormalizedURI: normalizedURI,
	}); err != nil {
		return IssuedSession{}, err
	}
	issuedAccess, err := preparedAccess.IssueFor(AccessIssueInput{
		OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID,
		EnvironmentID: binding.EnvironmentID, ApplicationUserID: binding.ApplicationUserID,
		InstallationID: binding.InstallationID, SessionGrantID: newGrantID,
		IdentityProvider: binding.IdentityProvider, TrustLevel: binding.TrustLevel,
		PolicyRevisionID: snapshot.RevisionID, DPoPJKT: binding.DPoPJKT,
	}, policy.AccessTokenTTL)
	if err != nil {
		return IssuedSession{}, err
	}
	issuedAt := latestTime(now, issuedAccess.IssuedAt)
	if !issuedAccess.ExpiresAt.After(issuedAt) {
		return IssuedSession{}, ErrRefreshInvalid
	}
	if err := insertRotatedGrant(ctx, tx, binding, newGrantID, snapshot.RevisionID, binding.TrustLevel,
		binding.IdentityVerifiedAt, binding.IdentityExpiresAt, binding.AttestedAt,
		binding.AttestationProvider, binding.AttestationExpiresAt,
		issuedAccess, issuedAt); err != nil {
		return IssuedSession{}, err
	}
	refreshExpiresAt := issuedAt.Add(policy.RefreshTokenTTL)
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (
			refresh_token_id, family_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, session_grant_id, parent_refresh_token_id,
			token_hash, status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'staged', $11, $12)
	`, newRefreshID, binding.RefreshFamilyID, binding.OrganizationID, binding.ApplicationID,
		binding.EnvironmentID, binding.ApplicationUserID, binding.InstallationID, newGrantID,
		binding.RefreshTokenID, newRefreshHash[:], issuedAt, refreshExpiresAt); err != nil {
		return IssuedSession{}, fmt.Errorf("stage rotated refresh token: %w", err)
	}
	command, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'rotated', used_at = $3, rotated_to_refresh_token_id = $2
		WHERE refresh_token_id = $1 AND token_hash = $4 AND status = 'active'
	`, binding.RefreshTokenID, newRefreshID, now, refreshDigest[:])
	if err != nil {
		return IssuedSession{}, fmt.Errorf("rotate previous refresh token: %w", err)
	}
	if command.RowsAffected() != 1 {
		return IssuedSession{}, ErrRefreshReused
	}
	command, err = tx.Exec(ctx, `
		UPDATE refresh_tokens SET status = 'active'
		WHERE refresh_token_id = $1 AND status = 'staged'
	`, newRefreshID)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("activate rotated refresh token: %w", err)
	}
	if command.RowsAffected() != 1 {
		return IssuedSession{}, ErrRefreshInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit refresh rotation: %w", err)
	}
	return IssuedSession{
		Access: issuedAccess, Refresh: newRefresh, RefreshID: newRefreshID,
		RefreshFamilyID: binding.RefreshFamilyID, RefreshExpiresAt: refreshExpiresAt,
		GrantID:      newGrantID,
		Installation: Installation{ID: binding.InstallationID, Platform: binding.Platform, DPoPJKT: binding.DPoPJKT, Status: "active", AppVersion: binding.AppVersion},
		Trust: Trust{
			Provider: binding.AttestationProvider, Level: binding.TrustLevel,
			VerifiedAt: binding.AttestedAt, ExpiresAt: binding.AttestationExpiresAt,
		},
	}, nil
}

func sameRefreshScope(left, right RefreshBinding) bool {
	return left.RefreshTokenID == right.RefreshTokenID &&
		left.RefreshFamilyID == right.RefreshFamilyID &&
		left.OrganizationID == right.OrganizationID &&
		left.ApplicationID == right.ApplicationID &&
		left.EnvironmentID == right.EnvironmentID &&
		left.ApplicationUserID == right.ApplicationUserID &&
		left.InstallationID == right.InstallationID &&
		left.SessionGrantID == right.SessionGrantID &&
		left.DPoPJKT == right.DPoPJKT
}

func (store *Store) commitRevokedRefresh(ctx context.Context, tx pgx.Tx, binding RefreshBinding, now time.Time, reason string, result error) (IssuedSession, error) {
	if err := revokeRefreshFamily(ctx, tx, binding.RefreshFamilyID, "", now, reason, false); err != nil {
		return IssuedSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit revoked refresh family: %w", err)
	}
	return IssuedSession{}, result
}

type refreshBindingQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadRefreshBinding(ctx context.Context, query refreshBindingQuerier, tokenHash []byte, forUpdate bool) (RefreshBinding, error) {
	statement := `
		SELECT r.refresh_token_id, r.family_id, r.organization_id, r.application_id,
		       r.environment_id, r.application_user_id, r.installation_id,
		       r.session_grant_id, r.status, r.expires_at,
		       g.policy_revision_id, g.trust_level, g.identity_provider_key,
		       g.identity_verified_at,
		       g.identity_expires_at, g.attested_at, g.attestation_provider,
		       g.attestation_expires_at, g.revoked_at IS NOT NULL,
		       i.dpop_jkt, i.dpop_public_jwk, i.status, i.trust_level, i.platform, i.app_version,
		       u.status, a.status, e.status, o.status
		FROM refresh_tokens r
		JOIN session_grants g
		  ON g.organization_id = r.organization_id AND g.application_id = r.application_id
		 AND g.environment_id = r.environment_id AND g.session_grant_id = r.session_grant_id
		JOIN installations i
		  ON i.organization_id = r.organization_id AND i.application_id = r.application_id
		 AND i.environment_id = r.environment_id AND i.installation_id = r.installation_id
		JOIN application_users u
		  ON u.organization_id = r.organization_id AND u.application_id = r.application_id
		 AND u.application_user_id = r.application_user_id
		JOIN applications a ON a.organization_id = r.organization_id AND a.application_id = r.application_id
		JOIN environments e
		  ON e.organization_id = r.organization_id AND e.application_id = r.application_id
		 AND e.environment_id = r.environment_id
		JOIN organizations o ON o.organization_id = r.organization_id
		WHERE r.token_hash = $1
	`
	if forUpdate {
		statement += " FOR UPDATE OF r"
	}
	var result RefreshBinding
	var encodedJWK []byte
	var identityProvider, attestationProvider *string
	var identityExpiresAt, attestedAt, attestationExpiresAt *time.Time
	err := query.QueryRow(ctx, statement, tokenHash).Scan(
		&result.RefreshTokenID, &result.RefreshFamilyID, &result.OrganizationID, &result.ApplicationID,
		&result.EnvironmentID, &result.ApplicationUserID, &result.InstallationID,
		&result.SessionGrantID, &result.Status, &result.ExpiresAt,
		&result.PolicyRevisionID, &result.TrustLevel, &identityProvider,
		&result.IdentityVerifiedAt,
		&identityExpiresAt, &attestedAt, &attestationProvider,
		&attestationExpiresAt, &result.grantRevoked,
		&result.DPoPJKT, &encodedJWK, &result.InstallationStatus, &result.InstallationTrust,
		&result.Platform, &result.AppVersion,
		&result.userStatus, &result.applicationStatus, &result.environmentStatus, &result.organizationStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshBinding{}, ErrRefreshInvalid
	}
	if err != nil {
		return RefreshBinding{}, fmt.Errorf("resolve refresh-token binding: %w", err)
	}
	if identityProvider == nil || identityExpiresAt == nil || attestedAt == nil || attestationProvider == nil || attestationExpiresAt == nil {
		if result.grantRevoked || result.Status == "revoked" {
			return RefreshBinding{}, ErrSessionRevoked
		}
		return RefreshBinding{}, ErrRefreshInvalid
	}
	result.IdentityProvider = *identityProvider
	result.AttestationProvider = *attestationProvider
	if !sessionIdentifierPattern.MatchString(result.IdentityProvider) || !sessionIdentifierPattern.MatchString(result.AttestationProvider) {
		return RefreshBinding{}, ErrRefreshInvalid
	}
	result.IdentityExpiresAt = identityExpiresAt.UTC()
	result.AttestedAt = attestedAt.UTC()
	result.AttestationExpiresAt = attestationExpiresAt.UTC()
	result.DPoPPublicJWK, err = decodeStoredDPoPPublicJWK(encodedJWK, result.DPoPJKT)
	if err != nil {
		return RefreshBinding{}, ErrRefreshInvalid
	}
	if id.Validate(result.RefreshTokenID, id.RefreshToken) != nil || id.Validate(result.RefreshFamilyID, id.RefreshTokenFamily) != nil || id.Validate(result.SessionGrantID, id.SessionGrant) != nil || id.Validate(result.InstallationID, id.Installation) != nil {
		return RefreshBinding{}, ErrRefreshInvalid
	}
	return result, nil
}

func insertRotatedGrant(ctx context.Context, tx pgx.Tx, binding RefreshBinding, grantID, policyRevisionID, trustLevel string,
	identityVerifiedAt, identityExpiresAt, attestedAt time.Time, attestationProvider string,
	attestationExpiresAt time.Time, access IssuedAccess, issuedAt time.Time) error {
	command, err := tx.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
			policy_revision_id, trust_level, identity_provider_key,
			identity_verified_at, identity_expires_at,
			attested_at, attestation_provider, attestation_expires_at, issued_at, expires_at
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
		FROM active_config_revisions active_revision
		JOIN organizations o ON o.organization_id = $2 AND o.status = 'active'
		JOIN applications a ON a.organization_id = $2 AND a.application_id = $3 AND a.status = 'active'
		JOIN environments e ON e.organization_id = $2 AND e.application_id = $3 AND e.environment_id = $4 AND e.status = 'active'
		JOIN application_users u ON u.organization_id = $2 AND u.application_id = $3 AND u.application_user_id = $5 AND u.status = 'active'
		JOIN installations i ON i.organization_id = $2 AND i.application_id = $3 AND i.environment_id = $4 AND i.installation_id = $6 AND i.status = 'active'
		WHERE active_revision.organization_id = $2
		  AND active_revision.application_id = $3
		  AND active_revision.environment_id = $4
		  AND active_revision.config_revision_id = $9
	`, grantID, binding.OrganizationID, binding.ApplicationID, binding.EnvironmentID,
		binding.ApplicationUserID, binding.InstallationID, access.JTIHash[:], binding.DPoPJKT,
		policyRevisionID, trustLevel, binding.IdentityProvider, identityVerifiedAt, identityExpiresAt,
		attestedAt, attestationProvider, attestationExpiresAt, issuedAt, access.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store rotated session grant: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSessionScope
	}
	return nil
}

func revokeRefreshFamily(ctx context.Context, tx pgx.Tx, familyID, reusedTokenID string, now time.Time, reason string, markReuse bool) error {
	if markReuse {
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens
			SET status = CASE
			        WHEN refresh_token_id = $2 THEN 'reused'
			        WHEN status IN ('staged', 'active') THEN 'revoked'
			        ELSE status
			    END,
			    revoked_at = CASE
			        WHEN refresh_token_id = $2 OR status IN ('staged', 'active')
			        THEN COALESCE(revoked_at, GREATEST(issued_at, $3))
			        ELSE revoked_at
			    END
			WHERE family_id = $1
		`, familyID, reusedTokenID, now); err != nil {
			return fmt.Errorf("mark refresh-token family reuse: %w", err)
		}
	} else if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2))
		WHERE family_id = $1 AND status IN ('staged', 'active')
	`, familyID, now); err != nil {
		return fmt.Errorf("revoke refresh-token family: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2)), revoke_reason = COALESCE(revoke_reason, $3)
		WHERE session_grant_id IN (
			SELECT session_grant_id FROM refresh_tokens WHERE family_id = $1
		) AND revoked_at IS NULL
	`, familyID, now, reason); err != nil {
		return fmt.Errorf("revoke refresh-token family grants: %w", err)
	}
	return nil
}
