package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

const componentRefreshIdempotencyGrace = 30 * time.Second

type RefreshBinding struct {
	ComponentAware            bool
	RefreshTokenID            string
	RefreshFamilyID           string
	OrganizationID            string
	ApplicationID             string
	EnvironmentID             string
	ApplicationUserID         string
	InstallationID            string
	InstallationFamilyID      string
	ComponentID               string
	ComponentDefinitionID     string
	ComponentKind             string
	ComponentIsRoot           bool
	ComponentKeyID            string
	ComponentKeyStatus        string
	ComponentSessionStatus    string
	ComponentStatus           string
	FamilyStatus              string
	TrustSource               string
	TrustVerifiedAt           time.Time
	TrustExpiresAt            time.Time
	ParentComponentID         string
	ParentAttestationProvider string
	DelegationID              string
	GrantedFeatures           []string
	SessionGrantID            string
	IdentityProvider          string
	PolicyRevisionID          string
	DPoPJKT                   string
	DPoPPublicJWK             dpop.PublicJWK
	Status                    string
	InstallationStatus        string
	InstallationTrust         string
	Platform                  string
	AppVersion                string
	TrustLevel                string
	AttestationProvider       string
	IdentityVerifiedAt        time.Time
	IdentityExpiresAt         time.Time
	AttestedAt                time.Time
	AttestationExpiresAt      time.Time
	ExpiresAt                 time.Time
	grantRevoked              bool
	userStatus                string
	applicationStatus         string
	environmentStatus         string
	organizationStatus        string
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
	Origin       string
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
	if !snapshotOriginAllowed(snapshot, preflightBinding.Platform, input.Origin) {
		return IssuedSession{}, ErrSessionInvalid
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
	if preflightBinding.ComponentAware {
		return store.rotateComponentSession(
			ctx, input, preflightBinding, snapshot, policy,
			validatedProof, normalizedURI, refreshDigest, now,
		)
	}
	preflightPolicyErr := currentRefreshPolicyError(snapshot, preflightBinding, now)
	var preparedAccess PreparedAccessIssuer
	var newRefresh RefreshToken
	var newRefreshID string
	var newRefreshHash [sha256.Size]byte
	var newGrantID string
	if preflightBinding.Status == "active" && preflightPolicyErr == nil {
		preparedAccess, err = store.accessTokens.Prepare(ctx)
		if err != nil {
			return IssuedSession{}, err
		}
		newRefresh, newRefreshID, newRefreshHash, err = store.newRefreshToken()
		if err != nil {
			return IssuedSession{}, err
		}
		newGrantID, err = id.New(id.SessionGrant)
		if err != nil {
			return IssuedSession{}, fmt.Errorf("generate rotated session-grant ID: %w", err)
		}
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer rollbackSigning(tx)
	if err := lockActiveCredentialScope(ctx, tx, preflightBinding.OrganizationID, preflightBinding.ApplicationID, preflightBinding.EnvironmentID); err != nil {
		return IssuedSession{}, err
	}
	// Installation is the stable root of every session mutation. Lock it before
	// the refresh row so rotation, exchange, and installation revocation share
	// one lock order. This prevents a rotated child credential from appearing
	// after revocation has taken its snapshot and avoids refresh/revoke
	// deadlocks (refresh-token -> installation versus installation -> token).
	if err := lockRefreshInstallation(ctx, tx, preflightBinding); err != nil {
		return IssuedSession{}, err
	}
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
	if err := lockActiveRefreshRevision(ctx, tx, binding, snapshot.RevisionID); err != nil {
		return IssuedSession{}, err
	}
	if policyErr := currentRefreshPolicyError(snapshot, binding, now); policyErr != nil {
		return IssuedSession{}, policyErr
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

type cachedComponentRotation struct {
	AccessToken      string    `json:"access_token"`
	AccessJTIHash    string    `json:"access_jti_hash"`
	AccessIssuedAt   time.Time `json:"access_issued_at"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshTokenID   string    `json:"refresh_token_id"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	SessionGrantID   string    `json:"session_grant_id"`
	SessionFamilyID  string    `json:"session_family_id"`
}

func (store *Store) rotateComponentSession(
	ctx context.Context,
	input RotateInput,
	preflightBinding RefreshBinding,
	snapshot configuration.ActiveSnapshot,
	policy configuration.SessionPolicy,
	validatedProof dpop.Result,
	normalizedURI string,
	refreshDigest [sha256.Size]byte,
	now time.Time,
) (IssuedSession, error) {
	if store.rotationProtector == nil {
		return IssuedSession{}, ErrRefreshInvalid
	}
	preflightPolicyErr := store.currentComponentRefreshPolicyError(ctx, store.pool, snapshot, preflightBinding, now)
	var preparedAccess PreparedAccessIssuer
	var newRefresh RefreshToken
	var newRefreshID string
	var newRefreshHash [sha256.Size]byte
	var newGrantID string
	var rotationResultID string
	var err error
	if preflightBinding.Status == "active" && preflightPolicyErr == nil {
		preparedAccess, err = store.accessTokens.Prepare(ctx)
		if err != nil {
			return IssuedSession{}, err
		}
		newRefresh, newRefreshID, newRefreshHash, err = store.newRefreshTokenWithPrefix(id.ComponentRefresh)
		if err != nil {
			return IssuedSession{}, err
		}
		newGrantID, err = id.New(id.SessionGrant)
		if err != nil {
			return IssuedSession{}, fmt.Errorf("generate rotated component grant ID: %w", err)
		}
		rotationResultID, err = id.New(id.RefreshRotation)
		if err != nil {
			return IssuedSession{}, fmt.Errorf("generate refresh-rotation result ID: %w", err)
		}
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin component refresh rotation: %w", err)
	}
	defer rollbackSigning(tx)
	if err := lockActiveCredentialScope(ctx, tx, preflightBinding.OrganizationID, preflightBinding.ApplicationID, preflightBinding.EnvironmentID); err != nil {
		return IssuedSession{}, err
	}
	if err := lockComponentRefreshBoundary(ctx, tx, preflightBinding); err != nil {
		return IssuedSession{}, err
	}
	binding, err := loadRefreshBinding(ctx, tx, refreshDigest[:], true)
	if err != nil {
		return IssuedSession{}, err
	}
	if !sameRefreshScope(preflightBinding, binding) || !binding.ComponentAware {
		return IssuedSession{}, ErrRefreshInvalid
	}
	validatedProof, err = dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI, ExpectedJKT: binding.DPoPJKT,
		Now: now, ClockSkew: policy.MaximumClockSkew, ClockSkewSet: true,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	if stateErr := componentRefreshStateError(binding); stateErr != nil {
		return IssuedSession{}, stateErr
	}
	if binding.Status == "rotated" {
		issued, found, cachedErr := store.loadCachedComponentRotation(
			ctx, tx, refreshDigest[:], binding, now,
		)
		if cachedErr != nil {
			return IssuedSession{}, cachedErr
		}
		if found {
			if err := tx.Commit(ctx); err != nil {
				return IssuedSession{}, fmt.Errorf("commit idempotent component refresh: %w", err)
			}
			return issued, nil
		}
		if err := revokeComponentRefreshFamily(ctx, tx, binding, now, "refresh_token_reuse", true); err != nil {
			return IssuedSession{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return IssuedSession{}, fmt.Errorf("commit component refresh reuse: %w", err)
		}
		return IssuedSession{}, ErrRefreshReused
	}
	if binding.Status == "reused" {
		return IssuedSession{}, ErrRefreshReused
	}
	if binding.Status != "active" {
		return IssuedSession{}, ErrSessionRevoked
	}
	if !binding.ExpiresAt.After(now) {
		if _, err := tx.Exec(ctx, `
			UPDATE component_refresh_tokens
			SET status = 'expired', revoked_at = $2
			WHERE component_refresh_token_id = $1 AND status = 'active'
		`, binding.RefreshTokenID, now); err != nil {
			return IssuedSession{}, fmt.Errorf("expire component refresh token: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return IssuedSession{}, fmt.Errorf("commit component refresh expiry: %w", err)
		}
		return IssuedSession{}, ErrRefreshInvalid
	}
	if !binding.IdentityExpiresAt.After(now) {
		return IssuedSession{}, ErrIdentityRefreshRequired
	}
	if err := lockActiveRefreshRevision(ctx, tx, binding, snapshot.RevisionID); err != nil {
		return IssuedSession{}, err
	}
	if policyErr := store.currentComponentRefreshPolicyError(ctx, tx, snapshot, binding, now); policyErr != nil {
		return IssuedSession{}, policyErr
	}
	if preparedAccess == nil || rotationResultID == "" {
		return IssuedSession{}, ErrRefreshInvalid
	}
	if err := store.replay.accept(ctx, tx, ReplayInput{
		OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID,
		EnvironmentID: binding.EnvironmentID, InstallationID: binding.InstallationID,
		SessionGrantID: binding.SessionGrantID, ProofJTI: validatedProof.JTI,
		HTTPMethod: input.HTTPMethod, NormalizedURI: normalizedURI,
	}); err != nil {
		return IssuedSession{}, err
	}
	issuedAccess, err := preparedAccess.IssueFor(componentAccessIssueInput(binding, newGrantID, snapshot.RevisionID), policy.AccessTokenTTL)
	if err != nil {
		return IssuedSession{}, err
	}
	issuedAt := latestTime(now, issuedAccess.IssuedAt)
	if !issuedAccess.ExpiresAt.After(issuedAt) {
		return IssuedSession{}, ErrRefreshInvalid
	}
	if err := insertRotatedGrant(
		ctx, tx, binding, newGrantID, snapshot.RevisionID, binding.TrustLevel,
		binding.IdentityVerifiedAt, binding.IdentityExpiresAt, binding.AttestedAt,
		binding.AttestationProvider, binding.AttestationExpiresAt,
		issuedAccess, issuedAt,
	); err != nil {
		return IssuedSession{}, err
	}
	refreshExpiresAt := issuedAt.Add(policy.RefreshTokenTTL)
	if !binding.ComponentIsRoot && binding.TrustExpiresAt.Before(refreshExpiresAt) {
		refreshExpiresAt = binding.TrustExpiresAt
	}
	if !refreshExpiresAt.After(issuedAt) {
		if binding.ComponentIsRoot {
			return IssuedSession{}, ErrRefreshInvalid
		}
		return IssuedSession{}, ErrComponentParentTrustExpired
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO component_refresh_tokens (
			component_refresh_token_id, component_session_family_id,
			client_component_id, component_key_id, session_grant_id,
			parent_component_refresh_token_id, token_hash, status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'staged', $8, $9)
	`, newRefreshID, binding.RefreshFamilyID, binding.ComponentID, binding.ComponentKeyID,
		newGrantID, binding.RefreshTokenID, newRefreshHash[:], issuedAt, refreshExpiresAt); err != nil {
		return IssuedSession{}, fmt.Errorf("stage rotated component refresh token: %w", err)
	}
	command, err := tx.Exec(ctx, `
		UPDATE component_refresh_tokens
		SET status = 'rotated', used_at = $3,
		    rotated_to_component_refresh_token_id = $2
		WHERE component_refresh_token_id = $1 AND token_hash = $4 AND status = 'active'
	`, binding.RefreshTokenID, newRefreshID, now, refreshDigest[:])
	if err != nil {
		return IssuedSession{}, fmt.Errorf("rotate component refresh token: %w", err)
	}
	if command.RowsAffected() != 1 {
		return IssuedSession{}, ErrRefreshReused
	}
	command, err = tx.Exec(ctx, `
		UPDATE component_refresh_tokens SET status = 'active'
		WHERE component_refresh_token_id = $1 AND status = 'staged'
	`, newRefreshID)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("activate component refresh token: %w", err)
	}
	if command.RowsAffected() != 1 {
		return IssuedSession{}, ErrRefreshInvalid
	}
	issued := issuedComponentSession(binding, issuedAccess, newRefresh, newRefreshID, refreshExpiresAt, newGrantID)
	if err := store.storeComponentRotationResult(
		ctx, tx, rotationResultID, refreshDigest[:], binding, issued, now,
	); err != nil {
		return IssuedSession{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM refresh_rotation_results WHERE expires_at <= $1`, now); err != nil {
		return IssuedSession{}, fmt.Errorf("delete expired refresh rotation results: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit component refresh rotation: %w", err)
	}
	return issued, nil
}

func componentAccessIssueInput(binding RefreshBinding, grantID, policyRevisionID string) AccessIssueInput {
	return AccessIssueInput{
		OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID,
		EnvironmentID: binding.EnvironmentID, ApplicationUserID: binding.ApplicationUserID,
		InstallationID: binding.InstallationID, InstallationFamilyID: binding.InstallationFamilyID,
		ComponentID: binding.ComponentID, ComponentDefinitionID: binding.ComponentDefinitionID,
		ComponentKind: binding.ComponentKind, ComponentIsRoot: binding.ComponentIsRoot,
		TrustSource: binding.TrustSource, AttestationProvider: binding.AttestationProvider,
		ParentComponentID:         binding.ParentComponentID,
		ParentAttestationProvider: binding.ParentAttestationProvider,
		DelegationID:              binding.DelegationID, Features: append([]string(nil), binding.GrantedFeatures...),
		SessionGrantID: grantID, IdentityProvider: binding.IdentityProvider,
		TrustLevel: binding.TrustLevel, PolicyRevisionID: policyRevisionID,
		DPoPJKT: binding.DPoPJKT,
	}
}

func issuedComponentSession(
	binding RefreshBinding,
	access IssuedAccess,
	refresh RefreshToken,
	refreshID string,
	refreshExpiresAt time.Time,
	grantID string,
) IssuedSession {
	return IssuedSession{
		Access: access, Refresh: refresh, RefreshID: refreshID,
		RefreshFamilyID: binding.RefreshFamilyID, RefreshExpiresAt: refreshExpiresAt,
		GrantID: grantID,
		Installation: Installation{
			ID: binding.InstallationID, Platform: binding.Platform,
			DPoPJKT: binding.DPoPJKT, Status: "active", AppVersion: binding.AppVersion,
		},
		Family: InstallationFamily{ID: binding.InstallationFamilyID, Status: binding.FamilyStatus},
		Component: ClientComponent{
			ID: binding.ComponentID, DefinitionID: binding.ComponentDefinitionID,
			Kind: binding.ComponentKind, Platform: binding.Platform,
			IsRoot: binding.ComponentIsRoot, Status: binding.ComponentStatus,
			KeyID: binding.ComponentKeyID, DPoPJKT: binding.DPoPJKT,
			TrustSource: binding.TrustSource, AttestationProvider: binding.AttestationProvider,
			ParentComponentID:         binding.ParentComponentID,
			ParentAttestationProvider: binding.ParentAttestationProvider,
			DelegationID:              binding.DelegationID,
			GrantedFeatures:           append([]string(nil), binding.GrantedFeatures...),
		},
		Trust: Trust{
			Provider: binding.AttestationProvider, Level: binding.TrustLevel,
			VerifiedAt: binding.AttestedAt, ExpiresAt: binding.AttestationExpiresAt,
		},
	}
}

func componentRefreshStateError(binding RefreshBinding) error {
	if binding.FamilyStatus != "active" {
		return ErrInstallationFamilyRevoked
	}
	if binding.ComponentStatus != "active" || binding.ComponentKeyStatus != "active" {
		return ErrComponentRevoked
	}
	if binding.ComponentSessionStatus != "active" {
		return ErrSessionRevoked
	}
	if binding.grantRevoked || binding.userStatus != "active" ||
		binding.applicationStatus != "active" || binding.environmentStatus != "active" ||
		binding.organizationStatus != "active" {
		return ErrSessionRevoked
	}
	return nil
}

func lockComponentRefreshBoundary(ctx context.Context, tx pgx.Tx, binding RefreshBinding) error {
	var familyStatus, componentStatus, keyStatus, sessionStatus, storedJKT string
	err := tx.QueryRow(ctx, `
		SELECT f.status, c.status, k.status, sf.status, k.dpop_jkt
		FROM installation_families f
		JOIN client_components c
		  ON c.installation_family_id = f.installation_family_id
		JOIN component_keys k
		  ON k.client_component_id = c.client_component_id
		JOIN component_session_families sf
		  ON sf.client_component_id = c.client_component_id
		 AND sf.component_key_id = k.component_key_id
		WHERE f.installation_family_id = $1
		  AND c.client_component_id = $2
		  AND k.component_key_id = $3
		  AND sf.component_session_family_id = $4
		FOR SHARE OF f, c, k, sf
	`, binding.InstallationFamilyID, binding.ComponentID, binding.ComponentKeyID,
		binding.RefreshFamilyID).Scan(
		&familyStatus, &componentStatus, &keyStatus, &sessionStatus, &storedJKT,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRefreshInvalid
	}
	if err != nil {
		return fmt.Errorf("lock component refresh boundary: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedJKT), []byte(binding.DPoPJKT)) != 1 ||
		familyStatus != binding.FamilyStatus || componentStatus != binding.ComponentStatus ||
		keyStatus != binding.ComponentKeyStatus || sessionStatus != binding.ComponentSessionStatus {
		return ErrRefreshInvalid
	}
	return nil
}

func (store *Store) currentComponentRefreshPolicyError(
	ctx context.Context,
	query refreshBindingQuerier,
	snapshot configuration.ActiveSnapshot,
	binding RefreshBinding,
	now time.Time,
) error {
	if stateErr := componentRefreshStateError(binding); stateErr != nil {
		return stateErr
	}
	definition, ok := snapshot.ComponentDefinition(binding.ComponentDefinitionID)
	if !ok || definition.Platform != binding.Platform || definition.Kind != binding.ComponentKind ||
		(definition.FamilyRole == "root") != binding.ComponentIsRoot ||
		!componentFeatureSubset(binding.GrantedFeatures, definition.AllowedFeatures) {
		return ErrComponentNotConfigured
	}
	if !binding.TrustExpiresAt.IsZero() && !binding.TrustExpiresAt.After(now) {
		return ErrAttestationRefreshNeeded
	}
	if binding.ComponentIsRoot {
		return currentRefreshPolicyError(snapshot, binding, now)
	}
	if definition.Delegation == nil || binding.DelegationID == "" || binding.ParentComponentID == "" {
		return ErrSessionRevoked
	}
	var delegationExpiresAt time.Time
	var delegationRevokedAt, parentRevokedAt, parentTrustExpiresAt *time.Time
	var parentStatus, parentTrustSource string
	err := query.QueryRow(ctx, `
		SELECT d.expires_at, d.revoked_at, p.status, p.revoked_at,
		       p.trust_source, p.trust_expires_at
		FROM component_delegations d
		JOIN client_components p ON p.client_component_id = d.parent_component_id
		WHERE d.component_delegation_id = $1
		  AND d.child_component_id = $2
		  AND d.parent_component_id = $3
		  AND d.configuration_revision_id = $4
	`, binding.DelegationID, binding.ComponentID, binding.ParentComponentID,
		snapshot.RevisionID).Scan(
		&delegationExpiresAt, &delegationRevokedAt, &parentStatus, &parentRevokedAt,
		&parentTrustSource, &parentTrustExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) || delegationRevokedAt != nil {
		return ErrSessionRevoked
	}
	if err != nil {
		return ErrSessionScope
	}
	if parentStatus != "active" || parentRevokedAt != nil {
		return ErrComponentRevoked
	}
	if !delegationExpiresAt.After(now) ||
		(parentTrustExpiresAt != nil && !parentTrustExpiresAt.After(now)) ||
		(parentTrustSource != "direct_attested" && componentTrustRequiresAttestedParent(binding.TrustSource)) {
		return ErrAttestationRefreshNeeded
	}
	return nil
}

func componentTrustRequiresAttestedParent(trustSource string) bool {
	return trustSource == "delegated_from_attested_root" || trustSource == "delegated_direct_attested"
}

func (store *Store) storeComponentRotationResult(
	ctx context.Context,
	tx pgx.Tx,
	resultID string,
	oldTokenHash []byte,
	binding RefreshBinding,
	issued IssuedSession,
	now time.Time,
) error {
	payload := cachedComponentRotation{
		AccessToken:    issued.Access.Token.Reveal(),
		AccessJTIHash:  base64.RawURLEncoding.EncodeToString(issued.Access.JTIHash[:]),
		AccessIssuedAt: issued.Access.IssuedAt, AccessExpiresAt: issued.Access.ExpiresAt,
		RefreshToken: issued.Refresh.Reveal(), RefreshTokenID: issued.RefreshID,
		RefreshExpiresAt: issued.RefreshExpiresAt, SessionGrantID: issued.GrantID,
		SessionFamilyID: issued.RefreshFamilyID,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return ErrRefreshInvalid
	}
	defer clear(plaintext)
	envelope, err := store.rotationProtector.Encrypt(plaintext, secrets.AssociatedData{
		OrganizationID: binding.OrganizationID, EnvironmentID: binding.EnvironmentID,
		SecretID: resultID, SecretVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		return fmt.Errorf("encrypt refresh rotation result: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_rotation_results (
			refresh_rotation_result_id, old_refresh_token_hash,
			client_component_id, component_key_id, dpop_jkt,
			rotation_response_ciphertext, rotation_response_nonce,
			encryption_format_version, encryption_algorithm, master_key_identifier,
			created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, resultID, oldTokenHash, binding.ComponentID, binding.ComponentKeyID, binding.DPoPJKT,
		envelope.Ciphertext, envelope.Nonce, envelope.FormatVersion, envelope.Algorithm,
		envelope.KeyID, now, now.Add(componentRefreshIdempotencyGrace)); err != nil {
		return fmt.Errorf("store refresh rotation result: %w", err)
	}
	return nil
}

func (store *Store) loadCachedComponentRotation(
	ctx context.Context,
	tx pgx.Tx,
	oldTokenHash []byte,
	binding RefreshBinding,
	now time.Time,
) (IssuedSession, bool, error) {
	var resultID, algorithm, keyID string
	var ciphertext, nonce []byte
	var formatVersion int
	err := tx.QueryRow(ctx, `
		SELECT refresh_rotation_result_id, rotation_response_ciphertext,
		       rotation_response_nonce, encryption_format_version,
		       encryption_algorithm, master_key_identifier
		FROM refresh_rotation_results
		WHERE old_refresh_token_hash = $1
		  AND client_component_id = $2
		  AND component_key_id = $3
		  AND dpop_jkt = $4
		  AND expires_at > $5
	`, oldTokenHash, binding.ComponentID, binding.ComponentKeyID, binding.DPoPJKT, now).Scan(
		&resultID, &ciphertext, &nonce, &formatVersion, &algorithm, &keyID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return IssuedSession{}, false, nil
	}
	if err != nil {
		return IssuedSession{}, false, fmt.Errorf("load refresh rotation result: %w", err)
	}
	plaintext, err := store.rotationProtector.Decrypt(secrets.Envelope{
		FormatVersion: formatVersion, Algorithm: algorithm, KeyID: keyID,
		Nonce: nonce, Ciphertext: ciphertext,
	}, secrets.AssociatedData{
		OrganizationID: binding.OrganizationID, EnvironmentID: binding.EnvironmentID,
		SecretID: resultID, SecretVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		return IssuedSession{}, false, fmt.Errorf("decrypt refresh rotation result: %w", err)
	}
	defer clear(plaintext)
	var cached cachedComponentRotation
	if err := json.Unmarshal(plaintext, &cached); err != nil {
		return IssuedSession{}, false, ErrRefreshInvalid
	}
	access, err := NewAccessToken(cached.AccessToken)
	if err != nil {
		return IssuedSession{}, false, ErrRefreshInvalid
	}
	refresh, err := NewRefreshToken(cached.RefreshToken)
	if err != nil {
		return IssuedSession{}, false, ErrRefreshInvalid
	}
	jtiHash, err := base64.RawURLEncoding.Strict().DecodeString(cached.AccessJTIHash)
	if err != nil || len(jtiHash) != sha256.Size ||
		id.Validate(cached.RefreshTokenID, id.ComponentRefresh) != nil ||
		id.Validate(cached.SessionGrantID, id.SessionGrant) != nil ||
		cached.SessionFamilyID != binding.RefreshFamilyID ||
		!cached.AccessExpiresAt.After(cached.AccessIssuedAt) ||
		!cached.RefreshExpiresAt.After(cached.AccessIssuedAt) {
		return IssuedSession{}, false, ErrRefreshInvalid
	}
	var digest [sha256.Size]byte
	copy(digest[:], jtiHash)
	issued := issuedComponentSession(binding, IssuedAccess{
		Token: access, JTIHash: digest, IssuedAt: cached.AccessIssuedAt.UTC(),
		ExpiresAt: cached.AccessExpiresAt.UTC(),
	}, refresh, cached.RefreshTokenID, cached.RefreshExpiresAt.UTC(), cached.SessionGrantID)
	return issued, true, nil
}

func revokeComponentRefreshFamily(
	ctx context.Context,
	tx pgx.Tx,
	binding RefreshBinding,
	now time.Time,
	reason string,
	markReuse bool,
) error {
	if markReuse {
		if _, err := tx.Exec(ctx, `
			UPDATE component_refresh_tokens
			SET status = CASE
			        WHEN component_refresh_token_id = $2 THEN 'reused'
			        WHEN status IN ('staged', 'active') THEN 'revoked'
			        ELSE status
			    END,
			    revoked_at = CASE
			        WHEN component_refresh_token_id = $2 OR status IN ('staged', 'active')
			        THEN COALESCE(revoked_at, GREATEST(issued_at, $3))
			        ELSE revoked_at
			    END
			WHERE component_session_family_id = $1
		`, binding.RefreshFamilyID, binding.RefreshTokenID, now); err != nil {
			return fmt.Errorf("mark component refresh reuse: %w", err)
		}
	} else if _, err := tx.Exec(ctx, `
		UPDATE component_refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2))
		WHERE component_session_family_id = $1 AND status IN ('staged', 'active')
	`, binding.RefreshFamilyID, now); err != nil {
		return fmt.Errorf("revoke component refresh family: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2)),
		    revoke_reason = COALESCE(revoke_reason, $3)
		WHERE component_session_family_id = $1 AND revoked_at IS NULL
	`, binding.RefreshFamilyID, now, reason); err != nil {
		return fmt.Errorf("revoke component session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE component_session_families
		SET status = 'revoked', updated_at = $2, revoked_at = $2,
		    revocation_reason = $3
		WHERE component_session_family_id = $1 AND status = 'active'
	`, binding.RefreshFamilyID, now, reason); err != nil {
		return fmt.Errorf("revoke component session family: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM refresh_rotation_results
		WHERE client_component_id = $1
		  AND old_refresh_token_hash IN (
			SELECT token_hash FROM component_refresh_tokens
			WHERE component_session_family_id = $2
		  )
	`, binding.ComponentID, binding.RefreshFamilyID); err != nil {
		return fmt.Errorf("delete refresh rotation result: %w", err)
	}
	return nil
}

func lockRefreshInstallation(ctx context.Context, tx pgx.Tx, binding RefreshBinding) error {
	var storedJKT, status string
	err := tx.QueryRow(ctx, `
		SELECT dpop_jkt, status
		FROM installations
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5
		FOR SHARE
	`, binding.OrganizationID, binding.ApplicationID, binding.EnvironmentID,
		binding.ApplicationUserID, binding.InstallationID).Scan(&storedJKT, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRefreshInvalid
	}
	if err != nil {
		return fmt.Errorf("lock refresh installation: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedJKT), []byte(binding.DPoPJKT)) != 1 ||
		(status != "active" && status != "revoked") {
		return ErrRefreshInvalid
	}
	return nil
}

func currentRefreshPolicyError(snapshot configuration.ActiveSnapshot, binding RefreshBinding, now time.Time) error {
	if _, ok := snapshot.IdentityProvider(binding.IdentityProvider); !ok {
		return ErrIdentityRefreshRequired
	}
	policy, selection, ok := snapshot.RequiredAttestationForPlatform(binding.Platform)
	if !ok || policy.ID == "" || selection.Mode != "required" ||
		!validAttestationProvider(selection.Provider) ||
		!trustLevelPattern.MatchString(selection.MinimumTrustLevel) ||
		policy.MaxAge < time.Minute || policy.MaxAge > 30*24*time.Hour ||
		selection.Provider != binding.AttestationProvider ||
		!trustSatisfies(binding.TrustLevel, selection.MinimumTrustLevel) {
		return ErrAttestationStepUpRequired
	}
	if binding.AttestedAt.IsZero() || !binding.AttestationExpiresAt.After(now) {
		return ErrAttestationRefreshNeeded
	}
	if now.IsZero() {
		return ErrAttestationStepUpRequired
	}
	if !binding.AttestedAt.Add(policy.MaxAge).After(now) {
		return ErrAttestationRefreshNeeded
	}
	return nil
}

func lockActiveRefreshRevision(ctx context.Context, tx pgx.Tx, binding RefreshBinding, revisionID string) error {
	var activeRevisionID string
	err := tx.QueryRow(ctx, `
		SELECT config_revision_id
		FROM active_config_revisions
		WHERE organization_id = $1
		  AND application_id = $2
		  AND environment_id = $3
		FOR SHARE
	`, binding.OrganizationID, binding.ApplicationID, binding.EnvironmentID).Scan(&activeRevisionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionScope
	}
	if err != nil {
		return fmt.Errorf("lock active refresh policy revision: %w", err)
	}
	if activeRevisionID != revisionID {
		return ErrAttestationStepUpRequired
	}
	return nil
}

func sameRefreshScope(left, right RefreshBinding) bool {
	if left.ComponentAware != right.ComponentAware {
		return false
	}
	if left.ComponentAware && (left.InstallationFamilyID != right.InstallationFamilyID ||
		left.ComponentID != right.ComponentID ||
		left.ComponentDefinitionID != right.ComponentDefinitionID ||
		left.ComponentKind != right.ComponentKind ||
		left.ComponentIsRoot != right.ComponentIsRoot ||
		left.ComponentKeyID != right.ComponentKeyID ||
		left.DPoPJKT != right.DPoPJKT ||
		left.TrustSource != right.TrustSource) {
		return false
	}
	return left.RefreshTokenID == right.RefreshTokenID &&
		left.RefreshFamilyID == right.RefreshFamilyID &&
		left.OrganizationID == right.OrganizationID &&
		left.ApplicationID == right.ApplicationID &&
		left.EnvironmentID == right.EnvironmentID &&
		left.ApplicationUserID == right.ApplicationUserID &&
		left.InstallationID == right.InstallationID &&
		left.SessionGrantID == right.SessionGrantID &&
		left.DPoPJKT == right.DPoPJKT &&
		left.Platform == right.Platform
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
	componentBinding, found, err := loadComponentRefreshBinding(ctx, query, tokenHash, forUpdate)
	if err != nil {
		return RefreshBinding{}, err
	}
	if found {
		return componentBinding, nil
	}
	return loadLegacyRefreshBinding(ctx, query, tokenHash, forUpdate)
}

func loadLegacyRefreshBinding(ctx context.Context, query refreshBindingQuerier, tokenHash []byte, forUpdate bool) (RefreshBinding, error) {
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

func loadComponentRefreshBinding(
	ctx context.Context,
	query refreshBindingQuerier,
	tokenHash []byte,
	forUpdate bool,
) (RefreshBinding, bool, error) {
	statement := `
		SELECT r.component_refresh_token_id, r.component_session_family_id,
		       sf.organization_id, sf.application_id, sf.environment_id,
		       sf.application_user_id, g.installation_id, r.session_grant_id,
		       r.status, r.expires_at, g.policy_revision_id, g.trust_level,
		       g.identity_provider_key, g.identity_verified_at,
		       g.identity_expires_at, g.attested_at, g.attestation_provider,
		       g.attestation_expires_at, g.revoked_at IS NOT NULL,
		       k.dpop_jkt, k.public_jwk,
		       f.installation_family_id, f.status,
		       c.client_component_id, c.component_definition_id, c.component_kind,
		       c.is_root, c.status, c.trust_source, c.trust_attestation_provider,
		       c.trust_verified_at, c.trust_expires_at,
		       c.trust_parent_component_id, p.trust_attestation_provider,
		       c.trust_delegation_id,
		       c.granted_features, c.platform, c.app_version,
		       k.component_key_id, k.status, sf.status,
		       u.status, a.status, e.status, o.status
		FROM component_refresh_tokens r
		JOIN component_session_families sf
		  ON sf.component_session_family_id = r.component_session_family_id
		JOIN session_grants g ON g.session_grant_id = r.session_grant_id
		JOIN component_keys k
		  ON k.component_key_id = r.component_key_id
		 AND k.client_component_id = r.client_component_id
		JOIN client_components c
		  ON c.client_component_id = r.client_component_id
		JOIN installation_families f
		  ON f.installation_family_id = c.installation_family_id
		LEFT JOIN client_components p
		  ON p.client_component_id = c.trust_parent_component_id
		JOIN application_users u
		  ON u.organization_id = sf.organization_id AND u.application_id = sf.application_id
		 AND u.application_user_id = sf.application_user_id
		JOIN applications a
		  ON a.organization_id = sf.organization_id AND a.application_id = sf.application_id
		JOIN environments e
		  ON e.organization_id = sf.organization_id AND e.application_id = sf.application_id
		 AND e.environment_id = sf.environment_id
		JOIN organizations o ON o.organization_id = sf.organization_id
		WHERE r.token_hash = $1
	`
	if forUpdate {
		statement += " FOR UPDATE OF r"
	}
	result := RefreshBinding{ComponentAware: true}
	var encodedJWK []byte
	var identityProvider, attestationProvider, componentAttestationProvider *string
	var identityExpiresAt, attestedAt, attestationExpiresAt *time.Time
	var trustVerifiedAt, trustExpiresAt *time.Time
	var parentComponentID, parentAttestationProvider, delegationID *string
	err := query.QueryRow(ctx, statement, tokenHash).Scan(
		&result.RefreshTokenID, &result.RefreshFamilyID,
		&result.OrganizationID, &result.ApplicationID, &result.EnvironmentID,
		&result.ApplicationUserID, &result.InstallationID, &result.SessionGrantID,
		&result.Status, &result.ExpiresAt, &result.PolicyRevisionID, &result.TrustLevel,
		&identityProvider, &result.IdentityVerifiedAt,
		&identityExpiresAt, &attestedAt, &attestationProvider,
		&attestationExpiresAt, &result.grantRevoked,
		&result.DPoPJKT, &encodedJWK,
		&result.InstallationFamilyID, &result.FamilyStatus,
		&result.ComponentID, &result.ComponentDefinitionID, &result.ComponentKind,
		&result.ComponentIsRoot, &result.ComponentStatus, &result.TrustSource,
		&componentAttestationProvider, &trustVerifiedAt, &trustExpiresAt,
		&parentComponentID, &parentAttestationProvider, &delegationID,
		&result.GrantedFeatures, &result.Platform, &result.AppVersion,
		&result.ComponentKeyID, &result.ComponentKeyStatus, &result.ComponentSessionStatus,
		&result.userStatus, &result.applicationStatus, &result.environmentStatus,
		&result.organizationStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshBinding{}, false, nil
	}
	if err != nil {
		return RefreshBinding{}, false, fmt.Errorf("resolve component refresh-token binding: %w", err)
	}
	if identityProvider == nil || identityExpiresAt == nil || attestedAt == nil ||
		attestationProvider == nil || attestationExpiresAt == nil {
		if result.grantRevoked || result.Status == "revoked" {
			return RefreshBinding{}, false, ErrSessionRevoked
		}
		return RefreshBinding{}, false, ErrRefreshInvalid
	}
	result.IdentityProvider = *identityProvider
	result.AttestationProvider = *attestationProvider
	if componentAttestationProvider != nil && result.AttestationProvider != *componentAttestationProvider {
		return RefreshBinding{}, false, ErrRefreshInvalid
	}
	if parentComponentID != nil {
		result.ParentComponentID = *parentComponentID
	}
	if parentAttestationProvider != nil {
		result.ParentAttestationProvider = *parentAttestationProvider
	}
	if delegationID != nil {
		result.DelegationID = *delegationID
	}
	result.IdentityExpiresAt = identityExpiresAt.UTC()
	result.AttestedAt = attestedAt.UTC()
	result.AttestationExpiresAt = attestationExpiresAt.UTC()
	if trustVerifiedAt != nil {
		result.TrustVerifiedAt = trustVerifiedAt.UTC()
	}
	if trustExpiresAt != nil {
		result.TrustExpiresAt = trustExpiresAt.UTC()
	}
	result.DPoPPublicJWK, err = decodeStoredDPoPPublicJWK(encodedJWK, result.DPoPJKT)
	if err != nil ||
		id.Validate(result.RefreshTokenID, id.ComponentRefresh) != nil ||
		id.Validate(result.RefreshFamilyID, id.ComponentSession) != nil ||
		id.Validate(result.InstallationFamilyID, id.InstallationFamily) != nil ||
		id.Validate(result.ComponentID, id.ClientComponent) != nil ||
		id.Validate(result.ComponentKeyID, id.ComponentKey) != nil ||
		id.Validate(result.SessionGrantID, id.SessionGrant) != nil ||
		id.Validate(result.InstallationID, id.Installation) != nil ||
		!sessionIdentifierPattern.MatchString(result.ComponentDefinitionID) ||
		!componentKindPattern.MatchString(result.ComponentKind) ||
		!trustSourcePattern.MatchString(result.TrustSource) ||
		!sessionIdentifierList(result.GrantedFeatures) {
		return RefreshBinding{}, false, ErrRefreshInvalid
	}
	result.InstallationStatus = result.FamilyStatus
	result.InstallationTrust = result.TrustLevel
	return result, true, nil
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
			attested_at, attestation_provider, attestation_expires_at, issued_at, expires_at,
			installation_family_id, client_component_id, component_definition_id,
			component_kind, component_is_root, trust_source, component_session_family_id
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
		       $19, $20, $21, $22, $23, $24, $25
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
		attestedAt, attestationProvider, attestationExpiresAt, issuedAt, access.ExpiresAt,
		nullIfEmpty(binding.InstallationFamilyID), nullIfEmpty(binding.ComponentID),
		nullIfEmpty(binding.ComponentDefinitionID), nullIfEmpty(binding.ComponentKind),
		nullableBool(binding.ComponentID, binding.ComponentIsRoot), nullIfEmpty(binding.TrustSource),
		componentSessionFamilyValue(binding))
	if err != nil {
		return fmt.Errorf("store rotated session grant: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSessionScope
	}
	return nil
}

func componentSessionFamilyValue(binding RefreshBinding) any {
	if !binding.ComponentAware {
		return nil
	}
	return binding.RefreshFamilyID
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
