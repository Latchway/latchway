package session

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/identity"
)

// VerifySessionIdentity uses still-live refresh possession, not cached access
// authorization, so an expired ID token cannot block its own recovery. It does
// not grant a session, extend attestation, rotate credentials or touch quota.
func (coordinator *clientCoordinator) VerifySessionIdentity(ctx context.Context, input clientapi.VerifyIdentityInput) (clientapi.VerifyIdentityResult, error) {
	refresh, err := NewRefreshToken(input.RefreshToken.Reveal())
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure("session_expired")
	}
	proof, err := NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure("dpop_invalid")
	}
	binding, err := coordinator.sessions.InspectRefresh(ctx, refresh)
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure(mapSessionError(err))
	}
	if err := identityRefreshPossessionError(binding, coordinator.now().UTC()); err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure(mapSessionError(err))
	}
	environment, err := coordinator.resolveEnvironmentByID(ctx, binding.OrganizationID, binding.ApplicationID, binding.EnvironmentID)
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure("session_revoked")
	}
	snapshot, err := coordinator.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID, EnvironmentID: binding.EnvironmentID,
	})
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure("server_not_ready")
	}
	rotate := RotateInput{Runtime: input.Metadata.Runtime(), RefreshToken: refresh, DPoPProof: proof,
		HTTPMethod: input.Metadata.HTTPMethod, RequestURI: &input.Metadata.TargetURL, Origin: input.Metadata.Origin}
	if err := validateIdentityRefreshRequest(rotate, binding, snapshot, coordinator.now().UTC()); err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure(mapSessionError(err))
	}
	if input.IdentityProvider != binding.IdentityProvider {
		return clientapi.VerifyIdentityResult{}, clientFailure("identity_token_invalid")
	}
	provider, ok := snapshot.IdentityProvider(input.IdentityProvider)
	if !ok {
		return clientapi.VerifyIdentityResult{}, clientFailure("identity_token_invalid")
	}
	credential, err := identity.NewRawIdentityCredential(input.IdentityToken.Reveal())
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure("identity_token_invalid")
	}
	verifier, err := coordinator.identityVerifier(environment, snapshot, provider)
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure("server_not_ready")
	}
	principal, err := verifier.Verify(ctx, credential)
	if err != nil {
		return clientapi.VerifyIdentityResult{}, clientFailure(mapIdentityError(err))
	}
	if principal.ProviderID != binding.IdentityProvider {
		return clientapi.VerifyIdentityResult{}, clientFailure("identity_token_invalid")
	}
	// Network/key verification finishes before acquiring database locks. The
	// transaction rechecks configuration, key, grant and revocation afterwards.
	verifiedAt, err := coordinator.sessions.commitVerifiedIdentity(ctx, rotate, binding, snapshot, principal, coordinator.users)
	if err != nil {
		if err == identity.ErrCredentialInvalid || err == identity.ErrCredentialExpired || err == identity.ErrUserBlocked {
			return clientapi.VerifyIdentityResult{}, clientFailure(mapIdentityError(err))
		}
		return clientapi.VerifyIdentityResult{}, clientFailure(mapSessionError(err))
	}
	return clientapi.VerifyIdentityResult{InstallationID: binding.InstallationID,
		Identity: clientapi.VerifiedIdentity{Provider: principal.ProviderID, Issuer: principal.Issuer,
			Subject: principal.Subject, Audience: append([]string(nil), principal.Audience...), VerifiedAt: verifiedAt, ExpiresAt: principal.ExpiresAt}}, nil
}

func identityRefreshPossessionError(binding RefreshBinding, now time.Time) error {
	if binding.ComponentAware {
		if err := componentRefreshStateError(binding); err != nil {
			return err
		}
	} else if binding.InstallationStatus != "active" || binding.InstallationTrust != binding.TrustLevel ||
		binding.grantRevoked || binding.userStatus != "active" || binding.applicationStatus != "active" ||
		binding.environmentStatus != "active" || binding.organizationStatus != "active" {
		return ErrSessionRevoked
	}
	if binding.Status != "active" || !binding.ExpiresAt.After(now) {
		return ErrRefreshInvalid
	}
	return nil
}

func validateIdentityRefreshRequest(input RotateInput, binding RefreshBinding, snapshot configuration.ActiveSnapshot, now time.Time) error {
	if err := input.validate(); err != nil {
		return err
	}
	if !snapshotOriginAllowed(snapshot, binding.Platform, input.Origin) {
		return ErrSessionInvalid
	}
	if !requestRuntimeAllowed(snapshot, input.Runtime, binding.Platform, binding.ComponentAware && !binding.ComponentIsRoot) {
		return ErrClientRuntime
	}
	if binding.ComponentAware && !binding.ComponentIsRoot && !requestDelegatedRuntimeAllowed(snapshot, input.Runtime, binding.HostPlatform, binding.ComponentDefinitionID) {
		return ErrClientRuntime
	}
	_, err := dpop.Validate(input.DPoPProof.value, dpop.Options{Method: input.HTTPMethod, URI: input.RequestURI,
		ExpectedJKT: binding.DPoPJKT, Now: now, ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true})
	return err
}

func (store *Store) commitVerifiedIdentity(ctx context.Context, input RotateInput, preflight RefreshBinding,
	snapshot configuration.ActiveSnapshot, principal identity.VerifiedPrincipal, users *identity.UserStore) (time.Time, error) {
	now := store.now().UTC().Truncate(time.Second)
	if !principal.ExpiresAt.After(now) {
		return time.Time{}, identity.ErrCredentialExpired
	}
	if principal.ProviderID != preflight.IdentityProvider {
		return time.Time{}, identity.ErrCredentialInvalid
	}
	digest := sha256.Sum256([]byte(input.RefreshToken.value))
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return time.Time{}, fmt.Errorf("begin identity verification: %w", err)
	}
	defer rollbackSigning(tx)
	if err := lockActiveCredentialScope(ctx, tx, preflight.OrganizationID, preflight.ApplicationID, preflight.EnvironmentID); err != nil {
		return time.Time{}, err
	}
	if preflight.ComponentAware {
		if err := lockComponentRefreshBoundary(ctx, tx, preflight); err != nil {
			return time.Time{}, err
		}
	} else if err := lockRefreshInstallation(ctx, tx, preflight); err != nil {
		return time.Time{}, err
	}
	binding, err := loadRefreshBinding(ctx, tx, digest[:], true)
	if err != nil {
		return time.Time{}, err
	}
	if !sameRefreshScope(preflight, binding) {
		return time.Time{}, ErrRefreshInvalid
	}
	if err := identityRefreshPossessionError(binding, now); err != nil {
		return time.Time{}, err
	}
	if err := lockActiveRefreshRevision(ctx, tx, binding, snapshot.RevisionID); err != nil {
		return time.Time{}, err
	}
	if err := validateIdentityRefreshRequest(input, binding, snapshot, now); err != nil {
		return time.Time{}, err
	}
	if binding.ComponentAware {
		if err := store.currentComponentRefreshPolicyError(ctx, tx, snapshot, binding, now); err != nil {
			return time.Time{}, err
		}
	} else if err := currentRefreshPolicyError(snapshot, binding, now); err != nil {
		return time.Time{}, err
	}
	validated, err := dpop.Validate(input.DPoPProof.value, dpop.Options{Method: input.HTTPMethod, URI: input.RequestURI,
		ExpectedJKT: binding.DPoPJKT, Now: now, ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true})
	if err != nil {
		return time.Time{}, err
	}
	uri, err := dpop.NormalizeHTU(input.RequestURI)
	if err != nil {
		return time.Time{}, err
	}
	if err := users.RefreshMatchingUserTx(ctx, tx, identity.UserScope{OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID}, binding.ApplicationUserID, principal, now); err != nil {
		return time.Time{}, err
	}
	if err := store.replay.accept(ctx, tx, ReplayInput{OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID,
		EnvironmentID: binding.EnvironmentID, InstallationID: binding.InstallationID, SessionGrantID: binding.SessionGrantID,
		ProofJTI: validated.JTI, HTTPMethod: input.HTTPMethod, NormalizedURI: uri}); err != nil {
		return time.Time{}, err
	}
	command, err := tx.Exec(ctx, `UPDATE session_grants SET identity_verified_at = $2, identity_expires_at = $3
		WHERE session_grant_id = $1 AND revoked_at IS NULL`, binding.SessionGrantID, now, principal.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("renew verified identity freshness: %w", err)
	}
	if command.RowsAffected() != 1 {
		return time.Time{}, ErrSessionRevoked
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, fmt.Errorf("commit verified identity: %w", err)
	}
	return now, nil
}
