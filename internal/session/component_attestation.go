package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
)

const componentAttestationPurpose = "component_attestation_step_up"

// ComponentAttestationChallenge is a one-use, component-scoped App Attest
// boundary. The binding carries every family and key identity that must remain
// stable between challenge creation and exchange.
type ComponentAttestationChallenge struct {
	ID                      string
	Nonce                   string
	Binding                 attestation.Binding
	BindingHash             [sha256.Size]byte
	OrganizationID          string
	EnvironmentID           string
	ConfigurationRevisionID string
	Attestation             ChallengeAttestationPolicy
	ExpiresAt               time.Time
}

type ComponentAttestationChallengeInput struct {
	Access      AccessRequestInput
	ComponentID string
}

func componentStepUpSelection(
	snapshot configuration.ActiveSnapshot,
	definitionID string,
) (configuration.ComponentDefinition, configuration.AttestationPolicy, configuration.PlatformAttestation, error) {
	definition, ok := snapshot.ComponentDefinition(definitionID)
	if !ok || definition.FamilyRole != "delegated" || definition.Delegation == nil ||
		definition.Attestation.Strategy != "delegated" || !definition.Attestation.DirectStepUp ||
		definition.Attestation.DirectAttestationPolicy == "" ||
		!componentDirectStepUpSupported(definition.Platform, definition.Kind) ||
		len(definition.Identifiers.BundleIdentifiers) != 1 {
		return configuration.ComponentDefinition{}, configuration.AttestationPolicy{}, configuration.PlatformAttestation{}, ErrComponentNotConfigured
	}
	policy, ok := snapshot.AttestationPolicy(definition.Attestation.DirectAttestationPolicy)
	if !ok || policy.MaxAge < time.Minute || policy.MaxAge > 30*24*time.Hour {
		return configuration.ComponentDefinition{}, configuration.AttestationPolicy{}, configuration.PlatformAttestation{}, ErrComponentNotConfigured
	}
	selection, ok := snapshot.SelectAttestation(policy.ID, definition.Platform)
	// Component-only App Attest policies are preferred in the shared snapshot
	// so they can never become an ambiguous initial-session policy. This
	// endpoint makes the explicitly selected proof mandatory and canonicalizes
	// the verifier input to required.
	if !ok || selection.Provider != "app_attest" || selection.Mode != "preferred" ||
		selection.MinimumTrustLevel != "app_verified" || selection.AppAttest == nil ||
		selection.AppAttest.BundleID != definition.Identifiers.BundleIdentifiers[0] {
		return configuration.ComponentDefinition{}, configuration.AttestationPolicy{}, configuration.PlatformAttestation{}, ErrComponentNotConfigured
	}
	selection.Mode = "required"
	return definition, policy, selection, nil
}

func componentDirectStepUpSupported(platform, kind string) bool {
	return (platform == "ios" || platform == "react_native_ios" || platform == "watchos") &&
		(kind == "action_extension" || kind == "sso_extension" || kind == "watch_extension")
}

// CreateComponentAttestationChallenge authorizes the current delegated
// component and persists a version-2 binding under the same transaction as
// DPoP replay acceptance.
func (store *Store) CreateComponentAttestationChallenge(
	ctx context.Context,
	input ComponentAttestationChallengeInput,
) (ComponentAttestationChallenge, error) {
	if id.Validate(input.ComponentID, id.ClientComponent) != nil ||
		input.ComponentID != input.Access.Principal.ComponentID ||
		input.Access.Principal.ComponentIsRoot {
		return ComponentAttestationChallenge{}, ErrComponentNotProvisioned
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: input.Access.Principal.OrganizationID,
		ApplicationID:  input.Access.Principal.ApplicationID,
		EnvironmentID:  input.Access.Principal.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != input.Access.Principal.PolicyRevisionID {
		return ComponentAttestationChallenge{}, ErrComponentNotConfigured
	}
	definition, policy, selection, err := componentStepUpSelection(snapshot, input.Access.Principal.ComponentDefinitionID)
	if err != nil {
		return ComponentAttestationChallenge{}, err
	}
	challengeID, err := id.New(id.SessionChallenge)
	if err != nil {
		return ComponentAttestationChallenge{}, fmt.Errorf("generate component attestation challenge ID: %w", err)
	}
	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(store.random, nonceBytes); err != nil {
		return ComponentAttestationChallenge{}, errors.New("generate component attestation challenge nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	nonceHash := sha256.Sum256(nonceBytes)
	var result ComponentAttestationChallenge
	_, err = store.authorizeAccess(ctx, input.Access, false, true, func(
		ctx context.Context,
		tx pgx.Tx,
		state authorizationState,
		now time.Time,
	) error {
		if state.ComponentID != input.ComponentID || state.ComponentIsRoot ||
			state.ComponentDefinitionID != definition.ID || state.ComponentKind != definition.Kind ||
			state.ComponentKeyID == "" || state.InstallationFamilyID == "" ||
			state.PolicyRevisionID != snapshot.RevisionID {
			return ErrComponentNotProvisioned
		}
		var environmentSlug, platform, definitionID, componentKeyID, dpopJKT string
		var familyStatus, componentStatus, keyStatus, delegationID string
		var delegationExpiresAt time.Time
		var delegationRevokedAt *time.Time
		err := tx.QueryRow(ctx, `
			SELECT e.slug, f.status, c.status, c.platform,
			       c.component_definition_id, c.current_component_key_id,
			       k.status, k.dpop_jkt, c.trust_delegation_id,
			       d.expires_at, d.revoked_at
			FROM installation_families f
			JOIN environments e
			  ON e.organization_id = f.organization_id
			 AND e.application_id = f.application_id
			 AND e.environment_id = f.environment_id
			JOIN client_components c
			  ON c.installation_family_id = f.installation_family_id
			JOIN component_keys k
			  ON k.client_component_id = c.client_component_id
			 AND k.component_key_id = c.current_component_key_id
			JOIN component_delegations d
			  ON d.component_delegation_id = c.trust_delegation_id
			 AND d.child_component_id = c.client_component_id
			 AND d.child_component_key_id = k.component_key_id
			WHERE f.installation_family_id = $1
			  AND c.client_component_id = $2
			  AND c.organization_id = $3
			  AND c.application_id = $4
			  AND c.environment_id = $5
			FOR SHARE OF f, c, k, d, e
		`, state.InstallationFamilyID, state.ComponentID, state.OrganizationID,
			state.ApplicationID, state.EnvironmentID).Scan(
			&environmentSlug, &familyStatus, &componentStatus, &platform,
			&definitionID, &componentKeyID, &keyStatus, &dpopJKT, &delegationID,
			&delegationExpiresAt, &delegationRevokedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrComponentNotProvisioned
		}
		if err != nil {
			return fmt.Errorf("lock component attestation challenge scope: %w", err)
		}
		if familyStatus != "active" || componentStatus != "active" || keyStatus != "active" ||
			platform != definition.Platform || definitionID != definition.ID ||
			componentKeyID != state.ComponentKeyID || delegationID != state.DelegationID ||
			dpopJKT != state.DPoPJKT || delegationRevokedAt != nil || !delegationExpiresAt.After(now) {
			return ErrComponentNotProvisioned
		}
		expiresAt := now.Add(snapshot.SessionPolicy().ChallengeTTL)
		if delegationExpiresAt.Before(expiresAt) {
			expiresAt = delegationExpiresAt
		}
		if state.IdentityExpiresAt.Before(expiresAt) {
			expiresAt = state.IdentityExpiresAt
		}
		if !expiresAt.After(now) {
			return ErrComponentParentTrustExpired
		}
		binding := attestation.Binding{
			Version: 2, Purpose: componentAttestationPurpose,
			ChallengeID: challengeID, ChallengeNonce: nonce,
			ApplicationID: state.ApplicationID, Environment: environmentSlug,
			PrincipalID: state.ApplicationUserID, DPoPJKT: state.DPoPJKT,
			Platform: definition.Platform, IssuedAt: now.UTC().Truncate(time.Second).Unix(),
			InstallationFamilyID: state.InstallationFamilyID,
			ClientComponentID:    state.ComponentID, ComponentDefinitionID: definition.ID,
			ComponentKeyID: state.ComponentKeyID,
		}
		bindingHash, err := binding.Hash()
		if err != nil {
			return ErrComponentNotConfigured
		}
		command, err := tx.Exec(ctx, `
			INSERT INTO component_attestation_challenges (
				component_attestation_challenge_id, organization_id, application_id,
				environment_id, application_user_id, installation_family_id,
				client_component_id, component_key_id, config_revision_id,
				platform, dpop_jkt, nonce_hash, binding_hash, challenge_nonce,
				attestation_policy_id, attestation_provider, attestation_mode,
				attestation_minimum_trust_level,
				attestation_maximum_age_milliseconds, created_at, expires_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
				$14, $15, 'app_attest', 'required', 'app_verified', $16, $17, $18
			)
		`, challengeID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.ApplicationUserID, state.InstallationFamilyID, state.ComponentID,
			state.ComponentKeyID, snapshot.RevisionID, definition.Platform, state.DPoPJKT,
			nonceHash[:], bindingHash[:], nonce, policy.ID, policy.MaxAge.Milliseconds(),
			time.Unix(binding.IssuedAt, 0).UTC(), expiresAt)
		if err != nil {
			return fmt.Errorf("store component attestation challenge: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrComponentNotConfigured
		}
		result = ComponentAttestationChallenge{
			ID: challengeID, Nonce: nonce, Binding: binding, BindingHash: bindingHash,
			OrganizationID: state.OrganizationID, EnvironmentID: state.EnvironmentID,
			ConfigurationRevisionID: snapshot.RevisionID,
			Attestation: ChallengeAttestationPolicy{
				ID: policy.ID, Provider: selection.Provider, Mode: "required",
				MinimumTrustLevel: selection.MinimumTrustLevel, MaximumAge: policy.MaxAge,
			},
			ExpiresAt: expiresAt,
		}
		return nil
	})
	if err != nil {
		return ComponentAttestationChallenge{}, err
	}
	if result.ID == "" {
		return ComponentAttestationChallenge{}, ErrComponentNotConfigured
	}
	return result, nil
}

// GetComponentAttestationChallenge reconstructs every signed member and
// rejects configuration, family, component, or key drift before verification.
func (store *Store) GetComponentAttestationChallenge(
	ctx context.Context,
	challengeID string,
) (ComponentAttestationChallenge, error) {
	if id.Validate(challengeID, id.SessionChallenge) != nil {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	var result ComponentAttestationChallenge
	var applicationID, principalID, familyID, componentID, definitionID, keyID string
	var environmentSlug, platform, dpopJKT, nonce string
	var storedNonceHash, storedBindingHash []byte
	var maximumAgeMilliseconds int64
	var createdAt time.Time
	var consumedAt *time.Time
	var familyStatus, componentStatus, keyStatus, currentKeyID, storedKeyJKT string
	err := store.pool.QueryRow(ctx, `
		SELECT challenge.organization_id, challenge.application_id,
		       challenge.environment_id, environment.slug,
		       challenge.application_user_id, challenge.installation_family_id,
		       challenge.client_component_id, component.component_definition_id,
		       challenge.component_key_id, challenge.platform, challenge.dpop_jkt,
		       challenge.nonce_hash, challenge.binding_hash,
		       challenge.challenge_nonce, challenge.config_revision_id,
		       challenge.attestation_policy_id, challenge.attestation_provider,
		       challenge.attestation_mode,
		       challenge.attestation_minimum_trust_level,
		       challenge.attestation_maximum_age_milliseconds,
		       challenge.created_at, challenge.expires_at, challenge.consumed_at,
		       family.status, component.status, component_key.status,
		       component.current_component_key_id, component_key.dpop_jkt
		FROM component_attestation_challenges challenge
		JOIN environments environment
		  ON environment.organization_id = challenge.organization_id
		 AND environment.application_id = challenge.application_id
		 AND environment.environment_id = challenge.environment_id
		JOIN installation_families family
		  ON family.installation_family_id = challenge.installation_family_id
		JOIN client_components component
		  ON component.client_component_id = challenge.client_component_id
		 AND component.installation_family_id = challenge.installation_family_id
		JOIN component_keys component_key
		  ON component_key.component_key_id = challenge.component_key_id
		 AND component_key.client_component_id = challenge.client_component_id
		WHERE challenge.component_attestation_challenge_id = $1
	`, challengeID).Scan(
		&result.OrganizationID, &applicationID, &result.EnvironmentID, &environmentSlug,
		&principalID, &familyID, &componentID, &definitionID, &keyID, &platform,
		&dpopJKT, &storedNonceHash, &storedBindingHash, &nonce,
		&result.ConfigurationRevisionID, &result.Attestation.ID,
		&result.Attestation.Provider, &result.Attestation.Mode,
		&result.Attestation.MinimumTrustLevel, &maximumAgeMilliseconds,
		&createdAt, &result.ExpiresAt, &consumedAt,
		&familyStatus, &componentStatus, &keyStatus, &currentKeyID, &storedKeyJKT,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	if err != nil {
		return ComponentAttestationChallenge{}, fmt.Errorf("read component attestation challenge: %w", err)
	}
	if consumedAt != nil {
		return ComponentAttestationChallenge{}, ErrChallengeConsumed
	}
	now := store.now().UTC()
	if !now.Before(result.ExpiresAt) {
		return ComponentAttestationChallenge{}, ErrChallengeExpired
	}
	if familyStatus != "active" || componentStatus != "active" || keyStatus != "active" ||
		currentKeyID != keyID || subtle.ConstantTimeCompare([]byte(storedKeyJKT), []byte(dpopJKT)) != 1 ||
		result.Attestation.Provider != "app_attest" || result.Attestation.Mode != "required" ||
		result.Attestation.MinimumTrustLevel != "app_verified" ||
		maximumAgeMilliseconds < int64(time.Minute/time.Millisecond) ||
		maximumAgeMilliseconds > int64((30*24*time.Hour)/time.Millisecond) {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	result.Attestation.MaximumAge = time.Duration(maximumAgeMilliseconds) * time.Millisecond
	nonceBytes, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(nonceBytes) != 32 || len(storedNonceHash) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(nonceBytes) != nonce {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	nonceHash := sha256.Sum256(nonceBytes)
	if subtle.ConstantTimeCompare(nonceHash[:], storedNonceHash) != 1 {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	result.ID = challengeID
	result.Nonce = nonce
	result.Binding = attestation.Binding{
		Version: 2, Purpose: componentAttestationPurpose,
		ChallengeID: challengeID, ChallengeNonce: nonce,
		ApplicationID: applicationID, Environment: environmentSlug,
		PrincipalID: principalID, DPoPJKT: dpopJKT, Platform: platform,
		IssuedAt: createdAt.UTC().Unix(), InstallationFamilyID: familyID,
		ClientComponentID: componentID, ComponentDefinitionID: definitionID,
		ComponentKeyID: keyID,
	}
	bindingHash, err := result.Binding.Hash()
	if err != nil || len(storedBindingHash) != sha256.Size ||
		subtle.ConstantTimeCompare(bindingHash[:], storedBindingHash) != 1 {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	result.BindingHash = bindingHash
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: result.OrganizationID, ApplicationID: applicationID,
		EnvironmentID: result.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != result.ConfigurationRevisionID {
		return ComponentAttestationChallenge{}, ErrSessionScope
	}
	definition, policy, selection, err := componentStepUpSelection(snapshot, definitionID)
	if err != nil || definition.Platform != platform || policy.ID != result.Attestation.ID ||
		policy.MaxAge != result.Attestation.MaximumAge || selection.Provider != result.Attestation.Provider ||
		selection.MinimumTrustLevel != result.Attestation.MinimumTrustLevel {
		return ComponentAttestationChallenge{}, ErrChallengeInvalid
	}
	return result, nil
}

type ComponentAttestationExchangeInput struct {
	Access      AccessRequestInput
	ComponentID string
	Challenge   ComponentAttestationChallenge
	Attestation attestation.Result
}

// ExchangeComponentAttestation consumes the component challenge and rotates
// every delegated-only credential in the same transaction that records direct
// evidence. Parent and delegation identities remain on the new grant.
func (store *Store) ExchangeComponentAttestation(
	ctx context.Context,
	input ComponentAttestationExchangeInput,
) (IssuedSession, error) {
	now := store.now().UTC().Truncate(time.Second)
	if id.Validate(input.ComponentID, id.ClientComponent) != nil ||
		input.ComponentID != input.Access.Principal.ComponentID ||
		input.Access.Principal.ComponentIsRoot || input.Challenge.ID == "" ||
		input.Challenge.Binding.ClientComponentID != input.ComponentID {
		return IssuedSession{}, ErrComponentNotProvisioned
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: input.Access.Principal.OrganizationID,
		ApplicationID:  input.Access.Principal.ApplicationID,
		EnvironmentID:  input.Access.Principal.EnvironmentID,
	})
	if err != nil || snapshot.RevisionID != input.Challenge.ConfigurationRevisionID {
		return IssuedSession{}, ErrComponentNotConfigured
	}
	definition, policy, selection, err := componentStepUpSelection(snapshot, input.Access.Principal.ComponentDefinitionID)
	if err != nil || policy.ID != input.Challenge.Attestation.ID ||
		selection.Provider != input.Challenge.Attestation.Provider {
		return IssuedSession{}, ErrComponentNotConfigured
	}
	verified, err := input.Attestation.ValidatedSnapshot(input.Challenge.BindingHash, now)
	if err != nil || !challengeAttestationAllows(input.Challenge.Attestation, verified, now) {
		return IssuedSession{}, ErrSessionInvalid
	}
	preparedAccess, err := store.accessTokens.Prepare(ctx)
	if err != nil {
		return IssuedSession{}, err
	}
	grantID, err := id.New(id.SessionGrant)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate stepped-up component grant ID: %w", err)
	}
	sessionFamilyID, err := id.New(id.ComponentSession)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate stepped-up component session family ID: %w", err)
	}
	refresh, refreshID, refreshHash, err := store.newRefreshTokenWithPrefix(id.ComponentRefresh)
	if err != nil {
		return IssuedSession{}, err
	}
	attestationEventID, err := id.New(id.AttestationEvent)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate component attestation event ID: %w", err)
	}
	auditEventID, err := id.New(id.AuditEvent)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate component attestation audit event ID: %w", err)
	}
	encodedSignals, err := json.Marshal(verified.NormalizedSignals)
	if err != nil {
		return IssuedSession{}, ErrSessionInvalid
	}
	var result IssuedSession
	_, err = store.authorizeAccess(ctx, input.Access, false, true, func(
		ctx context.Context,
		tx pgx.Tx,
		state authorizationState,
		txNow time.Time,
	) error {
		if state.ComponentID != input.ComponentID || state.ComponentIsRoot ||
			state.ComponentDefinitionID != definition.ID || state.ComponentKind != definition.Kind ||
			state.ComponentKeyID != input.Challenge.Binding.ComponentKeyID ||
			state.InstallationFamilyID != input.Challenge.Binding.InstallationFamilyID ||
			state.DPoPJKT != input.Challenge.Binding.DPoPJKT ||
			state.ApplicationUserID != input.Challenge.Binding.PrincipalID ||
			state.ApplicationID != input.Challenge.Binding.ApplicationID ||
			state.PolicyRevisionID != snapshot.RevisionID {
			return ErrComponentNotProvisioned
		}
		var delegationExpiresAt time.Time
		var delegationRevokedAt *time.Time
		var parentStatus, parentTrustSource string
		var parentRevokedAt, parentTrustExpiresAt *time.Time
		var keyStatus, componentStatus, familyStatus, currentKeyID, storedJKT string
		err := tx.QueryRow(ctx, `
			SELECT f.status, c.status, c.current_component_key_id,
			       k.status, k.dpop_jkt, d.expires_at, d.revoked_at,
			       parent.status, parent.revoked_at,
			       parent.trust_source, parent.trust_expires_at
			FROM installation_families f
			JOIN client_components c
			  ON c.installation_family_id = f.installation_family_id
			JOIN component_keys k
			  ON k.client_component_id = c.client_component_id
			 AND k.component_key_id = c.current_component_key_id
			JOIN component_delegations d
			  ON d.component_delegation_id = c.trust_delegation_id
			 AND d.child_component_id = c.client_component_id
			 AND d.child_component_key_id = k.component_key_id
			JOIN client_components parent
			  ON parent.client_component_id = d.parent_component_id
			WHERE f.installation_family_id = $1
			  AND c.client_component_id = $2
			  AND d.component_delegation_id = $3
			FOR UPDATE OF c, k, d FOR SHARE OF f, parent
		`, state.InstallationFamilyID, state.ComponentID, state.DelegationID).Scan(
			&familyStatus, &componentStatus, &currentKeyID, &keyStatus, &storedJKT,
			&delegationExpiresAt, &delegationRevokedAt, &parentStatus, &parentRevokedAt,
			&parentTrustSource, &parentTrustExpiresAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrComponentNotProvisioned
		}
		if err != nil {
			return fmt.Errorf("lock component direct-attestation scope: %w", err)
		}
		if familyStatus != "active" || componentStatus != "active" || keyStatus != "active" ||
			currentKeyID != state.ComponentKeyID || storedJKT != state.DPoPJKT ||
			delegationRevokedAt != nil || !delegationExpiresAt.After(txNow) ||
			parentStatus != "active" || parentRevokedAt != nil ||
			parentTrustExpiresAt == nil || !parentTrustExpiresAt.After(txNow) ||
			parentTrustSource != "direct_attested" {
			return ErrComponentParentTrustExpired
		}
		command, err := tx.Exec(ctx, `
			UPDATE component_attestation_challenges
			SET consumed_at = $2
			WHERE component_attestation_challenge_id = $1
			  AND organization_id = $3 AND application_id = $4 AND environment_id = $5
			  AND application_user_id = $6 AND installation_family_id = $7
			  AND client_component_id = $8 AND component_key_id = $9
			  AND config_revision_id = $10 AND binding_hash = $11
			  AND dpop_jkt = $12 AND consumed_at IS NULL AND expires_at > $2
		`, input.Challenge.ID, txNow, state.OrganizationID, state.ApplicationID,
			state.EnvironmentID, state.ApplicationUserID, state.InstallationFamilyID,
			state.ComponentID, state.ComponentKeyID, snapshot.RevisionID,
			input.Challenge.BindingHash[:], state.DPoPJKT)
		if err != nil {
			return fmt.Errorf("consume component attestation challenge: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrChallengeConsumed
		}
		effectiveTrust, ok := minimumTrustLevel(state.TrustLevel, verified.TrustLevel)
		if !ok {
			return ErrSessionInvalid
		}
		effectiveExpiry := earliestTime(
			verified.ExpiresAt, delegationExpiresAt, *parentTrustExpiresAt,
			state.IdentityExpiresAt, state.AttestationExpiresAt,
		)
		if !effectiveExpiry.After(txNow) {
			return ErrComponentParentTrustExpired
		}
		if err := linkComponentAppAttestKey(ctx, tx, state, input.Challenge, verified, txNow); err != nil {
			return err
		}
		if err := revokeActiveComponentSessions(ctx, tx, state.ComponentID, txNow, "component_direct_attestation_step_up"); err != nil {
			return err
		}
		trustSignals := map[string]any{
			"delegated": true, "direct_attestation": true,
			"direct_attestation_provider": verified.Provider,
		}
		encodedTrustSignals, err := json.Marshal(trustSignals)
		if err != nil {
			return ErrSessionInvalid
		}
		command, err = tx.Exec(ctx, `
			UPDATE client_components
			SET trust_source = 'delegated_direct_attested',
			    trust_attestation_provider = $2,
			    trust_verified_at = $3, trust_expires_at = $4,
			    trust_signals = $5, updated_at = $6, last_seen_at = $6
			WHERE client_component_id = $1 AND status = 'active'
			  AND current_component_key_id = $7
		`, state.ComponentID, verified.Provider, verified.VerifiedAt,
			effectiveExpiry, encodedTrustSignals, txNow, state.ComponentKeyID)
		if err != nil {
			return fmt.Errorf("persist direct component trust: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrComponentNotProvisioned
		}
		access, err := preparedAccess.IssueFor(AccessIssueInput{
			OrganizationID: state.OrganizationID, ApplicationID: state.ApplicationID,
			EnvironmentID: state.EnvironmentID, ApplicationUserID: state.ApplicationUserID,
			InstallationID: state.InstallationID, InstallationFamilyID: state.InstallationFamilyID,
			ComponentID: state.ComponentID, ComponentDefinitionID: state.ComponentDefinitionID,
			ComponentKind: state.ComponentKind, ComponentIsRoot: false,
			TrustSource: "delegated_direct_attested", AttestationProvider: verified.Provider,
			ParentComponentID:         state.ParentComponentID,
			ParentAttestationProvider: state.ParentAttestationProvider,
			DelegationID:              state.DelegationID, Features: append([]string(nil), state.GrantedFeatures...),
			SessionGrantID: grantID, IdentityProvider: state.IdentityProvider,
			TrustLevel: effectiveTrust, PolicyRevisionID: snapshot.RevisionID,
			DPoPJKT: state.DPoPJKT,
		}, snapshot.SessionPolicy().AccessTokenTTL)
		if err != nil {
			return err
		}
		issuedAt := latestTime(txNow, access.IssuedAt)
		refreshExpiresAt := issuedAt.Add(snapshot.SessionPolicy().RefreshTokenTTL)
		if effectiveExpiry.Before(refreshExpiresAt) {
			refreshExpiresAt = effectiveExpiry
		}
		if !refreshExpiresAt.After(issuedAt) {
			return ErrComponentParentTrustExpired
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_session_families (
				component_session_family_id, organization_id, application_id, environment_id,
				application_user_id, installation_family_id, client_component_id,
				component_key_id, status, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $9)
		`, sessionFamilyID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.ApplicationUserID, state.InstallationFamilyID, state.ComponentID,
			state.ComponentKeyID, issuedAt); err != nil {
			return fmt.Errorf("create stepped-up component session family: %w", err)
		}
		command, err = tx.Exec(ctx, `
			INSERT INTO session_grants (
				session_grant_id, organization_id, application_id, environment_id,
				application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
				policy_revision_id, trust_level, identity_provider_key,
				identity_verified_at, identity_expires_at, attested_at,
				attestation_provider, attestation_expires_at, issued_at, expires_at,
				installation_family_id, client_component_id, component_definition_id,
				component_kind, component_is_root, trust_source, component_session_family_id
			) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			         $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
			         $22, false, 'delegated_direct_attested', $23
			  FROM active_config_revisions active
			  WHERE active.organization_id = $2 AND active.application_id = $3
			    AND active.environment_id = $4 AND active.config_revision_id = $9
		`, grantID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.ApplicationUserID, state.InstallationID, access.JTIHash[:], state.DPoPJKT,
			snapshot.RevisionID, effectiveTrust, state.IdentityProvider,
			state.IdentityVerifiedAt, state.IdentityExpiresAt, verified.VerifiedAt,
			verified.Provider, effectiveExpiry, issuedAt, access.ExpiresAt,
			state.InstallationFamilyID, state.ComponentID, state.ComponentDefinitionID,
			state.ComponentKind, sessionFamilyID)
		if err != nil {
			return fmt.Errorf("store stepped-up component session grant: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrSessionScope
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_refresh_tokens (
				component_refresh_token_id, component_session_family_id,
				client_component_id, component_key_id, session_grant_id, grant_kind,
				token_hash, status, issued_at, expires_at
			) VALUES ($1, $2, $3, $4, $5, 'session', $6, 'active', $7, $8)
		`, refreshID, sessionFamilyID, state.ComponentID, state.ComponentKeyID,
			grantID, refreshHash[:], issuedAt, refreshExpiresAt); err != nil {
			return fmt.Errorf("store stepped-up component refresh token: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO attestation_events (
				attestation_event_id, organization_id, application_id, environment_id,
				installation_id, provider, outcome, trust_level, evidence_hash,
				normalized_signals, occurred_at, installation_family_id,
				client_component_id, trust_source, parent_component_id,
				component_delegation_id
			) VALUES (
				$1, $2, $3, $4, $5, $6, 'accepted', $7, $8, $9, $10,
				$11, $12, 'delegated_direct_attested', $13, $14
			)
		`, attestationEventID, state.OrganizationID, state.ApplicationID,
			state.EnvironmentID, state.InstallationID, verified.Provider, effectiveTrust,
			verified.EvidenceHash[:], encodedSignals, verified.VerifiedAt,
			state.InstallationFamilyID, state.ComponentID, state.ParentComponentID,
			state.DelegationID); err != nil {
			return fmt.Errorf("record direct component attestation: %w", err)
		}
		if err := insertComponentLifecycleAudit(
			ctx, tx, auditEventID, state.OrganizationID, state.EnvironmentID,
			"client.component.direct_attestation_completed", state.ComponentID, txNow,
			[][2]string{{"direct_attestation", "set"}, {"component_session_family", "rotate"}},
		); err != nil {
			return err
		}
		result = IssuedSession{
			Access: access, Refresh: refresh, RefreshID: refreshID,
			RefreshFamilyID: sessionFamilyID, RefreshExpiresAt: refreshExpiresAt,
			GrantID: grantID,
			Installation: Installation{ID: state.InstallationID, Platform: definition.Platform,
				DPoPJKT: state.DPoPJKT, Status: "active"},
			Family: InstallationFamily{ID: state.InstallationFamilyID, Status: "active"},
			Component: ClientComponent{
				ID: state.ComponentID, DefinitionID: state.ComponentDefinitionID,
				Kind: state.ComponentKind, Platform: definition.Platform, IsRoot: false,
				Status: "active", KeyID: state.ComponentKeyID, DPoPJKT: state.DPoPJKT,
				TrustSource: "delegated_direct_attested", AttestationProvider: verified.Provider,
				ParentComponentID:         state.ParentComponentID,
				ParentAttestationProvider: state.ParentAttestationProvider,
				DelegationID:              state.DelegationID,
				GrantedFeatures:           append([]string(nil), state.GrantedFeatures...),
			},
			Trust: Trust{Provider: verified.Provider, Level: effectiveTrust,
				VerifiedAt: verified.VerifiedAt, ExpiresAt: effectiveExpiry},
		}
		return nil
	})
	if err != nil {
		return IssuedSession{}, err
	}
	if result.GrantID == "" {
		return IssuedSession{}, ErrSessionInvalid
	}
	return result, nil
}

func linkComponentAppAttestKey(
	ctx context.Context,
	tx pgx.Tx,
	state authorizationState,
	challenge ComponentAttestationChallenge,
	verified attestation.Result,
	now time.Time,
) error {
	keyID, ok := verified.AppAttestKeyID()
	if !ok || now.IsZero() {
		return ErrSessionInvalid
	}
	command, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET installation_family_id = $1,
		    client_component_id = $2,
		    component_key_id = $3,
		    linked_at = CASE
		        WHEN linked_at IS NULL THEN GREATEST(created_at, transaction_timestamp(), $11)
		        ELSE linked_at
		    END,
		    updated_at = GREATEST(updated_at, transaction_timestamp(), $11)
		WHERE provider = 'app_attest' AND provider_key_hash = $4
		  AND organization_id = $5 AND application_id = $6 AND environment_id = $7
		  AND application_user_id = $8 AND binding_environment = $9
		  AND platform = $10 AND dpop_jkt = $12 AND status = 'active'
		  AND installation_id IS NULL
		  AND (
		      (
		          installation_family_id IS NULL AND client_component_id IS NULL
		          AND component_key_id IS NULL AND linked_at IS NULL
		      )
		      OR (
		          installation_family_id = $1 AND client_component_id = $2
		          AND component_key_id = $3 AND linked_at IS NOT NULL
		      )
		  )
	`, state.InstallationFamilyID, state.ComponentID, state.ComponentKeyID, keyID[:],
		state.OrganizationID, state.ApplicationID, state.EnvironmentID,
		state.ApplicationUserID, challenge.Binding.Environment, challenge.Binding.Platform,
		now, state.DPoPJKT)
	if err != nil {
		return fmt.Errorf("link App Attest key to component: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSessionInvalid
	}
	return nil
}

func earliestTime(values ...time.Time) time.Time {
	var result time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		value = value.UTC()
		if result.IsZero() || value.Before(result) {
			result = value
		}
	}
	return result
}

func minimumTrustLevel(left, right string) (string, bool) {
	if left == "debug" || right == "debug" {
		return "", false
	}
	leftRank, leftOK := trustRank(left)
	rightRank, rightOK := trustRank(right)
	if !leftOK || !rightOK {
		return "", false
	}
	if leftRank <= rightRank {
		return left, true
	}
	return right, true
}
