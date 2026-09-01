package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
)

// ComponentProvisionInput is authorized by the root component's current
// DPoP-bound access session. PublicJWK is the child's public key only; private
// key material cannot be represented by this boundary.
type ComponentProvisionInput struct {
	Access            AccessRequestInput
	DefinitionID      string
	PublicJWK         dpop.PublicJWK
	RequestedFeatures []string
	AppVersion        string
	SDKVersion        string
}

type ProvisionedComponent struct {
	Component        ClientComponent
	Family           InstallationFamily
	RefreshGrant     RefreshToken
	RefreshGrantID   string
	RefreshExpiresAt time.Time
	TrustExpiresAt   time.Time
}

func (input ComponentProvisionInput) validate() (string, []string, error) {
	if !sessionIdentifierPattern.MatchString(input.DefinitionID) ||
		!boundedComponentVersion(input.AppVersion) || !boundedComponentVersion(input.SDKVersion) {
		return "", nil, ErrComponentNotConfigured
	}
	if _, err := input.PublicJWK.PublicKey(); err != nil {
		return "", nil, ErrComponentKeyInvalid
	}
	jkt, err := input.PublicJWK.Thumbprint()
	if err != nil || !validThumbprint(jkt) {
		return "", nil, ErrComponentKeyInvalid
	}
	features, ok := canonicalComponentFeatures(input.RequestedFeatures)
	if !ok {
		return "", nil, ErrComponentFeatureNotGranted
	}
	return jkt, features, nil
}

func boundedComponentVersion(value string) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= 1 && length <= 128 &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func canonicalComponentFeatures(values []string) ([]string, bool) {
	if len(values) == 0 || len(values) > 256 {
		return nil, false
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !sessionIdentifierPattern.MatchString(value) || (index > 0 && result[index-1] == value) {
			return nil, false
		}
	}
	return result, true
}

func componentFeatureSubset(requested, allowed []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	for _, value := range requested {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func componentParentAllowed(definition configuration.ComponentDefinition, parentDefinitionID string) bool {
	if definition.FamilyRole != "delegated" || definition.Delegation == nil {
		return false
	}
	for _, candidate := range definition.Delegation.AllowedParents {
		if candidate == parentDefinitionID {
			return true
		}
	}
	return false
}

// ProvisionComponent creates or replaces one configured delegated component.
// Replacement preserves the component identity for historical attribution but
// rotates its key, delegation, component session family and refresh chain.
func (store *Store) ProvisionComponent(ctx context.Context, input ComponentProvisionInput) (ProvisionedComponent, error) {
	jkt, requestedFeatures, err := input.validate()
	if err != nil {
		return ProvisionedComponent{}, err
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: input.Access.Principal.OrganizationID,
		ApplicationID:  input.Access.Principal.ApplicationID,
		EnvironmentID:  input.Access.Principal.EnvironmentID,
	})
	if err != nil {
		return ProvisionedComponent{}, ErrSessionScope
	}
	definition, ok := snapshot.ComponentDefinition(input.DefinitionID)
	if !ok {
		return ProvisionedComponent{}, ErrComponentDefinitionNotFound
	}
	if !componentParentAllowed(definition, input.Access.Principal.ComponentDefinitionID) {
		return ProvisionedComponent{}, ErrComponentNotConfigured
	}
	if !componentFeatureSubset(requestedFeatures, definition.AllowedFeatures) ||
		!componentFeatureSubset(requestedFeatures, input.Access.Principal.Features) {
		return ProvisionedComponent{}, ErrComponentFeatureNotGranted
	}

	componentCandidate, err := id.New(id.ClientComponent)
	if err != nil {
		return ProvisionedComponent{}, fmt.Errorf("generate component ID: %w", err)
	}
	keyID, err := id.New(id.ComponentKey)
	if err != nil {
		return ProvisionedComponent{}, fmt.Errorf("generate component-key ID: %w", err)
	}
	delegationID, err := id.New(id.ComponentDelegation)
	if err != nil {
		return ProvisionedComponent{}, fmt.Errorf("generate component-delegation ID: %w", err)
	}
	sessionFamilyID, err := id.New(id.ComponentSession)
	if err != nil {
		return ProvisionedComponent{}, fmt.Errorf("generate component-session-family ID: %w", err)
	}
	auditEventID, err := id.New(id.AuditEvent)
	if err != nil {
		return ProvisionedComponent{}, fmt.Errorf("generate component audit-event ID: %w", err)
	}
	refreshGrant, refreshID, refreshHash, err := store.newRefreshTokenWithPrefix(id.ComponentRefresh)
	if err != nil {
		return ProvisionedComponent{}, err
	}
	encodedJWK, err := json.Marshal(input.PublicJWK)
	if err != nil {
		return ProvisionedComponent{}, ErrComponentKeyInvalid
	}
	encodedFeatures, err := json.Marshal(requestedFeatures)
	if err != nil {
		return ProvisionedComponent{}, ErrComponentFeatureNotGranted
	}
	definitionDocument, err := json.Marshal(map[string]any{
		"id": definition.ID, "platform": definition.Platform, "kind": definition.Kind,
		"familyRole": definition.FamilyRole, "identifiers": definition.Identifiers,
		"attestation": definition.Attestation, "allowedFeatures": definition.AllowedFeatures,
		"delegation": definition.Delegation,
	})
	if err != nil {
		return ProvisionedComponent{}, ErrComponentNotConfigured
	}

	var result ProvisionedComponent
	_, err = store.authorizeAccess(ctx, input.Access, false, true, func(
		ctx context.Context, tx pgx.Tx, state authorizationState, now time.Time,
	) error {
		if state.ComponentID == "" || !state.ComponentIsRoot ||
			state.InstallationFamilyID == "" || state.familyStatus != "active" {
			return ErrComponentNotProvisioned
		}
		if state.ComponentDefinitionID != input.Access.Principal.ComponentDefinitionID ||
			!componentParentAllowed(definition, state.ComponentDefinitionID) ||
			!componentFeatureSubset(requestedFeatures, state.GrantedFeatures) {
			return ErrComponentFeatureNotGranted
		}
		if !state.AttestationExpiresAt.After(now) {
			return ErrComponentParentTrustExpired
		}
		var activeRevisionID string
		if err := tx.QueryRow(ctx, `
			SELECT config_revision_id
			FROM active_config_revisions
			WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
			FOR SHARE
		`, state.OrganizationID, state.ApplicationID, state.EnvironmentID).Scan(&activeRevisionID); err != nil {
			return ErrSessionScope
		}
		if activeRevisionID != snapshot.RevisionID {
			return ErrComponentNotConfigured
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			state.InstallationFamilyID+":"+definition.ID); err != nil {
			return fmt.Errorf("lock component definition slot: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_definitions (
				environment_id, config_revision_id, component_definition_id,
				platform, component_kind, family_role, definition
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (environment_id, config_revision_id, component_definition_id) DO NOTHING
		`, state.EnvironmentID, snapshot.RevisionID, definition.ID, definition.Platform,
			definition.Kind, definition.FamilyRole, definitionDocument); err != nil {
			return fmt.Errorf("persist delegated component definition: %w", err)
		}

		var parentAttestationEventID string
		if err := tx.QueryRow(ctx, `
			SELECT attestation_event_id
			FROM attestation_events
			WHERE installation_family_id = $1 AND client_component_id = $2
			  AND outcome = 'accepted'
			ORDER BY occurred_at DESC, attestation_event_id DESC
			LIMIT 1
		`, state.InstallationFamilyID, state.ComponentID).Scan(&parentAttestationEventID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrComponentParentTrustExpired
			}
			return fmt.Errorf("resolve parent attestation event: %w", err)
		}
		trustExpiresAt := now.Add(definition.Delegation.MaximumLifetime)
		if state.AttestationExpiresAt.Before(trustExpiresAt) {
			trustExpiresAt = state.AttestationExpiresAt
		}
		if state.IdentityExpiresAt.Before(trustExpiresAt) {
			trustExpiresAt = state.IdentityExpiresAt
		}
		if !trustExpiresAt.After(now) {
			return ErrComponentParentTrustExpired
		}
		trustSource := "delegated_identity_only"
		if state.TrustSource == "direct_attested" {
			trustSource = "delegated_from_attested_root"
		}

		componentID := componentCandidate
		var existingID string
		err := tx.QueryRow(ctx, `
			SELECT client_component_id
			FROM client_components
			WHERE installation_family_id = $1 AND component_definition_id = $2
			  AND status = 'active'
			FOR UPDATE
		`, state.InstallationFamilyID, definition.ID).Scan(&existingID)
		if err == nil {
			componentID = existingID
			if err := revokeActiveComponentSessions(ctx, tx, componentID, now, "component_reprovisioned"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
					UPDATE attestation_keys
					SET status = 'revoked', revoked_at = GREATEST(created_at, $2),
					    updated_at = GREATEST(updated_at, created_at, $2)
					WHERE client_component_id = $1 AND status <> 'revoked'
				`, componentID, now); err != nil {
				return fmt.Errorf("revoke re-provisioned component attestation keys: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_delegations
				SET revoked_at = COALESCE(revoked_at, $2)
				WHERE child_component_id = $1 AND revoked_at IS NULL
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke replaced component delegation: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_keys
				SET status = 'replaced', replaced_at = COALESCE(replaced_at, $2)
				WHERE client_component_id = $1 AND status = 'active'
			`, componentID, now); err != nil {
				return fmt.Errorf("replace component key: %w", err)
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("resolve component definition slot: %w", err)
		} else {
			if _, err := tx.Exec(ctx, `
				INSERT INTO client_components (
					client_component_id, organization_id, application_id, environment_id,
					application_user_id, installation_family_id, component_definition_id,
					component_kind, platform, is_root, status, trust_source,
					trust_attestation_provider, trust_parent_component_id,
					trust_parent_attestation_event_id, trust_verified_at, trust_expires_at,
					trust_signals, granted_features, key_storage_claim, app_version, sdk_version,
					created_at, updated_at, last_seen_at
				) VALUES (
					$1, $2, $3, $4, $5, $6, $7, $8, $9, false, 'active', $10,
					$11, $12, $13, $14, $15, '{"delegated":true}'::jsonb, $16,
					'unknown', $17, $18, $14, $14, $14
				)
			`, componentID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
				state.ApplicationUserID, state.InstallationFamilyID, definition.ID,
				definition.Kind, definition.Platform, trustSource, state.AttestationProvider,
				state.ComponentID, parentAttestationEventID, now, trustExpiresAt,
				encodedFeatures, input.AppVersion, input.SDKVersion); err != nil {
				return fmt.Errorf("create delegated component: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE client_components
			SET component_kind = $2, platform = $3, trust_source = $4,
			    trust_attestation_provider = $5, trust_parent_component_id = $6,
			    trust_parent_attestation_event_id = $7, trust_verified_at = $8,
			    trust_expires_at = $9, trust_signals = '{"delegated":true}'::jsonb,
			    granted_features = $10, app_version = $11, sdk_version = $12,
			    updated_at = $8, last_seen_at = $8
			WHERE client_component_id = $1 AND status = 'active'
		`, componentID, definition.Kind, definition.Platform, trustSource,
			state.AttestationProvider, state.ComponentID, parentAttestationEventID,
			now, trustExpiresAt, encodedFeatures, input.AppVersion, input.SDKVersion); err != nil {
			return fmt.Errorf("update delegated component: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_keys (
				component_key_id, organization_id, application_id, environment_id,
				installation_family_id, client_component_id, dpop_jkt, public_jwk,
				status, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9)
		`, keyID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.InstallationFamilyID, componentID, jkt, encodedJWK, now); err != nil {
			return fmt.Errorf("create delegated component key: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_delegations (
				component_delegation_id, organization_id, application_id, environment_id,
				installation_family_id, parent_component_id, child_component_id,
				child_component_key_id, parent_session_grant_id, feature_scopes,
				configuration_revision_id, parent_attestation_event_id,
				identity_provider_key, trust_level, identity_verified_at,
				identity_expires_at, attested_at, attestation_provider,
				attestation_expires_at, nonce_hash, created_at, expires_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
				$13, $14, $15, $16, $17, $18, $19, $20, $21, $22
			)
		`, delegationID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.InstallationFamilyID, state.ComponentID, componentID, keyID,
			state.SessionGrantID, encodedFeatures, snapshot.RevisionID, parentAttestationEventID,
			state.IdentityProvider, state.TrustLevel, state.IdentityVerifiedAt,
			state.IdentityExpiresAt, state.AttestedAt, state.AttestationProvider,
			state.AttestationExpiresAt, refreshHash[:], now, trustExpiresAt); err != nil {
			return fmt.Errorf("create component delegation: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE client_components
			SET current_component_key_id = $2, trust_delegation_id = $3, updated_at = $4
			WHERE client_component_id = $1 AND status = 'active'
		`, componentID, keyID, delegationID, now); err != nil {
			return fmt.Errorf("link delegated component key: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_session_families (
				component_session_family_id, organization_id, application_id, environment_id,
				application_user_id, installation_family_id, client_component_id,
				component_key_id, status, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $9)
		`, sessionFamilyID, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.ApplicationUserID, state.InstallationFamilyID, componentID, keyID, now); err != nil {
			return fmt.Errorf("create provisioned component session family: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_refresh_tokens (
				component_refresh_token_id, component_session_family_id,
				client_component_id, component_key_id, session_grant_id, grant_kind,
				token_hash, status, issued_at, expires_at
			) VALUES ($1, $2, $3, $4, NULL, 'provisioning', $5, 'active', $6, $7)
		`, refreshID, sessionFamilyID, componentID, keyID, refreshHash[:], now, trustExpiresAt); err != nil {
			return fmt.Errorf("store component provisioning grant: %w", err)
		}
		if err := insertComponentLifecycleAudit(ctx, tx, auditEventID, state.OrganizationID,
			state.EnvironmentID, "client.component.provisioned", componentID, now,
			[][2]string{{"component_key", "rotate"}, {"component_session_family", "set"}, {"delegation", "set"}}); err != nil {
			return err
		}
		result = ProvisionedComponent{
			Component: ClientComponent{
				ID: componentID, DefinitionID: definition.ID, Kind: definition.Kind,
				Platform: definition.Platform, IsRoot: false, Status: "active", KeyID: keyID,
				DPoPJKT: jkt, TrustSource: trustSource,
				AttestationProvider:       state.AttestationProvider,
				ParentComponentID:         state.ComponentID,
				ParentAttestationProvider: state.AttestationProvider,
				DelegationID:              delegationID, GrantedFeatures: append([]string(nil), requestedFeatures...),
			},
			Family:       InstallationFamily{ID: state.InstallationFamilyID, Status: "active"},
			RefreshGrant: refreshGrant, RefreshGrantID: refreshID,
			RefreshExpiresAt: trustExpiresAt, TrustExpiresAt: trustExpiresAt,
		}
		return nil
	})
	if err != nil {
		return ProvisionedComponent{}, err
	}
	if result.Component.ID == "" {
		return ProvisionedComponent{}, ErrSessionInvalid
	}
	return result, nil
}

type ComponentSessionInput struct {
	ComponentID  string
	RefreshGrant RefreshToken
	DPoPProof    DPoPProof
	HTTPMethod   string
	RequestURI   *url.URL
	Origin       string
}

func (input ComponentSessionInput) validate() error {
	if id.Validate(input.ComponentID, id.ClientComponent) != nil || input.RefreshGrant.value == "" ||
		input.DPoPProof.value == "" || !replayMethodPattern.MatchString(input.HTTPMethod) ||
		input.RequestURI == nil {
		return ErrComponentNotProvisioned
	}
	return nil
}

type componentProvisioningBinding struct {
	RefreshTokenID, SessionFamilyID, OrganizationID, ApplicationID, EnvironmentID             string
	ApplicationUserID, InstallationID, FamilyID, FamilyStatus, ComponentID                    string
	ComponentDefinitionID, ComponentKind, ComponentStatus, ComponentKeyID, ComponentKeyStatus string
	CurrentComponentKeyID, SessionStatus, DPoPJKT, TrustSource, ParentComponentID             string
	ParentAttestationProvider, DelegationID, DelegationRevisionID, Platform, AppVersion       string
	IdentityProvider, TrustLevel, AttestationProvider, TokenStatus                            string
	GrantedFeatures                                                                           []string
	PublicJWK                                                                                 dpop.PublicJWK
	IdentityVerifiedAt, IdentityExpiresAt, AttestedAt, AttestationExpiresAt                   time.Time
	TrustExpiresAt, DelegationExpiresAt, TokenExpiresAt                                       time.Time
	DelegationConsumed                                                                        bool
	DelegationRevoked                                                                         bool
	ParentActive                                                                              bool
}

type componentProvisioningQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadComponentProvisioningBinding(ctx context.Context, query componentProvisioningQuerier, tokenHash []byte, componentID string, forUpdate bool) (componentProvisioningBinding, error) {
	statement := `
		SELECT r.component_refresh_token_id, r.component_session_family_id,
		       sf.organization_id, sf.application_id, sf.environment_id, sf.application_user_id,
		       f.root_installation_id, f.installation_family_id, f.status,
		       c.client_component_id, c.component_definition_id, c.component_kind, c.status,
		       k.component_key_id, k.status, c.current_component_key_id, sf.status,
		       k.dpop_jkt, k.public_jwk, c.trust_source, c.trust_parent_component_id,
		       COALESCE(p.trust_attestation_provider, ''), d.component_delegation_id,
		       d.configuration_revision_id, c.granted_features, c.platform, COALESCE(c.app_version, ''),
		       d.identity_provider_key, d.trust_level, d.identity_verified_at,
		       d.identity_expires_at, d.attested_at, d.attestation_provider,
		       d.attestation_expires_at, c.trust_expires_at, d.expires_at,
		       d.consumed_at IS NOT NULL, d.revoked_at IS NOT NULL,
		       p.status = 'active' AND p.revoked_at IS NULL
		          AND (p.trust_expires_at IS NULL OR p.trust_expires_at > statement_timestamp()),
		       r.status, r.expires_at
		FROM component_refresh_tokens r
		JOIN component_session_families sf
		  ON sf.component_session_family_id = r.component_session_family_id
		JOIN installation_families f ON f.installation_family_id = sf.installation_family_id
		JOIN client_components c ON c.client_component_id = r.client_component_id
		JOIN component_keys k
		  ON k.component_key_id = r.component_key_id AND k.client_component_id = r.client_component_id
		JOIN component_delegations d
		  ON d.child_component_id = c.client_component_id
		 AND d.child_component_key_id = k.component_key_id
		 AND d.component_delegation_id = c.trust_delegation_id
		JOIN client_components p ON p.client_component_id = d.parent_component_id
		WHERE r.token_hash = $1 AND r.client_component_id = $2
		  AND r.grant_kind = 'provisioning' AND r.session_grant_id IS NULL
	`
	if forUpdate {
		statement += " FOR UPDATE OF f, c, k, sf, d, r"
	}
	var result componentProvisioningBinding
	var encodedJWK, encodedFeatures []byte
	var trustExpiresAt *time.Time
	err := query.QueryRow(ctx, statement, tokenHash, componentID).Scan(
		&result.RefreshTokenID, &result.SessionFamilyID,
		&result.OrganizationID, &result.ApplicationID, &result.EnvironmentID,
		&result.ApplicationUserID, &result.InstallationID, &result.FamilyID, &result.FamilyStatus,
		&result.ComponentID, &result.ComponentDefinitionID, &result.ComponentKind,
		&result.ComponentStatus, &result.ComponentKeyID, &result.ComponentKeyStatus,
		&result.CurrentComponentKeyID, &result.SessionStatus, &result.DPoPJKT, &encodedJWK,
		&result.TrustSource, &result.ParentComponentID, &result.ParentAttestationProvider,
		&result.DelegationID, &result.DelegationRevisionID, &encodedFeatures,
		&result.Platform, &result.AppVersion, &result.IdentityProvider, &result.TrustLevel,
		&result.IdentityVerifiedAt, &result.IdentityExpiresAt, &result.AttestedAt,
		&result.AttestationProvider, &result.AttestationExpiresAt, &trustExpiresAt,
		&result.DelegationExpiresAt, &result.DelegationConsumed, &result.DelegationRevoked,
		&result.ParentActive, &result.TokenStatus, &result.TokenExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return componentProvisioningBinding{}, ErrComponentNotProvisioned
	}
	if err != nil {
		return componentProvisioningBinding{}, fmt.Errorf("load component provisioning grant: %w", err)
	}
	if trustExpiresAt == nil {
		return componentProvisioningBinding{}, ErrComponentNotProvisioned
	}
	result.TrustExpiresAt = trustExpiresAt.UTC()
	if err := json.Unmarshal(encodedJWK, &result.PublicJWK); err != nil {
		return componentProvisioningBinding{}, ErrComponentKeyInvalid
	}
	if err := json.Unmarshal(encodedFeatures, &result.GrantedFeatures); err != nil {
		return componentProvisioningBinding{}, ErrComponentNotProvisioned
	}
	thumbprint, err := result.PublicJWK.Thumbprint()
	if err != nil || subtle.ConstantTimeCompare([]byte(thumbprint), []byte(result.DPoPJKT)) != 1 ||
		id.Validate(result.RefreshTokenID, id.ComponentRefresh) != nil ||
		id.Validate(result.SessionFamilyID, id.ComponentSession) != nil ||
		id.Validate(result.InstallationID, id.Installation) != nil ||
		id.Validate(result.FamilyID, id.InstallationFamily) != nil ||
		id.Validate(result.ComponentID, id.ClientComponent) != nil ||
		id.Validate(result.ComponentKeyID, id.ComponentKey) != nil ||
		id.Validate(result.DelegationID, id.ComponentDelegation) != nil ||
		!sessionIdentifierList(result.GrantedFeatures) {
		return componentProvisioningBinding{}, ErrComponentNotProvisioned
	}
	return result, nil
}

func componentProvisioningStateError(binding componentProvisioningBinding, snapshot configuration.ActiveSnapshot, now time.Time) error {
	if binding.FamilyStatus != "active" {
		return ErrInstallationFamilyRevoked
	}
	if binding.ComponentStatus == "replaced" || binding.ComponentKeyStatus == "replaced" ||
		binding.CurrentComponentKeyID != binding.ComponentKeyID {
		return ErrComponentKeyReplaced
	}
	if binding.ComponentStatus != "active" || binding.ComponentKeyStatus != "active" {
		return ErrComponentRevoked
	}
	if binding.SessionStatus != "active" {
		return ErrSessionRevoked
	}
	if binding.TokenStatus != "active" || !binding.TokenExpiresAt.After(now) {
		return ErrComponentNotProvisioned
	}
	if binding.DelegationConsumed || binding.DelegationRevoked || !binding.DelegationExpiresAt.After(now) {
		return ErrComponentDelegationExpired
	}
	if !binding.ParentActive || !binding.TrustExpiresAt.After(now) ||
		!binding.AttestationExpiresAt.After(now) {
		return ErrComponentParentTrustExpired
	}
	if !binding.IdentityExpiresAt.After(now) {
		return ErrIdentityRefreshRequired
	}
	definition, ok := snapshot.ComponentDefinition(binding.ComponentDefinitionID)
	if !ok || definition.FamilyRole != "delegated" || definition.Kind != binding.ComponentKind ||
		definition.Platform != binding.Platform || binding.DelegationRevisionID != snapshot.RevisionID ||
		!componentFeatureSubset(binding.GrantedFeatures, definition.AllowedFeatures) {
		return ErrComponentNotConfigured
	}
	return nil
}

// CreateComponentSession consumes a DPoP-bound provisioning grant and creates
// the component's first independently rotating access/refresh pair.
func (store *Store) CreateComponentSession(ctx context.Context, input ComponentSessionInput) (IssuedSession, error) {
	now := store.now().UTC().Truncate(time.Second)
	if err := input.validate(); err != nil {
		return IssuedSession{}, err
	}
	digest := sha256.Sum256([]byte(input.RefreshGrant.value))
	preflight, err := loadComponentProvisioningBinding(ctx, store.pool, digest[:], input.ComponentID, false)
	if err != nil {
		return IssuedSession{}, err
	}
	snapshot, err := store.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: preflight.OrganizationID, ApplicationID: preflight.ApplicationID,
		EnvironmentID: preflight.EnvironmentID,
	})
	if err != nil {
		return IssuedSession{}, ErrSessionScope
	}
	if !snapshotOriginAllowed(snapshot, preflight.Platform, input.Origin) {
		return IssuedSession{}, ErrSessionInvalid
	}
	if err := componentProvisioningStateError(preflight, snapshot, now); err != nil {
		return IssuedSession{}, err
	}
	proof, err := dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI, ExpectedJKT: preflight.DPoPJKT,
		Now: now, ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	normalizedURI, err := dpop.NormalizeHTU(input.RequestURI)
	if err != nil {
		return IssuedSession{}, ErrComponentNotProvisioned
	}
	preparedAccess, err := store.accessTokens.Prepare(ctx)
	if err != nil {
		return IssuedSession{}, err
	}
	grantID, err := id.New(id.SessionGrant)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate component session grant ID: %w", err)
	}
	refresh, refreshID, refreshHash, err := store.newRefreshTokenWithPrefix(id.ComponentRefresh)
	if err != nil {
		return IssuedSession{}, err
	}
	auditEventID, err := id.New(id.AuditEvent)
	if err != nil {
		return IssuedSession{}, fmt.Errorf("generate component session audit-event ID: %w", err)
	}
	access, err := preparedAccess.IssueFor(AccessIssueInput{
		OrganizationID: preflight.OrganizationID, ApplicationID: preflight.ApplicationID,
		EnvironmentID: preflight.EnvironmentID, ApplicationUserID: preflight.ApplicationUserID,
		InstallationID: preflight.InstallationID, InstallationFamilyID: preflight.FamilyID,
		ComponentID: preflight.ComponentID, ComponentDefinitionID: preflight.ComponentDefinitionID,
		ComponentKind: preflight.ComponentKind, ComponentIsRoot: false,
		TrustSource: preflight.TrustSource, AttestationProvider: preflight.AttestationProvider,
		ParentComponentID:         preflight.ParentComponentID,
		ParentAttestationProvider: preflight.ParentAttestationProvider,
		DelegationID:              preflight.DelegationID, Features: append([]string(nil), preflight.GrantedFeatures...),
		SessionGrantID: grantID, IdentityProvider: preflight.IdentityProvider,
		TrustLevel: preflight.TrustLevel, PolicyRevisionID: snapshot.RevisionID,
		DPoPJKT: preflight.DPoPJKT,
	}, snapshot.SessionPolicy().AccessTokenTTL)
	if err != nil {
		return IssuedSession{}, err
	}
	issuedAt := latestTime(now, access.IssuedAt)
	refreshExpiresAt := issuedAt.Add(snapshot.SessionPolicy().RefreshTokenTTL)
	if preflight.TrustExpiresAt.Before(refreshExpiresAt) {
		refreshExpiresAt = preflight.TrustExpiresAt
	}
	if !refreshExpiresAt.After(issuedAt) {
		return IssuedSession{}, ErrComponentParentTrustExpired
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return IssuedSession{}, fmt.Errorf("begin component session exchange: %w", err)
	}
	defer rollbackSigning(tx)
	var installationStatus string
	if err := tx.QueryRow(ctx, `
		SELECT status FROM installations
		WHERE installation_id = $1 AND organization_id = $2 AND application_id = $3
		  AND environment_id = $4 AND application_user_id = $5
		FOR SHARE
	`, preflight.InstallationID, preflight.OrganizationID, preflight.ApplicationID,
		preflight.EnvironmentID, preflight.ApplicationUserID).Scan(&installationStatus); err != nil || installationStatus != "active" {
		return IssuedSession{}, ErrSessionRevoked
	}
	binding, err := loadComponentProvisioningBinding(ctx, tx, digest[:], input.ComponentID, true)
	if err != nil {
		return IssuedSession{}, err
	}
	if binding.RefreshTokenID != preflight.RefreshTokenID || binding.ComponentKeyID != preflight.ComponentKeyID ||
		binding.SessionFamilyID != preflight.SessionFamilyID || binding.DPoPJKT != preflight.DPoPJKT {
		return IssuedSession{}, ErrComponentNotProvisioned
	}
	if err := componentProvisioningStateError(binding, snapshot, now); err != nil {
		return IssuedSession{}, err
	}
	proof, err = dpop.Validate(input.DPoPProof.value, dpop.Options{
		Method: input.HTTPMethod, URI: input.RequestURI, ExpectedJKT: binding.DPoPJKT,
		Now: now, ClockSkew: snapshot.SessionPolicy().MaximumClockSkew, ClockSkewSet: true,
	})
	if err != nil {
		return IssuedSession{}, err
	}
	if err := insertProvisionedComponentGrant(ctx, tx, binding, grantID, snapshot.RevisionID,
		access, issuedAt); err != nil {
		return IssuedSession{}, err
	}
	if err := store.replay.accept(ctx, tx, ReplayInput{
		OrganizationID: binding.OrganizationID, ApplicationID: binding.ApplicationID,
		EnvironmentID: binding.EnvironmentID, InstallationID: binding.InstallationID,
		SessionGrantID: grantID, ProofJTI: proof.JTI, HTTPMethod: input.HTTPMethod,
		NormalizedURI: normalizedURI,
	}); err != nil {
		return IssuedSession{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO component_refresh_tokens (
			component_refresh_token_id, component_session_family_id,
			client_component_id, component_key_id, session_grant_id, grant_kind,
			parent_component_refresh_token_id, token_hash, status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'session', $6, $7, 'staged', $8, $9)
	`, refreshID, binding.SessionFamilyID, binding.ComponentID, binding.ComponentKeyID,
		grantID, binding.RefreshTokenID, refreshHash[:], issuedAt, refreshExpiresAt); err != nil {
		return IssuedSession{}, fmt.Errorf("stage initial component refresh token: %w", err)
	}
	command, err := tx.Exec(ctx, `
		UPDATE component_refresh_tokens
		SET status = 'rotated', used_at = $2,
		    rotated_to_component_refresh_token_id = $3
		WHERE component_refresh_token_id = $1 AND token_hash = $4
		  AND grant_kind = 'provisioning' AND status = 'active'
	`, binding.RefreshTokenID, now, refreshID, digest[:])
	if err != nil {
		return IssuedSession{}, fmt.Errorf("consume component provisioning grant: %w", err)
	}
	if command.RowsAffected() != 1 {
		return IssuedSession{}, ErrComponentNotProvisioned
	}
	command, err = tx.Exec(ctx, `
		UPDATE component_refresh_tokens SET status = 'active'
		WHERE component_refresh_token_id = $1 AND grant_kind = 'session' AND status = 'staged'
	`, refreshID)
	if err != nil || command.RowsAffected() != 1 {
		return IssuedSession{}, ErrRefreshInvalid
	}
	command, err = tx.Exec(ctx, `
		UPDATE component_delegations SET consumed_at = $2
		WHERE component_delegation_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
	`, binding.DelegationID, now)
	if err != nil || command.RowsAffected() != 1 {
		return IssuedSession{}, ErrComponentDelegationExpired
	}
	if err := insertComponentLifecycleAudit(ctx, tx, auditEventID, binding.OrganizationID,
		binding.EnvironmentID, "client.component.session_created", binding.ComponentID, now,
		[][2]string{{"component_session_family", "set"}, {"refresh_grant", "consume"}}); err != nil {
		return IssuedSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IssuedSession{}, fmt.Errorf("commit component session exchange: %w", err)
	}
	return IssuedSession{
		Access: access, Refresh: refresh, RefreshID: refreshID,
		RefreshFamilyID: binding.SessionFamilyID, RefreshExpiresAt: refreshExpiresAt,
		GrantID: grantID,
		Installation: Installation{ID: binding.InstallationID, Platform: binding.Platform,
			DPoPJKT: binding.DPoPJKT, Status: "active", AppVersion: binding.AppVersion},
		Family: InstallationFamily{ID: binding.FamilyID, Status: "active"},
		Component: ClientComponent{
			ID: binding.ComponentID, DefinitionID: binding.ComponentDefinitionID,
			Kind: binding.ComponentKind, Platform: binding.Platform, IsRoot: false,
			Status: "active", KeyID: binding.ComponentKeyID, DPoPJKT: binding.DPoPJKT,
			TrustSource: binding.TrustSource, AttestationProvider: binding.AttestationProvider,
			ParentComponentID:         binding.ParentComponentID,
			ParentAttestationProvider: binding.ParentAttestationProvider,
			DelegationID:              binding.DelegationID,
			GrantedFeatures:           append([]string(nil), binding.GrantedFeatures...),
		},
		Trust: Trust{Provider: binding.AttestationProvider, Level: binding.TrustLevel,
			VerifiedAt: binding.AttestedAt, ExpiresAt: binding.TrustExpiresAt},
	}, nil
}

func insertProvisionedComponentGrant(ctx context.Context, tx pgx.Tx, binding componentProvisioningBinding,
	grantID, policyRevisionID string, access IssuedAccess, issuedAt time.Time) error {
	command, err := tx.Exec(ctx, `
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
		         $22, false, $23, $24
		  FROM application_users u
		  JOIN applications a ON a.organization_id = $2 AND a.application_id = $3
		  JOIN environments e
		    ON e.organization_id = $2 AND e.application_id = $3 AND e.environment_id = $4
		  JOIN organizations o ON o.organization_id = $2
		  WHERE u.organization_id = $2 AND u.application_id = $3
		    AND u.application_user_id = $5
		    AND u.status = 'active' AND a.status = 'active'
		    AND e.status = 'active' AND o.status = 'active'
	`, grantID, binding.OrganizationID, binding.ApplicationID, binding.EnvironmentID,
		binding.ApplicationUserID, binding.InstallationID, access.JTIHash[:], binding.DPoPJKT,
		policyRevisionID, binding.TrustLevel, binding.IdentityProvider,
		binding.IdentityVerifiedAt, binding.IdentityExpiresAt, binding.AttestedAt,
		binding.AttestationProvider, binding.TrustExpiresAt, issuedAt, access.ExpiresAt,
		binding.FamilyID, binding.ComponentID, binding.ComponentDefinitionID,
		binding.ComponentKind, binding.TrustSource, binding.SessionFamilyID)
	if err != nil {
		return fmt.Errorf("store provisioned component session grant: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrSessionScope
	}
	return nil
}

// RevokeComponent revokes one delegated component without affecting siblings.
func (store *Store) RevokeComponent(ctx context.Context, access AccessRequestInput, componentID string) error {
	if id.Validate(componentID, id.ClientComponent) != nil {
		return ErrComponentNotProvisioned
	}
	auditEventID, err := id.New(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate component revocation audit-event ID: %w", err)
	}
	_, err = store.authorizeAccess(ctx, access, false, true, func(
		ctx context.Context, tx pgx.Tx, state authorizationState, now time.Time,
	) error {
		if state.ComponentID == "" || !state.ComponentIsRoot || state.familyStatus != "active" {
			return ErrComponentNotProvisioned
		}
		var status string
		var isRoot bool
		err := tx.QueryRow(ctx, `
			SELECT status, is_root
			FROM client_components
			WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
			  AND installation_family_id = $4 AND client_component_id = $5
			FOR UPDATE
		`, state.OrganizationID, state.ApplicationID, state.EnvironmentID,
			state.InstallationFamilyID, componentID).Scan(&status, &isRoot)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrComponentNotProvisioned
		}
		if err != nil {
			return fmt.Errorf("lock component for revocation: %w", err)
		}
		if isRoot {
			return ErrComponentNotConfigured
		}
		if status != "active" && status != "revoked" && status != "replaced" {
			return ErrComponentRevoked
		}
		if status == "active" {
			if _, err := tx.Exec(ctx, `
					UPDATE attestation_keys
					SET status = 'revoked', revoked_at = GREATEST(created_at, $2),
					    updated_at = GREATEST(updated_at, created_at, $2)
					WHERE client_component_id = $1 AND status <> 'revoked'
				`, componentID, now); err != nil {
				return fmt.Errorf("revoke component attestation keys: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_refresh_tokens
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2))
				WHERE client_component_id = $1 AND status IN ('staged', 'active')
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke component refresh credentials: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE session_grants
				SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2)),
				    revoke_reason = COALESCE(revoke_reason, 'client_component_revoked')
				WHERE client_component_id = $1 AND revoked_at IS NULL
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke component session grants: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_session_families
				SET status = 'revoked', updated_at = $2, revoked_at = COALESCE(revoked_at, $2),
				    revocation_reason = COALESCE(revocation_reason, 'client_component_revoked')
				WHERE client_component_id = $1 AND status = 'active'
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke component session families: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_delegations
				SET revoked_at = COALESCE(revoked_at, $2)
				WHERE child_component_id = $1 AND revoked_at IS NULL
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke component delegations: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_keys
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2)
				WHERE client_component_id = $1 AND status = 'active'
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke component keys: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE client_components
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2),
				    revocation_reason = COALESCE(revocation_reason, 'client_component_revoked'),
				    updated_at = $2
				WHERE client_component_id = $1 AND status = 'active'
			`, componentID, now); err != nil {
				return fmt.Errorf("revoke client component: %w", err)
			}
		}
		return insertComponentLifecycleAudit(ctx, tx, auditEventID, state.OrganizationID,
			state.EnvironmentID, "client.component.revoked", componentID, now,
			[][2]string{{"component", "revoke"}, {"component_session_family", "revoke"}})
	})
	return err
}

// RevokeCurrentFamily revokes every component and independent session chain
// in the family authenticated by a root-component access token.
func (store *Store) RevokeCurrentFamily(ctx context.Context, access AccessRequestInput) error {
	auditEventID, err := id.New(id.AuditEvent)
	if err != nil {
		return fmt.Errorf("generate family revocation audit-event ID: %w", err)
	}
	_, err = store.authorizeAccess(ctx, access, true, true, func(
		ctx context.Context, tx pgx.Tx, state authorizationState, now time.Time,
	) error {
		if state.ComponentID == "" || !state.ComponentIsRoot || state.InstallationFamilyID == "" {
			return ErrComponentNotProvisioned
		}
		if state.familyStatus != "active" && state.familyStatus != "revoked" {
			return ErrInstallationFamilyRevoked
		}
		if state.familyStatus == "active" {
			if _, err := tx.Exec(ctx, `
					UPDATE attestation_keys
					SET status = 'revoked', revoked_at = GREATEST(created_at, $2),
					    updated_at = GREATEST(updated_at, created_at, $2)
					WHERE installation_family_id = $1 AND status <> 'revoked'
				`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family component attestation keys: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_refresh_tokens
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2))
				WHERE client_component_id IN (
					SELECT client_component_id FROM client_components
					WHERE installation_family_id = $1
				) AND status IN ('staged', 'active')
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family component refresh credentials: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE session_grants
				SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $2)),
				    revoke_reason = COALESCE(revoke_reason, 'client_family_revoked')
				WHERE installation_family_id = $1 AND revoked_at IS NULL
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family session grants: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_session_families
				SET status = 'revoked', updated_at = $2, revoked_at = COALESCE(revoked_at, $2),
				    revocation_reason = COALESCE(revocation_reason, 'client_family_revoked')
				WHERE installation_family_id = $1 AND status = 'active'
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family component sessions: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_delegations
				SET revoked_at = COALESCE(revoked_at, $2)
				WHERE installation_family_id = $1 AND revoked_at IS NULL
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family delegations: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE component_keys
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2)
				WHERE installation_family_id = $1 AND status = 'active'
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family component keys: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE client_components
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2),
				    revocation_reason = COALESCE(revocation_reason, 'client_family_revoked'),
				    updated_at = $2
				WHERE installation_family_id = $1 AND status = 'active'
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke family components: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE installation_families
				SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2),
				    revocation_reason = COALESCE(revocation_reason, 'client_family_revoked'),
				    updated_at = $2, last_seen_at = GREATEST(last_seen_at, $2)
				WHERE installation_family_id = $1 AND status = 'active'
			`, state.InstallationFamilyID, now); err != nil {
				return fmt.Errorf("revoke installation family: %w", err)
			}
			if err := revokeCurrentInstallation(ctx, tx, state, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_events (
				audit_event_id, organization_id, environment_id, actor_kind, actor_id,
				action, resource_type, resource_id, outcome, occurred_at, source
			) VALUES ($1, $2, $3, 'system', NULL, 'client.family.revoked',
			          'installation_family', $4, 'succeeded', $5, 'system')
		`, auditEventID, state.OrganizationID, state.EnvironmentID,
			state.InstallationFamilyID, now); err != nil {
			return fmt.Errorf("record family lifecycle audit event: %w", err)
		}
		return nil
	})
	return err
}

func insertComponentLifecycleAudit(ctx context.Context, tx pgx.Tx, eventID, organizationID,
	environmentID, action, componentID string, now time.Time, changes [][2]string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events (
			audit_event_id, organization_id, environment_id, actor_kind, actor_id,
			action, resource_type, resource_id, outcome, occurred_at, source
		) VALUES ($1, $2, $3, 'system', NULL, $4, 'client_component', $5, 'succeeded', $6, 'system')
	`, eventID, organizationID, environmentID, action, componentID, now); err != nil {
		return fmt.Errorf("record component lifecycle audit event: %w", err)
	}
	for index, change := range changes {
		classification := "public"
		if strings.Contains(change[0], "grant") || strings.Contains(change[0], "key") {
			classification = "sensitive"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_event_changes (
				audit_event_id, ordinal, field_name, operation, classification
			) VALUES ($1, $2, $3, $4, $5)
		`, eventID, index, change[0], change[1], classification); err != nil {
			return fmt.Errorf("record component lifecycle audit change: %w", err)
		}
	}
	return nil
}
