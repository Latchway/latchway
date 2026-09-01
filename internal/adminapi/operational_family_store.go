package adminapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

const (
	maximumFamilyComponents = 128
	maximumGrantedFeatures  = 256
)

type installationFamilyDocument struct {
	ID                 string                    `json:"id"`
	UserID             string                    `json:"user_id"`
	EnvironmentID      string                    `json:"environment_id"`
	Platform           string                    `json:"platform"`
	Status             string                    `json:"status"`
	RootComponentID    string                    `json:"root_component_id"`
	RootTrustSource    string                    `json:"root_trust_source"`
	RootTrustExpiresAt *time.Time                `json:"root_trust_expires_at,omitempty"`
	ComponentCount     int64                     `json:"component_count"`
	RequestCount       int64                     `json:"request_count"`
	Usage              usageValues               `json:"usage"`
	CreatedAt          time.Time                 `json:"created_at"`
	UpdatedAt          time.Time                 `json:"updated_at"`
	LastSeenAt         time.Time                 `json:"last_seen_at"`
	RevokedAt          *time.Time                `json:"revoked_at,omitempty"`
	RevocationReason   *string                   `json:"revocation_reason,omitempty"`
	Components         []clientComponentDocument `json:"components,omitempty"`
}

type componentDelegationDocument struct {
	ID                      string     `json:"id"`
	ParentComponentID       string     `json:"parent_component_id"`
	FeatureScopes           []string   `json:"feature_scopes"`
	ConfigurationRevisionID string     `json:"configuration_revision_id"`
	TrustLevel              string     `json:"trust_level"`
	AttestationProvider     string     `json:"attestation_provider"`
	IdentityExpiresAt       time.Time  `json:"identity_expires_at"`
	AttestationExpiresAt    time.Time  `json:"attestation_expires_at"`
	CreatedAt               time.Time  `json:"created_at"`
	ExpiresAt               time.Time  `json:"expires_at"`
	ConsumedAt              *time.Time `json:"consumed_at,omitempty"`
	RevokedAt               *time.Time `json:"revoked_at,omitempty"`
}

type clientComponentDocument struct {
	ID                       string                       `json:"id"`
	InstallationFamilyID     string                       `json:"installation_family_id"`
	UserID                   string                       `json:"user_id"`
	EnvironmentID            string                       `json:"environment_id"`
	DefinitionID             string                       `json:"definition_id"`
	Kind                     string                       `json:"kind"`
	Platform                 string                       `json:"platform"`
	IsRoot                   bool                         `json:"is_root"`
	Status                   string                       `json:"status"`
	ComponentKeyID           string                       `json:"component_key_id"`
	DPoPJKT                  string                       `json:"dpop_jkt"`
	KeyStorageClaim          string                       `json:"key_storage_claim"`
	TrustSource              string                       `json:"trust_source"`
	AttestationProvider      *string                      `json:"attestation_provider,omitempty"`
	ParentComponentID        *string                      `json:"parent_component_id,omitempty"`
	ParentAttestationEventID *string                      `json:"parent_attestation_event_id,omitempty"`
	TrustVerifiedAt          *time.Time                   `json:"trust_verified_at,omitempty"`
	TrustExpiresAt           *time.Time                   `json:"trust_expires_at,omitempty"`
	GrantedFeatures          []string                     `json:"granted_features"`
	AppVersion               *string                      `json:"app_version,omitempty"`
	SDKVersion               *string                      `json:"sdk_version,omitempty"`
	SessionFamilyID          *string                      `json:"session_family_id,omitempty"`
	SessionStatus            *string                      `json:"session_status,omitempty"`
	SessionExpiresAt         *time.Time                   `json:"session_expires_at,omitempty"`
	SessionFailureCount      int64                        `json:"session_failure_count"`
	RefreshReuseCount        int64                        `json:"refresh_reuse_count"`
	RequestCount             int64                        `json:"request_count"`
	Usage                    usageValues                  `json:"usage"`
	Delegation               *componentDelegationDocument `json:"delegation,omitempty"`
	CreatedAt                time.Time                    `json:"created_at"`
	UpdatedAt                time.Time                    `json:"updated_at"`
	LastSeenAt               time.Time                    `json:"last_seen_at"`
	RevokedAt                *time.Time                   `json:"revoked_at,omitempty"`
	RevocationReason         *string                      `json:"revocation_reason,omitempty"`
}

func (store *operationalStore) listInstallationFamilies(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	userID string,
	page operationalPage,
) ([]installationFamilyDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil ||
		(userID != "" && id.Validate(userID, id.ApplicationUser) != nil) ||
		page.validate(id.InstallationFamily) != nil {
		return nil, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, `
		SELECT family.installation_family_id, family.application_user_id,
		       family.environment_id, family.platform, family.status,
		       family.root_component_id, root.trust_source, root.trust_expires_at,
		       (
		           SELECT count(*)::bigint FROM client_components AS component
		           WHERE component.installation_family_id = family.installation_family_id
		       ),
		       stats.request_count, stats.logical_requests, stats.input_tokens,
		       stats.output_tokens, stats.total_tokens, stats.cost_nano_usd,
		       family.created_at, family.updated_at, family.last_seen_at,
		       family.revoked_at, family.revocation_reason
		FROM installation_families AS family
		JOIN environments AS environment
		  ON environment.organization_id = family.organization_id
		 AND environment.application_id = family.application_id
		 AND environment.environment_id = family.environment_id
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		LEFT JOIN client_components AS root
		  ON root.client_component_id = family.root_component_id
		LEFT JOIN LATERAL (
		    SELECT count(DISTINCT request.logical_request_id)::bigint AS request_count,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'logical_requests'), 0)::bigint AS logical_requests,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'input_tokens'), 0)::bigint AS input_tokens,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'output_tokens'), 0)::bigint AS output_tokens,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'total_tokens'), 0)::bigint AS total_tokens,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'cost_nano_usd'), 0)::bigint AS cost_nano_usd
		    FROM logical_requests AS request
		    LEFT JOIN usage_records AS usage
		      ON usage.organization_id = request.organization_id
		     AND usage.environment_id = request.environment_id
		     AND usage.logical_request_id = request.logical_request_id
		    WHERE request.organization_id = family.organization_id
		      AND request.environment_id = family.environment_id
		      AND request.installation_family_id = family.installation_family_id
		) AS stats ON true
		WHERE family.organization_id = $1 AND family.environment_id = $2
		  AND ($3::text IS NULL OR family.application_user_id = $3)
		  AND organization.status = 'active'
		  AND ($4::timestamptz IS NULL OR
		       (family.created_at, family.installation_family_id) > ($4, $5))
		ORDER BY family.created_at, family.installation_family_id
		LIMIT $6
	`, principal.OrganizationID, environmentID, nullableString(userID),
		nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list installation families: %w", err)
	}
	defer rows.Close()
	items := make([]installationFamilyDocument, 0, page.size+1)
	for rows.Next() {
		item, scanErr := scanInstallationFamily(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate installation families: %w", err)
	}
	return items, nil
}

func (store *operationalStore) getInstallationFamily(
	ctx context.Context,
	principal adminauth.Principal,
	familyID string,
) (installationFamilyDocument, error) {
	if id.Validate(familyID, id.InstallationFamily) != nil {
		return installationFamilyDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return installationFamilyDocument{}, errOperationalForbidden
	}
	item, err := queryInstallationFamily(ctx, store.pool, principal.OrganizationID, familyID)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	components, err := store.listClientComponents(
		ctx, principal, item.EnvironmentID, familyID,
		operationalPage{size: maximumFamilyComponents + 1},
	)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if len(components) > maximumFamilyComponents || int64(len(components)) != item.ComponentCount {
		return installationFamilyDocument{}, errOperationalCorrupt
	}
	item.Components = components
	return item, nil
}

func queryInstallationFamily(
	ctx context.Context,
	queryer rowQueryer,
	organizationID string,
	familyID string,
) (installationFamilyDocument, error) {
	row := queryer.QueryRow(ctx, `
		SELECT family.installation_family_id, family.application_user_id,
		       family.environment_id, family.platform, family.status,
		       family.root_component_id, root.trust_source, root.trust_expires_at,
		       (
		           SELECT count(*)::bigint FROM client_components AS component
		           WHERE component.installation_family_id = family.installation_family_id
		       ),
		       stats.request_count, stats.logical_requests, stats.input_tokens,
		       stats.output_tokens, stats.total_tokens, stats.cost_nano_usd,
		       family.created_at, family.updated_at, family.last_seen_at,
		       family.revoked_at, family.revocation_reason
		FROM installation_families AS family
		JOIN environments AS environment
		  ON environment.organization_id = family.organization_id
		 AND environment.application_id = family.application_id
		 AND environment.environment_id = family.environment_id
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		LEFT JOIN client_components AS root
		  ON root.client_component_id = family.root_component_id
		LEFT JOIN LATERAL (
		    SELECT count(DISTINCT request.logical_request_id)::bigint AS request_count,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'logical_requests'), 0)::bigint AS logical_requests,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'input_tokens'), 0)::bigint AS input_tokens,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'output_tokens'), 0)::bigint AS output_tokens,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'total_tokens'), 0)::bigint AS total_tokens,
		           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'cost_nano_usd'), 0)::bigint AS cost_nano_usd
		    FROM logical_requests AS request
		    LEFT JOIN usage_records AS usage
		      ON usage.organization_id = request.organization_id
		     AND usage.environment_id = request.environment_id
		     AND usage.logical_request_id = request.logical_request_id
		    WHERE request.organization_id = family.organization_id
		      AND request.environment_id = family.environment_id
		      AND request.installation_family_id = family.installation_family_id
		) AS stats ON true
		WHERE family.organization_id = $1 AND family.installation_family_id = $2
		  AND organization.status = 'active'
	`, organizationID, familyID)
	item, err := scanInstallationFamily(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return installationFamilyDocument{}, errOperationalNotFound
	}
	return item, err
}

func scanInstallationFamily(row rowScanner) (installationFamilyDocument, error) {
	var item installationFamilyDocument
	var rootComponentID *string
	if err := row.Scan(
		&item.ID, &item.UserID, &item.EnvironmentID, &item.Platform, &item.Status,
		&rootComponentID, &item.RootTrustSource, &item.RootTrustExpiresAt,
		&item.ComponentCount, &item.RequestCount,
		&item.Usage.LogicalRequests, &item.Usage.InputTokens, &item.Usage.OutputTokens,
		&item.Usage.TotalTokens, &item.Usage.CostNanoUSD,
		&item.CreatedAt, &item.UpdatedAt, &item.LastSeenAt,
		&item.RevokedAt, &item.RevocationReason,
	); err != nil {
		return installationFamilyDocument{}, err
	}
	if rootComponentID == nil || id.Validate(item.ID, id.InstallationFamily) != nil ||
		id.Validate(*rootComponentID, id.ClientComponent) != nil || item.ComponentCount < 1 ||
		item.ComponentCount > maximumFamilyComponents || item.RequestCount < 0 ||
		!validUsageValues(item.Usage) || !validFamilyStatus(item.Status) ||
		!operationalIdentifierPattern.MatchString(item.RootTrustSource) ||
		item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) ||
		item.LastSeenAt.Before(item.CreatedAt) {
		return installationFamilyDocument{}, errOperationalCorrupt
	}
	item.RootComponentID = *rootComponentID
	return item, nil
}

func (store *operationalStore) listClientComponents(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	familyID string,
	page operationalPage,
) ([]clientComponentDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || page.validate(id.ClientComponent) != nil ||
		(familyID != "" && id.Validate(familyID, id.InstallationFamily) != nil) {
		return nil, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, clientComponentSelect+`
		WHERE component.organization_id = $1 AND component.environment_id = $2
		  AND ($3::text IS NULL OR component.installation_family_id = $3)
		  AND organization.status = 'active'
		  AND ($4::timestamptz IS NULL OR
		       (component.created_at, component.client_component_id) > ($4, $5))
		ORDER BY component.created_at, component.client_component_id
		LIMIT $6
	`, principal.OrganizationID, environmentID, nullableString(familyID),
		nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list client components: %w", err)
	}
	defer rows.Close()
	items := make([]clientComponentDocument, 0, page.size+1)
	for rows.Next() {
		item, scanErr := scanClientComponent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client components: %w", err)
	}
	return items, nil
}

func (store *operationalStore) getClientComponent(
	ctx context.Context,
	principal adminauth.Principal,
	componentID string,
) (clientComponentDocument, error) {
	if id.Validate(componentID, id.ClientComponent) != nil {
		return clientComponentDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return clientComponentDocument{}, errOperationalForbidden
	}
	return queryClientComponent(ctx, store.pool, principal.OrganizationID, componentID)
}

const clientComponentSelect = `
	SELECT component.client_component_id, component.installation_family_id,
	       component.application_user_id, component.environment_id,
	       component.component_definition_id, component.component_kind,
	       component.platform, component.is_root, component.status,
	       component.current_component_key_id, component_key.dpop_jkt,
	       component.key_storage_claim, component.trust_source,
	       component.trust_attestation_provider, component.trust_parent_component_id,
	       component.trust_parent_attestation_event_id,
	       component.trust_verified_at, component.trust_expires_at,
	       component.granted_features, component.app_version, component.sdk_version,
	       session_record.component_session_family_id, session_record.status,
	       (
	           SELECT max(grant_record.expires_at)
	           FROM session_grants AS grant_record
	           WHERE grant_record.client_component_id = component.client_component_id
	             AND grant_record.revoked_at IS NULL
	       ),
	       (
	           SELECT count(*)::bigint
	           FROM component_session_families AS failed_session
	           WHERE failed_session.client_component_id = component.client_component_id
	             AND failed_session.status IN ('revoked', 'expired')
	       ),
	       (
	           SELECT count(*)::bigint
	           FROM component_refresh_tokens AS refresh_record
	           WHERE refresh_record.client_component_id = component.client_component_id
	             AND refresh_record.status = 'reused'
	       ),
	       stats.request_count, stats.logical_requests, stats.input_tokens,
	       stats.output_tokens, stats.total_tokens, stats.cost_nano_usd,
	       delegation.component_delegation_id, delegation.parent_component_id,
	       delegation.feature_scopes, delegation.configuration_revision_id,
	       delegation.trust_level, delegation.attestation_provider,
	       delegation.identity_expires_at, delegation.attestation_expires_at,
	       delegation.created_at, delegation.expires_at,
	       delegation.consumed_at, delegation.revoked_at,
	       component.created_at, component.updated_at, component.last_seen_at,
	       component.revoked_at, component.revocation_reason
	FROM client_components AS component
	JOIN environments AS environment
	  ON environment.organization_id = component.organization_id
	 AND environment.application_id = component.application_id
	 AND environment.environment_id = component.environment_id
	JOIN applications AS application
	  ON application.organization_id = environment.organization_id
	 AND application.application_id = environment.application_id
	JOIN organizations AS organization
	  ON organization.organization_id = environment.organization_id
	LEFT JOIN component_keys AS component_key
	  ON component_key.component_key_id = component.current_component_key_id
	LEFT JOIN component_delegations AS delegation
	  ON delegation.component_delegation_id = component.trust_delegation_id
	LEFT JOIN LATERAL (
	    SELECT family_record.component_session_family_id, family_record.status
	    FROM component_session_families AS family_record
	    WHERE family_record.client_component_id = component.client_component_id
	    ORDER BY family_record.created_at DESC, family_record.component_session_family_id DESC
	    LIMIT 1
	) AS session_record ON true
	LEFT JOIN LATERAL (
	    SELECT count(DISTINCT request.logical_request_id)::bigint AS request_count,
	           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'logical_requests'), 0)::bigint AS logical_requests,
	           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'input_tokens'), 0)::bigint AS input_tokens,
	           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'output_tokens'), 0)::bigint AS output_tokens,
	           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'total_tokens'), 0)::bigint AS total_tokens,
	           COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'cost_nano_usd'), 0)::bigint AS cost_nano_usd
	    FROM logical_requests AS request
	    LEFT JOIN usage_records AS usage
	      ON usage.organization_id = request.organization_id
	     AND usage.environment_id = request.environment_id
	     AND usage.logical_request_id = request.logical_request_id
	    WHERE request.organization_id = component.organization_id
	      AND request.environment_id = component.environment_id
	      AND request.client_component_id = component.client_component_id
	) AS stats ON true
`

func queryClientComponent(
	ctx context.Context,
	queryer rowQueryer,
	organizationID string,
	componentID string,
) (clientComponentDocument, error) {
	row := queryer.QueryRow(ctx, clientComponentSelect+`
		WHERE component.organization_id = $1 AND component.client_component_id = $2
		  AND organization.status = 'active'
	`, organizationID, componentID)
	item, err := scanClientComponent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return clientComponentDocument{}, errOperationalNotFound
	}
	return item, err
}

func scanClientComponent(row rowScanner) (clientComponentDocument, error) {
	var item clientComponentDocument
	var delegationID, delegationParent, delegationRevision, delegationTrust *string
	var delegationProvider *string
	var delegationFeatures []string
	var identityExpiresAt, attestationExpiresAt, delegationCreatedAt, delegationExpiresAt *time.Time
	var delegationConsumedAt, delegationRevokedAt *time.Time
	if err := row.Scan(
		&item.ID, &item.InstallationFamilyID, &item.UserID, &item.EnvironmentID,
		&item.DefinitionID, &item.Kind, &item.Platform, &item.IsRoot, &item.Status,
		&item.ComponentKeyID, &item.DPoPJKT, &item.KeyStorageClaim, &item.TrustSource,
		&item.AttestationProvider, &item.ParentComponentID,
		&item.ParentAttestationEventID, &item.TrustVerifiedAt, &item.TrustExpiresAt,
		&item.GrantedFeatures, &item.AppVersion, &item.SDKVersion,
		&item.SessionFamilyID, &item.SessionStatus, &item.SessionExpiresAt,
		&item.SessionFailureCount, &item.RefreshReuseCount, &item.RequestCount,
		&item.Usage.LogicalRequests, &item.Usage.InputTokens, &item.Usage.OutputTokens,
		&item.Usage.TotalTokens, &item.Usage.CostNanoUSD,
		&delegationID, &delegationParent, &delegationFeatures, &delegationRevision,
		&delegationTrust, &delegationProvider, &identityExpiresAt, &attestationExpiresAt,
		&delegationCreatedAt, &delegationExpiresAt,
		&delegationConsumedAt, &delegationRevokedAt,
		&item.CreatedAt, &item.UpdatedAt, &item.LastSeenAt,
		&item.RevokedAt, &item.RevocationReason,
	); err != nil {
		return clientComponentDocument{}, err
	}
	if !validClientComponentDocument(item) {
		return clientComponentDocument{}, errOperationalCorrupt
	}
	if delegationID != nil {
		if delegationParent == nil || delegationRevision == nil || delegationTrust == nil ||
			delegationProvider == nil || identityExpiresAt == nil || attestationExpiresAt == nil ||
			delegationCreatedAt == nil || delegationExpiresAt == nil ||
			id.Validate(*delegationID, id.ComponentDelegation) != nil ||
			id.Validate(*delegationParent, id.ClientComponent) != nil ||
			id.Validate(*delegationRevision, id.ConfigRevision) != nil ||
			!validFeatureList(delegationFeatures) {
			return clientComponentDocument{}, errOperationalCorrupt
		}
		item.Delegation = &componentDelegationDocument{
			ID: *delegationID, ParentComponentID: *delegationParent,
			FeatureScopes: delegationFeatures, ConfigurationRevisionID: *delegationRevision,
			TrustLevel: *delegationTrust, AttestationProvider: *delegationProvider,
			IdentityExpiresAt: *identityExpiresAt, AttestationExpiresAt: *attestationExpiresAt,
			CreatedAt: *delegationCreatedAt, ExpiresAt: *delegationExpiresAt,
			ConsumedAt: delegationConsumedAt, RevokedAt: delegationRevokedAt,
		}
	}
	return item, nil
}

func validClientComponentDocument(item clientComponentDocument) bool {
	if id.Validate(item.ID, id.ClientComponent) != nil ||
		id.Validate(item.InstallationFamilyID, id.InstallationFamily) != nil ||
		id.Validate(item.ComponentKeyID, id.ComponentKey) != nil ||
		!operationalIdentifierPattern.MatchString(item.DefinitionID) ||
		!operationalIdentifierPattern.MatchString(item.Kind) ||
		!operationalIdentifierPattern.MatchString(item.TrustSource) ||
		len(item.DPoPJKT) != 43 || !validComponentStatus(item.Status) ||
		!validFeatureList(item.GrantedFeatures) || item.SessionFailureCount < 0 ||
		item.RefreshReuseCount < 0 ||
		item.RequestCount < 0 || !validUsageValues(item.Usage) ||
		item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) ||
		item.LastSeenAt.Before(item.CreatedAt) {
		return false
	}
	if item.IsRoot != (item.ParentComponentID == nil) {
		return false
	}
	if item.ParentComponentID != nil && id.Validate(*item.ParentComponentID, id.ClientComponent) != nil {
		return false
	}
	if item.ParentAttestationEventID != nil &&
		id.Validate(*item.ParentAttestationEventID, id.AttestationEvent) != nil {
		return false
	}
	if (item.SessionFamilyID == nil) != (item.SessionStatus == nil) {
		return false
	}
	if item.SessionFamilyID != nil &&
		(id.Validate(*item.SessionFamilyID, id.ComponentSession) != nil ||
			!validComponentSessionStatus(*item.SessionStatus)) {
		return false
	}
	for _, version := range []*string{item.AppVersion, item.SDKVersion} {
		if version != nil && !validOperationalVersion(*version) {
			return false
		}
	}
	return true
}

func validFeatureList(features []string) bool {
	if features == nil || len(features) > maximumGrantedFeatures {
		return false
	}
	seen := make(map[string]struct{}, len(features))
	for _, feature := range features {
		if !operationalIdentifierPattern.MatchString(feature) {
			return false
		}
		if _, duplicate := seen[feature]; duplicate {
			return false
		}
		seen[feature] = struct{}{}
	}
	return true
}

func validUsageValues(values usageValues) bool {
	return values.LogicalRequests >= 0 && values.InputTokens >= 0 &&
		values.OutputTokens >= 0 && values.TotalTokens >= 0 && values.CostNanoUSD >= 0
}

func validFamilyStatus(status string) bool {
	return status == "active" || status == "suspended" || status == "revoked"
}

func validComponentStatus(status string) bool {
	return status == "active" || status == "suspended" ||
		status == "revoked" || status == "replaced"
}

func validComponentSessionStatus(status string) bool {
	return status == "active" || status == "revoked" ||
		status == "expired" || status == "replaced"
}

func validateOperationalRevocationReason(reason, fallback string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = fallback
	}
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > 100 ||
		strings.ContainsAny(reason, "\r\n\x00") {
		return "", errOperationalInvalid
	}
	return reason, nil
}

// installationFamilyScope resolves immutable scope identifiers without taking
// a target-row lock. Callers use them to acquire application and environment
// lifecycle locks before locking the family itself.
func installationFamilyScope(
	ctx context.Context,
	queryer rowQueryer,
	organizationID string,
	familyID string,
) (string, string, error) {
	var applicationID, environmentID string
	if err := queryer.QueryRow(ctx, `
		SELECT application_id, environment_id
		FROM installation_families
		WHERE organization_id = $1 AND installation_family_id = $2
	`, organizationID, familyID).Scan(&applicationID, &environmentID); errors.Is(err, pgx.ErrNoRows) {
		return "", "", errOperationalNotFound
	} else if err != nil {
		return "", "", fmt.Errorf("locate installation family scope: %w", err)
	}
	return applicationID, environmentID, nil
}

// clientComponentScope resolves the immutable family and lifecycle scope
// without taking a target-row lock. Component mutations subsequently lock the
// family and component separately, in that order.
func clientComponentScope(
	ctx context.Context,
	queryer rowQueryer,
	organizationID string,
	componentID string,
) (string, string, string, error) {
	var familyID, applicationID, environmentID string
	if err := queryer.QueryRow(ctx, `
		SELECT installation_family_id, application_id, environment_id
		FROM client_components
		WHERE organization_id = $1 AND client_component_id = $2
	`, organizationID, componentID).Scan(
		&familyID, &applicationID, &environmentID,
	); errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", errOperationalNotFound
	} else if err != nil {
		return "", "", "", fmt.Errorf("locate client component scope: %w", err)
	}
	return familyID, applicationID, environmentID, nil
}

func (store *operationalStore) revokeInstallationFamily(
	ctx context.Context,
	principal adminauth.Principal,
	familyID string,
	reason string,
	requestID string,
) (installationFamilyDocument, error) {
	if id.Validate(familyID, id.InstallationFamily) != nil ||
		id.Validate(requestID, id.AdminRequest) != nil {
		return installationFamilyDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return installationFamilyDocument{}, errOperationalForbidden
	}
	reason, err := validateOperationalRevocationReason(reason, "admin_installation_family_revoked")
	if err != nil {
		return installationFamilyDocument{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return installationFamilyDocument{}, fmt.Errorf("begin installation-family revocation: %w", err)
	}
	defer rollbackOperational(tx)

	applicationID, environmentID, err := installationFamilyScope(
		ctx, tx, principal.OrganizationID, familyID,
	)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if err := lockActiveOperationalScope(ctx, tx, principal.OrganizationID, applicationID, environmentID); err != nil {
		return installationFamilyDocument{}, err
	}
	var userID, rootInstallationID, status string
	if err := tx.QueryRow(ctx, `
		/* operational_lock_installation_family */
		SELECT application_user_id, root_installation_id, status
		FROM installation_families
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND application_id = $3 AND environment_id = $4
		FOR UPDATE
	`, principal.OrganizationID, familyID, applicationID, environmentID).Scan(
		&userID, &rootInstallationID, &status,
	); errors.Is(err, pgx.ErrNoRows) {
		return installationFamilyDocument{}, errOperationalNotFound
	} else if err != nil {
		return installationFamilyDocument{}, fmt.Errorf("lock installation family: %w", err)
	}
	if !validFamilyStatus(status) {
		return installationFamilyDocument{}, errOperationalCorrupt
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return installationFamilyDocument{}, fmt.Errorf("read installation-family revocation time: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE installation_families
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(created_at, $3)),
		    revocation_reason = COALESCE(revocation_reason, $4),
		    updated_at = GREATEST(updated_at, created_at, $3)
		WHERE organization_id = $1 AND installation_family_id = $2
	`, principal.OrganizationID, familyID, now, reason); err != nil {
		return installationFamilyDocument{}, fmt.Errorf("revoke installation family: %w", err)
	}
	if err := revokeComponentCredentials(
		ctx, tx, principal.OrganizationID, familyID, nil, now, reason,
	); err != nil {
		return installationFamilyDocument{}, err
	}
	if err := revokeLegacyRootCredentials(
		ctx, tx, principal.OrganizationID, applicationID, environmentID,
		userID, rootInstallationID, now, reason,
	); err != nil {
		return installationFamilyDocument{}, err
	}
	statusChange, err := adminauth.NewPublicAuditChange("status", adminauth.AuditSet)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	componentsChange, err := adminauth.NewSensitiveAuditChange("component_credentials", adminauth.AuditRevoke)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if err := store.audit(
		ctx, tx, principal, environmentID, "admin.installation_family_revoke",
		"installation_family", familyID, requestID, now,
		[]adminauth.AuditChange{statusChange, componentsChange},
	); err != nil {
		return installationFamilyDocument{}, err
	}
	result, err := queryInstallationFamily(ctx, tx, principal.OrganizationID, familyID)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return installationFamilyDocument{}, mapOperationalCommit("commit installation-family revocation", err)
	}
	return result, nil
}

// requireInstallationFamilyRenewal expires the family's trust and rotating
// refresh credentials without revoking already-issued access grants. This
// preserves the documented default: access tokens may live until expiry, but
// the containing app must establish fresh direct trust before any component
// can refresh or be provisioned again.
func (store *operationalStore) requireInstallationFamilyRenewal(
	ctx context.Context,
	principal adminauth.Principal,
	familyID string,
	reason string,
	requestID string,
) (installationFamilyDocument, error) {
	if id.Validate(familyID, id.InstallationFamily) != nil ||
		id.Validate(requestID, id.AdminRequest) != nil {
		return installationFamilyDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return installationFamilyDocument{}, errOperationalForbidden
	}
	if _, err := validateOperationalRevocationReason(reason, "admin_containing_app_renewal_required"); err != nil {
		return installationFamilyDocument{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return installationFamilyDocument{}, fmt.Errorf("begin containing-app renewal requirement: %w", err)
	}
	defer rollbackOperational(tx)

	applicationID, environmentID, err := installationFamilyScope(
		ctx, tx, principal.OrganizationID, familyID,
	)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if err := lockActiveOperationalScope(ctx, tx, principal.OrganizationID, applicationID, environmentID); err != nil {
		return installationFamilyDocument{}, err
	}
	var userID, rootInstallationID, status string
	if err := tx.QueryRow(ctx, `
		/* operational_lock_installation_family */
		SELECT application_user_id, root_installation_id, status
		FROM installation_families
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND application_id = $3 AND environment_id = $4
		FOR UPDATE
	`, principal.OrganizationID, familyID, applicationID, environmentID).Scan(
		&userID, &rootInstallationID, &status,
	); errors.Is(err, pgx.ErrNoRows) {
		return installationFamilyDocument{}, errOperationalNotFound
	} else if err != nil {
		return installationFamilyDocument{}, fmt.Errorf("lock family for containing-app renewal: %w", err)
	}
	if status != "active" {
		return installationFamilyDocument{}, errOperationalInvalid
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return installationFamilyDocument{}, fmt.Errorf("read containing-app renewal time: %w", err)
	}
	if err := expireComponentTrustAndRefresh(
		ctx, tx, principal.OrganizationID, familyID, nil, now,
	); err != nil {
		return installationFamilyDocument{}, err
	}
	if err := revokeLegacyRefreshForRenewal(
		ctx, tx, principal.OrganizationID, applicationID, environmentID,
		userID, rootInstallationID, now,
	); err != nil {
		return installationFamilyDocument{}, err
	}
	trustChange, err := adminauth.NewPublicAuditChange("containing_app_renewal_required", adminauth.AuditSet)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	refreshChange, err := adminauth.NewSensitiveAuditChange("refresh_credentials", adminauth.AuditRevoke)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if err := store.audit(
		ctx, tx, principal, environmentID, "admin.installation_family_require_renewal",
		"installation_family", familyID, requestID, now,
		[]adminauth.AuditChange{trustChange, refreshChange},
	); err != nil {
		return installationFamilyDocument{}, err
	}
	result, err := queryInstallationFamily(ctx, tx, principal.OrganizationID, familyID)
	if err != nil {
		return installationFamilyDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return installationFamilyDocument{}, mapOperationalCommit("commit containing-app renewal requirement", err)
	}
	return result, nil
}

func (store *operationalStore) revokeClientComponent(
	ctx context.Context,
	principal adminauth.Principal,
	componentID string,
	reason string,
	requestID string,
) (clientComponentDocument, error) {
	if id.Validate(componentID, id.ClientComponent) != nil ||
		id.Validate(requestID, id.AdminRequest) != nil {
		return clientComponentDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return clientComponentDocument{}, errOperationalForbidden
	}
	reason, err := validateOperationalRevocationReason(reason, "admin_client_component_revoked")
	if err != nil {
		return clientComponentDocument{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return clientComponentDocument{}, fmt.Errorf("begin client-component revocation: %w", err)
	}
	defer rollbackOperational(tx)

	familyID, applicationID, environmentID, err := clientComponentScope(
		ctx, tx, principal.OrganizationID, componentID,
	)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := lockActiveOperationalScope(ctx, tx, principal.OrganizationID, applicationID, environmentID); err != nil {
		return clientComponentDocument{}, err
	}
	var rootInstallationID string
	if err := tx.QueryRow(ctx, `
		/* operational_lock_component_family */
		SELECT root_installation_id
		FROM installation_families
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND application_id = $3 AND environment_id = $4
		FOR UPDATE
	`, principal.OrganizationID, familyID, applicationID, environmentID).Scan(
		&rootInstallationID,
	); errors.Is(err, pgx.ErrNoRows) {
		return clientComponentDocument{}, errOperationalNotFound
	} else if err != nil {
		return clientComponentDocument{}, fmt.Errorf("lock client component family: %w", err)
	}
	var userID string
	var isRoot bool
	if err := tx.QueryRow(ctx, `
		/* operational_lock_client_component */
		SELECT application_user_id, is_root
		FROM client_components
		WHERE organization_id = $1 AND client_component_id = $2
		  AND installation_family_id = $3 AND application_id = $4 AND environment_id = $5
		FOR UPDATE
	`, principal.OrganizationID, componentID, familyID, applicationID, environmentID).Scan(
		&userID, &isRoot,
	); errors.Is(err, pgx.ErrNoRows) {
		return clientComponentDocument{}, errOperationalNotFound
	} else if err != nil {
		return clientComponentDocument{}, fmt.Errorf("lock client component: %w", err)
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return clientComponentDocument{}, fmt.Errorf("read client-component revocation time: %w", err)
	}
	affected, err := affectedComponentIDs(ctx, tx, familyID, componentID, isRoot)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := revokeComponentCredentials(
		ctx, tx, principal.OrganizationID, familyID, affected, now, reason,
	); err != nil {
		return clientComponentDocument{}, err
	}
	if isRoot {
		if _, err := tx.Exec(ctx, `
			UPDATE installation_families
			SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(created_at, $3)),
			    revocation_reason = COALESCE(revocation_reason, $4),
			    updated_at = GREATEST(updated_at, created_at, $3)
			WHERE organization_id = $1 AND installation_family_id = $2
		`, principal.OrganizationID, familyID, now, reason); err != nil {
			return clientComponentDocument{}, fmt.Errorf("revoke root component family: %w", err)
		}
		if err := revokeLegacyRootCredentials(
			ctx, tx, principal.OrganizationID, applicationID, environmentID,
			userID, rootInstallationID, now, reason,
		); err != nil {
			return clientComponentDocument{}, err
		}
	}
	statusChange, err := adminauth.NewPublicAuditChange("status", adminauth.AuditSet)
	if err != nil {
		return clientComponentDocument{}, err
	}
	credentialChange, err := adminauth.NewSensitiveAuditChange("component_credentials", adminauth.AuditRevoke)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := store.audit(
		ctx, tx, principal, environmentID, "admin.client_component_revoke",
		"client_component", componentID, requestID, now,
		[]adminauth.AuditChange{statusChange, credentialChange},
	); err != nil {
		return clientComponentDocument{}, err
	}
	result, err := queryClientComponent(ctx, tx, principal.OrganizationID, componentID)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return clientComponentDocument{}, mapOperationalCommit("commit client-component revocation", err)
	}
	return result, nil
}

// requireClientComponentReattestation expires one component trust subtree and
// its refresh credentials while leaving sibling components and current access
// grants untouched. A root-component action therefore affects the whole
// family, matching the containing-app trust boundary.
func (store *operationalStore) requireClientComponentReattestation(
	ctx context.Context,
	principal adminauth.Principal,
	componentID string,
	reason string,
	requestID string,
) (clientComponentDocument, error) {
	if id.Validate(componentID, id.ClientComponent) != nil ||
		id.Validate(requestID, id.AdminRequest) != nil {
		return clientComponentDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RevokeInstallations, adminauth.AuthorizationContext{}) {
		return clientComponentDocument{}, errOperationalForbidden
	}
	if _, err := validateOperationalRevocationReason(reason, "admin_component_reattestation_required"); err != nil {
		return clientComponentDocument{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return clientComponentDocument{}, fmt.Errorf("begin component re-attestation requirement: %w", err)
	}
	defer rollbackOperational(tx)

	familyID, applicationID, environmentID, err := clientComponentScope(
		ctx, tx, principal.OrganizationID, componentID,
	)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := lockActiveOperationalScope(ctx, tx, principal.OrganizationID, applicationID, environmentID); err != nil {
		return clientComponentDocument{}, err
	}
	var rootInstallationID, familyStatus string
	if err := tx.QueryRow(ctx, `
		/* operational_lock_component_family */
		SELECT root_installation_id, status
		FROM installation_families
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND application_id = $3 AND environment_id = $4
		FOR UPDATE
	`, principal.OrganizationID, familyID, applicationID, environmentID).Scan(
		&rootInstallationID, &familyStatus,
	); errors.Is(err, pgx.ErrNoRows) {
		return clientComponentDocument{}, errOperationalNotFound
	} else if err != nil {
		return clientComponentDocument{}, fmt.Errorf("lock component family for re-attestation: %w", err)
	}
	var userID, componentStatus string
	var isRoot bool
	if err := tx.QueryRow(ctx, `
		/* operational_lock_client_component */
		SELECT application_user_id, is_root, status
		FROM client_components
		WHERE organization_id = $1 AND client_component_id = $2
		  AND installation_family_id = $3 AND application_id = $4 AND environment_id = $5
		FOR UPDATE
	`, principal.OrganizationID, componentID, familyID, applicationID, environmentID).Scan(
		&userID, &isRoot, &componentStatus,
	); errors.Is(err, pgx.ErrNoRows) {
		return clientComponentDocument{}, errOperationalNotFound
	} else if err != nil {
		return clientComponentDocument{}, fmt.Errorf("lock component for re-attestation: %w", err)
	}
	if componentStatus != "active" || familyStatus != "active" {
		return clientComponentDocument{}, errOperationalInvalid
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return clientComponentDocument{}, fmt.Errorf("read component re-attestation time: %w", err)
	}
	affected, err := affectedComponentIDs(ctx, tx, familyID, componentID, isRoot)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := expireComponentTrustAndRefresh(
		ctx, tx, principal.OrganizationID, familyID, affected, now,
	); err != nil {
		return clientComponentDocument{}, err
	}
	if isRoot {
		if err := revokeLegacyRefreshForRenewal(
			ctx, tx, principal.OrganizationID, applicationID, environmentID,
			userID, rootInstallationID, now,
		); err != nil {
			return clientComponentDocument{}, err
		}
	}
	trustChange, err := adminauth.NewPublicAuditChange("reattestation_required", adminauth.AuditSet)
	if err != nil {
		return clientComponentDocument{}, err
	}
	refreshChange, err := adminauth.NewSensitiveAuditChange("refresh_credentials", adminauth.AuditRevoke)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := store.audit(
		ctx, tx, principal, environmentID, "admin.client_component_require_reattestation",
		"client_component", componentID, requestID, now,
		[]adminauth.AuditChange{trustChange, refreshChange},
	); err != nil {
		return clientComponentDocument{}, err
	}
	result, err := queryClientComponent(ctx, tx, principal.OrganizationID, componentID)
	if err != nil {
		return clientComponentDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return clientComponentDocument{}, mapOperationalCommit("commit component re-attestation requirement", err)
	}
	return result, nil
}

func affectedComponentIDs(
	ctx context.Context,
	tx pgx.Tx,
	familyID string,
	componentID string,
	root bool,
) ([]string, error) {
	var rows pgx.Rows
	var err error
	if root {
		rows, err = tx.Query(ctx, `
			SELECT client_component_id
			FROM client_components
			WHERE installation_family_id = $1
			ORDER BY created_at, client_component_id
		`, familyID)
	} else {
		rows, err = tx.Query(ctx, `
			WITH RECURSIVE affected AS (
			    SELECT client_component_id
			    FROM client_components
			    WHERE installation_family_id = $1 AND client_component_id = $2
			    UNION ALL
			    SELECT child.client_component_id
			    FROM client_components AS child
			    JOIN affected AS parent
			      ON child.trust_parent_component_id = parent.client_component_id
			    WHERE child.installation_family_id = $1
			)
			SELECT client_component_id FROM affected ORDER BY client_component_id
		`, familyID, componentID)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve client-component revocation graph: %w", err)
	}
	defer rows.Close()
	components := make([]string, 0, 4)
	for rows.Next() {
		var candidate string
		if err := rows.Scan(&candidate); err != nil {
			return nil, fmt.Errorf("scan client-component revocation graph: %w", err)
		}
		if id.Validate(candidate, id.ClientComponent) != nil {
			return nil, errOperationalCorrupt
		}
		components = append(components, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client-component revocation graph: %w", err)
	}
	if len(components) == 0 || len(components) > maximumFamilyComponents {
		return nil, errOperationalCorrupt
	}
	return components, nil
}

// revokeComponentCredentials revokes a whole family when componentIDs is nil,
// or exactly the supplied component subtree otherwise. It also removes the
// bounded encrypted refresh-rotation cache so revocation cannot retrieve an
// otherwise idempotent credential result.
func revokeComponentCredentials(
	ctx context.Context,
	tx pgx.Tx,
	organizationID string,
	familyID string,
	componentIDs []string,
	now time.Time,
	reason string,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE component_refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4))
		WHERE client_component_id IN (
		    SELECT client_component_id FROM client_components
		    WHERE organization_id = $1 AND installation_family_id = $2
		      AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		) AND status IN ('staged', 'active')
	`, organizationID, familyID, nullableStringSlice(componentIDs), now); err != nil {
		return fmt.Errorf("revoke component refresh credentials: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM refresh_rotation_results
		WHERE client_component_id IN (
		    SELECT client_component_id FROM client_components
		    WHERE organization_id = $1 AND installation_family_id = $2
		      AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		)
	`, organizationID, familyID, nullableStringSlice(componentIDs)); err != nil {
		return fmt.Errorf("remove revoked-component refresh results: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4)),
		    revoke_reason = COALESCE(revoke_reason, $5)
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		  AND revoked_at IS NULL
	`, organizationID, familyID, nullableStringSlice(componentIDs), now, reason); err != nil {
		return fmt.Errorf("revoke component session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE component_session_families
		SET status = 'revoked', updated_at = GREATEST(updated_at, created_at, $4),
		    revoked_at = COALESCE(revoked_at, GREATEST(created_at, $4)),
		    revocation_reason = COALESCE(revocation_reason, $5)
		WHERE installation_family_id = $2
		  AND client_component_id IN (
		      SELECT client_component_id FROM client_components
		      WHERE organization_id = $1 AND installation_family_id = $2
		        AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		  ) AND status = 'active'
	`, organizationID, familyID, nullableStringSlice(componentIDs), now, reason); err != nil {
		return fmt.Errorf("revoke component session families: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE component_delegations
		SET revoked_at = COALESCE(revoked_at, GREATEST(created_at, $4))
		WHERE installation_family_id = $2
		  AND (
		      parent_component_id IN (
		          SELECT client_component_id FROM client_components
		          WHERE organization_id = $1 AND installation_family_id = $2
		            AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		      )
		      OR child_component_id IN (
		          SELECT client_component_id FROM client_components
		          WHERE organization_id = $1 AND installation_family_id = $2
		            AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		      )
		  ) AND revoked_at IS NULL
	`, organizationID, familyID, nullableStringSlice(componentIDs), now); err != nil {
		return fmt.Errorf("revoke component delegations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE component_keys
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(created_at, $4))
		WHERE installation_family_id = $2
		  AND client_component_id IN (
		      SELECT client_component_id FROM client_components
		      WHERE organization_id = $1 AND installation_family_id = $2
		        AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		  ) AND status = 'active'
	`, organizationID, familyID, nullableStringSlice(componentIDs), now); err != nil {
		return fmt.Errorf("revoke component keys: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE client_components
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(created_at, $4)),
		    revocation_reason = COALESCE(revocation_reason, $5),
		    updated_at = GREATEST(updated_at, created_at, $4)
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		  AND status IN ('active', 'suspended')
	`, organizationID, familyID, nullableStringSlice(componentIDs), now, reason); err != nil {
		return fmt.Errorf("revoke client components: %w", err)
	}
	return nil
}

func expireComponentTrustAndRefresh(
	ctx context.Context,
	tx pgx.Tx,
	organizationID string,
	familyID string,
	componentIDs []string,
	now time.Time,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE component_refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $4))
		WHERE client_component_id IN (
		    SELECT client_component_id FROM client_components
		    WHERE organization_id = $1 AND installation_family_id = $2
		      AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		) AND status IN ('staged', 'active')
	`, organizationID, familyID, nullableStringSlice(componentIDs), now); err != nil {
		return fmt.Errorf("expire component refresh credentials: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM refresh_rotation_results
		WHERE client_component_id IN (
		    SELECT client_component_id FROM client_components
		    WHERE organization_id = $1 AND installation_family_id = $2
		      AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		)
	`, organizationID, familyID, nullableStringSlice(componentIDs)); err != nil {
		return fmt.Errorf("remove expired-trust refresh results: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE client_components
		SET trust_expires_at = CASE
		        WHEN trust_expires_at IS NULL THEN
		             GREATEST($4, COALESCE(trust_verified_at, created_at) + interval '1 microsecond')
		        ELSE LEAST(
		             trust_expires_at,
		             GREATEST($4, COALESCE(trust_verified_at, created_at) + interval '1 microsecond')
		        )
		    END,
		    updated_at = GREATEST(updated_at, created_at, $4)
		WHERE organization_id = $1 AND installation_family_id = $2
		  AND ($3::text[] IS NULL OR client_component_id = ANY($3))
		  AND status = 'active'
	`, organizationID, familyID, nullableStringSlice(componentIDs), now); err != nil {
		return fmt.Errorf("expire component trust: %w", err)
	}
	return nil
}

func revokeLegacyRefreshForRenewal(
	ctx context.Context,
	tx pgx.Tx,
	organizationID, applicationID, environmentID, userID, installationID string,
	now time.Time,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $6))
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5
		  AND status IN ('staged', 'active')
	`, organizationID, applicationID, environmentID, userID, installationID, now); err != nil {
		return fmt.Errorf("expire family root refresh credentials: %w", err)
	}
	return nil
}

func revokeLegacyRootCredentials(
	ctx context.Context,
	tx pgx.Tx,
	organizationID, applicationID, environmentID, userID, installationID string,
	now time.Time,
	reason string,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $6)),
		    revoke_reason = COALESCE(revoke_reason, $7)
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5 AND revoked_at IS NULL
	`, organizationID, applicationID, environmentID, userID, installationID, now, reason); err != nil {
		return fmt.Errorf("revoke family root session grants: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(issued_at, $6))
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND application_user_id = $4 AND installation_id = $5
		  AND status IN ('staged', 'active')
	`, organizationID, applicationID, environmentID, userID, installationID, now); err != nil {
		return fmt.Errorf("revoke family root refresh credentials: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE attestation_keys
		SET status = 'revoked', revoked_at = GREATEST(created_at, $5),
		    updated_at = GREATEST(updated_at, created_at, $5)
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND installation_id = $4 AND status <> 'revoked'
	`, organizationID, applicationID, environmentID, installationID, now); err != nil {
		return fmt.Errorf("revoke family root attestation keys: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE installations
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, GREATEST(created_at, $3)),
		    revoke_reason = COALESCE(revoke_reason, $4),
		    updated_at = GREATEST(updated_at, created_at, $3)
		WHERE organization_id = $1 AND installation_id = $2
	`, organizationID, installationID, now, reason); err != nil {
		return fmt.Errorf("revoke family root installation: %w", err)
	}
	return nil
}

func nullableStringSlice(values []string) any {
	if values == nil {
		return nil
	}
	return values
}
