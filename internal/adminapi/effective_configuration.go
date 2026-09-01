package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/protocol"
)

var errEffectiveFeatureNotFound = errors.New("effective configuration feature not found")

type effectiveConfigurationQuery struct {
	EnvironmentID        string
	Feature              string
	InstallationID       string
	ComponentID          string
	Streaming            bool
	EstimatedInputTokens int64
	MaximumOutputTokens  int64
}

type effectiveSubjectDocument struct {
	Kind           string `json:"kind"`
	ID             string `json:"id"`
	UserID         string `json:"user_id"`
	InstallationID string `json:"installation_id,omitempty"`
	ComponentID    string `json:"component_id,omitempty"`
}

type effectiveInputProvenance struct {
	Fact         string            `json:"fact"`
	Source       string            `json:"source"`
	Availability string            `json:"availability"`
	Keys         []string          `json:"keys,omitempty"`
	Values       map[string]string `json:"values,omitempty"`
	Detail       string            `json:"detail"`
}

type effectiveLimitDocument struct {
	Index             int      `json:"index"`
	Metric            string   `json:"metric"`
	Algorithm         string   `json:"algorithm"`
	Scope             []string `json:"scope"`
	Window            string   `json:"window,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`
	Maximum           int64    `json:"maximum,omitempty"`
	PerRequestMaximum int64    `json:"per_request_maximum,omitempty"`
	Capacity          int64    `json:"capacity,omitempty"`
	RefillPerSecond   string   `json:"refill_per_second,omitempty"`
	Hard              bool     `json:"hard"`
	Source            string   `json:"source"`
}

type effectiveRouteDocument struct {
	Order                int      `json:"order"`
	Route                string   `json:"route"`
	Upstream             string   `json:"upstream"`
	Model                string   `json:"model"`
	PhysicalModel        string   `json:"physical_model"`
	MatchExpression      string   `json:"match_expression"`
	ConfiguredPriority   int64    `json:"configured_priority"`
	ConfiguredWeight     int64    `json:"configured_weight"`
	StickyBy             string   `json:"sticky_by,omitempty"`
	FallbackOn           []string `json:"fallback_on"`
	RetryMaximumAttempts int64    `json:"retry_maximum_attempts"`
	RetryOn              []string `json:"retry_on"`
	Source               string   `json:"source"`
	Observed             bool     `json:"observed"`
}

type effectiveOutputDocument struct {
	ConfiguredDefaultMaximumTokens  int64  `json:"configured_default_maximum_tokens,omitempty"`
	ConfiguredAbsoluteMaximumTokens int64  `json:"configured_absolute_maximum_tokens,omitempty"`
	EffectiveDefaultMaximumTokens   int64  `json:"effective_default_maximum_tokens,omitempty"`
	EffectiveMaximumTokens          int64  `json:"effective_maximum_tokens,omitempty"`
	RequestedMaximumTokens          int64  `json:"requested_maximum_tokens,omitempty"`
	Source                          string `json:"source"`
}

type effectiveConfigurationDocument struct {
	Subject                 effectiveSubjectDocument       `json:"subject"`
	EvaluationMode          string                         `json:"evaluation_mode"`
	EnvironmentID           string                         `json:"environment_id"`
	EnvironmentKind         string                         `json:"environment_kind"`
	RevisionID              string                         `json:"revision_id"`
	Feature                 string                         `json:"feature"`
	Protocol                string                         `json:"protocol,omitempty"`
	RequestStatus           string                         `json:"request_status,omitempty"`
	PolicyOutcome           string                         `json:"policy_outcome"`
	DenialReason            string                         `json:"denial_reason,omitempty"`
	MatchedAccessExpression string                         `json:"matched_access_expression,omitempty"`
	MatchedLimitExpression  string                         `json:"matched_limit_plan_expression,omitempty"`
	LimitPlan               string                         `json:"limit_plan,omitempty"`
	LimitPlanSource         string                         `json:"limit_plan_source,omitempty"`
	UserOverrideID          string                         `json:"user_override_id,omitempty"`
	ComponentDefinitionID   string                         `json:"component_definition_id,omitempty"`
	ComponentAllowed        *bool                          `json:"component_allowed,omitempty"`
	Inputs                  []effectiveInputProvenance     `json:"inputs"`
	Output                  *effectiveOutputDocument       `json:"output,omitempty"`
	Limits                  []effectiveLimitDocument       `json:"limits"`
	SelectedRoute           *effectiveRouteDocument        `json:"selected_route,omitempty"`
	Routes                  []effectiveRouteDocument       `json:"routes"`
	DecisionStages          []requestDecisionStageDocument `json:"decision_stages"`
	Warnings                []string                       `json:"warnings"`
}

type effectiveUserBasis struct {
	ApplicationID            string
	EnvironmentID            string
	EnvironmentKind          string
	RevisionID               string
	UserID                   string
	UserStatus               string
	Claims                   map[string]any
	OverrideID               string
	OverridePlan             string
	InstallationID           string
	Platform                 string
	TrustLevel               string
	AttestationProvider      string
	IdentityProvider         string
	InstallationFamilyID     string
	InstallationFamilyStatus string
	ComponentID              string
	ComponentDefinitionID    string
	ComponentKind            string
	ComponentIsRoot          bool
	TrustSource              string
	GrantedFeatures          []string
	SessionAvailable         bool
}

type effectiveRequestBasis struct {
	RequestID             string
	EnvironmentID         string
	RevisionID            string
	UserID                string
	InstallationID        string
	InstallationFamilyID  string
	ComponentID           string
	ComponentDefinitionID string
	ComponentKind         string
	TrustSource           string
	Feature               string
	Protocol              string
	Status                string
	LimitPlan             string
	SelectedRoute         string
	SelectedUpstream      string
	SelectedModel         string
	SelectedPhysicalModel string
	DecisionStages        []requestDecisionStageDocument
	Attempts              []effectiveRequestAttempt
}

type effectiveRequestAttempt struct {
	Order         int
	Route         string
	Upstream      string
	PhysicalModel string
}

func (api *API) effectiveUserConfiguration(w http.ResponseWriter, r *http.Request) {
	query, ok := parseEffectiveConfigurationQuery(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The effective-configuration query is invalid."))
		return
	}
	principal := mustPrincipal(r.Context())
	basis, err := api.operations.effectiveUserBasis(
		r.Context(), principal, query, chi.URLParam(r, "userID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	compiled, err := api.configurations.ExplanationSnapshot(r.Context(), principal, basis.RevisionID)
	if err != nil {
		api.handleEffectiveConfigurationError(w, r, err)
		return
	}
	document, err := api.resolveEffectiveUserConfiguration(r.Context(), compiled, basis, query)
	if err != nil {
		if errors.Is(err, errEffectiveFeatureNotFound) {
			api.writeProblem(w, r, problem.Error{Code: "feature_not_found", Detail: "The active configuration has no feature with this identifier."})
			return
		}
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (api *API) effectiveRequestConfiguration(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The recorded effective-configuration query is invalid."))
		return
	}
	principal := mustPrincipal(r.Context())
	basis, err := api.operations.effectiveRequestBasis(
		r.Context(), principal, chi.URLParam(r, "requestID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	compiled, err := api.configurations.ExplanationSnapshot(r.Context(), principal, basis.RevisionID)
	if err != nil {
		api.handleEffectiveConfigurationError(w, r, err)
		return
	}
	document, err := recordedEffectiveConfiguration(compiled, basis)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func parseEffectiveConfigurationQuery(r *http.Request) (effectiveConfigurationQuery, bool) {
	if !onlyQueryKeys(
		r, "environment_id", "feature", "installation_id", "component_id",
		"streaming", "estimated_input_tokens", "maximum_output_tokens",
	) {
		return effectiveConfigurationQuery{}, false
	}
	environmentID, environmentOK := requiredQueryValue(r, "environment_id")
	feature, featureOK := requiredQueryValue(r, "feature")
	installationID, installationOK := optionalQueryValue(r, "installation_id")
	componentID, componentOK := optionalQueryValue(r, "component_id")
	if !environmentOK || !featureOK || !installationOK || !componentOK {
		return effectiveConfigurationQuery{}, false
	}
	result := effectiveConfigurationQuery{
		EnvironmentID: environmentID, Feature: feature,
		InstallationID: installationID, ComponentID: componentID,
	}
	if id.Validate(result.EnvironmentID, id.Environment) != nil ||
		!operationalIdentifierPattern.MatchString(result.Feature) ||
		(result.InstallationID != "" && id.Validate(result.InstallationID, id.Installation) != nil) ||
		(result.ComponentID != "" && id.Validate(result.ComponentID, id.ClientComponent) != nil) ||
		(result.InstallationID != "" && result.ComponentID != "") {
		return effectiveConfigurationQuery{}, false
	}
	var ok bool
	if result.Streaming, ok = optionalEffectiveBool(r, "streaming"); !ok {
		return effectiveConfigurationQuery{}, false
	}
	if result.EstimatedInputTokens, ok = optionalEffectiveInt64(r, "estimated_input_tokens"); !ok {
		return effectiveConfigurationQuery{}, false
	}
	if result.MaximumOutputTokens, ok = optionalEffectiveInt64(r, "maximum_output_tokens"); !ok {
		return effectiveConfigurationQuery{}, false
	}
	return result, true
}

func optionalEffectiveBool(r *http.Request, name string) (bool, bool) {
	values, exists := r.URL.Query()[name]
	if !exists {
		return false, true
	}
	raw, ok := exactQueryValue(values, true)
	if !ok || raw == "" {
		return false, false
	}
	value, err := strconv.ParseBool(raw)
	return value, err == nil
}

func optionalEffectiveInt64(r *http.Request, name string) (int64, bool) {
	values, exists := r.URL.Query()[name]
	if !exists {
		return 0, true
	}
	raw, ok := exactQueryValue(values, true)
	if !ok || raw == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	return value, err == nil && value >= 0 && value <= protocol.MaximumPolicyRequestTokens
}

func (store *operationalStore) effectiveUserBasis(
	ctx context.Context,
	principal adminauth.Principal,
	query effectiveConfigurationQuery,
	userID string,
) (effectiveUserBasis, error) {
	if !validOperationalRead(principal) || id.Validate(userID, id.ApplicationUser) != nil {
		if id.Validate(userID, id.ApplicationUser) != nil {
			return effectiveUserBasis{}, errOperationalInvalid
		}
		return effectiveUserBasis{}, errOperationalForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return effectiveUserBasis{}, fmt.Errorf("begin effective user snapshot: %w", err)
	}
	defer rollbackOperational(tx)
	user, err := queryApplicationUser(ctx, tx, principal.OrganizationID, query.EnvironmentID, userID)
	if err != nil {
		return effectiveUserBasis{}, err
	}
	result := effectiveUserBasis{
		EnvironmentID: query.EnvironmentID, UserID: user.ID, UserStatus: user.Status,
		Claims: user.NormalizedClaims,
	}
	if user.LimitPlanOverride != nil {
		result.OverrideID = user.LimitPlanOverride.ID
		result.OverridePlan = user.LimitPlanOverride.LimitPlan
	}
	if err := tx.QueryRow(ctx, `
		SELECT environment.application_id, environment.kind, active.config_revision_id
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		JOIN active_config_revisions AS active
		  ON active.environment_id = environment.environment_id
		WHERE environment.organization_id = $1 AND environment.environment_id = $2
		  AND environment.status = 'active' AND application.status = 'active'
		  AND organization.status = 'active'
	`, principal.OrganizationID, query.EnvironmentID).Scan(
		&result.ApplicationID, &result.EnvironmentKind, &result.RevisionID,
	); errors.Is(err, pgx.ErrNoRows) {
		return effectiveUserBasis{}, errOperationalNotFound
	} else if err != nil {
		return effectiveUserBasis{}, fmt.Errorf("load effective user revision: %w", err)
	}

	var claimsJSON []byte
	var familyID, familyStatus, componentID, definitionID, componentKind, trustSource *string
	var componentIsRoot *bool
	var grantedFeaturesJSON []byte
	err = tx.QueryRow(ctx, `
		SELECT grant.installation_id, installation.platform, grant.trust_level,
		       grant.attestation_provider, grant.identity_provider_key,
		       grant.installation_family_id, family.status,
		       grant.client_component_id, grant.component_definition_id,
		       grant.component_kind, grant.component_is_root, grant.trust_source,
		       COALESCE(component.granted_features, '[]'::jsonb), users.normalized_claims
		FROM session_grants AS grant
		JOIN installations AS installation
		  ON installation.organization_id = grant.organization_id
		 AND installation.application_id = grant.application_id
		 AND installation.environment_id = grant.environment_id
		 AND installation.installation_id = grant.installation_id
		JOIN application_users AS users
		  ON users.organization_id = grant.organization_id
		 AND users.application_id = grant.application_id
		 AND users.application_user_id = grant.application_user_id
		LEFT JOIN installation_families AS family
		  ON family.installation_family_id = grant.installation_family_id
		LEFT JOIN client_components AS component
		  ON component.client_component_id = grant.client_component_id
		WHERE grant.organization_id = $1 AND grant.application_id = $2
		  AND grant.environment_id = $3 AND grant.application_user_id = $4
		  AND grant.policy_revision_id = $5 AND grant.revoked_at IS NULL
		  AND grant.identity_provider_key IS NOT NULL
		  AND grant.expires_at > transaction_timestamp()
		  AND grant.identity_expires_at > transaction_timestamp()
		  AND grant.attestation_expires_at > transaction_timestamp()
		  AND installation.status = 'active' AND users.status = 'active'
		  AND ($6::text IS NULL OR grant.installation_id = $6)
		  AND ($7::text IS NULL OR grant.client_component_id = $7)
		  AND (grant.installation_family_id IS NULL OR family.status = 'active')
		  AND (grant.client_component_id IS NULL OR component.status = 'active')
		ORDER BY grant.issued_at DESC, grant.session_grant_id DESC
		LIMIT 1
	`, principal.OrganizationID, result.ApplicationID, query.EnvironmentID, userID,
		result.RevisionID, nullableString(query.InstallationID), nullableString(query.ComponentID)).Scan(
		&result.InstallationID, &result.Platform, &result.TrustLevel,
		&result.AttestationProvider, &result.IdentityProvider,
		&familyID, &familyStatus, &componentID, &definitionID, &componentKind,
		&componentIsRoot, &trustSource, &grantedFeaturesJSON, &claimsJSON,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return effectiveUserBasis{}, fmt.Errorf("commit effective user snapshot: %w", commitErr)
		}
		return result, nil
	}
	if err != nil {
		return effectiveUserBasis{}, fmt.Errorf("load effective user session: %w", err)
	}
	claims, err := decodeNormalizedClaims(claimsJSON)
	if err != nil {
		return effectiveUserBasis{}, err
	}
	result.Claims = claims
	if componentID != nil || familyID != nil || definitionID != nil || componentKind != nil || componentIsRoot != nil || trustSource != nil {
		if componentID == nil || familyID == nil || familyStatus == nil || definitionID == nil ||
			componentKind == nil || componentIsRoot == nil || trustSource == nil {
			return effectiveUserBasis{}, errOperationalCorrupt
		}
		result.InstallationFamilyID = *familyID
		result.InstallationFamilyStatus = *familyStatus
		result.ComponentID = *componentID
		result.ComponentDefinitionID = *definitionID
		result.ComponentKind = *componentKind
		result.ComponentIsRoot = *componentIsRoot
		result.TrustSource = *trustSource
		if err := decodeIdentifierArray(grantedFeaturesJSON, &result.GrantedFeatures, maximumGrantedFeatures); err != nil {
			return effectiveUserBasis{}, errOperationalCorrupt
		}
	}
	result.SessionAvailable = true
	if err := tx.Commit(ctx); err != nil {
		return effectiveUserBasis{}, fmt.Errorf("commit effective user snapshot: %w", err)
	}
	return result, nil
}

func (store *operationalStore) effectiveRequestBasis(
	ctx context.Context,
	principal adminauth.Principal,
	requestID string,
) (effectiveRequestBasis, error) {
	request, err := store.getRequest(ctx, principal, requestID)
	if err != nil {
		return effectiveRequestBasis{}, err
	}
	result := effectiveRequestBasis{
		RequestID: request.ID, EnvironmentID: request.EnvironmentID,
		RevisionID: request.ConfigRevisionID, UserID: request.UserID,
		InstallationID: request.InstallationID, Feature: request.Feature,
		Protocol: request.Protocol, Status: request.Status,
		LimitPlan:      request.SelectedLimitPlan,
		DecisionStages: append([]requestDecisionStageDocument(nil), request.DecisionStages...),
		Attempts:       make([]effectiveRequestAttempt, 0, len(request.Attempts)),
	}
	if request.InstallationFamilyID != nil {
		result.InstallationFamilyID = *request.InstallationFamilyID
		result.ComponentID = *request.ClientComponentID
		result.ComponentDefinitionID = *request.ComponentDefinitionID
		result.ComponentKind = *request.ComponentKind
		result.TrustSource = *request.TrustSource
	}
	if request.SelectedRoute != nil {
		result.SelectedRoute = *request.SelectedRoute
		result.SelectedUpstream = *request.SelectedUpstream
		result.SelectedModel = *request.SelectedModel
		result.SelectedPhysicalModel = *request.SelectedPhysicalModel
	}
	for _, attempt := range request.Attempts {
		result.Attempts = append(result.Attempts, effectiveRequestAttempt{
			Order: int(attempt.AttemptNumber), Route: attempt.Route,
			Upstream: attempt.Upstream, PhysicalModel: attempt.Model,
		})
	}
	return result, nil
}

func (api *API) resolveEffectiveUserConfiguration(
	ctx context.Context,
	compiled configuration.SimulationSnapshot,
	basis effectiveUserBasis,
	query effectiveConfigurationQuery,
) (effectiveConfigurationDocument, error) {
	document, _, err := baseEffectiveConfiguration(compiled, effectiveSubjectDocument{
		Kind: "user", ID: basis.UserID, UserID: basis.UserID,
		InstallationID: basis.InstallationID, ComponentID: basis.ComponentID,
	}, "current_user_projection", query.Feature)
	if err != nil {
		return effectiveConfigurationDocument{}, err
	}
	claimKeys := sortedMapKeys(basis.Claims)
	document.Inputs = []effectiveInputProvenance{
		{Fact: "environment", Source: "active_configuration_pointer", Availability: "available", Values: map[string]string{"kind": basis.EnvironmentKind}, Detail: "The environment kind and revision are authoritative database state."},
		{Fact: "normalized_claims", Source: "current_application_user", Availability: "available", Keys: claimKeys, Detail: "Only normalized claim keys are shown here; values are omitted from this explanation."},
		{Fact: "request_shape", Source: "effective_configuration_query", Availability: "available", Values: map[string]string{"streaming": strconv.FormatBool(query.Streaming), "estimated_input_tokens": strconv.FormatInt(query.EstimatedInputTokens, 10), "maximum_output_tokens": strconv.FormatInt(query.MaximumOutputTokens, 10)}, Detail: "Streaming and bounded token facts are explicit inspector assumptions."},
	}
	if basis.OverrideID != "" {
		document.Inputs = append(document.Inputs, effectiveInputProvenance{
			Fact: "limit_plan_override", Source: basis.OverrideID, Availability: "available",
			Detail: "The active server-owned user override supersedes the feature limit-plan expression.",
		})
	}
	if !basis.SessionAvailable {
		document.PolicyOutcome = "unavailable"
		document.DenialReason = "no_active_session"
		document.Warnings = append(document.Warnings,
			"No unexpired, unrevoked session for this user and selected surface is bound to the active revision; Latchway will not invent trust or routing facts.",
		)
		return document, nil
	}
	document.Inputs = append(document.Inputs,
		effectiveInputProvenance{Fact: "client_trust", Source: "current_session_and_component_state", Availability: "available", Values: map[string]string{"platform": basis.Platform, "trust_level": basis.TrustLevel, "attestation_provider": basis.AttestationProvider, "identity_provider": basis.IdentityProvider, "installation_family_status": basis.InstallationFamilyStatus, "component_kind": basis.ComponentKind, "trust_source": basis.TrustSource}, Detail: "Platform, trust level, attestation provider, and component provenance are loaded from durable server state."},
	)
	if basis.ComponentID != "" {
		allowed := slices.Contains(basis.GrantedFeatures, query.Feature)
		document.ComponentAllowed = &allowed
		document.ComponentDefinitionID = basis.ComponentDefinitionID
		if !allowed {
			document.PolicyOutcome = "denied"
			document.DenialReason = "component_feature_not_granted"
			return document, nil
		}
	}
	input, err := policy.NewSimulationInput(policy.SimulationFacts{
		OrganizationID: compiled.Scope.OrganizationID, ApplicationID: compiled.Scope.ApplicationID,
		EnvironmentID: compiled.Scope.EnvironmentID, EnvironmentKind: compiled.EnvironmentKind,
		PolicyRevisionID: compiled.Snapshot.PolicyRevision(), UserOverrideID: basis.OverrideID,
		LimitPlanOverride: basis.OverridePlan, ApplicationUserID: basis.UserID,
		InstallationID: basis.InstallationID, InstallationFamilyID: basis.InstallationFamilyID,
		InstallationFamilyStatus: basis.InstallationFamilyStatus, ComponentID: basis.ComponentID,
		ComponentDefinitionID: basis.ComponentDefinitionID, ComponentKind: basis.ComponentKind,
		ComponentIsRoot: basis.ComponentIsRoot, TrustSource: basis.TrustSource,
		LogicalRequestID: simulationRequestID, InstallationPlatform: basis.Platform,
		IdentityProvider: basis.IdentityProvider, TrustLevel: basis.TrustLevel,
		AttestationProvider: basis.AttestationProvider, Authenticated: true,
		NormalizedClaims: basis.Claims, Streaming: query.Streaming,
		EstimatedInputTokens: query.EstimatedInputTokens, MaximumOutputTokens: query.MaximumOutputTokens,
		EvaluatedAt: time.Now().UTC(),
	})
	if err != nil {
		return effectiveConfigurationDocument{}, fmt.Errorf("construct effective user policy input: %w", err)
	}
	plan, err := api.policyResolver.ResolvePlan(ctx, compiled.Snapshot, query.Feature, input)
	if err != nil {
		if detail, denied := simulationDenial(err); denied {
			document.PolicyOutcome = "denied"
			document.DenialReason = effectiveDenialReason(err)
			document.Warnings = append(document.Warnings, detail)
			return document, nil
		}
		return effectiveConfigurationDocument{}, fmt.Errorf("resolve effective user policy: %w", err)
	}
	document.PolicyOutcome = "allowed"
	document.LimitPlan = plan.LimitPlan.ID
	document.LimitPlanSource = "feature_limit_plan_expression"
	if basis.OverrideID != "" {
		document.LimitPlanSource = "user_override"
		document.UserOverrideID = basis.OverrideID
	}
	document.Limits = effectiveLimits(plan.LimitPlan)
	applyEffectiveOutput(&document, plan.LimitPlan, query.MaximumOutputTokens)
	document.Routes = effectiveRoutes(plan.Candidates)
	if len(document.Routes) > 0 {
		selected := document.Routes[0]
		document.SelectedRoute = &selected
	}
	document.Warnings = append(document.Warnings,
		"This current-state projection uses the exact production CEL and route resolver but performs no quota reservation or upstream dispatch.",
		"Request-scoped sticky routing uses a stable synthetic request identity; inspect a recorded request for its observed route.",
	)
	return document, nil
}

func recordedEffectiveConfiguration(
	compiled configuration.SimulationSnapshot,
	basis effectiveRequestBasis,
) (effectiveConfigurationDocument, error) {
	document, feature, err := baseEffectiveConfiguration(compiled, effectiveSubjectDocument{
		Kind: "request", ID: basis.RequestID, UserID: basis.UserID,
		InstallationID: basis.InstallationID, ComponentID: basis.ComponentID,
	}, "recorded_request", basis.Feature)
	if err != nil {
		return effectiveConfigurationDocument{}, err
	}
	document.EnvironmentID = basis.EnvironmentID
	document.Protocol = basis.Protocol
	document.RequestStatus = basis.Status
	document.ComponentDefinitionID = basis.ComponentDefinitionID
	document.DecisionStages = append([]requestDecisionStageDocument(nil), basis.DecisionStages...)
	selectedPlanAvailability := "available"
	if basis.LimitPlan == "legacy_unknown" {
		selectedPlanAvailability = "unavailable"
	}
	routingAvailability := "available"
	if basis.SelectedRoute == "" {
		routingAvailability = "unavailable"
	}
	document.Inputs = []effectiveInputProvenance{
		{Fact: "revision", Source: basis.RevisionID, Availability: "available", Detail: "The immutable revision ID is recorded on the logical request."},
		{Fact: "selected_limit_plan", Source: "logical_request", Availability: selectedPlanAvailability, Detail: "The selected plan is durable request provenance; legacy_unknown means it was not recorded."},
		{Fact: "normalized_claims", Source: "historical_request", Availability: "unavailable", Detail: "Historical claim values and override identity were not persisted; this endpoint does not infer them from current user state."},
		{Fact: "client_context", Source: "logical_request", Availability: "available", Values: map[string]string{"component_kind": basis.ComponentKind, "trust_source": basis.TrustSource}, Detail: "Durable user, installation, family, component, and trust-source attribution is shown without proofs or credentials."},
		{Fact: "decision_lifecycle", Source: "logical_request_decision_stages", Availability: "available", Detail: "Append-only policy, quota, and routing stages contain only bounded identifiers, public failure codes, limits, and timing."},
		{Fact: "routing", Source: "logical_request_and_upstream_attempts", Availability: routingAvailability, Detail: "The selected route and observed attempts are durable; provider bodies and credentials remain excluded."},
	}
	if basis.SelectedRoute != "" {
		route, routeFound := configuredFeatureRoute(feature, basis.SelectedRoute)
		model, modelFound := compiled.Snapshot.Model(basis.SelectedModel)
		if !routeFound || !modelFound || route.ModelID != model.ID ||
			model.UpstreamID != basis.SelectedUpstream || model.UpstreamModel != basis.SelectedPhysicalModel {
			return effectiveConfigurationDocument{}, fmt.Errorf("recorded selected route provenance is inconsistent")
		}
		selected := configuredEffectiveRoute(1, route, model, "logical_request.selected_route", false)
		document.SelectedRoute = &selected
	} else {
		document.Warnings = append(document.Warnings,
			"This request predates durable pre-dispatch route selection or ended before route selection; no route is inferred.",
		)
	}
	for _, attempt := range basis.Attempts {
		route, routeFound := configuredFeatureRoute(feature, attempt.Route)
		if !routeFound {
			return effectiveConfigurationDocument{}, fmt.Errorf("recorded request route provenance is inconsistent")
		}
		model, modelFound := compiled.Snapshot.Model(route.ModelID)
		if !modelFound || model.UpstreamID != attempt.Upstream || model.UpstreamModel != attempt.PhysicalModel {
			return effectiveConfigurationDocument{}, fmt.Errorf("recorded request route provenance is inconsistent")
		}
		document.Routes = append(document.Routes,
			configuredEffectiveRoute(attempt.Order, route, model, "upstream_attempt", true),
		)
	}
	for _, stage := range basis.DecisionStages {
		if stage.Stage != "policy_evaluated" {
			continue
		}
		switch stage.Outcome {
		case "succeeded":
			document.PolicyOutcome = "allowed"
		case "denied":
			document.PolicyOutcome = "denied"
			if stage.FailureCode != nil {
				document.DenialReason = *stage.FailureCode
			}
		default:
			document.PolicyOutcome = "unavailable"
		}
		break
	}
	plan, found := compiled.Snapshot.LimitPlan(basis.LimitPlan)
	if !found {
		if document.PolicyOutcome == "unavailable" {
			document.DenialReason = "selection_not_recorded"
		}
		document.Warnings = append(document.Warnings,
			"This request predates exact selected-plan provenance or was denied before plan selection; no plan is inferred.",
		)
		return document, nil
	}
	if document.PolicyOutcome == "unavailable" {
		document.PolicyOutcome = "allowed"
	}
	document.LimitPlan = plan.ID
	document.LimitPlanSource = "durable_request_record"
	document.Limits = effectiveLimits(plan)
	applyEffectiveOutput(&document, plan, 0)
	document.Warnings = append(document.Warnings,
		"The recorded plan and attempts are exact historical provenance; historical claim values and user-override identity are intentionally unavailable.",
	)
	return document, nil
}

func baseEffectiveConfiguration(
	compiled configuration.SimulationSnapshot,
	subject effectiveSubjectDocument,
	mode string,
	featureID string,
) (effectiveConfigurationDocument, configuration.Feature, error) {
	feature, found := compiled.Snapshot.Feature(featureID)
	if !found {
		return effectiveConfigurationDocument{}, configuration.Feature{}, errEffectiveFeatureNotFound
	}
	document := effectiveConfigurationDocument{
		Subject: subject, EvaluationMode: mode, EnvironmentID: compiled.Scope.EnvironmentID,
		EnvironmentKind: compiled.EnvironmentKind, RevisionID: compiled.Snapshot.PolicyRevision(),
		Feature: feature.ID, Protocol: feature.Protocol, PolicyOutcome: "unavailable",
		MatchedAccessExpression: feature.AccessExpression,
		MatchedLimitExpression:  feature.LimitPlanExpression,
		Limits:                  []effectiveLimitDocument{}, Routes: []effectiveRouteDocument{},
		DecisionStages: []requestDecisionStageDocument{}, Warnings: []string{},
	}
	if feature.Output != nil {
		document.Output = &effectiveOutputDocument{
			ConfiguredDefaultMaximumTokens:  feature.Output.DefaultMaximumTokens,
			ConfiguredAbsoluteMaximumTokens: feature.Output.AbsoluteMaximumTokens,
			EffectiveDefaultMaximumTokens:   feature.Output.DefaultMaximumTokens,
			EffectiveMaximumTokens:          feature.Output.AbsoluteMaximumTokens,
			Source:                          "feature.output",
		}
	}
	return document, feature, nil
}

func effectiveLimits(plan configuration.LimitPlan) []effectiveLimitDocument {
	result := make([]effectiveLimitDocument, 0, len(plan.Limits))
	for index, limit := range plan.Limits {
		document := effectiveLimitDocument{
			Index: index, Metric: limit.Metric, Algorithm: limit.Algorithm,
			Scope: cloneEffectiveStrings(limit.Scope), Hard: limit.Hard,
			Source: fmt.Sprintf("limitPlans.%s.limits.%d", plan.ID, index),
		}
		switch limit.Algorithm {
		case "calendar":
			document.Window = limit.Window
			document.Timezone = limit.Timezone
			document.Maximum = limit.Maximum
		case "token_bucket":
			document.Capacity = limit.Capacity
			document.RefillPerSecond = limit.RefillPerSecond.String()
		case "per_request":
			document.PerRequestMaximum = limit.PerRequestMaximum
		case "concurrency":
			document.Maximum = limit.Maximum
		}
		result = append(result, document)
	}
	return result
}

func applyEffectiveOutput(document *effectiveConfigurationDocument, plan configuration.LimitPlan, requested int64) {
	if document == nil || document.Output == nil {
		return
	}
	effectiveMaximum := document.Output.ConfiguredAbsoluteMaximumTokens
	for _, limit := range plan.Limits {
		if limit.Metric != "output_tokens" {
			continue
		}
		candidate := int64(0)
		switch limit.Algorithm {
		case "per_request":
			candidate = limit.PerRequestMaximum
		case "token_bucket":
			candidate = limit.Capacity
		}
		if candidate > 0 && candidate < effectiveMaximum {
			effectiveMaximum = candidate
		}
	}
	document.Output.EffectiveMaximumTokens = effectiveMaximum
	document.Output.EffectiveDefaultMaximumTokens = document.Output.ConfiguredDefaultMaximumTokens
	if document.Output.EffectiveDefaultMaximumTokens > effectiveMaximum {
		document.Output.EffectiveDefaultMaximumTokens = effectiveMaximum
	}
	document.Output.RequestedMaximumTokens = requested
	document.Output.Source = fmt.Sprintf("feature.output + limitPlans.%s.limits", plan.ID)
}

func effectiveRoutes(candidates []policy.RouteDecision) []effectiveRouteDocument {
	result := make([]effectiveRouteDocument, 0, len(candidates))
	for index, candidate := range candidates {
		result = append(result, configuredEffectiveRoute(
			index+1, candidate.Route, candidate.Model,
			fmt.Sprintf("feature.routes.%s", candidate.Route.ID), false,
		))
	}
	return result
}

func configuredEffectiveRoute(
	order int,
	route configuration.Route,
	model configuration.Model,
	source string,
	observed bool,
) effectiveRouteDocument {
	return effectiveRouteDocument{
		Order: order, Route: route.ID, Upstream: model.UpstreamID,
		Model: model.ID, PhysicalModel: model.UpstreamModel,
		MatchExpression:    route.When,
		ConfiguredPriority: route.Priority, ConfiguredWeight: route.Weight,
		StickyBy:             route.StickyBy,
		FallbackOn:           cloneEffectiveStrings(route.FallbackOn),
		RetryMaximumAttempts: routeRetryMaximumAttempts(route),
		RetryOn:              cloneEffectiveStrings(routeRetryOn(route)),
		Source:               source, Observed: observed,
	}
}

func routeRetryMaximumAttempts(route configuration.Route) int64 {
	if route.RetryPolicy == nil {
		return 1
	}
	return route.RetryPolicy.MaxAttempts
}

func routeRetryOn(route configuration.Route) []string {
	if route.RetryPolicy == nil {
		return []string{}
	}
	return route.RetryPolicy.RetryOn
}

func cloneEffectiveStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func configuredFeatureRoute(feature configuration.Feature, routeID string) (configuration.Route, bool) {
	for _, route := range feature.Routes {
		if route.ID == routeID {
			return route, true
		}
	}
	return configuration.Route{}, false
}

func sortedMapKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func decodeIdentifierArray(encoded []byte, target *[]string, maximum int) error {
	var values []string
	if len(encoded) == 0 || len(encoded) > 64<<10 || json.Unmarshal(encoded, &values) != nil ||
		len(values) > maximum {
		return errOperationalCorrupt
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !operationalIdentifierPattern.MatchString(value) {
			return errOperationalCorrupt
		}
		if _, exists := seen[value]; exists {
			return errOperationalCorrupt
		}
		seen[value] = struct{}{}
	}
	*target = append([]string(nil), values...)
	return nil
}

func effectiveDenialReason(err error) string {
	switch {
	case errors.Is(err, policy.ErrFeatureNotAllowed):
		return "access_expression_denied"
	case errors.Is(err, policy.ErrLimitPlanNotFound):
		return "limit_plan_unavailable"
	case errors.Is(err, policy.ErrRouteNotFound):
		return "route_unavailable"
	default:
		return "trust_requirement_not_satisfied"
	}
}

func (api *API) handleEffectiveConfigurationError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, configuration.ErrForbidden) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot inspect effective configuration."})
		return
	}
	api.handleConfigurationError(w, r, err)
}
