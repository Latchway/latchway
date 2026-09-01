package quota

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

const (
	staleAuthenticatedRequestAge = 24 * time.Hour

	DecisionIdentityVerified       = "identity_verified"
	DecisionClientTrustVerified    = "client_trust_verified"
	DecisionClientContextValidated = "client_context_validated"
	DecisionConfigurationLoaded    = "configuration_loaded"
	DecisionRequestInspected       = "request_inspected"
	DecisionPolicyEvaluated        = "policy_evaluated"
	DecisionRouteSelected          = "route_selected"
	DecisionQuotaRuleEvaluated     = "quota_rule_evaluated"
	DecisionQuotaReserved          = "quota_reserved"
	DecisionLifecycleRecovered     = "lifecycle_recovered"

	DecisionSucceeded = "succeeded"
	DecisionDenied    = "denied"
	DecisionFailed    = "failed"
	DecisionCancelled = "cancelled"
)

var allowedDecisionStages = []string{
	DecisionIdentityVerified,
	DecisionClientTrustVerified,
	DecisionClientContextValidated,
	DecisionConfigurationLoaded,
	DecisionRequestInspected,
	DecisionPolicyEvaluated,
	DecisionRouteSelected,
	DecisionQuotaRuleEvaluated,
	DecisionQuotaReserved,
	DecisionLifecycleRecovered,
}

var allowedDecisionOutcomes = []string{
	DecisionSucceeded, DecisionDenied, DecisionFailed, DecisionCancelled,
}

var (
	decisionRuleKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	decisionMetricPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// AuthenticatedRequestInput is the redaction-safe identity available only
// after both the access token and request-bound DPoP proof have succeeded.
// Provider payloads, identity subjects, claims, proofs, and credentials have
// no representation in this type.
type AuthenticatedRequestInput struct {
	LogicalRequestID requestidentity.LogicalID

	OrganizationID        string
	ApplicationID         string
	EnvironmentID         string
	ApplicationUserID     string
	InstallationID        string
	InstallationFamilyID  string
	ClientComponentID     string
	ComponentDefinitionID string
	ComponentKind         string
	TrustSource           string
	SessionGrantID        string
	ConfigRevisionID      string

	FeatureKey       string
	Protocol         string
	ClientRequestID  string
	Framework        string
	FrameworkVersion string
}

// AuthenticatedRequest is an opaque handle for one already-bound logical
// request. Only Store can construct a non-zero handle.
type AuthenticatedRequest struct {
	organizationID   string
	applicationID    string
	environmentID    string
	logicalRequestID string
	configRevisionID string
}

func (request AuthenticatedRequest) LogicalRequestID() string { return request.logicalRequestID }

// DecisionStage contains a closed stage/outcome and bounded provenance only.
// A non-success outcome is terminal before quota reservation and must carry
// the exact public problem code returned to the client.
type DecisionStage struct {
	Stage       string
	Outcome     string
	FailureCode string
	StartedAt   time.Time
	CompletedAt time.Time

	PolicyRuleKey   string
	LimitPlanKey    string
	LimitRuleKey    string
	LimitMetric     string
	LimitAlgorithm  string
	LimitMaximum    int64
	HasLimitMaximum bool

	RouteKey      string
	UpstreamKey   string
	ModelKey      string
	PhysicalModel string
}

func prepareAuthenticatedRequest(input AuthenticatedRequestInput) (AuthenticatedRequestInput, error) {
	if id.Validate(input.LogicalRequestID.String(), id.LogicalRequest) != nil ||
		id.Validate(input.OrganizationID, id.Organization) != nil ||
		id.Validate(input.ApplicationID, id.Application) != nil ||
		id.Validate(input.EnvironmentID, id.Environment) != nil ||
		id.Validate(input.ApplicationUserID, id.ApplicationUser) != nil ||
		id.Validate(input.InstallationID, id.Installation) != nil ||
		id.Validate(input.SessionGrantID, id.SessionGrant) != nil ||
		id.Validate(input.ConfigRevisionID, id.ConfigRevision) != nil ||
		!validComponentAttribution(
			input.InstallationFamilyID, input.ClientComponentID,
			input.ComponentDefinitionID, input.ComponentKind, input.TrustSource,
		) || !validFrameworkAttribution(input.Framework, input.FrameworkVersion) ||
		!identifierPattern.MatchString(input.FeatureKey) ||
		!slices.Contains(allowedProtocolValues, input.Protocol) ||
		(input.ClientRequestID != "" &&
			(len(input.ClientRequestID) < 8 || len(input.ClientRequestID) > 128 ||
				!clientRequestPattern.MatchString(input.ClientRequestID))) {
		return AuthenticatedRequestInput{}, ErrInvalidInput
	}
	return input, nil
}

func authenticatedRequestHandle(input AuthenticatedRequestInput) AuthenticatedRequest {
	return AuthenticatedRequest{
		organizationID: input.OrganizationID, applicationID: input.ApplicationID,
		environmentID:    input.EnvironmentID,
		logicalRequestID: input.LogicalRequestID.String(),
		configRevisionID: input.ConfigRevisionID,
	}
}

// BeginAuthenticatedRequest creates the logical row before any post-auth
// validation, configuration lookup, request inspection, policy evaluation, or
// quota reservation. An exact replay is idempotent; an identity collision
// fails closed.
func (store *Store) BeginAuthenticatedRequest(
	ctx context.Context,
	input AuthenticatedRequestInput,
) (AuthenticatedRequest, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return AuthenticatedRequest{}, ErrInvalidInput
	}
	prepared, err := prepareAuthenticatedRequest(input)
	if err != nil {
		return AuthenticatedRequest{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return AuthenticatedRequest{}, persistenceFailure("begin authenticated request", err)
	}
	defer rollback(tx)
	requestedAt, err := transactionTime(ctx, tx)
	if err != nil {
		return AuthenticatedRequest{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id, organization_id, application_id, environment_id,
			application_user_id, installation_id,
			installation_family_id, client_component_id, component_definition_id,
			component_kind, trust_source, session_grant_id,
			config_revision_id, feature_key, selected_limit_plan_key,
			protocol, client_request_id, framework, framework_version,
			status, requested_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			$12, $13, $14, 'legacy_unknown', $15, $16, $17, $18,
			'authenticated', $19
		)
		ON CONFLICT DO NOTHING
	`, prepared.LogicalRequestID.String(), prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, prepared.ApplicationUserID, prepared.InstallationID,
		nullableString(prepared.InstallationFamilyID), nullableString(prepared.ClientComponentID),
		nullableString(prepared.ComponentDefinitionID), nullableString(prepared.ComponentKind),
		nullableString(prepared.TrustSource), prepared.SessionGrantID, prepared.ConfigRevisionID,
		prepared.FeatureKey, prepared.Protocol, nullableString(prepared.ClientRequestID),
		nullableString(prepared.Framework), nullableString(prepared.FrameworkVersion), requestedAt)
	if err != nil {
		return AuthenticatedRequest{}, mapWriteError("insert authenticated logical request", err)
	}
	if command.RowsAffected() == 0 {
		if err := validateExistingAuthenticatedRequest(ctx, tx, prepared); err != nil {
			return AuthenticatedRequest{}, err
		}
	} else if command.RowsAffected() != 1 {
		return AuthenticatedRequest{}, ErrInvalidState
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthenticatedRequest{}, persistenceFailure("commit authenticated request", err)
	}
	return authenticatedRequestHandle(prepared), nil
}

func validateExistingAuthenticatedRequest(
	ctx context.Context,
	tx pgx.Tx,
	input AuthenticatedRequestInput,
) error {
	var organizationID, applicationID, environmentID, userID, installationID string
	var sessionGrantID, revisionID, feature, requestProtocol string
	var familyID, componentID, definitionID, componentKind, trustSource *string
	var clientRequestID, framework, frameworkVersion *string
	err := tx.QueryRow(ctx, `
		SELECT organization_id, application_id, environment_id,
		       application_user_id, installation_id,
		       installation_family_id, client_component_id,
		       component_definition_id, component_kind, trust_source,
		       session_grant_id, config_revision_id, feature_key, protocol,
		       client_request_id, framework, framework_version
		FROM logical_requests
		WHERE logical_request_id = $1
	`, input.LogicalRequestID.String()).Scan(
		&organizationID, &applicationID, &environmentID, &userID, &installationID,
		&familyID, &componentID, &definitionID, &componentKind, &trustSource,
		&sessionGrantID, &revisionID, &feature, &requestProtocol,
		&clientRequestID, &framework, &frameworkVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidState
	}
	if err != nil {
		return persistenceFailure("read existing authenticated request", err)
	}
	if organizationID != input.OrganizationID || applicationID != input.ApplicationID ||
		environmentID != input.EnvironmentID || userID != input.ApplicationUserID ||
		installationID != input.InstallationID || sessionGrantID != input.SessionGrantID ||
		revisionID != input.ConfigRevisionID || feature != input.FeatureKey ||
		requestProtocol != input.Protocol ||
		!nullableStringMatches(familyID, input.InstallationFamilyID) ||
		!nullableStringMatches(componentID, input.ClientComponentID) ||
		!nullableStringMatches(definitionID, input.ComponentDefinitionID) ||
		!nullableStringMatches(componentKind, input.ComponentKind) ||
		!nullableStringMatches(trustSource, input.TrustSource) ||
		!nullableStringMatches(clientRequestID, input.ClientRequestID) ||
		!nullableStringMatches(framework, input.Framework) ||
		!nullableStringMatches(frameworkVersion, input.FrameworkVersion) {
		return ErrInvalidInput
	}
	return nil
}

// claimAuthenticatedRequest advances the pre-reservation row created by
// BeginAuthenticatedRequest. The logical row lock also serializes projection
// and stage numbering with any final post-auth decision.
func claimAuthenticatedRequest(
	ctx context.Context,
	tx pgx.Tx,
	input preparedRequest,
	fingerprint string,
) (bool, error) {
	var status, organizationID, applicationID, environmentID, userID, installationID string
	var sessionGrantID, revisionID, feature, requestProtocol, selectedPlan string
	var familyID, componentID, definitionID, componentKind, trustSource *string
	var clientRequestID, framework, frameworkVersion, storedFingerprint *string
	var routeKey, upstreamKey, modelKey, physicalModel *string
	var planProvenanceExists bool
	err := tx.QueryRow(ctx, `
		SELECT status, organization_id, application_id, environment_id,
		       application_user_id, installation_id,
		       installation_family_id, client_component_id,
		       component_definition_id, component_kind, trust_source,
		       session_grant_id, config_revision_id, feature_key, protocol,
		       client_request_id, framework, framework_version,
		       selected_limit_plan_key, selected_route_key,
		       selected_upstream_key, selected_model_key,
		       selected_physical_model, trusted_decision_fingerprint,
		       EXISTS (
		           SELECT 1 FROM logical_request_decision_stages AS stage
		           WHERE stage.logical_request_id = logical_requests.logical_request_id
		             AND stage.limit_plan_key IS NOT NULL
		       )
		FROM logical_requests
		WHERE logical_request_id = $1
		FOR UPDATE
	`, input.LogicalRequestID.String()).Scan(
		&status, &organizationID, &applicationID, &environmentID, &userID, &installationID,
		&familyID, &componentID, &definitionID, &componentKind, &trustSource,
		&sessionGrantID, &revisionID, &feature, &requestProtocol,
		&clientRequestID, &framework, &frameworkVersion, &selectedPlan,
		&routeKey, &upstreamKey, &modelKey, &physicalModel, &storedFingerprint,
		&planProvenanceExists,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrInvalidState
	}
	if err != nil {
		return false, persistenceFailure("lock authenticated request for quota", err)
	}
	if status != "authenticated" {
		return false, nil
	}
	if organizationID != input.OrganizationID || applicationID != input.ApplicationID ||
		environmentID != input.EnvironmentID || userID != input.ApplicationUserID ||
		installationID != input.InstallationID || sessionGrantID != input.SessionGrantID ||
		revisionID != input.ConfigRevisionID || feature != input.FeatureKey ||
		requestProtocol != input.Protocol || storedFingerprint != nil ||
		!nullableStringMatches(familyID, input.InstallationFamilyID) ||
		!nullableStringMatches(componentID, input.ClientComponentID) ||
		!nullableStringMatches(definitionID, input.ComponentDefinitionID) ||
		!nullableStringMatches(componentKind, input.ComponentKind) ||
		!nullableStringMatches(trustSource, input.TrustSource) ||
		!nullableStringMatches(clientRequestID, input.ClientRequestID) ||
		!nullableStringMatches(framework, input.Framework) ||
		!nullableStringMatches(frameworkVersion, input.FrameworkVersion) ||
		(selectedPlan != input.LimitPlanKey &&
			(selectedPlan != "legacy_unknown" || planProvenanceExists)) ||
		!nullableSelectionMatches(routeKey, input.RouteKey) ||
		!nullableSelectionMatches(upstreamKey, input.UpstreamKey) ||
		!nullableSelectionMatches(modelKey, input.ModelKey) ||
		!nullableSelectionMatches(physicalModel, input.PhysicalModel) {
		return false, ErrInvalidInput
	}
	command, err := tx.Exec(ctx, `
		UPDATE logical_requests
		SET selected_limit_plan_key = $2,
		    selected_route_key = $3,
		    selected_upstream_key = $4,
		    selected_model_key = $5,
		    selected_physical_model = $6,
		    trusted_decision_fingerprint = $7,
		    status = 'reserved'
		WHERE logical_request_id = $1 AND status = 'authenticated'
		  AND trusted_decision_fingerprint IS NULL
	`, input.LogicalRequestID.String(), input.LimitPlanKey, input.RouteKey,
		input.UpstreamKey, input.ModelKey, input.PhysicalModel, fingerprint)
	if err != nil {
		return false, mapWriteError("claim authenticated request for quota", err)
	}
	if command.RowsAffected() != 1 {
		return false, ErrInvalidState
	}
	return true, nil
}

func nullableSelectionMatches(stored *string, expected string) bool {
	return stored == nil || *stored == expected
}

func prepareDecisionStage(stage DecisionStage) (DecisionStage, error) {
	if !slices.Contains(allowedDecisionStages, stage.Stage) ||
		!slices.Contains(allowedDecisionOutcomes, stage.Outcome) ||
		stage.StartedAt.IsZero() || stage.CompletedAt.IsZero() ||
		stage.CompletedAt.Before(stage.StartedAt) ||
		(stage.Outcome == DecisionSucceeded) != (stage.FailureCode == "") ||
		(stage.FailureCode != "" && !failureCodePattern.MatchString(stage.FailureCode)) {
		return DecisionStage{}, ErrInvalidInput
	}
	if (stage.PolicyRuleKey != "" && !identifierPattern.MatchString(stage.PolicyRuleKey) &&
		!decisionRuleKeyPattern.MatchString(stage.PolicyRuleKey)) ||
		(stage.PolicyRuleKey != "" && stage.Stage != DecisionPolicyEvaluated) ||
		(stage.LimitPlanKey != "" && (!identifierPattern.MatchString(stage.LimitPlanKey) ||
			!slices.Contains([]string{
				DecisionPolicyEvaluated, DecisionRouteSelected,
				DecisionQuotaRuleEvaluated, DecisionQuotaReserved,
			}, stage.Stage))) {
		return DecisionStage{}, ErrInvalidInput
	}
	limitPresent := stage.LimitRuleKey != "" || stage.LimitMetric != "" ||
		stage.LimitAlgorithm != "" || stage.HasLimitMaximum
	if limitPresent && (!decisionRuleKeyPattern.MatchString(stage.LimitRuleKey) ||
		!decisionMetricPattern.MatchString(stage.LimitMetric) ||
		!slices.Contains([]string{
			CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm, ConcurrencyAlgorithm,
		}, stage.LimitAlgorithm) || !stage.HasLimitMaximum || stage.LimitMaximum < 0 ||
		stage.Stage != DecisionQuotaRuleEvaluated) {
		return DecisionStage{}, ErrInvalidInput
	}
	routePresent := stage.RouteKey != "" || stage.UpstreamKey != "" ||
		stage.ModelKey != "" || stage.PhysicalModel != ""
	if routePresent && (!identifierPattern.MatchString(stage.RouteKey) ||
		!identifierPattern.MatchString(stage.UpstreamKey) ||
		!identifierPattern.MatchString(stage.ModelKey) || !validPhysicalModel(stage.PhysicalModel) ||
		!slices.Contains([]string{DecisionRouteSelected, DecisionQuotaReserved}, stage.Stage)) {
		return DecisionStage{}, ErrInvalidInput
	}
	stage.StartedAt = stage.StartedAt.UTC()
	stage.CompletedAt = stage.CompletedAt.UTC()
	return stage, nil
}

// RecordDecisionStage appends one bounded stage. A denied, failed, or
// cancelled pre-reservation stage atomically closes the logical request.
func (store *Store) RecordDecisionStage(
	ctx context.Context,
	request AuthenticatedRequest,
	stage DecisionStage,
) error {
	if store == nil || store.pool == nil || ctx == nil || !validAuthenticatedRequestHandle(request) {
		return ErrInvalidInput
	}
	prepared, err := prepareDecisionStage(stage)
	if err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return persistenceFailure("begin request decision stage", err)
	}
	defer rollback(tx)
	var status, revisionID string
	if err := tx.QueryRow(ctx, `
		SELECT status, config_revision_id
		FROM logical_requests
		WHERE organization_id = $1 AND application_id = $2
		  AND environment_id = $3 AND logical_request_id = $4
		FOR UPDATE
	`, request.organizationID, request.applicationID, request.environmentID,
		request.logicalRequestID).Scan(&status, &revisionID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return persistenceFailure("lock request decision lifecycle", err)
	}
	if revisionID != request.configRevisionID || status != "authenticated" {
		return ErrInvalidState
	}
	if err := projectDecisionStage(ctx, tx, request, prepared); err != nil {
		return err
	}
	if err := appendDecisionStage(ctx, tx, request, prepared); err != nil {
		return err
	}
	if prepared.Outcome != DecisionSucceeded {
		terminalStatus := prepared.Outcome
		if terminalStatus == DecisionCancelled {
			terminalStatus = "cancelled"
		}
		command, err := tx.Exec(ctx, `
			UPDATE logical_requests
			SET status = $2, failure_code = $3,
			    completed_at = GREATEST(requested_at, $4)
			WHERE logical_request_id = $1 AND status = 'authenticated'
		`, request.logicalRequestID, terminalStatus, prepared.FailureCode, prepared.CompletedAt)
		if err != nil {
			return persistenceFailure("close pre-reservation logical request", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return persistenceFailure("commit request decision stage", err)
	}
	return nil
}

func validAuthenticatedRequestHandle(request AuthenticatedRequest) bool {
	return id.Validate(request.organizationID, id.Organization) == nil &&
		id.Validate(request.applicationID, id.Application) == nil &&
		id.Validate(request.environmentID, id.Environment) == nil &&
		id.Validate(request.logicalRequestID, id.LogicalRequest) == nil &&
		id.Validate(request.configRevisionID, id.ConfigRevision) == nil
}

func projectDecisionStage(
	ctx context.Context,
	tx pgx.Tx,
	request AuthenticatedRequest,
	stage DecisionStage,
) error {
	if stage.LimitPlanKey != "" {
		command, err := tx.Exec(ctx, `
			UPDATE logical_requests
			SET selected_limit_plan_key = $2
			WHERE logical_request_id = $1 AND status = 'authenticated'
			  AND (selected_limit_plan_key = $2 OR (
			      selected_limit_plan_key = 'legacy_unknown'
			      AND NOT EXISTS (
			          SELECT 1 FROM logical_request_decision_stages AS stage
			          WHERE stage.logical_request_id = logical_requests.logical_request_id
			            AND stage.limit_plan_key IS NOT NULL
			      )
			  ))
		`, request.logicalRequestID, stage.LimitPlanKey)
		if err != nil {
			return persistenceFailure("project selected limit plan", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if stage.RouteKey != "" {
		command, err := tx.Exec(ctx, `
			UPDATE logical_requests
			SET selected_route_key = $2, selected_upstream_key = $3,
			    selected_model_key = $4, selected_physical_model = $5
			WHERE logical_request_id = $1 AND status = 'authenticated'
			  AND (selected_route_key IS NULL OR (
			      selected_route_key = $2 AND selected_upstream_key = $3
			      AND selected_model_key = $4 AND selected_physical_model = $5
			  ))
		`, request.logicalRequestID, stage.RouteKey, stage.UpstreamKey,
			stage.ModelKey, stage.PhysicalModel)
		if err != nil {
			return persistenceFailure("project selected route", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	return nil
}

func appendDecisionStage(
	ctx context.Context,
	tx pgx.Tx,
	request AuthenticatedRequest,
	stage DecisionStage,
) error {
	var next int32
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(stage_number), 0) + 1
		FROM logical_request_decision_stages
		WHERE logical_request_id = $1
	`, request.logicalRequestID).Scan(&next); err != nil {
		return persistenceFailure("select next request decision stage", err)
	}
	if next < 1 || next > 256 {
		return ErrInvalidState
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO logical_request_decision_stages (
			organization_id, application_id, environment_id, logical_request_id,
			stage_number, stage, outcome, failure_code, config_revision_id,
			policy_rule_key, limit_plan_key, limit_rule_key, limit_metric,
			limit_algorithm, limit_maximum, route_key, upstream_key, model_key,
			physical_model, started_at, completed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
	`, request.organizationID, request.applicationID, request.environmentID,
		request.logicalRequestID, next, stage.Stage, stage.Outcome,
		nullableString(stage.FailureCode), request.configRevisionID,
		nullableString(stage.PolicyRuleKey), nullableString(stage.LimitPlanKey),
		nullableString(stage.LimitRuleKey), nullableString(stage.LimitMetric),
		nullableString(stage.LimitAlgorithm), nullableInt64(stage.LimitMaximum, stage.HasLimitMaximum),
		nullableString(stage.RouteKey), nullableString(stage.UpstreamKey),
		nullableString(stage.ModelKey), nullableString(stage.PhysicalModel),
		stage.StartedAt, stage.CompletedAt)
	if err != nil {
		return mapWriteError("append request decision stage", err)
	}
	return nil
}

func nullableInt64(value int64, present bool) any {
	if !present {
		return nil
	}
	return value
}

func requestHandleForPrepared(input preparedRequest) AuthenticatedRequest {
	return AuthenticatedRequest{
		organizationID: input.OrganizationID, applicationID: input.ApplicationID,
		environmentID:    input.EnvironmentID,
		logicalRequestID: input.LogicalRequestID.String(),
		configRevisionID: input.ConfigRevisionID,
	}
}

func decisionLimitMaximum(rule preparedRule) int64 {
	switch rule.Algorithm {
	case TokenBucketAlgorithm:
		return rule.Capacity
	case PerRequestAlgorithm:
		return rule.PerRequestMaximum
	default:
		return rule.Maximum
	}
}

func appendQuotaDecisionStages(
	ctx context.Context,
	tx pgx.Tx,
	input preparedRequest,
	startedAt time.Time,
	completedAt time.Time,
	evaluatedRuleKeys map[string]struct{},
	deniedRuleKeys map[string]struct{},
	failureCode string,
) error {
	request := requestHandleForPrepared(input)
	for _, rule := range input.rules {
		if _, evaluated := evaluatedRuleKeys[rule.ruleKey]; !evaluated {
			continue
		}
		outcome := DecisionSucceeded
		code := ""
		if _, denied := deniedRuleKeys[rule.ruleKey]; denied {
			outcome = DecisionDenied
			code = failureCode
		}
		if err := appendDecisionStage(ctx, tx, request, DecisionStage{
			Stage: DecisionQuotaRuleEvaluated, Outcome: outcome, FailureCode: code,
			StartedAt: startedAt, CompletedAt: completedAt, LimitPlanKey: input.LimitPlanKey,
			LimitRuleKey: rule.ruleKey, LimitMetric: rule.Metric,
			LimitAlgorithm: rule.Algorithm, LimitMaximum: decisionLimitMaximum(rule),
			HasLimitMaximum: true,
		}); err != nil {
			return err
		}
	}
	outcome := DecisionSucceeded
	if failureCode != "" {
		outcome = DecisionDenied
	}
	return appendDecisionStage(ctx, tx, request, DecisionStage{
		Stage: DecisionQuotaReserved, Outcome: outcome, FailureCode: failureCode,
		StartedAt: startedAt, CompletedAt: completedAt, LimitPlanKey: input.LimitPlanKey,
		RouteKey: input.RouteKey, UpstreamKey: input.UpstreamKey,
		ModelKey: input.ModelKey, PhysicalModel: input.PhysicalModel,
	})
}

func requestBoundEvaluatedRuleKeySet(rules []preparedRule) map[string]struct{} {
	result := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.Algorithm == PerRequestAlgorithm ||
			(rule.Algorithm == TokenBucketAlgorithm && rule.Metric != LogicalRequestsMetric) {
			result[rule.ruleKey] = struct{}{}
		}
	}
	return result
}

func evaluatedReservationRuleKeySet(rules []preparedRule, plans []plannedBucket) map[string]struct{} {
	result := requestBoundEvaluatedRuleKeySet(rules)
	for _, plan := range plans {
		result[plan.rule.ruleKey] = struct{}{}
	}
	return result
}

func deniedRuleKeySet(rules []preparedRule) map[string]struct{} {
	result := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		result[rule.ruleKey] = struct{}{}
	}
	return result
}

func deniedPlanRuleKeySet(plans []plannedBucket, indexes ...[]int) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	for _, group := range indexes {
		for _, index := range group {
			if index < 0 || index >= len(plans) {
				return nil, fmt.Errorf("denied quota plan index: %w", ErrInvalidState)
			}
			result[plans[index].rule.ruleKey] = struct{}{}
		}
	}
	return result, nil
}

// RecoverStaleAuthenticatedRequestsBatch terminally reconciles requests that
// could not advance because their handler lost the ability to persist a
// decision stage. A 24-hour database-clock grace period is deliberately far
// longer than the normal bounded pre-reservation path. Row locks and SKIP LOCKED make
// concurrent worker replicas safe, while the inserted recovery stage makes the
// reason visible without persisting an arbitrary dependency error.
func (store *Store) RecoverStaleAuthenticatedRequestsBatch(ctx context.Context, limit int) (int64, error) {
	if store == nil || store.pool == nil || ctx == nil || limit < 1 || limit > maximumExpiryBatch {
		return 0, ErrInvalidInput
	}
	var processed int64
	err := store.pool.QueryRow(ctx, `
		WITH candidates AS MATERIALIZED (
		    SELECT request.organization_id, request.application_id,
		           request.environment_id, request.logical_request_id,
		           request.config_revision_id
		    FROM logical_requests AS request
		    WHERE request.status = 'authenticated'
		      AND request.requested_at <= statement_timestamp() - make_interval(secs => $2)
		    ORDER BY request.requested_at, request.logical_request_id
		    FOR UPDATE SKIP LOCKED
		    LIMIT $1
		), inserted AS (
		    INSERT INTO logical_request_decision_stages (
		        organization_id, application_id, environment_id, logical_request_id,
		        stage_number, stage, outcome, failure_code, config_revision_id,
		        started_at, completed_at
		    )
		    SELECT candidate.organization_id, candidate.application_id,
		           candidate.environment_id, candidate.logical_request_id,
		           COALESCE((
		               SELECT max(stage.stage_number)
		               FROM logical_request_decision_stages AS stage
		               WHERE stage.logical_request_id = candidate.logical_request_id
		           ), 0) + 1,
		           'lifecycle_recovered', 'failed', 'internal_error',
		           candidate.config_revision_id,
		           statement_timestamp(), statement_timestamp()
		    FROM candidates AS candidate
		    RETURNING organization_id, application_id, environment_id, logical_request_id
		), updated AS (
		    UPDATE logical_requests AS request
		    SET status = 'failed', failure_code = 'internal_error',
		        completed_at = GREATEST(request.requested_at, statement_timestamp())
		    FROM inserted
		    WHERE request.organization_id = inserted.organization_id
		      AND request.application_id = inserted.application_id
		      AND request.environment_id = inserted.environment_id
		      AND request.logical_request_id = inserted.logical_request_id
		      AND request.status = 'authenticated'
		    RETURNING request.logical_request_id
		)
		SELECT count(*) FROM updated
	`, limit, int64(staleAuthenticatedRequestAge/time.Second)).Scan(&processed)
	if err != nil {
		return 0, persistenceFailure("recover stale authenticated requests", err)
	}
	return processed, nil
}
