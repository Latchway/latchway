package adminapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/session"
)

const (
	simulationUserID         = "usr_00000000000000000000000000"
	simulationInstallationID = "ins_00000000000000000000000000"
	simulationRequestID      = "req_00000000000000000000000000"
	maximumSimulatedTokens   = protocol.MaximumPolicyRequestTokens
	maximumSimulatedBytes    = protocol.MaximumMeasuredRequestBytes
	maximumSimulatedUnits    = protocol.MaximumRequestStructuredUnits
)

type routeSimulationPrincipal struct {
	Authenticated *bool          `json:"authenticated"`
	Claims        map[string]any `json:"claims"`
}

type routeSimulationRequest struct {
	ApplicationID string                      `json:"application_id,omitempty"`
	EnvironmentID string                      `json:"environment_id,omitempty"`
	Feature       string                      `json:"feature"`
	Platform      string                      `json:"platform"`
	Principal     routeSimulationPrincipal    `json:"principal"`
	TrustLevel    string                      `json:"trust_level"`
	Request       routeSimulationRequestFacts `json:"request"`
	Failures      []routeSimulationFailure    `json:"failures,omitempty"`
}

// routeSimulationFailure makes attempts on one route fail with a condition:
// the first Attempts tries, or every try when Attempts is zero.
// "non_retryable" stands for any failure no retry or fallback policy names.
type routeSimulationFailure struct {
	Route     string `json:"route"`
	Condition string `json:"condition"`
	Attempts  int64  `json:"attempts,omitempty"`
}

type routeSimulationAttempt struct {
	Number          int64  `json:"number"`
	Route           string `json:"route"`
	Upstream        string `json:"upstream"`
	Model           string `json:"model"`
	Outcome         string `json:"outcome"`
	Condition       string `json:"condition,omitempty"`
	Next            string `json:"next,omitempty"`
	RetryDelayMaxMS *int64 `json:"retry_delay_max_ms,omitempty"`
}

type routeSimulationAttemptPlan struct {
	Attempts         []routeSimulationAttempt `json:"attempts"`
	Outcome          string                   `json:"outcome"`
	ServedByRoute    string                   `json:"served_by_route,omitempty"`
	FailureCondition string                   `json:"failure_condition,omitempty"`
	Assumptions      []string                 `json:"assumptions"`
}

const (
	nonRetryableSimulationCondition = "non_retryable"
	maximumSimulationFailures       = 16
)

type routeSimulationRequestFacts struct {
	Streaming             bool   `json:"streaming"`
	HTTPMethod            string `json:"http_method,omitempty"`
	AppVersion            string `json:"app_version,omitempty"`
	RequestedInputTokens  int64  `json:"requested_input_tokens,omitempty"`
	RequestedOutputMax    int64  `json:"requested_output_max,omitempty"`
	RewrittenRequestBytes int64  `json:"rewritten_request_bytes,omitempty"`
	FramingUnitCount      int64  `json:"framing_unit_count,omitempty"`
	ExpandedSchemaBytes   int64  `json:"expanded_schema_bytes,omitempty"`
	ImageUnits            int64  `json:"image_units,omitempty"`
	ToolCalls             int64  `json:"tool_calls,omitempty"`
}

type routeSimulationLimit struct {
	Metric             string   `json:"metric"`
	Algorithm          string   `json:"algorithm"`
	Scope              []string `json:"scope"`
	Window             string   `json:"window,omitempty"`
	Timezone           string   `json:"timezone,omitempty"`
	Maximum            int64    `json:"maximum,omitempty"`
	PerRequestMaximum  int64    `json:"per_request_maximum,omitempty"`
	Capacity           int64    `json:"capacity,omitempty"`
	RefillPerSecond    string   `json:"refill_per_second,omitempty"`
	CostRetryTreatment string   `json:"cost_retry_treatment,omitempty"`
	Hard               bool     `json:"hard"`
}

type routeSimulationCandidate struct {
	Route         string   `json:"route"`
	Upstream      string   `json:"upstream"`
	Model         string   `json:"model"`
	PhysicalModel string   `json:"physical_model"`
	FallbackOn    []string `json:"fallback_on"`
}

type routeSimulationFacts struct {
	ApplicationID         string         `json:"application_id"`
	EnvironmentID         string         `json:"environment_id"`
	RevisionID            string         `json:"revision_id"`
	EnvironmentKind       string         `json:"environment_kind"`
	Feature               string         `json:"feature"`
	Platform              string         `json:"platform"`
	TrustLevel            string         `json:"trust_level"`
	Authenticated         bool           `json:"authenticated"`
	NormalizedClaims      map[string]any `json:"normalized_claims"`
	Streaming             bool           `json:"streaming"`
	AppVersion            string         `json:"app_version,omitempty"`
	RequestedInputTokens  int64          `json:"requested_input_tokens"`
	RequestedOutputMax    int64          `json:"requested_output_max"`
	RewrittenRequestBytes int64          `json:"rewritten_request_bytes"`
	FramingUnitCount      int64          `json:"framing_unit_count"`
	ExpandedSchemaBytes   int64          `json:"expanded_schema_bytes"`
	ImageUnits            int64          `json:"image_units"`
	ToolCalls             int64          `json:"tool_calls"`
}

type routeSimulationFactUse struct {
	Fact        string `json:"fact"`
	Role        string `json:"role"`
	AffectsCEL  bool   `json:"affects_cel"`
	Explanation string `json:"explanation"`
}

type routeSimulationInputAccounting struct {
	Required                       bool   `json:"required"`
	ProfileID                      string `json:"profile_id,omitempty"`
	Method                         string `json:"method,omitempty"`
	RewrittenRequestBytes          int64  `json:"rewritten_request_bytes"`
	FramingUnitCount               int64  `json:"framing_unit_count"`
	MaximumFramingTokensPerRequest int64  `json:"maximum_framing_tokens_per_request"`
	MaximumFramingTokensPerUnit    int64  `json:"maximum_framing_tokens_per_unit"`
	ExpandedSchemaBytes            int64  `json:"expanded_schema_bytes"`
	InputTokenBound                int64  `json:"input_token_bound"`
	MaximumContextTokens           int64  `json:"maximum_context_tokens"`
}

type routeSimulationAllocation struct {
	Metric     string `json:"metric"`
	Algorithm  string `json:"algorithm"`
	Units      int64  `json:"units"`
	Applicable bool   `json:"applicable"`
	Durable    bool   `json:"durable"`
}

type routeSimulationReservation struct {
	AppliedOutputMaximum int64                          `json:"applied_output_maximum"`
	TotalTokenBound      int64                          `json:"total_token_bound"`
	CostNanoUSDBound     int64                          `json:"cost_nano_usd_bound"`
	CostBoundKnown       bool                           `json:"cost_bound_known"`
	PricingCatalog       string                         `json:"pricing_catalog,omitempty"`
	InputAccounting      routeSimulationInputAccounting `json:"input_accounting"`
	Allocations          []routeSimulationAllocation    `json:"allocations"`
}

type routeSimulationResult struct {
	Allowed                 bool                        `json:"allowed"`
	Feature                 string                      `json:"feature"`
	ApplicationID           string                      `json:"application_id"`
	EnvironmentID           string                      `json:"environment_id"`
	RevisionID              string                      `json:"revision_id"`
	EnvironmentKind         string                      `json:"environment_kind"`
	Facts                   routeSimulationFacts        `json:"facts"`
	FactUsage               []routeSimulationFactUse    `json:"fact_usage"`
	Protocol                string                      `json:"protocol,omitempty"`
	MatchedAccessExpression string                      `json:"matched_access_expression,omitempty"`
	LimitPlan               string                      `json:"limit_plan,omitempty"`
	Limits                  []routeSimulationLimit      `json:"limits,omitempty"`
	Route                   string                      `json:"route,omitempty"`
	Upstream                string                      `json:"upstream,omitempty"`
	Model                   string                      `json:"model,omitempty"`
	PhysicalModel           string                      `json:"physical_model,omitempty"`
	FallbackSequence        []routeSimulationCandidate  `json:"fallback_sequence,omitempty"`
	PricingConfidence       string                      `json:"pricing_confidence,omitempty"`
	Reservation             *routeSimulationReservation `json:"reservation,omitempty"`
	AttemptPlan             *routeSimulationAttemptPlan `json:"attempt_plan,omitempty"`
	Warnings                []string                    `json:"warnings,omitempty"`
	Explanation             []string                    `json:"explanation"`
}

func (api *API) simulateConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[routeSimulationRequest](r)
	if err != nil || !validRouteSimulationRequest(&request) {
		api.writeProblem(w, r, invalidRequest("The route-simulation request is invalid."))
		return
	}
	compiled, err := api.configurations.SimulationSnapshot(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	result, failure := api.simulateRoute(r.Context(), compiled, request)
	if failure != nil {
		api.writeProblem(w, r, *failure)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

const maximumBatchSimulations = 50

type routeSimulationBatchRequest struct {
	Requests []routeSimulationRequest `json:"requests"`
}

type routeSimulationBatchItem struct {
	Index   int                    `json:"index"`
	Result  *routeSimulationResult `json:"result,omitempty"`
	Problem *simulationItemProblem `json:"problem,omitempty"`
}

type simulationItemProblem struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// simulateConfigurationRevisionBatch runs up to 50 simulations against one
// compiled revision. Each item succeeds or fails on its own.
func (api *API) simulateConfigurationRevisionBatch(w http.ResponseWriter, r *http.Request) {
	batch, err := decodeJSON[routeSimulationBatchRequest](r)
	if err != nil || len(batch.Requests) == 0 || len(batch.Requests) > maximumBatchSimulations {
		api.writeProblem(w, r, invalidRequest("The batch must hold 1 to 50 route-simulation requests."))
		return
	}
	compiled, err := api.configurations.SimulationSnapshot(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	items := make([]routeSimulationBatchItem, 0, len(batch.Requests))
	for index := range batch.Requests {
		item := routeSimulationBatchItem{Index: index}
		if !validRouteSimulationRequest(&batch.Requests[index]) {
			item.Problem = &simulationItemProblem{Code: "invalid_request", Detail: "The route-simulation request is invalid."}
		} else if result, failure := api.simulateRoute(r.Context(), compiled, batch.Requests[index]); failure != nil {
			item.Problem = &simulationItemProblem{Code: failure.Code, Detail: failure.Detail}
		} else {
			item.Result = &result
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func validRouteSimulationRequest(request *routeSimulationRequest) bool {
	if request.Principal.Authenticated == nil || request.Principal.Claims == nil ||
		len(request.Principal.Claims) > 64 || !validSimulationRequestFacts(request.Request) ||
		len(request.Failures) > maximumSimulationFailures {
		return false
	}
	if request.TrustLevel == "" {
		request.TrustLevel = "none"
	}
	conditions := configuration.RetryConditions()
	seen := make(map[string]struct{}, len(request.Failures))
	for _, failure := range request.Failures {
		if !operationalIdentifierPattern.MatchString(failure.Route) || failure.Attempts < 0 ||
			failure.Attempts > configuration.MaximumLogicalAttempts ||
			(failure.Condition != nonRetryableSimulationCondition && !slices.Contains(conditions, failure.Condition)) {
			return false
		}
		if _, duplicate := seen[failure.Route]; duplicate {
			return false
		}
		seen[failure.Route] = struct{}{}
	}
	return true
}

// simulateRoute evaluates one request against a compiled revision. A non-nil
// problem means the request or revision can't be simulated; a denial is a
// result.
func (api *API) simulateRoute(
	ctx context.Context,
	compiled configuration.SimulationSnapshot,
	request routeSimulationRequest,
) (routeSimulationResult, *problem.Error) {
	if request.ApplicationID != "" && (id.Validate(request.ApplicationID, id.Application) != nil ||
		request.ApplicationID != compiled.Scope.ApplicationID) ||
		request.EnvironmentID != "" && (id.Validate(request.EnvironmentID, id.Environment) != nil ||
			request.EnvironmentID != compiled.Scope.EnvironmentID) {
		failure := invalidRequest("The simulator application or environment does not match the selected revision.")
		return routeSimulationResult{}, &failure
	}
	facts := simulationFacts(compiled, request)
	base := baseSimulationResult(compiled, facts)
	if !*request.Principal.Authenticated {
		base.Explanation = []string{"Authentication fails before production policy evaluation."}
		return base, nil
	}
	feature, found := compiled.Snapshot.Feature(request.Feature)
	if !found {
		base.Explanation = []string{"The selected revision has no feature with this identifier."}
		return base, nil
	}
	attestationPolicy, found := compiled.Snapshot.AttestationPolicy(feature.AttestationPolicyID)
	if !found {
		return routeSimulationResult{}, &problem.Error{Code: "configuration_invalid", Detail: "The selected revision has an invalid attestation-policy reference."}
	}
	attestation, found := attestationPolicy.Platforms[request.Platform]
	if !found {
		return deniedSimulationResult(
			base, feature,
			"The feature's attestation policy does not define the simulated platform.",
		), nil
	}
	now := time.Now().UTC()
	input, err := policy.NewSimulationInput(policy.SimulationFacts{
		OrganizationID: compiled.Scope.OrganizationID, ApplicationID: compiled.Scope.ApplicationID,
		EnvironmentID: compiled.Scope.EnvironmentID, EnvironmentKind: compiled.EnvironmentKind,
		PolicyRevisionID:  compiled.Snapshot.PolicyRevision(),
		ApplicationUserID: simulationUserID, InstallationID: simulationInstallationID,
		LogicalRequestID: simulationRequestID, InstallationPlatform: request.Platform,
		IdentityProvider: "simulator", TrustLevel: request.TrustLevel,
		AttestationProvider: attestation.Provider, Authenticated: true,
		NormalizedClaims: request.Principal.Claims, Streaming: request.Request.Streaming,
		EstimatedInputTokens: request.Request.RequestedInputTokens,
		MaximumOutputTokens:  request.Request.RequestedOutputMax,
		EvaluatedAt:          now,
	})
	if err != nil {
		failure := invalidRequest("The route-simulation facts are invalid or exceed their safety bound.")
		return routeSimulationResult{}, &failure
	}
	plan, err := api.policyResolver.ResolvePlan(ctx, compiled.Snapshot, request.Feature, input)
	if err != nil {
		if detail, denied := simulationDenial(err); denied {
			return deniedSimulationResult(base, feature, detail), nil
		}
		return routeSimulationResult{}, &problem.Error{Code: "configuration_invalid", Detail: "The selected revision could not produce an executable route plan."}
	}
	if len(plan.Candidates) == 0 {
		return routeSimulationResult{}, &problem.Error{Code: "configuration_invalid", Detail: "The selected revision produced an empty route plan."}
	}
	for _, failure := range request.Failures {
		if !slices.ContainsFunc(plan.Candidates, func(candidate policy.RouteDecision) bool { return candidate.Route.ID == failure.Route }) {
			unknown := invalidRequest("A simulated failure names a route that isn't in this request's route plan.")
			return routeSimulationResult{}, &unknown
		}
	}
	primary := plan.Candidates[0]
	projection, err := dataplane.ProjectReservation(compiled.Snapshot, policy.Decision{
		Feature: plan.Feature, LimitPlan: plan.LimitPlan, Route: primary.Route,
		Model: primary.Model, Upstream: primary.Upstream,
	}, dataplane.ReservationProjectionInput{
		RequestedOutputMaximum: request.Request.RequestedOutputMax,
		RewrittenRequestBytes:  request.Request.RewrittenRequestBytes,
		FramingUnitCount:       request.Request.FramingUnitCount,
		ExpandedSchemaBytes:    request.Request.ExpandedSchemaBytes,
		ImageUnits:             request.Request.ImageUnits,
		ToolCalls:              request.Request.ToolCalls,
		Streaming:              request.Request.Streaming, EvaluatedAt: now,
	})
	if err != nil {
		if errors.Is(err, dataplane.ErrInvalidReservationProjection) {
			failure := invalidRequest("The request shape cannot produce the trusted conservative reservation required by this route.")
			return routeSimulationResult{}, &failure
		}
		return routeSimulationResult{}, &problem.Error{Code: "configuration_invalid", Detail: "The selected revision could not produce an exact conservative reservation."}
	}

	limits := make([]routeSimulationLimit, 0, len(plan.LimitPlan.Limits))
	for _, limit := range plan.LimitPlan.Limits {
		limits = append(limits, routeSimulationLimit{
			Metric: limit.Metric, Algorithm: limit.Algorithm, Scope: append([]string(nil), limit.Scope...),
			Window: limit.Window, Timezone: limit.Timezone, Maximum: limit.Maximum, PerRequestMaximum: limit.PerRequestMaximum,
			Capacity: limit.Capacity, RefillPerSecond: limit.RefillPerSecond.String(),
			CostRetryTreatment: limit.CostRetryTreatment, Hard: limit.Hard,
		})
	}
	candidates := make([]routeSimulationCandidate, 0, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		candidates = append(candidates, routeSimulationCandidate{
			Route: candidate.Route.ID, Upstream: candidate.Upstream.ID, Model: candidate.Model.ID,
			PhysicalModel: candidate.Model.UpstreamModel,
			FallbackOn:    append([]string(nil), candidate.Route.FallbackOn...),
		})
	}
	warnings := []string{
		"Simulation performs no quota reservation and no upstream dispatch.",
		"Weighted and sticky selection uses stable synthetic opaque identities for repeatable explanations.",
		"The input-token estimate is untrusted CEL policy/scheduling context and never quota or accounting authority.",
		"The requested output maximum is exposed to CEL while the independent server-owned clamp remains authoritative for reservation.",
		"App version is explanatory only and request-shape proofs affect reservation, not CEL.",
	}
	pricingConfidence := "unknown"
	if primary.Model.PricingRef != "" {
		pricingConfidence = "configured"
	}
	base.Allowed = true
	base.Protocol = plan.Feature.Protocol
	base.MatchedAccessExpression = plan.Feature.AccessExpression
	base.LimitPlan = plan.LimitPlan.ID
	base.Limits = limits
	base.Route = primary.Route.ID
	base.Upstream = primary.Upstream.ID
	base.Model = primary.Model.ID
	base.PhysicalModel = primary.Model.UpstreamModel
	base.FallbackSequence = candidates
	base.PricingConfidence = pricingConfidence
	base.Reservation = simulationReservation(projection)
	base.Warnings = warnings
	base.Explanation = []string{
		"The exact compiled production CEL policy allowed the simulated principal.",
		"The route order applies configured priority, weight, sticky selection, and fallback policy.",
		"Reservation units use the production clamp, trusted-input, pricing, and quota projection helpers without mutating quota state.",
	}
	if len(request.Failures) != 0 {
		attemptPlan := simulateAttempts(plan.Candidates, request.Failures, plan.Feature.Protocol, request.Request.HTTPMethod)
		base.AttemptPlan = &attemptPlan
	}
	return base, nil
}

// simulateAttempts walks the route plan the way the data plane does after a
// failed attempt: retry on the same route when its retry policy names the
// condition, otherwise fall back to the next candidate when its fallback
// policy does, within the logical attempt limit. It shares those decisions
// with the data plane through configuration.Route.
func simulateAttempts(candidates []policy.RouteDecision, failures []routeSimulationFailure, protocolID, method string) routeSimulationAttemptPlan {
	byRoute := make(map[string]routeSimulationFailure, len(failures))
	for _, failure := range failures {
		byRoute[failure.Route] = failure
	}
	plan := routeSimulationAttemptPlan{
		Attempts: make([]routeSimulationAttempt, 0, 4),
		Assumptions: []string{
			"Every retry delay fits within the request deadline.",
			"No response bytes reach the app before an attempt fails.",
		},
	}
	replayable := func(route configuration.Route) bool {
		return protocolID != protocol.OpaqueHTTPID || method == http.MethodGet || route.RetryUnsafeMethods
	}
	if protocolID == protocol.OpaqueHTTPID && method == "" {
		plan.Assumptions = append(plan.Assumptions, "The opaque HTTP request is not a GET, so it is replayed only on routes that allow unsafe-method retries.")
	}
	failed := make(map[string]int64, len(failures))
	index, routeAttempts := 0, int64(1)
	for total := int64(1); ; total++ {
		candidate := candidates[index]
		attempt := routeSimulationAttempt{
			Number: total, Route: candidate.Route.ID, Upstream: candidate.Upstream.ID, Model: candidate.Model.ID,
		}
		failure, failing := byRoute[candidate.Route.ID]
		if !failing || (failure.Attempts != 0 && failed[candidate.Route.ID] >= failure.Attempts) {
			attempt.Outcome = "succeeded"
			plan.Attempts = append(plan.Attempts, attempt)
			plan.Outcome, plan.ServedByRoute = "served", candidate.Route.ID
			return plan
		}
		failed[candidate.Route.ID]++
		attempt.Outcome, attempt.Condition, attempt.Next = "failed", failure.Condition, "stop"
		retryable := failure.Condition != nonRetryableSimulationCondition
		if retryable && total < configuration.MaximumLogicalAttempts && replayable(candidate.Route) {
			if candidate.Route.RetriesOn(failure.Condition, routeAttempts) {
				attempt.Next = "retry"
				delay := candidate.Route.RetryPolicy.BackoffCeiling(routeAttempts).Milliseconds()
				attempt.RetryDelayMaxMS = &delay
			} else if candidate.Route.FallsBackOn(failure.Condition) && index+1 < len(candidates) && replayable(candidates[index+1].Route) {
				attempt.Next = "fallback"
			}
		}
		plan.Attempts = append(plan.Attempts, attempt)
		switch attempt.Next {
		case "retry":
			routeAttempts++
		case "fallback":
			index, routeAttempts = index+1, 1
		default:
			plan.Outcome, plan.FailureCondition = "failed", failure.Condition
			return plan
		}
	}
}

func validSimulationRequestFacts(facts routeSimulationRequestFacts) bool {
	return (facts.HTTPMethod == "" || slices.Contains([]string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	}, facts.HTTPMethod)) &&
		len(facts.AppVersion) <= 128 && !strings.ContainsAny(facts.AppVersion, "\r\n\x00") &&
		facts.RequestedInputTokens >= 0 && facts.RequestedInputTokens <= maximumSimulatedTokens &&
		facts.RequestedOutputMax >= 0 && facts.RequestedOutputMax <= maximumSimulatedTokens &&
		facts.RewrittenRequestBytes >= 0 && facts.RewrittenRequestBytes <= maximumSimulatedBytes &&
		facts.FramingUnitCount >= 0 && facts.FramingUnitCount <= 4096 &&
		facts.ExpandedSchemaBytes >= 0 && facts.ExpandedSchemaBytes <= 4*1024*1024 &&
		facts.ImageUnits >= 0 && facts.ImageUnits <= maximumSimulatedUnits &&
		facts.ToolCalls >= 0 && facts.ToolCalls <= maximumSimulatedUnits
}

func simulationFacts(
	compiled configuration.SimulationSnapshot,
	request routeSimulationRequest,
) routeSimulationFacts {
	return routeSimulationFacts{
		ApplicationID: compiled.Scope.ApplicationID, EnvironmentID: compiled.Scope.EnvironmentID,
		RevisionID: compiled.Snapshot.PolicyRevision(), EnvironmentKind: compiled.EnvironmentKind,
		Feature: request.Feature, Platform: request.Platform, TrustLevel: request.TrustLevel,
		Authenticated: *request.Principal.Authenticated, NormalizedClaims: request.Principal.Claims,
		Streaming: request.Request.Streaming, AppVersion: request.Request.AppVersion,
		RequestedInputTokens:  request.Request.RequestedInputTokens,
		RequestedOutputMax:    request.Request.RequestedOutputMax,
		RewrittenRequestBytes: request.Request.RewrittenRequestBytes,
		FramingUnitCount:      request.Request.FramingUnitCount,
		ExpandedSchemaBytes:   request.Request.ExpandedSchemaBytes,
		ImageUnits:            request.Request.ImageUnits,
		ToolCalls:             request.Request.ToolCalls,
	}
}

func baseSimulationResult(
	compiled configuration.SimulationSnapshot,
	facts routeSimulationFacts,
) routeSimulationResult {
	return routeSimulationResult{
		Feature: facts.Feature, ApplicationID: compiled.Scope.ApplicationID,
		EnvironmentID: compiled.Scope.EnvironmentID, RevisionID: compiled.Snapshot.PolicyRevision(),
		EnvironmentKind: compiled.EnvironmentKind, Facts: facts,
		FactUsage: []routeSimulationFactUse{
			{Fact: "application_id", Role: "scope", Explanation: "Authoritative revision scope; it cannot be overridden by simulated facts."},
			{Fact: "environment_id", Role: "scope", Explanation: "Authoritative revision scope; it cannot be overridden by simulated facts."},
			{Fact: "revision_id", Role: "scope", Explanation: "Selects the immutable compiled snapshot."},
			{Fact: "request.feature", Role: "policy", AffectsCEL: true, Explanation: "Bound from the exact immutable Feature after lookup; the request cannot override it."},
			{Fact: "request.protocol", Role: "policy", AffectsCEL: true, Explanation: "Bound from the immutable Feature's server-owned protocol after lookup."},
			{Fact: "platform", Role: "policy", AffectsCEL: true, Explanation: "Selects the platform attestation requirement and is exposed to CEL."},
			{Fact: "trust_level", Role: "policy", AffectsCEL: true, Explanation: "Checked by attestation policy and exposed to CEL."},
			{Fact: "authenticated", Role: "authentication", Explanation: "Authentication is checked before CEL."},
			{Fact: "normalized_claims", Role: "policy", AffectsCEL: true, Explanation: "Bounded normalized claims are exposed to CEL."},
			{Fact: "request.streaming", Role: "policy", AffectsCEL: true, Explanation: "The normalized streaming flag is exposed to CEL and stream concurrency."},
			{Fact: "request.estimated_input_tokens", Role: "policy", AffectsCEL: true, Explanation: "Bounded untrusted estimate for conservative policy and scheduling only; never quota, accounting, pricing, or context authority."},
			{Fact: "request.maximum_output_tokens", Role: "policy", AffectsCEL: true, Explanation: "Exact normalized requested maximum (zero when omitted); the independent server-owned clamp controls reservation and dispatch."},
			{Fact: "rewritten_request_bytes", Role: "reservation", Explanation: "Models the adapter-proved rewritten body size used by trusted input accounting."},
			{Fact: "framing_unit_count", Role: "reservation", Explanation: "Models the adapter-proved message, item, tool, schema-object, and content-part count used by trusted input accounting."},
			{Fact: "expanded_schema_bytes", Role: "reservation", Explanation: "Models the additional bounded local schema expansion bytes used by Chat and Responses trusted input accounting; it does not alter CEL."},
			{Fact: "image_units", Role: "reservation", Explanation: "Models the adapter-proved structured image count used by a hard per-request guard; it does not alter CEL."},
			{Fact: "tool_calls", Role: "reservation", Explanation: "Models the adapter-proved structured tool-call count used by a hard per-request guard; it does not alter CEL."},
			{Fact: "app_version", Role: "explanatory", Explanation: "Returned for context only; it is not currently exposed to production CEL."},
		},
		Explanation: []string{},
	}
}

func simulationReservation(projection dataplane.ReservationProjection) *routeSimulationReservation {
	allocations := make([]routeSimulationAllocation, 0, len(projection.Allocations))
	for _, allocation := range projection.Allocations {
		allocations = append(allocations, routeSimulationAllocation{
			Metric: allocation.Metric, Algorithm: allocation.Algorithm, Units: allocation.Units,
			Applicable: allocation.Applicable, Durable: allocation.Durable,
		})
	}
	accounting := projection.InputAccounting
	return &routeSimulationReservation{
		AppliedOutputMaximum: projection.AppliedOutputMaximum,
		TotalTokenBound:      projection.TotalTokenBound, CostNanoUSDBound: projection.CostNanoUSDBound,
		CostBoundKnown: projection.CostBoundKnown, PricingCatalog: projection.PricingCatalog,
		InputAccounting: routeSimulationInputAccounting{
			Required: accounting.Required, ProfileID: accounting.ProfileID, Method: accounting.Method,
			RewrittenRequestBytes:          accounting.RewrittenRequestBytes,
			FramingUnitCount:               accounting.FramingUnitCount,
			MaximumFramingTokensPerRequest: accounting.MaximumFramingTokensPerRequest,
			MaximumFramingTokensPerUnit:    accounting.MaximumFramingTokensPerUnit,
			ExpandedSchemaBytes:            accounting.ExpandedSchemaBytes,
			InputTokenBound:                accounting.InputTokenBound,
			MaximumContextTokens:           accounting.MaximumContextTokens,
		},
		Allocations: allocations,
	}
}

func deniedSimulationResult(result routeSimulationResult, feature configuration.Feature, detail string) routeSimulationResult {
	result.Protocol = feature.Protocol
	result.MatchedAccessExpression = feature.AccessExpression
	result.Warnings = []string{"Simulation performs no quota reservation and no upstream dispatch."}
	result.Explanation = []string{detail}
	return result
}

func simulationDenial(err error) (string, bool) {
	switch {
	case errors.Is(err, policy.ErrFeatureNotAllowed):
		return "The compiled access expression denied the simulated principal.", true
	case errors.Is(err, policy.ErrLimitPlanNotFound):
		return "The compiled limit-plan expression selected no executable plan.", true
	case errors.Is(err, policy.ErrRouteNotFound):
		return "No executable route matched the simulated facts.", true
	case errors.Is(err, session.ErrAttestationStepUpRequired):
		return "The simulated trust level or attestation provider does not satisfy the feature policy.", true
	case errors.Is(err, session.ErrAttestationRefreshNeeded):
		return "The simulated attestation is not fresh enough for the feature policy.", true
	default:
		return "", false
	}
}
