package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/session"
)

const (
	simulationUserID         = "usr_00000000000000000000000000"
	simulationInstallationID = "ins_00000000000000000000000000"
	simulationRequestID      = "req_00000000000000000000000000"
)

type routeSimulationPrincipal struct {
	Authenticated *bool          `json:"authenticated"`
	Claims        map[string]any `json:"claims"`
}

type routeSimulationRequest struct {
	Feature    string                   `json:"feature"`
	Platform   string                   `json:"platform"`
	Principal  routeSimulationPrincipal `json:"principal"`
	TrustLevel string                   `json:"trust_level"`
	Request    map[string]any           `json:"request"`
}

type routeSimulationLimit struct {
	Metric            string   `json:"metric"`
	Algorithm         string   `json:"algorithm"`
	Scope             []string `json:"scope"`
	Window            string   `json:"window,omitempty"`
	Maximum           int64    `json:"maximum,omitempty"`
	PerRequestMaximum int64    `json:"per_request_maximum,omitempty"`
	Capacity          int64    `json:"capacity,omitempty"`
	RefillPerSecond   string   `json:"refill_per_second,omitempty"`
	Hard              bool     `json:"hard"`
}

type routeSimulationCandidate struct {
	Route         string   `json:"route"`
	Upstream      string   `json:"upstream"`
	Model         string   `json:"model"`
	PhysicalModel string   `json:"physical_model"`
	FallbackOn    []string `json:"fallback_on"`
}

type routeSimulationResult struct {
	Allowed                 bool                       `json:"allowed"`
	Feature                 string                     `json:"feature"`
	Protocol                string                     `json:"protocol,omitempty"`
	MatchedAccessExpression string                     `json:"matched_access_expression,omitempty"`
	LimitPlan               string                     `json:"limit_plan,omitempty"`
	Limits                  []routeSimulationLimit     `json:"limits,omitempty"`
	Route                   string                     `json:"route,omitempty"`
	Upstream                string                     `json:"upstream,omitempty"`
	Model                   string                     `json:"model,omitempty"`
	PhysicalModel           string                     `json:"physical_model,omitempty"`
	FallbackSequence        []routeSimulationCandidate `json:"fallback_sequence,omitempty"`
	PricingConfidence       string                     `json:"pricing_confidence,omitempty"`
	Warnings                []string                   `json:"warnings,omitempty"`
	Explanation             []string                   `json:"explanation"`
}

func (api *API) simulateConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[routeSimulationRequest](r)
	if err != nil || request.Principal.Authenticated == nil || request.Principal.Claims == nil ||
		len(request.Principal.Claims) > 64 || len(request.Request) > 64 {
		api.writeProblem(w, r, invalidRequest("The route-simulation request is invalid."))
		return
	}
	if request.TrustLevel == "" {
		request.TrustLevel = "none"
	}
	streaming := false
	if raw, exists := request.Request["streaming"]; exists {
		parsed, ok := raw.(bool)
		if !ok {
			api.writeProblem(w, r, invalidRequest("The simulated request.streaming value must be boolean."))
			return
		}
		streaming = parsed
	}

	compiled, err := api.configurations.SimulationSnapshot(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	if !*request.Principal.Authenticated {
		writeJSON(w, http.StatusOK, routeSimulationResult{
			Allowed: false, Feature: request.Feature,
			Explanation: []string{"Authentication fails before production policy evaluation."},
		})
		return
	}
	feature, found := compiled.Snapshot.Feature(request.Feature)
	if !found {
		writeJSON(w, http.StatusOK, routeSimulationResult{
			Allowed: false, Feature: request.Feature,
			Explanation: []string{"The selected revision has no feature with this identifier."},
		})
		return
	}
	attestationPolicy, found := compiled.Snapshot.AttestationPolicy(feature.AttestationPolicyID)
	if !found {
		api.writeProblem(w, r, problem.Error{Code: "configuration_invalid", Detail: "The selected revision has an invalid attestation-policy reference."})
		return
	}
	attestation, found := attestationPolicy.Platforms[request.Platform]
	if !found {
		writeJSON(w, http.StatusOK, deniedSimulationResult(
			request.Feature, feature,
			"The feature's attestation policy does not define the simulated platform.",
		))
		return
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
		NormalizedClaims: request.Principal.Claims, Streaming: streaming, EvaluatedAt: now,
	})
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The route-simulation facts are invalid or exceed their safety bound."))
		return
	}
	plan, err := api.policyResolver.ResolvePlan(r.Context(), compiled.Snapshot, request.Feature, input)
	if err != nil {
		if detail, denied := simulationDenial(err); denied {
			writeJSON(w, http.StatusOK, deniedSimulationResult(request.Feature, feature, detail))
			return
		}
		api.writeProblem(w, r, problem.Error{Code: "configuration_invalid", Detail: "The selected revision could not produce an executable route plan."})
		return
	}
	if len(plan.Candidates) == 0 {
		api.writeProblem(w, r, problem.Error{Code: "configuration_invalid", Detail: "The selected revision produced an empty route plan."})
		return
	}

	limits := make([]routeSimulationLimit, 0, len(plan.LimitPlan.Limits))
	for _, limit := range plan.LimitPlan.Limits {
		limits = append(limits, routeSimulationLimit{
			Metric: limit.Metric, Algorithm: limit.Algorithm, Scope: append([]string(nil), limit.Scope...),
			Window: limit.Window, Maximum: limit.Maximum, PerRequestMaximum: limit.PerRequestMaximum,
			Capacity: limit.Capacity, RefillPerSecond: limit.RefillPerSecond.String(), Hard: limit.Hard,
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
	}
	if len(request.Request) > 0 && (len(request.Request) != 1 || request.Request["streaming"] == nil) {
		warnings = append(warnings, "Only request.streaming is currently exposed to production feature CEL; other request fields do not affect this decision.")
	}
	primary := plan.Candidates[0]
	pricingConfidence := "unknown"
	if primary.Model.PricingRef != "" {
		pricingConfidence = "configured"
	}
	writeJSON(w, http.StatusOK, routeSimulationResult{
		Allowed: true, Feature: plan.Feature.ID, Protocol: plan.Feature.Protocol,
		MatchedAccessExpression: plan.Feature.AccessExpression,
		LimitPlan:               plan.LimitPlan.ID, Limits: limits,
		Route: primary.Route.ID, Upstream: primary.Upstream.ID, Model: primary.Model.ID,
		PhysicalModel: primary.Model.UpstreamModel, FallbackSequence: candidates,
		PricingConfidence: pricingConfidence, Warnings: warnings,
		Explanation: []string{
			"The exact compiled production CEL policy allowed the simulated principal.",
			"The route order applies configured priority, weight, sticky selection, and fallback policy.",
		},
	})
}

func deniedSimulationResult(featureID string, feature configuration.Feature, detail string) routeSimulationResult {
	return routeSimulationResult{
		Allowed: false, Feature: featureID, Protocol: feature.Protocol,
		MatchedAccessExpression: feature.AccessExpression,
		Warnings:                []string{"Simulation performs no quota reservation and no upstream dispatch."},
		Explanation:             []string{detail},
	}
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
