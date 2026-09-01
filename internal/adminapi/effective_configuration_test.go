package adminapi

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/protocol"
)

func TestParseEffectiveConfigurationQueryIsBoundedAndUnambiguous(t *testing.T) {
	t.Parallel()
	environmentID := id.Must(id.Environment)
	installationID := id.Must(id.Installation)
	values := url.Values{
		"environment_id":         {environmentID},
		"feature":                {"assistant"},
		"installation_id":        {installationID},
		"streaming":              {"true"},
		"estimated_input_tokens": {strconv.FormatInt(protocol.MaximumPolicyRequestTokens, 10)},
		"maximum_output_tokens":  {"512"},
	}
	request := httptest.NewRequest("GET", "/?"+values.Encode(), nil)
	query, ok := parseEffectiveConfigurationQuery(request)
	if !ok || query.EnvironmentID != environmentID || query.Feature != "assistant" ||
		query.InstallationID != installationID || !query.Streaming ||
		query.EstimatedInputTokens != protocol.MaximumPolicyRequestTokens ||
		query.MaximumOutputTokens != 512 {
		t.Fatalf("parseEffectiveConfigurationQuery() = %+v, %t", query, ok)
	}

	invalid := []url.Values{
		{"environment_id": {environmentID}, "feature": {"assistant"}, "unknown": {"value"}},
		{"environment_id": {environmentID}, "feature": {"assistant", "duplicate"}},
		{"environment_id": {environmentID}, "feature": {"assistant"}, "installation_id": {installationID}, "component_id": {id.Must(id.ClientComponent)}},
		{"environment_id": {environmentID}, "feature": {"assistant"}, "estimated_input_tokens": {strconv.FormatInt(protocol.MaximumPolicyRequestTokens+1, 10)}},
		{"environment_id": {environmentID}, "feature": {"assistant"}, "streaming": {"yes"}},
	}
	for index, candidate := range invalid {
		candidateRequest := httptest.NewRequest("GET", "/?"+candidate.Encode(), nil)
		if _, accepted := parseEffectiveConfigurationQuery(candidateRequest); accepted {
			t.Fatalf("invalid query %d was accepted: %s", index, candidate.Encode())
		}
	}
}

func TestEffectiveLimitsExposeOnlyAlgorithmFieldsAndExactOutputClamp(t *testing.T) {
	t.Parallel()
	plan := configuration.LimitPlan{ID: "paid", Limits: []configuration.Limit{
		{Metric: "logical_requests", Algorithm: "calendar", Scope: []string{"user"}, Window: "1d", Timezone: "UTC", Maximum: 100, Hard: true},
		{Metric: "output_tokens", Algorithm: "token_bucket", Scope: []string{"user"}, Capacity: 600, RefillPerSecond: configuration.RefillRate{Numerator: 1, Denominator: 2}, Hard: true},
		{Metric: "output_tokens", Algorithm: "per_request", Scope: []string{"feature", "user"}, PerRequestMaximum: 400, Hard: true},
		{Metric: "concurrent_requests", Algorithm: "concurrency", Scope: []string{"user"}, Maximum: 3, Hard: true},
		{Metric: "cost_nano_usd", Algorithm: "calendar", Scope: []string{"user"}, Window: "1d", Timezone: "UTC", Maximum: 1_000, CostRetryTreatment: configuration.CostRetryTreatmentInitialAttemptOnly, Hard: true},
	}}
	limits := effectiveLimits(plan)
	if len(limits) != 5 || limits[0].Maximum != 100 || limits[0].Capacity != 0 ||
		limits[1].Capacity != 600 || limits[1].RefillPerSecond != "0.5" || limits[1].Maximum != 0 ||
		limits[2].PerRequestMaximum != 400 || limits[2].RefillPerSecond != "" ||
		limits[3].Maximum != 3 || limits[4].CostRetryTreatment != configuration.CostRetryTreatmentInitialAttemptOnly {
		t.Fatalf("effectiveLimits() = %+v", limits)
	}
	document := effectiveConfigurationDocument{Output: &effectiveOutputDocument{
		ConfiguredDefaultMaximumTokens: 800, ConfiguredAbsoluteMaximumTokens: 1_500,
	}}
	applyEffectiveOutput(&document, plan, 700)
	if document.Output.EffectiveMaximumTokens != 400 ||
		document.Output.EffectiveDefaultMaximumTokens != 400 ||
		document.Output.RequestedMaximumTokens != 700 ||
		document.Output.Source != "feature.output + limitPlans.paid.limits" {
		t.Fatalf("effective output = %+v", document.Output)
	}
}
