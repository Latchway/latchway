package configuration

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProviderReportedCostRequiresExplicitCompatibleUpstreamOptIn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy any
		kind   string
		valid  bool
	}{
		{
			name: "openrouter exact USD usage cost",
			policy: map[string]any{
				"source": ProviderReportedCostSourceOpenRouterUsage, "currency": "USD",
			},
			kind: "openai_compatible", valid: true,
		},
		{name: "absent remains disabled", kind: "openai_compatible", valid: true},
		{name: "anthropic incompatible", policy: map[string]any{"source": ProviderReportedCostSourceOpenRouterUsage, "currency": "USD"}, kind: "anthropic"},
		{name: "unknown source", policy: map[string]any{"source": "generic_usage_cost", "currency": "USD"}, kind: "openai_compatible"},
		{name: "wrong currency", policy: map[string]any{"source": ProviderReportedCostSourceOpenRouterUsage, "currency": "EUR"}, kind: "openai_compatible"},
		{name: "missing currency", policy: map[string]any{"source": ProviderReportedCostSourceOpenRouterUsage}, kind: "openai_compatible"},
		{name: "unknown member", policy: map[string]any{"source": ProviderReportedCostSourceOpenRouterUsage, "currency": "USD", "round": true}, kind: "openai_compatible"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			document := configurationObject(t)
			upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
			upstream["type"] = test.kind
			if test.policy != nil {
				upstream["providerReportedCost"] = test.policy
			}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid != test.valid {
				t.Fatalf("valid=%t issues=%+v", report.Valid, report.Issues)
			}
			if !test.valid {
				return
			}
			snapshot, err := newActiveSnapshot(
				"rev_00000000000000000000000000",
				"env_00000000000000000000000000",
				encoded,
				compiled,
			)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := snapshot.Upstream(stringValue(upstream, "id"))
			if !ok {
				t.Fatal("compiled upstream missing")
			}
			if test.policy == nil {
				if got.ProviderReportedCost != (ProviderReportedCostPolicy{}) {
					t.Fatalf("absent opt-in became enabled: %+v", got.ProviderReportedCost)
				}
			} else if !got.ProviderReportedCost.Enabled() {
				t.Fatalf("valid opt-in was not retained: %+v", got.ProviderReportedCost)
			}
		})
	}
}
