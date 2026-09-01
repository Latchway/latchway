package cli

import "testing"

func TestEffectiveLimitCLIValidatesCostRetryTreatment(t *testing.T) {
	t.Parallel()
	base := effectiveLimitCLI{
		Index: 0, Metric: "cost_nano_usd", Algorithm: "calendar",
		Scope: []string{"organization"}, Window: "1d", Timezone: "UTC",
		Maximum: 100, CostRetryTreatment: "actual_attempts", Hard: true,
		Source: "limitPlans.paid.limits.0",
	}
	if !validEffectiveLimitCLI(base, 0) {
		t.Fatal("organization actual-attempt cost policy was rejected")
	}
	initial := base
	initial.Scope = []string{"user"}
	initial.CostRetryTreatment = "initial_attempt_only"
	if !validEffectiveLimitCLI(initial, 0) {
		t.Fatal("user initial-attempt-only cost policy was rejected")
	}
	initial.Scope = []string{"organization"}
	if validEffectiveLimitCLI(initial, 0) {
		t.Fatal("organization initial-attempt-only cost policy was accepted")
	}
	nonCost := base
	nonCost.Metric = "logical_requests"
	if validEffectiveLimitCLI(nonCost, 0) {
		t.Fatal("non-cost retry treatment was accepted")
	}
}
