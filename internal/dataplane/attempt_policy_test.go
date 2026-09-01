package dataplane

import (
	"slices"
	"testing"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
)

func TestSupportedDecisionUpstreamAttemptShapes(t *testing.T) {
	t.Parallel()
	tests := []configuration.Limit{
		{
			Metric: quota.UpstreamAttemptsMetric, Algorithm: quota.CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 2, Hard: true,
		},
		{
			Metric: quota.UpstreamAttemptsMetric, Algorithm: quota.TokenBucketAlgorithm,
			Scope: []string{"user"}, Capacity: 2,
			RefillPerSecond: configuration.RefillRate{Numerator: 1, Denominator: 1}, Hard: true,
		},
		{
			Metric: quota.UpstreamAttemptsMetric, Algorithm: quota.PerRequestAlgorithm,
			Scope: []string{"user"}, PerRequestMaximum: 2, Hard: true,
		},
	}
	for _, limit := range tests {
		if !supportedDecisionLimit(limit) {
			t.Fatalf("supported upstream-attempt %s rule rejected: %+v", limit.Algorithm, limit)
		}
	}
}

func TestFeaturePlanProjectionPreservesCostRetryTreatment(t *testing.T) {
	t.Parallel()
	feature := configuration.Feature{
		ID: "assistant", Protocol: protocol.OpenAIChatID,
		Output: &configuration.OutputPolicy{DefaultMaximumTokens: 32, AbsoluteMaximumTokens: 64},
	}
	plan := configuration.LimitPlan{
		ID: "user-cost", Limits: []configuration.Limit{
			{
				Metric: quota.CostNanoUSDMetric, Algorithm: quota.CalendarAlgorithm,
				Scope: []string{"organization"}, Window: "1d", Maximum: 100,
				CostRetryTreatment: configuration.CostRetryTreatmentActualAttempts, Hard: true,
			},
			{
				Metric: quota.CostNanoUSDMetric, Algorithm: quota.CalendarAlgorithm,
				Scope: []string{"user"}, Window: "1d", Maximum: 100,
				CostRetryTreatment: configuration.CostRetryTreatmentInitialAttemptOnly, Hard: true,
			},
		},
	}
	validated, err := validateFeatureLimitPlan(feature.ID, feature, plan)
	if err != nil || len(validated.rules) != 2 ||
		validated.rules[1].CostRetryTreatment != quota.InitialAttemptOnlyCostRetryTreatment {
		t.Fatalf("validated cost retry treatment = %#v, %v", validated.rules, err)
	}
	if _, err := validateFeatureLimitPlan(feature.ID, feature, configuration.LimitPlan{
		ID: "unpaired", Limits: []configuration.Limit{plan.Limits[1]},
	}); err == nil {
		t.Fatal("unpaired user initial-only cost policy was accepted")
	}

	organization := plan.Limits[1]
	organization.Scope = []string{"organization"}
	if supportedDecisionLimit(organization) {
		t.Fatal("organization initial-only cost policy was accepted")
	}
	organization.CostRetryTreatment = configuration.CostRetryTreatmentActualAttempts
	if !supportedDecisionLimit(organization) {
		t.Fatal("organization actual-attempt cost policy was rejected")
	}
}

func TestRetryInputRetainsTrustedCostForInitialOnlyUserPolicy(t *testing.T) {
	t.Parallel()
	prepared := preparedExecutionAttempt{
		decision: policy.Decision{
			Route:    configuration.Route{ID: "secondary"},
			Upstream: configuration.Upstream{ID: "provider-b"},
			Model:    configuration.Model{ID: "model-b", UpstreamModel: "provider/model-b"},
		},
		rules: []quota.Rule{{
			Metric: quota.CostNanoUSDMetric, ReservedUnits: 41,
			CostRetryTreatment: quota.InitialAttemptOnlyCostRetryTreatment,
		}},
	}
	input, err := retryAttemptInput(prepared)
	if err != nil {
		t.Fatal(err)
	}
	want := []quota.AttemptAllocation{{Metric: quota.CostNanoUSDMetric, Units: 41}}
	if !slices.Equal(input.Allocations, want) {
		t.Fatalf("initial-only retry trusted allocations = %#v, want %#v", input.Allocations, want)
	}
}
