package quota

import (
	"errors"
	"testing"
)

func TestPrepareUpstreamAttemptRulesDeriveOneAndEnforceAggregatePerRequestBound(t *testing.T) {
	t.Parallel()
	values := map[string]string{"user": "user_123"}
	tests := []struct {
		name     string
		rule     Rule
		stateful bool
	}{
		{
			name: "calendar",
			rule: Rule{
				Metric: UpstreamAttemptsMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user"}, Window: "1d", Maximum: 2, Hard: true,
			},
			stateful: true,
		},
		{
			name: "token bucket",
			rule: Rule{
				Metric: UpstreamAttemptsMetric, Algorithm: TokenBucketAlgorithm,
				Scope: []string{"user"}, Capacity: 2,
				RefillNumerator: 1, RefillDenominator: 1, Hard: true,
			},
			stateful: true,
		},
		{
			name: "per request",
			rule: Rule{
				Metric: UpstreamAttemptsMetric, Algorithm: PerRequestAlgorithm,
				Scope: []string{"user"}, PerRequestMaximum: 2, Hard: true,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			prepared, err := prepareRules([]Rule{test.rule}, values, reserveRulePreparation)
			if err != nil || len(prepared) != 1 {
				t.Fatalf("prepareRules() = %#v, %v", prepared, err)
			}
			if prepared[0].stateful != test.stateful || prepared[0].ReservedUnits != 0 {
				t.Fatalf("prepared attempt rule = %#v, want stateful=%t and zero caller units", prepared[0], test.stateful)
			}
			if units, applicable := ProjectedReservationUnits(prepared[0].Rule, false); units != 1 || !applicable {
				t.Fatalf("projected attempt units = (%d, %t), want (1, true)", units, applicable)
			}
		})
	}

	prepared, err := prepareRules([]Rule{tests[2].rule}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestBoundExceededRulesAtAttempt(prepared, 2); len(got) != 0 {
		t.Fatalf("second aggregate attempt exceeded: %#v", got)
	}
	if got := requestBoundExceededRulesAtAttempt(prepared, 3); len(got) != 1 || got[0].Metric != UpstreamAttemptsMetric {
		t.Fatalf("third aggregate attempt bound = %#v, want upstream_attempts denial", got)
	}
}

func TestPrepareCostRetryTreatmentDefaultsAndBindsOnlyOptInPolicy(t *testing.T) {
	t.Parallel()
	values := map[string]string{"organization": "org_123", "user": "user_123"}
	base := Rule{
		Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 100,
		ReservedUnits: 10, Hard: true,
	}
	omitted, err := prepareRules([]Rule{base}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	explicitRule := base
	explicitRule.CostRetryTreatment = ActualAttemptsCostRetryTreatment
	explicit, err := prepareRules([]Rule{explicitRule}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	if omitted[0].CostRetryTreatment != ActualAttemptsCostRetryTreatment ||
		explicit[0].CostRetryTreatment != ActualAttemptsCostRetryTreatment ||
		omitted[0].ruleKey != explicit[0].ruleKey {
		t.Fatalf("default treatment identity changed: omitted=%#v explicit=%#v", omitted[0], explicit[0])
	}

	initialRule := base
	initialRule.CostRetryTreatment = InitialAttemptOnlyCostRetryTreatment
	if _, err := prepareRules([]Rule{initialRule}, values, reserveRulePreparation); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unpaired user initial-only treatment error = %v, want ErrInvalidInput", err)
	}
	organizationRule := base
	organizationRule.Scope = []string{"organization"}
	organizationRule.CostRetryTreatment = ActualAttemptsCostRetryTreatment
	initial, err := prepareRules([]Rule{initialRule, organizationRule}, values, reserveRulePreparation)
	if err != nil {
		t.Fatal(err)
	}
	var initialUser preparedRule
	for _, rule := range initial {
		if rule.CostRetryTreatment == InitialAttemptOnlyCostRetryTreatment {
			initialUser = rule
		}
	}
	if initialUser.ruleKey != omitted[0].ruleKey {
		t.Fatal("retry treatment changed the durable bucket identity")
	}
	if _, err := prepareRules(
		[]Rule{explicitRule, initialRule, organizationRule}, values, reserveRulePreparation,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("treatment-only duplicate error = %v, want ErrInvalidInput", err)
	}

	organizationOnly := initialRule
	organizationOnly.Scope = []string{"organization"}
	if _, err := prepareRules([]Rule{organizationOnly}, values, reserveRulePreparation); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("organization initial-only treatment error = %v, want ErrInvalidInput", err)
	}
	nonCost := Rule{
		Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 1,
		CostRetryTreatment: ActualAttemptsCostRetryTreatment, Hard: true,
	}
	if _, err := prepareRules([]Rule{nonCost}, values, reserveRulePreparation); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-cost treatment error = %v, want ErrInvalidInput", err)
	}

	if got, ok := canonicalStoredCostRetryTreatment(CostNanoUSDMetric, ""); !ok || got != ActualAttemptsCostRetryTreatment {
		t.Fatalf("legacy empty stored treatment = %q ok=%t", got, ok)
	}
	if _, ok := canonicalStoredCostRetryTreatment(LogicalRequestsMetric, ActualAttemptsCostRetryTreatment); ok {
		t.Fatal("non-cost stored treatment was accepted")
	}

	request := validReserveInput(t)
	request.Pricing = PricingSelection{CatalogID: "standard-usd", Currency: USDCurrency}
	request.Rules = []Rule{base}
	preparedDefault, err := prepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Rules[0].CostRetryTreatment = ActualAttemptsCostRetryTreatment
	preparedExplicit, err := prepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if requestFingerprint(preparedDefault) != requestFingerprint(preparedExplicit) {
		t.Fatal("explicit default changed the historical request replay fingerprint")
	}

	request.Rules = []Rule{organizationRule, initialRule}
	preparedInitial, err := prepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Rules[1].CostRetryTreatment = ActualAttemptsCostRetryTreatment
	preparedActual, err := prepareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if requestFingerprint(preparedInitial) == requestFingerprint(preparedActual) {
		t.Fatal("initial-only treatment did not bind the request replay fingerprint")
	}
}

func TestPrepareRetryAttemptInputRejectsCallerSuppliedAttemptAllocation(t *testing.T) {
	t.Parallel()
	_, err := prepareRetryAttemptInput(RetryAttemptInput{
		RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "backup-model",
		PhysicalModel: "provider/backup-model",
		Allocations:   []AttemptAllocation{{Metric: UpstreamAttemptsMetric, Units: 1}},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("caller-supplied attempt allocation error = %v, want ErrInvalidInput", err)
	}
}
