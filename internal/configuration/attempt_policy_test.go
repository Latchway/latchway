package configuration

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNormalizeExecutableUpstreamAttemptLimits(t *testing.T) {
	t.Parallel()
	tests := []Limit{
		{
			Metric: "upstream_attempts", Algorithm: "calendar", Scope: []string{"user"},
			Window: "1d", Maximum: 2, Hard: true,
		},
		{
			Metric: "upstream_attempts", Algorithm: "token_bucket", Scope: []string{"user"},
			Capacity: 2, RefillPerSecond: RefillRate{Numerator: 1, Denominator: 1}, Hard: true,
		},
		{
			Metric: "upstream_attempts", Algorithm: "per_request", Scope: []string{"user"},
			PerRequestMaximum: 2, Hard: true,
		},
	}
	for _, limit := range tests {
		limit := limit
		t.Run(limit.Algorithm, func(t *testing.T) {
			t.Parallel()
			normalized, _, ok := normalizeExecutableLimit(limit)
			if !ok || normalized.Metric != "upstream_attempts" || normalized.Algorithm != limit.Algorithm {
				t.Fatalf("normalized upstream-attempt limit = %+v ok=%t", normalized, ok)
			}
		})
	}
}

func TestNormalizeExecutableCostRetryTreatmentIsUserScopedAndIdentityBearing(t *testing.T) {
	t.Parallel()
	base := Limit{
		Metric: "cost_nano_usd", Algorithm: "calendar", Scope: []string{"user"},
		Window: "1d", Maximum: 100, Hard: true,
	}
	actual, actualIdentity, ok := normalizeExecutableLimit(base)
	if !ok || actual.CostRetryTreatment != CostRetryTreatmentActualAttempts {
		t.Fatalf("default cost treatment = %+v ok=%t", actual, ok)
	}
	explicit := base
	explicit.CostRetryTreatment = CostRetryTreatmentActualAttempts
	_, explicitIdentity, ok := normalizeExecutableLimit(explicit)
	if !ok || explicitIdentity != actualIdentity {
		t.Fatalf("explicit default identity = %+v, want %+v", explicitIdentity, actualIdentity)
	}
	initial := base
	initial.CostRetryTreatment = CostRetryTreatmentInitialAttemptOnly
	normalizedInitial, initialIdentity, ok := normalizeExecutableLimit(initial)
	if !ok || normalizedInitial.CostRetryTreatment != CostRetryTreatmentInitialAttemptOnly ||
		initialIdentity != actualIdentity {
		t.Fatalf("initial-only cost policy = %+v identity=%+v ok=%t", normalizedInitial, initialIdentity, ok)
	}
	initial.Scope = []string{"organization"}
	if normalized, identity, ok := normalizeExecutableLimit(initial); ok {
		t.Fatalf("organization initial-only policy accepted: %+v %+v", normalized, identity)
	}
	nonCost := Limit{
		Metric: "logical_requests", Algorithm: "calendar", Scope: []string{"user"},
		Window: "1d", Maximum: 1, CostRetryTreatment: CostRetryTreatmentActualAttempts, Hard: true,
	}
	if normalized, identity, ok := normalizeExecutableLimit(nonCost); ok {
		t.Fatalf("non-cost treatment accepted: %+v %+v", normalized, identity)
	}
}

func TestValidatorActivatesAttemptQuotaAndPersistsCostRetryTreatment(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	validate := func(t *testing.T, treatment string, costScope []any, pairOrganizationCost bool) (ValidationReport, []byte, []byte) {
		t.Helper()
		document := configurationObject(t)
		spec := objectValue(document, "spec")
		objectArray(spec, "models")[0]["pricingRef"] = "standard"
		spec["pricingCatalogs"] = []any{map[string]any{
			"id": "standard", "currency": "USD",
			"entries": []any{map[string]any{
				"model": "fast", "inputNanoUsdPerMillion": json.Number("0"),
				"outputNanoUsdPerMillion": json.Number("1"), "requestNanoUsd": json.Number("0"),
			}},
		}}
		cost := map[string]any{
			"metric": "cost_nano_usd", "algorithm": "calendar", "scope": costScope,
			"window": "1d", "maximum": json.Number("1000"), "hard": true,
		}
		if treatment != "" {
			cost["costRetryTreatment"] = treatment
		}
		limits := []any{
			map[string]any{
				"metric": "upstream_attempts", "algorithm": "per_request", "scope": []any{"user"},
				"perRequestMaximum": json.Number("2"), "hard": true,
			},
			cost,
		}
		if treatment == CostRetryTreatmentInitialAttemptOnly && pairOrganizationCost {
			limits = append(limits, map[string]any{
				"metric": "cost_nano_usd", "algorithm": "calendar", "scope": []any{"organization"},
				"window": "1d", "maximum": json.Number("1000"),
				"costRetryTreatment": CostRetryTreatmentActualAttempts, "hard": true,
			})
		}
		objectArray(spec, "limitPlans")[0]["limits"] = limits
		encoded, marshalErr := json.Marshal(document)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
		return report, encoded, compiled
	}

	for _, test := range []struct {
		name      string
		treatment string
		want      string
	}{
		{name: "default actual attempts", want: CostRetryTreatmentActualAttempts},
		{name: "explicit initial attempt only", treatment: CostRetryTreatmentInitialAttemptOnly, want: CostRetryTreatmentInitialAttemptOnly},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			report, encoded, compiled := validate(t, test.treatment, []any{"user"}, true)
			if !report.Valid || len(compiled) == 0 {
				t.Fatalf("valid attempt policy rejected: %+v", report.Issues)
			}
			if !strings.Contains(string(compiled), `"costRetryTreatment":"`+test.want+`"`) {
				t.Fatalf("compiled policy omitted retry treatment: %s", compiled)
			}
			snapshot, snapshotErr := newActiveSnapshot("revision", "environment", encoded, compiled)
			if snapshotErr != nil {
				t.Fatal(snapshotErr)
			}
			plan, ok := snapshot.LimitPlan("free")
			wantCount := 2
			if test.treatment == CostRetryTreatmentInitialAttemptOnly {
				wantCount = 3
			}
			if !ok || len(plan.Limits) != wantCount {
				t.Fatalf("active attempt plan = %+v ok=%t", plan, ok)
			}
			seenAttempts, seenCost := false, false
			for _, limit := range plan.Limits {
				switch limit.Metric {
				case "upstream_attempts":
					seenAttempts = limit.Algorithm == "per_request" && limit.PerRequestMaximum == 2
				case "cost_nano_usd":
					if slices.Contains(limit.Scope, "user") {
						seenCost = limit.CostRetryTreatment == test.want
					}
				}
			}
			if !seenAttempts || !seenCost {
				t.Fatalf("active attempt policy lost fields: %+v", plan.Limits)
			}
		})
	}

	t.Run("reject initial only organization cost", func(t *testing.T) {
		report, _, compiled := validate(t, CostRetryTreatmentInitialAttemptOnly, []any{"organization"}, true)
		if report.Valid || len(compiled) != 0 {
			t.Fatalf("organization initial-only policy compiled: report=%+v compiled=%s", report, compiled)
		}
	})

	t.Run("reject unpaired user initial only cost", func(t *testing.T) {
		report, _, compiled := validate(t, CostRetryTreatmentInitialAttemptOnly, []any{"user"}, false)
		if report.Valid || len(compiled) != 0 {
			t.Fatalf("unpaired user initial-only policy compiled: report=%+v compiled=%s", report, compiled)
		}
	})

	t.Run("reject treatment on non-cost rule", func(t *testing.T) {
		document := configurationObject(t)
		limit := objectArray(objectArray(objectValue(document, "spec"), "limitPlans")[0], "limits")[0]
		limit["costRetryTreatment"] = CostRetryTreatmentActualAttempts
		encoded, marshalErr := json.Marshal(document)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
		if report.Valid || len(compiled) != 0 {
			t.Fatalf("non-cost retry treatment compiled: report=%+v compiled=%s", report, compiled)
		}
	})
}

func TestCompiledCostRetryTreatmentDistinguishesOmittedFromExplicitEmpty(t *testing.T) {
	t.Parallel()
	omittedJSON := []byte(`{"metric":"cost_nano_usd","algorithm":"calendar","scope":["organization"],"window":"1d","timezone":"UTC","maximum":100,"hard":true}`)
	var omitted compiledLimit
	if err := json.Unmarshal(omittedJSON, &omitted); err != nil {
		t.Fatal(err)
	}
	normalized, _, ok := omitted.normalizeExecutable()
	if !ok || normalized.CostRetryTreatment != CostRetryTreatmentActualAttempts {
		t.Fatalf("legacy omitted retry treatment = %+v ok=%t", normalized, ok)
	}

	for _, encoded := range [][]byte{
		[]byte(`{"metric":"cost_nano_usd","algorithm":"calendar","scope":["organization"],"window":"1d","timezone":"UTC","maximum":100,"costRetryTreatment":"","hard":true}`),
		[]byte(`{"metric":"logical_requests","algorithm":"calendar","scope":["user"],"window":"1d","timezone":"UTC","maximum":100,"costRetryTreatment":"","hard":true}`),
	} {
		var explicit compiledLimit
		if err := json.Unmarshal(encoded, &explicit); err != nil {
			t.Fatal(err)
		}
		if normalized, identity, ok := explicit.normalizeExecutable(); ok {
			t.Fatalf("explicit empty retry treatment accepted: %+v %+v", normalized, identity)
		}
	}
}

func TestRuntimeLimitPlanRejectsTreatmentOnlyDuplicateIdentity(t *testing.T) {
	t.Parallel()
	compiled := func(scope []string, treatment string) compiledLimit {
		return compiledLimit{
			Limit: Limit{
				Metric: "cost_nano_usd", Algorithm: "calendar", Scope: scope,
				Window: "1d", Timezone: "UTC", Maximum: 100,
				CostRetryTreatment: treatment, Hard: true,
			},
			hasWindow: true, hasTimezone: true, hasMaximum: true, hasCostRetryTreatment: true,
		}
	}
	_, err := runtimeLimitPlan(compiledLimitPlan{ID: "duplicate", Limits: []compiledLimit{
		compiled([]string{"user"}, CostRetryTreatmentActualAttempts),
		compiled([]string{"user"}, CostRetryTreatmentInitialAttemptOnly),
		compiled([]string{"organization"}, CostRetryTreatmentActualAttempts),
	}})
	if err == nil {
		t.Fatal("retry-treatment-only duplicate manufactured a fresh runtime bucket")
	}
}
