package configuration

import (
	"encoding/json"
	"math"
	"slices"
	"testing"
)

func TestExecutableCalendarWindowUsesDeterministicOneYearBounds(t *testing.T) {
	t.Parallel()

	valid := []string{
		"1m", "15m", "527040m",
		"1h", "8784h",
		"1d", "366d",
		"1mo", "12mo",
	}
	for _, window := range valid {
		window := window
		t.Run("valid_"+window, func(t *testing.T) {
			t.Parallel()
			if !executableCalendarWindow(window) {
				t.Fatalf("expected %q to be executable", window)
			}
		})
	}

	invalid := []string{
		"", "0d", "01d", "1w",
		"527041m", "8785h", "367d", "13mo",
		"9223372036854775808d",
	}
	for _, window := range invalid {
		window := window
		t.Run("invalid_"+window, func(t *testing.T) {
			t.Parallel()
			if executableCalendarWindow(window) {
				t.Fatalf("expected %q to be rejected", window)
			}
		})
	}
}

func TestNormalizeExecutableLimitAcceptsBoundedRequestAndOutputTokenRules(t *testing.T) {
	t.Parallel()

	inputScope := []string{
		"model", "upstream", "route", "feature", "installation",
		"user", "environment", "application", "organization",
	}
	first, firstIdentity, ok := normalizeExecutableLimit(Limit{
		Metric:    "logical_requests",
		Algorithm: "calendar",
		Window:    "1d",
		Maximum:   5,
		Hard:      true,
		Scope:     inputScope,
	})
	if !ok {
		t.Fatal("expected supported rule to normalize")
	}
	if !slices.Equal(first.Scope, executableLimitScopeOrder) {
		t.Fatalf("normalized scope = %#v, want %#v", first.Scope, executableLimitScopeOrder)
	}
	first.Scope[0] = "changed"
	if inputScope[0] != "model" {
		t.Fatalf("normalization aliased input scope: %#v", inputScope)
	}

	_, changedMaximumIdentity, ok := normalizeExecutableLimit(Limit{
		Metric:    "logical_requests",
		Algorithm: "calendar",
		Window:    "1d",
		Maximum:   99,
		Hard:      true,
		Scope:     append([]string(nil), inputScope...),
	})
	if !ok {
		t.Fatal("expected reordered rule with changed maximum to normalize")
	}
	if changedMaximumIdentity != firstIdentity {
		t.Fatalf("immutable identity changed with maximum/scope ordering: %#v != %#v", changedMaximumIdentity, firstIdentity)
	}

	outputCalendar, outputCalendarIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "output_tokens", Algorithm: "calendar", Scope: []string{"model", "user"},
		Window: "12mo", Maximum: math.MaxInt64, Hard: true,
	})
	if !ok || outputCalendar.Maximum != math.MaxInt64 || !slices.Equal(outputCalendar.Scope, []string{"user", "model"}) {
		t.Fatalf("output-token calendar rule = %+v ok=%t", outputCalendar, ok)
	}
	outputPerRequest, outputPerRequestIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "output_tokens", Algorithm: "per_request", Scope: []string{"model", "user"},
		PerRequestMaximum: math.MaxInt64, Hard: true,
	})
	if !ok || outputPerRequest.PerRequestMaximum != math.MaxInt64 || !slices.Equal(outputPerRequest.Scope, []string{"user", "model"}) {
		t.Fatalf("output-token per-request rule = %+v ok=%t", outputPerRequest, ok)
	}
	if outputCalendarIdentity == outputPerRequestIdentity {
		t.Fatal("calendar and per-request output-token rules shared an immutable identity")
	}
	_, changedPerRequestIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "output_tokens", Algorithm: "per_request", Scope: []string{"user", "model"},
		PerRequestMaximum: 1, Hard: true,
	})
	if !ok || changedPerRequestIdentity != outputPerRequestIdentity {
		t.Fatalf("per-request maximum changed immutable identity: %#v != %#v", changedPerRequestIdentity, outputPerRequestIdentity)
	}
}

func TestNormalizeExecutableLimitRejectsUnsupportedMetricsAlgorithmsAndFieldShapes(t *testing.T) {
	t.Parallel()

	calendar := Limit{
		Metric: "output_tokens", Algorithm: "calendar", Scope: []string{"user"},
		Window: "1d", Maximum: 100, Hard: true,
	}
	perRequest := Limit{
		Metric: "output_tokens", Algorithm: "per_request", Scope: []string{"user"},
		PerRequestMaximum: 100, Hard: true,
	}
	tests := []struct {
		name  string
		limit Limit
	}{
		{name: "input token calendar", limit: withLimitMetric(calendar, "input_tokens")},
		{name: "total token calendar", limit: withLimitMetric(calendar, "total_tokens")},
		{name: "cost calendar", limit: withLimitMetric(calendar, "cost_nano_usd")},
		{name: "concurrency", limit: Limit{Metric: "concurrent_requests", Algorithm: "concurrency", Scope: []string{"user"}, Maximum: 1, Hard: true}},
		{name: "token bucket", limit: Limit{Metric: "output_tokens", Algorithm: "token_bucket", Scope: []string{"user"}, Capacity: 1, RefillPerSecond: json.Number("1"), Hard: true}},
		{name: "logical request per request", limit: withLimitMetric(perRequest, "logical_requests")},
		{name: "soft calendar", limit: withLimitHard(calendar, false)},
		{name: "soft per request", limit: withLimitHard(perRequest, false)},
		{name: "calendar zero maximum", limit: withLimitMaximum(calendar, 0)},
		{name: "calendar per-request field", limit: withLimitPerRequestMaximum(calendar, 1)},
		{name: "calendar capacity field", limit: withLimitCapacity(calendar, 1)},
		{name: "calendar refill field", limit: withLimitRefill(calendar, json.Number("1"))},
		{name: "calendar missing window", limit: withLimitWindow(calendar, "")},
		{name: "calendar over window bound", limit: withLimitWindow(calendar, "367d")},
		{name: "per request zero maximum", limit: withLimitPerRequestMaximum(perRequest, 0)},
		{name: "per request window field", limit: withLimitWindow(perRequest, "1d")},
		{name: "per request maximum field", limit: withLimitMaximum(perRequest, 1)},
		{name: "per request capacity field", limit: withLimitCapacity(perRequest, 1)},
		{name: "per request refill field", limit: withLimitRefill(perRequest, json.Number("1"))},
		{name: "missing scope", limit: withLimitScope(calendar, nil)},
		{name: "per request missing scope", limit: withLimitScope(perRequest, nil)},
		{name: "unknown scope", limit: withLimitScope(calendar, []string{"tenant"})},
		{name: "duplicate scope", limit: withLimitScope(calendar, []string{"user", "user"})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if normalized, identity, ok := normalizeExecutableLimit(test.limit); ok {
				t.Fatalf("unsupported rule normalized: limit=%+v identity=%+v", normalized, identity)
			}
		})
	}
}

func withLimitMetric(limit Limit, metric string) Limit {
	limit.Metric = metric
	return limit
}

func withLimitHard(limit Limit, hard bool) Limit {
	limit.Hard = hard
	return limit
}

func withLimitWindow(limit Limit, window string) Limit {
	limit.Window = window
	return limit
}

func withLimitMaximum(limit Limit, maximum int64) Limit {
	limit.Maximum = maximum
	return limit
}

func withLimitPerRequestMaximum(limit Limit, maximum int64) Limit {
	limit.PerRequestMaximum = maximum
	return limit
}

func withLimitCapacity(limit Limit, capacity int64) Limit {
	limit.Capacity = capacity
	return limit
}

func withLimitRefill(limit Limit, refill json.Number) Limit {
	limit.RefillPerSecond = refill
	return limit
}

func withLimitScope(limit Limit, scope []string) Limit {
	limit.Scope = scope
	return limit
}
