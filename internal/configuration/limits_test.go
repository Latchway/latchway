package configuration

import (
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

func TestNormalizeExecutableLimitAcceptsBoundedRequestTokenBucketOutputTokenCostAndConcurrencyRules(t *testing.T) {
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

	tokenBucket, tokenBucketIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "logical_requests", Algorithm: "token_bucket", Scope: []string{"feature", "user"},
		Capacity: maximumExecutableTokenBucketCapacity,
		RefillPerSecond: RefillRate{
			Numerator: maximumExecutableTokenBucketRefillPerSecond, Denominator: 1,
		},
		Hard: true,
	})
	if !ok || tokenBucket.Capacity != maximumExecutableTokenBucketCapacity ||
		tokenBucket.RefillPerSecond != (RefillRate{Numerator: maximumExecutableTokenBucketRefillPerSecond, Denominator: 1}) ||
		!slices.Equal(tokenBucket.Scope, []string{"user", "feature"}) {
		t.Fatalf("logical-request token bucket = %+v ok=%t", tokenBucket, ok)
	}
	_, changedTokenBucketIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "logical_requests", Algorithm: "token_bucket", Scope: []string{"user", "feature"},
		Capacity: 1, RefillPerSecond: RefillRate{Numerator: 333333, Denominator: 1_000_000}, Hard: true,
	})
	if !ok || changedTokenBucketIdentity != tokenBucketIdentity {
		t.Fatalf("token-bucket capacity/rate changed immutable identity: %#v != %#v", changedTokenBucketIdentity, tokenBucketIdentity)
	}
	outputTokenBucket, outputTokenBucketIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "output_tokens", Algorithm: "token_bucket", Scope: []string{"feature", "user"},
		Capacity: maximumExecutableTokenBucketCapacity,
		RefillPerSecond: RefillRate{
			Numerator: maximumExecutableTokenBucketRefillPerSecond, Denominator: 1,
		},
		Hard: true,
	})
	if !ok || outputTokenBucket.Capacity != maximumExecutableTokenBucketCapacity ||
		outputTokenBucket.RefillPerSecond != (RefillRate{Numerator: maximumExecutableTokenBucketRefillPerSecond, Denominator: 1}) ||
		!slices.Equal(outputTokenBucket.Scope, []string{"user", "feature"}) {
		t.Fatalf("output-token token bucket = %+v ok=%t", outputTokenBucket, ok)
	}
	if outputTokenBucketIdentity == tokenBucketIdentity {
		t.Fatal("logical-request and output-token buckets shared an immutable identity")
	}
	_, changedOutputTokenBucketIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "output_tokens", Algorithm: "token_bucket", Scope: []string{"user", "feature"},
		Capacity: 1, RefillPerSecond: RefillRate{Numerator: 1, Denominator: 2}, Hard: true,
	})
	if !ok || changedOutputTokenBucketIdentity != outputTokenBucketIdentity {
		t.Fatalf("output-token bucket capacity/rate changed immutable identity: %#v != %#v",
			changedOutputTokenBucketIdentity, outputTokenBucketIdentity)
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
	costCalendar, costCalendarIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "cost_nano_usd", Algorithm: "calendar", Scope: []string{"feature", "user"},
		Window: "1d", Maximum: math.MaxInt64, Hard: true,
	})
	if !ok || costCalendar.Maximum != math.MaxInt64 ||
		!slices.Equal(costCalendar.Scope, []string{"user", "feature"}) {
		t.Fatalf("cost calendar rule = %+v ok=%t", costCalendar, ok)
	}
	if costCalendarIdentity == outputCalendarIdentity {
		t.Fatal("cost and output-token calendar rules shared an immutable identity")
	}
	_, changedPerRequestIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "output_tokens", Algorithm: "per_request", Scope: []string{"user", "model"},
		PerRequestMaximum: 1, Hard: true,
	})
	if !ok || changedPerRequestIdentity != outputPerRequestIdentity {
		t.Fatalf("per-request maximum changed immutable identity: %#v != %#v", changedPerRequestIdentity, outputPerRequestIdentity)
	}

	requestConcurrency, requestConcurrencyIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "concurrent_requests", Algorithm: "concurrency", Scope: []string{"feature", "organization", "user"},
		Maximum: math.MaxInt64, Hard: true,
	})
	if !ok || requestConcurrency.Maximum != math.MaxInt64 ||
		!slices.Equal(requestConcurrency.Scope, []string{"organization", "user", "feature"}) {
		t.Fatalf("request concurrency rule = %+v ok=%t", requestConcurrency, ok)
	}
	_, changedConcurrencyIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "concurrent_requests", Algorithm: "concurrency", Scope: []string{"user", "feature", "organization"},
		Maximum: 1, Hard: true,
	})
	if !ok || changedConcurrencyIdentity != requestConcurrencyIdentity {
		t.Fatalf("concurrency maximum/scope order changed immutable identity: %#v != %#v", changedConcurrencyIdentity, requestConcurrencyIdentity)
	}
	streamConcurrency, streamConcurrencyIdentity, ok := normalizeExecutableLimit(Limit{
		Metric: "concurrent_streams", Algorithm: "concurrency", Scope: []string{"model", "user"},
		Maximum: 4096, Hard: true,
	})
	if !ok || streamConcurrency.Maximum != 4096 || !slices.Equal(streamConcurrency.Scope, []string{"user", "model"}) {
		t.Fatalf("stream concurrency rule = %+v ok=%t", streamConcurrency, ok)
	}
	if streamConcurrencyIdentity == requestConcurrencyIdentity {
		t.Fatal("request and stream concurrency rules shared an immutable identity")
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
	concurrency := Limit{
		Metric: "concurrent_requests", Algorithm: "concurrency", Scope: []string{"user"},
		Maximum: 10, Hard: true,
	}
	tokenBucket := Limit{
		Metric: "logical_requests", Algorithm: "token_bucket", Scope: []string{"user"},
		Capacity: 10, RefillPerSecond: RefillRate{Numerator: 1, Denominator: 1}, Hard: true,
	}
	tests := []struct {
		name  string
		limit Limit
	}{
		{name: "input token calendar", limit: withLimitMetric(calendar, "input_tokens")},
		{name: "total token calendar", limit: withLimitMetric(calendar, "total_tokens")},
		{name: "logical request concurrency", limit: withLimitMetric(concurrency, "logical_requests")},
		{name: "concurrent request calendar", limit: Limit{Metric: "concurrent_requests", Algorithm: "calendar", Scope: []string{"user"}, Window: "1d", Maximum: 1, Hard: true}},
		{name: "input token bucket", limit: withLimitMetric(tokenBucket, "input_tokens")},
		{name: "total token bucket", limit: withLimitMetric(tokenBucket, "total_tokens")},
		{name: "cost token bucket", limit: withLimitMetric(tokenBucket, "cost_nano_usd")},
		{name: "soft token bucket", limit: withLimitHard(tokenBucket, false)},
		{name: "token bucket zero capacity", limit: withLimitCapacity(tokenBucket, 0)},
		{name: "token bucket excessive capacity", limit: withLimitCapacity(tokenBucket, maximumExecutableTokenBucketCapacity+1)},
		{name: "token bucket missing refill", limit: withLimitRefill(tokenBucket, RefillRate{})},
		{name: "token bucket noncanonical refill", limit: withLimitRefill(tokenBucket, RefillRate{Numerator: 2, Denominator: 2})},
		{name: "token bucket excessive refill", limit: withLimitRefill(tokenBucket, RefillRate{Numerator: maximumExecutableTokenBucketRefillPerSecond + 1, Denominator: 1})},
		{name: "token bucket fractional excessive refill", limit: withLimitRefill(tokenBucket, RefillRate{Numerator: 1_000_000_000_001, Denominator: 1_000_000})},
		{name: "token bucket calendar field", limit: withLimitWindow(tokenBucket, "1d")},
		{name: "token bucket maximum field", limit: withLimitMaximum(tokenBucket, 1)},
		{name: "token bucket per-request field", limit: withLimitPerRequestMaximum(tokenBucket, 1)},
		{name: "logical request per request", limit: withLimitMetric(perRequest, "logical_requests")},
		{name: "soft calendar", limit: withLimitHard(calendar, false)},
		{name: "soft per request", limit: withLimitHard(perRequest, false)},
		{name: "calendar zero maximum", limit: withLimitMaximum(calendar, 0)},
		{name: "calendar per-request field", limit: withLimitPerRequestMaximum(calendar, 1)},
		{name: "calendar capacity field", limit: withLimitCapacity(calendar, 1)},
		{name: "calendar refill field", limit: withLimitRefill(calendar, RefillRate{Numerator: 1, Denominator: 1})},
		{name: "calendar missing window", limit: withLimitWindow(calendar, "")},
		{name: "calendar over window bound", limit: withLimitWindow(calendar, "367d")},
		{name: "per request zero maximum", limit: withLimitPerRequestMaximum(perRequest, 0)},
		{name: "per request window field", limit: withLimitWindow(perRequest, "1d")},
		{name: "per request maximum field", limit: withLimitMaximum(perRequest, 1)},
		{name: "per request capacity field", limit: withLimitCapacity(perRequest, 1)},
		{name: "per request refill field", limit: withLimitRefill(perRequest, RefillRate{Numerator: 1, Denominator: 1})},
		{name: "soft concurrency", limit: withLimitHard(concurrency, false)},
		{name: "concurrency zero maximum", limit: withLimitMaximum(concurrency, 0)},
		{name: "concurrency window field", limit: withLimitWindow(concurrency, "1d")},
		{name: "concurrency per-request field", limit: withLimitPerRequestMaximum(concurrency, 1)},
		{name: "concurrency capacity field", limit: withLimitCapacity(concurrency, 1)},
		{name: "concurrency refill field", limit: withLimitRefill(concurrency, RefillRate{Numerator: 1, Denominator: 1})},
		{name: "missing scope", limit: withLimitScope(calendar, nil)},
		{name: "per request missing scope", limit: withLimitScope(perRequest, nil)},
		{name: "concurrency missing scope", limit: withLimitScope(concurrency, nil)},
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

func TestNormalizeExecutableOutputTokenBucketRejectsInvalidShapesAndBounds(t *testing.T) {
	t.Parallel()

	valid := Limit{
		Metric: "output_tokens", Algorithm: "token_bucket", Scope: []string{"user"},
		Capacity: 10, RefillPerSecond: RefillRate{Numerator: 1, Denominator: 2}, Hard: true,
	}
	tests := []struct {
		name  string
		limit Limit
	}{
		{name: "zero capacity", limit: withLimitCapacity(valid, 0)},
		{name: "capacity above bound", limit: withLimitCapacity(valid, maximumExecutableTokenBucketCapacity+1)},
		{name: "missing refill", limit: withLimitRefill(valid, RefillRate{})},
		{name: "unreduced refill", limit: withLimitRefill(valid, RefillRate{Numerator: 2, Denominator: 4})},
		{name: "refill above bound", limit: withLimitRefill(valid, RefillRate{Numerator: maximumExecutableTokenBucketRefillPerSecond + 1, Denominator: 1})},
		{name: "fractional refill above bound", limit: withLimitRefill(valid, RefillRate{Numerator: 1_000_000_000_001, Denominator: 1_000_000})},
		{name: "window", limit: withLimitWindow(valid, "1d")},
		{name: "maximum", limit: withLimitMaximum(valid, 1)},
		{name: "per request maximum", limit: withLimitPerRequestMaximum(valid, 1)},
		{name: "soft", limit: withLimitHard(valid, false)},
		{name: "missing scope", limit: withLimitScope(valid, nil)},
		{name: "duplicate scope", limit: withLimitScope(valid, []string{"user", "user"})},
		{name: "unknown scope", limit: withLimitScope(valid, []string{"tenant"})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if normalized, identity, ok := normalizeExecutableLimit(test.limit); ok {
				t.Fatalf("invalid output-token bucket normalized: limit=%+v identity=%+v", normalized, identity)
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

func withLimitRefill(limit Limit, refill RefillRate) Limit {
	limit.RefillPerSecond = refill
	return limit
}

func withLimitScope(limit Limit, scope []string) Limit {
	limit.Scope = scope
	return limit
}
