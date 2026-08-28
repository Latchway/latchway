package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/upstream"
)

func TestFallbackConditionIsTypedAndPreCommitOnly(t *testing.T) {
	t.Parallel()

	dispatchFailure := fmt.Errorf("%w: private dial failure", errUpstreamDispatch)
	dispatchTimeout := fmt.Errorf("%w: %w", errUpstreamDispatch, timeoutNetError{})
	tests := []struct {
		name      string
		ctx       context.Context
		result    executionResult
		condition string
		ok        bool
	}{
		{
			name: "connect error", condition: fallbackConnectError, ok: true,
			ctx: context.Background(), result: executionResult{err: dispatchFailure, beginInvoked: true, dispatchOwner: true},
		},
		{
			name: "timeout before headers", condition: fallbackTimeoutBeforeHeaders, ok: true,
			ctx: context.Background(), result: executionResult{
				err:          fmt.Errorf("%w: %w", errUpstreamDispatch, context.DeadlineExceeded),
				beginInvoked: true, dispatchOwner: true,
			},
		},
		{
			name: "net error timeout before headers", condition: fallbackTimeoutBeforeHeaders, ok: true,
			ctx: context.Background(), result: executionResult{
				err: dispatchTimeout, beginInvoked: true, dispatchOwner: true,
			},
		},
		{
			name: "status 408", condition: "status_408", ok: true,
			ctx: context.Background(), result: executionResult{
				err:   fmt.Errorf("%w: %w", errUpstreamRelay, upstream.ErrUpstreamNonSuccess),
				relay: upstream.RelayOutcome{StatusCode: http.StatusRequestTimeout}, beginInvoked: true, dispatchOwner: true,
			},
		},
		{
			name: "status 503", condition: "status_503", ok: true,
			ctx: context.Background(), result: executionResult{
				err:   fmt.Errorf("%w: %w", errUpstreamRelay, upstream.ErrUpstreamNonSuccess),
				relay: upstream.RelayOutcome{StatusCode: http.StatusServiceUnavailable}, beginInvoked: true, dispatchOwner: true,
			},
		},
		{
			name: "status not configured", ctx: context.Background(),
			result: executionResult{err: errors.New("failure"), relay: upstream.RelayOutcome{StatusCode: http.StatusTeapot}, beginInvoked: true, dispatchOwner: true},
		},
		{
			name: "client already started", ctx: context.Background(),
			result: executionResult{err: dispatchFailure, relay: upstream.RelayOutcome{ClientStarted: true}, beginInvoked: true, dispatchOwner: true},
		},
		{
			name: "before durable attempt", ctx: context.Background(),
			result: executionResult{err: dispatchFailure},
		},
		{
			name: "not dispatch owner", ctx: context.Background(),
			result: executionResult{err: dispatchFailure, beginInvoked: true},
		},
		{
			name: "protocol failure", ctx: context.Background(),
			result: executionResult{err: errUpstreamProtocol, beginInvoked: true, dispatchOwner: true},
		},
		{
			name: "relay net timeout", ctx: context.Background(),
			result: executionResult{
				err:          fmt.Errorf("%w: %w", errUpstreamRelay, timeoutNetError{}),
				beginInvoked: true, dispatchOwner: true,
			},
		},
		{
			name: "protocol failure with retryable-looking status", ctx: context.Background(),
			result: executionResult{
				err: errUpstreamProtocol, relay: upstream.RelayOutcome{StatusCode: http.StatusServiceUnavailable},
				beginInvoked: true, dispatchOwner: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			condition, ok := fallbackCondition(test.ctx, test.result)
			if condition != test.condition || ok != test.ok {
				t.Fatalf("fallbackCondition() = %q, %t; want %q, %t", condition, ok, test.condition, test.ok)
			}
		})
	}
}

func TestFallbackConditionNeverRetriesClientCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, err := range []error{
		fmt.Errorf("%w: private dial failure", errUpstreamDispatch),
		fmt.Errorf("%w: %w", errUpstreamDispatch, context.Canceled),
	} {
		if condition, ok := fallbackCondition(ctx, executionResult{
			err: err, beginInvoked: true, dispatchOwner: true,
		}); ok || condition != "" {
			t.Fatalf("client cancellation classified as %q", condition)
		}
	}
}

func TestFallbackConditionNeverRetriesAfterTheRequestDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	condition, ok := fallbackCondition(ctx, executionResult{
		err:          fmt.Errorf("%w: %w", errUpstreamDispatch, context.DeadlineExceeded),
		beginInvoked: true, dispatchOwner: true,
	})
	if ok || condition != "" {
		t.Fatalf("expired request deadline classified as %q", condition)
	}
}

func TestRouteAllowsOnlyExplicitFallbackConditions(t *testing.T) {
	t.Parallel()

	route := configuration.Route{FallbackOn: []string{"connect_error", "status_503"}}
	if !routeAllowsFallback(route, "connect_error") || !routeAllowsFallback(route, "status_503") ||
		routeAllowsFallback(route, "status_429") || routeAllowsFallback(route, "") {
		t.Fatalf("route fallback policy was not exact: %+v", route.FallbackOn)
	}
}

func TestRouteRetryPolicyIsExplicitAndAttemptBounded(t *testing.T) {
	t.Parallel()

	route := configuration.Route{RetryPolicy: &configuration.RetryPolicy{
		MaxAttempts: 3, RetryOn: []string{"connect_error", "status_503"},
	}}
	if !routeAllowsRetry(route, "connect_error", 1) || !routeAllowsRetry(route, "status_503", 2) ||
		routeAllowsRetry(route, "connect_error", 3) || routeAllowsRetry(route, "status_429", 1) ||
		routeAllowsRetry(configuration.Route{}, "connect_error", 1) {
		t.Fatalf("route retry policy was not exact: %+v", route.RetryPolicy)
	}
}

func TestRouteRetryBackoffIsBoundedDeterministicAndExponentiallyCapped(t *testing.T) {
	t.Parallel()

	route := configuration.Route{ID: "primary", RetryPolicy: &configuration.RetryPolicy{
		MaxAttempts: 8, InitialBackoff: 100 * time.Millisecond,
		MaximumBackoff: 400 * time.Millisecond, JitterRatio: 0.25,
		RetryOn: []string{"connect_error"},
	}}
	windows := []struct {
		ordinal int64
		minimum time.Duration
		maximum time.Duration
	}{
		{ordinal: 1, minimum: 75 * time.Millisecond, maximum: 100 * time.Millisecond},
		{ordinal: 2, minimum: 150 * time.Millisecond, maximum: 200 * time.Millisecond},
		{ordinal: 3, minimum: 300 * time.Millisecond, maximum: 400 * time.Millisecond},
		{ordinal: 7, minimum: 300 * time.Millisecond, maximum: 400 * time.Millisecond},
	}
	for _, window := range windows {
		first, ok := routeRetryBackoff("req_00000000000000000000000000", route, window.ordinal)
		second, replayOK := routeRetryBackoff("req_00000000000000000000000000", route, window.ordinal)
		if !ok || !replayOK || first != second || first < window.minimum || first > window.maximum ||
			first%time.Millisecond != 0 {
			t.Fatalf("retry ordinal %d delay = %v/%v ok=%t/%t, want deterministic within [%v,%v]",
				window.ordinal, first, second, ok, replayOK, window.minimum, window.maximum)
		}
	}

	withoutJitter := route
	policy := *route.RetryPolicy
	policy.JitterRatio = 0
	withoutJitter.RetryPolicy = &policy
	for ordinal, want := range []time.Duration{
		100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 400 * time.Millisecond,
	} {
		got, ok := routeRetryBackoff("req_00000000000000000000000000", withoutJitter, int64(ordinal+1))
		if !ok || got != want {
			t.Fatalf("unjittered retry ordinal %d = %v ok=%t, want %v", ordinal+1, got, ok, want)
		}
	}
}

func TestRetryBackoffHonorsCancellationAndRemainingDeadline(t *testing.T) {
	t.Parallel()

	deadlineContext, cancelDeadline := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelDeadline()
	if retryDelayFitsContext(deadlineContext, 100*time.Millisecond) ||
		!retryDelayFitsContext(deadlineContext, 0) {
		t.Fatal("retry delay ignored the remaining request deadline")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepForRetry(cancelled, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled retry sleep = %v, want context.Canceled", err)
	}
}

func TestValidRetryPolicyIsClosedAndBounded(t *testing.T) {
	t.Parallel()

	valid := &configuration.RetryPolicy{
		MaxAttempts: 3, InitialBackoff: time.Millisecond, MaximumBackoff: time.Second,
		JitterRatio: 0.5, RetryOn: []string{"status_408", "status_503"},
	}
	if !validRetryPolicy(nil) || !validRetryPolicy(valid) {
		t.Fatal("absent or valid retry policy was rejected")
	}
	invalid := []configuration.RetryPolicy{
		{MaxAttempts: 1, RetryOn: []string{"status_503"}},
		{MaxAttempts: 9, RetryOn: []string{"status_503"}},
		{MaxAttempts: 2, InitialBackoff: time.Second, MaximumBackoff: time.Millisecond, RetryOn: []string{"status_503"}},
		{MaxAttempts: 2, InitialBackoff: 0, MaximumBackoff: time.Millisecond, RetryOn: []string{"status_503"}},
		{MaxAttempts: 2, InitialBackoff: time.Microsecond, MaximumBackoff: time.Millisecond, RetryOn: []string{"status_503"}},
		{MaxAttempts: 2, JitterRatio: 1.1, RetryOn: []string{"status_503"}},
		{MaxAttempts: 2, RetryOn: nil},
		{MaxAttempts: 2, RetryOn: []string{"provider_text"}},
		{MaxAttempts: 2, RetryOn: []string{"status_503", "status_503"}},
	}
	for index := range invalid {
		if validRetryPolicy(&invalid[index]) {
			t.Fatalf("invalid retry policy %d accepted: %+v", index, invalid[index])
		}
	}
}

func TestValidFallbackPolicyIsClosedAndDuplicateFree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		conditions []string
		want       bool
	}{
		{name: "empty", want: true},
		{name: "all typed conditions", conditions: []string{
			fallbackConnectError, fallbackTimeoutBeforeHeaders, "status_408", "status_429",
			"status_500", "status_502", "status_503", "status_504",
		}, want: true},
		{name: "duplicate", conditions: []string{"status_503", "status_503"}},
		{name: "provider text", conditions: []string{"capacity"}},
		{name: "arbitrary status", conditions: []string{"status_501"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validFallbackPolicy(test.conditions); got != test.want {
				t.Fatalf("validFallbackPolicy(%q) = %t, want %t", test.conditions, got, test.want)
			}
		})
	}
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "private TLS handshake timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestRetryAttemptInputUsesOneDeterministicAllocationPerBilledMetric(t *testing.T) {
	t.Parallel()

	prepared := preparedExecutionAttempt{
		decision: policy.Decision{
			Route:    configuration.Route{ID: "secondary"},
			Upstream: configuration.Upstream{ID: "provider_b"},
			Model: configuration.Model{
				ID: "model_b", UpstreamModel: "provider-model-b",
			},
		},
		rules: []quota.Rule{
			{Metric: quota.LogicalRequestsMetric},
			{Metric: quota.ConcurrentRequestsMetric},
			{Metric: quota.CostNanoUSDMetric, ReservedUnits: 41},
			{Metric: quota.OutputTokensMetric, ReservedUnits: 13},
			{Metric: quota.InputTokensMetric, ReservedUnits: 7},
			{Metric: quota.OutputTokensMetric, ReservedUnits: 13},
			{Metric: quota.TotalTokensMetric, ReservedUnits: 20},
		},
		pricing: configuredPricing{rates: pricing.Rates{InputNanoUSDPerMillion: 17}},
	}
	input, err := retryAttemptInput(prepared)
	if err != nil {
		t.Fatalf("retryAttemptInput: %v", err)
	}
	want := []quota.AttemptAllocation{
		{Metric: quota.InputTokensMetric, Units: 7},
		{Metric: quota.OutputTokensMetric, Units: 13},
		{Metric: quota.TotalTokensMetric, Units: 20},
		{Metric: quota.CostNanoUSDMetric, Units: 41},
	}
	if !slices.Equal(input.Allocations, want) || input.RouteKey != "secondary" ||
		input.UpstreamKey != "provider_b" || input.ModelKey != "model_b" ||
		input.PhysicalModel != "provider-model-b" || input.InputNanoUSDPerMillion != 17 {
		t.Fatalf("retry input = %#v, want allocations %#v", input, want)
	}

	prepared.rules = append(prepared.rules, quota.Rule{
		Metric: quota.OutputTokensMetric, ReservedUnits: 12,
	})
	if _, err := retryAttemptInput(prepared); !errors.Is(err, policy.ErrConfiguration) {
		t.Fatalf("inconsistent repeated allocation error = %v, want policy configuration error", err)
	}
}
