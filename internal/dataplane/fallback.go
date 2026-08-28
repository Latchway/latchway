package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	fallbackConnectError         = "connect_error"
	fallbackTimeoutBeforeHeaders = "timeout_before_headers"
	maximumRouteAttempts         = int64(8)
	maximumLogicalAttempts       = int64(32)
	maximumRetryBackoff          = 60 * time.Second
)

var retryableFallbackStatuses = map[int]string{
	http.StatusRequestTimeout:      "status_408",
	http.StatusTooManyRequests:     "status_429",
	http.StatusInternalServerError: "status_500",
	http.StatusBadGateway:          "status_502",
	http.StatusServiceUnavailable:  "status_503",
	http.StatusGatewayTimeout:      "status_504",
}

// fallbackCondition returns one stable route-policy outcome only when the
// attempt owned dispatch and no response bytes reached the client. It never
// turns policy, quota, target-validation, protocol, relay, persistence, or
// client-cancellation failures into retries.
func fallbackCondition(requestContext context.Context, result executionResult) (string, bool) {
	if result.err == nil || !result.beginInvoked || !result.dispatchOwner || result.relay.ClientStarted {
		return "", false
	}
	if requestContext == nil || requestContext.Err() != nil ||
		errors.Is(result.err, context.Canceled) {
		return "", false
	}
	if condition, ok := retryableFallbackStatuses[result.relay.StatusCode]; ok &&
		errors.Is(result.err, upstream.ErrUpstreamNonSuccess) {
		return condition, true
	}
	if result.relay.StatusCode != 0 || !errors.Is(result.err, errUpstreamDispatch) {
		return "", false
	}
	if isPreHeaderTimeout(result.err) {
		return fallbackTimeoutBeforeHeaders, true
	}
	return fallbackConnectError, true
}

func errorIsTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func isPreHeaderTimeout(err error) bool {
	return errors.Is(err, errUpstreamDispatch) &&
		(errors.Is(err, context.DeadlineExceeded) || errorIsTimeout(err))
}

func isUpstreamTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, upstream.ErrResponseIdleTimeout) ||
		(errors.Is(err, errUpstreamDispatch) && errorIsTimeout(err))
}

func routeAllowsFallback(route configuration.Route, condition string) bool {
	return condition != "" && slices.Contains(route.FallbackOn, condition)
}

func routeAllowsRetry(route configuration.Route, condition string, attempts int64) bool {
	policy := route.RetryPolicy
	return policy != nil && condition != "" && attempts >= 1 &&
		attempts < policy.MaxAttempts && slices.Contains(policy.RetryOn, condition)
}

// routeRetryBackoff returns the deterministic delay before retryOrdinal, where
// ordinal one is the first retry after the route's initial attempt. Jitter is
// downward-only, so the configured exponential delay remains a hard maximum.
func routeRetryBackoff(logicalRequestID string, route configuration.Route, retryOrdinal int64) (time.Duration, bool) {
	policy := route.RetryPolicy
	if policy == nil || logicalRequestID == "" || retryOrdinal < 1 || !validRetryPolicy(policy) {
		return 0, false
	}
	base := policy.InitialBackoff
	for ordinal := int64(1); ordinal < retryOrdinal && base < policy.MaximumBackoff; ordinal++ {
		if base > policy.MaximumBackoff/2 {
			base = policy.MaximumBackoff
			break
		}
		base *= 2
	}
	if base > policy.MaximumBackoff {
		base = policy.MaximumBackoff
	}
	baseMilliseconds := int64(base / time.Millisecond)
	jitterMilliseconds := int64(math.Floor(float64(baseMilliseconds) * policy.JitterRatio))
	if jitterMilliseconds == 0 {
		return base, true
	}
	seed := "latchway/retry-jitter/v1\x00" + logicalRequestID + "\x00" + route.ID + "\x00" + strconv.FormatInt(retryOrdinal, 10)
	digest := sha256.Sum256([]byte(seed))
	offset := int64(binary.BigEndian.Uint64(digest[:8]) % uint64(jitterMilliseconds+1))
	return time.Duration(baseMilliseconds-offset) * time.Millisecond, true
}

func retryDelayFitsContext(ctx context.Context, delay time.Duration) bool {
	if ctx == nil || delay < 0 || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || delay < time.Until(deadline)
}

func sleepForRetry(ctx context.Context, delay time.Duration) error {
	if !retryDelayFitsContext(ctx, delay) {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return context.DeadlineExceeded
	}
	if delay == 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
}

func validFallbackPolicy(conditions []string) bool {
	return validRetryConditions(conditions, false)
}

func validRetryPolicy(policy *configuration.RetryPolicy) bool {
	if policy == nil {
		return true
	}
	return policy.MaxAttempts >= 2 && policy.MaxAttempts <= maximumRouteAttempts &&
		policy.InitialBackoff >= 0 && policy.InitialBackoff <= maximumRetryBackoff &&
		policy.MaximumBackoff >= policy.InitialBackoff && policy.MaximumBackoff <= maximumRetryBackoff &&
		(policy.InitialBackoff != 0 || policy.MaximumBackoff == 0) &&
		policy.InitialBackoff%time.Millisecond == 0 && policy.MaximumBackoff%time.Millisecond == 0 &&
		!math.IsNaN(policy.JitterRatio) && !math.IsInf(policy.JitterRatio, 0) &&
		policy.JitterRatio >= 0 && policy.JitterRatio <= 1 &&
		validRetryConditions(policy.RetryOn, true)
}

func validRetryConditions(conditions []string, requireOne bool) bool {
	if requireOne && len(conditions) == 0 {
		return false
	}
	if len(conditions) > len(retryableFallbackStatuses)+2 {
		return false
	}
	seen := make(map[string]struct{}, len(conditions))
	for _, condition := range conditions {
		if condition != fallbackConnectError && condition != fallbackTimeoutBeforeHeaders {
			if _, ok := retryableFallbackStatusesCondition(condition); !ok {
				return false
			}
		}
		if _, duplicate := seen[condition]; duplicate {
			return false
		}
		seen[condition] = struct{}{}
	}
	return true
}

func retryableFallbackStatusesCondition(condition string) (int, bool) {
	for status, candidate := range retryableFallbackStatuses {
		if candidate == condition {
			return status, true
		}
	}
	return 0, false
}
