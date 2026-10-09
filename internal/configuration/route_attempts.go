package configuration

import (
	"slices"
	"time"
)

// MaximumLogicalAttempts bounds the attempts one logical request may make
// across every retry and fallback.
const MaximumLogicalAttempts = int64(32)

// RetryConditions are the closed attempt outcomes a route's retry or fallback
// policy can name. Any other failure ends the request.
func RetryConditions() []string {
	return append([]string(nil), runtimeRetryConditions...)
}

// FallsBackOn reports whether a failed attempt with condition may move on to
// the next candidate route.
func (route Route) FallsBackOn(condition string) bool {
	return condition != "" && slices.Contains(route.FallbackOn, condition)
}

// RetriesOn reports whether a failed attempt with condition may be retried on
// the same route after attempts tries there.
func (route Route) RetriesOn(condition string, attempts int64) bool {
	policy := route.RetryPolicy
	return policy != nil && condition != "" && attempts >= 1 &&
		attempts < policy.MaxAttempts && slices.Contains(policy.RetryOn, condition)
}

// BackoffCeiling is the exponential delay before retryOrdinal (one is the
// first retry), capped at MaximumBackoff. Runtime jitter only lowers it.
func (policy RetryPolicy) BackoffCeiling(retryOrdinal int64) time.Duration {
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
	return base
}
