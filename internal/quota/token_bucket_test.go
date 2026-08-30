package quota

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestTokenBucketPolicyValidation(t *testing.T) {
	t.Parallel()
	if maximumTokenCapacity != 9_223_372 {
		t.Fatalf("maximum capacity=%d, want 9223372", maximumTokenCapacity)
	}
	valid := []struct {
		capacity, numerator, denominator int64
	}{
		{1, 1, tokenRateDecimalScale},
		{maximumTokenCapacity, 333_333, tokenRateDecimalScale},
		{2, 3, 2},
		{1, tokenRateDecimalScale, 1},
	}
	for _, test := range valid {
		if err := validateTokenBucketPolicy(test.capacity, test.numerator, test.denominator); err != nil {
			t.Errorf("valid policy %d/%d/%d: %v", test.capacity, test.numerator, test.denominator, err)
		}
	}
	invalid := []struct {
		capacity, numerator, denominator int64
	}{
		{0, 1, 1},
		{maximumTokenCapacity + 1, 1, 1},
		{1, 0, 1},
		{1, 1, 0},
		{1, 1, 3},
		{1, 2, 2},
		{1, tokenRateDecimalScale + 1, 1},
		{1, math.MaxInt64, tokenRateDecimalScale},
		{1, math.MaxInt64, 1},
	}
	for _, test := range invalid {
		if err := validateTokenBucketPolicy(test.capacity, test.numerator, test.denominator); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("invalid policy %d/%d/%d returned %v", test.capacity, test.numerator, test.denominator, err)
		}
	}
}

func TestTokenBucketRefillIsExactAndFragmentationIndependent(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 123_456_789, time.UTC)
	const creditPerTick int64 = 333_333
	maximum := int64(2) * tokenBalanceScale

	batchedBalance, batchedCursor, err := refillTokenBalance(0, maximum, creditPerTick, start, start.Add(3*time.Microsecond+900*time.Nanosecond))
	if err != nil {
		t.Fatalf("batched refill: %v", err)
	}
	balance, cursor := int64(0), start
	for _, now := range []time.Time{
		start.Add(time.Microsecond),
		start.Add(2*time.Microsecond + 500*time.Nanosecond),
		start.Add(3*time.Microsecond + 900*time.Nanosecond),
	} {
		balance, cursor, err = refillTokenBalance(balance, maximum, creditPerTick, cursor, now)
		if err != nil {
			t.Fatalf("fragmented refill at %s: %v", now, err)
		}
	}
	if balance != 999_999 || balance != batchedBalance || !cursor.Equal(start.Add(3*time.Microsecond)) ||
		!cursor.Equal(batchedCursor) {
		t.Fatalf("fragmented=%d/%s batched=%d/%s", balance, cursor, batchedBalance, batchedCursor)
	}

	fullBalance, fullCursor, err := refillTokenBalance(maximum-1, maximum, creditPerTick, cursor, start.Add(10*time.Microsecond))
	if err != nil || fullBalance != maximum || !fullCursor.Equal(start.Add(10*time.Microsecond)) {
		t.Fatalf("saturating refill=%d/%s, %v", fullBalance, fullCursor, err)
	}
	// Time spent at capacity is discarded: draining immediately after this
	// point earns only ticks after the full-bucket cursor.
	drained, accepted, err := reserveTokenBalance(tokenBucketState{
		capacity: 2, balance: fullBalance, numerator: 333_333,
		denominator: tokenRateDecimalScale, refilledAt: fullCursor,
	}, 1)
	if err != nil || !accepted {
		t.Fatalf("drain full bucket accepted=%t: %v", accepted, err)
	}
	drained.balance, drained.refilledAt, err = refillTokenBalance(
		drained.balance, maximum, creditPerTick, drained.refilledAt,
		fullCursor.Add(time.Microsecond),
	)
	if err != nil || drained.balance != tokenBalanceScale+creditPerTick {
		t.Fatalf("post-drain balance=%d: %v", drained.balance, err)
	}
}

func TestTokenBucketPolicyTransitionIsConservative(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name                         string
		stored                       tokenBucketState
		capacity, numerator, divisor int64
		elapsed                      time.Duration
		wantBalance                  int64
	}{
		{
			name:     "capacity increase has no gift",
			stored:   tokenBucketState{capacity: 2, balance: 0, numerator: 2, denominator: 1, refilledAt: start},
			capacity: 5, numerator: 4, divisor: 1, elapsed: 250 * time.Millisecond,
			wantBalance: tokenBalanceScale / 2,
		},
		{
			name:     "capacity decrease clamps",
			stored:   tokenBucketState{capacity: 5, balance: 4 * tokenBalanceScale, numerator: 4, denominator: 1, refilledAt: start},
			capacity: 2, numerator: 4, divisor: 1, elapsed: time.Second,
			wantBalance: 2 * tokenBalanceScale,
		},
		{
			name:     "rate decrease uses lower rate",
			stored:   tokenBucketState{capacity: 5, balance: 0, numerator: 4, denominator: 1, refilledAt: start},
			capacity: 5, numerator: 1, divisor: 1, elapsed: 100 * time.Millisecond,
			wantBalance: tokenBalanceScale / 10,
		},
		{
			name:     "rate increase uses lower rate",
			stored:   tokenBucketState{capacity: 5, balance: 0, numerator: 1, denominator: 1, refilledAt: start},
			capacity: 5, numerator: 4, divisor: 1, elapsed: 100 * time.Millisecond,
			wantBalance: tokenBalanceScale / 10,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := reconcileTokenBucket(
				test.stored, test.capacity, test.numerator, test.divisor, start.Add(test.elapsed),
			)
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if result.capacity != test.capacity || result.numerator != test.numerator ||
				result.denominator != test.divisor || result.balance != test.wantBalance ||
				!result.refilledAt.Equal(start.Add(test.elapsed)) {
				t.Fatalf("reconciled state = %#v", result)
			}
		})
	}
}

func TestTokenBucketClockRegressionAndRefundCursor(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	state := tokenBucketState{
		capacity: 2, balance: 0, numerator: 1, denominator: 1,
		refilledAt: start,
	}
	reconciled, err := reconcileTokenBucket(state, 2, 1, 1, start.Add(-time.Second))
	if err != nil || reconciled.balance != 0 || !reconciled.refilledAt.Equal(start) {
		t.Fatalf("clock regression minted credit: %#v, %v", reconciled, err)
	}

	partial, err := refundTokenBalance(state, 1, start.Add(10*time.Second))
	if err != nil || partial.balance != tokenBalanceScale || !partial.refilledAt.Equal(start) {
		t.Fatalf("partial refund = %#v, %v", partial, err)
	}
	fullState := state
	fullState.capacity = 1
	full, err := refundTokenBalance(fullState, 1, start.Add(10*time.Second))
	if err != nil || full.balance != tokenBalanceScale || !full.refilledAt.Equal(start.Add(10*time.Second)) {
		t.Fatalf("full refund = %#v, %v", full, err)
	}
	regressed, err := refundTokenBalance(fullState, 1, start.Add(-time.Second))
	if err != nil || !regressed.refilledAt.Equal(start) {
		t.Fatalf("regressed refund cursor = %#v, %v", regressed, err)
	}
}

func TestTokenBucketRetryAtUsesExactMicrosecondCeiling(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	state := tokenBucketState{
		capacity: 1, balance: 900_000_000_001, numerator: 1, denominator: 10,
		refilledAt: start,
	}
	retryAt, err := tokenRetryAt(state, 1, start)
	if err != nil {
		t.Fatalf("retry at: %v", err)
	}
	// At 0.1 token/s each tick earns 100,000 quanta. A 99,999,999,999
	// quantum deficit therefore requires exactly 1,000,000 complete ticks.
	if want := start.Add(time.Second); !retryAt.Equal(want) {
		t.Fatalf("retryAt=%s, want %s", retryAt, want)
	}
}

func TestTokenBucketVariableUnitsUseExactBalanceAndRefunds(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	state := tokenBucketState{
		capacity: 100, balance: 64*tokenBalanceScale - 1,
		numerator: tokenRateDecimalScale, denominator: 1, refilledAt: start,
	}
	if _, accepted, err := reserveTokenBalance(state, 64); err != nil || accepted {
		t.Fatalf("one quantum short accepted=%t: %v", accepted, err)
	}
	retryAt, err := tokenRetryAt(state, 64, start)
	if err != nil || !retryAt.Equal(start.Add(time.Microsecond)) {
		t.Fatalf("one quantum retry=%v: %v", retryAt, err)
	}
	state.balance++
	reserved, accepted, err := reserveTokenBalance(state, 64)
	if err != nil || !accepted || reserved.balance != 0 {
		t.Fatalf("exact variable reserve=%#v accepted=%t: %v", reserved, accepted, err)
	}

	partiallySpent := tokenBucketState{
		capacity: 100, balance: 36 * tokenBalanceScale,
		numerator: 1, denominator: 1, refilledAt: start,
	}
	partial, err := refundTokenBalance(partiallySpent, 57, start.Add(time.Second))
	if err != nil || partial.balance != 93*tokenBalanceScale || !partial.refilledAt.Equal(start) {
		t.Fatalf("partial variable refund=%#v: %v", partial, err)
	}
	full, err := refundTokenBalance(partiallySpent, 64, start.Add(time.Second))
	if err != nil || full.balance != 100*tokenBalanceScale ||
		!full.refilledAt.Equal(start.Add(time.Second)) {
		t.Fatalf("saturating variable refund=%#v: %v", full, err)
	}
}

func TestTokenBucketHugeRetryAndRefillAvoidDurationOverflow(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 123_000, time.UTC)
	state := tokenBucketState{
		capacity: maximumTokenCapacity, balance: 0,
		numerator: 1, denominator: tokenRateDecimalScale, refilledAt: start,
	}
	ticks := maximumTokenCapacity * tokenBalanceScale
	wantRetry, err := addTokenTicks(start, ticks)
	if err != nil {
		t.Fatalf("construct huge retry boundary: %v", err)
	}
	retryAt, err := tokenRetryAt(state, maximumTokenCapacity, start)
	if err != nil || !retryAt.Equal(wantRetry) || retryAt.Year() < 294_000 {
		t.Fatalf("huge retry=%v want=%v: %v", retryAt, wantRetry, err)
	}
	before, err := addTokenTicks(start, ticks-1)
	if err != nil {
		t.Fatalf("construct pre-boundary: %v", err)
	}
	preBoundary, err := reconcileTokenBucket(
		state, state.capacity, state.numerator, state.denominator, before,
	)
	if err != nil {
		t.Fatalf("huge pre-boundary refill: %v", err)
	}
	if preBoundary.balance != maximumTokenCapacity*tokenBalanceScale-1 {
		t.Fatalf("huge pre-boundary balance=%d", preBoundary.balance)
	}
	if _, accepted, err := reserveTokenBalance(preBoundary, maximumTokenCapacity); err != nil || accepted {
		t.Fatalf("huge pre-boundary accepted=%t: %v", accepted, err)
	}
	atBoundary, err := reconcileTokenBucket(
		state, state.capacity, state.numerator, state.denominator, retryAt,
	)
	if err != nil {
		t.Fatalf("huge boundary refill: %v", err)
	}
	reserved, accepted, err := reserveTokenBalance(atBoundary, maximumTokenCapacity)
	if err != nil || !accepted || reserved.balance != 0 {
		t.Fatalf("huge boundary reserve=%#v accepted=%t: %v", reserved, accepted, err)
	}

	middle, err := addTokenTicks(start, ticks/2)
	if err != nil {
		t.Fatalf("construct huge midpoint: %v", err)
	}
	fragmented, err := reconcileTokenBucket(
		state, state.capacity, state.numerator, state.denominator, middle,
	)
	if err != nil {
		t.Fatalf("huge first fragment: %v", err)
	}
	fragmented, err = reconcileTokenBucket(
		fragmented, state.capacity, state.numerator, state.denominator, retryAt,
	)
	if err != nil || fragmented.balance != atBoundary.balance ||
		!fragmented.refilledAt.Equal(atBoundary.refilledAt) {
		t.Fatalf("huge fragmented=%#v batched=%#v: %v", fragmented, atBoundary, err)
	}

	nearUnixLimit := time.Unix(math.MaxInt64-1, 0).UTC()
	if _, err := addTokenTicks(nearUnixLimit, 2*tokenTicksPerSecond); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("overflowing tick addition returned %v", err)
	}
}

func TestTokenBucketFractionalEligibilityBoundaryAndSaturatingOverflowSafety(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	state := tokenBucketState{
		capacity: 1, balance: 0, numerator: 333_333,
		denominator: tokenRateDecimalScale, refilledAt: start,
	}
	atThreeSeconds, err := reconcileTokenBucket(
		state, state.capacity, state.numerator, state.denominator, start.Add(3*time.Second),
	)
	if err != nil || atThreeSeconds.balance != 999_999_000_000 {
		t.Fatalf("3s balance=%d: %v", atThreeSeconds.balance, err)
	}
	if _, accepted, err := reserveTokenBalance(atThreeSeconds, 1); err != nil || accepted {
		t.Fatalf("3s eligibility accepted=%t: %v", accepted, err)
	}
	atBoundary, err := reconcileTokenBucket(
		state, state.capacity, state.numerator, state.denominator,
		start.Add(3*time.Second+4*time.Microsecond),
	)
	if err != nil {
		t.Fatalf("3000004us reconcile: %v", err)
	}
	if _, accepted, err := reserveTokenBalance(atBoundary, 1); err != nil || !accepted {
		t.Fatalf("3000004us eligibility accepted=%t balance=%d: %v", accepted, atBoundary.balance, err)
	}

	fast := tokenBucketState{
		capacity: 1, numerator: 2_000, denominator: 1, refilledAt: start,
	}
	at499Microseconds, err := reconcileTokenBucket(
		fast, fast.capacity, fast.numerator, fast.denominator,
		start.Add(499*time.Microsecond),
	)
	if err != nil || at499Microseconds.balance != 998_000_000_000 {
		t.Fatalf("499us balance=%d: %v", at499Microseconds.balance, err)
	}
	if _, accepted, err := reserveTokenBalance(at499Microseconds, 1); err != nil || accepted {
		t.Fatalf("499us eligibility accepted=%t: %v", accepted, err)
	}
	at500Microseconds, err := reconcileTokenBucket(
		fast, fast.capacity, fast.numerator, fast.denominator,
		start.Add(500*time.Microsecond),
	)
	if err != nil {
		t.Fatalf("500us reconcile: %v", err)
	}
	if _, accepted, err := reserveTokenBalance(at500Microseconds, 1); err != nil || !accepted {
		t.Fatalf("500us eligibility accepted=%t balance=%d: %v", accepted, at500Microseconds.balance, err)
	}

	maximum, ok := tokenCapacityBalance(maximumTokenCapacity)
	if !ok {
		t.Fatal("maximum capacity did not scale")
	}
	hugeBalance, hugeCursor, err := refillTokenBalance(
		0, maximum, tokenBalanceScale, start, start.Add(time.Duration(math.MaxInt64)),
	)
	if err != nil || hugeBalance != maximum || !hugeCursor.Equal(start.Add(time.Duration(math.MaxInt64))) {
		t.Fatalf("huge saturating refill=%d/%s: %v", hugeBalance, hugeCursor, err)
	}
}

func TestTokenBucketPersistedFieldMappingFailsClosed(t *testing.T) {
	t.Parallel()
	value := func(value int64) *int64 { return &value }
	timestamp := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	valid := lockedBucket{
		hardMaximum: value(2), available: value(tokenBalanceScale),
		refillNumerator: value(1), refillDenominator: value(1),
		refilledAt: &timestamp,
	}
	if _, err := tokenStateFromLockedBucket(valid); err != nil {
		t.Fatalf("valid persisted mapping: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*lockedBucket)
	}{
		{name: "missing capacity", mutate: func(bucket *lockedBucket) { bucket.hardMaximum = nil }},
		{name: "missing balance", mutate: func(bucket *lockedBucket) { bucket.available = nil }},
		{name: "missing numerator", mutate: func(bucket *lockedBucket) { bucket.refillNumerator = nil }},
		{name: "missing denominator", mutate: func(bucket *lockedBucket) { bucket.refillDenominator = nil }},
		{name: "missing cursor", mutate: func(bucket *lockedBucket) { bucket.refilledAt = nil }},
		{name: "used counter", mutate: func(bucket *lockedBucket) { bucket.used = 1 }},
		{name: "reserved counter", mutate: func(bucket *lockedBucket) { bucket.reserved = 1 }},
		{name: "negative version", mutate: func(bucket *lockedBucket) { bucket.version = -1 }},
		{name: "balance above capacity", mutate: func(bucket *lockedBucket) { bucket.available = value(2*tokenBalanceScale + 1) }},
		{name: "unreduced rate", mutate: func(bucket *lockedBucket) {
			bucket.refillNumerator = value(2)
			bucket.refillDenominator = value(2)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bucket := valid
			test.mutate(&bucket)
			if _, err := tokenStateFromLockedBucket(bucket); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("corrupt persisted mapping returned %v", err)
			}
		})
	}
}
