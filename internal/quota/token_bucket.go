package quota

import (
	"math"
	"time"
)

const (
	tokenBalanceScale     int64 = 1_000_000_000_000
	tokenRateDecimalScale int64 = 1_000_000
	tokenBucketWindowKey        = "rolling"
	tokenRefillTick             = time.Microsecond
	maximumTokenCapacity  int64 = math.MaxInt64 / tokenBalanceScale
)

type tokenBucketState struct {
	capacity    int64
	balance     int64
	numerator   int64
	denominator int64
	refilledAt  time.Time
}

func validateTokenBucketPolicy(capacity, numerator, denominator int64) error {
	if capacity <= 0 || capacity > maximumTokenCapacity {
		return ErrInvalidInput
	}
	_, err := tokenCreditPerTick(numerator, denominator)
	return err
}

func validatePersistedTokenBucket(state tokenBucketState) error {
	if validateTokenBucketPolicy(state.capacity, state.numerator, state.denominator) != nil ||
		state.refilledAt.IsZero() {
		return ErrInvalidState
	}
	maximum, ok := tokenCapacityBalance(state.capacity)
	if !ok || state.balance < 0 || state.balance > maximum {
		return ErrInvalidState
	}
	return nil
}

func tokenCapacityBalance(capacity int64) (int64, bool) {
	if capacity <= 0 || capacity > maximumTokenCapacity {
		return 0, false
	}
	return capacity * tokenBalanceScale, true
}

// tokenCreditPerTick validates the canonical reduced six-decimal rate and
// returns fixed-point balance quanta earned per complete microsecond. Limiting
// one tick's credit to one token also caps executable rates at 1,000,000
// tokens per second.
func tokenCreditPerTick(numerator, denominator int64) (int64, error) {
	if numerator <= 0 || denominator <= 0 || tokenRateDecimalScale%denominator != 0 ||
		greatestCommonDivisor(numerator, denominator) != 1 {
		return 0, ErrInvalidInput
	}
	factor := tokenRateDecimalScale / denominator
	if numerator > math.MaxInt64/factor {
		return 0, ErrInvalidInput
	}
	credit := numerator * factor
	if credit <= 0 || credit > tokenBalanceScale {
		return 0, ErrInvalidInput
	}
	return credit, nil
}

func greatestCommonDivisor(left, right int64) int64 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

// reconcileTokenBucket applies every complete refill tick using integer
// arithmetic. A policy transition has no durable activation instant, so its
// unprocessed interval uses the lower old/new capacity and rate, then rebases
// to the selected policy. That can under-credit once but cannot over-credit.
func reconcileTokenBucket(
	stored tokenBucketState,
	selectedCapacity int64,
	selectedNumerator int64,
	selectedDenominator int64,
	now time.Time,
) (tokenBucketState, error) {
	if validatePersistedTokenBucket(stored) != nil || now.IsZero() ||
		validateTokenBucketPolicy(selectedCapacity, selectedNumerator, selectedDenominator) != nil {
		return tokenBucketState{}, ErrInvalidState
	}
	oldCredit, _ := tokenCreditPerTick(stored.numerator, stored.denominator)
	newCredit, _ := tokenCreditPerTick(selectedNumerator, selectedDenominator)
	changed := stored.capacity != selectedCapacity || stored.numerator != selectedNumerator ||
		stored.denominator != selectedDenominator

	effectiveCapacity := min(stored.capacity, selectedCapacity)
	effectiveMaximum, _ := tokenCapacityBalance(effectiveCapacity)
	balance := min(stored.balance, effectiveMaximum)
	credit := min(oldCredit, newCredit)
	balance, cursor, err := refillTokenBalance(balance, effectiveMaximum, credit, stored.refilledAt, now)
	if err != nil {
		return tokenBucketState{}, err
	}
	if changed && !now.Before(stored.refilledAt) {
		cursor = now.UTC()
	}
	result := tokenBucketState{
		capacity: selectedCapacity, balance: balance,
		numerator: selectedNumerator, denominator: selectedDenominator,
		refilledAt: cursor,
	}
	if validatePersistedTokenBucket(result) != nil {
		return tokenBucketState{}, ErrInvalidState
	}
	return result, nil
}

func refillTokenBalance(balance, maximum, credit int64, cursor, now time.Time) (int64, time.Time, error) {
	if balance < 0 || maximum <= 0 || balance > maximum || credit <= 0 || cursor.IsZero() || now.IsZero() {
		return 0, time.Time{}, ErrInvalidState
	}
	if now.Before(cursor) {
		return balance, cursor, nil
	}
	if balance == maximum {
		return balance, now.UTC(), nil
	}
	elapsed := now.Sub(cursor)
	ticks := int64(elapsed / tokenRefillTick)
	if ticks <= 0 {
		return balance, cursor, nil
	}
	missing := maximum - balance
	ticksToFull := ceilingDivision(missing, credit)
	if ticks >= ticksToFull {
		return maximum, now.UTC(), nil
	}
	// ticks < ceil(missing/credit), so this product is strictly below missing
	// and therefore cannot overflow int64.
	addition := ticks * credit
	advance := time.Duration(ticks) * tokenRefillTick
	return balance + addition, cursor.Add(advance).UTC(), nil
}

func reserveTokenBalance(state tokenBucketState, units int64) (tokenBucketState, bool, error) {
	if validatePersistedTokenBucket(state) != nil || units <= 0 || units > math.MaxInt64/tokenBalanceScale {
		return tokenBucketState{}, false, ErrInvalidState
	}
	required := units * tokenBalanceScale
	if state.balance < required {
		return state, false, nil
	}
	state.balance -= required
	return state, true, nil
}

func refundTokenBalance(state tokenBucketState, units int64, now time.Time) (tokenBucketState, error) {
	if validatePersistedTokenBucket(state) != nil || units <= 0 ||
		units > math.MaxInt64/tokenBalanceScale || now.IsZero() {
		return tokenBucketState{}, ErrInvalidState
	}
	maximum, _ := tokenCapacityBalance(state.capacity)
	refund := units * tokenBalanceScale
	if refund >= maximum-state.balance {
		state.balance = maximum
		if !now.Before(state.refilledAt) {
			state.refilledAt = now.UTC()
		}
		return state, nil
	}
	state.balance += refund
	return state, nil
}

func tokenRetryAt(state tokenBucketState, units int64, now time.Time) (time.Time, error) {
	if validatePersistedTokenBucket(state) != nil || units <= 0 ||
		units > math.MaxInt64/tokenBalanceScale || now.IsZero() {
		return time.Time{}, ErrInvalidState
	}
	required := units * tokenBalanceScale
	if state.balance >= required {
		return now.UTC(), nil
	}
	credit, err := tokenCreditPerTick(state.numerator, state.denominator)
	if err != nil {
		return time.Time{}, ErrInvalidState
	}
	ticks := ceilingDivision(required-state.balance, credit)
	if ticks > int64(math.MaxInt64/time.Duration(tokenRefillTick)) {
		return time.Time{}, ErrInvalidState
	}
	retryAt := state.refilledAt.Add(time.Duration(ticks) * tokenRefillTick).UTC()
	if retryAt.Before(now) {
		return now.UTC(), nil
	}
	return retryAt, nil
}

func ceilingDivision(numerator, denominator int64) int64 {
	return 1 + (numerator-1)/denominator
}
