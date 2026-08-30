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
	tokenTicksPerSecond   int64 = int64(time.Second / tokenRefillTick)
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
	ticks, err := elapsedTokenTicks(cursor, now)
	if err != nil {
		return 0, time.Time{}, err
	}
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
	advanced, err := addTokenTicks(cursor, ticks)
	if err != nil {
		return 0, time.Time{}, err
	}
	return balance + addition, advanced, nil
}

func reserveTokenBalance(state tokenBucketState, units int64) (tokenBucketState, bool, error) {
	if validatePersistedTokenBucket(state) != nil || units <= 0 || units > state.capacity ||
		units > math.MaxInt64/tokenBalanceScale {
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
		units > state.capacity || units > math.MaxInt64/tokenBalanceScale || now.IsZero() {
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
	retryAt, err := addTokenTicks(state.refilledAt, ticks)
	if err != nil {
		return time.Time{}, ErrInvalidState
	}
	if retryAt.Before(now) {
		return now.UTC(), nil
	}
	return retryAt, nil
}

// elapsedTokenTicks returns the exact number of complete refill ticks between
// two instants without passing through time.Duration. It saturates only when
// the count itself exceeds int64; that is sufficient to fill every valid
// bucket because a valid scaled capacity is strictly below MaxInt64.
func elapsedTokenTicks(from, to time.Time) (int64, error) {
	if from.IsZero() || to.IsZero() {
		return 0, ErrInvalidState
	}
	if to.Before(from) {
		return 0, nil
	}
	fromSeconds, toSeconds := from.Unix(), to.Unix()
	if toSeconds < fromSeconds {
		return 0, ErrInvalidState
	}
	maximumWholeSeconds := int64(math.MaxInt64 / tokenTicksPerSecond)
	// Permit one extra raw second because borrowing for a negative nanosecond
	// difference can reduce it before conversion to complete microseconds.
	comparisonSpan := maximumWholeSeconds + 1
	if fromSeconds <= math.MaxInt64-comparisonSpan &&
		toSeconds > fromSeconds+comparisonSpan {
		return math.MaxInt64, nil
	}
	seconds := toSeconds - fromSeconds
	nanoseconds := int64(to.Nanosecond()) - int64(from.Nanosecond())
	if nanoseconds < 0 {
		seconds--
		nanoseconds += int64(time.Second)
	}
	if seconds < 0 {
		return 0, ErrInvalidState
	}
	if seconds > maximumWholeSeconds {
		return math.MaxInt64, nil
	}
	ticks := seconds * tokenTicksPerSecond
	additional := nanoseconds / int64(tokenRefillTick)
	if additional > math.MaxInt64-ticks {
		return math.MaxInt64, nil
	}
	return ticks + additional, nil
}

// addTokenTicks adds an exact microsecond tick count by splitting it into Unix
// seconds and a sub-second remainder. This supports the full valid retry
// horizon (about 292,000 years) without time.Duration overflow.
func addTokenTicks(at time.Time, ticks int64) (time.Time, error) {
	if at.IsZero() || ticks < 0 {
		return time.Time{}, ErrInvalidState
	}
	seconds := ticks / tokenTicksPerSecond
	nanoseconds := int64(at.Nanosecond()) +
		(ticks%tokenTicksPerSecond)*int64(tokenRefillTick)
	seconds += nanoseconds / int64(time.Second)
	nanoseconds %= int64(time.Second)
	baseSeconds := at.Unix()
	if baseSeconds > math.MaxInt64-seconds {
		return time.Time{}, ErrInvalidState
	}
	return time.Unix(baseSeconds+seconds, nanoseconds).UTC(), nil
}

func ceilingDivision(numerator, denominator int64) int64 {
	return 1 + (numerator-1)/denominator
}
