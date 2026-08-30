package quota

import (
	"testing"
	"time"
)

func FuzzTokenBucketReservationArithmetic(f *testing.F) {
	f.Add(uint64(1), uint64(0), uint64(0), uint64(0))
	f.Add(uint64(maximumTokenCapacity-1), ^uint64(0), ^uint64(0), uint64(9_999_999))
	f.Add(uint64(99), uint64(64*tokenBalanceScale-1), uint64(63), uint64(500_000))

	start := time.Date(2026, time.August, 31, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, rawCapacity, rawBalance, rawUnits, rawElapsed uint64) {
		capacity := int64(rawCapacity%uint64(maximumTokenCapacity)) + 1
		maximum, ok := tokenCapacityBalance(capacity)
		if !ok {
			t.Fatalf("bounded capacity %d was rejected", capacity)
		}
		balance := int64(rawBalance % uint64(maximum+1))
		units := int64(rawUnits%uint64(capacity)) + 1
		elapsed := int64(rawElapsed % 10_000_000)
		now := start.Add(time.Duration(elapsed) * time.Microsecond)
		initial := tokenBucketState{
			capacity: capacity, balance: balance,
			numerator: 333_333, denominator: tokenRateDecimalScale,
			refilledAt: start,
		}

		batched, err := reconcileTokenBucket(
			initial, capacity, initial.numerator, initial.denominator, now,
		)
		if err != nil {
			t.Fatalf("valid batched reconciliation failed: %v", err)
		}
		middle := start.Add(time.Duration(elapsed/2) * time.Microsecond)
		fragmented, err := reconcileTokenBucket(
			initial, capacity, initial.numerator, initial.denominator, middle,
		)
		if err != nil {
			t.Fatalf("valid first reconciliation fragment failed: %v", err)
		}
		fragmented, err = reconcileTokenBucket(
			fragmented, capacity, initial.numerator, initial.denominator, now,
		)
		if err != nil {
			t.Fatalf("valid second reconciliation fragment failed: %v", err)
		}
		if fragmented != batched {
			t.Fatalf("fragmented reconciliation %#v differs from batched %#v", fragmented, batched)
		}

		required := units * tokenBalanceScale
		reserved, accepted, err := reserveTokenBalance(batched, units)
		if err != nil {
			t.Fatalf("valid reservation failed: %v", err)
		}
		if accepted != (batched.balance >= required) {
			t.Fatalf("accepted=%t with balance=%d and required=%d", accepted, batched.balance, required)
		}
		if !accepted {
			if reserved != batched {
				t.Fatalf("denied reservation mutated state: got %#v want %#v", reserved, batched)
			}
		} else {
			if reserved.balance != batched.balance-required ||
				reserved.balance < 0 || reserved.balance > maximum {
				t.Fatalf("reserved balance=%d from balance=%d required=%d", reserved.balance, batched.balance, required)
			}
			refunded, refundErr := refundTokenBalance(reserved, units, now)
			if refundErr != nil {
				t.Fatalf("valid matching refund failed: %v", refundErr)
			}
			if refunded.balance != batched.balance {
				t.Fatalf("reserve/refund changed balance: got %d want %d", refunded.balance, batched.balance)
			}
		}

		retryAt, err := tokenRetryAt(batched, units, now)
		if err != nil || retryAt.Before(now) {
			t.Fatalf("valid retry boundary=%s: %v", retryAt, err)
		}
		ready, err := reconcileTokenBucket(
			batched, capacity, batched.numerator, batched.denominator, retryAt,
		)
		if err != nil {
			t.Fatalf("retry-boundary reconciliation failed: %v", err)
		}
		_, retryAccepted, err := reserveTokenBalance(ready, units)
		if err != nil || !retryAccepted {
			t.Fatalf("retry boundary did not make reservation eligible: accepted=%t err=%v", retryAccepted, err)
		}
	})
}
