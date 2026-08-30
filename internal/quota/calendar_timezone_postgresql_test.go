package quota

import (
	"errors"
	"fmt"
	"testing"
)

func TestStorePostgreSQLCalendarTimezoneReservationSnapshotAndRecoveryEquality(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)
	inputFor := func(feature string) ReserveInput {
		input := fixture.input(t, feature, 10)
		input.Rules[0].Window = "1w"
		input.Rules[0].Timezone = "America/New_York"
		return input
	}
	assertSnapshot := func(input ReserveInput, wantUsed, wantReserved, wantRemaining int64, wantResetAtEqual Reservation) Snapshot {
		t.Helper()
		snapshot, err := fixture.store.Snapshot(fixture.ctx, snapshotInputFromReserve(input))
		if err != nil {
			t.Fatalf("snapshot %q: %v", input.FeatureKey, err)
		}
		if len(snapshot.Limits) != 1 {
			t.Fatalf("snapshot %q limits = %#v", input.FeatureKey, snapshot.Limits)
		}
		limit := snapshot.Limits[0]
		if limit.Maximum == nil || limit.Used == nil || limit.Reserved == nil ||
			limit.Remaining == nil || limit.ResetsAt == nil ||
			*limit.Maximum != 10 || *limit.Used != wantUsed ||
			*limit.Reserved != wantReserved || *limit.Remaining != wantRemaining ||
			!limit.ResetsAt.Equal(wantResetAtEqual.ResetAt()) {
			t.Fatalf("snapshot %q = %#v, reservation reset=%s", input.FeatureKey, limit, wantResetAtEqual.ResetAt())
		}
		return snapshot
	}

	input := inputFor("calendar-timezone-equality")
	reservation, err := fixture.store.Reserve(fixture.ctx, input)
	if err != nil || reservation.ResetAt().IsZero() {
		t.Fatalf("reserve week/IANA rule reset=%s err=%v", reservation.ResetAt(), err)
	}
	assertSnapshot(input, 0, 1, 9, reservation)
	attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
	if err != nil || !owner {
		t.Fatalf("begin week/IANA attempt owner=%t err=%v", owner, err)
	}
	if err := fixture.store.Settle(fixture.ctx, attempt, Outcome{Status: AttemptSucceeded, HTTPStatus: 204}); err != nil {
		t.Fatalf("settle week/IANA attempt: %v", err)
	}
	assertSnapshot(input, 1, 0, 9, reservation)

	// Changing only timezone must address a pristine independent bucket while
	// keeping the exact same scope and mutable maximum.
	utcInput := input
	utcInput.Rules = cloneRules(input.Rules)
	utcInput.Rules[0].Timezone = "UTC"
	utcSnapshot, err := fixture.store.Snapshot(fixture.ctx, snapshotInputFromReserve(utcInput))
	if err != nil {
		t.Fatal(err)
	}
	utcLimit := utcSnapshot.Limits[0]
	if utcLimit.Used == nil || utcLimit.Reserved == nil || utcLimit.Remaining == nil || utcLimit.ResetsAt == nil ||
		*utcLimit.Used != 0 || *utcLimit.Reserved != 0 || *utcLimit.Remaining != 10 ||
		utcLimit.ResetsAt.Equal(reservation.ResetAt()) {
		t.Fatalf("UTC timezone did not isolate calendar identity: %#v NY reset=%s", utcLimit, reservation.ResetAt())
	}

	pendingInput := inputFor("calendar-timezone-recovery")
	pending, err := fixture.store.Reserve(fixture.ctx, pendingInput)
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot(pendingInput, 0, 1, 9, pending)
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = $1
	`, pending.ID()); err != nil {
		t.Fatalf("backdate week/IANA reservation: %v", err)
	}
	processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
	if err != nil || processed != 1 {
		t.Fatalf("recover week/IANA reservation processed=%d err=%v", processed, err)
	}
	assertSnapshot(pendingInput, 0, 0, 10, pending)
	if replayed, replayErr := fixture.store.ExpirePendingBatch(fixture.ctx, 1); replayErr != nil || replayed != 0 {
		t.Fatalf("replay week/IANA recovery processed=%d err=%v", replayed, replayErr)
	}
}

func TestStorePostgreSQLCalendarTimezoneSettlementRecoveryRace(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)
	for iteration := range 4 {
		input := fixture.input(t, fmt.Sprintf("calendar-timezone-race-%d", iteration), 10)
		input.Rules[0].Window = "1w"
		input.Rules[0].Timezone = "America/New_York"
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("iteration %d reserve: %v", iteration, err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("iteration %d begin owner=%t err=%v", iteration, owner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = $1
		`, reservation.ID()); err != nil {
			t.Fatalf("iteration %d backdate: %v", iteration, err)
		}
		start := make(chan struct{})
		settled := make(chan error, 1)
		expired := make(chan struct {
			processed int64
			err       error
		}, 1)
		go func() {
			<-start
			settled <- fixture.store.Settle(fixture.ctx, attempt, Outcome{
				Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable",
			})
		}()
		go func() {
			<-start
			processed, expiryErr := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
			expired <- struct {
				processed int64
				err       error
			}{processed: processed, err: expiryErr}
		}()
		close(start)
		settleErr := <-settled
		expiry := <-expired
		settleWon := settleErr == nil && expiry.err == nil && expiry.processed == 0
		expiryWon := errors.Is(settleErr, ErrFinalized) && expiry.err == nil && expiry.processed == 1
		if !settleWon && !expiryWon {
			t.Fatalf("iteration %d settle=%v expiry=%d/%v", iteration, settleErr, expiry.processed, expiry.err)
		}
		snapshot, err := fixture.store.Snapshot(fixture.ctx, snapshotInputFromReserve(input))
		if err != nil {
			t.Fatalf("iteration %d snapshot: %v", iteration, err)
		}
		limit := snapshot.Limits[0]
		if limit.Used == nil || limit.Reserved == nil || limit.Remaining == nil || limit.ResetsAt == nil ||
			*limit.Used != 1 || *limit.Reserved != 0 || *limit.Remaining != 9 ||
			!limit.ResetsAt.Equal(reservation.ResetAt()) {
			t.Fatalf("iteration %d post-race snapshot=%#v reservation reset=%s", iteration, limit, reservation.ResetAt())
		}
	}
}
