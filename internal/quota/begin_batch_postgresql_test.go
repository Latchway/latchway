package quota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestStorePostgreSQLBeginInsertBatch(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("late allocation failure rolls back dispatch attempt and earlier allocations", func(t *testing.T) {
		input := lifecycleHotPathInput(t, fixture, "begin-batch-rollback", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			CREATE FUNCTION reject_begin_batch_test_allocation() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF (SELECT count(*) FROM upstream_attempt_quota_entries
				    WHERE upstream_attempt_id = NEW.upstream_attempt_id) = 2 THEN
					RAISE EXCEPTION 'injected third-allocation failure' USING ERRCODE = 'XX000';
				END IF;
				RETURN NEW;
			END;
			$$;
			CREATE TRIGGER begin_batch_test_failure BEFORE INSERT ON upstream_attempt_quota_entries
			FOR EACH ROW EXECUTE FUNCTION reject_begin_batch_test_allocation()
		`); err != nil {
			t.Fatal(err)
		}
		drop := func(ctx context.Context) {
			_, _ = fixture.pool.Exec(ctx, `DROP TRIGGER IF EXISTS begin_batch_test_failure ON upstream_attempt_quota_entries`)
			_, _ = fixture.pool.Exec(ctx, `DROP FUNCTION IF EXISTS reject_begin_batch_test_allocation()`)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			drop(ctx)
		})
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if !errors.Is(err, ErrDependency) || owner || attempt.ID() != "" {
			t.Fatalf("injected late allocation failure owner=%t attempt=%q: %v", owner, attempt.ID(), err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM logical_requests
			WHERE logical_request_id = $1 AND status = 'reserved' AND dispatched_at IS NULL`, reservation.LogicalRequestID()); got != 1 {
			t.Fatal("failed insert batch persisted the earlier dispatch update")
		}
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, reservation.LogicalRequestID()); got != 0 {
			t.Fatalf("failed insert batch persisted %d attempts", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempt_quota_entries WHERE logical_request_id = $1`, reservation.LogicalRequestID()); got != 0 {
			t.Fatalf("failed insert batch persisted %d allocations", got)
		}
		assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
			LogicalRequestsMetric: {reserved: 1, maximum: 1},
			InputTokensMetric:     {reserved: 140, maximum: 140},
			OutputTokensMetric:    {reserved: 8, maximum: 8},
			TotalTokensMetric:     {reserved: 148, maximum: 148},
		})
		drop(fixture.ctx)
		attempt, owner, err = fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("reuse pool and reservation after rollback owner=%t: %v", owner, err)
		}
		assertBeginBatchAllocations(t, fixture, reservation, attempt, 3)
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, hotPathSuccessOutcome()); err != nil {
			t.Fatal(err)
		}
		assertHotPathTerminalCounts(t, fixture, input.FeatureKey, 1)
	})

	t.Run("zero one and three allocations retain replay ownership and exact counts", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			input ReserveInput
			count int64
		}{
			{"entryless", fixture.perRequestOutputInput(t, "begin-batch-entryless", 128, 64), 0},
			{"logical-only", fixture.input(t, "begin-batch-logical-only", 1), 0},
			{"output-only", fixture.calendarTokenInput(t, "begin-batch-output-only",
				calendarTokenReservation{metric: OutputTokensMetric, maximum: 8, reserved: 8}), 1},
			{"three-token", lifecycleHotPathInput(t, fixture, "begin-batch-three-token", 1), 3},
		} {
			t.Run(test.name, func(t *testing.T) {
				reservation, err := fixture.store.Reserve(fixture.ctx, test.input)
				if err != nil {
					t.Fatal(err)
				}
				attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
				if err != nil || !owner {
					t.Fatalf("initial begin owner=%t: %v", owner, err)
				}
				assertBeginBatchAllocations(t, fixture, reservation, attempt, test.count)
				assertReplay := func() {
					t.Helper()
					originalNewID := fixture.store.newID
					fixture.store.newID = func(id.Prefix) (string, error) { return "", errors.New("replay allocated an identifier") }
					replayed, replayOwner, replayErr := fixture.store.BeginAttempt(fixture.ctx, reservation)
					fixture.store.newID = originalNewID
					if replayErr != nil || replayOwner || replayed.ID() != attempt.ID() {
						t.Fatalf("begin replay owner=%t: %v", replayOwner, replayErr)
					}
					assertBeginBatchAllocations(t, fixture, reservation, attempt, test.count)
				}
				assertReplay()
				if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
					t.Fatal(err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, hotPathSuccessOutcome()); err != nil {
					t.Fatal(err)
				}
				assertReplay()
			})
		}
	})
}

func assertBeginBatchAllocations(t *testing.T, fixture quotaPostgreSQLFixture, reservation Reservation, attempt Attempt, want int64) {
	t.Helper()
	if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, reservation.LogicalRequestID()); got != 1 {
		t.Fatalf("attempt count = %d, want 1", got)
	}
	if got := fixture.count(t, `SELECT count(*) FROM upstream_attempt_quota_entries
		WHERE upstream_attempt_id = $1`, attempt.ID()); got != want {
		t.Fatalf("allocation count = %d, want %d", got, want)
	}
	if got := fixture.count(t, `SELECT count(*) FROM upstream_attempt_quota_entries AS allocation
		JOIN quota_reservation_entries AS entry USING (quota_reservation_entry_id)
		WHERE allocation.upstream_attempt_id = $1
		  AND allocation.organization_id = $2 AND allocation.application_id = $3
		  AND allocation.environment_id = $4 AND allocation.logical_request_id = $5
		  AND allocation.quota_reservation_id = $6 AND allocation.quota_bucket_id = entry.quota_bucket_id
		  AND allocation.allocated_units = entry.initial_reserved_units`, attempt.ID(),
		reservation.organizationID, reservation.applicationID, reservation.environmentID,
		reservation.LogicalRequestID(), reservation.ID()); got != want {
		t.Fatalf("exact allocation attribution/unit count = %d, want %d", got, want)
	}
}
