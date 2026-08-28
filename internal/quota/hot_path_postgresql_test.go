package quota

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestStorePostgreSQLLifecycleHotPath(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("begin and first byte do not wait for shared quota buckets", func(t *testing.T) {
		input := lifecycleHotPathInput(t, fixture, "lifecycle-bucket-bypass", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve lifecycle fixture: %v", err)
		}

		blocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin bucket blocker: %v", err)
		}
		defer func() { _ = blocker.Rollback(fixture.ctx) }()
		lockHotPathQuotaBuckets(t, fixture.ctx, blocker, reservation.ID())

		operationCtx, cancel := context.WithTimeout(fixture.ctx, 2*time.Second)
		attempt, owner, err := fixture.store.BeginAttempt(operationCtx, reservation)
		cancel()
		if err != nil || !owner {
			t.Fatalf("begin attempt behind bucket locks owner=%t: %v", owner, err)
		}
		operationCtx, cancel = context.WithTimeout(fixture.ctx, 2*time.Second)
		replayed, replayOwner, err := fixture.store.BeginAttempt(operationCtx, reservation)
		cancel()
		if err != nil || replayOwner || replayed.ID() != attempt.ID() {
			t.Fatalf("begin replay behind bucket locks = %#v owner=%t: %v", replayed, replayOwner, err)
		}
		operationCtx, cancel = context.WithTimeout(fixture.ctx, 2*time.Second)
		err = fixture.store.MarkFirstByte(operationCtx, attempt)
		cancel()
		if err != nil {
			t.Fatalf("mark first byte behind bucket locks: %v", err)
		}
		operationCtx, cancel = context.WithTimeout(fixture.ctx, 2*time.Second)
		err = fixture.store.MarkFirstByte(operationCtx, attempt)
		cancel()
		if err != nil {
			t.Fatalf("mark first-byte replay behind bucket locks: %v", err)
		}

		assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
			LogicalRequestsMetric: {used: 0, reserved: 1, maximum: 1},
			InputTokensMetric:     {used: 0, reserved: 140, maximum: 140},
			OutputTokensMetric:    {used: 0, reserved: 8, maximum: 8},
			TotalTokensMetric:     {used: 0, reserved: 148, maximum: 148},
		})
		if err := blocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("release bucket blocker: %v", err)
		}

		outcome := hotPathSuccessOutcome()
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle lifecycle fixture: %v", err)
		}

		terminalBlocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin terminal bucket blocker: %v", err)
		}
		defer func() { _ = terminalBlocker.Rollback(fixture.ctx) }()
		lockHotPathQuotaBuckets(t, fixture.ctx, terminalBlocker, reservation.ID())
		operationCtx, cancel = context.WithTimeout(fixture.ctx, 2*time.Second)
		terminalAttempt, terminalOwner, err := fixture.store.BeginAttempt(operationCtx, reservation)
		cancel()
		if err != nil || terminalOwner || terminalAttempt.ID() != attempt.ID() {
			t.Fatalf("terminal begin replay behind bucket locks = %#v owner=%t: %v",
				terminalAttempt, terminalOwner, err)
		}
		operationCtx, cancel = context.WithTimeout(fixture.ctx, 2*time.Second)
		err = fixture.store.MarkFirstByte(operationCtx, attempt)
		cancel()
		if err != nil {
			t.Fatalf("terminal first-byte replay behind bucket locks: %v", err)
		}
		if err := terminalBlocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("release terminal bucket blocker: %v", err)
		}

		assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
			LogicalRequestsMetric: {used: 1, reserved: 0, maximum: 1},
			InputTokensMetric:     {used: 11, reserved: 0, maximum: 140},
			OutputTokensMetric:    {used: 7, reserved: 0, maximum: 8},
			TotalTokensMetric:     {used: 18, reserved: 0, maximum: 148},
		})
		assertHotPathTerminalCounts(t, fixture, input.FeatureKey, 1)
	})

	t.Run("request entry and concurrency lease locks remain fail closed", func(t *testing.T) {
		input := fixture.concurrencyInput(t, "lifecycle-private-locks", 1, 0, false, false)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve concurrency fixture: %v", err)
		}

		entryBlocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin reservation-entry blocker: %v", err)
		}
		defer func() { _ = entryBlocker.Rollback(fixture.ctx) }()
		lockHotPathReservationEntries(t, fixture.ctx, entryBlocker, reservation.ID())
		operationCtx, cancel := context.WithTimeout(fixture.ctx, 250*time.Millisecond)
		_, _, err = fixture.store.BeginAttempt(operationCtx, reservation)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("begin attempt behind reservation-entry lock = %v, want deadline", err)
		}
		if err := entryBlocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("release reservation-entry blocker: %v", err)
		}

		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin attempt after entry unlock owner=%t: %v", owner, err)
		}
		leaseBlocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin concurrency-lease blocker: %v", err)
		}
		defer func() { _ = leaseBlocker.Rollback(fixture.ctx) }()
		lockHotPathConcurrencyLeases(t, fixture.ctx, leaseBlocker, reservation.LogicalRequestID())
		operationCtx, cancel = context.WithTimeout(fixture.ctx, 250*time.Millisecond)
		err = fixture.store.MarkFirstByte(operationCtx, attempt)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("mark first byte behind concurrency-lease lock = %v, want deadline", err)
		}
		if err := leaseBlocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("release concurrency-lease blocker: %v", err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark first byte after lease unlock: %v", err)
		}
		if err := fixture.store.Settle(
			fixture.ctx, attempt, Outcome{Status: AttemptSucceeded, HTTPStatus: 204},
		); err != nil {
			t.Fatalf("settle concurrency fixture: %v", err)
		}
		assertConcurrencyEntryState(
			t, fixture, reservation.ID(), ConcurrentRequestsMetric, 1, 0, 1, 0, 0, true,
		)
	})

	t.Run("concurrent multi metric lifecycle settles exact usage without deadlines", func(t *testing.T) {
		const requests = 32
		reservations := make([]Reservation, requests)
		feature := "lifecycle-concurrent-accounting"
		for index := range reservations {
			input := lifecycleHotPathInput(t, fixture, feature, requests)
			reservation, err := fixture.store.Reserve(fixture.ctx, input)
			if err != nil {
				t.Fatalf("reserve request %d: %v", index, err)
			}
			reservations[index] = reservation
		}

		attempts := beginHotPathAttemptsConcurrently(t, fixture, reservations)
		markHotPathFirstBytesConcurrently(t, fixture, attempts)
		settleHotPathAttemptsConcurrently(t, fixture, attempts)

		assertHotPathBucketState(t, fixture, reservations[0].ID(), map[string]hotPathBucketExpectation{
			LogicalRequestsMetric: {used: requests, reserved: 0, maximum: requests},
			InputTokensMetric:     {used: requests * 11, reserved: 0, maximum: requests * 140},
			OutputTokensMetric:    {used: requests * 7, reserved: 0, maximum: requests * 8},
			TotalTokensMetric:     {used: requests * 18, reserved: 0, maximum: requests * 148},
		})
		assertHotPathTerminalCounts(t, fixture, feature, requests)
	})
}

type hotPathBucketExpectation struct {
	used     int64
	reserved int64
	maximum  int64
}

func lifecycleHotPathInput(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	feature string,
	requests int64,
) ReserveInput {
	t.Helper()
	input := fixture.calendarTokenInput(t, feature,
		calendarTokenReservation{metric: InputTokensMetric, maximum: requests * 140, reserved: 140},
		calendarTokenReservation{metric: OutputTokensMetric, maximum: requests * 8, reserved: 8},
		calendarTokenReservation{metric: TotalTokensMetric, maximum: requests * 148, reserved: 148},
	)
	input.Rules = append(input.Rules, Rule{
		Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user", "feature"}, Window: "1d",
		Maximum: requests, Hard: true,
	})
	return input
}

func hotPathSuccessOutcome() Outcome {
	return Outcome{
		Status: AttemptSucceeded, HTTPStatus: 200,
		Usage: Usage{
			InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
			Known: true, Provenance: ProviderReportedProvenance,
		},
	}
}

func lockHotPathQuotaBuckets(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	reservationID string,
) {
	t.Helper()
	lockHotPathRows(t, ctx, tx, "quota buckets", `
		SELECT bucket.quota_bucket_id
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket
		  ON bucket.organization_id = entry.organization_id
		 AND bucket.application_id = entry.application_id
		 AND bucket.environment_id = entry.environment_id
		 AND bucket.quota_bucket_id = entry.quota_bucket_id
		WHERE entry.quota_reservation_id = $1
		ORDER BY bucket.quota_bucket_id COLLATE "C"
		FOR UPDATE OF bucket
	`, reservationID)
}

func lockHotPathReservationEntries(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	reservationID string,
) {
	t.Helper()
	lockHotPathRows(t, ctx, tx, "reservation entries", `
		SELECT quota_reservation_entry_id
		FROM quota_reservation_entries
		WHERE quota_reservation_id = $1
		ORDER BY quota_reservation_entry_id COLLATE "C"
		FOR UPDATE
	`, reservationID)
}

func lockHotPathConcurrencyLeases(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	logicalRequestID string,
) {
	t.Helper()
	lockHotPathRows(t, ctx, tx, "concurrency leases", `
		SELECT concurrency_lease_id
		FROM concurrency_leases
		WHERE logical_request_id = $1
		ORDER BY concurrency_lease_id COLLATE "C"
		FOR UPDATE
	`, logicalRequestID)
}

func lockHotPathRows(
	t *testing.T,
	ctx context.Context,
	tx pgx.Tx,
	name string,
	query string,
	argument string,
) {
	t.Helper()
	rows, err := tx.Query(ctx, query, argument)
	if err != nil {
		t.Fatalf("lock %s: %v", name, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var ignored string
		if err := rows.Scan(&ignored); err != nil {
			t.Fatalf("scan locked %s: %v", name, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate locked %s: %v", name, err)
	}
	if count == 0 {
		t.Fatalf("locked %s = 0 rows, want at least one", name)
	}
}

func beginHotPathAttemptsConcurrently(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservations []Reservation,
) []Attempt {
	t.Helper()
	type result struct {
		index   int
		attempt Attempt
		owner   bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, len(reservations))
	var wait sync.WaitGroup
	for index, reservation := range reservations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ctx, cancel := context.WithTimeout(fixture.ctx, 10*time.Second)
			attempt, owner, err := fixture.store.BeginAttempt(ctx, reservation)
			cancel()
			results <- result{index: index, attempt: attempt, owner: owner, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	attempts := make([]Attempt, len(reservations))
	failures := make([]string, 0)
	deadlines := 0
	for result := range results {
		if errors.Is(result.err, context.DeadlineExceeded) {
			deadlines++
		}
		if result.err != nil || !result.owner {
			failures = append(failures, fmt.Sprintf("%d owner=%t err=%v", result.index, result.owner, result.err))
			continue
		}
		attempts[result.index] = result.attempt
	}
	if len(failures) != 0 {
		t.Fatalf("concurrent begin failures (deadlines=%d): %s", deadlines, strings.Join(failures, "; "))
	}
	return attempts
}

func markHotPathFirstBytesConcurrently(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	attempts []Attempt,
) {
	t.Helper()
	runHotPathAttemptsConcurrently(t, fixture, "mark first byte", attempts, func(ctx context.Context, attempt Attempt) error {
		return fixture.store.MarkFirstByte(ctx, attempt)
	})
}

func settleHotPathAttemptsConcurrently(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	attempts []Attempt,
) {
	t.Helper()
	outcome := hotPathSuccessOutcome()
	runHotPathAttemptsConcurrently(t, fixture, "settle", attempts, func(ctx context.Context, attempt Attempt) error {
		return fixture.store.Settle(ctx, attempt, outcome)
	})
}

func runHotPathAttemptsConcurrently(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	operation string,
	attempts []Attempt,
	perform func(context.Context, Attempt) error,
) {
	t.Helper()
	type result struct {
		index int
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, len(attempts))
	var wait sync.WaitGroup
	for index, attempt := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ctx, cancel := context.WithTimeout(fixture.ctx, 10*time.Second)
			err := perform(ctx, attempt)
			cancel()
			results <- result{index: index, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	failures := make([]string, 0)
	deadlines := 0
	for result := range results {
		if errors.Is(result.err, context.DeadlineExceeded) {
			deadlines++
		}
		if result.err != nil {
			failures = append(failures, fmt.Sprintf("%d err=%v", result.index, result.err))
		}
	}
	if len(failures) != 0 {
		t.Fatalf("concurrent %s failures (deadlines=%d): %s", operation, deadlines, strings.Join(failures, "; "))
	}
}

func assertHotPathBucketState(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationID string,
	want map[string]hotPathBucketExpectation,
) {
	t.Helper()
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT bucket.metric, bucket.used_units, bucket.reserved_units, bucket.hard_maximum
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket
		  ON bucket.organization_id = entry.organization_id
		 AND bucket.application_id = entry.application_id
		 AND bucket.environment_id = entry.environment_id
		 AND bucket.quota_bucket_id = entry.quota_bucket_id
		WHERE entry.quota_reservation_id = $1
	`, reservationID)
	if err != nil {
		t.Fatalf("read hot-path bucket state: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(want))
	for rows.Next() {
		var metric string
		var used, reserved, maximum int64
		if err := rows.Scan(&metric, &used, &reserved, &maximum); err != nil {
			t.Fatalf("scan hot-path bucket state: %v", err)
		}
		expected, ok := want[metric]
		if !ok {
			t.Fatalf("unexpected hot-path bucket metric %q", metric)
		}
		if _, duplicate := seen[metric]; duplicate {
			t.Fatalf("duplicate hot-path bucket metric %q", metric)
		}
		seen[metric] = struct{}{}
		if used != expected.used || reserved != expected.reserved || maximum != expected.maximum {
			t.Errorf("%s bucket used/reserved/maximum = %d/%d/%d, want %d/%d/%d",
				metric, used, reserved, maximum, expected.used, expected.reserved, expected.maximum)
		}
		if used > maximum-reserved {
			t.Errorf("%s bucket overspent: used=%d reserved=%d maximum=%d", metric, used, reserved, maximum)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate hot-path bucket state: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("hot-path bucket metrics = %v, want %v", seen, want)
	}
}

func assertHotPathTerminalCounts(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	feature string,
	requests int64,
) {
	t.Helper()
	var total, pending, settled, succeeded int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE reservation.status = 'pending'),
		       count(*) FILTER (WHERE reservation.status = 'settled'),
		       count(*) FILTER (WHERE request.status = 'succeeded')
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		WHERE request.feature_key = $1
	`, feature).Scan(&total, &pending, &settled, &succeeded); err != nil {
		t.Fatalf("read hot-path terminal reservation counts: %v", err)
	}
	if total != requests || pending != 0 || settled != requests || succeeded != requests {
		t.Errorf("terminal requests total/pending/settled/succeeded = %d/%d/%d/%d, want %d/0/%d/%d",
			total, pending, settled, succeeded, requests, requests, requests)
	}

	var attempts, incomplete int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*),
		       count(*) FILTER (
		           WHERE attempt.status <> $2 OR attempt.first_byte_at IS NULL
		       )
		FROM upstream_attempts AS attempt
		JOIN logical_requests AS request USING (logical_request_id)
		WHERE request.feature_key = $1
	`, feature, AttemptSucceeded).Scan(&attempts, &incomplete); err != nil {
		t.Fatalf("read hot-path terminal attempt counts: %v", err)
	}
	if attempts != requests || incomplete != 0 {
		t.Errorf("terminal attempts total/incomplete = %d/%d, want %d/0", attempts, incomplete, requests)
	}

	type usageExpectation struct {
		rows  int64
		units int64
	}
	wantUsage := map[string]usageExpectation{
		LogicalRequestsMetric: {rows: requests, units: requests},
		InputTokensMetric:     {rows: requests, units: requests * 11},
		OutputTokensMetric:    {rows: requests, units: requests * 7},
		TotalTokensMetric:     {rows: requests, units: requests * 18},
	}
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT usage.metric, count(*), sum(usage.units)
		FROM usage_records AS usage
		JOIN logical_requests AS request USING (logical_request_id)
		WHERE request.feature_key = $1
		GROUP BY usage.metric
	`, feature)
	if err != nil {
		t.Fatalf("read hot-path usage counts: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(wantUsage))
	for rows.Next() {
		var metric string
		var rowCount, units int64
		if err := rows.Scan(&metric, &rowCount, &units); err != nil {
			t.Fatalf("scan hot-path usage counts: %v", err)
		}
		expected, ok := wantUsage[metric]
		if !ok {
			t.Fatalf("unexpected hot-path usage metric %q", metric)
		}
		seen[metric] = struct{}{}
		if rowCount != expected.rows || units != expected.units {
			t.Errorf("%s usage rows/units = %d/%d, want %d/%d",
				metric, rowCount, units, expected.rows, expected.units)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate hot-path usage counts: %v", err)
	}
	if len(seen) != len(wantUsage) {
		t.Fatalf("hot-path usage metrics = %v, want %v", seen, wantUsage)
	}
}
