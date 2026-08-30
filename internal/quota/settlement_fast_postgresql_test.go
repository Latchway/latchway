package quota

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestStorePostgreSQLInitialFinalSettlementFastPath(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("canonical settlement writes exact accounting and timestamps", func(t *testing.T) {
		input, reservation, attempt, outcome := prepareInitialFinalSettlement(
			t, fixture, "initial-final-fast-exact", 1,
		)
		handled, err := fixture.store.settleInitialFinalAttempt(fixture.ctx, attempt, outcome)
		if err != nil || !handled {
			t.Fatalf("canonical initial settlement handled=%t: %v", handled, err)
		}
		assertInitialFinalSettlement(t, fixture, input, reservation, attempt)

		originalNewID := fixture.store.newID
		fixture.store.newID = func(id.Prefix) (string, error) {
			return "", errors.New("replay allocated an identifier")
		}
		replayErr := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome)
		fixture.store.newID = originalNewID
		if replayErr != nil {
			t.Fatalf("terminal replay with unavailable identifiers: %v", replayErr)
		}
		assertInitialFinalSettlement(t, fixture, input, reservation, attempt)
	})

	t.Run("completion follows blocking usage identifier generation", func(t *testing.T) {
		input, reservation, attempt, outcome := prepareInitialFinalSettlement(
			t, fixture, "initial-final-fast-id-clock", 1,
		)
		originalNewID := fixture.store.newID
		started := make(chan struct{})
		release := make(chan struct{})
		var signal sync.Once
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix == id.UsageRecord {
				signal.Do(func() { close(started) })
				<-release
			}
			return originalNewID(prefix)
		}
		type result struct {
			handled bool
			err     error
		}
		settled := make(chan result, 1)
		go func() {
			handled, err := fixture.store.settleInitialFinalAttempt(
				fixture.ctx, attempt, outcome,
			)
			settled <- result{handled: handled, err: err}
		}()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			fixture.store.newID = originalNewID
			t.Fatal("initial settlement did not reach usage identifier generation")
		}
		var identifierBoundary time.Time
		if err := fixture.pool.QueryRow(
			fixture.ctx, "SELECT statement_timestamp()",
		).Scan(&identifierBoundary); err != nil {
			close(release)
			fixture.store.newID = originalNewID
			t.Fatalf("capture identifier completion boundary: %v", err)
		}
		close(release)
		settlement := <-settled
		fixture.store.newID = originalNewID
		if settlement.err != nil || !settlement.handled {
			t.Fatalf("blocking identifier settlement handled=%t: %v",
				settlement.handled, settlement.err)
		}
		var attemptCompletedAt, logicalCompletedAt, reservationSettledAt, usageRecordedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT attempt.completed_at, request.completed_at, reservation.settled_at,
			       min(usage.recorded_at)
			FROM upstream_attempts AS attempt
			JOIN logical_requests AS request USING (logical_request_id)
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN usage_records AS usage USING (logical_request_id)
			WHERE attempt.upstream_attempt_id = $1
			GROUP BY attempt.completed_at, request.completed_at, reservation.settled_at
		`, attempt.ID()).Scan(
			&attemptCompletedAt, &logicalCompletedAt, &reservationSettledAt, &usageRecordedAt,
		); err != nil {
			t.Fatalf("read blocking identifier timestamps: %v", err)
		}
		for name, completedAt := range map[string]time.Time{
			"attempt": attemptCompletedAt, "logical": logicalCompletedAt,
			"reservation": reservationSettledAt, "usage": usageRecordedAt,
		} {
			if completedAt.Before(identifierBoundary) {
				t.Errorf("%s completion %s precedes identifier boundary %s",
					name, completedAt, identifierBoundary)
			}
		}
		assertInitialFinalSettlement(t, fixture, input, reservation, attempt)
	})

	t.Run("identifier failure performs no writes", func(t *testing.T) {
		input, reservation, attempt, outcome := prepareInitialFinalSettlement(
			t, fixture, "initial-final-fast-id-failure", 1,
		)
		originalNewID := fixture.store.newID
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix == id.UsageRecord {
				return "", errors.New("usage entropy unavailable")
			}
			return originalNewID(prefix)
		}
		settlementErr := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome)
		fixture.store.newID = originalNewID
		if settlementErr == nil || errors.Is(settlementErr, ErrInvalidState) {
			t.Fatalf("identifier failure settlement = %v, want generator failure", settlementErr)
		}
		assertInitialFinalPending(t, fixture, input, reservation, attempt)
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle after identifier failure: %v", err)
		}
		assertInitialFinalSettlement(t, fixture, input, reservation, attempt)
	})

	t.Run("concurrent identical settlers create one accounting set", func(t *testing.T) {
		input, reservation, attempt, outcome := prepareInitialFinalSettlement(
			t, fixture, "initial-final-fast-concurrent", 1,
		)
		const callers = 8
		start := make(chan struct{})
		failures := make(chan error, callers)
		var wait sync.WaitGroup
		for range callers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				if err := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome); err != nil {
					failures <- err
				}
			}()
		}
		close(start)
		wait.Wait()
		close(failures)
		for err := range failures {
			t.Errorf("concurrent identical settlement: %v", err)
		}
		assertInitialFinalSettlement(t, fixture, input, reservation, attempt)
	})

	t.Run("mid-write unique violation rolls back and leaves pool reusable", func(t *testing.T) {
		input, reservation, attempt, outcome := prepareInitialFinalSettlement(
			t, fixture, "initial-final-fast-write-rollback", 1,
		)
		otherInput := lifecycleHotPathInput(t, fixture, "initial-final-fast-id-owner", 1)
		otherReservation, err := fixture.store.Reserve(fixture.ctx, otherInput)
		if err != nil {
			t.Fatalf("reserve duplicate-ID owner: %v", err)
		}
		originalNewID := fixture.store.newID
		duplicateUsageID, err := originalNewID(id.UsageRecord)
		if err != nil {
			t.Fatalf("generate duplicate usage identifier: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				confidence, provenance_key, recorded_at
			) VALUES ($1, $2, $3, $4, $5, NULL, 'logical_requests', 1,
			          'calculated', $6, statement_timestamp())
		`, duplicateUsageID, quotaTestOrganizationID, quotaTestApplicationID,
			quotaTestEnvironmentID, otherReservation.LogicalRequestID(),
			"test-duplicate:"+otherReservation.LogicalRequestID()); err != nil {
			t.Fatalf("seed duplicate usage identifier: %v", err)
		}
		generated := 0
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix != id.UsageRecord {
				return originalNewID(prefix)
			}
			generated++
			if generated == 2 {
				return duplicateUsageID, nil
			}
			return originalNewID(prefix)
		}
		settlementErr := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome)
		fixture.store.newID = originalNewID
		if !errors.Is(settlementErr, ErrInvalidState) {
			t.Fatalf("mid-write duplicate settlement = %v, want ErrInvalidState", settlementErr)
		}
		assertInitialFinalPending(t, fixture, input, reservation, attempt)

		if err := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle through reused pool after rollback: %v", err)
		}
		assertInitialFinalSettlement(t, fixture, input, reservation, attempt)
	})

	t.Run("corrupt attempt allocation falls back and fails closed", func(t *testing.T) {
		input, reservation, attempt, outcome := prepareInitialFinalSettlement(
			t, fixture, "initial-final-fast-corrupt", 1,
		)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE upstream_attempt_quota_entries
			SET allocated_units = allocated_units - 1
			WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
		`, attempt.ID()); err != nil {
			t.Fatalf("corrupt attempt allocation: %v", err)
		}
		handled, fastErr := fixture.store.settleInitialFinalAttempt(fixture.ctx, attempt, outcome)
		if fastErr != nil || handled {
			t.Fatalf("corrupt initial settlement handled=%t: %v, want slow fallback", handled, fastErr)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, attempt, outcome); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("corrupt slow settlement = %v, want ErrInvalidState", err)
		}
		assertInitialFinalPending(t, fixture, input, reservation, attempt)
	})

	t.Run("calendar metric subset uses the fast path", func(t *testing.T) {
		input := fixture.outputInput(t, "initial-final-fast-output-fallback", 100, 20)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve output-only fallback: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin output-only fallback owner=%t: %v", owner, err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark output-only first byte: %v", err)
		}
		outcome := hotPathSuccessOutcome()
		handled, fastErr := fixture.store.settleInitialFinalAttempt(fixture.ctx, attempt, outcome)
		if fastErr != nil || !handled {
			t.Fatalf("output-only initial settlement handled=%t: %v", handled, fastErr)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, reservation.LogicalRequestID()); got != 4 {
			t.Fatalf("output-only fallback usage rows = %d, want 4", got)
		}
		assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
			LogicalRequestsMetric: {used: 1, reserved: 0, maximum: 10_000},
			OutputTokensMetric:    {used: 7, reserved: 0, maximum: 100},
		})
		assertHotPathTerminalCounts(t, fixture, input.FeatureKey, 1)
	})

	t.Run("per-request-only guard uses zero-row settlement batches", func(t *testing.T) {
		input := fixture.perRequestOutputInput(t, "initial-final-fast-per-request", 8, 8)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve per-request-only initial settlement: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin per-request-only initial settlement owner=%t: %v", owner, err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark per-request-only first byte: %v", err)
		}
		handled, fastErr := fixture.store.settleInitialFinalAttempt(
			fixture.ctx, attempt, hotPathSuccessOutcome(),
		)
		if fastErr != nil || !handled {
			t.Fatalf("per-request-only initial settlement handled=%t: %v", handled, fastErr)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM quota_reservation_entries WHERE quota_reservation_id = $1
		`, reservation.ID()); got != 0 {
			t.Fatalf("per-request-only reservation entries = %d, want 0", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempt_quota_entries WHERE upstream_attempt_id = $1
		`, attempt.ID()); got != 0 {
			t.Fatalf("per-request-only attempt quota entries = %d, want 0", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, reservation.LogicalRequestID()); got != 4 {
			t.Fatalf("per-request-only usage rows = %d, want 4", got)
		}
		assertHotPathTerminalCounts(t, fixture, input.FeatureKey, 1)
	})

	t.Run("duplicate metric scopes settle every calendar entry", func(t *testing.T) {
		input := lifecycleHotPathInput(t, fixture, "initial-final-fast-multi-scope", 1)
		input.Rules = append(input.Rules,
			Rule{
				Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user"}, Window: "1h", Maximum: 1, Hard: true,
			},
			Rule{
				Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user"}, Window: "1h", Maximum: 8,
				ReservedUnits: 8, Hard: true,
			},
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve multi-scope initial settlement: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin multi-scope initial settlement owner=%t: %v", owner, err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark multi-scope first byte: %v", err)
		}
		handled, fastErr := fixture.store.settleInitialFinalAttempt(
			fixture.ctx, attempt, hotPathSuccessOutcome(),
		)
		if fastErr != nil || !handled {
			t.Fatalf("multi-scope initial settlement handled=%t: %v", handled, fastErr)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			  AND entry.reserved_units = entry.settled_units + entry.released_units
			  AND bucket.reserved_units = 0
			  AND bucket.used_units = CASE bucket.metric
			        WHEN 'logical_requests' THEN 1
			        WHEN 'input_tokens' THEN 11
			        WHEN 'output_tokens' THEN 7
			        WHEN 'total_tokens' THEN 18
			      END
		`, reservation.ID()); got != 6 {
			t.Fatalf("settled multi-scope calendar entries = %d, want 6", got)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM upstream_attempt_quota_entries
			WHERE upstream_attempt_id = $1 AND settled_at IS NOT NULL
			  AND allocated_units = charged_units + released_units
		`, attempt.ID()); got != 4 {
			t.Fatalf("settled multi-scope attempt quota entries = %d, want 4", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, reservation.LogicalRequestID()); got != 4 {
			t.Fatalf("multi-scope usage rows = %d, want 4", got)
		}
		assertHotPathTerminalCounts(t, fixture, input.FeatureKey, 1)
	})
}

func prepareInitialFinalSettlement(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	feature string,
	requests int64,
) (ReserveInput, Reservation, Attempt, Outcome) {
	t.Helper()
	input := lifecycleHotPathInput(t, fixture, feature, requests)
	reservation, err := fixture.store.Reserve(fixture.ctx, input)
	if err != nil {
		t.Fatalf("reserve initial settlement: %v", err)
	}
	attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
	if err != nil || !owner {
		t.Fatalf("begin initial settlement owner=%t: %v", owner, err)
	}
	if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
		t.Fatalf("mark initial settlement first byte: %v", err)
	}
	return input, reservation, attempt, hotPathSuccessOutcome()
}

func assertInitialFinalSettlement(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	input ReserveInput,
	reservation Reservation,
	attempt Attempt,
) {
	t.Helper()
	assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
		LogicalRequestsMetric: {used: 1, reserved: 0, maximum: 1},
		InputTokensMetric:     {used: 11, reserved: 0, maximum: 140},
		OutputTokensMetric:    {used: 7, reserved: 0, maximum: 8},
		TotalTokensMetric:     {used: 18, reserved: 0, maximum: 148},
	})
	assertInitialFinalEntryAccounting(t, fixture, reservation.ID(), map[string][3]int64{
		LogicalRequestsMetric: {1, 1, 0},
		InputTokensMetric:     {140, 11, 129},
		OutputTokensMetric:    {8, 7, 1},
		TotalTokensMetric:     {148, 18, 130},
	})
	assertInitialFinalAttemptAccounting(t, fixture, attempt.ID(), map[string][3]int64{
		InputTokensMetric:  {140, 11, 129},
		OutputTokensMetric: {8, 7, 1},
		TotalTokensMetric:  {148, 18, 130},
	})
	assertInitialFinalUsage(t, fixture, reservation.LogicalRequestID(), attempt.ID())
	assertHotPathTerminalCounts(t, fixture, input.FeatureKey, 1)

	var firstByteAt, attemptCompletedAt, logicalCompletedAt, reservationSettledAt time.Time
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT attempt.first_byte_at, attempt.completed_at,
		       request.completed_at, reservation.settled_at
		FROM upstream_attempts AS attempt
		JOIN logical_requests AS request USING (logical_request_id)
		JOIN quota_reservations AS reservation USING (logical_request_id)
		WHERE attempt.upstream_attempt_id = $1
	`, attempt.ID()).Scan(
		&firstByteAt, &attemptCompletedAt, &logicalCompletedAt, &reservationSettledAt,
	); err != nil {
		t.Fatalf("read initial final timestamps: %v", err)
	}
	if attemptCompletedAt.Before(firstByteAt) || logicalCompletedAt.Before(attemptCompletedAt) ||
		reservationSettledAt.Before(attemptCompletedAt) {
		t.Fatalf("initial final timestamp order first=%s attempt=%s logical=%s reservation=%s",
			firstByteAt, attemptCompletedAt, logicalCompletedAt, reservationSettledAt)
	}
}

func assertInitialFinalPending(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	input ReserveInput,
	reservation Reservation,
	attempt Attempt,
) {
	t.Helper()
	assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
		LogicalRequestsMetric: {used: 0, reserved: 1, maximum: 1},
		InputTokensMetric:     {used: 0, reserved: 140, maximum: 140},
		OutputTokensMetric:    {used: 0, reserved: 8, maximum: 8},
		TotalTokensMetric:     {used: 0, reserved: 148, maximum: 148},
	})
	if got := fixture.count(t, `
		SELECT count(*)
		FROM quota_reservation_entries
		WHERE quota_reservation_id = $1 AND settled_units = 0 AND released_units = 0
	`, reservation.ID()); got != 4 {
		t.Fatalf("pending unchanged reservation entries = %d, want 4", got)
	}
	if got := fixture.count(t, `
		SELECT count(*)
		FROM upstream_attempt_quota_entries
		WHERE upstream_attempt_id = $1
		  AND charged_units IS NULL AND released_units IS NULL AND settled_at IS NULL
	`, attempt.ID()); got != 3 {
		t.Fatalf("pending unchanged attempt quota entries = %d, want 3", got)
	}
	if got := fixture.count(t, `
		SELECT count(*) FROM usage_records WHERE logical_request_id = $1
	`, reservation.LogicalRequestID()); got != 0 {
		t.Fatalf("pending usage rows = %d, want 0", got)
	}
	var logicalStatus, reservationStatus, attemptStatus string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT request.status, reservation.status, attempt.status
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		WHERE request.logical_request_id = $1
	`, input.LogicalRequestID.String()).Scan(
		&logicalStatus, &reservationStatus, &attemptStatus,
	); err != nil {
		t.Fatalf("read pending initial lifecycle: %v", err)
	}
	if logicalStatus != "streaming" || reservationStatus != "pending" || attemptStatus != "started" {
		t.Fatalf("pending initial lifecycle = %s/%s/%s", logicalStatus, reservationStatus, attemptStatus)
	}
}

func assertInitialFinalEntryAccounting(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationID string,
	want map[string][3]int64,
) {
	t.Helper()
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT bucket.metric, entry.reserved_units, entry.settled_units, entry.released_units
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE entry.quota_reservation_id = $1
	`, reservationID)
	if err != nil {
		t.Fatalf("read initial final reservation entries: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(want))
	for rows.Next() {
		var metric string
		var reserved, settled, released int64
		if err := rows.Scan(&metric, &reserved, &settled, &released); err != nil {
			t.Fatalf("scan initial final reservation entry: %v", err)
		}
		expected, ok := want[metric]
		if !ok || [3]int64{reserved, settled, released} != expected {
			t.Fatalf("initial final entry %s = %d/%d/%d, want %v",
				metric, reserved, settled, released, expected)
		}
		seen[metric] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate initial final reservation entries: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("initial final reservation entry metrics = %v, want %v", seen, want)
	}
}

func assertInitialFinalAttemptAccounting(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	attemptID string,
	want map[string][3]int64,
) {
	t.Helper()
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT metric, allocated_units, charged_units, released_units, settled_at
		FROM upstream_attempt_quota_entries
		WHERE upstream_attempt_id = $1
	`, attemptID)
	if err != nil {
		t.Fatalf("read initial final attempt accounting: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(want))
	for rows.Next() {
		var metric string
		var allocated, charged, released int64
		var settledAt time.Time
		if err := rows.Scan(&metric, &allocated, &charged, &released, &settledAt); err != nil {
			t.Fatalf("scan initial final attempt accounting: %v", err)
		}
		expected, ok := want[metric]
		if !ok || [3]int64{allocated, charged, released} != expected || settledAt.IsZero() {
			t.Fatalf("initial final attempt %s = %d/%d/%d at %s, want %v",
				metric, allocated, charged, released, settledAt, expected)
		}
		seen[metric] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate initial final attempt accounting: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("initial final attempt metrics = %v, want %v", seen, want)
	}
}

func assertInitialFinalUsage(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	logicalRequestID string,
	attemptID string,
) {
	t.Helper()
	type expectedUsage struct {
		attemptID  *string
		units      int64
		confidence string
		provenance string
	}
	storedAttemptID := attemptID
	want := map[string]expectedUsage{
		LogicalRequestsMetric: {
			units: 1, confidence: "calculated",
			provenance: logicalUsageProvenanceKey(logicalRequestID),
		},
		InputTokensMetric: {
			attemptID: &storedAttemptID, units: 11, confidence: "reported",
			provenance: providerUsageProvenanceKey(attemptID, InputTokensMetric),
		},
		OutputTokensMetric: {
			attemptID: &storedAttemptID, units: 7, confidence: "reported",
			provenance: providerUsageProvenanceKey(attemptID, OutputTokensMetric),
		},
		TotalTokensMetric: {
			attemptID: &storedAttemptID, units: 18, confidence: "reported",
			provenance: providerUsageProvenanceKey(attemptID, TotalTokensMetric),
		},
	}
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT upstream_attempt_id, metric, units, confidence, provenance_key, recorded_at
		FROM usage_records
		WHERE logical_request_id = $1
	`, logicalRequestID)
	if err != nil {
		t.Fatalf("read initial final usage: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(want))
	for rows.Next() {
		var gotAttemptID *string
		var metric, confidence, provenance string
		var units int64
		var recordedAt time.Time
		if err := rows.Scan(
			&gotAttemptID, &metric, &units, &confidence, &provenance, &recordedAt,
		); err != nil {
			t.Fatalf("scan initial final usage: %v", err)
		}
		expected, ok := want[metric]
		if !ok || units != expected.units || confidence != expected.confidence ||
			provenance != expected.provenance || recordedAt.IsZero() ||
			!optionalStringMatches(gotAttemptID, expected.attemptID) {
			t.Fatalf("initial final usage %s = %v/%d/%s/%s/%s, want %#v",
				metric, gotAttemptID, units, confidence, provenance, recordedAt, expected)
		}
		seen[metric] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate initial final usage: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("initial final usage metrics = %v, want %v", seen, want)
	}
}
