package quota

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestStorePostgreSQLInputAndTotalCalendarSnapshot(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)

	input := snapshotInputFromReserve(fixture.input(t, "snapshot-input-total", 1))
	input.Rules = []Rule{
		{
			Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: 100, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: 250, Hard: true,
		},
	}

	beforeCount := fixture.count(t, `SELECT count(*) FROM quota_buckets`)
	pristine, err := fixture.store.Snapshot(fixture.ctx, input)
	if err != nil {
		t.Fatalf("read pristine input/total snapshot: %v", err)
	}
	assertInputTotalCalendarSnapshot(t, pristine, map[string]calendarSnapshotCounters{
		InputTokensMetric: {maximum: 100},
		TotalTokensMetric: {maximum: 250},
	})
	if afterCount := fixture.count(t, `SELECT count(*) FROM quota_buckets`); afterCount != beforeCount {
		t.Fatalf("pristine snapshot materialized buckets: before=%d after=%d", beforeCount, afterCount)
	}

	prepared, err := prepareSnapshot(input)
	if err != nil {
		t.Fatalf("prepare input/total snapshot: %v", err)
	}
	currentPlans, err := snapshotPlansAt(prepared.rules, pristine.ObservedAt)
	if err != nil {
		t.Fatalf("plan current input/total snapshot: %v", err)
	}
	// Seed the immediately following UTC window as well so this integration
	// test remains deterministic if the second snapshot crosses midnight.
	nextPlans, err := snapshotPlansAt(prepared.rules, currentPlans[0].period.end)
	if err != nil {
		t.Fatalf("plan next input/total snapshot: %v", err)
	}
	want := map[string]calendarSnapshotCounters{
		InputTokensMetric: {maximum: 100, used: 24, reserved: 6},
		TotalTokensMetric: {maximum: 250, used: 80, reserved: 20},
	}
	bucketIDs := seedInputTotalCalendarSnapshotBuckets(
		t, fixture, input, want, currentPlans, nextPlans,
	)
	beforeRows := make(map[string]quotaSnapshotFootprint, len(bucketIDs))
	for _, bucketID := range bucketIDs {
		beforeRows[bucketID] = readQuotaSnapshotFootprint(t, fixture, bucketID)
	}

	populated, err := fixture.store.Snapshot(fixture.ctx, input)
	if err != nil {
		t.Fatalf("read populated input/total snapshot: %v", err)
	}
	assertInputTotalCalendarSnapshot(t, populated, want)
	for _, bucketID := range bucketIDs {
		if after := readQuotaSnapshotFootprint(t, fixture, bucketID); !reflect.DeepEqual(after, beforeRows[bucketID]) {
			t.Fatalf("snapshot mutated bucket %s\nbefore=%#v\nafter=%#v",
				bucketID, beforeRows[bucketID], after)
		}
	}

	for _, metric := range []string{InputTokensMetric, TotalTokensMetric} {
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET refilled_at = statement_timestamp()
			WHERE environment_id = $1 AND metric = $2
		`, input.EnvironmentID, metric); err != nil {
			t.Fatalf("corrupt %s calendar state: %v", metric, err)
		}
		corruptRows := make(map[string]quotaSnapshotFootprint, len(bucketIDs))
		for _, bucketID := range bucketIDs {
			corruptRows[bucketID] = readQuotaSnapshotFootprint(t, fixture, bucketID)
		}
		if _, err := fixture.store.Snapshot(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("corrupt %s snapshot = %v, want ErrInvalidState", metric, err)
		}
		for _, bucketID := range bucketIDs {
			if after := readQuotaSnapshotFootprint(t, fixture, bucketID); !reflect.DeepEqual(after, corruptRows[bucketID]) {
				t.Fatalf("failed %s snapshot mutated bucket %s\nbefore=%#v\nafter=%#v",
					metric, bucketID, corruptRows[bucketID], after)
			}
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET refilled_at = NULL
			WHERE environment_id = $1 AND metric = $2
		`, input.EnvironmentID, metric); err != nil {
			t.Fatalf("repair %s calendar state: %v", metric, err)
		}
	}
}

func TestStorePostgreSQLInputAndTotalTokenBucketAndPerRequestSnapshot(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)

	reserveInput := trustedTokenShapeInput(t, fixture, "snapshot-input-total-modern", []Rule{
		{
			Metric: InputTokensMetric, Algorithm: TokenBucketAlgorithm,
			Scope: []string{"user", "feature"}, Capacity: 100,
			RefillNumerator: 1, RefillDenominator: tokenRateDecimalScale,
			ReservedUnits: 20, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: TokenBucketAlgorithm,
			Scope: []string{"user", "feature"}, Capacity: 250,
			RefillNumerator: 1, RefillDenominator: tokenRateDecimalScale,
			ReservedUnits: 35, Hard: true,
		},
		{
			Metric: InputTokensMetric, Algorithm: PerRequestAlgorithm,
			Scope: []string{"user", "feature"}, PerRequestMaximum: 64,
			ReservedUnits: 20, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: PerRequestAlgorithm,
			Scope: []string{"user", "feature"}, PerRequestMaximum: 128,
			ReservedUnits: 35, Hard: true,
		},
	}, 20, 15)
	snapshotInput := snapshotInputFromReserve(reserveInput)
	for index := range snapshotInput.Rules {
		snapshotInput.Rules[index].ReservedUnits = 0
	}

	beforeCount := fixture.count(t, `SELECT count(*) FROM quota_buckets`)
	pristine, err := fixture.store.Snapshot(fixture.ctx, snapshotInput)
	if err != nil {
		t.Fatalf("read pristine token/per-request snapshot: %v", err)
	}
	assertModernInputTotalSnapshot(t, pristine, 0, 0)
	if afterCount := fixture.count(t, `SELECT count(*) FROM quota_buckets`); afterCount != beforeCount {
		t.Fatalf("pristine modern snapshot materialized buckets: before=%d after=%d", beforeCount, afterCount)
	}

	reservation, err := fixture.store.Reserve(fixture.ctx, reserveInput)
	if err != nil {
		t.Fatalf("reserve modern snapshot counters: %v", err)
	}
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT quota_bucket_id
		FROM quota_buckets
		WHERE environment_id = $1 AND algorithm = 'token_bucket'
		  AND metric IN ('input_tokens', 'total_tokens')
	`, reserveInput.EnvironmentID)
	if err != nil {
		t.Fatalf("list modern snapshot buckets: %v", err)
	}
	var bucketIDs []string
	for rows.Next() {
		var bucketID string
		if err := rows.Scan(&bucketID); err != nil {
			rows.Close()
			t.Fatalf("scan modern snapshot bucket: %v", err)
		}
		bucketIDs = append(bucketIDs, bucketID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("iterate modern snapshot buckets: %v", err)
	}
	rows.Close()
	if len(bucketIDs) != 2 {
		t.Fatalf("modern snapshot bucket IDs = %#v", bucketIDs)
	}
	beforeRows := make(map[string]quotaSnapshotFootprint, len(bucketIDs))
	for _, bucketID := range bucketIDs {
		beforeRows[bucketID] = readQuotaSnapshotFootprint(t, fixture, bucketID)
	}

	populated, err := fixture.store.Snapshot(fixture.ctx, snapshotInput)
	if err != nil {
		t.Fatalf("read populated token/per-request snapshot: %v", err)
	}
	assertModernInputTotalSnapshot(t, populated, 20, 35)
	for _, bucketID := range bucketIDs {
		if after := readQuotaSnapshotFootprint(t, fixture, bucketID); !reflect.DeepEqual(after, beforeRows[bucketID]) {
			t.Fatalf("modern snapshot mutated bucket %s\nbefore=%#v\nafter=%#v",
				bucketID, beforeRows[bucketID], after)
		}
	}
	if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "snapshot_done"); err != nil {
		t.Fatalf("release modern snapshot reservation: %v", err)
	}
}

func assertModernInputTotalSnapshot(t *testing.T, snapshot Snapshot, inputUsed, totalUsed int64) {
	t.Helper()
	if snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.Location() != time.UTC || len(snapshot.Limits) != 4 {
		t.Fatalf("modern input/total snapshot envelope = %#v", snapshot)
	}
	type expectedLimit struct {
		metric              string
		maximum, used, left int64
		stateful            bool
	}
	want := map[int64]expectedLimit{
		100: {metric: InputTokensMetric, maximum: 100, used: inputUsed, left: 100 - inputUsed, stateful: true},
		250: {metric: TotalTokensMetric, maximum: 250, used: totalUsed, left: 250 - totalUsed, stateful: true},
		64:  {metric: InputTokensMetric, maximum: 64},
		128: {metric: TotalTokensMetric, maximum: 128},
	}
	for _, limit := range snapshot.Limits {
		if limit.Maximum == nil {
			t.Fatalf("modern limit omitted maximum: %#v", limit)
		}
		expected, ok := want[*limit.Maximum]
		if !ok || limit.Metric != expected.metric || !limit.Hard || limit.ResetsAt != nil {
			t.Fatalf("unexpected modern limit: %#v", limit)
		}
		delete(want, *limit.Maximum)
		if expected.stateful {
			if limit.Used == nil || *limit.Used != expected.used ||
				limit.Reserved == nil || *limit.Reserved != 0 ||
				limit.Remaining == nil || *limit.Remaining != expected.left {
				t.Fatalf("stateful modern limit = %#v, want %+v", limit, expected)
			}
		} else if limit.Used != nil || limit.Reserved != nil || limit.Remaining != nil {
			t.Fatalf("per-request modern limit exposed counters: %#v", limit)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing modern limits: %+v", want)
	}
}

type calendarSnapshotCounters struct {
	maximum  int64
	used     int64
	reserved int64
}

func assertInputTotalCalendarSnapshot(
	t *testing.T,
	snapshot Snapshot,
	want map[string]calendarSnapshotCounters,
) {
	t.Helper()
	if snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.Location() != time.UTC ||
		len(snapshot.Limits) != len(want) {
		t.Fatalf("input/total snapshot envelope = %#v", snapshot)
	}
	period, err := calendarWindow(snapshot.ObservedAt, "1d")
	if err != nil {
		t.Fatalf("snapshot calendar window: %v", err)
	}
	seen := make(map[string]bool, len(snapshot.Limits))
	for _, limit := range snapshot.Limits {
		counters, ok := want[limit.Metric]
		if !ok || seen[limit.Metric] {
			t.Fatalf("unexpected input/total limit = %#v", limit)
		}
		seen[limit.Metric] = true
		remaining := counters.maximum - counters.used - counters.reserved
		if limit.Maximum == nil || *limit.Maximum != counters.maximum ||
			limit.Used == nil || *limit.Used != counters.used ||
			limit.Reserved == nil || *limit.Reserved != counters.reserved ||
			limit.Remaining == nil || *limit.Remaining != remaining ||
			limit.ResetsAt == nil || limit.ResetsAt.Location() != time.UTC ||
			!limit.ResetsAt.Equal(period.end) || !limit.Hard {
			t.Fatalf("%s calendar limit = %#v", limit.Metric, limit)
		}
	}
}

func seedInputTotalCalendarSnapshotBuckets(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	input SnapshotInput,
	counters map[string]calendarSnapshotCounters,
	planSets ...[]snapshotPlan,
) []string {
	t.Helper()
	bucketIDs := make([]string, 0, len(planSets)*len(counters))
	for _, plans := range planSets {
		for _, plan := range plans {
			values, ok := counters[plan.rule.Metric]
			if !ok {
				t.Fatalf("missing seed counters for %s", plan.rule.Metric)
			}
			bucketID := id.Must(id.QuotaBucket)
			if _, err := fixture.pool.Exec(fixture.ctx, `
				INSERT INTO quota_buckets (
					quota_bucket_id, organization_id, application_id, environment_id,
					limit_plan_key, rule_key, metric, scope_type, scope_dimensions,
					scope_key, algorithm, window_key, hard_maximum,
					used_units, reserved_units
				) VALUES (
					$1, $2, $3, $4, $5, $6, $7, $8, $9,
					$10, $11, $12, $13, $14, $15
				)
			`, bucketID, input.OrganizationID, input.ApplicationID, input.EnvironmentID,
				input.LimitPlanKey, plan.rule.ruleKey, plan.rule.Metric, plan.rule.scopeType,
				plan.rule.scopeDimensions, plan.rule.scopeKey, plan.rule.Algorithm,
				plan.period.key, values.maximum, values.used, values.reserved); err != nil {
				t.Fatalf("seed %s calendar bucket: %v", plan.rule.Metric, err)
			}
			bucketIDs = append(bucketIDs, bucketID)
		}
	}
	return bucketIDs
}
