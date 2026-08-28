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
