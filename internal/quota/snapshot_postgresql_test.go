package quota

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const quotaSnapshotSecondRevisionID = "rev_00000000000000000000000002"

func TestStorePostgreSQLQuotaSnapshot(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)

	t.Run("missing mixed rules are pristine ordered and never materialized", func(t *testing.T) {
		input := snapshotInputFromReserve(fixture.input(t, "snapshot-missing", 1))
		input.Rules = []Rule{
			{Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm, Scope: []string{"installation"}, PerRequestMaximum: 32, Hard: true},
			{Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm, Scope: []string{"user", "feature"}, Window: "1d", Maximum: 10, Hard: true},
			{Metric: ConcurrentStreamsMetric, Algorithm: ConcurrencyAlgorithm, Scope: []string{"user"}, Maximum: 2, Hard: true},
			{Metric: OutputTokensMetric, Algorithm: TokenBucketAlgorithm, Scope: []string{"environment"}, Capacity: 50, RefillNumerator: 1, RefillDenominator: 2, Hard: true},
			{Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm, Scope: []string{"user"}, Maximum: 3, Hard: true},
			{Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm, Scope: []string{"feature"}, Capacity: 4, RefillNumerator: 1, RefillDenominator: 1, Hard: true},
			{Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm, Scope: []string{"user", "feature"}, Window: "1h", Maximum: 100, Hard: true},
		}
		before := fixture.count(t, `SELECT count(*) FROM quota_buckets`)
		snapshot, err := fixture.store.Snapshot(fixture.ctx, input)
		if err != nil {
			t.Fatalf("read missing mixed snapshot: %v", err)
		}
		if snapshot.Feature != input.FeatureKey || snapshot.ObservedAt.IsZero() ||
			snapshot.ObservedAt.Location() != time.UTC || len(snapshot.Limits) != len(input.Rules) {
			t.Fatalf("snapshot envelope = %#v", snapshot)
		}
		gotMetrics := make([]string, len(snapshot.Limits))
		var metadataCount, calendarCount, statefulWithoutReset int
		for index, limit := range snapshot.Limits {
			gotMetrics[index] = limit.Metric
			if !limit.Hard || limit.Maximum == nil {
				t.Fatalf("limit %d lacks hard maximum: %#v", index, limit)
			}
			switch {
			case limit.Used == nil:
				metadataCount++
				if limit.Reserved != nil || limit.Remaining != nil || limit.ResetsAt != nil ||
					limit.Metric != OutputTokensMetric || *limit.Maximum != 32 {
					t.Fatalf("per-request metadata = %#v", limit)
				}
			case limit.ResetsAt != nil:
				calendarCount++
				if !limit.ResetsAt.After(snapshot.ObservedAt) {
					t.Fatalf("calendar reset %s is not after observed_at %s", *limit.ResetsAt, snapshot.ObservedAt)
				}
			default:
				statefulWithoutReset++
			}
			if limit.Used != nil && (*limit.Used != 0 || *limit.Reserved != 0 ||
				*limit.Remaining != *limit.Maximum) {
				t.Fatalf("missing stateful limit is not pristine: %#v", limit)
			}
		}
		wantMetrics := []string{
			ConcurrentRequestsMetric, ConcurrentStreamsMetric,
			LogicalRequestsMetric, LogicalRequestsMetric,
			OutputTokensMetric, OutputTokensMetric, OutputTokensMetric,
		}
		if !slices.Equal(gotMetrics, wantMetrics) || metadataCount != 1 ||
			calendarCount != 2 || statefulWithoutReset != 4 {
			t.Fatalf("ordered mixed limits metrics=%v metadata=%d calendar=%d stateful-no-reset=%d",
				gotMetrics, metadataCount, calendarCount, statefulWithoutReset)
		}
		if after := fixture.count(t, `SELECT count(*) FROM quota_buckets`); after != before {
			t.Fatalf("snapshot materialized buckets: before=%d after=%d", before, after)
		}

		reversed := input
		reversed.Rules = cloneRules(input.Rules)
		slices.Reverse(reversed.Rules)
		again, err := fixture.store.Snapshot(fixture.ctx, reversed)
		if err != nil {
			t.Fatalf("read reversed snapshot: %v", err)
		}
		firstLimits := append([]LimitSnapshot(nil), snapshot.Limits...)
		secondLimits := append([]LimitSnapshot(nil), again.Limits...)
		for index := range firstLimits {
			// A call exactly across a real calendar boundary may legitimately
			// select a new reset instant; ordering and all public shapes remain
			// invariant.
			firstLimits[index].ResetsAt = nil
			secondLimits[index].ResetsAt = nil
		}
		if !reflect.DeepEqual(firstLimits, secondLimits) {
			t.Fatalf("caller rule order changed snapshot limits\nfirst=%#v\nagain=%#v", snapshot.Limits, again.Limits)
		}
	})

	t.Run("calendar counters and maximum transitions are read without mutation", func(t *testing.T) {
		first := fixture.input(t, "snapshot-calendar", 5)
		settledReservation, err := fixture.store.Reserve(fixture.ctx, first)
		if err != nil {
			t.Fatalf("reserve settled calendar request: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, settledReservation)
		if err != nil || !owner {
			t.Fatalf("begin settled calendar attempt owner=%t err=%v", owner, err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, Outcome{Status: AttemptSucceeded, HTTPStatus: 204}); err != nil {
			t.Fatalf("settle calendar request: %v", err)
		}

		pending := fixture.input(t, "snapshot-calendar", 5)
		pendingReservation, err := fixture.store.Reserve(fixture.ctx, pending)
		if err != nil {
			t.Fatalf("reserve pending calendar request: %v", err)
		}
		bucketID := onlyReservationBucketID(t, pendingReservation)
		before := readQuotaSnapshotFootprint(t, fixture, bucketID)

		selected := snapshotInputFromReserve(pending)
		selected.Rules[0].Maximum = 1
		snapshot, err := fixture.store.Snapshot(fixture.ctx, selected)
		if err != nil {
			t.Fatalf("snapshot decreased calendar maximum: %v", err)
		}
		limit := snapshot.Limits[0]
		if *limit.Maximum != 1 || *limit.Used != 1 || *limit.Reserved != 1 ||
			*limit.Remaining != 0 || limit.ResetsAt == nil {
			t.Fatalf("decreased calendar limit = %#v", limit)
		}
		if after := readQuotaSnapshotFootprint(t, fixture, bucketID); !reflect.DeepEqual(after, before) {
			t.Fatalf("calendar snapshot mutated row\nbefore=%#v\nafter=%#v", before, after)
		}

		locker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin bucket row locker: %v", err)
		}
		defer func() { _ = locker.Rollback(fixture.ctx) }()
		var lockedID string
		if err := locker.QueryRow(fixture.ctx, `
			SELECT quota_bucket_id FROM quota_buckets
			WHERE quota_bucket_id = $1
			FOR UPDATE
		`, bucketID).Scan(&lockedID); err != nil {
			t.Fatalf("lock quota bucket row: %v", err)
		}
		lockFreeContext, cancel := context.WithTimeout(fixture.ctx, time.Second)
		defer cancel()
		if _, err := fixture.store.Snapshot(lockFreeContext, selected); err != nil {
			t.Fatalf("snapshot waited on a bucket row lock: %v", err)
		}
		if err := locker.Rollback(fixture.ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatalf("release bucket row lock: %v", err)
		}

		selected.Rules[0].Maximum = 10
		snapshot, err = fixture.store.Snapshot(fixture.ctx, selected)
		if err != nil {
			t.Fatalf("snapshot increased calendar maximum: %v", err)
		}
		limit = snapshot.Limits[0]
		if *limit.Maximum != 10 || *limit.Used != 1 || *limit.Reserved != 1 || *limit.Remaining != 8 {
			t.Fatalf("increased calendar limit = %#v", limit)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, pendingReservation, "snapshot_test_done"); err != nil {
			t.Fatalf("release pending calendar request: %v", err)
		}
	})

	t.Run("fractional token refill and policy changes remain virtual", func(t *testing.T) {
		reserveInput := fixture.tokenBucketInput(t, "snapshot-token", 2, 1, 100)
		reservation, err := fixture.store.Reserve(fixture.ctx, reserveInput)
		if err != nil {
			t.Fatalf("reserve token bucket: %v", err)
		}
		bucketID := onlyReservationBucketID(t, reservation)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET available_units = 0,
			    refilled_at = statement_timestamp() - interval '50 seconds'
			WHERE quota_bucket_id = $1
		`, bucketID); err != nil {
			t.Fatalf("seed fractional token state: %v", err)
		}
		before := readQuotaSnapshotFootprint(t, fixture, bucketID)
		selected := snapshotInputFromReserve(reserveInput)
		snapshot, err := fixture.store.Snapshot(fixture.ctx, selected)
		if err != nil {
			t.Fatalf("snapshot fractional token state: %v", err)
		}
		limit := snapshot.Limits[0]
		if *limit.Maximum != 2 || *limit.Used != 2 || *limit.Reserved != 0 ||
			*limit.Remaining != 0 || limit.ResetsAt != nil {
			t.Fatalf("fractional token limit = %#v", limit)
		}
		if after := readQuotaSnapshotFootprint(t, fixture, bucketID); !reflect.DeepEqual(after, before) {
			t.Fatalf("token snapshot persisted virtual refill\nbefore=%#v\nafter=%#v", before, after)
		}

		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET available_units = hard_maximum * $2,
			    refilled_at = statement_timestamp()
			WHERE quota_bucket_id = $1
		`, bucketID, tokenBalanceScale); err != nil {
			t.Fatalf("seed full old token policy: %v", err)
		}
		selected.Rules[0].Capacity = 3
		selected.Rules[0].RefillNumerator = 1
		selected.Rules[0].RefillDenominator = 1
		snapshot, err = fixture.store.Snapshot(fixture.ctx, selected)
		if err != nil {
			t.Fatalf("snapshot increased token policy: %v", err)
		}
		limit = snapshot.Limits[0]
		if *limit.Maximum != 3 || *limit.Used != 1 || *limit.Remaining != 2 {
			t.Fatalf("increased token policy = %#v", limit)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "snapshot_test_done"); err != nil {
			t.Fatalf("release token reservation: %v", err)
		}
	})

	t.Run("concurrency includes streams and counts expired leases until durable release", func(t *testing.T) {
		reserveInput := fixture.concurrencyInput(t, "snapshot-concurrency", 3, 2, true, true)
		reservation, err := fixture.store.Reserve(fixture.ctx, reserveInput)
		if err != nil {
			t.Fatalf("reserve concurrency: %v", err)
		}
		selected := snapshotInputFromReserve(reserveInput)
		assertConcurrencySnapshot := func(wantReserved int64) {
			t.Helper()
			snapshot, err := fixture.store.Snapshot(fixture.ctx, selected)
			if err != nil {
				t.Fatalf("snapshot concurrency: %v", err)
			}
			if len(snapshot.Limits) != 2 || snapshot.Limits[0].Metric != ConcurrentRequestsMetric ||
				snapshot.Limits[1].Metric != ConcurrentStreamsMetric {
				t.Fatalf("concurrency limits = %#v", snapshot.Limits)
			}
			for _, limit := range snapshot.Limits {
				if *limit.Used != 0 || *limit.Reserved != wantReserved ||
					*limit.Remaining != *limit.Maximum-wantReserved || limit.ResetsAt != nil {
					t.Fatalf("concurrency limit = %#v", limit)
				}
			}
		}
		assertConcurrencySnapshot(1)
		backdateConcurrencyReservations(t, fixture, reservation.ID())
		assertConcurrencySnapshot(1)
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "snapshot_test_done"); err != nil {
			t.Fatalf("durably release concurrency: %v", err)
		}
		assertConcurrencySnapshot(0)
	})

	t.Run("tenant plan and revision boundaries fail closed", func(t *testing.T) {
		input := fixture.input(t, "snapshot-isolation", 4)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve isolated bucket: %v", err)
		}
		selected := snapshotInputFromReserve(input)
		wrongTenant := selected
		wrongTenant.OrganizationID = "org_00000000000000000000000002"
		if _, err := fixture.store.Snapshot(fixture.ctx, wrongTenant); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("cross-tenant snapshot = %v, want invalid state", err)
		}
		stale := selected
		stale.ConfigRevisionID = quotaSnapshotSecondRevisionID
		if _, err := fixture.store.Snapshot(fixture.ctx, stale); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("stale revision snapshot = %v, want invalid state", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			DELETE FROM active_config_revisions WHERE environment_id = $1
		`, quotaTestEnvironmentID); err != nil {
			t.Fatalf("remove active revision: %v", err)
		}
		if _, err := fixture.store.Snapshot(fixture.ctx, selected); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("missing active revision snapshot = %v, want invalid state", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			INSERT INTO active_config_revisions (
				organization_id, application_id, environment_id, config_revision_id,
				revision_status, activated_by_admin_user_id, activated_at
			) SELECT organization_id, application_id, environment_id,
			         config_revision_id, 'valid',
			         'adm_00000000000000000000000001', activated_at
			  FROM config_revisions
			 WHERE config_revision_id = $1
		`, quotaTestConfigRevisionID); err != nil {
			t.Fatalf("restore active revision: %v", err)
		}
		otherPlan := selected
		otherPlan.LimitPlanKey = "other-plan"
		snapshot, err := fixture.store.Snapshot(fixture.ctx, otherPlan)
		if err != nil {
			t.Fatalf("snapshot isolated missing plan: %v", err)
		}
		if *snapshot.Limits[0].Used != 0 || *snapshot.Limits[0].Reserved != 0 ||
			*snapshot.Limits[0].Remaining != *snapshot.Limits[0].Maximum {
			t.Fatalf("other plan leaked counters: %#v", snapshot.Limits[0])
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "snapshot_test_done"); err != nil {
			t.Fatalf("release isolated reservation: %v", err)
		}
	})

	t.Run("corrupt durable token state fails closed", func(t *testing.T) {
		reserveInput := fixture.tokenBucketInput(t, "snapshot-corrupt", 2, 1, 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, reserveInput)
		if err != nil {
			t.Fatalf("reserve corrupt token fixture: %v", err)
		}
		bucketID := onlyReservationBucketID(t, reservation)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET available_units = hard_maximum * $2 + 1
			WHERE quota_bucket_id = $1
		`, bucketID, tokenBalanceScale); err != nil {
			t.Fatalf("corrupt token balance: %v", err)
		}
		if _, err := fixture.store.Snapshot(fixture.ctx, snapshotInputFromReserve(reserveInput)); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("corrupt token snapshot = %v, want invalid state", err)
		}
	})

	t.Run("activation and bucket updates cannot produce a mixed transaction snapshot", func(t *testing.T) {
		input := fixture.multiRuleInput(t, "snapshot-race", 10, "1h", 10)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve transaction snapshot buckets: %v", err)
		}
		insertQuotaSnapshotSecondRevision(t, fixture)

		writer, err := fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin activation writer: %v", err)
		}
		defer func() { _ = writer.Rollback(fixture.ctx) }()
		if _, err := writer.Exec(fixture.ctx, `LOCK TABLE quota_buckets IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatalf("lock quota buckets for activation writer: %v", err)
		}

		selected := snapshotInputFromReserve(input)
		type snapshotResult struct {
			snapshot Snapshot
			err      error
		}
		resultChannel := make(chan snapshotResult, 1)
		go func() {
			snapshot, snapshotErr := fixture.store.Snapshot(fixture.ctx, selected)
			resultChannel <- snapshotResult{snapshot: snapshot, err: snapshotErr}
		}()
		waitForQuotaSnapshotBucketLock(t, fixture)

		if _, err := writer.Exec(fixture.ctx, `
			UPDATE quota_buckets AS bucket
			SET used_units = 1, reserved_units = 0, version = version + 1,
			    updated_at = statement_timestamp()
			FROM quota_reservation_entries AS entry
			WHERE entry.quota_bucket_id = bucket.quota_bucket_id
			  AND entry.quota_reservation_id = $1
		`, reservation.ID()); err != nil {
			t.Fatalf("write next bucket generation: %v", err)
		}
		if _, err := writer.Exec(fixture.ctx, `
			UPDATE config_revisions
			SET activated_at = statement_timestamp()
			WHERE config_revision_id = $1 AND status = 'valid' AND activated_at IS NULL
		`, quotaSnapshotSecondRevisionID); err != nil {
			t.Fatalf("mark next revision activated: %v", err)
		}
		if _, err := writer.Exec(fixture.ctx, `
			UPDATE active_config_revisions
			SET config_revision_id = $1, activated_at = statement_timestamp()
			WHERE organization_id = $2 AND application_id = $3 AND environment_id = $4
		`, quotaSnapshotSecondRevisionID, quotaTestOrganizationID,
			quotaTestApplicationID, quotaTestEnvironmentID); err != nil {
			t.Fatalf("activate next revision: %v", err)
		}
		if err := writer.Commit(fixture.ctx); err != nil {
			t.Fatalf("commit activation writer: %v", err)
		}

		raced := <-resultChannel
		if raced.err != nil {
			t.Fatalf("snapshot racing activation: %v", raced.err)
		}
		if len(raced.snapshot.Limits) != 2 {
			t.Fatalf("racing snapshot limits = %#v", raced.snapshot.Limits)
		}
		for _, limit := range raced.snapshot.Limits {
			if *limit.Used != 0 || *limit.Reserved != 1 || *limit.Remaining != 9 {
				t.Fatalf("racing snapshot mixed bucket generations: %#v", raced.snapshot.Limits)
			}
		}
		var activatedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT activated_at FROM active_config_revisions WHERE environment_id = $1
		`, quotaTestEnvironmentID).Scan(&activatedAt); err != nil {
			t.Fatalf("read activation time: %v", err)
		}
		if !raced.snapshot.ObservedAt.Before(activatedAt) {
			t.Fatalf("snapshot observed_at %s is not before raced activation %s",
				raced.snapshot.ObservedAt, activatedAt)
		}
		if _, err := fixture.store.Snapshot(fixture.ctx, selected); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("old revision after activation = %v, want invalid state", err)
		}
		selected.ConfigRevisionID = quotaSnapshotSecondRevisionID
		after, err := fixture.store.Snapshot(fixture.ctx, selected)
		if err != nil {
			t.Fatalf("snapshot newly active revision: %v", err)
		}
		for _, limit := range after.Limits {
			if *limit.Used != 1 || *limit.Reserved != 0 || *limit.Remaining != 9 {
				t.Fatalf("new revision did not see committed generation: %#v", after.Limits)
			}
		}
	})
}

type quotaSnapshotFootprint struct {
	HardMaximum       *int64
	Used              int64
	Reserved          int64
	Available         *int64
	RefillNumerator   *int64
	RefillDenominator *int64
	RefilledAt        *time.Time
	Version           int64
	UpdatedAt         time.Time
}

func readQuotaSnapshotFootprint(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	bucketID string,
) quotaSnapshotFootprint {
	t.Helper()
	var result quotaSnapshotFootprint
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT hard_maximum, used_units, reserved_units, available_units,
		       refill_numerator, refill_denominator, refilled_at, version, updated_at
		FROM quota_buckets
		WHERE quota_bucket_id = $1
	`, bucketID).Scan(
		&result.HardMaximum, &result.Used, &result.Reserved, &result.Available,
		&result.RefillNumerator, &result.RefillDenominator, &result.RefilledAt,
		&result.Version, &result.UpdatedAt,
	); err != nil {
		t.Fatalf("read quota snapshot footprint: %v", err)
	}
	return result
}

func onlyReservationBucketID(t *testing.T, reservation Reservation) string {
	t.Helper()
	if len(reservation.entries) != 1 || reservation.entries[0].bucketID == "" {
		t.Fatalf("reservation entries = %#v, want one bucket", reservation.entries)
	}
	return reservation.entries[0].bucketID
}

func activateQuotaSnapshotRevision(t *testing.T, fixture quotaPostgreSQLFixture) {
	t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE config_revisions
		SET status = 'valid', compiled_document = '{}'::jsonb,
		    validation_errors = '[]'::jsonb,
		    validation_report = jsonb_build_object(
		        'valid', true, 'checked_at', statement_timestamp(), 'issues', '[]'::jsonb
		    ),
		    validated_at = statement_timestamp() - interval '1 second',
		    activated_at = statement_timestamp() - interval '1 second'
		WHERE config_revision_id = $1 AND status = 'draft'
	`, quotaTestConfigRevisionID); err != nil {
		t.Fatalf("validate quota snapshot revision: %v", err)
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `
		INSERT INTO active_config_revisions (
			organization_id, application_id, environment_id, config_revision_id,
			revision_status, activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, 'valid', 'adm_00000000000000000000000001',
		          statement_timestamp() - interval '1 second')
	`, quotaTestOrganizationID, quotaTestApplicationID,
		quotaTestEnvironmentID, quotaTestConfigRevisionID); err != nil {
		t.Fatalf("activate quota snapshot revision: %v", err)
	}
}

func insertQuotaSnapshotSecondRevision(t *testing.T, fixture quotaPostgreSQLFixture) {
	t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_errors, validation_report, created_by_admin_user_id,
			validated_at
		) VALUES (
			$1, $2, $3, $4, 2, 'quota-snapshot-etag-002', 'valid', '{}'::jsonb,
			'{}'::jsonb, '[]'::jsonb,
			jsonb_build_object(
				'valid', true, 'checked_at', statement_timestamp(), 'issues', '[]'::jsonb
			),
			'adm_00000000000000000000000001', statement_timestamp()
		)
	`, quotaSnapshotSecondRevisionID, quotaTestOrganizationID,
		quotaTestApplicationID, quotaTestEnvironmentID); err != nil {
		t.Fatalf("insert second quota snapshot revision: %v", err)
	}
}

func waitForQuotaSnapshotBucketLock(t *testing.T, fixture quotaPostgreSQLFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_stat_activity
				WHERE datname = current_database()
				  AND pid <> pg_backend_pid()
				  AND wait_event_type = 'Lock'
				  AND query LIKE '%requested.ordinality%'
			)
		`).Scan(&waiting); err != nil {
			t.Fatalf("inspect quota snapshot lock wait: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("quota snapshot did not reach the blocked bucket read")
}
