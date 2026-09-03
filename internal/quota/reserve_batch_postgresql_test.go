package quota

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

func TestStorePostgreSQLReserveBatch(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("combined provenance and capacity writes roll back on every failure boundary", func(t *testing.T) {
		for _, test := range []struct {
			name, table, event, body string
			want                     error
		}{
			{"stage", "logical_request_decision_stages", "INSERT",
				"IF NEW.stage = 'quota_reserved' THEN RAISE EXCEPTION 'injected reserve batch failure' USING ERRCODE = 'XX000'; END IF; RETURN NEW;", ErrDependency},
			{"entry", "quota_reservation_entries", "INSERT",
				"RAISE EXCEPTION 'injected reserve batch failure' USING ERRCODE = 'XX000';", ErrDependency},
			{"bucket_row_count", "quota_buckets", "UPDATE", "RETURN NULL;", ErrInvalidState},
		} {
			t.Run(test.name, func(t *testing.T) {
				input := lifecycleHotPathInput(t, fixture, "reserve-batch-rollback-"+test.name, 1)
				authenticated, err := fixture.store.BeginAuthenticatedRequest(fixture.ctx, authenticatedInputFromReserve(input))
				if err != nil {
					t.Fatal(err)
				}
				at := time.Now().UTC()
				if err := fixture.store.RecordDecisionStages(fixture.ctx, authenticated, []DecisionStage{{
					Stage: DecisionIdentityVerified, Outcome: DecisionSucceeded, StartedAt: at, CompletedAt: at,
				}}); err != nil {
					t.Fatal(err)
				}
				// Every interpolated value below is a fixed test-case constant, never input.
				if _, err := fixture.pool.Exec(fixture.ctx,
					"CREATE FUNCTION reject_reserve_batch_test_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "+test.body+" END; $$"); err != nil {
					t.Fatal(err)
				}
				table := pgx.Identifier{test.table}.Sanitize()
				drop := func(ctx context.Context) {
					_, _ = fixture.pool.Exec(ctx, "DROP TRIGGER IF EXISTS reserve_batch_test_failure ON "+table)
					_, _ = fixture.pool.Exec(ctx, "DROP FUNCTION IF EXISTS reject_reserve_batch_test_write()")
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					drop(ctx)
				})
				if _, err := fixture.pool.Exec(fixture.ctx,
					"CREATE TRIGGER reserve_batch_test_failure BEFORE "+test.event+" ON "+table+
						" FOR EACH ROW EXECUTE FUNCTION reject_reserve_batch_test_write()"); err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, test.want) {
					t.Fatalf("injected %s failure = %v, want %v", test.name, err, test.want)
				}
				if got := fixture.count(t, `SELECT count(*) FROM logical_requests
					WHERE logical_request_id = $1 AND status = 'authenticated'`, input.LogicalRequestID.String()); got != 1 {
					t.Fatal("failed batch changed the preexisting authenticated lifecycle")
				}
				if got := fixture.count(t, `SELECT count(*) FROM logical_request_decision_stages
					WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 1 {
					t.Fatalf("failed batch persisted %d stages, want only the original identity stage", got)
				}
				if got := fixture.count(t, `SELECT count(*) FROM quota_reservations
					WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 0 {
					t.Fatalf("failed batch persisted %d reservations", got)
				}
				prepared, err := prepareRequest(input)
				if err != nil {
					t.Fatal(err)
				}
				if got := fixture.count(t, `SELECT count(*) FROM quota_buckets
					WHERE environment_id = $1 AND scope_key = $2`, input.EnvironmentID, prepared.rules[0].scopeKey); got != 0 {
					t.Fatalf("failed batch persisted %d new capacity rows", got)
				}
				drop(fixture.ctx)
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				if err != nil {
					t.Fatalf("reuse pool and authenticated request after rollback: %v", err)
				}
				assertReserveBatchStages(t, fixture, input, 1)
				originalNewID := fixture.store.newID
				fixture.store.newID = func(id.Prefix) (string, error) { return "", errors.New("replay allocated an identifier") }
				replayed, replayErr := fixture.store.Reserve(fixture.ctx, input)
				fixture.store.newID = originalNewID
				if replayErr != nil || replayed.ID() != reservation.ID() {
					t.Fatalf("reserve replay = %#v, %v", replayed, replayErr)
				}
				assertReserveBatchStages(t, fixture, input, 1)
				assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
					LogicalRequestsMetric: {reserved: 1, maximum: 1},
					InputTokensMetric:     {reserved: 140, maximum: 140},
					OutputTokensMetric:    {reserved: 8, maximum: 8},
					TotalTokensMetric:     {reserved: 148, maximum: 148},
				})
			})
		}
	})

	t.Run("overlapping reserve begin first byte and settle preserves exact accounting", func(t *testing.T) {
		const requests = 48
		feature := "reserve-batch-overlap"
		inputs := make([]ReserveInput, requests)
		for index := range inputs {
			inputs[index] = lifecycleHotPathInput(t, fixture, feature, requests)
		}
		type result struct {
			reservation Reservation
			err         error
		}
		results := make(chan result, requests)
		start := make(chan struct{})
		for _, input := range inputs {
			go func() {
				<-start
				// There is deliberately no phase barrier between lifecycle operations.
				ctx, cancel := context.WithTimeout(fixture.ctx, 15*time.Second)
				defer cancel()
				reservation, err := fixture.store.Reserve(ctx, input)
				if err != nil {
					results <- result{err: fmt.Errorf("reserve: %w", err)}
					return
				}
				attempt, owner, err := fixture.store.BeginAttempt(ctx, reservation)
				if err != nil || !owner {
					results <- result{err: fmt.Errorf("begin owner=%t: %v", owner, err)}
					return
				}
				if err := fixture.store.MarkFirstByte(ctx, attempt); err != nil {
					results <- result{err: fmt.Errorf("first byte: %w", err)}
					return
				}
				if err := fixture.store.Settle(ctx, attempt, hotPathSuccessOutcome()); err != nil {
					results <- result{err: fmt.Errorf("settle: %w", err)}
					return
				}
				results <- result{reservation: reservation}
			}()
		}
		close(start)
		var reservation Reservation
		for range requests {
			result := <-results
			if result.err != nil {
				t.Error(result.err)
			} else {
				reservation = result.reservation
			}
		}
		if t.Failed() {
			return
		}
		assertHotPathBucketState(t, fixture, reservation.ID(), map[string]hotPathBucketExpectation{
			LogicalRequestsMetric: {used: requests, maximum: requests},
			InputTokensMetric:     {used: requests * 11, maximum: requests * 140},
			OutputTokensMetric:    {used: requests * 7, maximum: requests * 8},
			TotalTokensMetric:     {used: requests * 18, maximum: requests * 148},
		})
		assertHotPathTerminalCounts(t, fixture, feature, requests)
		for _, input := range inputs {
			assertReserveBatchStages(t, fixture, input, 0)
		}
	})

	t.Run("clock and decision stages follow the last sorted bucket lock", func(t *testing.T) {
		for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeSimpleProtocol} {
			t.Run(mode.String(), func(t *testing.T) {
				fixture := fixture
				config := fixture.pool.Config()
				config.ConnConfig.DefaultQueryExecMode = mode
				pool, err := pgxpool.NewWithConfig(fixture.ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
				store, err := NewStore(StoreConfig{Pool: pool, ReservationTTL: time.Hour})
				if err != nil {
					t.Fatal(err)
				}
				fixture.pool, fixture.store = pool, store
				feature := fmt.Sprintf("reserve-batch-clock-%d", mode)
				seedInput := lifecycleHotPathInput(t, fixture, feature, 2)
				seed, err := fixture.store.Reserve(fixture.ctx, seedInput)
				if err != nil {
					t.Fatal(err)
				}
				if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seed, "clock_test_seeded"); err != nil {
					t.Fatal(err)
				}
				blocker, err := fixture.pool.Begin(fixture.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = blocker.Rollback(fixture.ctx) }()
				var bucketID string
				if err := blocker.QueryRow(fixture.ctx, `
			SELECT bucket.quota_bucket_id FROM quota_buckets AS bucket
			JOIN quota_reservation_entries AS entry USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			ORDER BY bucket.quota_bucket_id COLLATE "C" DESC LIMIT 1 FOR UPDATE OF bucket
		`, seed.ID()).Scan(&bucketID); err != nil {
					t.Fatal(err)
				}
				const shortTTL = 250 * time.Millisecond
				fixture.store.reservationTTL = shortTTL
				input := lifecycleHotPathInput(t, fixture, feature, 2)
				type result struct {
					reservation Reservation
					err         error
				}
				reserved := make(chan result, 1)
				go func() {
					reservation, err := fixture.store.Reserve(fixture.ctx, input)
					reserved <- result{reservation, err}
				}()
				waitForQuotaBucketLock(t, fixture)
				time.Sleep(shortTTL + 50*time.Millisecond)
				var unlockedAt time.Time
				if err := blocker.QueryRow(fixture.ctx, "SELECT statement_timestamp()").Scan(&unlockedAt); err != nil {
					t.Fatal(err)
				}
				if err := blocker.Commit(fixture.ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case result := <-reserved:
					if result.err != nil {
						t.Fatal(result.err)
					}
					var requestedAt, createdAt, expiresAt time.Time
					if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT request.requested_at, reservation.created_at, reservation.expires_at
				FROM logical_requests AS request JOIN quota_reservations AS reservation USING (logical_request_id)
				WHERE request.logical_request_id = $1
			`, input.LogicalRequestID.String()).Scan(&requestedAt, &createdAt, &expiresAt); err != nil {
						t.Fatal(err)
					}
					if !requestedAt.Before(unlockedAt) || createdAt.Before(unlockedAt) ||
						!expiresAt.Equal(createdAt.Add(shortTTL)) || !result.reservation.ExpiresAt().Equal(expiresAt) {
						t.Fatalf("post-lock clock mismatch: requested=%s created=%s expires=%s unlock=%s",
							requestedAt, createdAt, expiresAt, unlockedAt)
					}
					assertReserveBatchStages(t, fixture, input, 0)
				case <-time.After(2 * time.Second):
					t.Fatal("Reserve did not resume after the final bucket was unlocked")
				}
			})
		}
	})
}

func assertReserveBatchStages(t *testing.T, fixture quotaPostgreSQLFixture, input ReserveInput, priorStages int) {
	t.Helper()
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT stage.stage_number, stage.stage, stage.outcome,
		       stage.limit_rule_key, stage.limit_metric, stage.limit_algorithm, stage.limit_maximum,
		       (($6::integer = 0 AND stage.started_at = request.requested_at)
		         OR ($6::integer > 0 AND stage.started_at >= request.requested_at))
		         AND stage.started_at <= stage.completed_at
		         AND stage.started_at = min(stage.started_at) OVER (),
		       stage.completed_at = reservation.created_at
		FROM logical_request_decision_stages AS stage
		JOIN logical_requests AS request USING (logical_request_id)
		JOIN quota_reservations AS reservation USING (logical_request_id)
		WHERE stage.logical_request_id = $1 AND stage.stage IN ('quota_rule_evaluated', 'quota_reserved')
		  AND stage.organization_id = $2 AND stage.application_id = $3 AND stage.environment_id = $4
		  AND stage.config_revision_id = $5
		ORDER BY stage.stage_number
	`, input.LogicalRequestID.String(), input.OrganizationID, input.ApplicationID,
		input.EnvironmentID, input.ConfigRevisionID, priorStages)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var number int
		var stage, outcome string
		var key, metric, algorithm *string
		var maximum *int64
		var startsAtRequest, endsAtReservation bool
		if err := rows.Scan(&number, &stage, &outcome, &key, &metric, &algorithm, &maximum,
			&startsAtRequest, &endsAtReservation); err != nil {
			t.Fatal(err)
		}
		if number != priorStages+count+1 || outcome != DecisionSucceeded || !startsAtRequest || !endsAtReservation {
			t.Fatalf("stage %d has inconsistent numbering, outcome or post-lock times", count)
		}
		if count < len(prepared.rules) {
			rule := prepared.rules[count]
			if stage != DecisionQuotaRuleEvaluated || key == nil || *key != rule.ruleKey ||
				metric == nil || *metric != rule.Metric || algorithm == nil || *algorithm != rule.Algorithm ||
				maximum == nil || *maximum != decisionLimitMaximum(rule) {
				t.Fatalf("stage %d lost exact quota rule provenance", count)
			}
		} else if stage != DecisionQuotaReserved {
			t.Fatalf("final stage = %q, want quota_reserved", stage)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != len(prepared.rules)+1 {
		t.Fatalf("quota stages = %d, want %d", count, len(prepared.rules)+1)
	}
}
