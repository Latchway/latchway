package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

var workerTestSchemaPattern = regexp.MustCompile(`^latchway_worker_test_[0-9]+$`)

func TestQueueClaimsScheduledJobsExactlyOnceAcrossReplicasPostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	first := mustWorkerQueue(t, pool, "runtime-AAAAAAAAAAAAAAAA", "worker")
	second := mustWorkerQueue(t, pool, "runtime-BBBBBBBBBBBBBBBB", "worker")
	if err := first.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	types := []string{"release_expired_reservations", "reconcile_pending_usage"}
	if err := first.Schedule(ctx, now, types); err != nil {
		t.Fatal(err)
	}
	if err := second.Schedule(ctx, now, types); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan Job, 2)
	errorsChannel := make(chan error, 2)
	var wait sync.WaitGroup
	for _, queue := range []*Queue{first, second} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			job, found, err := queue.Claim(ctx, 30*time.Second)
			if err == nil && !found {
				err = errors.New("no job was claimed")
			}
			if err == nil {
				results <- job
			}
			errorsChannel <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent claim: %v", err)
		}
	}
	seen := map[string]Job{}
	for job := range results {
		if _, duplicate := seen[job.ID]; duplicate {
			t.Fatalf("job %s was claimed twice", job.ID)
		}
		seen[job.ID] = job
	}
	if len(seen) != 2 {
		t.Fatalf("claimed jobs = %d, want 2", len(seen))
	}
	owners := make(map[string]string, len(seen))
	for _, job := range seen {
		var owner string
		if err := pool.QueryRow(ctx, "SELECT locked_by_instance_id FROM jobs WHERE job_id = $1", job.ID).Scan(&owner); err != nil {
			t.Fatal(err)
		}
		owners[job.ID] = owner
	}
	for _, queue := range []*Queue{first, second} {
		for _, job := range seen {
			if owners[job.ID] == queue.instanceID {
				if err := queue.Complete(ctx, job); err != nil {
					t.Fatalf("complete %s: %v", job.Type, err)
				}
			}
		}
	}
	var total, succeeded int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status = 'succeeded') FROM jobs`).Scan(&total, &succeeded); err != nil {
		t.Fatal(err)
	}
	if total != 2 || succeeded != 2 {
		t.Fatalf("job totals = %d/%d, want 2/2", total, succeeded)
	}
}

func TestQueueSchedulesEveryExecutableJobExactlyOnceAcrossReplicasPostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	first := mustWorkerQueue(t, pool, "runtime-ALLJOBSAAAAAAAAA", "worker")
	second := mustWorkerQueue(t, pool, "runtime-ALLJOBSBBBBBBBBB", "all")
	for _, queue := range []*Queue{first, second} {
		if err := queue.Heartbeat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	jobTypes := scheduledDurableJobTypes()
	if err := first.Schedule(ctx, now, jobTypes); err != nil {
		t.Fatal(err)
	}
	if err := second.Schedule(ctx, now, jobTypes); err != nil {
		t.Fatal(err)
	}
	if err := first.Schedule(ctx, now, []string{"run_scheduled_self_test"}); err == nil {
		t.Fatal("unsafe scheduled self-test was accepted without a persisted authorization contract")
	}

	start := make(chan struct{})
	claimed := make(chan Job, len(jobTypes))
	errorsChannel := make(chan error, 2)
	var wait sync.WaitGroup
	for _, queue := range []*Queue{first, second} {
		queue := queue
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for {
				job, found, err := queue.Claim(ctx, 30*time.Second)
				if err != nil {
					errorsChannel <- err
					return
				}
				if !found {
					return
				}
				if err := queue.Complete(ctx, job); err != nil {
					errorsChannel <- err
					return
				}
				claimed <- job
			}
		}()
	}
	close(start)
	wait.Wait()
	close(claimed)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("claim/complete all jobs: %v", err)
		}
	}
	seen := make(map[string]int, len(jobTypes))
	for job := range claimed {
		seen[job.Type]++
	}
	if len(seen) != len(jobTypes) {
		t.Fatalf("claimed job types=%v, want all %v", seen, jobTypes)
	}
	for _, jobType := range jobTypes {
		if seen[jobType] != 1 {
			t.Fatalf("job %q claims=%d, want exactly one", jobType, seen[jobType])
		}
	}
	var total, succeeded int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status = 'succeeded') FROM jobs`).Scan(&total, &succeeded); err != nil {
		t.Fatal(err)
	}
	if total != len(jobTypes) || succeeded != len(jobTypes) {
		t.Fatalf("all-job totals=%d/%d, want %d/%d", total, succeeded, len(jobTypes), len(jobTypes))
	}
}

func TestQueueRecoversJobAfterWorkerHeartbeatFailurePostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	lost := mustWorkerQueue(t, pool, "runtime-CCCCCCCCCCCCCCCC", "worker")
	recovery := mustWorkerQueue(t, pool, "runtime-DDDDDDDDDDDDDDDD", "all")
	if err := lost.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lost.Schedule(ctx, time.Now().UTC(), []string{"rotate_signing_keys"}); err != nil {
		t.Fatal(err)
	}
	firstClaim, found, err := lost.Claim(ctx, 30*time.Second)
	if err != nil || !found {
		t.Fatalf("initial claim found=%t err=%v", found, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runtime_instances SET heartbeat_at = statement_timestamp() - interval '10 minutes' WHERE instance_id = $1`, lost.instanceID); err != nil {
		t.Fatal(err)
	}

	recovered, found, err := recovery.Claim(ctx, 30*time.Second)
	if err != nil || !found {
		t.Fatalf("recovery claim found=%t err=%v", found, err)
	}
	if recovered.ID != firstClaim.ID || recovered.AttemptCount != 2 {
		t.Fatalf("recovered claim = %#v, first=%#v", recovered, firstClaim)
	}
	if err := lost.Complete(ctx, firstClaim); !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("lost worker completion = %v", err)
	}
	if err := recovery.Complete(ctx, recovered); err != nil {
		t.Fatal(err)
	}
	if err := CheckRecentHeartbeat(ctx, pool, 30*time.Second); err != nil {
		t.Fatalf("healthy recovery worker not ready: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE runtime_instances SET heartbeat_at = statement_timestamp() - interval '10 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := CheckRecentHeartbeat(ctx, pool, 30*time.Second); err == nil {
		t.Fatal("stale workers passed readiness")
	}
}

func TestOperationalRollupsAndRetentionAreIdempotentAcrossReplicasPostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	operations, err := NewPostgreSQLOperations(pool)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour)
	if count, err := operations.AggregateHourlyUsage(ctx, now); err != nil || count != 0 {
		t.Fatalf("empty hourly rollup count=%d err=%v", count, err)
	}
	if count, err := operations.AggregateDailyUsage(ctx, now); err != nil || count != 0 {
		t.Fatalf("empty daily rollup count=%d err=%v", count, err)
	}

	jobID, err := id.New(id.Job)
	if err != nil {
		t.Fatal(err)
	}
	old := now.Add(-31 * 24 * time.Hour)
	if _, err := pool.Exec(ctx, `
		INSERT INTO runtime_instances (instance_id, role, started_at, heartbeat_at)
		VALUES ('runtime-EEEEEEEEEEEEEEEE', 'worker', $1, $1)
	`, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO jobs (
			job_id, job_type, idempotency_key, status, available_at, max_attempts,
			created_at, updated_at, completed_at
		) VALUES ($1, 'enforce_retention', 'retention-test-history', 'succeeded', $2, 3, $2, $2, $2)
	`, jobID, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_jwks_cache (
			issuer_sha256, source_sha256, source_format, document, document_sha256,
			fetched_at, fresh_until, stale_until, created_at, updated_at
		) VALUES ($1,$2,'jwks',$3,$4,$5,$6,$7,$5,$5)
	`, bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32),
		[]byte(`{"keys":[]}`), bytes.Repeat([]byte{0x63}, 32),
		now.Add(-25*time.Hour), now.Add(-24*time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	counts := make(chan int64, 2)
	errorsChannel := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			count, retentionErr := operations.EnforceRetention(ctx, now, 10)
			counts <- count
			errorsChannel <- retentionErr
		}()
	}
	close(start)
	var total int64
	for range 2 {
		total += <-counts
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
	if total != 3 {
		t.Fatalf("concurrent retention processed %d records, want 3", total)
	}
	if count, err := operations.EnforceRetention(ctx, now, 10); err != nil || count != 0 {
		t.Fatalf("idempotent retention count=%d err=%v", count, err)
	}
}

func TestUsageRollupsContainOnlyLowCardinalityOperationalDimensionsPostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	operations, err := NewPostgreSQLOperations(pool)
	if err != nil {
		t.Fatal(err)
	}
	hourEnd := time.Now().UTC().Truncate(time.Hour)
	recordedAt := hourEnd.Add(-50 * time.Minute)
	fixture := insertWorkerUsageFixture(t, ctx, pool, recordedAt)
	count, err := operations.AggregateHourlyUsage(ctx, hourEnd)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("hourly rollup rows = %d, want 3", count)
	}
	rows, err := pool.Query(ctx, `
		SELECT metric, units, dimensions::text
		FROM usage_rollups_hourly
		WHERE environment_id = $1 ORDER BY metric
	`, fixture.environmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]int64{}
	for rows.Next() {
		var metric, dimensions string
		var units int64
		if err := rows.Scan(&metric, &units, &dimensions); err != nil {
			t.Fatal(err)
		}
		seen[metric] = units
		for _, forbidden := range []string{fixture.userID, fixture.installationID, fixture.requestID, "external_subject"} {
			if strings.Contains(dimensions, forbidden) {
				t.Fatalf("rollup dimensions leaked %q: %s", forbidden, dimensions)
			}
		}
		if !strings.Contains(dimensions, `"feature": "assistant"`) || !strings.Contains(dimensions, `"outcome": "succeeded"`) {
			t.Fatalf("rollup dimensions missing stable values: %s", dimensions)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen["logical_requests"] != 1 || seen["input_tokens"] != 10 || seen["upstream_attempts"] != 1 {
		t.Fatalf("hourly rollup metrics = %v", seen)
	}
	dailyAt := time.Date(recordedAt.Year(), recordedAt.Month(), recordedAt.Day()+1, 0, 0, 0, 0, time.UTC)
	if count, err := operations.AggregateDailyUsage(ctx, dailyAt); err != nil || count != 3 {
		t.Fatalf("daily rollup rows=%d err=%v", count, err)
	}
}

type workerUsageFixture struct {
	environmentID  string
	userID         string
	installationID string
	requestID      string
}

func insertWorkerUsageFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, at time.Time) workerUsageFixture {
	t.Helper()
	newID := func(prefix id.Prefix) string {
		value, err := id.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	organizationID, applicationID, environmentID := newID(id.Organization), newID(id.Application), newID(id.Environment)
	adminID, membershipID := newID(id.AdminUser), newID(id.AdminMembership)
	revisionID, userID := newID(id.ConfigRevision), newID(id.ApplicationUser)
	installationID, grantID := newID(id.Installation), newID(id.SessionGrant)
	requestID, attemptID := newID(id.LogicalRequest), newID(id.UpstreamAttempt)
	logicalUsageID, inputUsageID := newID(id.UsageRecord), newID(id.UsageRecord)
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at) VALUES ($1, 'worker-org', 'Worker Org', $2, $2)`, organizationID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO applications (application_id, organization_id, slug, display_name, created_at, updated_at) VALUES ($1,$2,'mobile-app','Mobile App',$3,$3)`, applicationID, organizationID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, created_at, updated_at) VALUES ($1,$2,$3,'production','Production','production',$4,$4)`, environmentID, organizationID, applicationID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_users (admin_user_id,email,email_normalized,display_name,created_at,updated_at) VALUES ($1,'worker@example.test','worker@example.test','Worker',$2,$2)`, adminID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_memberships (admin_membership_id,organization_id,admin_user_id,role,created_at,updated_at) VALUES ($1,$2,$3,'owner',$4,$4)`, membershipID, organizationID, adminID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id,organization_id,application_id,environment_id,revision_number,etag,status,
			document,compiled_document,validation_errors,validation_report,created_by_admin_user_id,
			created_at,validated_at
		) VALUES ($1,$2,$3,$4,1,'worker-etag-00000001','valid','{}','{}','[]',
		          '{"valid":true,"issues":[]}', $5,$6,$6)
	`, revisionID, organizationID, applicationID, environmentID, adminID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO application_users (application_user_id,organization_id,application_id,created_at,updated_at) VALUES ($1,$2,$3,$4,$4)`, userID, organizationID, applicationID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	jkt := strings.Repeat("A", 43)
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id,organization_id,application_id,environment_id,application_user_id,
			platform,dpop_jkt,dpop_public_jwk,key_storage,trust_level,created_at,updated_at,last_seen_at
		) VALUES ($1,$2,$3,$4,$5,'ios',$6,'{}','secure_enclave','device_verified',$7,$7,$7)
	`, installationID, organizationID, applicationID, environmentID, userID, jkt, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id,organization_id,application_id,environment_id,application_user_id,
			installation_id,access_token_jti_hash,dpop_jkt,policy_revision_id,trust_level,
			identity_verified_at,attested_at,issued_at,expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'identity_only',$10,NULL,$10,$11)
	`, grantID, organizationID, applicationID, environmentID, userID, installationID, make([]byte, 32), jkt, revisionID, at.Add(-time.Hour), at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id,organization_id,application_id,environment_id,application_user_id,
			installation_id,session_grant_id,config_revision_id,feature_key,protocol,status,
			requested_at,dispatched_at,completed_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'assistant','openai_responses','succeeded',$9,$9,$9)
	`, requestID, organizationID, applicationID, environmentID, userID, installationID, grantID, revisionID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO upstream_attempts (
			upstream_attempt_id,organization_id,application_id,environment_id,logical_request_id,
			attempt_number,route_key,upstream_key,physical_model,model_key,
			attempt_decision_binding_version,attempt_decision_sha256,status,started_at,completed_at
		) VALUES ($1,$2,$3,$4,$5,1,'primary','openai','gpt-test','fast',1,$6,'succeeded',$7,$7)
	`, attemptID, organizationID, applicationID, environmentID, requestID, bytes.Repeat([]byte{1}, 32), at); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO usage_records (
			usage_record_id,organization_id,application_id,environment_id,logical_request_id,
			upstream_attempt_id,metric,units,confidence,provenance_key,recorded_at
		) VALUES
			($1,$2,$3,$4,$5,NULL,'logical_requests',1,'calculated','worker-logical-usage',$8),
			($6,$2,$3,$4,$5,$7,'input_tokens',10,'reported','worker-provider-input',$8)
	`, logicalUsageID, organizationID, applicationID, environmentID, requestID, inputUsageID, attemptID, at); err != nil {
		t.Fatal(err)
	}
	return workerUsageFixture{environmentID: environmentID, userID: userID, installationID: installationID, requestID: requestID}
}

func isolatedWorkerPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_worker_test_%d", time.Now().UnixNano())
	if !workerTestSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsed.String(), 12)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func mustWorkerQueue(t *testing.T, pool *pgxpool.Pool, instanceID, role string) *Queue {
	t.Helper()
	queue, err := NewQueue(pool, instanceID, role)
	if err != nil {
		t.Fatal(err)
	}
	return queue
}
