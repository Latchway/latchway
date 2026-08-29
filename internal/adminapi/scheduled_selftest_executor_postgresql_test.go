package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

type recordingScheduledSelfTestService struct {
	mu     sync.Mutex
	runs   []preparedScheduledSelfTest
	result credentialSelfTestResult
}

func (service *recordingScheduledSelfTestService) Prepare(
	context.Context,
	credentialSelfTestInput,
) (preparedScheduledSelfTest, error) {
	return preparedScheduledSelfTest{}, nil
}

func (service *recordingScheduledSelfTestService) RunBound(
	_ context.Context,
	prepared preparedScheduledSelfTest,
) credentialSelfTestResult {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.runs = append(service.runs, prepared)
	return service.result
}

func (service *recordingScheduledSelfTestService) runCount() int {
	service.mu.Lock()
	defer service.mu.Unlock()
	return len(service.runs)
}

type scheduledExecutorFixture struct {
	organizationID string
	applicationID  string
	environmentID  string
	adminUserID    string
	tokenID        string
	revisionID     string
	scheduleID     string
	jobID          string
}

func TestScheduledSelfTestExecutorPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	nextFixture := 0
	seed := func(t *testing.T) scheduledExecutorFixture {
		t.Helper()
		nextFixture++
		return seedScheduledExecutorFixture(t, ctx, pool, nextFixture)
	}
	newExecutor := func(service *recordingScheduledSelfTestService) *ScheduledSelfTestExecutor {
		return &ScheduledSelfTestExecutor{pool: pool, service: service, newID: id.New}
	}
	passedResult := credentialSelfTestResult{State: "passed", Checks: []selfTestCheck{{
		Name: "usage", State: "passed", SafeDetail: "Bounded provider usage passed.",
	}}}

	t.Run("completed dispatch is not repeated", func(t *testing.T) {
		fixture := seed(t)
		service := &recordingScheduledSelfTestService{result: passedResult}
		executor := newExecutor(service)
		for attempt := 0; attempt < 2; attempt++ {
			processed, err := executor.ExecuteScheduled(ctx, fixture.jobID)
			if err != nil || processed != 1 {
				t.Fatalf("execute attempt %d processed=%d err=%v", attempt+1, processed, err)
			}
		}
		if service.runCount() != 1 {
			t.Fatalf("provider dispatches=%d, want 1", service.runCount())
		}
		run := readScheduledExecutorRun(t, ctx, pool, fixture.jobID)
		if run.State != "passed" || run.ScheduleID != fixture.scheduleID || run.Checks[0].SafeDetail != "Bounded provider usage passed." {
			t.Fatalf("completed run=%+v", run)
		}
		var audits int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action = 'system.self_test_schedule_run'`, fixture.organizationID).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if audits != 1 {
			t.Fatalf("run audits=%d, want 1", audits)
		}
	})

	t.Run("dispatch marker recovery never redispatches", func(t *testing.T) {
		fixture := seed(t)
		selfTestID := id.Must(id.SelfTest)
		if _, err := pool.Exec(ctx, `
			INSERT INTO scheduled_self_test_runs (
				job_id, self_test_schedule_id, self_test_id, status, budget_date,
				reserved_cost_nano_usd, started_at
			) VALUES ($1,$2,$3,'dispatching',CURRENT_DATE,1000000,statement_timestamp())
		`, fixture.jobID, fixture.scheduleID, selfTestID); err != nil {
			t.Fatal(err)
		}
		service := &recordingScheduledSelfTestService{result: passedResult}
		processed, err := newExecutor(service).ExecuteScheduled(ctx, fixture.jobID)
		if err != nil || processed != 1 || service.runCount() != 0 {
			t.Fatalf("recovery processed=%d dispatches=%d err=%v", processed, service.runCount(), err)
		}
		run := readScheduledExecutorRun(t, ctx, pool, fixture.jobID)
		if run.State != "failed" || len(run.Checks) != 1 || run.Checks[0].Name != "execution_recovery" ||
			run.Checks[0].SafeDetail != "A previous worker stopped after the durable dispatch marker; the request was not repeated." {
			t.Fatalf("recovered run=%+v", run)
		}
	})

	t.Run("revoked durable authorization fails closed", func(t *testing.T) {
		fixture := seed(t)
		if _, err := pool.Exec(ctx, `UPDATE admin_api_tokens SET revoked_at = statement_timestamp(), revoke_reason = 'test_revocation' WHERE admin_api_token_id = $1`, fixture.tokenID); err != nil {
			t.Fatal(err)
		}
		assertScheduledExecutorPermanentRejection(t, ctx, pool, newExecutor, fixture, "authorization")
	})

	t.Run("active configuration substitution fails closed", func(t *testing.T) {
		fixture := seed(t)
		replacementID := id.Must(id.ConfigRevision)
		if _, err := pool.Exec(ctx, `
			INSERT INTO config_revisions (
				config_revision_id, organization_id, application_id, environment_id,
				revision_number, etag, status, document, compiled_document,
				validation_report, created_by_admin_user_id, validated_at, activated_at
			) VALUES ($1,$2,$3,$4,2,'"replacement-revision"','valid','{}'::jsonb,'{}'::jsonb,
				'{"valid":true,"issues":[]}'::jsonb,$5,statement_timestamp(),statement_timestamp())
		`, replacementID, fixture.organizationID, fixture.applicationID, fixture.environmentID, fixture.adminUserID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE active_config_revisions SET config_revision_id = $2 WHERE environment_id = $1`, fixture.environmentID, replacementID); err != nil {
			t.Fatal(err)
		}
		assertScheduledExecutorPermanentRejection(t, ctx, pool, newExecutor, fixture, "active_configuration")
	})

	t.Run("provider credential substitution fails closed", func(t *testing.T) {
		fixture := seed(t)
		oldSecretID := id.Must(id.SecretRecord)
		newSecretID := id.Must(id.SecretRecord)
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_records (
				secret_record_id, organization_id, application_id, environment_id,
				name, version, encryption_format_version, algorithm, master_key_identifier,
				ciphertext, nonce, created_by_admin_user_id
			) VALUES ($1,$2,$3,$4,'provider_key',1,1,'aes-256-gcm','test-master',$5,$6,$7)
		`, oldSecretID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
			bytes.Repeat([]byte{0x41}, 17), bytes.Repeat([]byte{0x42}, 12), fixture.adminUserID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO self_test_schedule_secret_bindings (
				self_test_schedule_id, ordinal, organization_id, application_id,
				environment_id, secret_reference, secret_record_id, secret_version
			) VALUES ($1,0,$2,$3,$4,'secret/provider_key',$5,1)
		`, fixture.scheduleID, fixture.organizationID, fixture.applicationID, fixture.environmentID, oldSecretID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE secret_records SET rotated_at = statement_timestamp() WHERE secret_record_id = $1`, oldSecretID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_records (
				secret_record_id, organization_id, application_id, environment_id,
				name, version, encryption_format_version, algorithm, master_key_identifier,
				ciphertext, nonce, created_by_admin_user_id
			) VALUES ($1,$2,$3,$4,'provider_key',2,1,'aes-256-gcm','test-master',$5,$6,$7)
		`, newSecretID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
			bytes.Repeat([]byte{0x51}, 17), bytes.Repeat([]byte{0x52}, 12), fixture.adminUserID); err != nil {
			t.Fatal(err)
		}
		assertScheduledExecutorPermanentRejection(t, ctx, pool, newExecutor, fixture, "credential_binding")
		payload, err := json.Marshal(readScheduledExecutorRun(t, ctx, pool, fixture.jobID))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "provider_key") || strings.Contains(string(payload), oldSecretID) || strings.Contains(string(payload), newSecretID) {
			t.Fatalf("secret binding leaked into result: %s", payload)
		}
	})

	t.Run("secret binding cannot cross schedule tenant scope", func(t *testing.T) {
		scheduleFixture := seed(t)
		otherFixture := seed(t)
		otherSecretID := id.Must(id.SecretRecord)
		if _, err := pool.Exec(ctx, `
			INSERT INTO secret_records (
				secret_record_id, organization_id, application_id, environment_id,
				name, version, encryption_format_version, algorithm, master_key_identifier,
				ciphertext, nonce, created_by_admin_user_id
			) VALUES ($1,$2,$3,$4,'provider_key',1,1,'aes-256-gcm','test-master',$5,$6,$7)
		`, otherSecretID, otherFixture.organizationID, otherFixture.applicationID, otherFixture.environmentID,
			bytes.Repeat([]byte{0x61}, 17), bytes.Repeat([]byte{0x62}, 12), otherFixture.adminUserID); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO self_test_schedule_secret_bindings (
				self_test_schedule_id, ordinal, organization_id, application_id,
				environment_id, secret_reference, secret_record_id, secret_version
			) VALUES ($1,0,$2,$3,$4,'secret/provider_key',$5,1)
		`, scheduleFixture.scheduleID, otherFixture.organizationID, otherFixture.applicationID,
			otherFixture.environmentID, otherSecretID)
		if err == nil {
			t.Fatal("cross-tenant schedule secret binding was accepted")
		}
	})

	t.Run("concurrent jobs cannot exceed the daily budget", func(t *testing.T) {
		fixture := seed(t)
		priorJobID := seedAdditionalScheduledExecutorJob(t, ctx, pool, fixture, "prior")
		priorSelfTestID := id.Must(id.SelfTest)
		if _, err := pool.Exec(ctx, `
			INSERT INTO scheduled_self_test_runs (
				job_id, self_test_schedule_id, self_test_id, status, budget_date,
				reserved_cost_nano_usd, started_at, completed_at, result
			) VALUES ($1,$2,$3,'completed',CURRENT_DATE,23000000,
				statement_timestamp() - interval '1 minute',statement_timestamp(),'{}'::jsonb)
		`, priorJobID, fixture.scheduleID, priorSelfTestID); err != nil {
			t.Fatal(err)
		}
		secondJobID := seedAdditionalScheduledExecutorJob(t, ctx, pool, fixture, "concurrent")
		service := &recordingScheduledSelfTestService{result: passedResult}
		executor := newExecutor(service)
		start := make(chan struct{})
		errorsChannel := make(chan error, 2)
		var wait sync.WaitGroup
		for _, jobID := range []string{fixture.jobID, secondJobID} {
			jobID := jobID
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				_, err := executor.ExecuteScheduled(ctx, jobID)
				errorsChannel <- err
			}()
		}
		close(start)
		wait.Wait()
		close(errorsChannel)
		for err := range errorsChannel {
			if err != nil {
				t.Fatal(err)
			}
		}
		if service.runCount() != 1 {
			t.Fatalf("budget-race dispatches=%d, want 1", service.runCount())
		}
		var reserved int64
		var budgetFailures int
		if err := pool.QueryRow(ctx, `
			SELECT sum(reserved_cost_nano_usd), count(*) FILTER (WHERE result->'checks' @> '[{"name":"budget","state":"failed"}]'::jsonb)
			FROM scheduled_self_test_runs WHERE self_test_schedule_id = $1
		`, fixture.scheduleID).Scan(&reserved, &budgetFailures); err != nil {
			t.Fatal(err)
		}
		if reserved != 24_000_000 || budgetFailures != 1 {
			t.Fatalf("reserved=%d budget failures=%d", reserved, budgetFailures)
		}
	})
}

func assertScheduledExecutorPermanentRejection(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	newExecutor func(*recordingScheduledSelfTestService) *ScheduledSelfTestExecutor,
	fixture scheduledExecutorFixture,
	wantCheck string,
) {
	t.Helper()
	service := &recordingScheduledSelfTestService{result: credentialSelfTestResult{State: "passed"}}
	processed, err := newExecutor(service).ExecuteScheduled(ctx, fixture.jobID)
	if err != nil || processed != 1 || service.runCount() != 0 {
		t.Fatalf("rejection processed=%d dispatches=%d err=%v", processed, service.runCount(), err)
	}
	run := readScheduledExecutorRun(t, ctx, pool, fixture.jobID)
	if run.State != "failed" || len(run.Checks) != 1 || run.Checks[0].Name != wantCheck || len(run.Checks[0].SafeDetail) == 0 {
		t.Fatalf("rejected run=%+v", run)
	}
	var status, reason string
	if err := pool.QueryRow(ctx, `SELECT status, disabled_reason_code FROM self_test_schedules WHERE self_test_schedule_id = $1`, fixture.scheduleID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "disabled" || reason != wantCheck {
		t.Fatalf("schedule status=%q reason=%q", status, reason)
	}
}

func readScheduledExecutorRun(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	jobID string,
) selfTestDocument {
	t.Helper()
	var payload []byte
	var status string
	if err := pool.QueryRow(ctx, `SELECT status, result FROM scheduled_self_test_runs WHERE job_id = $1`, jobID).Scan(&status, &payload); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("run status=%q", status)
	}
	var run selfTestDocument
	if err := json.Unmarshal(payload, &run); err != nil || !validStoredSelfTest(run) {
		t.Fatalf("decode run=%+v err=%v payload=%s", run, err, payload)
	}
	return run
}

func seedScheduledExecutorFixture(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	ordinal int,
) scheduledExecutorFixture {
	t.Helper()
	fixture := scheduledExecutorFixture{
		organizationID: id.Must(id.Organization), applicationID: id.Must(id.Application),
		environmentID: id.Must(id.Environment), adminUserID: id.Must(id.AdminUser),
		tokenID: id.Must(id.AdminAPIToken), revisionID: id.Must(id.ConfigRevision),
		scheduleID: id.Must(id.SelfTestSchedule), jobID: id.Must(id.Job),
	}
	membershipID := id.Must(id.AdminMembership)
	runtimeID := fmt.Sprintf("scheduled-self-test-runtime-%d", ordinal)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations (organization_id, slug, display_name) VALUES ($1,$2,'Scheduled Test')`, []any{fixture.organizationID, fmt.Sprintf("scheduled-test-%d", ordinal)}},
		{`INSERT INTO applications (application_id, organization_id, slug, display_name) VALUES ($1,$2,'mobile','Mobile')`, []any{fixture.applicationID, fixture.organizationID}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind) VALUES ($1,$2,$3,'production','Production','production')`, []any{fixture.environmentID, fixture.organizationID, fixture.applicationID}},
		{`INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name) VALUES ($1,$2,$2,'Scheduler')`, []any{fixture.adminUserID, fmt.Sprintf("scheduler-%d@example.test", ordinal)}},
		{`INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role) VALUES ($1,$2,$3,'operator')`, []any{membershipID, fixture.organizationID, fixture.adminUserID}},
		{`INSERT INTO admin_api_tokens (admin_api_token_id, organization_id, admin_user_id, name, token_hash, token_hint, scopes, created_by_admin_user_id) VALUES ($1,$2,$3,'scheduler',$4,$5,ARRAY['run_self_tests']::text[],$3)`, []any{fixture.tokenID, fixture.organizationID, fixture.adminUserID, bytes.Repeat([]byte{byte(ordinal)}, 32), fmt.Sprintf("%06d", ordinal)}},
		{`INSERT INTO config_revisions (config_revision_id, organization_id, application_id, environment_id, revision_number, etag, status, document, compiled_document, validation_report, created_by_admin_user_id, validated_at, activated_at) VALUES ($1,$2,$3,$4,1,$5,'valid','{}'::jsonb,'{}'::jsonb,'{"valid":true,"issues":[]}'::jsonb,$6,statement_timestamp(),statement_timestamp())`, []any{fixture.revisionID, fixture.organizationID, fixture.applicationID, fixture.environmentID, fmt.Sprintf("\"scheduled-revision-%d\"", ordinal), fixture.adminUserID}},
		{`INSERT INTO active_config_revisions (organization_id, application_id, environment_id, config_revision_id, revision_status, activated_by_admin_user_id) VALUES ($1,$2,$3,$4,'valid',$5)`, []any{fixture.organizationID, fixture.applicationID, fixture.environmentID, fixture.revisionID, fixture.adminUserID}},
		{`INSERT INTO runtime_instances (instance_id, role) VALUES ($1,'worker')`, []any{runtimeID}},
		{`INSERT INTO self_test_schedules (self_test_schedule_id, organization_id, application_id, environment_id, config_revision_id, kind, upstream_key, model_key, max_cost_nano_usd, daily_cost_limit_nano_usd, interval_seconds, authorized_admin_user_id, authorization_method, authorization_credential_id, status, next_run_at) VALUES ($1,$2,$3,$4,$5,'upstream','primary','canary',1000000,24000000,3600,$6,'api_token',$7,'active',statement_timestamp() + interval '1 hour')`, []any{fixture.scheduleID, fixture.organizationID, fixture.applicationID, fixture.environmentID, fixture.revisionID, fixture.adminUserID, fixture.tokenID}},
		{`INSERT INTO jobs (job_id, organization_id, environment_id, job_type, idempotency_key, payload, status, available_at, locked_at, locked_by_instance_id, attempt_count, max_attempts) VALUES ($1,$2,$3,'run_scheduled_self_test',$4,jsonb_build_object('schedule_id',$5::text),'running',statement_timestamp(),statement_timestamp(),$6,1,3)`, []any{fixture.jobID, fixture.organizationID, fixture.environmentID, "scheduled-executor:" + fixture.jobID, fixture.scheduleID, runtimeID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed scheduled executor fixture: %v", err)
		}
	}
	return fixture
}

func seedAdditionalScheduledExecutorJob(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture scheduledExecutorFixture,
	suffix string,
) string {
	t.Helper()
	jobID := id.Must(id.Job)
	var runtimeID string
	if err := pool.QueryRow(ctx, `SELECT locked_by_instance_id FROM jobs WHERE job_id = $1`, fixture.jobID).Scan(&runtimeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO jobs (
			job_id, organization_id, environment_id, job_type, idempotency_key, payload,
			status, available_at, locked_at, locked_by_instance_id, attempt_count, max_attempts
		) VALUES ($1,$2,$3,'run_scheduled_self_test',$4,jsonb_build_object('schedule_id',$5::text),
			'running',statement_timestamp(),statement_timestamp(),$6,1,3)
	`, jobID, fixture.organizationID, fixture.environmentID, "scheduled-"+suffix+":"+jobID, fixture.scheduleID, runtimeID); err != nil {
		t.Fatal(err)
	}
	return jobID
}
