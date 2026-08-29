package worker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

const (
	defaultWorkerStaleAfter         = 90 * time.Second
	maximumJobsPerClaimPass         = 100
	maximumSelfTestsPerSchedulePass = 100
)

var (
	runtimeInstancePattern = regexp.MustCompile(`^runtime-[A-Za-z0-9_-]{16,64}$`)
	ErrJobLeaseLost        = errors.New("worker job lease was lost")
)

var periodicJobTypes = map[string]time.Duration{
	"release_expired_reservations":       time.Minute,
	"release_expired_concurrency_leases": time.Minute,
	"prune_dpop_replays":                 time.Minute,
	"prune_challenges":                   time.Minute,
	"rotate_signing_keys":                time.Minute,
	"refresh_jwks":                       5 * time.Minute,
	"aggregate_hourly_usage":             time.Hour,
	"aggregate_daily_usage":              24 * time.Hour,
	"enforce_retention":                  time.Hour,
	"reconcile_pending_usage":            time.Minute,
}

var supportedJobTypes = func() map[string]time.Duration {
	types := make(map[string]time.Duration, len(periodicJobTypes)+1)
	for jobType, interval := range periodicJobTypes {
		types[jobType] = interval
	}
	// Per-schedule cadence is persisted in self_test_schedules, so this value is
	// only the closed executable-type marker used by claim validation.
	types["run_scheduled_self_test"] = time.Hour
	return types
}()

// Job is the public, payload-free claim passed to bounded built-in handlers.
// The queue deliberately does not expose arbitrary database payloads to logs.
type Job struct {
	ID           string
	Type         string
	AttemptCount int
	MaxAttempts  int
	ScheduledAt  time.Time
}

// Queue is a PostgreSQL-backed, multi-replica-safe maintenance job queue.
type Queue struct {
	pool       *pgxpool.Pool
	instanceID string
	role       string
	newID      func(id.Prefix) (string, error)
}

func NewQueue(pool *pgxpool.Pool, instanceID, role string) (*Queue, error) {
	if pool == nil || !runtimeInstancePattern.MatchString(instanceID) || (role != "worker" && role != "all") {
		return nil, errors.New("worker queue configuration is invalid")
	}
	return &Queue{pool: pool, instanceID: instanceID, role: role, newID: id.New}, nil
}

// Heartbeat durably registers this replica and advances its database-clock
// heartbeat. started_at remains stable across updates for the same instance.
func (queue *Queue) Heartbeat(ctx context.Context) error {
	if queue == nil || ctx == nil {
		return errors.New("worker queue is invalid")
	}
	_, err := queue.pool.Exec(ctx, `
		INSERT INTO runtime_instances (instance_id, role, started_at, heartbeat_at, metadata)
		VALUES ($1, $2, statement_timestamp(), statement_timestamp(), '{}'::jsonb)
		ON CONFLICT (instance_id) DO UPDATE
		SET heartbeat_at = statement_timestamp(), role = EXCLUDED.role
	`, queue.instanceID, queue.role)
	if err != nil {
		return errors.New("persist worker heartbeat")
	}
	return nil
}

// HasRecentWorker reports whether a worker/all replica has a fresh durable
// heartbeat. It uses PostgreSQL time to avoid replica clock skew.
func (queue *Queue) HasRecentWorker(ctx context.Context, maxAge time.Duration) error {
	if queue == nil || ctx == nil || maxAge < 5*time.Second || maxAge > time.Hour {
		return errors.New("worker heartbeat readiness input is invalid")
	}
	return CheckRecentHeartbeat(ctx, queue.pool, maxAge)
}

// CheckRecentHeartbeat is the read-only readiness capability used by API-only
// replicas that do not own a worker Queue.
func CheckRecentHeartbeat(ctx context.Context, pool *pgxpool.Pool, maxAge time.Duration) error {
	if pool == nil || ctx == nil || maxAge < 5*time.Second || maxAge > time.Hour {
		return errors.New("worker heartbeat readiness input is invalid")
	}
	var healthy bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM runtime_instances
			WHERE role IN ('worker', 'all')
			  AND heartbeat_at >= statement_timestamp() - make_interval(secs => $1)
		)
	`, int64(maxAge/time.Second)).Scan(&healthy)
	if err != nil || !healthy {
		return errors.New("worker heartbeat is unavailable")
	}
	return nil
}

// Schedule inserts one deterministic job for each type's current UTC window.
// Concurrent replicas converge through the unique (job_type,idempotency_key)
// constraint.
func (queue *Queue) Schedule(ctx context.Context, now time.Time, jobTypes []string) error {
	if queue == nil || ctx == nil || now.IsZero() || len(jobTypes) == 0 || len(jobTypes) > len(periodicJobTypes) {
		return errors.New("worker scheduling input is invalid")
	}
	jobTypes = append([]string(nil), jobTypes...)
	sort.Strings(jobTypes)
	for index, jobType := range jobTypes {
		interval, ok := periodicJobTypes[jobType]
		if !ok || (index > 0 && jobTypes[index-1] == jobType) {
			return errors.New("worker scheduling input is invalid")
		}
		jobID, err := queue.newID(id.Job)
		if err != nil {
			return errors.New("generate worker job identifier")
		}
		bucket := scheduleBucket(now.UTC(), interval)
		idempotencyKey := "schedule:" + jobType + ":" + bucket.Format("20060102T150405Z")
		if _, err := queue.pool.Exec(ctx, `
			INSERT INTO jobs (
				job_id, job_type, idempotency_key, payload, status,
				available_at, max_attempts, created_at, updated_at
			) VALUES ($1, $2, $3, '{}'::jsonb, 'pending', $4, 8, statement_timestamp(), statement_timestamp())
			ON CONFLICT (job_type, idempotency_key) DO NOTHING
		`, jobID, jobType, idempotencyKey, bucket); err != nil {
			return errors.New("schedule worker job")
		}
	}
	return nil
}

// ScheduleSelfTests coalesces each overdue active schedule to one job and
// advances its next due instant in the same transaction. Concurrent replicas
// partition due rows with SKIP LOCKED and converge through the job queue's
// unique idempotency key without producing catch-up cost bursts.
func (queue *Queue) ScheduleSelfTests(ctx context.Context, now time.Time) (int, error) {
	if queue == nil || ctx == nil || now.IsZero() {
		return 0, errors.New("scheduled self-test input is invalid")
	}
	tx, err := queue.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, errors.New("begin scheduled self-test enqueue")
	}
	defer rollbackQueue(tx)
	rows, err := tx.Query(ctx, `
		SELECT self_test_schedule_id, organization_id, environment_id,
		       next_run_at, interval_seconds
		FROM self_test_schedules
		WHERE status = 'active' AND next_run_at <= $1
		ORDER BY next_run_at, created_at, self_test_schedule_id
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, now.UTC(), maximumSelfTestsPerSchedulePass)
	if err != nil {
		return 0, errors.New("select due self-test schedules")
	}
	type dueSchedule struct {
		id, organizationID, environmentID string
		dueAt                             time.Time
		intervalSeconds                   int64
	}
	due := make([]dueSchedule, 0, maximumSelfTestsPerSchedulePass)
	for rows.Next() {
		var item dueSchedule
		if err := rows.Scan(&item.id, &item.organizationID, &item.environmentID, &item.dueAt, &item.intervalSeconds); err != nil {
			rows.Close()
			return 0, errors.New("scan due self-test schedule")
		}
		if id.Validate(item.id, id.SelfTestSchedule) != nil ||
			id.Validate(item.organizationID, id.Organization) != nil ||
			id.Validate(item.environmentID, id.Environment) != nil || item.dueAt.IsZero() ||
			item.intervalSeconds < int64(time.Hour/time.Second) ||
			item.intervalSeconds > int64((30*24*time.Hour)/time.Second) {
			rows.Close()
			return 0, errors.New("stored self-test schedule is invalid")
		}
		due = append(due, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, errors.New("iterate due self-test schedules")
	}
	rows.Close()

	inserted := 0
	for _, item := range due {
		jobID, err := queue.newID(id.Job)
		if err != nil {
			return 0, errors.New("generate scheduled self-test job identifier")
		}
		interval := time.Duration(item.intervalSeconds) * time.Second
		next := nextScheduleAfter(item.dueAt.UTC(), interval, now.UTC())
		idempotencyKey := "self-test-schedule:" + item.id + ":" + item.dueAt.UTC().Format("20060102T150405Z")
		result, err := tx.Exec(ctx, `
			INSERT INTO jobs (
				job_id, organization_id, environment_id, job_type, idempotency_key,
				payload, status, available_at, max_attempts, created_at, updated_at
			) VALUES (
				$1, $2, $3, 'run_scheduled_self_test', $4,
				jsonb_build_object('schedule_id', $5::text, 'scheduled_for', $6::timestamptz),
				'pending', $6, 3, statement_timestamp(), statement_timestamp()
			)
			ON CONFLICT (job_type, idempotency_key) DO NOTHING
		`, jobID, item.organizationID, item.environmentID, idempotencyKey, item.id, item.dueAt.UTC())
		if err != nil {
			return 0, errors.New("enqueue scheduled self-test")
		}
		inserted += int(result.RowsAffected())
		if _, err := tx.Exec(ctx, `
			UPDATE self_test_schedules
			SET next_run_at = $2, last_enqueued_at = $3, updated_at = statement_timestamp()
			WHERE self_test_schedule_id = $1 AND status = 'active'
		`, item.id, next, item.dueAt.UTC()); err != nil {
			return 0, errors.New("advance scheduled self-test")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, errors.New("commit scheduled self-test enqueue")
	}
	return inserted, nil
}

func nextScheduleAfter(dueAt time.Time, interval time.Duration, now time.Time) time.Time {
	if dueAt.After(now) {
		return dueAt
	}
	elapsed := now.Sub(dueAt)
	steps := elapsed/interval + 1
	return dueAt.Add(steps * interval)
}

func scheduleBucket(now time.Time, interval time.Duration) time.Time {
	if interval == 24*time.Hour {
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
	return now.Truncate(interval)
}

// Claim recovers stale claims first, then claims one available job with
// SKIP LOCKED. A crashed worker can therefore never permanently strand work.
func (queue *Queue) Claim(ctx context.Context, staleAfter time.Duration) (Job, bool, error) {
	if queue == nil || ctx == nil || staleAfter < 10*time.Second || staleAfter > time.Hour {
		return Job{}, false, errors.New("worker claim input is invalid")
	}
	tx, err := queue.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Job{}, false, errors.New("begin worker job claim")
	}
	defer rollbackQueue(tx)
	if _, err := tx.Exec(ctx, `
		WITH stale AS (
			SELECT candidate.job_id
			FROM jobs AS candidate
			LEFT JOIN runtime_instances AS owner
			  ON owner.instance_id = candidate.locked_by_instance_id
			WHERE candidate.status = 'running'
			  AND (owner.instance_id IS NULL OR owner.heartbeat_at < statement_timestamp() - make_interval(secs => $1))
			ORDER BY candidate.locked_at, candidate.job_id
			LIMIT $2
			FOR UPDATE OF candidate SKIP LOCKED
		)
		UPDATE jobs AS job
		SET status = CASE WHEN job.attempt_count >= job.max_attempts THEN 'dead' ELSE 'pending' END,
		    available_at = CASE WHEN job.attempt_count >= job.max_attempts THEN job.available_at ELSE statement_timestamp() END,
		    locked_at = NULL,
		    locked_by_instance_id = NULL,
		    last_error_code = 'worker_heartbeat_expired',
		    last_error_detail = 'The previous worker heartbeat expired before the job completed.',
		    updated_at = statement_timestamp(),
		    completed_at = CASE WHEN job.attempt_count >= job.max_attempts THEN statement_timestamp() ELSE NULL END
		FROM stale
		WHERE job.job_id = stale.job_id
	`, int64(staleAfter/time.Second), maximumJobsPerClaimPass); err != nil {
		return Job{}, false, errors.New("recover stale worker jobs")
	}

	var job Job
	err = tx.QueryRow(ctx, `
		SELECT job_id, job_type, attempt_count + 1, max_attempts, available_at
		FROM jobs
		WHERE status = 'pending' AND available_at <= statement_timestamp()
		ORDER BY available_at, created_at, job_id
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`).Scan(&job.ID, &job.Type, &job.AttemptCount, &job.MaxAttempts, &job.ScheduledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return Job{}, false, errors.New("commit empty worker claim")
		}
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, errors.New("select worker job")
	}
	if _, ok := supportedJobTypes[job.Type]; !ok || id.Validate(job.ID, id.Job) != nil ||
		job.AttemptCount < 1 || job.AttemptCount > job.MaxAttempts || job.ScheduledAt.IsZero() {
		return Job{}, false, errors.New("stored worker job is invalid")
	}
	result, err := tx.Exec(ctx, `
		UPDATE jobs
		SET status = 'running', locked_at = statement_timestamp(), locked_by_instance_id = $2,
		    attempt_count = attempt_count + 1, last_error_code = NULL, last_error_detail = NULL,
		    updated_at = statement_timestamp(), completed_at = NULL
		WHERE job_id = $1 AND status = 'pending'
	`, job.ID, queue.instanceID)
	if err != nil {
		return Job{}, false, errors.New("persist worker job claim")
	}
	if result.RowsAffected() != 1 {
		return Job{}, false, ErrJobLeaseLost
	}
	if err := tx.Commit(ctx); err != nil {
		return Job{}, false, errors.New("commit worker job claim")
	}
	return job, true, nil
}

func (queue *Queue) Complete(ctx context.Context, job Job) error {
	if err := queue.validateClaim(job); err != nil {
		return err
	}
	result, err := queue.pool.Exec(ctx, `
		UPDATE jobs
		SET status = 'succeeded', locked_at = NULL, locked_by_instance_id = NULL,
		    updated_at = statement_timestamp(), completed_at = statement_timestamp()
		WHERE job_id = $1 AND status = 'running' AND locked_by_instance_id = $2
		  AND attempt_count = $3
	`, job.ID, queue.instanceID, job.AttemptCount)
	if err != nil {
		return errors.New("complete worker job")
	}
	if result.RowsAffected() != 1 {
		return ErrJobLeaseLost
	}
	return nil
}

// Fail records only a stable code and generic detail. Dependency errors never
// enter the durable job table. Retry delay is capped exponential backoff.
func (queue *Queue) Fail(ctx context.Context, job Job, code string) error {
	if err := queue.validateClaim(job); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`).MatchString(code) {
		code = "job_failed"
	}
	retrySeconds := int64(1 << min(job.AttemptCount, 8))
	result, err := queue.pool.Exec(ctx, `
		UPDATE jobs
		SET status = CASE WHEN attempt_count >= max_attempts THEN 'dead' ELSE 'pending' END,
		    available_at = CASE WHEN attempt_count >= max_attempts THEN available_at
		                        ELSE statement_timestamp() + make_interval(secs => $4) END,
		    locked_at = NULL, locked_by_instance_id = NULL,
		    last_error_code = $5,
		    last_error_detail = 'The maintenance job failed; inspect redaction-safe process telemetry.',
		    updated_at = statement_timestamp(),
		    completed_at = CASE WHEN attempt_count >= max_attempts THEN statement_timestamp() ELSE NULL END
		WHERE job_id = $1 AND status = 'running' AND locked_by_instance_id = $2
		  AND attempt_count = $3
	`, job.ID, queue.instanceID, job.AttemptCount, retrySeconds, code)
	if err != nil {
		return errors.New("fail worker job")
	}
	if result.RowsAffected() != 1 {
		return ErrJobLeaseLost
	}
	return nil
}

func (queue *Queue) validateClaim(job Job) error {
	if queue == nil || id.Validate(job.ID, id.Job) != nil || supportedJobTypes[job.Type] == 0 ||
		job.AttemptCount < 1 || job.MaxAttempts < job.AttemptCount || job.MaxAttempts > 100 || job.ScheduledAt.IsZero() {
		return fmt.Errorf("invalid worker job claim: %w", ErrJobLeaseLost)
	}
	return nil
}

func rollbackQueue(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
