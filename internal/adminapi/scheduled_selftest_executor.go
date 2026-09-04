package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/telemetry"
)

// ScheduledSelfTestExecutor is the worker-facing implementation of the
// durable scheduled diagnostic contract. Its public method accepts only a job
// identifier; tenant, target, authorization, budget and credential metadata
// are loaded from PostgreSQL and never enter logs.
type ScheduledSelfTestExecutor struct {
	pool      *pgxpool.Pool
	service   scheduledSelfTestService
	telemetry *telemetry.Registry
	newID     func(id.Prefix) (string, error)
}

// NewScheduledSelfTestExecutor constructs the production worker capability.
func NewScheduledSelfTestExecutor(
	pool *pgxpool.Pool,
	configurations *configuration.Store,
	secretStore dataplane.SecretStore,
	targets dataplane.TargetFactory,
	observability *telemetry.Registry,
) (*ScheduledSelfTestExecutor, error) {
	if pool == nil || configurations == nil {
		return nil, errors.New("scheduled self-test executor dependency is nil")
	}
	service, err := newProductionScheduledSelfTestService(
		productionSelfTestSnapshotLoader{store: configurations}, secretStore, targets,
	)
	if err != nil {
		return nil, err
	}
	return &ScheduledSelfTestExecutor{
		pool: pool, service: service, telemetry: observability, newID: id.New,
	}, nil
}

type scheduledSelfTestExecution struct {
	jobID          string
	scheduleID     string
	organizationID string
	applicationID  string
	environmentID  string
	revisionID     string
	kind           string
	upstream       string
	model          string
	maxCost        int64
	startedAt      time.Time
	selfTestID     string
	bindings       []scheduledSelfTestSecretBinding
	failureCheck   string
	failureDetail  string
	recovered      bool
	terminal       bool
}

func (executor *ScheduledSelfTestExecutor) ExecuteScheduled(ctx context.Context, jobID string) (int64, error) {
	if executor == nil || executor.pool == nil || executor.service == nil || ctx == nil ||
		id.Validate(jobID, id.Job) != nil {
		return 0, errors.New("scheduled self-test execution is invalid")
	}
	execution, err := executor.prepareExecution(ctx, jobID)
	if err != nil {
		return 0, err
	}
	if execution.terminal {
		return 1, nil
	}
	var result credentialSelfTestResult
	outcome := "failed"
	if execution.failureCheck != "" {
		result = failedCredentialSelfTest(nil, execution.failureCheck, execution.failureDetail)
		outcome = "rejected"
	} else {
		result = executor.service.RunBound(ctx, preparedScheduledSelfTest{
			Scope: configuration.TenantScope{
				OrganizationID: execution.organizationID,
				ApplicationID:  execution.applicationID,
				EnvironmentID:  execution.environmentID,
			},
			RevisionID: execution.revisionID, Kind: execution.kind,
			UpstreamID: execution.upstream, ModelID: execution.model,
			MaxCostNanoUSD: execution.maxCost, SecretBindings: execution.bindings,
		})
		if result.State == "passed" {
			outcome = "passed"
		}
	}
	if result.State != "passed" && result.State != "failed" {
		result = failedCredentialSelfTest(nil, "runner", "The scheduled self-test runner returned an invalid result.")
		outcome = "failed"
	}
	if err := executor.persistExecutionResult(ctx, execution, result); err != nil {
		return 0, err
	}
	if executor.telemetry != nil {
		executor.telemetry.RecordScheduledSelfTest(ctx, telemetry.Labels{
			Application: execution.applicationID, Environment: execution.environmentID, Outcome: outcome,
		})
	}
	return 1, nil
}

func (executor *ScheduledSelfTestExecutor) prepareExecution(
	ctx context.Context,
	jobID string,
) (scheduledSelfTestExecution, error) {
	tx, err := executor.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return scheduledSelfTestExecution{}, errors.New("begin scheduled self-test execution")
	}
	defer rollbackOperational(tx)
	var execution scheduledSelfTestExecution
	execution.jobID = jobID
	var scheduleStatus string
	var authorizationMethod, authorizationCredentialID, authorizedAdminUserID string
	var dailyCostLimit, intervalSeconds int64
	var payloadScheduleID string
	err = tx.QueryRow(ctx, `
		SELECT schedule.self_test_schedule_id,
		       COALESCE(run.self_test_schedule_id, job.payload->>'schedule_id'),
		       schedule.organization_id, schedule.application_id, schedule.environment_id,
		       schedule.config_revision_id, schedule.kind, schedule.upstream_key,
		       schedule.model_key, schedule.max_cost_nano_usd,
		       schedule.daily_cost_limit_nano_usd, schedule.interval_seconds,
		       schedule.status, schedule.authorization_method,
		       schedule.authorization_credential_id, schedule.authorized_admin_user_id
		FROM jobs AS job
		LEFT JOIN scheduled_self_test_runs AS run ON run.job_id = job.job_id
		JOIN self_test_schedules AS schedule
		  ON schedule.self_test_schedule_id = COALESCE(run.self_test_schedule_id, job.payload->>'schedule_id')
		 AND schedule.organization_id = job.organization_id
		 AND schedule.environment_id = job.environment_id
		WHERE job.job_id = $1 AND job.job_type = 'run_scheduled_self_test'
		  AND job.status = 'running'
		FOR UPDATE OF job, schedule
	`, jobID).Scan(
		&execution.scheduleID, &payloadScheduleID, &execution.organizationID,
		&execution.applicationID, &execution.environmentID, &execution.revisionID,
		&execution.kind, &execution.upstream, &execution.model, &execution.maxCost,
		&dailyCostLimit, &intervalSeconds, &scheduleStatus, &authorizationMethod,
		&authorizationCredentialID, &authorizedAdminUserID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return scheduledSelfTestExecution{}, errors.New("scheduled self-test job binding is unavailable")
	}
	if err != nil {
		return scheduledSelfTestExecution{}, errors.New("read scheduled self-test job binding")
	}
	if payloadScheduleID != execution.scheduleID ||
		id.Validate(execution.scheduleID, id.SelfTestSchedule) != nil ||
		id.Validate(execution.organizationID, id.Organization) != nil ||
		id.Validate(execution.applicationID, id.Application) != nil ||
		id.Validate(execution.environmentID, id.Environment) != nil ||
		id.Validate(execution.revisionID, id.ConfigRevision) != nil ||
		(execution.kind != "upstream" && execution.kind != "openrouter") ||
		!selfTestIdentifierPattern.MatchString(execution.upstream) ||
		!selfTestIdentifierPattern.MatchString(execution.model) ||
		execution.maxCost < 1 || execution.maxCost > maximumSelfTestCostNanoUSD ||
		dailyCostLimit < execution.maxCost || dailyCostLimit > maximumSelfTestScheduleDailyCost ||
		intervalSeconds < int64(minimumSelfTestScheduleInterval/time.Second) ||
		intervalSeconds > int64(maximumSelfTestScheduleInterval/time.Second) ||
		authorizationMethod != "api_token" ||
		id.Validate(authorizationCredentialID, id.AdminAPIToken) != nil ||
		id.Validate(authorizedAdminUserID, id.AdminUser) != nil {
		return scheduledSelfTestExecution{}, errors.New("stored scheduled self-test binding is invalid")
	}

	var existingStatus, existingSelfTestID string
	var existingStartedAt time.Time
	var existingResult []byte
	err = tx.QueryRow(ctx, `
		SELECT status, self_test_id, started_at, COALESCE(result, '{}'::jsonb)
		FROM scheduled_self_test_runs WHERE job_id = $1
	`, jobID).Scan(&existingStatus, &existingSelfTestID, &existingStartedAt, &existingResult)
	if err == nil {
		execution.selfTestID = existingSelfTestID
		execution.startedAt = existingStartedAt.UTC()
		if existingStatus == "completed" {
			var run selfTestDocument
			if len(existingResult) == 0 || len(existingResult) > 64<<10 ||
				json.Unmarshal(existingResult, &run) != nil || !validStoredSelfTest(run) ||
				run.ID != existingSelfTestID || run.ScheduleID != execution.scheduleID ||
				run.EnvironmentID != execution.environmentID ||
				run.ConfigRevisionID != execution.revisionID {
				return scheduledSelfTestExecution{}, errors.New("stored scheduled self-test result is invalid")
			}
			execution.terminal = true
			if err := tx.Commit(ctx); err != nil {
				return scheduledSelfTestExecution{}, errors.New("commit completed scheduled self-test inspection")
			}
			return execution, nil
		}
		if existingStatus != "dispatching" {
			return scheduledSelfTestExecution{}, errors.New("stored scheduled self-test dispatch state is invalid")
		}
		completedAt := time.Now().UTC()
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&completedAt); err != nil {
			return scheduledSelfTestExecution{}, errors.New("read scheduled self-test recovery time")
		}
		run := selfTestDocument{
			ID: existingSelfTestID, ScheduleID: execution.scheduleID,
			EnvironmentID:    execution.environmentID,
			ConfigRevisionID: execution.revisionID, Kind: execution.kind,
			State: "failed", CreatedAt: existingStartedAt.UTC(), CompletedAt: utcTimePointer(completedAt),
			Checks: []selfTestCheck{{
				Name: "execution_recovery", State: "failed",
				SafeDetail: "A previous worker stopped after the durable dispatch marker; the request was not repeated.",
			}},
		}
		if err := executor.completeExecutionTx(ctx, tx, execution, run, completedAt.UTC()); err != nil {
			return scheduledSelfTestExecution{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return scheduledSelfTestExecution{}, errors.New("commit scheduled self-test recovery")
		}
		execution.recovered = true
		execution.terminal = true
		if executor.telemetry != nil {
			executor.telemetry.RecordScheduledSelfTest(ctx, telemetry.Labels{
				Application: execution.applicationID, Environment: execution.environmentID, Outcome: "recovered",
			})
		}
		return execution, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return scheduledSelfTestExecution{}, errors.New("inspect scheduled self-test dispatch marker")
	}

	execution.selfTestID, err = executor.newID(id.SelfTest)
	if err != nil {
		return scheduledSelfTestExecution{}, errors.New("generate scheduled self-test identifier")
	}
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&execution.startedAt); err != nil {
		return scheduledSelfTestExecution{}, errors.New("read scheduled self-test start time")
	}
	execution.startedAt = execution.startedAt.UTC()
	permanentFailure := false
	if scheduleStatus != "active" {
		execution.failureCheck = "schedule"
		execution.failureDetail = "The scheduled self-test is no longer active."
	} else {
		var authorized bool
		err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM admin_api_tokens AS token
				JOIN admin_memberships AS membership
				  ON membership.organization_id = token.organization_id
				 AND membership.admin_user_id = token.admin_user_id
				JOIN admin_users AS admin_user ON admin_user.admin_user_id = token.admin_user_id
				JOIN organizations AS organization ON organization.organization_id = token.organization_id
				JOIN applications AS application
				  ON application.organization_id = token.organization_id
				 AND application.application_id = $4
				JOIN environments AS environment
				  ON environment.organization_id = token.organization_id
				 AND environment.application_id = application.application_id
				 AND environment.environment_id = $5
				WHERE token.organization_id = $1 AND token.admin_api_token_id = $2
				  AND token.admin_user_id = $3 AND token.revoked_at IS NULL
				  AND (token.expires_at IS NULL OR token.expires_at > transaction_timestamp())
				  AND 'run_self_tests' = ANY(token.scopes)
				  AND membership.status = 'active'
				  AND membership.role IN ('owner', 'admin', 'operator')
				  AND admin_user.status = 'active' AND organization.status = 'active'
				  AND application.status = 'active' AND environment.status = 'active'
			)
		`, execution.organizationID, authorizationCredentialID, authorizedAdminUserID,
			execution.applicationID, execution.environmentID).Scan(&authorized)
		if err != nil {
			return scheduledSelfTestExecution{}, errors.New("validate scheduled self-test authorization")
		}
		if !authorized {
			execution.failureCheck = "authorization"
			execution.failureDetail = "The durable schedule authorization is no longer valid."
			permanentFailure = true
		}
	}
	if execution.failureCheck == "" {
		var exactConfiguration bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM active_config_revisions
				WHERE organization_id = $1 AND application_id = $2
				  AND environment_id = $3 AND config_revision_id = $4
			)
		`, execution.organizationID, execution.applicationID,
			execution.environmentID, execution.revisionID).Scan(&exactConfiguration); err != nil {
			return scheduledSelfTestExecution{}, errors.New("validate scheduled configuration binding")
		}
		if !exactConfiguration {
			execution.failureCheck = "active_configuration"
			execution.failureDetail = "The pinned configuration revision is no longer active."
			permanentFailure = true
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT binding.secret_reference, binding.secret_record_id, binding.secret_version,
		       current.secret_record_id IS NOT NULL
		FROM self_test_schedule_secret_bindings AS binding
		LEFT JOIN secret_records AS current
		  ON current.organization_id = binding.organization_id
		 AND current.application_id = binding.application_id
		 AND current.environment_id = binding.environment_id
		 AND current.name = substring(binding.secret_reference FROM 8)
		 AND current.secret_record_id = binding.secret_record_id
		 AND current.version = binding.secret_version
		 AND current.rotated_at IS NULL AND current.destroyed_at IS NULL
		WHERE binding.self_test_schedule_id = $1
		ORDER BY binding.ordinal
	`, execution.scheduleID)
	if err != nil {
		return scheduledSelfTestExecution{}, errors.New("read scheduled credential bindings")
	}
	credentialsCurrent := true
	for rows.Next() {
		var binding scheduledSelfTestSecretBinding
		var current bool
		if err := rows.Scan(&binding.Reference, &binding.RecordID, &binding.Version, &current); err != nil {
			rows.Close()
			return scheduledSelfTestExecution{}, errors.New("scan scheduled credential binding")
		}
		credentialsCurrent = credentialsCurrent && current
		execution.bindings = append(execution.bindings, binding)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return scheduledSelfTestExecution{}, errors.New("iterate scheduled credential bindings")
	}
	rows.Close()
	if execution.failureCheck == "" && !credentialsCurrent {
		execution.failureCheck = "credential_binding"
		execution.failureDetail = "A pinned provider credential revision is no longer current."
		permanentFailure = true
	}

	budgetDate := execution.startedAt.UTC().Truncate(24 * time.Hour)
	reservedCost := int64(0)
	if execution.failureCheck == "" {
		var alreadyReserved int64
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(sum(reserved_cost_nano_usd), 0)
			FROM scheduled_self_test_runs
			WHERE self_test_schedule_id = $1 AND budget_date = $2
		`, execution.scheduleID, budgetDate).Scan(&alreadyReserved); err != nil {
			return scheduledSelfTestExecution{}, errors.New("read scheduled self-test budget")
		}
		if alreadyReserved > dailyCostLimit-execution.maxCost {
			execution.failureCheck = "budget"
			execution.failureDetail = "The UTC-day scheduled self-test cost budget is exhausted."
		} else {
			reservedCost = execution.maxCost
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO scheduled_self_test_runs (
			job_id, self_test_schedule_id, self_test_id, status, budget_date,
			reserved_cost_nano_usd, started_at
		) VALUES ($1,$2,$3,'dispatching',$4,$5,$6)
	`, execution.jobID, execution.scheduleID, execution.selfTestID,
		budgetDate, reservedCost, execution.startedAt); err != nil {
		return scheduledSelfTestExecution{}, errors.New("persist scheduled self-test dispatch marker")
	}
	if permanentFailure {
		if _, err := tx.Exec(ctx, `
			UPDATE self_test_schedules
			SET status = 'disabled', next_run_at = NULL, disabled_at = $2,
			    disabled_reason_code = $3, updated_at = $2
			WHERE self_test_schedule_id = $1 AND status = 'active'
		`, execution.scheduleID, execution.startedAt, execution.failureCheck); err != nil {
			return scheduledSelfTestExecution{}, errors.New("disable invalid scheduled self-test")
		}
		if err := executor.insertSystemAudit(ctx, tx, execution, "system.self_test_schedule_disable",
			"self_test_schedule", execution.scheduleID, execution.startedAt); err != nil {
			return scheduledSelfTestExecution{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return scheduledSelfTestExecution{}, errors.New("commit scheduled self-test dispatch marker")
	}
	return execution, nil
}

func (executor *ScheduledSelfTestExecutor) persistExecutionResult(
	ctx context.Context,
	execution scheduledSelfTestExecution,
	result credentialSelfTestResult,
) error {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := executor.pool.BeginTx(persistCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return errors.New("begin scheduled self-test result")
	}
	defer rollbackOperational(tx)
	var status string
	if err := tx.QueryRow(persistCtx, `
		SELECT status FROM scheduled_self_test_runs WHERE job_id = $1 FOR UPDATE
	`, execution.jobID).Scan(&status); err != nil {
		return errors.New("lock scheduled self-test result")
	}
	if status == "completed" {
		if err := tx.Commit(persistCtx); err != nil {
			return errors.New("commit completed scheduled self-test result")
		}
		return nil
	}
	if status != "dispatching" {
		return errors.New("stored scheduled self-test result state is invalid")
	}
	var completedAt time.Time
	if err := tx.QueryRow(persistCtx, `SELECT transaction_timestamp()`).Scan(&completedAt); err != nil {
		return errors.New("read scheduled self-test completion time")
	}
	run := selfTestDocument{
		ID: execution.selfTestID, ScheduleID: execution.scheduleID,
		EnvironmentID:    execution.environmentID,
		ConfigRevisionID: execution.revisionID, Kind: execution.kind,
		State: result.State, CreatedAt: execution.startedAt.UTC(), CompletedAt: utcTimePointer(completedAt),
		Checks: append([]selfTestCheck(nil), result.Checks...),
	}
	if !validStoredSelfTest(run) {
		return errors.New("scheduled self-test result is invalid")
	}
	if err := executor.completeExecutionTx(persistCtx, tx, execution, run, completedAt.UTC()); err != nil {
		return err
	}
	if err := tx.Commit(persistCtx); err != nil {
		return errors.New("commit scheduled self-test result")
	}
	return nil
}

func (executor *ScheduledSelfTestExecutor) completeExecutionTx(
	ctx context.Context,
	tx pgx.Tx,
	execution scheduledSelfTestExecution,
	run selfTestDocument,
	completedAt time.Time,
) error {
	payload, err := json.Marshal(run)
	if err != nil || len(payload) > 64<<10 {
		return errors.New("encode scheduled self-test result")
	}
	result, err := tx.Exec(ctx, `
		UPDATE scheduled_self_test_runs
		SET status = 'completed', result = $2, completed_at = $3
		WHERE job_id = $1 AND status = 'dispatching'
	`, execution.jobID, payload, completedAt.UTC())
	if err != nil || result.RowsAffected() != 1 {
		return errors.New("persist scheduled self-test result")
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = $2, updated_at = $3 WHERE job_id = $1`,
		execution.jobID, payload, completedAt.UTC()); err != nil {
		return errors.New("publish scheduled self-test result")
	}
	return executor.insertSystemAudit(ctx, tx, execution, "system.self_test_schedule_run",
		"self_test", run.ID, completedAt.UTC())
}

func (executor *ScheduledSelfTestExecutor) insertSystemAudit(
	ctx context.Context,
	tx pgx.Tx,
	execution scheduledSelfTestExecution,
	action string,
	resourceType string,
	resourceID string,
	at time.Time,
) error {
	eventID, err := executor.newID(id.AuditEvent)
	if err != nil {
		return errors.New("generate scheduled self-test audit identifier")
	}
	change, err := adminauth.NewPublicAuditChange("state", adminauth.AuditSet)
	if err != nil {
		return err
	}
	mutation, err := adminauth.NewAuditMutation(
		eventID, execution.organizationID, execution.environmentID, adminauth.SystemActor(),
		action, resourceType, resourceID, adminauth.AuditSucceeded, "", at.UTC(),
		[]adminauth.AuditChange{change},
	)
	if err != nil {
		return err
	}
	if err := adminauth.InsertAuditMutation(ctx, tx, mutation); err != nil {
		return fmt.Errorf("insert scheduled self-test audit event: %w", err)
	}
	return nil
}

func utcTimePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}
