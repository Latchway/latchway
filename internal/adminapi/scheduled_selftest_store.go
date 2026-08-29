package adminapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
)

const (
	minimumSelfTestScheduleInterval  = time.Hour
	maximumSelfTestScheduleInterval  = 30 * 24 * time.Hour
	maximumSelfTestScheduleDailyCost = int64(10_000_000_000)
	maximumActiveSelfTestSchedules   = int64(32)
)

type createSelfTestScheduleInput struct {
	Kind           string
	Environment    string
	Upstream       string
	Model          string
	MaxCost        int64
	DailyCostLimit int64
	Interval       time.Duration
	RequestID      string
}

type selfTestScheduleDocument struct {
	ID                        string     `json:"id"`
	EnvironmentID             string     `json:"environment_id"`
	ApplicationID             string     `json:"application_id"`
	ConfigRevisionID          string     `json:"config_revision_id"`
	Kind                      string     `json:"kind"`
	Upstream                  string     `json:"upstream"`
	Model                     string     `json:"model"`
	MaxCostNanoUSD            int64      `json:"max_cost_nano_usd"`
	DailyCostLimitNanoUSD     int64      `json:"daily_cost_limit_nano_usd"`
	IntervalSeconds           int64      `json:"interval_seconds"`
	Status                    string     `json:"status"`
	NextRunAt                 *time.Time `json:"next_run_at,omitempty"`
	LastEnqueuedAt            *time.Time `json:"last_enqueued_at,omitempty"`
	LastSelfTestID            string     `json:"last_self_test_id,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
	DisabledAt                *time.Time `json:"disabled_at,omitempty"`
	DisabledReasonCode        string     `json:"disabled_reason_code,omitempty"`
	AuthorizationCredentialID string     `json:"authorization_credential_id"`
}

func (store *operationalStore) createSelfTestSchedule(
	ctx context.Context,
	principal adminauth.Principal,
	input createSelfTestScheduleInput,
) (selfTestScheduleDocument, error) {
	if store == nil || store.selfSchedules == nil || ctx == nil ||
		id.Validate(input.Environment, id.Environment) != nil ||
		id.Validate(input.RequestID, id.AdminRequest) != nil ||
		(input.Kind != "upstream" && input.Kind != "openrouter") ||
		!selfTestIdentifierPattern.MatchString(input.Upstream) ||
		!selfTestIdentifierPattern.MatchString(input.Model) ||
		input.MaxCost < 1 || input.MaxCost > maximumSelfTestCostNanoUSD ||
		input.DailyCostLimit < input.MaxCost || input.DailyCostLimit > maximumSelfTestScheduleDailyCost ||
		input.Interval < minimumSelfTestScheduleInterval || input.Interval > maximumSelfTestScheduleInterval ||
		input.Interval%time.Second != 0 {
		return selfTestScheduleDocument{}, errOperationalInvalid
	}
	if principal.Method != adminauth.AuthenticationAPIToken ||
		id.Validate(principal.CredentialID, id.AdminAPIToken) != nil ||
		!principal.Allows(adminauth.RunSelfTests, adminauth.AuthorizationContext{}) {
		return selfTestScheduleDocument{}, errOperationalForbidden
	}
	credentialID := principal.CredentialID
	runsPerDay := int64((24*time.Hour + input.Interval - 1) / input.Interval)
	if input.MaxCost > input.DailyCostLimit/runsPerDay {
		return selfTestScheduleDocument{}, errOperationalInvalid
	}

	var applicationID string
	err := store.pool.QueryRow(ctx, `
		SELECT environment.application_id
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE environment.organization_id = $1 AND environment.environment_id = $2
		  AND organization.status = 'active' AND application.status = 'active'
		  AND environment.status = 'active'
	`, principal.OrganizationID, input.Environment).Scan(&applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestScheduleDocument{}, errOperationalNotFound
	}
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("resolve scheduled self-test environment: %w", err)
	}
	prepared, err := store.selfSchedules.Prepare(ctx, credentialSelfTestInput{
		Scope: configuration.TenantScope{
			OrganizationID: principal.OrganizationID,
			ApplicationID:  applicationID,
			EnvironmentID:  input.Environment,
		},
		Kind: input.Kind, UpstreamID: input.Upstream, ModelID: input.Model,
		MaxCostNano: input.MaxCost,
	})
	if err != nil {
		return selfTestScheduleDocument{}, errOperationalInvalid
	}
	scheduleID, err := store.newID(id.SelfTestSchedule)
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("generate self-test schedule ID: %w", err)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("begin self-test schedule creation: %w", err)
	}
	defer rollbackOperational(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, principal.OrganizationID); err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("lock self-test schedule tenant: %w", err)
	}
	var now time.Time
	var activeCount int64
	err = tx.QueryRow(ctx, `
		SELECT transaction_timestamp(), count(*)
		FROM self_test_schedules
		WHERE organization_id = $1 AND status = 'active'
	`, principal.OrganizationID).Scan(&now, &activeCount)
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("count active self-test schedules: %w", err)
	}
	if activeCount >= maximumActiveSelfTestSchedules {
		return selfTestScheduleDocument{}, errOperationalInvalid
	}
	var authorizedAdminUserID string
	err = tx.QueryRow(ctx, `
		SELECT token.admin_user_id
		FROM admin_api_tokens AS token
		JOIN admin_memberships AS membership
		  ON membership.organization_id = token.organization_id
		 AND membership.admin_user_id = token.admin_user_id
		JOIN admin_users AS admin_user ON admin_user.admin_user_id = token.admin_user_id
		JOIN active_config_revisions AS active
		  ON active.organization_id = token.organization_id
		 AND active.environment_id = $4
		WHERE token.organization_id = $1
		  AND token.admin_api_token_id = $2
		  AND token.admin_user_id = $3
		  AND token.revoked_at IS NULL
		  AND (token.expires_at IS NULL OR token.expires_at > transaction_timestamp())
		  AND 'run_self_tests' = ANY(token.scopes)
		  AND membership.status = 'active'
		  AND membership.role IN ('owner', 'admin', 'operator')
		  AND admin_user.status = 'active'
		  AND active.application_id = $5
		  AND active.config_revision_id = $6
	`, principal.OrganizationID, credentialID, principal.AdminUserID,
		input.Environment, applicationID, prepared.RevisionID).Scan(&authorizedAdminUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestScheduleDocument{}, errOperationalForbidden
	}
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("verify self-test schedule authorization: %w", err)
	}
	for _, binding := range prepared.SecretBindings {
		var current bool
		err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM secret_records
				WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
				  AND name = $4 AND secret_record_id = $5 AND version = $6
				  AND rotated_at IS NULL AND destroyed_at IS NULL
			)
		`, principal.OrganizationID, applicationID, input.Environment,
			binding.Reference[len("secret/"):], binding.RecordID, binding.Version).Scan(&current)
		if err != nil {
			return selfTestScheduleDocument{}, fmt.Errorf("verify scheduled secret binding: %w", err)
		}
		if !current {
			return selfTestScheduleDocument{}, errOperationalInvalid
		}
	}
	nextRun := now.UTC().Add(input.Interval)
	_, err = tx.Exec(ctx, `
		INSERT INTO self_test_schedules (
			self_test_schedule_id, organization_id, application_id, environment_id,
			config_revision_id, kind, upstream_key, model_key, max_cost_nano_usd,
			daily_cost_limit_nano_usd, interval_seconds, authorized_admin_user_id,
			authorization_method, authorization_credential_id, status, next_run_at,
			created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'api_token',$13,'active',$14,$15,$15)
	`, scheduleID, principal.OrganizationID, applicationID, input.Environment,
		prepared.RevisionID, input.Kind, input.Upstream, input.Model, input.MaxCost,
		input.DailyCostLimit, int64(input.Interval/time.Second), authorizedAdminUserID,
		credentialID, nextRun, now.UTC())
	if err != nil {
		return selfTestScheduleDocument{}, mapOperationalDatabase("persist self-test schedule", err)
	}
	for ordinal, binding := range prepared.SecretBindings {
		if _, err := tx.Exec(ctx, `
			INSERT INTO self_test_schedule_secret_bindings (
				self_test_schedule_id, ordinal, organization_id, application_id,
				environment_id, secret_reference, secret_record_id, secret_version
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		`, scheduleID, ordinal, principal.OrganizationID, applicationID, input.Environment,
			binding.Reference, binding.RecordID, binding.Version); err != nil {
			return selfTestScheduleDocument{}, mapOperationalDatabase("persist scheduled secret binding", err)
		}
	}
	change, err := adminauth.NewPublicAuditChange("status", adminauth.AuditSet)
	if err != nil {
		return selfTestScheduleDocument{}, err
	}
	if err := store.audit(ctx, tx, principal, input.Environment, "admin.self_test_schedule_create",
		"self_test_schedule", scheduleID, input.RequestID, now, []adminauth.AuditChange{change}); err != nil {
		return selfTestScheduleDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return selfTestScheduleDocument{}, mapOperationalCommit("commit self-test schedule", err)
	}
	return selfTestScheduleDocument{
		ID: scheduleID, EnvironmentID: input.Environment, ApplicationID: applicationID,
		ConfigRevisionID: prepared.RevisionID, Kind: input.Kind, Upstream: input.Upstream,
		Model: input.Model, MaxCostNanoUSD: input.MaxCost,
		DailyCostLimitNanoUSD: input.DailyCostLimit, IntervalSeconds: int64(input.Interval / time.Second),
		Status: "active", NextRunAt: &nextRun, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
		AuthorizationCredentialID: credentialID,
	}, nil
}

func (store *operationalStore) listSelfTestSchedules(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	page operationalPage,
) ([]selfTestScheduleDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || page.validate(id.SelfTestSchedule) != nil {
		return nil, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RunSelfTests, adminauth.AuthorizationContext{}) {
		return nil, errOperationalForbidden
	}
	rows, err := store.pool.Query(ctx, selfTestScheduleSelect+`
		WHERE schedule.organization_id = $1 AND schedule.environment_id = $2
		  AND ($3::timestamptz IS NULL OR (schedule.created_at, schedule.self_test_schedule_id) < ($3, $4::text))
		ORDER BY schedule.created_at DESC, schedule.self_test_schedule_id DESC
		LIMIT $5
	`, principal.OrganizationID, environmentID, nullableTime(page.after), nullableString(page.afterID), page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list self-test schedules: %w", err)
	}
	defer rows.Close()
	items := make([]selfTestScheduleDocument, 0, page.size+1)
	for rows.Next() {
		item, scanErr := scanSelfTestSchedule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate self-test schedules: %w", err)
	}
	return items, nil
}

func (store *operationalStore) getSelfTestSchedule(
	ctx context.Context,
	principal adminauth.Principal,
	scheduleID string,
) (selfTestScheduleDocument, error) {
	if id.Validate(scheduleID, id.SelfTestSchedule) != nil {
		return selfTestScheduleDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RunSelfTests, adminauth.AuthorizationContext{}) {
		return selfTestScheduleDocument{}, errOperationalForbidden
	}
	item, err := scanSelfTestSchedule(store.pool.QueryRow(ctx, selfTestScheduleSelect+`
		WHERE schedule.organization_id = $1 AND schedule.self_test_schedule_id = $2
	`, principal.OrganizationID, scheduleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestScheduleDocument{}, errOperationalNotFound
	}
	return item, err
}

func (store *operationalStore) disableSelfTestSchedule(
	ctx context.Context,
	principal adminauth.Principal,
	scheduleID string,
	requestID string,
) (selfTestScheduleDocument, error) {
	if id.Validate(scheduleID, id.SelfTestSchedule) != nil || id.Validate(requestID, id.AdminRequest) != nil {
		return selfTestScheduleDocument{}, errOperationalInvalid
	}
	if !principal.Allows(adminauth.RunSelfTests, adminauth.AuthorizationContext{}) {
		return selfTestScheduleDocument{}, errOperationalForbidden
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("begin self-test schedule disable: %w", err)
	}
	defer rollbackOperational(tx)
	var environmentID string
	var now time.Time
	err = tx.QueryRow(ctx, `
		SELECT environment_id, transaction_timestamp()
		FROM self_test_schedules
		WHERE organization_id = $1 AND self_test_schedule_id = $2
		FOR UPDATE
	`, principal.OrganizationID, scheduleID).Scan(&environmentID, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestScheduleDocument{}, errOperationalNotFound
	}
	if err != nil {
		return selfTestScheduleDocument{}, fmt.Errorf("lock self-test schedule: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE self_test_schedules
		SET status = 'disabled', next_run_at = NULL,
		    disabled_at = COALESCE(disabled_at, $3),
		    disabled_reason_code = COALESCE(disabled_reason_code, 'operator_disabled'),
		    updated_at = $3
		WHERE organization_id = $1 AND self_test_schedule_id = $2
	`, principal.OrganizationID, scheduleID, now.UTC()); err != nil {
		return selfTestScheduleDocument{}, mapOperationalDatabase("disable self-test schedule", err)
	}
	change, err := adminauth.NewPublicAuditChange("status", adminauth.AuditSet)
	if err != nil {
		return selfTestScheduleDocument{}, err
	}
	if err := store.audit(ctx, tx, principal, environmentID, "admin.self_test_schedule_disable",
		"self_test_schedule", scheduleID, requestID, now, []adminauth.AuditChange{change}); err != nil {
		return selfTestScheduleDocument{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return selfTestScheduleDocument{}, mapOperationalCommit("commit self-test schedule disable", err)
	}
	return store.getSelfTestSchedule(ctx, principal, scheduleID)
}

const selfTestScheduleSelect = `
	SELECT schedule.self_test_schedule_id, schedule.environment_id, schedule.application_id,
	       schedule.config_revision_id, schedule.kind, schedule.upstream_key, schedule.model_key,
	       schedule.max_cost_nano_usd, schedule.daily_cost_limit_nano_usd,
	       schedule.interval_seconds, schedule.status, schedule.next_run_at,
	       schedule.last_enqueued_at, COALESCE(last_run.self_test_id, ''),
	       schedule.created_at, schedule.updated_at, schedule.disabled_at,
	       COALESCE(schedule.disabled_reason_code, ''), schedule.authorization_credential_id
	FROM self_test_schedules AS schedule
	LEFT JOIN LATERAL (
		SELECT run.self_test_id
		FROM scheduled_self_test_runs AS run
		WHERE run.self_test_schedule_id = schedule.self_test_schedule_id
		ORDER BY run.started_at DESC, run.self_test_id DESC
		LIMIT 1
	) AS last_run ON true
`

type selfTestScheduleScanner interface {
	Scan(...any) error
}

func scanSelfTestSchedule(scanner selfTestScheduleScanner) (selfTestScheduleDocument, error) {
	var item selfTestScheduleDocument
	if err := scanner.Scan(
		&item.ID, &item.EnvironmentID, &item.ApplicationID, &item.ConfigRevisionID,
		&item.Kind, &item.Upstream, &item.Model, &item.MaxCostNanoUSD,
		&item.DailyCostLimitNanoUSD, &item.IntervalSeconds, &item.Status,
		&item.NextRunAt, &item.LastEnqueuedAt, &item.LastSelfTestID,
		&item.CreatedAt, &item.UpdatedAt, &item.DisabledAt, &item.DisabledReasonCode,
		&item.AuthorizationCredentialID,
	); err != nil {
		return selfTestScheduleDocument{}, err
	}
	if !validSelfTestScheduleDocument(item) {
		return selfTestScheduleDocument{}, errOperationalCorrupt
	}
	return item, nil
}

func validSelfTestScheduleDocument(item selfTestScheduleDocument) bool {
	if id.Validate(item.ID, id.SelfTestSchedule) != nil ||
		id.Validate(item.EnvironmentID, id.Environment) != nil ||
		id.Validate(item.ApplicationID, id.Application) != nil ||
		id.Validate(item.ConfigRevisionID, id.ConfigRevision) != nil ||
		id.Validate(item.AuthorizationCredentialID, id.AdminAPIToken) != nil ||
		(item.Kind != "upstream" && item.Kind != "openrouter") ||
		!selfTestIdentifierPattern.MatchString(item.Upstream) ||
		!selfTestIdentifierPattern.MatchString(item.Model) ||
		item.MaxCostNanoUSD < 1 || item.MaxCostNanoUSD > maximumSelfTestCostNanoUSD ||
		item.DailyCostLimitNanoUSD < item.MaxCostNanoUSD ||
		item.DailyCostLimitNanoUSD > maximumSelfTestScheduleDailyCost ||
		item.IntervalSeconds < int64(minimumSelfTestScheduleInterval/time.Second) ||
		item.IntervalSeconds > int64(maximumSelfTestScheduleInterval/time.Second) ||
		item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) {
		return false
	}
	if item.LastSelfTestID != "" && id.Validate(item.LastSelfTestID, id.SelfTest) != nil {
		return false
	}
	switch item.Status {
	case "active":
		return item.NextRunAt != nil && item.DisabledAt == nil && item.DisabledReasonCode == ""
	case "disabled":
		return item.NextRunAt == nil && item.DisabledAt != nil && item.DisabledReasonCode != ""
	default:
		return false
	}
}
