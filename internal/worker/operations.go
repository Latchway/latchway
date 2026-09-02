package worker

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

const (
	defaultAdminSessionRetention = 7 * 24 * time.Hour
	defaultJobHistoryRetention   = 30 * 24 * time.Hour
	defaultRuntimeRetention      = 24 * time.Hour
)

// PostgreSQLOperations implements idempotent usage rollup and bounded
// operational retention directly in PostgreSQL.
type PostgreSQLOperations struct {
	pool *pgxpool.Pool
}

func NewPostgreSQLOperations(pool *pgxpool.Pool) (*PostgreSQLOperations, error) {
	if pool == nil {
		return nil, errors.New("worker PostgreSQL operations pool is nil")
	}
	return &PostgreSQLOperations{pool: pool}, nil
}

// AggregateHourlyUsage replaces one completed UTC hour with exact aggregates.
// Upserts make retries and concurrent replicas harmless.
func (operations *PostgreSQLOperations) AggregateHourlyUsage(ctx context.Context, scheduledAt time.Time) (int64, error) {
	if operations == nil || ctx == nil || scheduledAt.IsZero() {
		return 0, errors.New("hourly usage aggregation input is invalid")
	}
	end := scheduledAt.UTC().Truncate(time.Hour)
	start := end.Add(-time.Hour)
	result, err := operations.pool.Exec(ctx, `
		WITH measurements AS (
			SELECT usage.organization_id, usage.application_id, usage.environment_id,
			       usage.logical_request_id, logical.feature_key,
			       attempt.route_key, attempt.upstream_key, attempt.model_key,
			       logical.status AS outcome, usage.metric, usage.units,
			       COALESCE(usage.cost_nano_usd, 0) AS cost_nano_usd,
			       usage.recorded_at
			FROM usage_records AS usage
			JOIN logical_requests AS logical
			  ON logical.organization_id = usage.organization_id
			 AND logical.application_id = usage.application_id
			 AND logical.environment_id = usage.environment_id
			 AND logical.logical_request_id = usage.logical_request_id
			LEFT JOIN upstream_attempts AS attempt
			  ON attempt.organization_id = usage.organization_id
			 AND attempt.application_id = usage.application_id
			 AND attempt.environment_id = usage.environment_id
			 AND attempt.logical_request_id = usage.logical_request_id
			 AND attempt.upstream_attempt_id = usage.upstream_attempt_id
			WHERE usage.recorded_at >= $1 AND usage.recorded_at < $2
			UNION ALL
			SELECT attempt.organization_id, attempt.application_id, attempt.environment_id,
			       attempt.logical_request_id, logical.feature_key,
			       attempt.route_key, attempt.upstream_key, attempt.model_key,
			       attempt.status AS outcome, 'upstream_attempts'::text AS metric,
			       1::bigint AS units, 0::bigint AS cost_nano_usd, attempt.started_at AS recorded_at
			FROM upstream_attempts AS attempt
			JOIN logical_requests AS logical
			  ON logical.organization_id = attempt.organization_id
			 AND logical.application_id = attempt.application_id
			 AND logical.environment_id = attempt.environment_id
			 AND logical.logical_request_id = attempt.logical_request_id
			WHERE attempt.started_at >= $1 AND attempt.started_at < $2
		), shaped AS (
			SELECT measurement.*,
			       jsonb_strip_nulls(jsonb_build_object(
			         'feature', feature_key, 'route', route_key, 'upstream', upstream_key,
			         'model_alias', model_key, 'outcome', outcome
			       )) AS dimensions
			FROM measurements AS measurement
		), aggregated AS (
			SELECT organization_id, application_id, environment_id, $1::timestamptz AS bucket_start,
			       dimensions::text AS dimension_key, dimensions, metric,
			       sum(units)::bigint AS units, sum(cost_nano_usd)::bigint AS cost_nano_usd,
			       count(DISTINCT logical_request_id)::bigint AS request_count
			FROM shaped
			GROUP BY organization_id, application_id, environment_id, dimensions, metric
		)
		INSERT INTO usage_rollups_hourly (
			organization_id, application_id, environment_id, bucket_start,
			dimension_key, dimensions, metric, units, cost_nano_usd, request_count, updated_at
		)
		SELECT organization_id, application_id, environment_id, bucket_start,
		       dimension_key, dimensions, metric, units, cost_nano_usd, request_count,
		       statement_timestamp()
		FROM aggregated
		ON CONFLICT (environment_id, bucket_start, dimension_key, metric) DO UPDATE
		SET units = EXCLUDED.units, cost_nano_usd = EXCLUDED.cost_nano_usd,
		    request_count = EXCLUDED.request_count, dimensions = EXCLUDED.dimensions,
		    updated_at = statement_timestamp()
	`, start, end)
	if err != nil {
		return 0, errors.New("aggregate hourly usage")
	}
	return result.RowsAffected(), nil
}

// AggregateDailyUsage replaces the previous complete UTC day from hourly
// rollups. It is safe to retry after partial process failure.
func (operations *PostgreSQLOperations) AggregateDailyUsage(ctx context.Context, scheduledAt time.Time) (int64, error) {
	if operations == nil || ctx == nil || scheduledAt.IsZero() {
		return 0, errors.New("daily usage aggregation input is invalid")
	}
	end := time.Date(scheduledAt.UTC().Year(), scheduledAt.UTC().Month(), scheduledAt.UTC().Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -1)
	result, err := operations.pool.Exec(ctx, `
		INSERT INTO usage_rollups_daily (
			organization_id, application_id, environment_id, bucket_date,
			dimension_key, dimensions, metric, units, cost_nano_usd, request_count, updated_at
		)
		SELECT organization_id, application_id, environment_id, $1::date,
		       dimension_key, dimensions, metric, sum(units), sum(cost_nano_usd),
		       sum(request_count), statement_timestamp()
		FROM usage_rollups_hourly
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY organization_id, application_id, environment_id,
		         dimension_key, dimensions, metric
		ON CONFLICT (environment_id, bucket_date, dimension_key, metric) DO UPDATE
		SET units = EXCLUDED.units, cost_nano_usd = EXCLUDED.cost_nano_usd,
		    request_count = EXCLUDED.request_count, dimensions = EXCLUDED.dimensions,
		    updated_at = statement_timestamp()
	`, start, end)
	if err != nil {
		return 0, errors.New("aggregate daily usage")
	}
	return result.RowsAffected(), nil
}

// EnforceRetention removes only operational records with fixed, documented
// lifetimes. Audit, request, and usage retention remain tenant-policy owned and
// are never silently shortened by this job.
func (operations *PostgreSQLOperations) EnforceRetention(ctx context.Context, scheduledAt time.Time, limit int) (int64, error) {
	if operations == nil || ctx == nil || scheduledAt.IsZero() || limit < 1 || limit > 10_000 {
		return 0, errors.New("operational retention input is invalid")
	}
	tx, err := operations.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, errors.New("begin operational retention")
	}
	defer rollbackQueue(tx)
	var processed int64
	for _, statement := range []struct {
		query  string
		cutoff time.Time
	}{
		{query: `
			WITH doomed AS (
				SELECT admin_session_id FROM admin_sessions
				WHERE expires_at < $1
				ORDER BY expires_at, admin_session_id LIMIT $2 FOR UPDATE SKIP LOCKED
			)
			DELETE FROM admin_sessions AS session USING doomed
			WHERE session.admin_session_id = doomed.admin_session_id
		`, cutoff: cutoff(scheduledAt, defaultAdminSessionRetention)},
		{query: `
			WITH doomed AS (
				SELECT job_id FROM jobs
				WHERE status IN ('succeeded', 'dead') AND completed_at < $1
				ORDER BY completed_at, job_id LIMIT $2 FOR UPDATE SKIP LOCKED
			)
			DELETE FROM jobs AS job USING doomed WHERE job.job_id = doomed.job_id
		`, cutoff: cutoff(scheduledAt, defaultJobHistoryRetention)},
		{query: `
			WITH doomed AS (
				SELECT instance.instance_id FROM runtime_instances AS instance
				WHERE instance.heartbeat_at < $1
				  AND NOT EXISTS (
				    SELECT 1 FROM jobs WHERE locked_by_instance_id = instance.instance_id
				  )
				ORDER BY instance.heartbeat_at, instance.instance_id
				LIMIT $2 FOR UPDATE OF instance SKIP LOCKED
			)
			DELETE FROM runtime_instances AS instance USING doomed
			WHERE instance.instance_id = doomed.instance_id
		`, cutoff: cutoff(scheduledAt, defaultRuntimeRetention)},
		{query: `
			WITH doomed AS (
				SELECT issuer_sha256, source_sha256
				FROM identity_jwks_cache
				WHERE refresh_lease_token IS NULL
				  AND ((document IS NOT NULL AND stale_until <= $1)
				       OR (document IS NULL AND updated_at <= $1 - interval '1 hour'))
				ORDER BY COALESCE(stale_until, updated_at), issuer_sha256, source_sha256
				LIMIT $2 FOR UPDATE SKIP LOCKED
			)
			DELETE FROM identity_jwks_cache AS cache USING doomed
			WHERE cache.issuer_sha256 = doomed.issuer_sha256
			  AND cache.source_sha256 = doomed.source_sha256
		`, cutoff: scheduledAt.UTC()},
	} {
		result, execErr := tx.Exec(ctx, statement.query, statement.cutoff, limit)
		if execErr != nil {
			return processed, errors.New("delete expired operational records")
		}
		processed += result.RowsAffected()
	}
	result, err := tx.Exec(ctx, `
		WITH expired AS (
			SELECT refresh_token_id FROM refresh_tokens
			WHERE status IN ('staged', 'active') AND expires_at <= $1
			ORDER BY expires_at, refresh_token_id LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		UPDATE refresh_tokens AS token SET status = 'expired'
		FROM expired WHERE token.refresh_token_id = expired.refresh_token_id
	`, scheduledAt.UTC(), limit)
	if err != nil {
		return processed, errors.New("expire refresh-token state")
	}
	processed += result.RowsAffected()
	if err := tx.Commit(ctx); err != nil {
		return 0, errors.New("commit operational retention")
	}
	componentProcessed, err := operations.enforceComponentRetention(ctx, scheduledAt.UTC(), limit)
	processed += componentProcessed
	if err != nil {
		return processed, err
	}
	return processed, nil
}

// enforceComponentRetention uses one transaction per relation so maintenance
// never holds a component refresh-token lock while waiting for a session-family
// or rotation-result lock. Client refresh and lifecycle transactions may touch
// those relations in different combinations; short, independent statements
// keep retries idempotent and avoid introducing a cross-subsystem lock order.
func (operations *PostgreSQLOperations) enforceComponentRetention(
	ctx context.Context,
	retentionAt time.Time,
	limit int,
) (int64, error) {
	var processed int64
	statements := []struct {
		query   string
		failure string
	}{
		{
			query: `
				WITH expired AS (
					SELECT component_refresh_token_id
					FROM component_refresh_tokens
					WHERE status IN ('staged', 'active') AND expires_at <= $1
					ORDER BY expires_at, component_refresh_token_id
					LIMIT $2 FOR UPDATE SKIP LOCKED
				)
				UPDATE component_refresh_tokens AS token
				SET status = 'expired',
				    revoked_at = COALESCE(token.revoked_at, GREATEST(token.issued_at, $1))
				FROM expired
				WHERE token.component_refresh_token_id = expired.component_refresh_token_id
			`,
			failure: "expire component refresh-token state",
		},
		{
			query: `
				WITH doomed AS (
					SELECT refresh_rotation_result_id
					FROM refresh_rotation_results
					WHERE expires_at <= $1
					ORDER BY expires_at, refresh_rotation_result_id
					LIMIT $2 FOR UPDATE SKIP LOCKED
				)
				DELETE FROM refresh_rotation_results AS result
				USING doomed
				WHERE result.refresh_rotation_result_id = doomed.refresh_rotation_result_id
			`,
			failure: "delete expired component refresh rotation results",
		},
	}
	for _, statement := range statements {
		result, err := operations.pool.Exec(ctx, statement.query, retentionAt, limit)
		if err != nil {
			return processed, errors.New(statement.failure)
		}
		processed += result.RowsAffected()
	}
	familyProcessed, err := operations.expireComponentSessionFamilies(ctx, retentionAt, limit)
	processed += familyProcessed
	if err != nil {
		return processed, err
	}
	return processed, nil
}

const (
	componentSessionFamilyExpiredAction = "client.component.session_family_expired"
	componentSessionFamilyExpiredReason = "session_family_lifetime_elapsed"
)

type expiredComponentSessionFamily struct {
	id             string
	organizationID string
	environmentID  string
	componentID    string
}

// expireComponentSessionFamilies records one system audit event in the same
// transaction as every active-to-expired transition. The event is attached to
// the owning client component, so the existing Audit API can inspect the exact
// session-family failure without relying on an aggregate component counter.
func (operations *PostgreSQLOperations) expireComponentSessionFamilies(
	ctx context.Context,
	retentionAt time.Time,
	limit int,
) (int64, error) {
	tx, err := operations.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, errors.New("begin component session-family retention")
	}
	defer rollbackQueue(tx)
	rows, err := tx.Query(ctx, `
		SELECT family.component_session_family_id, family.organization_id,
		       family.environment_id, family.client_component_id
		FROM component_session_families AS family
		WHERE family.status = 'active'
		  AND NOT EXISTS (
		    SELECT 1
		    FROM component_refresh_tokens AS token
		    WHERE token.component_session_family_id = family.component_session_family_id
		      AND token.status IN ('staged', 'active')
		      AND token.expires_at > $1
		  )
		  AND NOT EXISTS (
		    SELECT 1
		    FROM session_grants AS grant_record
		    WHERE grant_record.component_session_family_id = family.component_session_family_id
		      AND grant_record.revoked_at IS NULL
		      AND grant_record.expires_at > $1
		  )
		ORDER BY family.updated_at, family.component_session_family_id
		LIMIT $2 FOR UPDATE OF family SKIP LOCKED
	`, retentionAt, limit)
	if err != nil {
		return 0, errors.New("select expired component session families")
	}
	families := make([]expiredComponentSessionFamily, 0, limit)
	for rows.Next() {
		var family expiredComponentSessionFamily
		if err := rows.Scan(
			&family.id, &family.organizationID, &family.environmentID, &family.componentID,
		); err != nil {
			rows.Close()
			return 0, errors.New("scan expired component session family")
		}
		families = append(families, family)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, errors.New("iterate expired component session families")
	}
	rows.Close()
	if len(families) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return 0, errors.New("commit empty component session-family retention")
		}
		return 0, nil
	}
	familyIDs := make([]string, len(families))
	eventIDs := make([]string, len(families))
	organizationIDs := make([]string, len(families))
	environmentIDs := make([]string, len(families))
	componentIDs := make([]string, len(families))
	for index, family := range families {
		eventID, err := id.New(id.AuditEvent)
		if err != nil {
			return 0, errors.New("generate component session-family audit event ID")
		}
		familyIDs[index] = family.id
		eventIDs[index] = eventID
		organizationIDs[index] = family.organizationID
		environmentIDs[index] = family.environmentID
		componentIDs[index] = family.componentID
	}
	result, err := tx.Exec(ctx, `
		UPDATE component_session_families
		SET status = 'expired', updated_at = GREATEST(updated_at, $1)
		WHERE component_session_family_id = ANY($2)
		  AND status = 'active'
	`, retentionAt, familyIDs)
	if err != nil || result.RowsAffected() != int64(len(families)) {
		return 0, errors.New("expire component session-family state")
	}
	result, err = tx.Exec(ctx, `
		INSERT INTO audit_events (
			audit_event_id, organization_id, environment_id, actor_kind, actor_id,
			action, resource_type, resource_id, outcome, occurred_at, source, reason
		)
		SELECT selected.audit_event_id, selected.organization_id,
		       selected.environment_id, 'system', NULL, $1, 'client_component',
		       selected.client_component_id, 'succeeded', $2, 'system', $3
		FROM unnest($4::text[], $5::text[], $6::text[], $7::text[]) AS selected(
			audit_event_id, organization_id, environment_id, client_component_id
		)
	`, componentSessionFamilyExpiredAction, retentionAt,
		componentSessionFamilyExpiredReason, eventIDs, organizationIDs, environmentIDs, componentIDs)
	if err != nil || result.RowsAffected() != int64(len(families)) {
		return 0, errors.New("record component session-family audit events")
	}
	result, err = tx.Exec(ctx, `
		INSERT INTO audit_event_changes (
			audit_event_id, ordinal, field_name, operation, classification
		)
		SELECT event.audit_event_id, change.ordinal, change.field_name,
		       change.operation, change.classification
		FROM unnest($1::text[]) AS event(audit_event_id)
		CROSS JOIN (VALUES
			(0::smallint, 'component_session_family_status', 'set', 'public'),
			(1::smallint, 'access_availability', 'clear', 'public'),
			(2::smallint, 'refresh_availability', 'clear', 'sensitive')
		) AS change(ordinal, field_name, operation, classification)
	`, eventIDs)
	if err != nil || result.RowsAffected() != int64(3*len(families)) {
		return 0, errors.New("record component session-family audit changes")
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, errors.New("commit component session-family retention")
	}
	return int64(len(families)), nil
}

func cutoff(scheduledAt time.Time, retention time.Duration) time.Time {
	return scheduledAt.UTC().Add(-retention)
}
