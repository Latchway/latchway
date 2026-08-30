package worker

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
	return processed, nil
}

func cutoff(scheduledAt time.Time, retention time.Duration) time.Time {
	return scheduledAt.UTC().Add(-retention)
}
