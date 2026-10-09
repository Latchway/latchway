-- Operations history (ADR 0050): the worker samples the server self-check
-- every five minutes so health can be read back over time.
ALTER TABLE jobs
    DROP CONSTRAINT jobs_job_type_check,
    ADD CONSTRAINT jobs_job_type_check CHECK (job_type IN (
        'release_expired_reservations',
        'release_expired_concurrency_leases',
        'recover_stale_authenticated_requests',
        'prune_dpop_replays',
        'prune_challenges',
        'rotate_signing_keys',
        'refresh_jwks',
        'aggregate_hourly_usage',
        'aggregate_daily_usage',
        'enforce_retention',
        'reconcile_pending_usage',
        'run_scheduled_self_test',
        'record_health_sample'
    ));

CREATE TABLE system_health_samples (
    sampled_at timestamptz PRIMARY KEY,
    overall_state text NOT NULL CHECK (overall_state IN ('healthy', 'degraded', 'unhealthy')),
    failed_checks text[] NOT NULL CHECK (cardinality(failed_checks) <= 64),
    warning_checks text[] NOT NULL CHECK (cardinality(warning_checks) <= 64),
    recorded_by_role text NOT NULL CHECK (recorded_by_role IN ('all', 'worker')),
    recorded_at timestamptz NOT NULL DEFAULT now()
);
