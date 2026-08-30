-- The operational Admin API uses tenant-scoped keyset pagination and bounded
-- batch hydration. Keep those paths index-backed without changing any domain
-- data or lifecycle constraints. Migrations execute inside a transaction, so
-- every definition below deliberately uses a plain index statement.

CREATE INDEX installations_admin_list_idx
    ON installations (organization_id, environment_id, created_at, installation_id);

CREATE INDEX logical_requests_admin_list_idx
    ON logical_requests (organization_id, environment_id, requested_at, logical_request_id);

CREATE INDEX upstream_attempts_admin_request_idx
    ON upstream_attempts (organization_id, logical_request_id, attempt_number)
    INCLUDE (upstream_attempt_id, upstream_key, physical_model, started_at, completed_at, status);

CREATE INDEX usage_records_admin_request_idx
    ON usage_records (organization_id, logical_request_id, recorded_at, usage_record_id)
    INCLUDE (upstream_attempt_id, metric, units, confidence);

CREATE INDEX usage_records_admin_time_idx
    ON usage_records (organization_id, environment_id, recorded_at, usage_record_id)
    INCLUDE (metric, units, confidence);

-- The foundation index leaves audit_event_id in ascending order. The Admin
-- feed compares and orders both keyset members descending, so preserve that
-- exact ordering here rather than forcing a sort on large tenant histories.
CREATE INDEX audit_events_admin_list_idx
    ON audit_events (organization_id, occurred_at DESC, audit_event_id DESC);

-- Self-test result payloads are durable and intentionally contain only the
-- public run document. Scope the expression index to this one job class.
CREATE INDEX jobs_admin_self_test_result_idx
    ON jobs (organization_id, ((payload ->> 'id')))
    WHERE job_type = 'run_scheduled_self_test';
