-- Persist the exact limit plan selected before reservation so tenant-scoped
-- usage reports can attribute requests and cost to an operator-defined plan.
-- The default is an explicit provenance label for rows created by older
-- binaries; a migration must never infer a historical CEL result.
ALTER TABLE logical_requests
    ADD COLUMN selected_limit_plan_key text NOT NULL DEFAULT 'legacy_unknown'
        CHECK (selected_limit_plan_key ~ '^[a-z][a-z0-9_-]{0,62}$');

CREATE INDEX logical_requests_usage_analytics_idx
    ON logical_requests (organization_id, environment_id, requested_at)
    INCLUDE (
        application_user_id,
        feature_key,
        selected_limit_plan_key,
        status,
        failure_code,
        dispatched_at,
        completed_at
    );

CREATE INDEX upstream_attempts_usage_analytics_idx
    ON upstream_attempts (organization_id, environment_id, started_at)
    INCLUDE (
        logical_request_id,
        attempt_number,
        model_key,
        status,
        first_byte_at,
        completed_at
    );

CREATE INDEX attestation_events_usage_analytics_idx
    ON attestation_events (organization_id, environment_id, occurred_at)
    INCLUDE (outcome);
