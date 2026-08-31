-- Keep the transport boundary used for quota/streaming state distinct from
-- the protocol-aware first generated token used by latency telemetry. Legacy
-- attempts remain NULL because historical first-byte timestamps cannot prove
-- when generated content was observed.
ALTER TABLE upstream_attempts
    ADD COLUMN first_token_at timestamptz,
    ADD CONSTRAINT upstream_attempts_first_token_order_check
        CHECK (
            first_token_at IS NULL
            OR (
                first_byte_at IS NOT NULL
                AND first_token_at >= first_byte_at
                AND (completed_at IS NULL OR first_token_at <= completed_at)
            )
        );

COMMENT ON COLUMN upstream_attempts.first_token_at IS
    'First protocol-validated generated content observed in the relayed response; NULL for lifecycle-only, opaque, and historical attempts.';

CREATE INDEX upstream_attempts_first_token_analytics_idx
    ON upstream_attempts (
        organization_id, environment_id, logical_request_id, first_token_at
    )
    WHERE first_token_at IS NOT NULL;
