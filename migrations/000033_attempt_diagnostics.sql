-- Safe, bounded evidence only. Raw provider errors, prompts and credentials
-- are intentionally not represented. Existing attempts retain legacy policy.
CREATE TABLE upstream_attempt_diagnostics (
    upstream_attempt_id text PRIMARY KEY,
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    accounting_policy text NOT NULL DEFAULT ''
        CHECK (accounting_policy IN ('', 'provider_rejection_v1', 'reported_usage_v1')),
    provider_error jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(provider_error) = 'object'
            AND octet_length(provider_error::text) <= 2048
            AND provider_error - ARRAY['category','parameter','provider_code','generation_id','request_id']::text[] = '{}'::jsonb),
    FOREIGN KEY (organization_id, application_id, environment_id, upstream_attempt_id)
        REFERENCES upstream_attempts (organization_id, application_id, environment_id, upstream_attempt_id)
        ON DELETE CASCADE
);

COMMENT ON TABLE upstream_attempt_diagnostics IS
    'Allowlisted provider diagnostics and versioned settlement evidence; absent row preserves historical settlement. Never stores prompts, raw errors or credentials.';
