-- Persist the complete authorization, target and budget contract required for
-- automated provider self-tests. Schedules are soft-disabled so historical
-- run evidence and audit references remain valid across upgrades.
CREATE TABLE self_test_schedules (
    self_test_schedule_id text PRIMARY KEY
        CHECK (self_test_schedule_id ~ '^sts_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    config_revision_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('upstream', 'openrouter')),
    upstream_key text NOT NULL CHECK (upstream_key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    model_key text NOT NULL CHECK (model_key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    max_cost_nano_usd bigint NOT NULL CHECK (max_cost_nano_usd BETWEEN 1 AND 1000000000),
    daily_cost_limit_nano_usd bigint NOT NULL
        CHECK (daily_cost_limit_nano_usd BETWEEN 1 AND 10000000000),
    interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 3600 AND 2592000),
    authorized_admin_user_id text NOT NULL,
    authorization_method text NOT NULL CHECK (authorization_method = 'api_token'),
    authorization_credential_id text NOT NULL
        CHECK (authorization_credential_id ~ '^tok_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    next_run_at timestamptz,
    last_enqueued_at timestamptz,
    disabled_at timestamptz,
    disabled_reason_code text
        CHECK (disabled_reason_code IS NULL OR disabled_reason_code ~ '^[a-z][a-z0-9_]{2,63}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, application_id, environment_id, config_revision_id)
        REFERENCES config_revisions (organization_id, application_id, environment_id, config_revision_id),
    FOREIGN KEY (organization_id, authorized_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    FOREIGN KEY (organization_id, authorization_credential_id)
        REFERENCES admin_api_tokens (organization_id, admin_api_token_id),
    CHECK (daily_cost_limit_nano_usd >= max_cost_nano_usd),
    CHECK (updated_at >= created_at),
    CHECK (last_enqueued_at IS NULL OR last_enqueued_at >= created_at),
    CHECK (
        (status = 'active' AND next_run_at IS NOT NULL AND disabled_at IS NULL AND disabled_reason_code IS NULL)
        OR
        (status = 'disabled' AND next_run_at IS NULL AND disabled_at IS NOT NULL AND disabled_reason_code IS NOT NULL)
    ),
    UNIQUE (organization_id, self_test_schedule_id),
    UNIQUE (self_test_schedule_id, organization_id, application_id, environment_id)
);

CREATE UNIQUE INDEX self_test_schedules_one_active_target_idx
    ON self_test_schedules (organization_id, environment_id, kind, upstream_key, model_key)
    WHERE status = 'active';

CREATE INDEX self_test_schedules_due_idx
    ON self_test_schedules (next_run_at, created_at, self_test_schedule_id)
    WHERE status = 'active';

CREATE INDEX self_test_schedules_tenant_idx
    ON self_test_schedules (organization_id, environment_id, created_at DESC, self_test_schedule_id DESC);

-- One row per secret reference makes multi-header authentication bindable
-- without putting credential values, hashes or ciphertext in job payloads.
CREATE TABLE self_test_schedule_secret_bindings (
    self_test_schedule_id text NOT NULL REFERENCES self_test_schedules (self_test_schedule_id),
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 7),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    secret_reference text NOT NULL CHECK (secret_reference ~ '^secret/[a-z][a-z0-9_-]{0,62}$'),
    secret_record_id text NOT NULL,
    secret_version bigint NOT NULL CHECK (secret_version > 0),
    FOREIGN KEY (organization_id, application_id, environment_id, secret_record_id)
        REFERENCES secret_records (organization_id, application_id, environment_id, secret_record_id),
    FOREIGN KEY (self_test_schedule_id, organization_id, application_id, environment_id)
        REFERENCES self_test_schedules (
            self_test_schedule_id, organization_id, application_id, environment_id
        ),
    UNIQUE (self_test_schedule_id, secret_reference),
    PRIMARY KEY (self_test_schedule_id, ordinal)
);

-- This is also the durable dispatch marker. Once a row reaches dispatching,
-- a retry or stale-worker recovery finalizes it as indeterminate and never
-- sends another provider request for the same scheduled job.
CREATE TABLE scheduled_self_test_runs (
    job_id text PRIMARY KEY REFERENCES jobs (job_id),
    self_test_schedule_id text NOT NULL REFERENCES self_test_schedules (self_test_schedule_id),
    self_test_id text NOT NULL UNIQUE
        CHECK (self_test_id ~ '^tst_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    status text NOT NULL CHECK (status IN ('dispatching', 'completed')),
    budget_date date NOT NULL,
    reserved_cost_nano_usd bigint NOT NULL CHECK (reserved_cost_nano_usd BETWEEN 0 AND 1000000000),
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    result jsonb CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    CHECK (
        (status = 'dispatching' AND completed_at IS NULL AND result IS NULL)
        OR
        (status = 'completed' AND completed_at IS NOT NULL AND result IS NOT NULL)
    ),
    CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE INDEX scheduled_self_test_runs_budget_idx
    ON scheduled_self_test_runs (self_test_schedule_id, budget_date);

CREATE INDEX scheduled_self_test_runs_result_idx
    ON scheduled_self_test_runs (self_test_id);
