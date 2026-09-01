-- Start the durable logical-request lifecycle immediately after the gateway
-- has verified both its access token and request-bound DPoP proof. Earlier
-- schemas created the row only inside quota reservation, which made
-- authenticated denials during client-context, configuration, request-shape,
-- policy, and route evaluation invisible to operators.
ALTER TABLE logical_requests
    DROP CONSTRAINT logical_requests_status_check,
    ADD CONSTRAINT logical_requests_status_check
        CHECK (status IN (
            'authenticated', 'reserved', 'dispatched', 'streaming',
            'succeeded', 'failed', 'cancelled', 'denied'
        )),
    ADD COLUMN selected_route_key text,
    ADD COLUMN selected_upstream_key text,
    ADD COLUMN selected_model_key text,
    ADD COLUMN selected_physical_model text,
    ADD CONSTRAINT logical_requests_decision_revision_key UNIQUE (
        organization_id, application_id, environment_id,
        logical_request_id, config_revision_id
    ),
    ADD CONSTRAINT logical_requests_selected_route_key_check
        CHECK (
            selected_route_key IS NULL
            OR selected_route_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        ),
    ADD CONSTRAINT logical_requests_selected_upstream_key_check
        CHECK (
            selected_upstream_key IS NULL
            OR selected_upstream_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        ),
    ADD CONSTRAINT logical_requests_selected_model_key_check
        CHECK (
            selected_model_key IS NULL
            OR selected_model_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        ),
    ADD CONSTRAINT logical_requests_selected_physical_model_check
        CHECK (
            selected_physical_model IS NULL
            OR (
                char_length(selected_physical_model) BETWEEN 1 AND 512
                AND selected_physical_model !~ '[[:cntrl:]]'
            )
        ),
    ADD CONSTRAINT logical_requests_selected_route_tuple_check
        CHECK (
            (
                selected_route_key IS NULL
                AND selected_upstream_key IS NULL
                AND selected_model_key IS NULL
                AND selected_physical_model IS NULL
            )
            OR (
                selected_route_key IS NOT NULL
                AND selected_upstream_key IS NOT NULL
                AND selected_model_key IS NOT NULL
                AND selected_physical_model IS NOT NULL
            )
        );

-- The recovery lane is a closed, payload-free periodic worker job. Extend the
-- original schema-2 inventory in the same migration that introduces the state
-- it reconciles, so an upgraded worker can schedule it immediately.
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
        'run_scheduled_self_test'
    ));

COMMENT ON COLUMN logical_requests.selected_route_key IS
    'Redaction-safe projection of the first server-selected route. The immutable decision history remains in logical_request_decision_stages.';

CREATE INDEX logical_requests_authenticated_recovery_idx
    ON logical_requests (requested_at, logical_request_id)
    WHERE status = 'authenticated';

-- Decision stages contain only bounded identifiers, integer limits, stable
-- public codes, and timestamps. They deliberately cannot contain provider
-- bodies, prompts, identity subjects, credentials, proofs, or arbitrary
-- detail strings.
CREATE TABLE logical_request_decision_stages (
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    logical_request_id text NOT NULL,
    stage_number smallint NOT NULL CHECK (stage_number BETWEEN 1 AND 256),
    stage text NOT NULL CHECK (stage IN (
        'identity_verified',
        'client_trust_verified',
        'client_context_validated',
        'configuration_loaded',
        'request_inspected',
        'policy_evaluated',
        'route_selected',
        'quota_rule_evaluated',
        'quota_reserved',
        'lifecycle_recovered'
    )),
    outcome text NOT NULL
        CHECK (outcome IN ('succeeded', 'denied', 'failed', 'cancelled')),
    failure_code text
        CHECK (
            failure_code IS NULL
            OR failure_code ~ '^[a-z][a-z0-9_]{0,99}$'
        ),
    config_revision_id text NOT NULL,
    policy_rule_key text
        CHECK (
            policy_rule_key IS NULL
            OR policy_rule_key ~ '^([a-z][a-z0-9_-]{0,62}|[A-Za-z0-9_-]{43})$'
        ),
    limit_plan_key text
        CHECK (
            limit_plan_key IS NULL
            OR limit_plan_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        ),
    limit_rule_key text
        CHECK (limit_rule_key IS NULL OR limit_rule_key ~ '^[A-Za-z0-9_-]{43}$'),
    limit_metric text
        CHECK (limit_metric IS NULL OR limit_metric ~ '^[a-z][a-z0-9_]{0,63}$'),
    limit_algorithm text
        CHECK (
            limit_algorithm IS NULL
            OR limit_algorithm IN ('calendar', 'token_bucket', 'per_request', 'concurrency')
        ),
    limit_maximum bigint CHECK (limit_maximum IS NULL OR limit_maximum >= 0),
    route_key text
        CHECK (route_key IS NULL OR route_key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    upstream_key text
        CHECK (upstream_key IS NULL OR upstream_key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    model_key text
        CHECK (model_key IS NULL OR model_key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    physical_model text
        CHECK (
            physical_model IS NULL
            OR (
                char_length(physical_model) BETWEEN 1 AND 512
                AND physical_model !~ '[[:cntrl:]]'
            )
        ),
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    FOREIGN KEY (
        organization_id, application_id, environment_id,
        logical_request_id, config_revision_id
    )
        REFERENCES logical_requests (
            organization_id, application_id, environment_id,
            logical_request_id, config_revision_id
        ) ON DELETE CASCADE,
    CHECK (completed_at >= started_at),
    CHECK ((outcome = 'succeeded') = (failure_code IS NULL)),
    CHECK (policy_rule_key IS NULL OR stage = 'policy_evaluated'),
    CHECK (
        limit_plan_key IS NULL
        OR stage IN (
            'policy_evaluated', 'route_selected',
            'quota_rule_evaluated', 'quota_reserved'
        )
    ),
    CHECK (
        (limit_rule_key IS NULL AND limit_metric IS NULL
            AND limit_algorithm IS NULL AND limit_maximum IS NULL)
        OR
        (limit_rule_key IS NOT NULL AND limit_metric IS NOT NULL
            AND limit_algorithm IS NOT NULL AND limit_maximum IS NOT NULL)
    ),
    CHECK (limit_rule_key IS NULL OR stage = 'quota_rule_evaluated'),
    CHECK (
        (route_key IS NULL AND upstream_key IS NULL
            AND model_key IS NULL AND physical_model IS NULL)
        OR
        (route_key IS NOT NULL AND upstream_key IS NOT NULL
            AND model_key IS NOT NULL AND physical_model IS NOT NULL)
    ),
    CHECK (route_key IS NULL OR stage IN ('route_selected', 'quota_reserved')),
    PRIMARY KEY (logical_request_id, stage_number),
    UNIQUE (
        organization_id, application_id, environment_id,
        logical_request_id, stage_number
    )
);

CREATE INDEX logical_request_decision_stages_tenant_idx
    ON logical_request_decision_stages (
        organization_id, environment_id, logical_request_id, stage_number
    );

COMMENT ON TABLE logical_request_decision_stages IS
    'Append-only, redaction-safe identity/trust/policy/quota/routing decisions for one authenticated logical request.';

-- Application code only inserts stages. Enforce that contract in PostgreSQL
-- as well so a later bug cannot rewrite the explanation shown to operators.
CREATE FUNCTION reject_logical_request_decision_stage_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- The child-row delete issued by the parent foreign-key cascade is nested
    -- beneath PostgreSQL's referential-action trigger. Direct child deletion
    -- has depth one and remains forbidden.
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'logical request decision stages are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER logical_request_decision_stages_append_only
    BEFORE UPDATE OR DELETE ON logical_request_decision_stages
    FOR EACH ROW EXECUTE FUNCTION reject_logical_request_decision_stage_mutation();
