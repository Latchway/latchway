-- Client request identifiers originate on an untrusted client. They are useful
-- correlation hints, but they are not an idempotency or authorization key and
-- therefore must not prevent two logical requests from being recorded.
DROP INDEX logical_requests_client_request_idx;

CREATE INDEX logical_requests_client_request_idx
    ON logical_requests (environment_id, client_request_id)
    WHERE client_request_id IS NOT NULL;

-- Feature keys are canonical configuration identifiers. The version 2 check
-- accidentally required 2-128 characters, while the configuration contract
-- permits exactly 1-63 lowercase identifier characters.
ALTER TABLE logical_requests
    DROP CONSTRAINT logical_requests_feature_key_check,
    ADD CONSTRAINT logical_requests_feature_key_identifier_check
        CHECK (
            feature_key = lower(feature_key)
            AND feature_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        );

-- A logical request has at most one quota reservation. The separately supplied
-- idempotency key remains unique as a second lookup path for safe retries.
ALTER TABLE quota_reservations
    ADD CONSTRAINT quota_reservations_logical_request_key
        UNIQUE (environment_id, logical_request_id);

-- Version 2 did not persist enough server-owned information to distinguish
-- quota rules and their composite scopes. There is no safe, deterministic way
-- to manufacture that identity for an existing bucket, so fail closed instead
-- of merging, resetting, or guessing live usage. The migrator executes this
-- file and its ledger insert in one transaction, so every preceding DDL change
-- is rolled back when this guard rejects an upgrade.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM quota_buckets LIMIT 1) THEN
        RAISE EXCEPTION
            'cannot establish quota bucket identity: quota_buckets contains persisted usage'
            USING ERRCODE = '23514';
    END IF;
END
$$;

ALTER TABLE quota_buckets
    ADD COLUMN limit_plan_key text NOT NULL,
    ADD COLUMN rule_key text NOT NULL,
    ADD COLUMN scope_dimensions text[] NOT NULL,
    ADD CONSTRAINT quota_buckets_limit_plan_key_identifier_check
        CHECK (
            limit_plan_key = lower(limit_plan_key)
            AND limit_plan_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        ),
    ADD CONSTRAINT quota_buckets_rule_key_hash_check
        CHECK (rule_key ~ '^[A-Za-z0-9_-]{43}$'),
    ADD CONSTRAINT quota_buckets_scope_dimensions_check
        CHECK (
            CASE
                WHEN array_ndims(scope_dimensions) = 1
                     AND array_lower(scope_dimensions, 1) = 1
                THEN
                    cardinality(scope_dimensions) BETWEEN 1 AND 9
                    AND array_position(scope_dimensions, NULL) IS NULL
                    AND scope_dimensions <@ ARRAY[
                        'organization',
                        'application',
                        'environment',
                        'user',
                        'installation',
                        'feature',
                        'route',
                        'upstream',
                        'model'
                    ]::text[]
                    AND cardinality(array_positions(scope_dimensions, 'organization')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'application')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'environment')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'user')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'installation')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'feature')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'route')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'upstream')) <= 1
                    AND cardinality(array_positions(scope_dimensions, 'model')) <= 1
                ELSE false
            END
        ),
    DROP CONSTRAINT quota_buckets_scope_type_check,
    ADD CONSTRAINT quota_buckets_scope_type_dimensions_check
        CHECK (
            scope_type IN (
                'organization',
                'application',
                'environment',
                'user',
                'installation',
                'feature',
                'route',
                'upstream',
                'model',
                'composite'
            )
            AND (
                (
                    scope_type = 'composite'
                    AND cardinality(scope_dimensions) BETWEEN 2 AND 9
                )
                OR (
                    scope_type <> 'composite'
                    AND cardinality(scope_dimensions) = 1
                    AND scope_dimensions[1] = scope_type
                )
            )
        ),
    DROP CONSTRAINT quota_buckets_scope_key_check,
    ADD CONSTRAINT quota_buckets_scope_key_hash_check
        CHECK (scope_key ~ '^[A-Za-z0-9_-]{43}$'),
    DROP CONSTRAINT quota_buckets_environment_id_metric_scope_type_scope_key_al_key,
    ADD CONSTRAINT quota_buckets_identity_key
        UNIQUE (
            environment_id,
            limit_plan_key,
            rule_key,
            metric,
            algorithm,
            window_key,
            scope_key
        );

COMMENT ON COLUMN quota_buckets.limit_plan_key IS
    'Canonical 1-63 character identifier of the server-selected configuration limit plan.';

COMMENT ON COLUMN quota_buckets.rule_key IS
    'Unpadded base64url SHA-256 of the canonical rule identity; mutable maximum and capacity values are excluded so policy changes do not reset usage.';

COMMENT ON COLUMN quota_buckets.scope_dimensions IS
    'Unique configuration dimension names whose server-owned values form this bucket scope.';

COMMENT ON COLUMN quota_buckets.scope_key IS
    'Unpadded base64url SHA-256 of a domain-separated canonical encoding of server-owned values for scope_dimensions; never a client-supplied key.';

DROP INDEX quota_buckets_scope_idx;

CREATE INDEX quota_buckets_tenant_scope_idx
    ON quota_buckets (
        organization_id,
        application_id,
        environment_id,
        scope_type,
        scope_dimensions,
        scope_key,
        limit_plan_key,
        metric
    );
