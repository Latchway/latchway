-- Expand the canonical quota-scope vocabulary without changing existing
-- bucket identities. Normalized claim values never enter this array; only the
-- configured selector name is stored, while scope_key retains its opaque
-- domain-separated digest.
ALTER TABLE quota_buckets
    DROP CONSTRAINT quota_buckets_scope_dimensions_check,
    ADD CONSTRAINT quota_buckets_scope_dimensions_check
        CHECK (
            CASE
                WHEN array_ndims(scope_dimensions) = 1
                     AND array_lower(scope_dimensions, 1) = 1
                THEN
                    cardinality(scope_dimensions) BETWEEN 1 AND 11
                    AND array_position(scope_dimensions, NULL) IS NULL
                    AND (E'\n' || array_to_string(scope_dimensions, E'\n', '<null>') || E'\n') ~
                        E'^\n(organization\n)?(application\n)?(environment\n)?(user\n)?(installation\n)?(feature\n)?(route\n)?(upstream\n)?(model\n)?(platform\n)?(normalized_claim:[a-z][a-z0-9_]{0,62}\n)?$'
                ELSE false
            END
        ),
    DROP CONSTRAINT quota_buckets_scope_type_dimensions_check,
    ADD CONSTRAINT quota_buckets_scope_type_dimensions_check
        CHECK (
            scope_type IN (
                'organization', 'application', 'environment', 'user',
                'installation', 'feature', 'route', 'upstream', 'model',
                'platform', 'normalized_claim', 'composite'
            )
            AND (
                (scope_type = 'composite' AND cardinality(scope_dimensions) BETWEEN 2 AND 11)
                OR (
                    scope_type = 'normalized_claim'
                    AND cardinality(scope_dimensions) = 1
                    AND scope_dimensions[1] ~ '^normalized_claim:[a-z][a-z0-9_]{0,62}$'
                )
                OR (
                    scope_type NOT IN ('composite', 'normalized_claim')
                    AND cardinality(scope_dimensions) = 1
                    AND scope_dimensions[1] = scope_type
                )
            )
        );

COMMENT ON COLUMN quota_buckets.scope_dimensions IS
    'Canonical configuration dimension names, including at most one normalized_claim:<name> selector; raw normalized claim values are never stored.';

-- A per-request guard has no quota bucket, but every dispatch attempt still
-- needs an immutable proof of the exact post-rewrite request units. Version 0
-- preserves pre-schema-18 rows; schema-18 writers explicitly use version 1.
ALTER TABLE upstream_attempts
    ADD COLUMN request_measurement_binding_version smallint NOT NULL DEFAULT 0,
    ADD COLUMN request_measurement_sha256 bytea,
    ADD COLUMN measured_request_bytes bigint,
    ADD COLUMN measured_image_units bigint,
    ADD COLUMN measured_tool_calls bigint,
    ADD CONSTRAINT upstream_attempts_request_measurement_binding_check
        CHECK (
            (
                request_measurement_binding_version = 0
                AND request_measurement_sha256 IS NULL
                AND measured_request_bytes IS NULL
                AND measured_image_units IS NULL
                AND measured_tool_calls IS NULL
            )
            OR (
                request_measurement_binding_version = 1
                AND (
                    (
                        request_measurement_sha256 IS NULL
                        AND measured_request_bytes IS NULL
                        AND measured_image_units IS NULL
                        AND measured_tool_calls IS NULL
                    )
                    OR (
                        octet_length(request_measurement_sha256) = 32
                        AND request_measurement_sha256 <> decode(repeat('00', 32), 'hex')
                        AND measured_request_bytes BETWEEN 0 AND 104857600
                        AND (measured_image_units IS NULL OR measured_image_units BETWEEN 0 AND 1000000)
                        AND (measured_tool_calls IS NULL OR measured_tool_calls BETWEEN 0 AND 1000000)
                    )
                )
            )
        ),
    DROP CONSTRAINT upstream_attempts_decision_binding_check,
    ADD CONSTRAINT upstream_attempts_decision_binding_check
        CHECK (
            (
                attempt_decision_binding_version = 0
                AND attempt_number = 1
                AND model_key IS NULL
                AND attempt_decision_sha256 IS NULL
                AND per_request_output_token_bound IS NULL
            )
            OR (
                attempt_decision_binding_version IN (1, 2)
                AND model_key ~ '^[a-z][a-z0-9_-]{0,62}$'
                AND physical_model IS NOT NULL
                AND octet_length(attempt_decision_sha256) = 32
                AND attempt_decision_sha256 <> decode(repeat('00', 32), 'hex')
                AND (
                    per_request_output_token_bound IS NULL
                    OR per_request_output_token_bound > 0
                )
                AND (
                    (attempt_decision_binding_version = 1 AND request_measurement_binding_version = 0)
                    OR (attempt_decision_binding_version = 2 AND request_measurement_binding_version = 1)
                )
            )
        );

COMMENT ON COLUMN upstream_attempts.request_measurement_sha256 IS
    'SHA-256 of the exact post-rewrite request body measured before dispatch; never a client-supplied digest.';
COMMENT ON COLUMN upstream_attempts.measured_request_bytes IS
    'Exact byte length of request_measurement_sha256 body; zero is valid for a bodyless opaque request.';
COMMENT ON COLUMN upstream_attempts.measured_image_units IS
    'Exact structured image-unit count, or NULL when the selected protocol cannot prove it.';
COMMENT ON COLUMN upstream_attempts.measured_tool_calls IS
    'Exact structured historical tool-call count, or NULL when the selected protocol cannot prove it.';
