-- Extend durable quota bucket identity with sealed installation-family,
-- component, and trust provenance. Existing bucket identities remain valid;
-- this migration only widens the closed canonical scope vocabulary.
ALTER TABLE quota_buckets
    DROP CONSTRAINT quota_buckets_scope_dimensions_check,
    ADD CONSTRAINT quota_buckets_scope_dimensions_check
        CHECK (
            CASE
                WHEN array_ndims(scope_dimensions) = 1
                     AND array_lower(scope_dimensions, 1) = 1
                THEN
                    cardinality(scope_dimensions) BETWEEN 1 AND 16
                    AND array_position(scope_dimensions, NULL) IS NULL
                    AND (E'\n' || array_to_string(scope_dimensions, E'\n', '<null>') || E'\n') ~
                        E'^\n(organization\n)?(application\n)?(environment\n)?(user\n)?(installation\n)?(installation_family\n)?(client_component\n)?(component_definition\n)?(component_kind\n)?(trust_source\n)?(feature\n)?(route\n)?(upstream\n)?(model\n)?(platform\n)?(normalized_claim:[a-z][a-z0-9_]{0,62}\n)?$'
                ELSE false
            END
        ),
    DROP CONSTRAINT quota_buckets_scope_type_dimensions_check,
    ADD CONSTRAINT quota_buckets_scope_type_dimensions_check
        CHECK (
            scope_type IN (
                'organization', 'application', 'environment', 'user',
                'installation', 'installation_family', 'client_component',
                'component_definition', 'component_kind', 'trust_source',
                'feature', 'route', 'upstream', 'model', 'platform',
                'normalized_claim', 'composite'
            )
            AND (
                (scope_type = 'composite' AND cardinality(scope_dimensions) BETWEEN 2 AND 16)
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
    'Canonical configuration dimension names, including sealed installation-family/component/trust provenance and at most one normalized_claim:<name> selector; raw normalized claim values are never stored.';

-- Logical-request attribution is optional for pre-component callers, but it
-- can never be partially populated. Framework identity is the closed public
-- registry ID paired with one canonical SemVer 2.0.0 declaration.
ALTER TABLE logical_requests
    ADD CONSTRAINT logical_requests_component_attribution_check
        CHECK (
            (
                installation_family_id IS NULL
                AND client_component_id IS NULL
                AND component_definition_id IS NULL
                AND component_kind IS NULL
                AND trust_source IS NULL
            )
            OR (
                installation_family_id IS NOT NULL
                AND client_component_id IS NOT NULL
                AND component_definition_id IS NOT NULL
                AND component_kind IS NOT NULL
                AND trust_source IS NOT NULL
                AND component_definition_id ~ '^[a-z][a-z0-9_-]{0,62}$'
                AND component_kind ~ '^[a-z][a-z0-9_-]{0,62}$'
                AND trust_source ~ '^[a-z][a-z0-9_-]{0,62}$'
            )
        ),
    ADD CONSTRAINT logical_requests_framework_attribution_check
        CHECK (
            (framework IS NULL AND framework_version IS NULL)
            OR (
                framework IS NOT NULL
                AND framework_version IS NOT NULL
                AND framework IN (
                    'android-okhttp', 'foundation-models', 'langchain-js',
                    'macpaw-openai', 'openai-js', 'react-native-fetch',
                    'swift-openai', 'vercel-ai-sdk'
                )
                AND char_length(framework_version) BETWEEN 5 AND 128
                AND framework_version ~
                    '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.((0|[1-9][0-9]*)|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
            )
        );
