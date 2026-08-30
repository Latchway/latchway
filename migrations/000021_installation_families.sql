-- Installation Families are the version-1 client boundary. A family groups
-- independently executing components; every component owns a distinct P-256
-- key, session family, refresh chain, trust provenance and revocation state.

CREATE TABLE component_definitions (
    environment_id text NOT NULL,
    config_revision_id text NOT NULL,
    component_definition_id text NOT NULL
        CHECK (component_definition_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    platform text NOT NULL
        CHECK (platform IN (
            'ios', 'android', 'web', 'node',
            'react_native_ios', 'react_native_android', 'watchos', 'wearos'
        )),
    component_kind text NOT NULL
        CHECK (component_kind IN (
            'main_app', 'widget', 'share_extension', 'app_intent_extension',
            'notification_service_extension', 'action_extension',
            'sso_extension', 'watch_extension', 'android_app', 'wear_app',
            'browser', 'node_process'
        )),
    family_role text NOT NULL CHECK (family_role IN ('root', 'delegated')),
    definition jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (config_revision_id)
        REFERENCES config_revisions (config_revision_id),
    PRIMARY KEY (environment_id, config_revision_id, component_definition_id)
);

CREATE INDEX component_definitions_lookup_idx
    ON component_definitions (environment_id, component_definition_id, config_revision_id);

CREATE TABLE installation_families (
    installation_family_id text PRIMARY KEY
        CHECK (installation_family_id ~ '^fam_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    platform text NOT NULL
        CHECK (platform IN (
            'ios', 'android', 'web', 'node',
            'react_native_ios', 'react_native_android', 'watchos', 'wearos'
        )),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    root_component_id text,
    root_installation_id text NOT NULL REFERENCES installations (installation_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revocation_reason text
        CHECK (revocation_reason IS NULL OR char_length(revocation_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    CHECK (updated_at >= created_at),
    CHECK (last_seen_at >= created_at),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
    UNIQUE (root_installation_id),
    UNIQUE (organization_id, application_id, environment_id, installation_family_id),
    UNIQUE (
        organization_id, application_id, environment_id,
        application_user_id, installation_family_id
    )
);

CREATE INDEX installation_families_user_idx
    ON installation_families (
        organization_id, application_id, application_user_id,
        environment_id, created_at DESC, installation_family_id
    );

CREATE TABLE client_components (
    client_component_id text PRIMARY KEY
        CHECK (client_component_id ~ '^cmp_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    installation_family_id text NOT NULL,
    component_definition_id text NOT NULL
        CHECK (component_definition_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    component_kind text NOT NULL
        CHECK (component_kind IN (
            'main_app', 'widget', 'share_extension', 'app_intent_extension',
            'notification_service_extension', 'action_extension',
            'sso_extension', 'watch_extension', 'android_app', 'wear_app',
            'browser', 'node_process'
        )),
    platform text NOT NULL
        CHECK (platform IN (
            'ios', 'android', 'web', 'node',
            'react_native_ios', 'react_native_android', 'watchos', 'wearos'
        )),
    is_root boolean NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked', 'replaced')),
    current_component_key_id text,
    trust_source text NOT NULL
        CHECK (trust_source IN (
            'direct_attested', 'delegated_from_attested_root',
            'delegated_identity_only', 'identity_only',
            'web_risk_verified', 'debug'
        )),
    trust_attestation_provider text
        CHECK (trust_attestation_provider IS NULL OR trust_attestation_provider IN (
            'app_attest', 'play_integrity', 'firebase_app_check', 'turnstile', 'debug'
        )),
    trust_parent_component_id text,
    trust_parent_attestation_event_id text,
    trust_delegation_id text,
    trust_verified_at timestamptz,
    trust_expires_at timestamptz,
    trust_signals jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(trust_signals) = 'object'),
    granted_features jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(granted_features) = 'array'),
    key_storage_claim text NOT NULL DEFAULT 'unknown'
        CHECK (key_storage_claim IN (
            'unknown', 'secure_enclave', 'keychain', 'strongbox', 'tee',
            'software', 'webcrypto', 'memory'
        )),
    app_version text CHECK (app_version IS NULL OR char_length(app_version) BETWEEN 1 AND 128),
    sdk_version text CHECK (sdk_version IS NULL OR char_length(sdk_version) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revocation_reason text
        CHECK (revocation_reason IS NULL OR char_length(revocation_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (
        organization_id, application_id, environment_id,
        application_user_id, installation_family_id
    ) REFERENCES installation_families (
        organization_id, application_id, environment_id,
        application_user_id, installation_family_id
    ),
    FOREIGN KEY (trust_parent_component_id) REFERENCES client_components (client_component_id),
    FOREIGN KEY (trust_parent_attestation_event_id) REFERENCES attestation_events (attestation_event_id),
    CHECK (updated_at >= created_at),
    CHECK (last_seen_at >= created_at),
    CHECK (trust_expires_at IS NULL OR trust_verified_at IS NULL OR trust_expires_at > trust_verified_at),
    CHECK ((status IN ('revoked', 'replaced')) = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
    CHECK (
        (is_root AND trust_parent_component_id IS NULL AND trust_delegation_id IS NULL)
        OR
        (NOT is_root AND trust_parent_component_id IS NOT NULL)
    ),
    UNIQUE (organization_id, application_id, environment_id, client_component_id),
    UNIQUE (installation_family_id, component_definition_id, client_component_id)
);

CREATE UNIQUE INDEX client_components_one_active_definition_idx
    ON client_components (installation_family_id, component_definition_id)
    WHERE status = 'active';

CREATE INDEX client_components_family_idx
    ON client_components (installation_family_id, status, created_at, client_component_id);

ALTER TABLE installation_families
    ADD CONSTRAINT installation_families_root_component_fk
    FOREIGN KEY (root_component_id) REFERENCES client_components (client_component_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE component_keys (
    component_key_id text PRIMARY KEY
        CHECK (component_key_id ~ '^cky_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    installation_family_id text NOT NULL,
    client_component_id text NOT NULL,
    dpop_jkt text NOT NULL CHECK (char_length(dpop_jkt) = 43),
    public_jwk jsonb NOT NULL CHECK (jsonb_typeof(public_jwk) = 'object'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'replaced', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    replaced_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id, client_component_id)
        REFERENCES client_components (
            organization_id, application_id, environment_id, client_component_id
        ),
    CHECK (replaced_at IS NULL OR replaced_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    UNIQUE (environment_id, dpop_jkt),
    UNIQUE (client_component_id, component_key_id)
);

CREATE UNIQUE INDEX component_keys_one_active_component_idx
    ON component_keys (client_component_id) WHERE status = 'active';

ALTER TABLE client_components
    ADD CONSTRAINT client_components_current_key_fk
    FOREIGN KEY (current_component_key_id)
        REFERENCES component_keys (component_key_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE component_delegations (
    component_delegation_id text PRIMARY KEY
        CHECK (component_delegation_id ~ '^dlg_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    installation_family_id text NOT NULL,
    parent_component_id text NOT NULL,
    child_component_id text NOT NULL,
    child_component_key_id text NOT NULL,
    parent_session_grant_id text NOT NULL,
    feature_scopes jsonb NOT NULL CHECK (jsonb_typeof(feature_scopes) = 'array'),
    configuration_revision_id text NOT NULL,
    parent_attestation_event_id text,
    identity_provider_key text NOT NULL,
    trust_level text NOT NULL CHECK (trust_level IN (
        'none', 'identity_only', 'web_risk_verified', 'app_verified',
        'device_verified', 'strong_device_verified', 'debug'
    )),
    identity_verified_at timestamptz NOT NULL,
    identity_expires_at timestamptz NOT NULL,
    attested_at timestamptz NOT NULL,
    attestation_provider text NOT NULL CHECK (attestation_provider IN (
        'app_attest', 'play_integrity', 'firebase_app_check', 'turnstile', 'debug'
    )),
    attestation_expires_at timestamptz NOT NULL,
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (parent_component_id) REFERENCES client_components (client_component_id),
    FOREIGN KEY (child_component_id) REFERENCES client_components (client_component_id),
    FOREIGN KEY (child_component_key_id) REFERENCES component_keys (component_key_id),
    FOREIGN KEY (parent_session_grant_id) REFERENCES session_grants (session_grant_id),
    FOREIGN KEY (organization_id, application_id, environment_id, configuration_revision_id)
        REFERENCES config_revisions (
            organization_id, application_id, environment_id, config_revision_id
        ),
    FOREIGN KEY (parent_attestation_event_id) REFERENCES attestation_events (attestation_event_id),
    CHECK (parent_component_id <> child_component_id),
    CHECK (identity_expires_at > identity_verified_at),
    CHECK (attestation_expires_at > attested_at),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    UNIQUE (environment_id, nonce_hash),
    UNIQUE (child_component_id, component_delegation_id)
);

ALTER TABLE client_components
    ADD CONSTRAINT client_components_trust_delegation_fk
    FOREIGN KEY (trust_delegation_id)
        REFERENCES component_delegations (component_delegation_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE component_session_families (
    component_session_family_id text PRIMARY KEY
        CHECK (component_session_family_id ~ '^csf_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    installation_family_id text NOT NULL,
    client_component_id text NOT NULL,
    component_key_id text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'expired', 'replaced')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revocation_reason text
        CHECK (revocation_reason IS NULL OR char_length(revocation_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, application_id, environment_id, client_component_id)
        REFERENCES client_components (
            organization_id, application_id, environment_id, client_component_id
        ),
    FOREIGN KEY (client_component_id, component_key_id)
        REFERENCES component_keys (client_component_id, component_key_id),
    CHECK (updated_at >= created_at),
    CHECK ((status IN ('revoked', 'replaced')) = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
    UNIQUE (organization_id, application_id, environment_id, component_session_family_id)
);

CREATE UNIQUE INDEX component_session_families_one_active_idx
    ON component_session_families (client_component_id)
    WHERE status = 'active';

CREATE TABLE component_refresh_tokens (
    component_refresh_token_id text PRIMARY KEY
        CHECK (component_refresh_token_id ~ '^crf_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    component_session_family_id text NOT NULL,
    client_component_id text NOT NULL,
    component_key_id text NOT NULL,
    session_grant_id text,
    grant_kind text NOT NULL DEFAULT 'session'
        CHECK (grant_kind IN ('provisioning', 'session')),
    parent_component_refresh_token_id text,
    rotated_to_component_refresh_token_id text,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    status text NOT NULL
        CHECK (status IN ('staged', 'active', 'rotated', 'revoked', 'reused', 'expired')),
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (component_session_family_id)
        REFERENCES component_session_families (component_session_family_id),
    FOREIGN KEY (client_component_id, component_key_id)
        REFERENCES component_keys (client_component_id, component_key_id),
    FOREIGN KEY (session_grant_id) REFERENCES session_grants (session_grant_id),
    FOREIGN KEY (parent_component_refresh_token_id)
        REFERENCES component_refresh_tokens (component_refresh_token_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (rotated_to_component_refresh_token_id)
        REFERENCES component_refresh_tokens (component_refresh_token_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (expires_at > issued_at),
    CHECK (used_at IS NULL OR used_at >= issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
    CHECK (parent_component_refresh_token_id IS NULL OR parent_component_refresh_token_id <> component_refresh_token_id),
    CHECK (rotated_to_component_refresh_token_id IS NULL OR rotated_to_component_refresh_token_id <> component_refresh_token_id),
    CHECK (
        (grant_kind = 'provisioning' AND session_grant_id IS NULL AND parent_component_refresh_token_id IS NULL)
        OR (grant_kind = 'session' AND session_grant_id IS NOT NULL)
    ),
    CHECK (
        (status IN ('staged', 'active') AND used_at IS NULL AND rotated_to_component_refresh_token_id IS NULL AND revoked_at IS NULL)
        OR (status = 'rotated' AND used_at IS NOT NULL AND rotated_to_component_refresh_token_id IS NOT NULL)
        OR status IN ('revoked', 'reused', 'expired')
    ),
    UNIQUE (component_session_family_id, component_refresh_token_id)
);

CREATE UNIQUE INDEX component_refresh_tokens_one_active_family_idx
    ON component_refresh_tokens (component_session_family_id)
    WHERE status = 'active';

CREATE INDEX component_refresh_tokens_family_idx
    ON component_refresh_tokens (component_session_family_id, issued_at DESC);

CREATE TABLE refresh_rotation_results (
    refresh_rotation_result_id text PRIMARY KEY
        CHECK (refresh_rotation_result_id ~ '^rrs_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    old_refresh_token_hash bytea NOT NULL UNIQUE CHECK (octet_length(old_refresh_token_hash) = 32),
    client_component_id text NOT NULL,
    component_key_id text NOT NULL,
    dpop_jkt text NOT NULL CHECK (char_length(dpop_jkt) = 43),
    rotation_response_ciphertext bytea NOT NULL
        CHECK (octet_length(rotation_response_ciphertext) >= 17),
    rotation_response_nonce bytea NOT NULL CHECK (octet_length(rotation_response_nonce) = 12),
    encryption_format_version smallint NOT NULL CHECK (encryption_format_version > 0),
    encryption_algorithm text NOT NULL CHECK (encryption_algorithm = 'AES-256-GCM'),
    master_key_identifier text NOT NULL
        CHECK (char_length(master_key_identifier) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (client_component_id, component_key_id)
        REFERENCES component_keys (client_component_id, component_key_id),
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '5 minutes')
);

CREATE INDEX refresh_rotation_results_expiry_idx
    ON refresh_rotation_results (expires_at);

ALTER TABLE attestation_events
    ADD COLUMN installation_family_id text,
    ADD COLUMN client_component_id text,
    ADD COLUMN trust_source text,
    ADD COLUMN parent_component_id text,
    ADD COLUMN component_delegation_id text;

ALTER TABLE attestation_events
    ADD CONSTRAINT attestation_events_family_fk
        FOREIGN KEY (installation_family_id)
        REFERENCES installation_families (installation_family_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT attestation_events_component_fk
        FOREIGN KEY (client_component_id)
        REFERENCES client_components (client_component_id)
        DEFERRABLE INITIALLY DEFERRED;

-- A delegated component uses the root installation as its durable family
-- anchor but presents its own DPoP key. The original session_grants foreign
-- key coupled installation ownership and the installation's root DPoP key,
-- which made an independently keyed child grant impossible to persist. Keep
-- the complete tenant/user/installation ownership invariant while allowing
-- session_grants.dpop_jkt to bind either the root key or a component key.
ALTER TABLE installations
    ADD CONSTRAINT installations_session_scope_unique
    UNIQUE (
        organization_id, application_id, environment_id,
        application_user_id, installation_id
    );

ALTER TABLE session_grants
    DROP CONSTRAINT session_grants_organization_id_application_id_environment__fkey,
    ADD CONSTRAINT session_grants_installation_scope_fk
    FOREIGN KEY (
        organization_id, application_id, environment_id,
        application_user_id, installation_id
    ) REFERENCES installations (
        organization_id, application_id, environment_id,
        application_user_id, installation_id
    );

ALTER TABLE session_grants
    ADD COLUMN installation_family_id text,
    ADD COLUMN client_component_id text,
    ADD COLUMN component_definition_id text,
    ADD COLUMN component_kind text,
    ADD COLUMN component_is_root boolean,
    ADD COLUMN trust_source text,
    ADD COLUMN component_session_family_id text;

ALTER TABLE session_grants
    ADD CONSTRAINT session_grants_family_fk
        FOREIGN KEY (installation_family_id)
        REFERENCES installation_families (installation_family_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT session_grants_component_fk
        FOREIGN KEY (client_component_id)
        REFERENCES client_components (client_component_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT session_grants_component_session_family_fk
        FOREIGN KEY (component_session_family_id)
        REFERENCES component_session_families (component_session_family_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT session_grants_component_shape_check CHECK (
        (
            installation_family_id IS NULL
            AND client_component_id IS NULL
            AND component_definition_id IS NULL
            AND component_kind IS NULL
            AND component_is_root IS NULL
            AND trust_source IS NULL
            AND component_session_family_id IS NULL
        )
        OR
        (
            installation_family_id IS NOT NULL
            AND client_component_id IS NOT NULL
            AND component_definition_id IS NOT NULL
            AND component_kind IS NOT NULL
            AND component_is_root IS NOT NULL
            AND trust_source IS NOT NULL
            AND component_session_family_id IS NOT NULL
        )
    );

ALTER TABLE logical_requests
    ADD COLUMN installation_family_id text,
    ADD COLUMN client_component_id text,
    ADD COLUMN component_definition_id text,
    ADD COLUMN component_kind text,
    ADD COLUMN trust_source text,
    ADD COLUMN framework text,
    ADD COLUMN framework_version text;

ALTER TABLE logical_requests
    ADD CONSTRAINT logical_requests_family_fk
        FOREIGN KEY (installation_family_id)
        REFERENCES installation_families (installation_family_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT logical_requests_component_fk
        FOREIGN KEY (client_component_id)
        REFERENCES client_components (client_component_id)
        DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX logical_requests_component_usage_idx
    ON logical_requests (
        organization_id, application_id, environment_id,
        installation_family_id, client_component_id, requested_at DESC
    );

CREATE INDEX logical_requests_framework_usage_idx
    ON logical_requests (
        organization_id, application_id, environment_id,
        framework, framework_version, requested_at DESC
    );

-- Deterministically lift every pre-family installation into the new model.
-- Reusing the existing ULID payload under a new type prefix makes the upgrade
-- reproducible, collision-free across each destination table, and independent
-- of database extensions or random functions. Legacy rows remain intact so
-- already-issued access tokens continue to authorize until their normal
-- expiry; duplicated refresh hashes are selected from the component table
-- first and therefore issue component-aware credentials on the next rotation.
INSERT INTO installation_families (
    installation_family_id, organization_id, application_id, environment_id,
    application_user_id, platform, status, root_installation_id,
    created_at, updated_at, last_seen_at, revoked_at, revocation_reason
)
SELECT
    'fam_' || substring(i.installation_id FROM 5),
    i.organization_id, i.application_id, i.environment_id,
    i.application_user_id, i.platform, i.status, i.installation_id,
    i.created_at, i.updated_at, i.last_seen_at, i.revoked_at, i.revoke_reason
FROM installations AS i
ON CONFLICT (installation_family_id) DO NOTHING;

-- Persist an audit/reference definition for migrated roots. Runtime snapshots
-- synthesize the same reserved definition only when an old active revision has
-- no explicit Component Definition, allowing operators to adopt a configured
-- root on the next direct session exchange.
INSERT INTO component_definitions (
    environment_id, config_revision_id, component_definition_id,
    platform, component_kind, family_role, definition
)
SELECT DISTINCT
    i.environment_id,
    active.config_revision_id,
    CASE i.platform
        WHEN 'ios' THEN 'legacy-ios-root'
        WHEN 'android' THEN 'legacy-android-root'
        WHEN 'web' THEN 'legacy-web-root'
        WHEN 'node' THEN 'legacy-node-root'
        WHEN 'react_native_ios' THEN 'legacy-react-native-ios-root'
        WHEN 'react_native_android' THEN 'legacy-react-native-android-root'
    END,
    i.platform,
    CASE i.platform
        WHEN 'android' THEN 'android_app'
        WHEN 'react_native_android' THEN 'android_app'
        WHEN 'web' THEN 'browser'
        WHEN 'node' THEN 'node_process'
        ELSE 'main_app'
    END,
    'root',
    jsonb_build_object(
        'id', CASE i.platform
            WHEN 'ios' THEN 'legacy-ios-root'
            WHEN 'android' THEN 'legacy-android-root'
            WHEN 'web' THEN 'legacy-web-root'
            WHEN 'node' THEN 'legacy-node-root'
            WHEN 'react_native_ios' THEN 'legacy-react-native-ios-root'
            WHEN 'react_native_android' THEN 'legacy-react-native-android-root'
        END,
        'platform', i.platform,
        'kind', CASE i.platform
            WHEN 'android' THEN 'android_app'
            WHEN 'react_native_android' THEN 'android_app'
            WHEN 'web' THEN 'browser'
            WHEN 'node' THEN 'node_process'
            ELSE 'main_app'
        END,
        'familyRole', 'root',
        'identifiers', '{}'::jsonb,
        'attestation', jsonb_build_object('strategy', 'identity_only'),
        'allowedFeatures', COALESCE((
            SELECT jsonb_agg(feature.value ->> 'id' ORDER BY feature.value ->> 'id')
            FROM jsonb_array_elements(
                COALESCE(active_revision.compiled_document #> '{spec,features}', '[]'::jsonb)
            ) AS feature(value)
            WHERE jsonb_typeof(feature.value) = 'object'
              AND feature.value ? 'id'
        ), '[]'::jsonb),
        'migration', jsonb_build_object('source', 'legacy_installation')
    )
FROM installations AS i
JOIN active_config_revisions AS active
  ON active.organization_id = i.organization_id
 AND active.application_id = i.application_id
 AND active.environment_id = i.environment_id
JOIN config_revisions AS active_revision
  ON active_revision.config_revision_id = active.config_revision_id
ON CONFLICT (environment_id, config_revision_id, component_definition_id) DO NOTHING;

INSERT INTO client_components (
    client_component_id, organization_id, application_id, environment_id,
    application_user_id, installation_family_id, component_definition_id,
    component_kind, platform, is_root, status, trust_source,
    trust_attestation_provider, trust_verified_at, trust_expires_at,
    trust_signals, granted_features, key_storage_claim, app_version,
    created_at, updated_at, last_seen_at, revoked_at, revocation_reason
)
SELECT
    'cmp_' || substring(i.installation_id FROM 5),
    i.organization_id, i.application_id, i.environment_id,
    i.application_user_id,
    'fam_' || substring(i.installation_id FROM 5),
    CASE i.platform
        WHEN 'ios' THEN 'legacy-ios-root'
        WHEN 'android' THEN 'legacy-android-root'
        WHEN 'web' THEN 'legacy-web-root'
        WHEN 'node' THEN 'legacy-node-root'
        WHEN 'react_native_ios' THEN 'legacy-react-native-ios-root'
        WHEN 'react_native_android' THEN 'legacy-react-native-android-root'
    END,
    CASE i.platform
        WHEN 'android' THEN 'android_app'
        WHEN 'react_native_android' THEN 'android_app'
        WHEN 'web' THEN 'browser'
        WHEN 'node' THEN 'node_process'
        ELSE 'main_app'
    END,
    i.platform, true, i.status,
    CASE latest_grant.attestation_provider
        WHEN 'app_attest' THEN 'direct_attested'
        WHEN 'play_integrity' THEN 'direct_attested'
        WHEN 'firebase_app_check' THEN 'web_risk_verified'
        WHEN 'turnstile' THEN 'web_risk_verified'
        WHEN 'debug' THEN 'debug'
        ELSE 'identity_only'
    END,
    latest_grant.attestation_provider,
    COALESCE(latest_grant.attested_at, latest_grant.identity_verified_at, i.created_at),
    latest_grant.attestation_expires_at,
    jsonb_build_object('migrated_legacy_installation', true),
    COALESCE((
        SELECT jsonb_agg(feature.value ->> 'id' ORDER BY feature.value ->> 'id')
        FROM jsonb_array_elements(
            COALESCE(active_revision.compiled_document #> '{spec,features}', '[]'::jsonb)
        ) AS feature(value)
        WHERE jsonb_typeof(feature.value) = 'object'
          AND feature.value ? 'id'
    ), '[]'::jsonb),
    i.key_storage, i.app_version,
    i.created_at, i.updated_at, i.last_seen_at, i.revoked_at, i.revoke_reason
FROM installations AS i
LEFT JOIN active_config_revisions AS active
  ON active.organization_id = i.organization_id
 AND active.application_id = i.application_id
 AND active.environment_id = i.environment_id
LEFT JOIN config_revisions AS active_revision
  ON active_revision.config_revision_id = active.config_revision_id
LEFT JOIN LATERAL (
    SELECT
        grant_row.identity_verified_at,
        grant_row.attested_at,
        grant_row.attestation_provider,
        grant_row.attestation_expires_at
    FROM session_grants AS grant_row
    WHERE grant_row.organization_id = i.organization_id
      AND grant_row.application_id = i.application_id
      AND grant_row.environment_id = i.environment_id
      AND grant_row.installation_id = i.installation_id
    ORDER BY grant_row.issued_at DESC, grant_row.session_grant_id DESC
    LIMIT 1
) AS latest_grant ON true
ON CONFLICT (client_component_id) DO NOTHING;

INSERT INTO component_keys (
    component_key_id, organization_id, application_id, environment_id,
    installation_family_id, client_component_id, dpop_jkt, public_jwk,
    status, created_at, revoked_at
)
SELECT
    'cky_' || substring(i.installation_id FROM 5),
    i.organization_id, i.application_id, i.environment_id,
    'fam_' || substring(i.installation_id FROM 5),
    'cmp_' || substring(i.installation_id FROM 5),
    i.dpop_jkt, i.dpop_public_jwk,
    CASE WHEN i.status = 'active' THEN 'active' ELSE 'revoked' END,
    i.created_at, i.revoked_at
FROM installations AS i
ON CONFLICT (component_key_id) DO NOTHING;

UPDATE client_components AS component
SET current_component_key_id = 'cky_' || substring(component.client_component_id FROM 5)
WHERE component.is_root
  AND component.current_component_key_id IS NULL
  AND component.trust_signals @> '{"migrated_legacy_installation":true}'::jsonb;

UPDATE installation_families AS family
SET root_component_id = 'cmp_' || substring(family.installation_family_id FROM 5)
WHERE family.root_component_id IS NULL;

INSERT INTO component_session_families (
    component_session_family_id, organization_id, application_id, environment_id,
    application_user_id, installation_family_id, client_component_id,
    component_key_id, status, created_at, updated_at, revoked_at, revocation_reason
)
SELECT
    'csf_' || substring(i.installation_id FROM 5),
    i.organization_id, i.application_id, i.environment_id, i.application_user_id,
    'fam_' || substring(i.installation_id FROM 5),
    'cmp_' || substring(i.installation_id FROM 5),
    'cky_' || substring(i.installation_id FROM 5),
    CASE WHEN i.status = 'active' THEN 'active' ELSE 'revoked' END,
    i.created_at, i.updated_at, i.revoked_at,
    CASE WHEN i.status = 'active' THEN NULL ELSE COALESCE(i.revoke_reason, 'legacy_installation_revoked') END
FROM installations AS i
ON CONFLICT (component_session_family_id) DO NOTHING;

INSERT INTO component_refresh_tokens (
    component_refresh_token_id, component_session_family_id,
    client_component_id, component_key_id, session_grant_id, grant_kind,
    parent_component_refresh_token_id, rotated_to_component_refresh_token_id,
    token_hash, status, issued_at, expires_at, used_at, revoked_at
)
SELECT
    'crf_' || substring(refresh.refresh_token_id FROM 5),
    'csf_' || substring(refresh.installation_id FROM 5),
    'cmp_' || substring(refresh.installation_id FROM 5),
    'cky_' || substring(refresh.installation_id FROM 5),
    refresh.session_grant_id, 'session',
    CASE WHEN refresh.parent_refresh_token_id IS NULL THEN NULL
         ELSE 'crf_' || substring(refresh.parent_refresh_token_id FROM 5) END,
    CASE WHEN refresh.rotated_to_refresh_token_id IS NULL THEN NULL
         ELSE 'crf_' || substring(refresh.rotated_to_refresh_token_id FROM 5) END,
    refresh.token_hash,
    CASE
        WHEN installation.status = 'revoked' AND refresh.status IN ('staged', 'active') THEN 'revoked'
        -- The legacy schema scoped its single-active constraint by the
        -- caller-generated refresh family. Multiple direct exchanges for one
        -- installation could therefore leave more than one active family.
        -- The component model deliberately permits only one active refresh
        -- credential per independently executing component. Preserve the
        -- newest active credential and fail closed for older active branches;
        -- their already-issued access grants remain untouched.
        WHEN refresh.status = 'active'
         AND refresh.refresh_token_id <> latest_active.refresh_token_id THEN 'revoked'
        ELSE refresh.status
    END,
    refresh.issued_at, refresh.expires_at, refresh.used_at,
    CASE
        WHEN installation.status = 'revoked' AND refresh.status IN ('staged', 'active')
            THEN COALESCE(refresh.revoked_at, installation.revoked_at, GREATEST(refresh.issued_at, installation.updated_at))
        WHEN refresh.status = 'active'
         AND refresh.refresh_token_id <> latest_active.refresh_token_id
            THEN GREATEST(refresh.issued_at, CURRENT_TIMESTAMP)
        ELSE refresh.revoked_at
    END
FROM refresh_tokens AS refresh
JOIN installations AS installation
  ON installation.organization_id = refresh.organization_id
 AND installation.application_id = refresh.application_id
 AND installation.environment_id = refresh.environment_id
 AND installation.installation_id = refresh.installation_id
LEFT JOIN LATERAL (
    SELECT candidate.refresh_token_id
    FROM refresh_tokens AS candidate
    WHERE candidate.organization_id = refresh.organization_id
      AND candidate.application_id = refresh.application_id
      AND candidate.environment_id = refresh.environment_id
      AND candidate.installation_id = refresh.installation_id
      AND candidate.status = 'active'
    ORDER BY candidate.issued_at DESC, candidate.refresh_token_id DESC
    LIMIT 1
) AS latest_active ON true
ON CONFLICT (component_refresh_token_id) DO NOTHING;

UPDATE attestation_events AS event
SET installation_family_id = 'fam_' || substring(event.installation_id FROM 5),
    client_component_id = 'cmp_' || substring(event.installation_id FROM 5),
    trust_source = CASE event.provider
        WHEN 'app_attest' THEN 'direct_attested'
        WHEN 'play_integrity' THEN 'direct_attested'
        WHEN 'firebase_app_check' THEN 'web_risk_verified'
        WHEN 'turnstile' THEN 'web_risk_verified'
        WHEN 'debug' THEN 'debug'
        ELSE 'identity_only'
    END
WHERE event.installation_id IS NOT NULL
  AND event.installation_family_id IS NULL;

UPDATE logical_requests AS request
SET installation_family_id = 'fam_' || substring(request.installation_id FROM 5),
    client_component_id = 'cmp_' || substring(request.installation_id FROM 5),
    component_definition_id = component.component_definition_id,
    component_kind = component.component_kind,
    trust_source = component.trust_source
FROM client_components AS component
WHERE component.client_component_id = 'cmp_' || substring(request.installation_id FROM 5)
  AND request.installation_family_id IS NULL;
