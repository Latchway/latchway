CREATE TABLE organizations (
    organization_id text PRIMARY KEY
        CHECK (organization_id ~ '^org_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    slug text NOT NULL UNIQUE
        CHECK (slug = lower(slug) AND slug ~ '^[a-z][a-z0-9-]{1,62}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    CHECK (updated_at >= created_at),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    UNIQUE (organization_id)
);

CREATE TABLE applications (
    application_id text PRIMARY KEY
        CHECK (application_id ~ '^app_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL REFERENCES organizations (organization_id),
    slug text NOT NULL
        CHECK (slug = lower(slug) AND slug ~ '^[a-z][a-z0-9-]{1,62}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    CHECK (updated_at >= created_at),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    UNIQUE (organization_id, slug),
    UNIQUE (organization_id, application_id)
);

CREATE INDEX applications_organization_idx
    ON applications (organization_id, created_at, application_id);

CREATE TABLE environments (
    environment_id text PRIMARY KEY
        CHECK (environment_id ~ '^env_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    slug text NOT NULL
        CHECK (slug = lower(slug) AND slug ~ '^[a-z][a-z0-9-]{1,62}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    kind text NOT NULL CHECK (kind IN ('development', 'staging', 'production')),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    FOREIGN KEY (organization_id, application_id)
        REFERENCES applications (organization_id, application_id),
    CHECK (updated_at >= created_at),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    UNIQUE (application_id, slug),
    UNIQUE (organization_id, application_id, environment_id),
    UNIQUE (organization_id, environment_id)
);

CREATE INDEX environments_tenant_idx
    ON environments (organization_id, application_id, created_at, environment_id);

CREATE TABLE admin_users (
    admin_user_id text PRIMARY KEY
        CHECK (admin_user_id ~ '^adm_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    email text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320),
    email_normalized text NOT NULL UNIQUE
        CHECK (
            email_normalized = lower(btrim(email_normalized))
            AND char_length(email_normalized) BETWEEN 3 AND 320
            AND position('@' IN email_normalized) > 1
        ),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    password_reset_required boolean NOT NULL DEFAULT false,
    CHECK (updated_at >= created_at),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    UNIQUE (admin_user_id)
);

CREATE TABLE admin_memberships (
    admin_membership_id text PRIMARY KEY
        CHECK (admin_membership_id ~ '^amb_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL REFERENCES organizations (organization_id),
    admin_user_id text NOT NULL REFERENCES admin_users (admin_user_id),
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_by_admin_user_id text REFERENCES admin_users (admin_user_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    CHECK (updated_at >= created_at),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    UNIQUE (organization_id, admin_user_id),
    UNIQUE (organization_id, admin_membership_id)
);

CREATE INDEX admin_memberships_user_idx
    ON admin_memberships (admin_user_id, organization_id);

CREATE TABLE admin_password_credentials (
    admin_user_id text PRIMARY KEY REFERENCES admin_users (admin_user_id),
    password_hash text NOT NULL
        CHECK (
            char_length(password_hash) BETWEEN 80 AND 256
            AND password_hash LIKE '$argon2id$v=19$%'
        ),
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz NOT NULL DEFAULT now(),
    reset_by_admin_user_id text REFERENCES admin_users (admin_user_id),
    CHECK (changed_at >= created_at)
);

CREATE TABLE admin_sessions (
    admin_session_id text PRIMARY KEY
        CHECK (admin_session_id ~ '^asn_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    admin_user_id text NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    token_hint text NOT NULL CHECK (token_hint ~ '^[A-Za-z0-9_-]{6}$'),
    csrf_token_hash bytea NOT NULL CHECK (octet_length(csrf_token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (expires_at > created_at),
    CHECK (last_seen_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
    UNIQUE (organization_id, admin_session_id)
);

CREATE INDEX admin_sessions_active_lookup_idx
    ON admin_sessions (token_hash, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX admin_sessions_user_idx
    ON admin_sessions (organization_id, admin_user_id, created_at DESC);

CREATE TABLE admin_api_tokens (
    admin_api_token_id text PRIMARY KEY
        CHECK (admin_api_token_id ~ '^tok_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    admin_user_id text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    token_hint text NOT NULL CHECK (token_hint ~ '^[A-Za-z0-9_-]{6}$'),
    scopes text[] NOT NULL
        CHECK (
            cardinality(scopes) BETWEEN 1 AND 7
            AND scopes <@ ARRAY[
                'manage_owners',
                'manage_secrets',
                'activate_configuration',
                'run_self_tests',
                'inspect_users',
                'revoke_installations',
                'view_prompt_bodies'
            ]::text[]
        ),
    created_by_admin_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    FOREIGN KEY (organization_id, created_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
    UNIQUE (organization_id, admin_api_token_id)
);

CREATE INDEX admin_api_tokens_active_lookup_idx
    ON admin_api_tokens (token_hash, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE admin_bootstrap_tokens (
    admin_bootstrap_token_id text PRIMARY KEY
        CHECK (admin_bootstrap_token_id ~ '^abt_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    generation smallint NOT NULL DEFAULT 1 UNIQUE CHECK (generation = 1),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    consumed_at timestamptz,
    consumed_by_admin_user_id text REFERENCES admin_users (admin_user_id),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK ((consumed_at IS NULL) = (consumed_by_admin_user_id IS NULL))
);

CREATE TABLE config_revisions (
    config_revision_id text PRIMARY KEY
        CHECK (config_revision_id ~ '^rev_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    revision_number bigint NOT NULL CHECK (revision_number > 0),
    etag text NOT NULL CHECK (char_length(etag) BETWEEN 16 AND 128),
    status text NOT NULL
        CHECK (status IN ('draft', 'valid', 'invalid', 'active', 'superseded')),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    compiled_document jsonb
        CHECK (compiled_document IS NULL OR jsonb_typeof(compiled_document) = 'object'),
    validation_errors jsonb
        CHECK (validation_errors IS NULL OR jsonb_typeof(validation_errors) = 'array'),
    created_by_admin_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    validated_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, created_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (
        (status IN ('valid', 'active', 'superseded')) =
        (validated_at IS NOT NULL AND compiled_document IS NOT NULL)
        OR status IN ('draft', 'invalid')
    ),
    UNIQUE (environment_id, revision_number),
    UNIQUE (environment_id, etag),
    UNIQUE (organization_id, application_id, environment_id, config_revision_id),
    UNIQUE (organization_id, application_id, environment_id, config_revision_id, status)
);

CREATE INDEX config_revisions_environment_idx
    ON config_revisions (organization_id, application_id, environment_id, revision_number DESC);

CREATE UNIQUE INDEX config_revisions_one_active_idx
    ON config_revisions (environment_id)
    WHERE status = 'active';

CREATE TABLE active_config_revisions (
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text PRIMARY KEY,
    config_revision_id text NOT NULL,
    revision_status text NOT NULL DEFAULT 'active' CHECK (revision_status = 'active'),
    activated_by_admin_user_id text NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        config_revision_id,
        revision_status
    )
        REFERENCES config_revisions (
            organization_id,
            application_id,
            environment_id,
            config_revision_id,
            status
        ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (organization_id, activated_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    UNIQUE (organization_id, environment_id)
);

CREATE TABLE secret_records (
    secret_record_id text PRIMARY KEY
        CHECK (secret_record_id ~ '^sec_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    name text NOT NULL
        CHECK (name = lower(name) AND name ~ '^[a-z][a-z0-9._/-]{1,127}$'),
    version bigint NOT NULL CHECK (version > 0),
    encryption_format_version smallint NOT NULL CHECK (encryption_format_version > 0),
    algorithm text NOT NULL CHECK (algorithm = 'aes-256-gcm'),
    master_key_identifier text NOT NULL
        CHECK (char_length(master_key_identifier) BETWEEN 1 AND 128),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) >= 17),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    created_by_admin_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz,
    destroyed_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, created_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (rotated_at IS NULL OR rotated_at >= created_at),
    CHECK (destroyed_at IS NULL OR destroyed_at >= created_at),
    UNIQUE (environment_id, name, version),
    UNIQUE (organization_id, application_id, environment_id, secret_record_id)
);

CREATE UNIQUE INDEX secret_records_current_version_idx
    ON secret_records (environment_id, name)
    WHERE rotated_at IS NULL AND destroyed_at IS NULL;

CREATE TABLE gateway_signing_keys (
    gateway_signing_key_id text PRIMARY KEY
        CHECK (gateway_signing_key_id ~ '^gsk_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    key_id text NOT NULL UNIQUE CHECK (char_length(key_id) BETWEEN 8 AND 128),
    algorithm text NOT NULL CHECK (algorithm IN ('ES256', 'EdDSA')),
    public_jwk jsonb NOT NULL CHECK (jsonb_typeof(public_jwk) = 'object'),
    encryption_format_version smallint NOT NULL CHECK (encryption_format_version > 0),
    master_key_identifier text NOT NULL
        CHECK (char_length(master_key_identifier) BETWEEN 1 AND 128),
    encrypted_private_key bytea NOT NULL CHECK (octet_length(encrypted_private_key) >= 17),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    status text NOT NULL CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    CHECK (not_after > not_before),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE UNIQUE INDEX gateway_signing_keys_one_active_idx
    ON gateway_signing_keys ((true))
    WHERE status = 'active';

CREATE INDEX gateway_signing_keys_validity_idx
    ON gateway_signing_keys (status, not_before, not_after);

CREATE TABLE identity_provider_states (
    identity_provider_state_id text PRIMARY KEY
        CHECK (identity_provider_state_id ~ '^idp_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    provider_key text NOT NULL
        CHECK (provider_key = lower(provider_key) AND provider_key ~ '^[a-z][a-z0-9_-]{1,63}$'),
    provider_type text NOT NULL
        CHECK (provider_type IN ('oidc', 'firebase', 'supabase', 'clerk', 'static_key', 'symmetric')),
    issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    state jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(state) = 'object'),
    jwks_refreshed_at timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR char_length(last_error_code) BETWEEN 1 AND 100),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    UNIQUE (environment_id, provider_key),
    UNIQUE (organization_id, application_id, environment_id, identity_provider_state_id)
);

CREATE TABLE application_users (
    application_user_id text PRIMARY KEY
        CHECK (application_user_id ~ '^usr_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'blocked', 'deleted')),
    normalized_claims jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(normalized_claims) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    blocked_at timestamptz,
    FOREIGN KEY (organization_id, application_id)
        REFERENCES applications (organization_id, application_id),
    CHECK (updated_at >= created_at),
    CHECK (last_seen_at IS NULL OR last_seen_at >= created_at),
    CHECK ((status = 'blocked') = (blocked_at IS NOT NULL)),
    UNIQUE (organization_id, application_id, application_user_id)
);

CREATE INDEX application_users_application_idx
    ON application_users (organization_id, application_id, created_at, application_user_id);

CREATE TABLE external_identities (
    external_identity_id text PRIMARY KEY
        CHECK (external_identity_id ~ '^xid_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    application_user_id text NOT NULL,
    provider_key text NOT NULL
        CHECK (provider_key = lower(provider_key) AND provider_key ~ '^[a-z][a-z0-9_-]{1,63}$'),
    issuer_hash bytea NOT NULL CHECK (octet_length(issuer_hash) = 32),
    subject_hmac bytea NOT NULL CHECK (octet_length(subject_hmac) = 32),
    selected_claims jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(selected_claims) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_verified_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    CHECK (last_verified_at >= created_at),
    UNIQUE (application_id, provider_key, issuer_hash, subject_hmac),
    UNIQUE (organization_id, application_id, external_identity_id)
);

CREATE INDEX external_identities_user_idx
    ON external_identities (organization_id, application_id, application_user_id);

CREATE TABLE user_overrides (
    user_override_id text PRIMARY KEY
        CHECK (user_override_id ~ '^uov_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    override_document jsonb NOT NULL CHECK (jsonb_typeof(override_document) = 'object'),
    reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    created_by_admin_user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    FOREIGN KEY (organization_id, created_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    UNIQUE (organization_id, application_id, environment_id, user_override_id)
);

CREATE UNIQUE INDEX user_overrides_one_active_idx
    ON user_overrides (environment_id, application_user_id)
    WHERE revoked_at IS NULL;

CREATE TABLE installations (
    installation_id text PRIMARY KEY
        CHECK (installation_id ~ '^ins_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    platform text NOT NULL CHECK (platform IN ('ios', 'android', 'web', 'node', 'react_native_ios', 'react_native_android')),
    dpop_jkt text NOT NULL CHECK (char_length(dpop_jkt) = 43),
    dpop_public_jwk jsonb NOT NULL CHECK (jsonb_typeof(dpop_public_jwk) = 'object'),
    key_storage text NOT NULL
        CHECK (key_storage IN ('secure_enclave', 'keychain', 'strongbox', 'tee', 'software', 'webcrypto', 'memory')),
    trust_level text NOT NULL
        CHECK (trust_level IN (
            'none',
            'identity_only',
            'web_risk_verified',
            'app_verified',
            'device_verified',
            'strong_device_verified',
            'debug'
        )),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    app_version text CHECK (app_version IS NULL OR char_length(app_version) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    CHECK (updated_at >= created_at),
    CHECK (last_seen_at >= created_at),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
    UNIQUE (environment_id, dpop_jkt),
    UNIQUE (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        dpop_jkt
    ),
    UNIQUE (organization_id, application_id, environment_id, installation_id)
);

CREATE INDEX installations_user_idx
    ON installations (organization_id, application_id, application_user_id, environment_id);

CREATE TABLE attestation_keys (
    attestation_key_id text PRIMARY KEY
        CHECK (attestation_key_id ~ '^aky_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    installation_id text NOT NULL,
    provider text NOT NULL
        CHECK (provider IN ('app_attest', 'play_integrity', 'firebase_app_check', 'turnstile', 'debug')),
    provider_key_id text
        CHECK (provider_key_id IS NULL OR char_length(provider_key_id) BETWEEN 1 AND 1024),
    public_key bytea,
    environment text NOT NULL CHECK (environment IN ('development', 'production')),
    sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invalid', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id, installation_id)
        REFERENCES installations (organization_id, application_id, environment_id, installation_id),
    CHECK (updated_at >= created_at),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    UNIQUE (organization_id, application_id, environment_id, attestation_key_id)
);

CREATE UNIQUE INDEX attestation_keys_provider_key_idx
    ON attestation_keys (environment_id, provider, provider_key_id)
    WHERE provider_key_id IS NOT NULL;

CREATE TABLE session_challenges (
    session_challenge_id text PRIMARY KEY
        CHECK (session_challenge_id ~ '^chl_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    identity_provider_key text NOT NULL
        CHECK (identity_provider_key = lower(identity_provider_key)),
    platform text NOT NULL CHECK (platform IN ('ios', 'android', 'web', 'node', 'react_native_ios', 'react_native_android')),
    dpop_jkt text NOT NULL CHECK (char_length(dpop_jkt) = 43),
    dpop_public_jwk jsonb NOT NULL CHECK (jsonb_typeof(dpop_public_jwk) = 'object'),
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    CHECK (expires_at > created_at),
    UNIQUE (organization_id, application_id, environment_id, session_challenge_id)
);

CREATE INDEX session_challenges_expiry_idx
    ON session_challenges (expires_at);

CREATE TABLE session_challenge_consumptions (
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    session_challenge_id text PRIMARY KEY,
    consumed_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id, session_challenge_id)
        REFERENCES session_challenges (
            organization_id,
            application_id,
            environment_id,
            session_challenge_id
        ),
    UNIQUE (organization_id, application_id, environment_id, session_challenge_id)
);

CREATE TABLE attestation_events (
    attestation_event_id text PRIMARY KEY
        CHECK (attestation_event_id ~ '^aev_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    installation_id text,
    session_challenge_id text,
    provider text NOT NULL
        CHECK (provider IN ('app_attest', 'play_integrity', 'firebase_app_check', 'turnstile', 'debug')),
    outcome text NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'error')),
    trust_level text
        CHECK (trust_level IS NULL OR trust_level IN (
            'none',
            'identity_only',
            'web_risk_verified',
            'app_verified',
            'device_verified',
            'strong_device_verified',
            'debug'
        )),
    evidence_hash bytea CHECK (evidence_hash IS NULL OR octet_length(evidence_hash) = 32),
    normalized_signals jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(normalized_signals) = 'object'),
    failure_code text CHECK (failure_code IS NULL OR char_length(failure_code) BETWEEN 1 AND 100),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    FOREIGN KEY (organization_id, application_id, environment_id, installation_id)
        REFERENCES installations (organization_id, application_id, environment_id, installation_id),
    FOREIGN KEY (organization_id, application_id, environment_id, session_challenge_id)
        REFERENCES session_challenges (organization_id, application_id, environment_id, session_challenge_id),
    CHECK ((outcome = 'accepted') = (failure_code IS NULL)),
    UNIQUE (organization_id, application_id, environment_id, attestation_event_id)
);

CREATE INDEX attestation_events_installation_idx
    ON attestation_events (organization_id, application_id, environment_id, installation_id, occurred_at DESC);

CREATE TABLE session_grants (
    session_grant_id text PRIMARY KEY
        CHECK (session_grant_id ~ '^sgr_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    installation_id text NOT NULL,
    access_token_jti_hash bytea NOT NULL UNIQUE CHECK (octet_length(access_token_jti_hash) = 32),
    dpop_jkt text NOT NULL CHECK (char_length(dpop_jkt) = 43),
    policy_revision_id text NOT NULL
        CHECK (policy_revision_id ~ '^rev_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    trust_level text NOT NULL
        CHECK (trust_level IN (
            'none',
            'identity_only',
            'web_risk_verified',
            'app_verified',
            'device_verified',
            'strong_device_verified',
            'debug'
        )),
    identity_verified_at timestamptz NOT NULL,
    attested_at timestamptz,
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        dpop_jkt
    ) REFERENCES installations (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        dpop_jkt
    ),
    FOREIGN KEY (organization_id, application_id, environment_id, policy_revision_id)
        REFERENCES config_revisions (organization_id, application_id, environment_id, config_revision_id),
    CHECK (expires_at > issued_at),
    CHECK (identity_verified_at <= issued_at),
    CHECK (attested_at IS NULL OR attested_at <= issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
    UNIQUE (organization_id, application_id, environment_id, session_grant_id),
    UNIQUE (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        session_grant_id
    )
);

CREATE INDEX session_grants_installation_idx
    ON session_grants (organization_id, application_id, environment_id, installation_id, issued_at DESC);

CREATE TABLE refresh_tokens (
    refresh_token_id text PRIMARY KEY
        CHECK (refresh_token_id ~ '^rft_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    family_id text NOT NULL
        CHECK (family_id ~ '^rff_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    installation_id text NOT NULL,
    session_grant_id text NOT NULL,
    parent_refresh_token_id text,
    rotated_to_refresh_token_id text,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    status text NOT NULL
        CHECK (status IN ('staged', 'active', 'rotated', 'revoked', 'reused', 'expired')),
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        session_grant_id
    ) REFERENCES session_grants (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        session_grant_id
    ),
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        family_id,
        parent_refresh_token_id
    ) REFERENCES refresh_tokens (
        organization_id,
        application_id,
        environment_id,
        family_id,
        refresh_token_id
    ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        family_id,
        rotated_to_refresh_token_id
    ) REFERENCES refresh_tokens (
        organization_id,
        application_id,
        environment_id,
        family_id,
        refresh_token_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CHECK (expires_at > issued_at),
    CHECK (used_at IS NULL OR used_at >= issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
    CHECK (parent_refresh_token_id IS NULL OR parent_refresh_token_id <> refresh_token_id),
    CHECK (rotated_to_refresh_token_id IS NULL OR rotated_to_refresh_token_id <> refresh_token_id),
    CHECK (
        (status IN ('staged', 'active') AND used_at IS NULL AND rotated_to_refresh_token_id IS NULL AND revoked_at IS NULL)
        OR (status = 'rotated' AND used_at IS NOT NULL AND rotated_to_refresh_token_id IS NOT NULL)
        OR (status IN ('revoked', 'reused', 'expired'))
    ),
    UNIQUE (organization_id, application_id, environment_id, refresh_token_id),
    UNIQUE (
        organization_id,
        application_id,
        environment_id,
        family_id,
        refresh_token_id
    )
);

CREATE UNIQUE INDEX refresh_tokens_one_active_family_idx
    ON refresh_tokens (family_id)
    WHERE status = 'active';

CREATE INDEX refresh_tokens_family_idx
    ON refresh_tokens (family_id, issued_at);

CREATE TABLE dpop_replay_entries (
    dpop_replay_entry_id text PRIMARY KEY
        CHECK (dpop_replay_entry_id ~ '^drp_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    session_grant_id text NOT NULL,
    proof_jti_hash bytea NOT NULL CHECK (octet_length(proof_jti_hash) = 32),
    http_method text NOT NULL CHECK (http_method ~ '^[A-Z]{3,10}$'),
    http_uri_hash bytea NOT NULL CHECK (octet_length(http_uri_hash) = 32),
    observed_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (organization_id, application_id, environment_id, session_grant_id)
        REFERENCES session_grants (organization_id, application_id, environment_id, session_grant_id),
    CHECK (expires_at > observed_at),
    UNIQUE (session_grant_id, proof_jti_hash),
    UNIQUE (organization_id, application_id, environment_id, dpop_replay_entry_id)
);

CREATE INDEX dpop_replay_entries_expiry_idx
    ON dpop_replay_entries (expires_at);

CREATE TABLE logical_requests (
    logical_request_id text PRIMARY KEY
        CHECK (logical_request_id ~ '^req_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    installation_id text NOT NULL,
    session_grant_id text NOT NULL,
    config_revision_id text NOT NULL,
    feature_key text NOT NULL
        CHECK (feature_key = lower(feature_key) AND feature_key ~ '^[a-z][a-z0-9_-]{1,127}$'),
    protocol text NOT NULL
        CHECK (protocol IN ('openai_responses', 'openai_chat', 'openai_embeddings', 'anthropic_messages', 'opaque_http')),
    client_request_id text CHECK (client_request_id IS NULL OR char_length(client_request_id) BETWEEN 1 AND 128),
    status text NOT NULL
        CHECK (status IN ('reserved', 'dispatched', 'streaming', 'succeeded', 'failed', 'cancelled', 'denied')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    dispatched_at timestamptz,
    completed_at timestamptz,
    failure_code text CHECK (failure_code IS NULL OR char_length(failure_code) BETWEEN 1 AND 100),
    FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    FOREIGN KEY (organization_id, application_id, environment_id, installation_id)
        REFERENCES installations (organization_id, application_id, environment_id, installation_id),
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        session_grant_id
    ) REFERENCES session_grants (
        organization_id,
        application_id,
        environment_id,
        application_user_id,
        installation_id,
        session_grant_id
    ),
    FOREIGN KEY (organization_id, application_id, environment_id, config_revision_id)
        REFERENCES config_revisions (organization_id, application_id, environment_id, config_revision_id),
    CHECK (dispatched_at IS NULL OR dispatched_at >= requested_at),
    CHECK (completed_at IS NULL OR completed_at >= requested_at),
    UNIQUE (organization_id, application_id, environment_id, logical_request_id)
);

CREATE UNIQUE INDEX logical_requests_client_request_idx
    ON logical_requests (environment_id, client_request_id)
    WHERE client_request_id IS NOT NULL;

CREATE INDEX logical_requests_user_idx
    ON logical_requests (organization_id, application_id, application_user_id, requested_at DESC);

CREATE TABLE quota_buckets (
    quota_bucket_id text PRIMARY KEY
        CHECK (quota_bucket_id ~ '^qbk_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    metric text NOT NULL
        CHECK (metric ~ '^[a-z][a-z0-9_]{1,63}$'),
    scope_type text NOT NULL
        CHECK (scope_type IN ('organization', 'application', 'environment', 'user', 'installation', 'feature')),
    scope_key text NOT NULL CHECK (char_length(scope_key) BETWEEN 1 AND 256),
    algorithm text NOT NULL CHECK (algorithm IN ('calendar', 'token_bucket', 'concurrency')),
    window_key text NOT NULL CHECK (char_length(window_key) BETWEEN 1 AND 128),
    hard_maximum bigint CHECK (hard_maximum IS NULL OR hard_maximum >= 0),
    used_units bigint NOT NULL DEFAULT 0 CHECK (used_units >= 0),
    reserved_units bigint NOT NULL DEFAULT 0 CHECK (reserved_units >= 0),
    available_units bigint CHECK (available_units IS NULL OR available_units >= 0),
    refill_numerator bigint CHECK (refill_numerator IS NULL OR refill_numerator >= 0),
    refill_denominator bigint CHECK (refill_denominator IS NULL OR refill_denominator > 0),
    refilled_at timestamptz,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    CHECK (
        hard_maximum IS NULL
        OR (
            used_units <= hard_maximum
            AND reserved_units <= hard_maximum - used_units
        )
    ),
    CHECK (
        (algorithm = 'token_bucket') =
        (available_units IS NOT NULL AND refill_numerator IS NOT NULL AND refill_denominator IS NOT NULL)
        OR algorithm IN ('calendar', 'concurrency')
    ),
    CHECK (updated_at >= created_at),
    UNIQUE (environment_id, metric, scope_type, scope_key, algorithm, window_key),
    UNIQUE (organization_id, application_id, environment_id, quota_bucket_id)
);

CREATE INDEX quota_buckets_scope_idx
    ON quota_buckets (organization_id, application_id, environment_id, scope_type, scope_key, metric);

CREATE TABLE quota_reservations (
    quota_reservation_id text PRIMARY KEY
        CHECK (quota_reservation_id ~ '^qrs_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    logical_request_id text NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128),
    status text NOT NULL CHECK (status IN ('pending', 'settled', 'released', 'expired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    settled_at timestamptz,
    released_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id, logical_request_id)
        REFERENCES logical_requests (organization_id, application_id, environment_id, logical_request_id),
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'pending' AND settled_at IS NULL AND released_at IS NULL)
        OR (status = 'settled' AND settled_at IS NOT NULL AND released_at IS NULL)
        OR (status IN ('released', 'expired') AND settled_at IS NULL AND released_at IS NOT NULL)
    ),
    UNIQUE (environment_id, idempotency_key),
    UNIQUE (organization_id, application_id, environment_id, quota_reservation_id)
);

CREATE INDEX quota_reservations_expiry_idx
    ON quota_reservations (expires_at)
    WHERE status = 'pending';

CREATE TABLE quota_reservation_entries (
    quota_reservation_entry_id text PRIMARY KEY
        CHECK (quota_reservation_entry_id ~ '^qre_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    quota_reservation_id text NOT NULL,
    quota_bucket_id text NOT NULL,
    reserved_units bigint NOT NULL CHECK (reserved_units >= 0),
    settled_units bigint NOT NULL DEFAULT 0 CHECK (settled_units >= 0),
    released_units bigint NOT NULL DEFAULT 0 CHECK (released_units >= 0),
    FOREIGN KEY (organization_id, application_id, environment_id, quota_reservation_id)
        REFERENCES quota_reservations (organization_id, application_id, environment_id, quota_reservation_id),
    FOREIGN KEY (organization_id, application_id, environment_id, quota_bucket_id)
        REFERENCES quota_buckets (organization_id, application_id, environment_id, quota_bucket_id),
    CHECK (settled_units <= reserved_units),
    CHECK (released_units <= reserved_units - settled_units),
    UNIQUE (quota_reservation_id, quota_bucket_id),
    UNIQUE (organization_id, application_id, environment_id, quota_reservation_entry_id)
);

CREATE TABLE concurrency_leases (
    concurrency_lease_id text PRIMARY KEY
        CHECK (concurrency_lease_id ~ '^cls_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    quota_bucket_id text NOT NULL,
    logical_request_id text NOT NULL,
    acquired_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    released_at timestamptz,
    FOREIGN KEY (organization_id, application_id, environment_id, quota_bucket_id)
        REFERENCES quota_buckets (organization_id, application_id, environment_id, quota_bucket_id),
    FOREIGN KEY (organization_id, application_id, environment_id, logical_request_id)
        REFERENCES logical_requests (organization_id, application_id, environment_id, logical_request_id),
    CHECK (expires_at > acquired_at),
    CHECK (released_at IS NULL OR released_at >= acquired_at),
    UNIQUE (quota_bucket_id, logical_request_id),
    UNIQUE (organization_id, application_id, environment_id, concurrency_lease_id)
);

CREATE INDEX concurrency_leases_expiry_idx
    ON concurrency_leases (expires_at)
    WHERE released_at IS NULL;

CREATE TABLE upstream_attempts (
    upstream_attempt_id text PRIMARY KEY
        CHECK (upstream_attempt_id ~ '^atm_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    logical_request_id text NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    route_key text NOT NULL CHECK (char_length(route_key) BETWEEN 1 AND 128),
    upstream_key text NOT NULL CHECK (char_length(upstream_key) BETWEEN 1 AND 128),
    physical_model text CHECK (physical_model IS NULL OR char_length(physical_model) BETWEEN 1 AND 512),
    status text NOT NULL
        CHECK (status IN ('started', 'succeeded', 'failed', 'cancelled', 'timed_out')),
    started_at timestamptz NOT NULL DEFAULT now(),
    first_byte_at timestamptz,
    completed_at timestamptz,
    http_status integer CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    failure_code text CHECK (failure_code IS NULL OR char_length(failure_code) BETWEEN 1 AND 100),
    billed_cost_nano_usd bigint CHECK (billed_cost_nano_usd IS NULL OR billed_cost_nano_usd >= 0),
    currency text CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
    price_revision text CHECK (price_revision IS NULL OR char_length(price_revision) BETWEEN 1 AND 128),
    pricing_source text CHECK (pricing_source IS NULL OR char_length(pricing_source) BETWEEN 1 AND 64),
    cost_confidence text
        CHECK (cost_confidence IS NULL OR cost_confidence IN ('reported', 'calculated', 'estimated', 'reconciled_later', 'unknown')),
    FOREIGN KEY (organization_id, application_id, environment_id, logical_request_id)
        REFERENCES logical_requests (organization_id, application_id, environment_id, logical_request_id),
    CHECK (first_byte_at IS NULL OR first_byte_at >= started_at),
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    UNIQUE (logical_request_id, attempt_number),
    UNIQUE (organization_id, application_id, environment_id, upstream_attempt_id)
);

CREATE INDEX upstream_attempts_request_idx
    ON upstream_attempts (organization_id, application_id, environment_id, logical_request_id, attempt_number);

CREATE TABLE usage_records (
    usage_record_id text PRIMARY KEY
        CHECK (usage_record_id ~ '^usg_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    logical_request_id text NOT NULL,
    upstream_attempt_id text,
    metric text NOT NULL CHECK (metric ~ '^[a-z][a-z0-9_]{1,63}$'),
    units bigint NOT NULL CHECK (units >= 0),
    cost_nano_usd bigint CHECK (cost_nano_usd IS NULL OR cost_nano_usd >= 0),
    currency text CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
    price_revision text CHECK (price_revision IS NULL OR char_length(price_revision) BETWEEN 1 AND 128),
    pricing_source text CHECK (pricing_source IS NULL OR char_length(pricing_source) BETWEEN 1 AND 64),
    confidence text NOT NULL
        CHECK (confidence IN ('reported', 'calculated', 'estimated', 'reconciled_later', 'unknown')),
    provenance_key text NOT NULL CHECK (char_length(provenance_key) BETWEEN 16 AND 128),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id, logical_request_id)
        REFERENCES logical_requests (organization_id, application_id, environment_id, logical_request_id),
    FOREIGN KEY (organization_id, application_id, environment_id, upstream_attempt_id)
        REFERENCES upstream_attempts (organization_id, application_id, environment_id, upstream_attempt_id),
    CHECK (
        (cost_nano_usd IS NULL AND currency IS NULL)
        OR (cost_nano_usd IS NOT NULL AND currency IS NOT NULL)
    ),
    UNIQUE (environment_id, provenance_key),
    UNIQUE (organization_id, application_id, environment_id, usage_record_id)
);

CREATE INDEX usage_records_request_idx
    ON usage_records (organization_id, application_id, environment_id, logical_request_id, recorded_at);

CREATE TABLE usage_rollups_hourly (
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    bucket_start timestamptz NOT NULL,
    dimension_key text NOT NULL CHECK (char_length(dimension_key) BETWEEN 1 AND 512),
    dimensions jsonb NOT NULL CHECK (jsonb_typeof(dimensions) = 'object'),
    metric text NOT NULL CHECK (metric ~ '^[a-z][a-z0-9_]{1,63}$'),
    units bigint NOT NULL CHECK (units >= 0),
    cost_nano_usd bigint NOT NULL DEFAULT 0 CHECK (cost_nano_usd >= 0),
    request_count bigint NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    CHECK (bucket_start = date_trunc('hour', bucket_start)),
    PRIMARY KEY (environment_id, bucket_start, dimension_key, metric)
);

CREATE INDEX usage_rollups_hourly_tenant_idx
    ON usage_rollups_hourly (organization_id, application_id, environment_id, bucket_start DESC);

CREATE TABLE usage_rollups_daily (
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    bucket_date date NOT NULL,
    dimension_key text NOT NULL CHECK (char_length(dimension_key) BETWEEN 1 AND 512),
    dimensions jsonb NOT NULL CHECK (jsonb_typeof(dimensions) = 'object'),
    metric text NOT NULL CHECK (metric ~ '^[a-z][a-z0-9_]{1,63}$'),
    units bigint NOT NULL CHECK (units >= 0),
    cost_nano_usd bigint NOT NULL DEFAULT 0 CHECK (cost_nano_usd >= 0),
    request_count bigint NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    PRIMARY KEY (environment_id, bucket_date, dimension_key, metric)
);

CREATE INDEX usage_rollups_daily_tenant_idx
    ON usage_rollups_daily (organization_id, application_id, environment_id, bucket_date DESC);

CREATE TABLE jobs (
    job_id text PRIMARY KEY
        CHECK (job_id ~ '^job_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text REFERENCES organizations (organization_id),
    environment_id text,
    job_type text NOT NULL
        CHECK (job_type IN (
            'release_expired_reservations',
            'release_expired_concurrency_leases',
            'prune_dpop_replays',
            'prune_challenges',
            'rotate_signing_keys',
            'refresh_jwks',
            'aggregate_hourly_usage',
            'aggregate_daily_usage',
            'enforce_retention',
            'reconcile_pending_usage',
            'run_scheduled_self_test'
        )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'dead')),
    available_at timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    locked_by_instance_id text REFERENCES runtime_instances (instance_id),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    last_error_code text CHECK (last_error_code IS NULL OR char_length(last_error_code) BETWEEN 1 AND 100),
    last_error_detail text CHECK (last_error_detail IS NULL OR char_length(last_error_detail) BETWEEN 1 AND 1000),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, environment_id),
    CHECK ((environment_id IS NULL) OR (organization_id IS NOT NULL)),
    CHECK ((locked_at IS NULL) = (locked_by_instance_id IS NULL)),
    CHECK (updated_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at),
    UNIQUE (job_type, idempotency_key)
);

CREATE INDEX jobs_claim_idx
    ON jobs (available_at, created_at, job_id)
    WHERE status = 'pending';

CREATE TABLE audit_events (
    audit_event_id text PRIMARY KEY
        CHECK (audit_event_id ~ '^aud_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text REFERENCES organizations (organization_id),
    environment_id text,
    actor_kind text NOT NULL
        CHECK (actor_kind IN ('admin_user', 'admin_api_token', 'system')),
    actor_id text,
    action text NOT NULL
        CHECK (action ~ '^[a-z][a-z0-9_.]{1,99}$'),
    resource_type text NOT NULL
        CHECK (resource_type ~ '^[a-z][a-z0-9_.]{1,63}$'),
    resource_id text NOT NULL
        CHECK (resource_id ~ '^[a-z][a-z0-9]{1,15}_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'denied', 'failed')),
    request_id text
        CHECK (request_id IS NULL OR request_id ~ '^arq_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, environment_id),
    CHECK ((environment_id IS NULL) OR (organization_id IS NOT NULL)),
    CHECK (
        (actor_kind = 'system' AND actor_id IS NULL)
        OR (
            actor_kind = 'admin_user'
            AND actor_id ~ '^adm_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'
        )
        OR (
            actor_kind = 'admin_api_token'
            AND actor_id ~ '^tok_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'
        )
    ),
    UNIQUE (organization_id, audit_event_id)
);

CREATE INDEX audit_events_tenant_time_idx
    ON audit_events (organization_id, occurred_at DESC, audit_event_id);

CREATE TABLE audit_event_changes (
    audit_event_id text NOT NULL REFERENCES audit_events (audit_event_id),
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 99),
    field_name text NOT NULL
        CHECK (field_name ~ '^[a-z][a-z0-9_.]{0,63}$'),
    operation text NOT NULL
        CHECK (operation IN ('set', 'clear', 'add', 'remove', 'rotate', 'consume', 'revoke')),
    classification text NOT NULL
        CHECK (classification IN ('public', 'sensitive')),
    CHECK (
        classification = 'sensitive'
        OR field_name !~* '(password|secret|token|credential|authorization|cookie|private_key|ciphertext|nonce|proof|evidence)'
    ),
    PRIMARY KEY (audit_event_id, ordinal)
);
