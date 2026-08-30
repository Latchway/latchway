-- A delegated Apple component may add component-specific App Attest evidence
-- after it has joined an installation family. Challenges remain separate from
-- root session challenges so a component proof can never create or replace a
-- root installation. The component's current DPoP key and immutable
-- configuration revision are authoritative throughout the exchange.

CREATE TABLE component_attestation_challenges (
    component_attestation_challenge_id text PRIMARY KEY
        CHECK (component_attestation_challenge_id ~ '^chl_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    application_user_id text NOT NULL,
    installation_family_id text NOT NULL,
    client_component_id text NOT NULL,
    component_key_id text NOT NULL,
    config_revision_id text NOT NULL,
    platform text NOT NULL
        CHECK (platform IN ('ios', 'react_native_ios', 'watchos')),
    dpop_jkt text NOT NULL CHECK (char_length(dpop_jkt) = 43),
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
    challenge_nonce text NOT NULL
        CHECK (char_length(challenge_nonce) BETWEEN 43 AND 86),
    attestation_policy_id text NOT NULL
        CHECK (attestation_policy_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    attestation_provider text NOT NULL CHECK (attestation_provider = 'app_attest'),
    attestation_mode text NOT NULL CHECK (attestation_mode = 'required'),
    attestation_minimum_trust_level text NOT NULL
        CHECK (attestation_minimum_trust_level = 'app_verified'),
    attestation_maximum_age_milliseconds bigint NOT NULL
        CHECK (attestation_maximum_age_milliseconds BETWEEN 60000 AND 2592000000),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (
        organization_id, application_id, environment_id,
        application_user_id, installation_family_id
    ) REFERENCES installation_families (
        organization_id, application_id, environment_id,
        application_user_id, installation_family_id
    ),
    FOREIGN KEY (
        organization_id, application_id, environment_id, client_component_id
    ) REFERENCES client_components (
        organization_id, application_id, environment_id, client_component_id
    ),
    FOREIGN KEY (client_component_id, component_key_id)
        REFERENCES component_keys (client_component_id, component_key_id),
    FOREIGN KEY (
        organization_id, application_id, environment_id, config_revision_id
    ) REFERENCES config_revisions (
        organization_id, application_id, environment_id, config_revision_id
    ),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    UNIQUE (
        organization_id, application_id, environment_id,
        component_attestation_challenge_id
    )
);

CREATE INDEX component_attestation_challenges_expiry_idx
    ON component_attestation_challenges (expires_at, component_attestation_challenge_id);

-- App Attest keys created for a component bind to that component's current
-- key, not to the root installation DPoP key. Exactly one durable link target
-- is permitted after the pre-session verifier transaction.
ALTER TABLE client_components
    ADD CONSTRAINT client_components_attestation_scope_key UNIQUE (
        organization_id, application_id, environment_id, application_user_id,
        installation_family_id, client_component_id, platform
    );

ALTER TABLE component_keys
    ADD CONSTRAINT component_keys_attestation_scope_key UNIQUE (
        organization_id, application_id, environment_id,
        installation_family_id, client_component_id, component_key_id, dpop_jkt
    );

ALTER TABLE attestation_keys
    ADD COLUMN installation_family_id text,
    ADD COLUMN client_component_id text,
    ADD COLUMN component_key_id text;

ALTER TABLE attestation_keys
    DROP CONSTRAINT attestation_keys_platform_check,
    ADD CONSTRAINT attestation_keys_platform_check CHECK (
        platform IN (
            'ios', 'android', 'web', 'node',
            'react_native_ios', 'react_native_android', 'watchos'
        )
    ),
    DROP CONSTRAINT attestation_keys_link_state_check,
    ADD CONSTRAINT attestation_keys_link_state_check CHECK (
        (
            linked_at IS NULL
            AND installation_id IS NULL
            AND installation_family_id IS NULL
            AND client_component_id IS NULL
            AND component_key_id IS NULL
        )
        OR
        (
            linked_at IS NOT NULL
            AND (
                (
                    installation_id IS NOT NULL
                    AND installation_family_id IS NULL
                    AND client_component_id IS NULL
                    AND component_key_id IS NULL
                )
                OR
                (
                    installation_id IS NULL
                    AND installation_family_id IS NOT NULL
                    AND client_component_id IS NOT NULL
                    AND component_key_id IS NOT NULL
                )
            )
        )
    ),
    DROP CONSTRAINT attestation_keys_app_attest_state_check,
    ADD CONSTRAINT attestation_keys_app_attest_state_check CHECK (
        provider <> 'app_attest'
        OR status <> 'active'
        OR (
            provider_key_id IS NOT NULL
            AND provider_key_id ~ '^[A-Za-z0-9+/]{43}=$'
            AND provider_key_hash IS NOT NULL
            AND octet_length(provider_key_hash) = 32
            AND provider_key_hash <> decode(repeat('00', 32), 'hex')
            AND public_key IS NOT NULL
            AND octet_length(public_key) = 65
            AND get_byte(public_key, 0) = 4
            AND app_id_hash IS NOT NULL
            AND octet_length(app_id_hash) = 32
            AND app_id_hash <> decode(repeat('00', 32), 'hex')
            AND platform IN ('ios', 'react_native_ios', 'watchos')
            AND dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'
            AND sign_count BETWEEN 0 AND 4294967295
            AND (
                (sign_count = 0 AND last_assertion_hash IS NULL)
                OR (
                    sign_count > 0
                    AND last_assertion_hash IS NOT NULL
                    AND octet_length(last_assertion_hash) = 32
                    AND last_assertion_hash <> decode(repeat('00', 32), 'hex')
                )
            )
            AND attested_at_unix_seconds IS NOT NULL
            AND attested_at_unix_seconds BETWEEN -62135596800 AND 253370764799
            AND attested_at_nanosecond IS NOT NULL
            AND attested_at_nanosecond BETWEEN 0 AND 999999999
            AND extensions_present IS NOT NULL
            AND (
                (
                    extensions_present = false
                    AND validation_category IS NULL
                    AND bundle_version IS NULL
                )
                OR (
                    extensions_present = true
                    AND validation_category IS NOT NULL
                    AND validation_category IN (1, 2, 3, 4, 5, 6, 10)
                    AND bundle_version IS NOT NULL
                    AND char_length(bundle_version) BETWEEN 1 AND 128
                    AND bundle_version ~ '^[A-Za-z0-9]([A-Za-z0-9.-]{0,126}[A-Za-z0-9])?$'
                    AND position('..' IN bundle_version) = 0
                )
            )
        )
    ),
    ADD CONSTRAINT attestation_keys_component_scope_fkey FOREIGN KEY (
        organization_id, application_id, environment_id, application_user_id,
        installation_family_id, client_component_id, platform
    ) REFERENCES client_components (
        organization_id, application_id, environment_id, application_user_id,
        installation_family_id, client_component_id, platform
    ),
    ADD CONSTRAINT attestation_keys_component_key_scope_fkey FOREIGN KEY (
        organization_id, application_id, environment_id,
        installation_family_id, client_component_id, component_key_id, dpop_jkt
    ) REFERENCES component_keys (
        organization_id, application_id, environment_id,
        installation_family_id, client_component_id, component_key_id, dpop_jkt
    );

DROP INDEX attestation_keys_unlinked_app_attest_idx;
CREATE INDEX attestation_keys_unlinked_app_attest_idx
    ON attestation_keys (
        organization_id, application_id, environment_id,
        application_user_id, created_at
    )
    WHERE provider = 'app_attest' AND linked_at IS NULL AND status = 'active';

CREATE OR REPLACE FUNCTION enforce_attestation_key_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.attestation_key_id IS DISTINCT FROM OLD.attestation_key_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.application_id IS DISTINCT FROM OLD.application_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.application_user_id IS DISTINCT FROM OLD.application_user_id
       OR NEW.binding_environment IS DISTINCT FROM OLD.binding_environment
       OR NEW.platform IS DISTINCT FROM OLD.platform
       OR NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt
       OR NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.provider_key_id IS DISTINCT FROM OLD.provider_key_id
       OR NEW.provider_key_hash IS DISTINCT FROM OLD.provider_key_hash
       OR NEW.public_key IS DISTINCT FROM OLD.public_key
       OR NEW.app_id_hash IS DISTINCT FROM OLD.app_id_hash
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.attested_at_unix_seconds IS DISTINCT FROM OLD.attested_at_unix_seconds
       OR NEW.attested_at_nanosecond IS DISTINCT FROM OLD.attested_at_nanosecond
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'attestation key identity and scope are immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_immutable_scope_check';
    END IF;
    IF OLD.linked_at IS NOT NULL AND (
        NEW.installation_id IS DISTINCT FROM OLD.installation_id
        OR NEW.installation_family_id IS DISTINCT FROM OLD.installation_family_id
        OR NEW.client_component_id IS DISTINCT FROM OLD.client_component_id
        OR NEW.component_key_id IS DISTINCT FROM OLD.component_key_id
        OR NEW.linked_at IS DISTINCT FROM OLD.linked_at
    ) THEN
        RAISE EXCEPTION 'attestation key durable link is immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_immutable_link_check';
    END IF;
    IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'revoked attestation key cannot be reactivated'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_terminal_status_check';
    END IF;
    IF OLD.status = 'invalid' AND NEW.status = 'active' THEN
        RAISE EXCEPTION 'invalid attestation key cannot be reactivated'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_terminal_status_check';
    END IF;
    IF OLD.provider = 'app_attest' AND NEW.sign_count < OLD.sign_count THEN
        RAISE EXCEPTION 'App Attest assertion counter cannot decrease'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_app_attest_counter_monotonic_check';
    END IF;
    IF OLD.provider = 'app_attest' AND NEW.sign_count = OLD.sign_count AND (
        NEW.last_assertion_hash IS DISTINCT FROM OLD.last_assertion_hash
        OR NEW.extensions_present IS DISTINCT FROM OLD.extensions_present
        OR NEW.validation_category IS DISTINCT FROM OLD.validation_category
        OR NEW.bundle_version IS DISTINCT FROM OLD.bundle_version
    ) THEN
        RAISE EXCEPTION 'App Attest same-counter assertion state is immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_app_attest_same_counter_state_check';
    END IF;
    IF OLD.provider = 'app_attest' AND NEW.sign_count > OLD.sign_count
       AND NEW.last_assertion_hash IS NOT DISTINCT FROM OLD.last_assertion_hash THEN
        RAISE EXCEPTION 'App Attest counter advance requires a new assertion digest'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_app_attest_counter_hash_check';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'attestation key update time cannot decrease'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_updated_at_monotonic_check';
    END IF;
    RETURN NEW;
END;
$$;

-- Preserve both sides of the trust proof. This source is delegated family
-- membership plus component-specific direct evidence; it is neither a root
-- direct-attestation source nor a relabelled delegation.
ALTER TABLE client_components
    DROP CONSTRAINT client_components_trust_source_check,
    ADD CONSTRAINT client_components_trust_source_check CHECK (trust_source IN (
        'direct_attested', 'delegated_from_attested_root',
        'delegated_identity_only', 'delegated_direct_attested',
        'identity_only', 'web_risk_verified', 'debug'
    ));

ALTER TABLE session_grants
    ADD CONSTRAINT session_grants_trust_source_check CHECK (
        trust_source IS NULL OR trust_source IN (
            'direct_attested', 'delegated_from_attested_root',
            'delegated_identity_only', 'delegated_direct_attested',
            'identity_only', 'web_risk_verified', 'debug'
        )
    );
