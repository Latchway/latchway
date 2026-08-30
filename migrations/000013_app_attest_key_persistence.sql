-- App Attest keys are registered while the session challenge still precedes
-- installation creation. Preserve the generic attestation_keys lifecycle, but
-- allow a verified key to exist without an installation until session exchange
-- links it to the exact principal, DPoP key, and platform.

ALTER TABLE attestation_keys
    ADD COLUMN application_user_id text,
    ADD COLUMN binding_environment text,
    ADD COLUMN platform text,
    ADD COLUMN dpop_jkt text,
    ADD COLUMN provider_key_hash bytea,
    ADD COLUMN app_id_hash bytea,
	ADD COLUMN last_assertion_hash bytea,
    ADD COLUMN extensions_present boolean,
    ADD COLUMN validation_category bigint,
    ADD COLUMN bundle_version text,
    ADD COLUMN attested_at_unix_seconds bigint,
    ADD COLUMN attested_at_nanosecond integer,
    ADD COLUMN linked_at timestamptz;

-- Every pre-v13 key necessarily had an installation. Backfill its authoritative
-- scope before installation_id becomes optional. The environment slug is part
-- of the signed App Attest binding and is intentionally retained separately
-- from the opaque environment resource identifier.
UPDATE attestation_keys AS attestation_key
   SET application_user_id = installation.application_user_id,
       binding_environment = environment.slug,
       platform = installation.platform,
       dpop_jkt = installation.dpop_jkt,
       linked_at = attestation_key.created_at
  FROM installations AS installation
  JOIN environments AS environment
    ON environment.organization_id = installation.organization_id
   AND environment.application_id = installation.application_id
   AND environment.environment_id = installation.environment_id
 WHERE installation.organization_id = attestation_key.organization_id
   AND installation.application_id = attestation_key.application_id
   AND installation.environment_id = attestation_key.environment_id
   AND installation.installation_id = attestation_key.installation_id;

ALTER TABLE attestation_keys
    ALTER COLUMN application_user_id SET NOT NULL,
    ALTER COLUMN binding_environment SET NOT NULL,
    ALTER COLUMN platform SET NOT NULL,
    ALTER COLUMN dpop_jkt SET NOT NULL,
    ALTER COLUMN installation_id DROP NOT NULL;

-- A legacy App Attest row did not contain enough durable material to validate
-- an assertion. Retain it for audit/revocation correlation, but fail it closed
-- instead of pretending that missing key state is usable.
UPDATE attestation_keys
   SET status = 'invalid',
       updated_at = GREATEST(updated_at, transaction_timestamp())
 WHERE provider = 'app_attest'
   AND status = 'active';

ALTER TABLE attestation_keys
    ADD CONSTRAINT attestation_keys_environment_scope_fkey
        FOREIGN KEY (organization_id, application_id, environment_id)
        REFERENCES environments (organization_id, application_id, environment_id),
    ADD CONSTRAINT attestation_keys_principal_scope_fkey
        FOREIGN KEY (organization_id, application_id, application_user_id)
        REFERENCES application_users (organization_id, application_id, application_user_id),
    ADD CONSTRAINT attestation_keys_platform_check
        CHECK (platform IN ('ios', 'android', 'web', 'node', 'react_native_ios', 'react_native_android')),
    ADD CONSTRAINT attestation_keys_pre_session_provider_check
        CHECK (provider = 'app_attest' OR installation_id IS NOT NULL),
	ADD CONSTRAINT attestation_keys_app_attest_retry_hash_provider_check
		CHECK (provider = 'app_attest' OR last_assertion_hash IS NULL),
    ADD CONSTRAINT attestation_keys_link_state_check
        CHECK ((installation_id IS NULL) = (linked_at IS NULL)),
    ADD CONSTRAINT attestation_keys_link_time_check
        CHECK (linked_at IS NULL OR linked_at >= created_at),
    ADD CONSTRAINT attestation_keys_revocation_time_check
        CHECK (revoked_at IS NULL OR revoked_at >= created_at);

ALTER TABLE environments
    ADD CONSTRAINT environments_attestation_binding_key
        UNIQUE (organization_id, application_id, environment_id, slug);

ALTER TABLE attestation_keys
    ADD CONSTRAINT attestation_keys_binding_environment_fkey
        FOREIGN KEY (organization_id, application_id, environment_id, binding_environment)
        REFERENCES environments (organization_id, application_id, environment_id, slug);

-- PostgreSQL requires a referenced UNIQUE key even though installation_id is
-- already globally unique. This composite key lets the optional link prove the
-- full immutable attestation scope rather than tenant ownership alone.
ALTER TABLE installations
    ADD CONSTRAINT installations_attestation_scope_key
        UNIQUE (
            organization_id,
            application_id,
            environment_id,
            application_user_id,
            installation_id,
            dpop_jkt,
            platform
        );

ALTER TABLE attestation_keys
    ADD CONSTRAINT attestation_keys_installation_scope_fkey
        FOREIGN KEY (
            organization_id,
            application_id,
            environment_id,
            application_user_id,
            installation_id,
            dpop_jkt,
            platform
        ) REFERENCES installations (
            organization_id,
            application_id,
            environment_id,
            application_user_id,
            installation_id,
            dpop_jkt,
            platform
        ),
    ADD CONSTRAINT attestation_keys_app_attest_state_check
        CHECK (
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
                AND platform IN ('ios', 'react_native_ios')
                AND dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'
                AND sign_count BETWEEN 0 AND 4294967295
				AND (
					(
						sign_count = 0
						AND last_assertion_hash IS NULL
					)
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
        );

-- The verifier transaction interface looks up assertions by the 32-byte Apple
-- credential identifier before it has any caller-selected tenant scope. Make
-- that identifier globally unambiguous for App Attest and reject a cryptographic
-- collision rather than selecting an arbitrary tenant row.
CREATE UNIQUE INDEX attestation_keys_app_attest_provider_key_hash_idx
    ON attestation_keys (provider, provider_key_hash)
    WHERE provider = 'app_attest' AND provider_key_hash IS NOT NULL;

CREATE INDEX attestation_keys_unlinked_app_attest_idx
    ON attestation_keys (organization_id, application_id, environment_id, application_user_id, created_at)
    WHERE provider = 'app_attest' AND installation_id IS NULL AND status = 'active';

CREATE INDEX attestation_keys_unlinked_app_attest_cleanup_idx
    ON attestation_keys (created_at, attestation_key_id)
    WHERE provider = 'app_attest'
      AND installation_id IS NULL
      AND linked_at IS NULL
      AND status = 'active';

-- A short-lived receipt lets the store resolve a COMMIT acknowledgement lost
-- to cancellation or a transport failure without repeating the verifier
-- callback. The normal success path deletes its receipt immediately; expiry is
-- retained for crash cleanup and future retention jobs.
CREATE TABLE app_attest_key_commit_receipts (
    commit_token bytea PRIMARY KEY,
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    attestation_key_id text NOT NULL,
    sign_count bigint NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT (transaction_timestamp() + interval '1 day'),
    CONSTRAINT app_attest_key_commit_receipts_token_check
        CHECK (
            octet_length(commit_token) = 32
            AND commit_token <> decode(repeat('00', 32), 'hex')
        ),
    CONSTRAINT app_attest_key_commit_receipts_sign_count_check
        CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT app_attest_key_commit_receipts_key_scope_fkey
        FOREIGN KEY (organization_id, application_id, environment_id, attestation_key_id)
        REFERENCES attestation_keys (
            organization_id,
            application_id,
            environment_id,
            attestation_key_id
        ) ON DELETE CASCADE,
    CONSTRAINT app_attest_key_commit_receipts_expiry_check
        CHECK (expires_at > committed_at)
);

CREATE INDEX app_attest_key_commit_receipts_expiry_idx
    ON app_attest_key_commit_receipts (expires_at, commit_token);

CREATE INDEX app_attest_key_commit_receipts_key_scope_idx
    ON app_attest_key_commit_receipts (
        organization_id,
        application_id,
        environment_id,
        attestation_key_id
    );

-- Key identity and tenant binding are append-only. Assertions may advance the
-- counter and Apple extension snapshot, session exchange may link the first
-- installation once, and revocation may terminalize the key. Direct SQL must
-- not turn a retained invalid/revoked key back into an active credential or
-- lower its replay counter.
CREATE FUNCTION enforce_attestation_key_lifecycle()
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

    IF OLD.installation_id IS NOT NULL
       AND NEW.installation_id IS DISTINCT FROM OLD.installation_id THEN
        RAISE EXCEPTION 'attestation key installation link is immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_immutable_link_check';
    END IF;
    IF OLD.linked_at IS NOT NULL AND NEW.linked_at IS DISTINCT FROM OLD.linked_at THEN
        RAISE EXCEPTION 'attestation key link timestamp is immutable'
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
	IF OLD.provider = 'app_attest'
	   AND NEW.sign_count = OLD.sign_count
	   AND (
		   NEW.last_assertion_hash IS DISTINCT FROM OLD.last_assertion_hash
		   OR NEW.extensions_present IS DISTINCT FROM OLD.extensions_present
		   OR NEW.validation_category IS DISTINCT FROM OLD.validation_category
		   OR NEW.bundle_version IS DISTINCT FROM OLD.bundle_version
	   ) THEN
		RAISE EXCEPTION 'App Attest same-counter assertion state is immutable'
			USING ERRCODE = '23514', CONSTRAINT = 'attestation_keys_app_attest_same_counter_state_check';
	END IF;
	IF OLD.provider = 'app_attest'
	   AND NEW.sign_count > OLD.sign_count
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

CREATE TRIGGER attestation_keys_lifecycle_guard
BEFORE UPDATE ON attestation_keys
FOR EACH ROW
EXECUTE FUNCTION enforce_attestation_key_lifecycle();
