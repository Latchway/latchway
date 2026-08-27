-- Version 5 challenges predate immutable policy and challenge-request DPoP
-- bindings. They cannot be upgraded without inventing security metadata, so
-- invalidate the ephemeral rows before making the version 6 fields mandatory.
-- Accepted attestation events remain in their durable audit table because the
-- version 5 migration removed its challenge foreign key.
DELETE FROM session_challenge_consumptions;
DELETE FROM session_challenges;

ALTER TABLE session_challenges
    ADD COLUMN config_revision_id text NOT NULL
        CHECK (config_revision_id ~ '^rev_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$'),
    ADD COLUMN attestation_policy_id text NOT NULL
        CHECK (
            attestation_policy_id = lower(attestation_policy_id)
            AND attestation_policy_id ~ '^[a-z][a-z0-9_-]{0,62}$'
        ),
    ADD COLUMN attestation_provider text NOT NULL
        CHECK (attestation_provider IN (
            'app_attest',
            'play_integrity',
            'firebase_app_check',
            'turnstile',
            'debug'
        )),
    ADD COLUMN attestation_mode text NOT NULL
        CHECK (attestation_mode IN ('required', 'preferred')),
    ADD COLUMN attestation_minimum_trust_level text NOT NULL
        CHECK (attestation_minimum_trust_level IN (
            'none',
            'identity_only',
            'web_risk_verified',
            'app_verified',
            'device_verified',
            'strong_device_verified',
            'debug'
        )),
    ADD COLUMN attestation_maximum_age_milliseconds bigint NOT NULL
        CHECK (
            attestation_maximum_age_milliseconds BETWEEN 60000 AND 2592000000
        ),
    ADD COLUMN challenge_dpop_proof_jti_hash bytea NOT NULL
        CHECK (octet_length(challenge_dpop_proof_jti_hash) = 32),
    ADD COLUMN challenge_dpop_http_method text NOT NULL
        CHECK (challenge_dpop_http_method ~ '^[A-Z]{3,10}$'),
    ADD COLUMN challenge_dpop_http_uri_hash bytea NOT NULL
        CHECK (octet_length(challenge_dpop_http_uri_hash) = 32),
    ADD CONSTRAINT session_challenges_config_revision_fkey
        FOREIGN KEY (
            organization_id,
            application_id,
            environment_id,
            config_revision_id
        ) REFERENCES config_revisions (
            organization_id,
            application_id,
            environment_id,
            config_revision_id
        ),
    ADD CONSTRAINT session_challenges_dpop_proof_unique
        UNIQUE (
            environment_id,
            dpop_jkt,
            challenge_dpop_proof_jti_hash
        );

COMMENT ON COLUMN session_challenges.config_revision_id IS
    'Exact immutable active configuration revision used to issue the challenge.';

COMMENT ON COLUMN session_challenges.challenge_dpop_proof_jti_hash IS
    'SHA-256 digest of the validated challenge-request DPoP jti; raw jti values are never persisted.';

COMMENT ON COLUMN session_challenges.challenge_dpop_http_uri_hash IS
    'SHA-256 digest of the normalized challenge-request URI; raw request URIs are never persisted.';

-- The locked session-exchange wire request has no key-storage assertion. Use
-- an explicitly conservative internal value until a verified native signal is
-- available; never manufacture a software or hardware-backed classification.
DO $$
DECLARE
    constraint_record record;
BEGIN
    FOR constraint_record IN
        SELECT constraint_entry.conname
          FROM pg_constraint AS constraint_entry
          JOIN pg_attribute AS attribute_entry
            ON attribute_entry.attrelid = constraint_entry.conrelid
           AND attribute_entry.attnum = constraint_entry.conkey[1]
         WHERE constraint_entry.conrelid = 'installations'::regclass
           AND constraint_entry.contype = 'c'
           AND cardinality(constraint_entry.conkey) = 1
           AND attribute_entry.attname = 'key_storage'
    LOOP
        EXECUTE format(
            'ALTER TABLE installations DROP CONSTRAINT %I',
            constraint_record.conname
        );
    END LOOP;
END
$$;

ALTER TABLE installations
    ADD CONSTRAINT installations_key_storage_check
        CHECK (key_storage IN (
            'unknown',
            'secure_enclave',
            'keychain',
            'strongbox',
            'tee',
            'software',
            'webcrypto',
            'memory'
        ));

-- The locked client contract permits application versions up to 128
-- characters. Replace the version 2 inline length check without depending on
-- PostgreSQL's generated constraint name.
DO $$
DECLARE
    constraint_record record;
BEGIN
    FOR constraint_record IN
        SELECT constraint_entry.conname
          FROM pg_constraint AS constraint_entry
          JOIN pg_attribute AS attribute_entry
            ON attribute_entry.attrelid = constraint_entry.conrelid
           AND attribute_entry.attnum = constraint_entry.conkey[1]
         WHERE constraint_entry.conrelid = 'installations'::regclass
           AND constraint_entry.contype = 'c'
           AND cardinality(constraint_entry.conkey) = 1
           AND attribute_entry.attname = 'app_version'
    LOOP
        EXECUTE format(
            'ALTER TABLE installations DROP CONSTRAINT %I',
            constraint_record.conname
        );
    END LOOP;
END
$$;

ALTER TABLE installations
    ADD CONSTRAINT installations_app_version_length_check
        CHECK (
            app_version IS NULL
            OR char_length(app_version) BETWEEN 1 AND 128
        );
