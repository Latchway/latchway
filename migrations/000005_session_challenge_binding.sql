-- The public nonce is part of the canonical attestation binding. Retaining it
-- allows every gateway replica to reconstruct the authoritative binding after
-- restart; the existing digest remains useful for integrity comparison.
ALTER TABLE session_challenges
    ADD COLUMN challenge_nonce text
        CHECK (
            challenge_nonce IS NULL
            OR challenge_nonce ~ '^[A-Za-z0-9_-]{43,86}$'
        ),
    ADD COLUMN identity_verified_at timestamptz,
    ADD COLUMN identity_expires_at timestamptz,
    ADD CONSTRAINT session_challenges_identity_window_check
        CHECK (
            (identity_verified_at IS NULL AND identity_expires_at IS NULL)
            OR identity_expires_at > identity_verified_at
        );

COMMENT ON COLUMN session_challenges.challenge_nonce IS
    'Public random nonce returned with the challenge; never an identity or bearer credential.';

COMMENT ON COLUMN session_challenges.identity_expires_at IS
    'Expiry of the already-verified external identity credential; the credential itself is never persisted.';

ALTER TABLE session_grants
    ADD COLUMN identity_provider_key text
        CHECK (
            identity_provider_key IS NULL
            OR (
                identity_provider_key = lower(identity_provider_key)
                AND identity_provider_key ~ '^[a-z][a-z0-9_-]{1,63}$'
            )
        ),
    ADD COLUMN identity_expires_at timestamptz,
    ADD COLUMN attestation_provider text
        CHECK (
            attestation_provider IS NULL
            OR attestation_provider IN ('app_attest', 'play_integrity', 'firebase_app_check', 'turnstile', 'debug')
        ),
    ADD COLUMN attestation_expires_at timestamptz;

-- Version 4 grants do not contain the identity-provider and proof-expiry data
-- required to authorize a version 5 session. Revoke every still-live legacy
-- credential rather than manufacturing trust metadata. The old attested_at
-- value cannot form a complete version 5 attestation record, so clear it while
-- leaving the durable attestation_events audit trail intact.
UPDATE refresh_tokens AS refresh_token
   SET status = 'revoked',
       revoked_at = GREATEST(
           COALESCE(refresh_token.revoked_at, CURRENT_TIMESTAMP),
           refresh_token.issued_at
       )
  FROM session_grants AS session_grant
 WHERE refresh_token.organization_id = session_grant.organization_id
   AND refresh_token.application_id = session_grant.application_id
   AND refresh_token.environment_id = session_grant.environment_id
   AND refresh_token.session_grant_id = session_grant.session_grant_id
   AND refresh_token.status IN ('staged', 'active');

UPDATE session_grants
   SET revoked_at = GREATEST(
           COALESCE(revoked_at, CURRENT_TIMESTAMP),
           issued_at
       ),
       revoke_reason = COALESCE(revoke_reason, 'schema_upgrade_v5'),
       attested_at = NULL;

ALTER TABLE session_grants
    ADD CONSTRAINT session_grants_identity_expiry_check
        CHECK (identity_expires_at IS NULL OR identity_expires_at > identity_verified_at),
    ADD CONSTRAINT session_grants_attestation_expiry_check
        CHECK (
            (attested_at IS NULL AND attestation_provider IS NULL AND attestation_expires_at IS NULL)
            OR (
                attested_at IS NOT NULL
                AND attestation_provider IS NOT NULL
                AND attestation_expires_at > attested_at
            )
        );

COMMENT ON COLUMN session_grants.identity_expires_at IS
    'Expiry of the external identity proof used for this grant; no raw identity credential is stored.';

COMMENT ON COLUMN session_grants.identity_provider_key IS
    'Configured identity provider used for this grant; never a raw external subject or credential.';

-- Replay protection must remain stable across refresh-token rotation, which
-- creates a new grant for the same installation. Backfill the installation
-- scope from the version 4 grant relation before making it mandatory.
ALTER TABLE dpop_replay_entries
    ADD COLUMN installation_id text;

UPDATE dpop_replay_entries AS replay
   SET installation_id = session_grant.installation_id
  FROM session_grants AS session_grant
 WHERE replay.organization_id = session_grant.organization_id
   AND replay.application_id = session_grant.application_id
   AND replay.environment_id = session_grant.environment_id
   AND replay.session_grant_id = session_grant.session_grant_id;

ALTER TABLE dpop_replay_entries
    ALTER COLUMN installation_id SET NOT NULL,
    ADD CONSTRAINT dpop_replay_entries_installation_fkey
        FOREIGN KEY (
            organization_id,
            application_id,
            environment_id,
            installation_id
        ) REFERENCES installations (
            organization_id,
            application_id,
            environment_id,
            installation_id
        );

-- A version 4 database could contain the same proof identifier under grants
-- produced by successive rotations. Keep the row with the longest remaining
-- replay window so the upgrade fails closed, then enforce installation scope.
WITH ranked_replays AS (
    SELECT
        dpop_replay_entry_id,
        row_number() OVER (
            PARTITION BY installation_id, proof_jti_hash
            ORDER BY expires_at DESC, observed_at, dpop_replay_entry_id
        ) AS replay_rank
    FROM dpop_replay_entries
)
DELETE FROM dpop_replay_entries AS replay
USING ranked_replays AS ranked
WHERE replay.dpop_replay_entry_id = ranked.dpop_replay_entry_id
  AND ranked.replay_rank > 1;

ALTER TABLE dpop_replay_entries
    DROP CONSTRAINT dpop_replay_entries_session_grant_id_proof_jti_hash_key,
    ADD CONSTRAINT dpop_replay_entries_installation_proof_jti_key
        UNIQUE (installation_id, proof_jti_hash);

CREATE INDEX dpop_replay_entries_grant_idx
    ON dpop_replay_entries (session_grant_id, observed_at);

-- Attestation events are durable audit records while challenges are ephemeral.
-- Preserve the challenge identifier as immutable audit text, but do not let an
-- audit row prevent bounded challenge retention and cleanup.
DO $$
DECLARE
    constraint_record record;
BEGIN
    FOR constraint_record IN
        SELECT constraint_entry.conname
          FROM pg_constraint AS constraint_entry
         WHERE constraint_entry.conrelid = 'attestation_events'::regclass
           AND constraint_entry.confrelid = 'session_challenges'::regclass
           AND constraint_entry.contype = 'f'
    LOOP
        EXECUTE format(
            'ALTER TABLE attestation_events DROP CONSTRAINT %I',
            constraint_record.conname
        );
    END LOOP;
END
$$;

COMMENT ON COLUMN attestation_events.session_challenge_id IS
    'Immutable audit correlation ID. Challenges may be removed after their retention window.';
