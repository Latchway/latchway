-- Identity-provider identifiers are locked to 1-63 lowercase characters.
-- Earlier checks used a 2-64-character expression (and challenges only
-- enforced lowercase), so align every persisted copy without rewriting or
-- truncating security-relevant identifiers.
DO $$
DECLARE
    invalid_identifier_count bigint;
BEGIN
    SELECT
        (SELECT count(*)
           FROM identity_provider_states
          WHERE provider_key !~ '^[a-z][a-z0-9_-]{0,62}$')
        + (SELECT count(*)
             FROM external_identities
            WHERE provider_key !~ '^[a-z][a-z0-9_-]{0,62}$')
        + (SELECT count(*)
             FROM session_challenges
            WHERE identity_provider_key !~ '^[a-z][a-z0-9_-]{0,62}$')
        + (SELECT count(*)
             FROM session_grants
            WHERE identity_provider_key IS NOT NULL
              AND identity_provider_key !~ '^[a-z][a-z0-9_-]{0,62}$')
      INTO invalid_identifier_count;

    IF invalid_identifier_count > 0 THEN
        RAISE EXCEPTION
            'cannot align identity-provider identifier bounds: % persisted row(s) are outside the locked 1-63 character format',
            invalid_identifier_count
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- These names were generated deterministically by the original CREATE TABLE
-- and ADD COLUMN statements. Dropping them explicitly makes a schema drift
-- fail closed instead of accidentally removing an unrelated custom check.
ALTER TABLE identity_provider_states
    DROP CONSTRAINT identity_provider_states_provider_key_check,
    ADD CONSTRAINT identity_provider_states_provider_key_identifier_check
        CHECK (
            provider_key = lower(provider_key)
            AND provider_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        );

ALTER TABLE external_identities
    DROP CONSTRAINT external_identities_provider_key_check,
    ADD CONSTRAINT external_identities_provider_key_identifier_check
        CHECK (
            provider_key = lower(provider_key)
            AND provider_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        );

ALTER TABLE session_challenges
    DROP CONSTRAINT session_challenges_identity_provider_key_check,
    ADD CONSTRAINT session_challenges_identity_provider_key_identifier_check
        CHECK (
            identity_provider_key = lower(identity_provider_key)
            AND identity_provider_key ~ '^[a-z][a-z0-9_-]{0,62}$'
        );

ALTER TABLE session_grants
    DROP CONSTRAINT session_grants_identity_provider_key_check,
    ADD CONSTRAINT session_grants_identity_provider_key_identifier_check
        CHECK (
            identity_provider_key IS NULL
            OR (
                identity_provider_key = lower(identity_provider_key)
                AND identity_provider_key ~ '^[a-z][a-z0-9_-]{0,62}$'
            )
        );
