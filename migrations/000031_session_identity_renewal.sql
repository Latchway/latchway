-- A same-account identity revalidation may occur after credential issuance.
-- Keep issued_at, access expiry and attestation immutable: only replace the
-- historical issuance-only check with the verified identity expiry bound.
DO $$
DECLARE
    issuance_constraint text;
BEGIN
    SELECT conname INTO STRICT issuance_constraint
    FROM pg_constraint
    WHERE conrelid = 'session_grants'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) = 'CHECK ((identity_verified_at <= issued_at))';

    EXECUTE format('ALTER TABLE session_grants DROP CONSTRAINT %I', issuance_constraint);
END
$$;

ALTER TABLE session_grants
    ADD CONSTRAINT session_grants_identity_freshness_valid
    CHECK (
        (identity_expires_at IS NULL AND identity_verified_at <= issued_at)
        OR (identity_expires_at IS NOT NULL AND identity_expires_at > identity_verified_at)
    );

COMMENT ON COLUMN session_grants.identity_verified_at IS
    'Most recent same-account identity verification; may follow original credential issuance. Does not extend access, refresh, attestation, or quota lifetime.';
