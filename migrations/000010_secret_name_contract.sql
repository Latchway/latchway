-- Align persisted secret names with the canonical Identifier/SecretRef
-- contract. The original foundation accidentally required at least two
-- characters and admitted dot, slash, and overlong names that no public
-- configuration can address.
--
-- Fail the transactional migration if a pre-v1 row uses a name that cannot be
-- addressed by the public API. An operator must rename or remove that row
-- under the prior constraint before retrying; schema readiness must never hide
-- an encrypted orphan that the runtime cannot manage.
ALTER TABLE secret_records
    DROP CONSTRAINT secret_records_name_check,
    ADD CONSTRAINT secret_records_name_check
        CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$');

COMMENT ON CONSTRAINT secret_records_name_check ON secret_records IS
    'Validated canonical one-to-63-character Latchway Identifier used by secret/<name> references.';
