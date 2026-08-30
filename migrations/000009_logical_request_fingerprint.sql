-- Bind every newly recorded logical request, including quota denials that do
-- not have a reservation row, to the complete trusted request and decision.
-- Existing rows remain nullable because their original decision cannot be
-- reconstructed safely; application replay handling fails closed for NULL.
ALTER TABLE logical_requests
    ADD COLUMN trusted_decision_fingerprint text,
    ADD CONSTRAINT logical_requests_trusted_decision_fingerprint_check
        CHECK (
            trusted_decision_fingerprint IS NULL
            OR trusted_decision_fingerprint ~ '^[A-Za-z0-9_-]{43}$'
        ) NOT VALID;

COMMENT ON COLUMN logical_requests.trusted_decision_fingerprint IS
    'Unpadded base64url SHA-256 of the canonical server-trusted request and resolved quota/routing decision. NULL is reserved for rows created before schema version 9 and cannot authorize a replay.';

-- PostgreSQL enforces a NOT VALID CHECK for every new or updated row while
-- avoiding an initial table scan under the ALTER TABLE lock. Validation is a
-- separate operational phase so it can be scheduled independently.
