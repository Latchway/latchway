-- A database COMMIT acknowledgement can be lost after PostgreSQL has applied
-- the transaction. Recording that observation as "failed" would contradict a
-- succeeded audit event committed atomically with the mutation. Preserve the
-- uncertainty explicitly for operator recovery and idempotent retry.
ALTER TABLE audit_events
    DROP CONSTRAINT audit_events_outcome_check,
    ADD CONSTRAINT audit_events_outcome_check
        CHECK (outcome IN ('succeeded', 'denied', 'failed', 'indeterminate'));

COMMENT ON CONSTRAINT audit_events_outcome_check ON audit_events IS
    'Observed administrative outcome; indeterminate means the commit acknowledgement was lost and persisted state must be inspected or retried safely.';
