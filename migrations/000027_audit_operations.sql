-- Audit browsing needs durable operator attribution without weakening the
-- value-free audit-change invariant. Source and reason are deliberately
-- closed, bounded labels; request bodies and arbitrary before/after values do
-- not belong in the audit ledger.
ALTER TABLE audit_events
    ADD COLUMN source text NOT NULL DEFAULT 'api',
    ADD COLUMN reason text;

UPDATE audit_events
SET source = 'system'
WHERE actor_kind = 'system';

-- Schema-27 must remain compatible with established server-owned audit
-- writers that omit the new source column. PostgreSQL, rather than a client
-- claim or a default, owns system attribution.
CREATE FUNCTION normalize_system_audit_source()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.actor_kind = 'system' THEN
        NEW.source = 'system';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_events_normalize_system_source
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION normalize_system_audit_source();

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_source_check
        CHECK (source IN ('console', 'cli', 'api', 'system')),
    ADD CONSTRAINT audit_events_reason_check
        CHECK (
            reason IS NULL
            OR (
                char_length(reason) BETWEEN 1 AND 100
                AND reason ~ '^[a-z][a-z0-9._-]{0,99}$'
                AND replace(reason, '.', '_') !~ '(password|secret|token|credential|authorization|cookie|private_key|ciphertext|proof|evidence)'
            )
        ),
    ADD CONSTRAINT audit_events_system_source_check
        CHECK ((source = 'system') = (actor_kind = 'system')),
    ADD CONSTRAINT audit_events_external_source_check
        CHECK (
            (source <> 'console' OR actor_kind = 'admin_user')
            AND (source <> 'cli' OR actor_kind = 'admin_api_token')
        );

CREATE INDEX audit_events_environment_time_idx
    ON audit_events (organization_id, environment_id, occurred_at DESC, audit_event_id DESC);

CREATE INDEX audit_events_browse_idx
    ON audit_events (
        organization_id, source, outcome, resource_type, action,
        occurred_at DESC, audit_event_id DESC
    );

CREATE INDEX audit_events_actor_time_idx
    ON audit_events (organization_id, actor_id, occurred_at DESC, audit_event_id DESC)
    WHERE actor_id IS NOT NULL;

CREATE INDEX audit_events_resource_time_idx
    ON audit_events (
        organization_id, resource_type, resource_id,
        occurred_at DESC, audit_event_id DESC
    );

COMMENT ON COLUMN audit_events.source IS
    'Bounded descriptive source: Console is derived from authenticated sessions; CLI versus API is an API-token client claim and is never authorization evidence; system is server-owned.';
COMMENT ON COLUMN audit_events.reason IS
    'Optional stable operational reason code. Free-form text and secret-bearing material are prohibited.';
