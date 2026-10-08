-- Draft lifecycle (ADR 0048): a never-activated draft stays editable after
-- validation, can be discarded as a tombstone, records who changed which
-- paths, and an activation can carry a publish note. Activated revisions keep
-- every existing immutability guarantee.

ALTER TABLE config_revisions
    DROP CONSTRAINT config_revisions_status_check,
    ADD CONSTRAINT config_revisions_status_check
        CHECK (status IN ('draft', 'valid', 'invalid', 'discarded')),
    ADD COLUMN discarded_at timestamptz,
    ADD COLUMN discarded_by_admin_user_id text,
    ADD COLUMN activation_note text
        CHECK (activation_note IS NULL OR char_length(activation_note) BETWEEN 1 AND 500),
    ADD CONSTRAINT config_revisions_discard_check
        CHECK (
            (status = 'discarded') = (discarded_at IS NOT NULL)
            AND (discarded_at IS NULL) = (discarded_by_admin_user_id IS NULL)
            AND (
                status <> 'discarded'
                OR (activated_at IS NULL AND compiled_document IS NULL AND validated_at IS NULL)
            )
        ),
    ADD CONSTRAINT config_revisions_activation_note_activated_check
        CHECK (activation_note IS NULL OR activated_at IS NOT NULL),
    ADD CONSTRAINT config_revisions_discarded_by_fkey
        FOREIGN KEY (organization_id, discarded_by_admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id);

CREATE TABLE config_revision_edits (
    organization_id text NOT NULL,
    config_revision_id text NOT NULL,
    edit_version bigint NOT NULL CHECK (edit_version > 0),
    kind text NOT NULL CHECK (kind IN ('created', 'edited', 'rebased', 'promoted')),
    admin_user_id text NOT NULL,
    edited_at timestamptz NOT NULL,
    change_count integer NOT NULL CHECK (change_count >= 0),
    changes jsonb NOT NULL
        CHECK (jsonb_typeof(changes) = 'array' AND jsonb_array_length(changes) <= 100),
    PRIMARY KEY (config_revision_id, edit_version),
    FOREIGN KEY (config_revision_id) REFERENCES config_revisions (config_revision_id),
    FOREIGN KEY (organization_id, admin_user_id)
        REFERENCES admin_memberships (organization_id, admin_user_id),
    CHECK (jsonb_array_length(changes) <= change_count)
);

CREATE OR REPLACE FUNCTION protect_config_revision_edits()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'configuration edit history is append-only'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER config_revision_edits_append_only
BEFORE UPDATE OR DELETE ON config_revision_edits
FOR EACH ROW
EXECUTE FUNCTION protect_config_revision_edits();

CREATE OR REPLACE FUNCTION protect_immutable_config_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status IN ('valid', 'discarded') OR OLD.activated_at IS NOT NULL THEN
            RAISE EXCEPTION 'validated configuration revisions are immutable'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.status = 'discarded' THEN
        RAISE EXCEPTION 'discarded configuration revisions are immutable'
            USING ERRCODE = '55000';
    END IF;

    -- Identity never changes, whatever the state.
    IF NEW.config_revision_id IS DISTINCT FROM OLD.config_revision_id
        OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.application_id IS DISTINCT FROM OLD.application_id
        OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
        OR NEW.revision_number IS DISTINCT FROM OLD.revision_number
        OR NEW.created_by_admin_user_id IS DISTINCT FROM OLD.created_by_admin_user_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'configuration revision identity is immutable'
            USING ERRCODE = '55000';
    END IF;

    -- A validated revision that was never activated may return to draft (an
    -- edit or rebase) or become discarded. Everything else about a validated
    -- or activated revision stays fixed.
    IF OLD.status = 'valid' AND OLD.activated_at IS NULL AND NEW.status IN ('draft', 'discarded') THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'valid' OR OLD.activated_at IS NOT NULL THEN
        IF NEW.etag IS DISTINCT FROM OLD.etag
            OR NEW.status IS DISTINCT FROM OLD.status
            OR NEW.document IS DISTINCT FROM OLD.document
            OR NEW.compiled_document IS DISTINCT FROM OLD.compiled_document
            OR NEW.validation_errors IS DISTINCT FROM OLD.validation_errors
            OR NEW.validation_report IS DISTINCT FROM OLD.validation_report
            OR NEW.validated_at IS DISTINCT FROM OLD.validated_at
            OR NEW.base_config_revision_id IS DISTINCT FROM OLD.base_config_revision_id
            OR NEW.description IS DISTINCT FROM OLD.description
            OR NEW.edit_version IS DISTINCT FROM OLD.edit_version
            OR NEW.discarded_at IS DISTINCT FROM OLD.discarded_at
            OR NEW.discarded_by_admin_user_id IS DISTINCT FROM OLD.discarded_by_admin_user_id
        THEN
            RAISE EXCEPTION 'validated configuration revisions are immutable'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    IF OLD.activated_at IS NOT NULL
        AND (
            NEW.activated_at IS DISTINCT FROM OLD.activated_at
            OR NEW.activation_note IS DISTINCT FROM OLD.activation_note
        )
    THEN
        RAISE EXCEPTION 'configuration activation history is immutable'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END
$$;
