ALTER TABLE config_revisions
    ADD COLUMN base_config_revision_id text,
    ADD COLUMN description text
        CHECK (description IS NULL OR char_length(description) <= 512),
    ADD COLUMN edit_version bigint NOT NULL DEFAULT 1 CHECK (edit_version > 0),
    ADD COLUMN validation_report jsonb
        CHECK (validation_report IS NULL OR jsonb_typeof(validation_report) = 'object'),
    ADD COLUMN activated_at timestamptz;

ALTER TABLE config_revisions
    ADD CONSTRAINT config_revisions_base_revision_fkey
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        base_config_revision_id
    ) REFERENCES config_revisions (
        organization_id,
        application_id,
        environment_id,
        config_revision_id
    ) DEFERRABLE INITIALLY DEFERRED;

DO $$
DECLARE
    constraint_name name;
BEGIN
    SELECT constraint_record.conname
      INTO constraint_name
      FROM pg_constraint AS constraint_record
     WHERE constraint_record.conrelid = 'active_config_revisions'::regclass
       AND constraint_record.contype = 'f'
       AND pg_get_constraintdef(constraint_record.oid) LIKE '%config_revisions%'
     LIMIT 1;

    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'active configuration revision foreign key is missing';
    END IF;
    EXECUTE format(
        'ALTER TABLE active_config_revisions DROP CONSTRAINT %I',
        constraint_name
    );
END
$$;

ALTER TABLE active_config_revisions
    DROP CONSTRAINT active_config_revisions_revision_status_check;

UPDATE config_revisions AS revision
   SET activated_at = COALESCE(active_revision.activated_at, revision.validated_at)
  FROM active_config_revisions AS active_revision
 WHERE active_revision.config_revision_id = revision.config_revision_id;

UPDATE config_revisions
   SET activated_at = COALESCE(activated_at, validated_at)
 WHERE status = 'superseded';

UPDATE config_revisions
   SET status = 'valid'
 WHERE status IN ('active', 'superseded');

UPDATE config_revisions
   SET validation_report = jsonb_build_object(
       'valid', true,
       'checked_at', COALESCE(validated_at, created_at),
       'issues', COALESCE(validation_errors, '[]'::jsonb)
   )
 WHERE status = 'valid'
   AND validation_report IS NULL;

UPDATE active_config_revisions
   SET revision_status = 'valid';

ALTER TABLE active_config_revisions
    ALTER COLUMN revision_status SET DEFAULT 'valid',
    ADD CONSTRAINT active_config_revisions_revision_status_check
        CHECK (revision_status = 'valid'),
    ADD CONSTRAINT active_config_revisions_valid_revision_fkey
        FOREIGN KEY (
            organization_id,
            application_id,
            environment_id,
            config_revision_id,
            revision_status
        ) REFERENCES config_revisions (
            organization_id,
            application_id,
            environment_id,
            config_revision_id,
            status
        ) DEFERRABLE INITIALLY DEFERRED;

DROP INDEX config_revisions_one_active_idx;

ALTER TABLE config_revisions
    DROP CONSTRAINT config_revisions_status_check,
    ADD CONSTRAINT config_revisions_status_check
        CHECK (status IN ('draft', 'valid', 'invalid')),
    ADD CONSTRAINT config_revisions_activation_check
        CHECK (
            activated_at IS NULL
            OR (
                status = 'valid'
                AND validated_at IS NOT NULL
                AND compiled_document IS NOT NULL
                AND validation_report IS NOT NULL
            )
        );

CREATE OR REPLACE FUNCTION protect_immutable_config_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status = 'valid' OR OLD.activated_at IS NOT NULL THEN
            RAISE EXCEPTION 'validated configuration revisions are immutable'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.status = 'valid' OR OLD.activated_at IS NOT NULL THEN
        IF NEW.config_revision_id IS DISTINCT FROM OLD.config_revision_id
            OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
            OR NEW.application_id IS DISTINCT FROM OLD.application_id
            OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
            OR NEW.revision_number IS DISTINCT FROM OLD.revision_number
            OR NEW.etag IS DISTINCT FROM OLD.etag
            OR NEW.status IS DISTINCT FROM OLD.status
            OR NEW.document IS DISTINCT FROM OLD.document
            OR NEW.compiled_document IS DISTINCT FROM OLD.compiled_document
            OR NEW.validation_errors IS DISTINCT FROM OLD.validation_errors
            OR NEW.validation_report IS DISTINCT FROM OLD.validation_report
            OR NEW.validated_at IS DISTINCT FROM OLD.validated_at
            OR NEW.base_config_revision_id IS DISTINCT FROM OLD.base_config_revision_id
            OR NEW.description IS DISTINCT FROM OLD.description
            OR NEW.edit_version IS DISTINCT FROM OLD.edit_version
            OR NEW.created_by_admin_user_id IS DISTINCT FROM OLD.created_by_admin_user_id
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
        THEN
            RAISE EXCEPTION 'validated configuration revisions are immutable'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    IF OLD.activated_at IS NOT NULL
        AND NEW.activated_at IS DISTINCT FROM OLD.activated_at
    THEN
        RAISE EXCEPTION 'configuration activation history is immutable'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER config_revisions_immutable_update
BEFORE UPDATE ON config_revisions
FOR EACH ROW
EXECUTE FUNCTION protect_immutable_config_revision();

CREATE TRIGGER config_revisions_immutable_delete
BEFORE DELETE ON config_revisions
FOR EACH ROW
EXECUTE FUNCTION protect_immutable_config_revision();
