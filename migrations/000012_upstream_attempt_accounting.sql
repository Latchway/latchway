-- Preserve the immutable reservation made for the first upstream dispatch.
-- reserved_units becomes the cumulative amount reserved across every attempt
-- while this column remains the replay binding for the original decision.
ALTER TABLE quota_reservation_entries
	ADD COLUMN initial_reserved_units bigint,
	ADD COLUMN origin_attempt_number integer NOT NULL DEFAULT 1
		CHECK (origin_attempt_number BETWEEN 1 AND 32);

UPDATE quota_reservation_entries
SET initial_reserved_units = reserved_units;

ALTER TABLE quota_reservation_entries
    ALTER COLUMN initial_reserved_units SET NOT NULL,
    ADD CONSTRAINT quota_reservation_entries_initial_reserved_units_check
        CHECK (
            initial_reserved_units >= 0
            AND initial_reserved_units <= reserved_units
        );

COMMENT ON COLUMN quota_reservation_entries.initial_reserved_units IS
	'Immutable amount reserved when this target-scoped entry was first materialized; reserved_units may grow through later atomic retry reservations.';

COMMENT ON COLUMN quota_reservation_entries.origin_attempt_number IS
	'Contiguous upstream attempt that first materialized this reservation entry; schema-11 and initial schema-12 entries are attempt 1.';

ALTER TABLE upstream_attempts
    DROP CONSTRAINT upstream_attempts_attempt_number_check,
    ADD CONSTRAINT upstream_attempts_attempt_number_check
        CHECK (attempt_number BETWEEN 1 AND 32),
	ADD COLUMN model_key text,
	ADD COLUMN attempt_decision_binding_version smallint NOT NULL DEFAULT 0,
	ADD COLUMN attempt_decision_sha256 bytea,
	ADD COLUMN per_request_output_token_bound bigint,
    ADD COLUMN input_accounting_binding_version smallint NOT NULL DEFAULT 0,
    ADD COLUMN input_accounting_method text,
    ADD COLUMN input_accounting_profile_id text,
    ADD COLUMN input_accounting_profile_digest bytea,
    ADD COLUMN rewritten_body_sha256 bytea,
    ADD COLUMN input_token_bound bigint,
    ADD COLUMN output_token_bound bigint,
    ADD COLUMN total_token_bound bigint,
    ADD CONSTRAINT upstream_attempts_decision_binding_check
        CHECK (
            (
                attempt_decision_binding_version = 0
                AND attempt_number = 1
				AND model_key IS NULL
				AND attempt_decision_sha256 IS NULL
				AND per_request_output_token_bound IS NULL
            )
            OR (
                attempt_decision_binding_version = 1
                AND model_key ~ '^[a-z][a-z0-9_-]{0,62}$'
                AND physical_model IS NOT NULL
                AND octet_length(attempt_decision_sha256) = 32
				AND attempt_decision_sha256 <> decode(repeat('00', 32), 'hex')
				AND (
					per_request_output_token_bound IS NULL
					OR per_request_output_token_bound > 0
				)
            )
        ),
    ADD CONSTRAINT upstream_attempts_input_accounting_binding_check
        CHECK (
            (
                input_accounting_binding_version = 0
                AND attempt_number = 1
                AND input_accounting_method IS NULL
                AND input_accounting_profile_id IS NULL
                AND input_accounting_profile_digest IS NULL
                AND rewritten_body_sha256 IS NULL
                AND input_token_bound IS NULL
                AND output_token_bound IS NULL
                AND total_token_bound IS NULL
            )
            OR (
                input_accounting_binding_version = 1
                AND (
                    (
                        input_accounting_method IS NULL
                        AND input_accounting_profile_id IS NULL
                        AND input_accounting_profile_digest IS NULL
                        AND rewritten_body_sha256 IS NULL
                        AND input_token_bound IS NULL
                        AND output_token_bound IS NULL
                        AND total_token_bound IS NULL
                    )
                    OR (
                        input_accounting_method = 'utf8_byte_bpe_declared_framing_v1'
                        AND input_accounting_profile_id IS NOT NULL
                        AND input_accounting_profile_digest IS NOT NULL
                        AND rewritten_body_sha256 IS NOT NULL
                        AND input_token_bound IS NOT NULL
                        AND output_token_bound IS NOT NULL
                        AND total_token_bound IS NOT NULL
                        AND input_accounting_profile_id ~ '^[a-z][a-z0-9_-]{0,62}$'
                        AND octet_length(input_accounting_profile_digest) = 32
                        AND octet_length(rewritten_body_sha256) = 32
                        AND input_accounting_profile_digest <> decode(repeat('00', 32), 'hex')
                        AND rewritten_body_sha256 <> decode(repeat('00', 32), 'hex')
                        AND input_token_bound > 0
                        AND output_token_bound > 0
                        AND total_token_bound = input_token_bound + output_token_bound
                        AND total_token_bound > input_token_bound
                    )
                )
            )
        ),
    ADD CONSTRAINT upstream_attempts_request_identity_key
        UNIQUE (
            organization_id,
            application_id,
            environment_id,
            logical_request_id,
            upstream_attempt_id
        );

-- Keep version 0 as the database default during the schema-11 rolling writer
-- window. Schema-12 writers name both version columns explicitly. An old
-- writer omits every new column and therefore creates the narrow legacy-v0
-- shape accepted above.

ALTER TABLE quota_reservation_entries
    ADD CONSTRAINT quota_reservation_entries_attempt_binding_key
        UNIQUE (
            organization_id,
            application_id,
            environment_id,
            quota_reservation_id,
            quota_reservation_entry_id,
            quota_bucket_id
        );

ALTER TABLE quota_reservations
    ADD CONSTRAINT quota_reservations_attempt_binding_key
        UNIQUE (
            organization_id,
            application_id,
            environment_id,
            logical_request_id,
            quota_reservation_id
        );

ALTER TABLE usage_records
    ADD CONSTRAINT usage_records_request_attempt_fkey
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        upstream_attempt_id
    ) REFERENCES upstream_attempts (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        upstream_attempt_id
    );

-- A schema-11 application never creates more than one attempt. Refuse to
-- guess how manually-created multi-attempt rows were charged during upgrade.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM upstream_attempts
        GROUP BY logical_request_id
        HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1
        FROM upstream_attempts
        WHERE attempt_number <> 1
    ) OR EXISTS (
        SELECT 1
        FROM upstream_attempts AS attempt
        LEFT JOIN quota_reservations AS reservation
          ON reservation.organization_id = attempt.organization_id
         AND reservation.application_id = attempt.application_id
         AND reservation.environment_id = attempt.environment_id
         AND reservation.logical_request_id = attempt.logical_request_id
        GROUP BY
            attempt.organization_id,
            attempt.application_id,
            attempt.environment_id,
            attempt.logical_request_id,
            attempt.upstream_attempt_id
        HAVING count(reservation.quota_reservation_id) <> 1
    ) THEN
        RAISE EXCEPTION
            'cannot establish upstream attempt accounting: legacy attempt topology is ambiguous'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE TABLE upstream_attempt_quota_entries (
    organization_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    logical_request_id text NOT NULL,
    upstream_attempt_id text NOT NULL,
    quota_reservation_id text NOT NULL,
    quota_reservation_entry_id text NOT NULL,
    quota_bucket_id text NOT NULL,
    metric text NOT NULL
        CHECK (metric IN ('input_tokens', 'output_tokens', 'total_tokens', 'cost_nano_usd')),
    allocated_units bigint NOT NULL,
    charged_units bigint,
    released_units bigint,
    settled_at timestamptz,
    CONSTRAINT upstream_attempt_quota_entries_attempt_fkey
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        upstream_attempt_id
    ) REFERENCES upstream_attempts (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        upstream_attempt_id
    ),
    CONSTRAINT upstream_attempt_quota_entries_request_reservation_fkey
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        quota_reservation_id
    ) REFERENCES quota_reservations (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        quota_reservation_id
    ),
    CONSTRAINT upstream_attempt_quota_entries_reservation_entry_fkey
    FOREIGN KEY (
        organization_id,
        application_id,
        environment_id,
        quota_reservation_id,
        quota_reservation_entry_id,
        quota_bucket_id
    ) REFERENCES quota_reservation_entries (
        organization_id,
        application_id,
        environment_id,
        quota_reservation_id,
        quota_reservation_entry_id,
        quota_bucket_id
    ),
    CONSTRAINT upstream_attempt_quota_entries_allocation_check
    CHECK (
        (metric = 'cost_nano_usd' AND allocated_units >= 0)
        OR (metric <> 'cost_nano_usd' AND allocated_units > 0)
    ),
    CONSTRAINT upstream_attempt_quota_entries_settlement_check
    CHECK (
        (
            charged_units IS NULL
            AND released_units IS NULL
            AND settled_at IS NULL
        )
        OR (
            charged_units IS NOT NULL
            AND released_units IS NOT NULL
            AND settled_at IS NOT NULL
            AND charged_units >= 0
            AND charged_units <= allocated_units
            AND released_units = allocated_units - charged_units
        )
    ),
    PRIMARY KEY (environment_id, upstream_attempt_id, quota_reservation_entry_id),
    UNIQUE (
        organization_id,
        application_id,
        environment_id,
        upstream_attempt_id,
        quota_reservation_entry_id
    ),
    UNIQUE (
        environment_id,
        upstream_attempt_id,
        quota_bucket_id
    )
);

CREATE INDEX upstream_attempt_quota_entries_request_idx
    ON upstream_attempt_quota_entries (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        upstream_attempt_id
    );

COMMENT ON TABLE upstream_attempt_quota_entries IS
    'Per-dispatch token and cost allocations and their conservative settlement under one logical quota reservation.';

-- Backfill every valid schema-11 attempt. A started attempt owns the original
-- allocation but is not settled. A terminal attempt inherits the already
-- finalized reservation split, preserving rolling-upgrade recovery and replay.
INSERT INTO upstream_attempt_quota_entries (
    organization_id,
    application_id,
    environment_id,
    logical_request_id,
    upstream_attempt_id,
    quota_reservation_id,
    quota_reservation_entry_id,
    quota_bucket_id,
    metric,
    allocated_units,
    charged_units,
    released_units,
    settled_at
)
SELECT attempt.organization_id,
       attempt.application_id,
       attempt.environment_id,
       attempt.logical_request_id,
       attempt.upstream_attempt_id,
       reservation.quota_reservation_id,
       entry.quota_reservation_entry_id,
       entry.quota_bucket_id,
       bucket.metric,
       entry.initial_reserved_units,
       CASE WHEN attempt.status = 'started' THEN NULL ELSE entry.settled_units END,
       CASE WHEN attempt.status = 'started' THEN NULL ELSE entry.released_units END,
       CASE WHEN attempt.status = 'started' THEN NULL ELSE attempt.completed_at END
FROM upstream_attempts AS attempt
JOIN quota_reservations AS reservation
  ON reservation.organization_id = attempt.organization_id
 AND reservation.application_id = attempt.application_id
 AND reservation.environment_id = attempt.environment_id
 AND reservation.logical_request_id = attempt.logical_request_id
JOIN quota_reservation_entries AS entry
  ON entry.organization_id = reservation.organization_id
 AND entry.application_id = reservation.application_id
 AND entry.environment_id = reservation.environment_id
 AND entry.quota_reservation_id = reservation.quota_reservation_id
JOIN quota_buckets AS bucket
  ON bucket.organization_id = entry.organization_id
 AND bucket.application_id = entry.application_id
 AND bucket.environment_id = entry.environment_id
 AND bucket.quota_bucket_id = entry.quota_bucket_id
WHERE bucket.metric IN ('input_tokens', 'output_tokens', 'total_tokens', 'cost_nano_usd');

-- A schema-11 Reserve INSERT does not name initial_reserved_units. Initialize
-- that one omitted column before NOT NULL/check enforcement while preserving
-- every explicit schema-12 value and the origin-attempt default.
CREATE FUNCTION latchway_schema12_reservation_entry_compat()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.initial_reserved_units IS NULL THEN
        NEW.initial_reserved_units := NEW.reserved_units;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER quota_reservation_entries_schema11_insert_compat
BEFORE INSERT ON quota_reservation_entries
FOR EACH ROW
EXECUTE FUNCTION latchway_schema12_reservation_entry_compat();

-- A schema-11 BeginAttempt INSERT also omits the per-attempt allocation
-- ledger. The reservation already committed in an earlier transaction, so an
-- AFTER INSERT trigger can copy its immutable first allocation atomically.
CREATE FUNCTION latchway_schema12_attempt_insert_compat()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    reservation_count integer;
    expected_count integer;
    inserted_count integer;
BEGIN
    IF NEW.attempt_decision_binding_version <> 0 THEN
        RETURN NEW;
    END IF;
    IF NEW.attempt_number <> 1 THEN
        RAISE EXCEPTION 'legacy attempt accounting requires attempt 1'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*)
    INTO reservation_count
    FROM quota_reservations AS reservation
    WHERE reservation.organization_id = NEW.organization_id
      AND reservation.application_id = NEW.application_id
      AND reservation.environment_id = NEW.environment_id
      AND reservation.logical_request_id = NEW.logical_request_id;
    IF reservation_count <> 1 THEN
        RAISE EXCEPTION 'legacy attempt accounting requires one reservation'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*)
    INTO expected_count
    FROM quota_reservations AS reservation
    JOIN quota_reservation_entries AS entry
      ON entry.organization_id = reservation.organization_id
     AND entry.application_id = reservation.application_id
     AND entry.environment_id = reservation.environment_id
     AND entry.quota_reservation_id = reservation.quota_reservation_id
    JOIN quota_buckets AS bucket
      ON bucket.organization_id = entry.organization_id
     AND bucket.application_id = entry.application_id
     AND bucket.environment_id = entry.environment_id
     AND bucket.quota_bucket_id = entry.quota_bucket_id
    WHERE reservation.organization_id = NEW.organization_id
      AND reservation.application_id = NEW.application_id
      AND reservation.environment_id = NEW.environment_id
      AND reservation.logical_request_id = NEW.logical_request_id
      AND entry.origin_attempt_number = 1
      AND bucket.metric IN ('input_tokens', 'output_tokens', 'total_tokens', 'cost_nano_usd');

    INSERT INTO upstream_attempt_quota_entries (
        organization_id,
        application_id,
        environment_id,
        logical_request_id,
        upstream_attempt_id,
        quota_reservation_id,
        quota_reservation_entry_id,
        quota_bucket_id,
        metric,
        allocated_units
    )
    SELECT NEW.organization_id,
           NEW.application_id,
           NEW.environment_id,
           NEW.logical_request_id,
           NEW.upstream_attempt_id,
           reservation.quota_reservation_id,
           entry.quota_reservation_entry_id,
           entry.quota_bucket_id,
           bucket.metric,
           entry.initial_reserved_units
    FROM quota_reservations AS reservation
    JOIN quota_reservation_entries AS entry
      ON entry.organization_id = reservation.organization_id
     AND entry.application_id = reservation.application_id
     AND entry.environment_id = reservation.environment_id
     AND entry.quota_reservation_id = reservation.quota_reservation_id
    JOIN quota_buckets AS bucket
      ON bucket.organization_id = entry.organization_id
     AND bucket.application_id = entry.application_id
     AND bucket.environment_id = entry.environment_id
     AND bucket.quota_bucket_id = entry.quota_bucket_id
    WHERE reservation.organization_id = NEW.organization_id
      AND reservation.application_id = NEW.application_id
      AND reservation.environment_id = NEW.environment_id
      AND reservation.logical_request_id = NEW.logical_request_id
      AND entry.origin_attempt_number = 1
      AND bucket.metric IN ('input_tokens', 'output_tokens', 'total_tokens', 'cost_nano_usd');
    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count <> expected_count THEN
        RAISE EXCEPTION 'legacy attempt allocation ledger is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER upstream_attempts_schema11_insert_compat
AFTER INSERT ON upstream_attempts
FOR EACH ROW
WHEN (NEW.attempt_decision_binding_version = 0)
EXECUTE FUNCTION latchway_schema12_attempt_insert_compat();

-- A schema-11 settler finalizes the attempt and reservation entries without
-- knowing about the new ledger. Run after all statements in that transaction.
-- A schema-12 settler continuing a legacy-v0 attempt has already settled the
-- ledger; that exact state is validated and left untouched.
CREATE FUNCTION latchway_schema12_attempt_terminal_compat()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    ledger_count integer;
    expected_count integer;
    settled_count integer;
    updated_count integer;
    reservation_status text;
    logical_status text;
BEGIN
    SELECT count(*),
           count(*) FILTER (
               WHERE charged_units IS NOT NULL
                 AND released_units IS NOT NULL
                 AND settled_at IS NOT NULL
           )
    INTO ledger_count, settled_count
    FROM upstream_attempt_quota_entries
    WHERE organization_id = NEW.organization_id
      AND application_id = NEW.application_id
      AND environment_id = NEW.environment_id
      AND logical_request_id = NEW.logical_request_id
      AND upstream_attempt_id = NEW.upstream_attempt_id;

    SELECT count(*)
    INTO expected_count
    FROM quota_reservations AS reservation
    JOIN quota_reservation_entries AS entry
      ON entry.organization_id = reservation.organization_id
     AND entry.application_id = reservation.application_id
     AND entry.environment_id = reservation.environment_id
     AND entry.quota_reservation_id = reservation.quota_reservation_id
    JOIN quota_buckets AS bucket
      ON bucket.organization_id = entry.organization_id
     AND bucket.application_id = entry.application_id
     AND bucket.environment_id = entry.environment_id
     AND bucket.quota_bucket_id = entry.quota_bucket_id
    WHERE reservation.organization_id = NEW.organization_id
      AND reservation.application_id = NEW.application_id
      AND reservation.environment_id = NEW.environment_id
      AND reservation.logical_request_id = NEW.logical_request_id
      AND entry.origin_attempt_number = 1
      AND bucket.metric IN ('input_tokens', 'output_tokens', 'total_tokens', 'cost_nano_usd');

    IF ledger_count <> expected_count OR
       (settled_count <> 0 AND settled_count <> ledger_count) THEN
        RAISE EXCEPTION 'legacy terminal attempt ledger is incomplete'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM upstream_attempt_quota_entries AS quota
        JOIN quota_reservation_entries AS entry
          ON entry.organization_id = quota.organization_id
         AND entry.application_id = quota.application_id
         AND entry.environment_id = quota.environment_id
         AND entry.quota_reservation_id = quota.quota_reservation_id
         AND entry.quota_reservation_entry_id = quota.quota_reservation_entry_id
         AND entry.quota_bucket_id = quota.quota_bucket_id
        JOIN quota_buckets AS bucket
          ON bucket.organization_id = entry.organization_id
         AND bucket.application_id = entry.application_id
         AND bucket.environment_id = entry.environment_id
         AND bucket.quota_bucket_id = entry.quota_bucket_id
        WHERE quota.organization_id = NEW.organization_id
          AND quota.application_id = NEW.application_id
          AND quota.environment_id = NEW.environment_id
          AND quota.logical_request_id = NEW.logical_request_id
          AND quota.upstream_attempt_id = NEW.upstream_attempt_id
          AND (
              quota.metric <> bucket.metric
              OR quota.allocated_units <> entry.initial_reserved_units
              OR entry.origin_attempt_number <> 1
          )
    ) THEN
        RAISE EXCEPTION 'legacy terminal attempt ledger has invalid allocation binding'
            USING ERRCODE = '23514';
    END IF;

    SELECT reservation.status, logical.status
    INTO reservation_status, logical_status
    FROM quota_reservations AS reservation
    JOIN logical_requests AS logical
      ON logical.organization_id = reservation.organization_id
     AND logical.application_id = reservation.application_id
     AND logical.environment_id = reservation.environment_id
     AND logical.logical_request_id = reservation.logical_request_id
    WHERE reservation.organization_id = NEW.organization_id
      AND reservation.application_id = NEW.application_id
      AND reservation.environment_id = NEW.environment_id
      AND reservation.logical_request_id = NEW.logical_request_id;
    IF settled_count = ledger_count THEN
        IF NOT COALESCE(
            (
                reservation_status = 'pending'
                AND logical_status IN ('dispatched', 'streaming')
                AND NEW.status IN ('failed', 'timed_out')
            ) OR (
                reservation_status = 'settled'
                AND (
                    (logical_status = 'succeeded' AND NEW.status = 'succeeded')
                    OR (logical_status = 'cancelled' AND NEW.status = 'cancelled')
                    OR (
                        logical_status = 'failed'
                        AND NEW.status IN ('failed', 'timed_out')
                    )
                )
            ),
            false
        ) THEN
            RAISE EXCEPTION 'settled legacy attempt has incoherent aggregate lifecycle'
                USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            SELECT 1
            FROM upstream_attempt_quota_entries AS quota
            JOIN quota_reservation_entries AS entry
              ON entry.organization_id = quota.organization_id
             AND entry.application_id = quota.application_id
             AND entry.environment_id = quota.environment_id
             AND entry.quota_reservation_id = quota.quota_reservation_id
             AND entry.quota_reservation_entry_id = quota.quota_reservation_entry_id
             AND entry.quota_bucket_id = quota.quota_bucket_id
            WHERE quota.organization_id = NEW.organization_id
              AND quota.application_id = NEW.application_id
              AND quota.environment_id = NEW.environment_id
              AND quota.logical_request_id = NEW.logical_request_id
              AND quota.upstream_attempt_id = NEW.upstream_attempt_id
              AND (
                  quota.charged_units <> entry.settled_units
                  OR quota.released_units <> entry.released_units
                  OR quota.settled_at IS DISTINCT FROM NEW.completed_at
              )
        ) THEN
            RAISE EXCEPTION 'legacy terminal attempt ledger disagrees with reservation'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT COALESCE(
        reservation_status = 'settled'
        AND (
            (logical_status = 'succeeded' AND NEW.status = 'succeeded')
            OR (logical_status = 'cancelled' AND NEW.status = 'cancelled')
            OR (
                logical_status = 'failed'
                AND NEW.status IN ('failed', 'timed_out')
            )
        ),
        false
    ) THEN
        RAISE EXCEPTION 'legacy terminal attempt requires coherent terminal reservation'
            USING ERRCODE = '23514';
    END IF;

    UPDATE upstream_attempt_quota_entries AS quota
    SET charged_units = entry.settled_units,
        released_units = entry.released_units,
        settled_at = NEW.completed_at
    FROM quota_reservation_entries AS entry
    WHERE quota.organization_id = NEW.organization_id
      AND quota.application_id = NEW.application_id
      AND quota.environment_id = NEW.environment_id
      AND quota.logical_request_id = NEW.logical_request_id
      AND quota.upstream_attempt_id = NEW.upstream_attempt_id
      AND entry.organization_id = quota.organization_id
      AND entry.application_id = quota.application_id
      AND entry.environment_id = quota.environment_id
      AND entry.quota_reservation_id = quota.quota_reservation_id
      AND entry.quota_reservation_entry_id = quota.quota_reservation_entry_id
      AND entry.quota_bucket_id = quota.quota_bucket_id
      AND quota.charged_units IS NULL
      AND quota.released_units IS NULL
      AND quota.settled_at IS NULL;
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    IF updated_count <> ledger_count THEN
        RAISE EXCEPTION 'legacy terminal attempt ledger update is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER upstream_attempts_schema11_terminal_compat
AFTER UPDATE OF status ON upstream_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (
    OLD.status = 'started'
    AND (
        OLD.attempt_decision_binding_version = 0
        OR OLD.attempt_number = 1
    )
    AND NEW.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
)
EXECUTE FUNCTION latchway_schema12_attempt_terminal_compat();
