-- Bind retry-cost treatment to each durable reservation entry and permit the
-- internal per-dispatch attempt allocation in the existing attempt ledger.
-- The empty default preserves rolling compatibility with schema-27 writers;
-- runtime canonicalization treats an empty cost value as actual_attempts.
ALTER TABLE quota_reservation_entries
    ADD COLUMN cost_retry_treatment text NOT NULL DEFAULT '',
    ADD CONSTRAINT quota_reservation_entries_cost_retry_treatment_check
        CHECK (cost_retry_treatment IN ('', 'actual_attempts', 'initial_attempt_only'));

UPDATE quota_reservation_entries AS entry
SET cost_retry_treatment = 'actual_attempts'
FROM quota_buckets AS bucket
WHERE bucket.organization_id = entry.organization_id
  AND bucket.application_id = entry.application_id
  AND bucket.environment_id = entry.environment_id
  AND bucket.quota_bucket_id = entry.quota_bucket_id
  AND bucket.metric = 'cost_nano_usd';

ALTER TABLE upstream_attempt_quota_entries
    DROP CONSTRAINT upstream_attempt_quota_entries_metric_check,
    ADD CONSTRAINT upstream_attempt_quota_entries_metric_check
        CHECK (
            metric IN (
                'upstream_attempts',
                'input_tokens',
                'output_tokens',
                'total_tokens',
                'cost_nano_usd'
            )
        );

-- Schema 12's deferred first-attempt compatibility trigger deliberately
-- validates modern attempt ledgers too. Include the new internally-derived
-- attempt row in its expected topology while preserving every legacy writer
-- and terminal-state check from the original function.
CREATE OR REPLACE FUNCTION latchway_schema12_attempt_terminal_compat()
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
      AND bucket.metric IN (
          'upstream_attempts',
          'input_tokens',
          'output_tokens',
          'total_tokens',
          'cost_nano_usd'
      );

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

COMMENT ON COLUMN quota_reservation_entries.cost_retry_treatment IS
    'Canonical cost quota retry treatment. Empty is accepted only as the schema-27 rolling-writer compatibility encoding of actual_attempts.';

COMMENT ON TABLE upstream_attempt_quota_entries IS
    'Per-dispatch attempt, token, and selected cost allocations and their conservative settlement under one logical quota reservation.';
