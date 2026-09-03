-- Reuse first-attempt terminal validation reads without weakening the deferred
-- schema-12 trigger, its five ordered checks, or legacy settlement repair.
-- No trigger, lock, index, constraint, or transaction timing is changed here.
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
    invalid_allocation boolean;
    invalid_settlement boolean;
BEGIN
    -- Count the complete ledger independently of binding joins: malformed or
    -- surplus rows must not disappear before the existing topology check.
    -- MATERIALIZED scopes avoid rereading the same private topology for each
    -- predicate. The mismatch aggregates retain the original EXISTS/NULL rules.
    WITH scoped_reservation AS MATERIALIZED (
        SELECT reservation.organization_id, reservation.application_id,
               reservation.environment_id, reservation.logical_request_id,
               reservation.quota_reservation_id, reservation.status
        FROM quota_reservations AS reservation
        WHERE reservation.organization_id = NEW.organization_id
          AND reservation.application_id = NEW.application_id
          AND reservation.environment_id = NEW.environment_id
          AND reservation.logical_request_id = NEW.logical_request_id
    ),
    scoped_ledger AS MATERIALIZED (
        SELECT quota.organization_id, quota.application_id, quota.environment_id,
               quota.quota_reservation_id, quota.quota_reservation_entry_id,
               quota.quota_bucket_id, quota.metric, quota.allocated_units,
               quota.charged_units, quota.released_units, quota.settled_at
        FROM upstream_attempt_quota_entries AS quota
        WHERE quota.organization_id = NEW.organization_id
          AND quota.application_id = NEW.application_id
          AND quota.environment_id = NEW.environment_id
          AND quota.logical_request_id = NEW.logical_request_id
          AND quota.upstream_attempt_id = NEW.upstream_attempt_id
    ),
    ledger_counts AS (
        SELECT count(*) AS total,
               count(*) FILTER (
                   WHERE charged_units IS NOT NULL
                     AND released_units IS NOT NULL
                     AND settled_at IS NOT NULL
               ) AS settled
        FROM scoped_ledger
    ),
    expected_entries AS (
        SELECT count(*) AS total
        FROM scoped_reservation AS reservation
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
        WHERE entry.origin_attempt_number = 1
          AND bucket.metric IN (
              'upstream_attempts',
              'input_tokens',
              'output_tokens',
              'total_tokens',
              'cost_nano_usd'
          )
    ),
    ledger_checks AS (
        SELECT COALESCE(bool_or(
                   bucket.quota_bucket_id IS NOT NULL AND (
                       quota.metric <> bucket.metric
                       OR quota.allocated_units <> entry.initial_reserved_units
                       OR entry.origin_attempt_number <> 1
                   )
               ), false) AS allocation_mismatch,
               COALESCE(bool_or(
                   quota.charged_units <> entry.settled_units
                   OR quota.released_units <> entry.released_units
                   OR quota.settled_at IS DISTINCT FROM NEW.completed_at
               ), false) AS settlement_mismatch
        FROM scoped_ledger AS quota
        JOIN quota_reservation_entries AS entry
          ON entry.organization_id = quota.organization_id
         AND entry.application_id = quota.application_id
         AND entry.environment_id = quota.environment_id
         AND entry.quota_reservation_id = quota.quota_reservation_id
         AND entry.quota_reservation_entry_id = quota.quota_reservation_entry_id
         AND entry.quota_bucket_id = quota.quota_bucket_id
        -- The old allocation check requires a bucket join, but the old
        -- settlement check does not. Preserve both relations independently.
        LEFT JOIN quota_buckets AS bucket
          ON bucket.organization_id = entry.organization_id
         AND bucket.application_id = entry.application_id
         AND bucket.environment_id = entry.environment_id
         AND bucket.quota_bucket_id = entry.quota_bucket_id
    ),
    aggregate_state AS (
        SELECT reservation.status AS reservation_status,
               logical.status AS logical_status
        FROM scoped_reservation AS reservation
        JOIN logical_requests AS logical
          ON logical.organization_id = reservation.organization_id
         AND logical.application_id = reservation.application_id
         AND logical.environment_id = reservation.environment_id
         AND logical.logical_request_id = reservation.logical_request_id
    )
    SELECT ledger_counts.total, ledger_counts.settled, expected_entries.total,
           ledger_checks.allocation_mismatch, ledger_checks.settlement_mismatch,
           aggregate_state.reservation_status, aggregate_state.logical_status
    INTO ledger_count, settled_count, expected_count,
         invalid_allocation, invalid_settlement, reservation_status, logical_status
    FROM ledger_counts
    CROSS JOIN expected_entries
    CROSS JOIN ledger_checks
    LEFT JOIN aggregate_state ON true;

    IF ledger_count <> expected_count OR
       (settled_count <> 0 AND settled_count <> ledger_count) THEN
        RAISE EXCEPTION 'legacy terminal attempt ledger is incomplete'
            USING ERRCODE = '23514';
    END IF;

    IF invalid_allocation THEN
        RAISE EXCEPTION 'legacy terminal attempt ledger has invalid allocation binding'
            USING ERRCODE = '23514';
    END IF;

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
        IF invalid_settlement THEN
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
