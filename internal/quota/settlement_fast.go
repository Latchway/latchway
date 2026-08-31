package quota

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

// The initial final-settlement path is intentionally narrow. It covers the
// production non-streaming shape without weakening the exhaustive retry
// lifecycle classifier: one first attempt, a marked first byte, known provider
// token usage, no pricing, and zero or more materialized hard calendar
// request/token rules. Digest-bound per-request guards create no settlement
// rows and are also eligible. Any replay, retry, legacy row, unsupported rule,
// or noncanonical snapshot rolls this transaction back and uses the slow path.
func (store *Store) settleInitialFinalAttempt(
	ctx context.Context,
	attempt Attempt,
	outcome Outcome,
) (bool, error) {
	if attempt.number != 1 || outcome.Status != AttemptSucceeded || !outcome.Usage.Known ||
		outcome.Cost.Known {
		return false, nil
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return true, persistenceFailure("begin initial final settlement", err)
	}
	defer rollback(tx)

	expected := attempt.reservation
	batch := &pgx.Batch{}
	batch.Queue(
		lockQuotaReservationSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID, expected.reservationID,
	)
	batch.Queue(
		lockLogicalRequestSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID,
	)
	batch.Queue(lockUpstreamAttemptsSQL, expected.logicalRequestID)
	batch.Queue(
		lockReservationEntriesQuery(true),
		expected.organizationID, expected.applicationID,
		expected.environmentID, expected.reservationID,
	)
	batch.Queue(lockConcurrencyLeasesSQL, expected.environmentID, expected.logicalRequestID)
	batch.Queue(
		lockAttemptQuotaEntriesSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID, attempt.attemptID, expected.reservationID,
	)
	batch.Queue(
		countInitialSettlementUsageSQL,
		expected.organizationID, expected.applicationID,
		expected.environmentID, expected.logicalRequestID,
	)
	results := tx.SendBatch(ctx, batch)
	reservation, scanErr := scanLockedReservation(results.QueryRow(), expected)
	if scanErr != nil {
		return finishInitialFinalReadMismatch(results, scanErr)
	}
	logical, scanErr := scanLockedLogicalRequest(results.QueryRow(), expected)
	if scanErr != nil {
		return finishInitialFinalReadMismatch(results, scanErr)
	}
	attemptRows, queryErr := results.Query()
	if queryErr != nil {
		return finishInitialFinalReadFailure(results, "lock upstream attempts", queryErr)
	}
	attempts, scanErr := scanStoredAttempts(attemptRows)
	if scanErr != nil {
		return finishInitialFinalReadMismatch(results, scanErr)
	}
	entryRows, queryErr := results.Query()
	if queryErr != nil {
		return finishInitialFinalReadFailure(results, "lock quota reservation entries", queryErr)
	}
	entries, scanErr := scanLockedReservationEntries(entryRows, reservation)
	if scanErr != nil {
		return finishInitialFinalReadMismatch(results, scanErr)
	}
	leaseRows, queryErr := results.Query()
	if queryErr != nil {
		return finishInitialFinalReadFailure(results, "lock concurrency leases", queryErr)
	}
	expectedBuckets, expectedIDs := expectedConcurrencyLeaseState(reservation, entries)
	leases, scanErr := scanLockedConcurrencyLeases(
		leaseRows, reservation, expectedBuckets, expectedIDs,
	)
	if scanErr != nil {
		return finishInitialFinalReadMismatch(results, scanErr)
	}
	quotaRows, queryErr := results.Query()
	if queryErr != nil {
		return finishInitialFinalReadFailure(results, "lock upstream attempt quota entries", queryErr)
	}
	quotaEntries, scanErr := scanLockedAttemptQuotaEntries(quotaRows, reservation)
	if scanErr != nil {
		return finishInitialFinalReadMismatch(results, scanErr)
	}
	var usageCount int64
	if scanErr = results.QueryRow().Scan(&usageCount); scanErr != nil {
		return finishInitialFinalReadFailure(results, "count initial settlement usage", scanErr)
	}
	if closeErr := results.Close(); closeErr != nil {
		return true, persistenceFailure("complete initial settlement read batch", closeErr)
	}

	state, canonical := canonicalInitialFinalSettlement(
		reservation, logical, attempts, entries, leases, quotaEntries,
		attempt, outcome, usageCount,
	)
	if !canonical {
		return false, nil
	}
	reservations, err := attemptTokenReservationUnits(state.quotaEntries)
	if err != nil {
		return false, nil
	}
	usageIDs, err := store.newSettlementUsageIDsForTokenMetrics(
		state.outcome.Usage, reservations, state.outcome.Cost, selectedPricing{},
	)
	if err != nil {
		return true, err
	}
	if !validInitialFinalUsageIDs(usageIDs) {
		return true, ErrInvalidState
	}
	// Preserve the lifecycle timestamp contract: identifier generation may
	// block, so completion is read only after every usage identifier exists.
	now, err := statementTime(ctx, tx)
	if err != nil {
		return true, err
	}
	if state.attempt.firstByteAt.After(now) {
		now = state.attempt.firstByteAt.UTC()
	}

	if err := writeInitialFinalSettlement(
		ctx, tx, reservation, logical, state, usageIDs, now,
	); err != nil {
		return true, err
	}
	if err := tx.Commit(ctx); err != nil {
		return true, persistenceFailure("commit initial final settlement", err)
	}
	return true, nil
}

const countInitialSettlementUsageSQL = `
	SELECT count(*)
	FROM usage_records
	WHERE organization_id = $1 AND application_id = $2
	  AND environment_id = $3 AND logical_request_id = $4
`

func finishInitialFinalReadMismatch(results pgx.BatchResults, err error) (bool, error) {
	if closeErr := results.Close(); closeErr != nil {
		return true, persistenceFailure("complete initial settlement read batch", closeErr)
	}
	if errors.Is(err, ErrInvalidState) || errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return true, err
}

func finishInitialFinalReadFailure(
	results pgx.BatchResults,
	operation string,
	err error,
) (bool, error) {
	if closeErr := results.Close(); closeErr != nil {
		return true, persistenceFailure("complete initial settlement read batch", closeErr)
	}
	return true, persistenceFailure(operation, err)
}

type initialFinalSettlementState struct {
	attempt        storedAttempt
	outcome        Outcome
	tokenEntries   []initialFinalCalendarEntry
	logicalEntries []lockedEntry
	quotaEntries   []lockedAttemptQuotaEntry
}

type initialFinalCalendarEntry struct {
	entry   lockedEntry
	charged int64
}

func canonicalInitialFinalSettlement(
	reservation lockedReservation,
	logical lockedLogical,
	attempts []storedAttempt,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
	quotaEntries []lockedAttemptQuotaEntry,
	expectedAttempt Attempt,
	outcome Outcome,
	usageCount int64,
) (initialFinalSettlementState, bool) {
	if len(attempts) != 1 || len(leases) != 0 || usageCount != 0 ||
		reservation.status != "pending" || logical.status != "streaming" ||
		logical.failureCode != nil || logical.protocol != reservation.protocol {
		return initialFinalSettlementState{}, false
	}
	stored := attempts[0]
	pricing, pricingErr := stored.selectedPricing()
	normalized, normalizeErr := normalizeOutcomeForPricing(outcome, pricing)
	if pricingErr != nil || normalizeErr != nil || pricing.present() || reservation.pricing.present() ||
		stored.id != expectedAttempt.attemptID || stored.number != 1 ||
		stored.status != "started" || stored.firstByteAt == nil ||
		stored.attemptDecisionBindingVersion != 2 ||
		stored.routeKey != reservation.routeKey || stored.upstreamKey != reservation.upstreamKey ||
		stored.physicalModel == nil || *stored.physicalModel != reservation.physicalModel ||
		!attemptPricingMatchesReservation(stored, reservation.Reservation) ||
		!storedModelKeyMatches(stored, reservation.modelKey) ||
		!storedInitialInputPreflightMatches(stored, reservation.inputPreflight) ||
		!storedInitialRequestMeasurementsMatch(stored, reservation.requestMeasurements) ||
		normalized.Status != AttemptSucceeded || !normalized.Usage.Known || normalized.Cost.Known ||
		!pendingEntriesMatch(logical.status, reservation, entries, leases) ||
		!initialAttemptEntriesUnchanged(entries) ||
		!attemptQuotaEntriesUnsettled(quotaEntries) ||
		!attemptQuotaEntriesMatchReservation(reservation, stored, quotaEntries, entries) {
		return initialFinalSettlementState{}, false
	}

	tokenEntries := make([]initialFinalCalendarEntry, 0, len(entries))
	logicalEntries := make([]lockedEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.algorithm != CalendarAlgorithm || entry.originAttemptNumber != 1 ||
			entry.initialReservedUnits <= 0 || entry.reservedUnits != entry.initialReservedUnits {
			return initialFinalSettlementState{}, false
		}
		if entry.metric == LogicalRequestsMetric {
			if entry.reservedUnits != 1 || entry.hardMaximum == nil ||
				entry.bucketReserved < 1 || entry.bucketUsed > *entry.hardMaximum ||
				1 > *entry.hardMaximum-entry.bucketUsed {
				return initialFinalSettlementState{}, false
			}
			logicalEntries = append(logicalEntries, entry)
			continue
		}
		actual, tokenMetric := tokenMetricUsageUnits(normalized.Usage, entry.metric)
		if !tokenMetric || actual < 0 || actual > entry.reservedUnits ||
			entry.hardMaximum == nil || entry.bucketReserved < entry.reservedUnits ||
			entry.bucketUsed > *entry.hardMaximum || actual > *entry.hardMaximum-entry.bucketUsed {
			return initialFinalSettlementState{}, false
		}
		tokenEntries = append(tokenEntries, initialFinalCalendarEntry{entry: entry, charged: actual})
	}
	if len(quotaEntries) != len(tokenEntries) {
		return initialFinalSettlementState{}, false
	}
	return initialFinalSettlementState{
		attempt: stored, outcome: normalized, tokenEntries: tokenEntries,
		logicalEntries: logicalEntries, quotaEntries: quotaEntries,
	}, true
}

func validInitialFinalUsageIDs(identifiers settlementUsageIDs) bool {
	for _, value := range []string{
		identifiers.logical, identifiers.providerInput,
		identifiers.providerOutput, identifiers.providerTotal,
	} {
		if id.Validate(value, id.UsageRecord) != nil {
			return false
		}
	}
	return identifiers.unknownInput == "" && identifiers.unknownOutput == "" &&
		identifiers.unknownTotal == "" && identifiers.cost == ""
}

const settleInitialCalendarBucketsSQL = `
	WITH expected AS (
		SELECT *
		FROM unnest(
			$1::text[], $2::text[], $3::bigint[], $4::bigint[],
			$5::bigint[], $6::bigint[], $7::bigint[]
		) AS row(
			bucket_id, metric, charged_units, allocated_units,
			used_units, reserved_units, hard_maximum
		)
	)
	UPDATE quota_buckets AS bucket
	SET used_units = bucket.used_units + expected.charged_units,
	    reserved_units = bucket.reserved_units - expected.allocated_units,
	    version = bucket.version + 1,
	    updated_at = GREATEST(bucket.updated_at, $8)
	FROM expected
	WHERE bucket.quota_bucket_id = expected.bucket_id
	  AND bucket.metric = expected.metric AND bucket.algorithm = 'calendar'
	  AND bucket.used_units = expected.used_units
	  AND bucket.reserved_units = expected.reserved_units
	  AND bucket.hard_maximum = expected.hard_maximum
	  AND expected.allocated_units > 0
	  AND expected.charged_units BETWEEN 0 AND expected.allocated_units
	  AND bucket.reserved_units >= expected.allocated_units
	  AND expected.charged_units <= bucket.hard_maximum - bucket.used_units
`

const settleInitialReservationEntriesSQL = `
	WITH expected AS (
		SELECT *
		FROM unnest($1::text[], $2::bigint[], $3::bigint[])
			AS row(entry_id, allocated_units, charged_units)
	)
	UPDATE quota_reservation_entries AS entry
	SET settled_units = expected.charged_units,
	    released_units = expected.allocated_units - expected.charged_units
	FROM expected
	WHERE entry.quota_reservation_entry_id = expected.entry_id
	  AND entry.initial_reserved_units = expected.allocated_units
	  AND entry.reserved_units = expected.allocated_units
	  AND entry.settled_units = 0 AND entry.released_units = 0
	  AND expected.allocated_units > 0
	  AND expected.charged_units BETWEEN 0 AND expected.allocated_units
`

const settleInitialAttemptQuotaEntriesSQL = `
	WITH expected AS (
		SELECT *
		FROM unnest(
			$1::text[], $2::text[], $3::text[], $4::bigint[], $5::bigint[]
		) AS row(entry_id, bucket_id, metric, allocated_units, charged_units)
	)
	UPDATE upstream_attempt_quota_entries AS quota
	SET charged_units = expected.charged_units,
	    released_units = expected.allocated_units - expected.charged_units,
	    settled_at = $12
	FROM expected
	WHERE quota.quota_reservation_entry_id = expected.entry_id
	  AND quota.quota_bucket_id = expected.bucket_id
	  AND quota.metric = expected.metric
	  AND quota.allocated_units = expected.allocated_units
	  AND quota.organization_id = $6 AND quota.application_id = $7
	  AND quota.environment_id = $8 AND quota.logical_request_id = $9
	  AND quota.upstream_attempt_id = $10 AND quota.quota_reservation_id = $11
	  AND quota.charged_units IS NULL AND quota.released_units IS NULL
	  AND quota.settled_at IS NULL
	  AND expected.allocated_units > 0
	  AND expected.charged_units BETWEEN 0 AND expected.allocated_units
`

const insertInitialAttemptUsageSQL = `
	INSERT INTO usage_records (
		usage_record_id, organization_id, application_id, environment_id,
		logical_request_id, upstream_attempt_id, metric, units,
		confidence, provenance_key, recorded_at
	)
	SELECT usage.usage_id, $1, $2, $3, $4, $5,
	       usage.metric, usage.units, 'reported', usage.provenance_key, $10
	FROM unnest($6::text[], $7::text[], $8::bigint[], $9::text[])
		AS usage(usage_id, metric, units, provenance_key)
`

const completeInitialAttemptSQL = `
	UPDATE upstream_attempts
	SET status = 'succeeded',
	    completed_at = GREATEST(started_at, first_byte_at, COALESCE(first_token_at, first_byte_at), $4),
	    http_status = $5,
	    failure_code = NULL,
	    billed_cost_nano_usd = NULL,
	    cost_confidence = NULL
	WHERE upstream_attempt_id = $1 AND logical_request_id = $2
	  AND attempt_number = 1 AND status = 'started'
	  AND first_byte_at = $3 AND completed_at IS NULL
	  AND currency IS NULL AND price_revision IS NULL AND pricing_source IS NULL
	  AND billed_cost_nano_usd IS NULL AND cost_confidence IS NULL
`

const insertInitialLogicalUsageSQL = `
	INSERT INTO usage_records (
		usage_record_id, organization_id, application_id, environment_id,
		logical_request_id, upstream_attempt_id, metric, units,
		confidence, provenance_key, recorded_at
	) VALUES ($1, $2, $3, $4, $5, NULL, 'logical_requests', 1,
	          'calculated', $6, $7)
`

const completeInitialLogicalRequestSQL = `
	UPDATE logical_requests
	SET status = 'succeeded',
	    completed_at = GREATEST(requested_at, dispatched_at, $5),
	    failure_code = NULL
	WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
	  AND logical_request_id = $4 AND status = 'streaming'
`

const completeInitialReservationSQL = `
	UPDATE quota_reservations
	SET status = 'settled', settled_at = GREATEST(created_at, $2)
	WHERE quota_reservation_id = $1 AND status = 'pending'
`

type initialFinalWriteOperation struct {
	operation string
	wantRows  int64
	mapWrite  bool
}

func writeInitialFinalSettlement(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logical lockedLogical,
	state initialFinalSettlementState,
	usageIDs settlementUsageIDs,
	now time.Time,
) error {
	bucketIDs := make([]string, 0, len(state.tokenEntries))
	metrics := make([]string, 0, len(state.tokenEntries))
	entryIDs := make([]string, 0, len(state.tokenEntries))
	charged := make([]int64, 0, len(state.tokenEntries))
	allocated := make([]int64, 0, len(state.tokenEntries))
	used := make([]int64, 0, len(state.tokenEntries))
	reserved := make([]int64, 0, len(state.tokenEntries))
	hardMaximum := make([]int64, 0, len(state.tokenEntries))
	for _, item := range state.tokenEntries {
		bucketIDs = append(bucketIDs, item.entry.bucketID)
		metrics = append(metrics, item.entry.metric)
		entryIDs = append(entryIDs, item.entry.id)
		charged = append(charged, item.charged)
		allocated = append(allocated, item.entry.reservedUnits)
		used = append(used, item.entry.bucketUsed)
		reserved = append(reserved, item.entry.bucketReserved)
		hardMaximum = append(hardMaximum, *item.entry.hardMaximum)
	}
	quotaEntryIDs := make([]string, 0, len(state.quotaEntries))
	quotaBucketIDs := make([]string, 0, len(state.quotaEntries))
	quotaMetrics := make([]string, 0, len(state.quotaEntries))
	quotaAllocated := make([]int64, 0, len(state.quotaEntries))
	quotaCharged := make([]int64, 0, len(state.quotaEntries))
	chargedByMetric := make(map[string]int64, len(state.tokenEntries))
	for _, item := range state.tokenEntries {
		chargedByMetric[item.entry.metric] = item.charged
	}
	for _, entry := range state.quotaEntries {
		value, ok := chargedByMetric[entry.metric]
		if !ok {
			return ErrInvalidState
		}
		quotaEntryIDs = append(quotaEntryIDs, entry.entryID)
		quotaBucketIDs = append(quotaBucketIDs, entry.bucketID)
		quotaMetrics = append(quotaMetrics, entry.metric)
		quotaAllocated = append(quotaAllocated, entry.allocated)
		quotaCharged = append(quotaCharged, value)
	}
	logicalBucketIDs := make([]string, 0, len(state.logicalEntries))
	logicalMetrics := make([]string, 0, len(state.logicalEntries))
	logicalEntryIDs := make([]string, 0, len(state.logicalEntries))
	logicalCharged := make([]int64, 0, len(state.logicalEntries))
	logicalAllocated := make([]int64, 0, len(state.logicalEntries))
	logicalUsed := make([]int64, 0, len(state.logicalEntries))
	logicalReserved := make([]int64, 0, len(state.logicalEntries))
	logicalHardMaximum := make([]int64, 0, len(state.logicalEntries))
	for _, entry := range state.logicalEntries {
		logicalBucketIDs = append(logicalBucketIDs, entry.bucketID)
		logicalMetrics = append(logicalMetrics, entry.metric)
		logicalEntryIDs = append(logicalEntryIDs, entry.id)
		logicalCharged = append(logicalCharged, 1)
		logicalAllocated = append(logicalAllocated, 1)
		logicalUsed = append(logicalUsed, entry.bucketUsed)
		logicalReserved = append(logicalReserved, entry.bucketReserved)
		logicalHardMaximum = append(logicalHardMaximum, *entry.hardMaximum)
	}

	batch := &pgx.Batch{}
	operations := make([]initialFinalWriteOperation, 0, 10)
	queue := func(operation string, wantRows int64, mapWrite bool, sql string, arguments ...any) {
		batch.Queue(sql, arguments...)
		operations = append(operations, initialFinalWriteOperation{
			operation: operation, wantRows: wantRows, mapWrite: mapWrite,
		})
	}
	queue(
		"settle initial calendar quota buckets", int64(len(state.tokenEntries)), false,
		settleInitialCalendarBucketsSQL,
		bucketIDs, metrics, charged, allocated, used, reserved, hardMaximum, now,
	)
	queue(
		"settle initial quota reservation entries", int64(len(state.tokenEntries)), false,
		settleInitialReservationEntriesSQL, entryIDs, allocated, charged,
	)
	queue(
		"settle initial upstream attempt quota entries", int64(len(state.quotaEntries)), false,
		settleInitialAttemptQuotaEntriesSQL,
		quotaEntryIDs, quotaBucketIDs, quotaMetrics, quotaAllocated, quotaCharged,
		reservation.organizationID, reservation.applicationID, reservation.environmentID,
		reservation.logicalRequestID, state.attempt.id, reservation.reservationID, now,
	)
	queue(
		"insert initial attempt usage", int64(len(reservedTokenMetricOrder)), true,
		insertInitialAttemptUsageSQL,
		reservation.organizationID, reservation.applicationID, reservation.environmentID,
		reservation.logicalRequestID, state.attempt.id,
		[]string{usageIDs.providerInput, usageIDs.providerOutput, usageIDs.providerTotal},
		[]string{InputTokensMetric, OutputTokensMetric, TotalTokensMetric},
		[]int64{
			state.outcome.Usage.InputTokens,
			state.outcome.Usage.OutputTokens,
			state.outcome.Usage.TotalTokens,
		},
		[]string{
			providerUsageProvenanceKey(state.attempt.id, InputTokensMetric),
			providerUsageProvenanceKey(state.attempt.id, OutputTokensMetric),
			providerUsageProvenanceKey(state.attempt.id, TotalTokensMetric),
		},
		now,
	)
	queue(
		"complete initial upstream attempt", 1, false, completeInitialAttemptSQL,
		state.attempt.id, reservation.logicalRequestID, *state.attempt.firstByteAt,
		now, state.outcome.HTTPStatus,
	)
	queue(
		"settle initial logical quota buckets", int64(len(state.logicalEntries)), false,
		settleInitialCalendarBucketsSQL,
		logicalBucketIDs, logicalMetrics, logicalCharged, logicalAllocated,
		logicalUsed, logicalReserved, logicalHardMaximum, now,
	)
	queue(
		"settle initial logical quota entries", int64(len(state.logicalEntries)), false,
		settleInitialReservationEntriesSQL,
		logicalEntryIDs, logicalAllocated, logicalCharged,
	)
	queue(
		"insert initial logical usage", 1, true, insertInitialLogicalUsageSQL,
		usageIDs.logical, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		logicalUsageProvenanceKey(reservation.logicalRequestID), now,
	)
	queue(
		"complete initial logical request", 1, false, completeInitialLogicalRequestSQL,
		reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID, now,
	)
	queue(
		"complete initial quota reservation", 1, false, completeInitialReservationSQL,
		reservation.reservationID, now,
	)

	results := tx.SendBatch(ctx, batch)
	for _, operation := range operations {
		command, err := results.Exec()
		if err != nil {
			_ = results.Close()
			if operation.mapWrite {
				return mapWriteError(operation.operation, err)
			}
			return persistenceFailure(operation.operation, err)
		}
		if command.RowsAffected() != operation.wantRows {
			if closeErr := results.Close(); closeErr != nil {
				return persistenceFailure("complete initial settlement write batch", closeErr)
			}
			return ErrInvalidState
		}
	}
	if err := results.Close(); err != nil {
		return persistenceFailure("complete initial settlement write batch", err)
	}
	return nil
}
