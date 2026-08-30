package quota

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/limitscope"
	"github.com/latchway/latchway/internal/protocol"
)

// SettleForRetry durably completes a failed or timed-out attempt while
// leaving the logical request, its one request-count reservation, and its
// concurrency leases open. Token and cost allocations are charged or
// released before this method returns, so a later retry must reserve its own
// capacity before dispatch.
func (store *Store) SettleForRetry(ctx context.Context, attempt Attempt, outcome Outcome) error {
	if outcome.Status != AttemptFailed && outcome.Status != AttemptTimedOut {
		return ErrInvalidInput
	}
	return store.settleRetryLifecycle(ctx, attempt, outcome, false)
}

// SettleFinalAttempt completes the last attempt and then finalizes the one
// logical reservation. It is separate from Settle so the existing single-
// attempt data-plane remains source-compatible until the route executor opts
// into retry lifecycle methods.
func (store *Store) SettleFinalAttempt(ctx context.Context, attempt Attempt, outcome Outcome) error {
	if store != nil && store.pool != nil && store.newID != nil && ctx != nil &&
		attempt.number == 1 && attempt.validate() == nil && outcome.validate() == nil {
		handled, err := store.settleInitialFinalAttempt(ctx, attempt, outcome)
		if handled {
			return err
		}
	}
	return store.settleRetryLifecycle(ctx, attempt, outcome, true)
}

func prepareRetryRuleSet(
	reservation Reservation,
	input RetryAttemptInput,
) (preparedRequest, map[string]int64, error) {
	plan := reservation.retryPlan
	if plan == nil || id.Validate(plan.applicationUserID, id.ApplicationUser) != nil ||
		id.Validate(plan.installationID, id.Installation) != nil ||
		id.Validate(plan.sessionGrantID, id.SessionGrant) != nil ||
		id.Validate(plan.configRevisionID, id.ConfigRevision) != nil ||
		!identifierPattern.MatchString(plan.featureKey) ||
		!identifierPattern.MatchString(plan.limitPlanKey) ||
		len(plan.rules) < 1 || len(plan.rules) > maximumRulesPerRequest {
		return preparedRequest{}, nil, ErrInvalidInput
	}
	if !validComponentAttribution(
		plan.installationFamilyID, plan.clientComponentID,
		plan.componentDefinitionID, plan.componentKind, plan.trustSource,
	) {
		return preparedRequest{}, nil, ErrInvalidInput
	}
	allocations := make(map[string]int64, len(input.Allocations))
	for _, allocation := range input.Allocations {
		allocations[allocation.Metric] = allocation.Units
	}
	rules := cloneLimitRules(plan.rules)
	expectedMetrics := make(map[string]struct{}, len(allocations))
	for index := range rules {
		if attemptAllocationOrder(rules[index].Metric) == math.MaxInt {
			continue
		}
		units, ok := allocations[rules[index].Metric]
		if !ok {
			return preparedRequest{}, nil, ErrInvalidInput
		}
		rules[index].ReservedUnits = units
		expectedMetrics[rules[index].Metric] = struct{}{}
	}
	if len(expectedMetrics) != len(allocations) {
		return preparedRequest{}, nil, ErrInvalidInput
	}
	values, err := quotaScopeValues(map[string]string{
		"organization":                          reservation.organizationID,
		"application":                           reservation.applicationID,
		"environment":                           reservation.environmentID,
		"user":                                  plan.applicationUserID,
		"installation":                          plan.installationID,
		limitscope.InstallationFamilyDimension:  plan.installationFamilyID,
		limitscope.ClientComponentDimension:     plan.clientComponentID,
		limitscope.ComponentDefinitionDimension: plan.componentDefinitionID,
		limitscope.ComponentKindDimension:       plan.componentKind,
		limitscope.TrustSourceDimension:         plan.trustSource,
		"feature":                               plan.featureKey,
		"route":                                 input.RouteKey,
		"upstream":                              input.UpstreamKey,
		"model":                                 input.ModelKey,
	}, plan.platform, plan.claimDigests)
	if err != nil {
		return preparedRequest{}, nil, err
	}
	preparedRules, err := prepareRules(rules, values, reserveRulePreparation)
	if err != nil {
		return preparedRequest{}, nil, err
	}
	preflight, err := prepareInputPreflight(
		input.InputPreflight, reservation.protocol, input.PhysicalModel, preparedRules,
	)
	if err != nil {
		return preparedRequest{}, nil, err
	}
	measurements, err := prepareRequestMeasurements(
		input.RequestMeasurements, reservation.protocol, preparedRules,
	)
	if err != nil || preflight != nil && measurements != nil &&
		preflight.RewrittenBodySHA256 != measurements.RewrittenBodySHA256 {
		return preparedRequest{}, nil, ErrInvalidInput
	}
	prepared := preparedRequest{ReserveInput: ReserveInput{
		OrganizationID:         reservation.organizationID,
		ApplicationID:          reservation.applicationID,
		EnvironmentID:          reservation.environmentID,
		ApplicationUserID:      plan.applicationUserID,
		InstallationID:         plan.installationID,
		InstallationFamilyID:   plan.installationFamilyID,
		ClientComponentID:      plan.clientComponentID,
		ComponentDefinitionID:  plan.componentDefinitionID,
		ComponentKind:          plan.componentKind,
		TrustSource:            plan.trustSource,
		SessionGrantID:         plan.sessionGrantID,
		ConfigRevisionID:       plan.configRevisionID,
		Platform:               plan.platform,
		NormalizedClaimDigests: cloneStringMap(plan.claimDigests),
		FeatureKey:             plan.featureKey,
		Protocol:               reservation.protocol,
		LimitPlanKey:           plan.limitPlanKey,
		RouteKey:               input.RouteKey,
		UpstreamKey:            input.UpstreamKey,
		ModelKey:               input.ModelKey,
		PhysicalModel:          input.PhysicalModel,
		Pricing:                input.Pricing,
		InputPreflight:         preflight,
		RequestMeasurements:    measurements,
		Streaming:              plan.streaming,
		Rules:                  clonePreparedRules(preparedRules),
	}, rules: preparedRules}
	return prepared, allocations, nil
}

func retryTargetPlansAt(prepared preparedRequest, at time.Time) ([]plannedBucket, error) {
	plans, err := plannedBucketsAt(prepared, at)
	if err != nil {
		return nil, err
	}
	result := make([]plannedBucket, 0, len(plans))
	for _, plan := range plans {
		// A logical request is charged exactly once. Candidate-target materialization
		// applies only to per-dispatch token/cost capacity and target concurrency.
		if plan.rule.Metric != LogicalRequestsMetric {
			result = append(result, plan)
		}
	}
	return result, nil
}

func perRequestOutputTokenBound(rules []Rule) (*int64, error) {
	var result *int64
	for _, rule := range rules {
		if rule.Metric != OutputTokensMetric || rule.Algorithm != PerRequestAlgorithm {
			continue
		}
		if result != nil && *result != rule.ReservedUnits {
			return nil, ErrInvalidState
		}
		value := rule.ReservedUnits
		result = &value
	}
	return result, nil
}

func resolveRetryTargetPlans(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	plans []plannedBucket,
) ([]plannedBucket, error) {
	for index := range plans {
		bucketID, err := findBucketID(ctx, tx, prepared, plans[index])
		if err != nil {
			return nil, err
		}
		plans[index].bucketID = bucketID
	}
	sort.Slice(plans, func(left, right int) bool { return plans[left].bucketID < plans[right].bucketID })
	for index := 1; index < len(plans); index++ {
		if plans[index-1].bucketID == plans[index].bucketID {
			return nil, ErrInvalidState
		}
	}
	return plans, nil
}

type retryMaterialization struct {
	plans      []plannedBucket
	newEntries map[string]struct{}
	leaseIDs   map[string]string
}

func (store *Store) materializeRetryTarget(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	prepared preparedRequest,
	plans []plannedBucket,
	originAttempt int32,
	now time.Time,
) (retryMaterialization, error) {
	if originAttempt < 2 || originAttempt > maximumAttemptsPerRequest ||
		len(plans) > maximumRulesPerRequest {
		return retryMaterialization{}, ErrInvalidInput
	}
	for index := range plans {
		bucketID, err := store.newID(id.QuotaBucket)
		if err != nil {
			return retryMaterialization{}, fmt.Errorf("generate retry quota-bucket identifier: %w", err)
		}
		plans[index].bucketID = bucketID
		plan := &plans[index]
		hardMaximum := plan.rule.Maximum
		var availableUnits, refillNumerator, refillDenominator, refilledAt any
		if plan.rule.Algorithm == TokenBucketAlgorithm {
			maximumBalance, ok := tokenCapacityBalance(plan.rule.Capacity)
			if !ok {
				return retryMaterialization{}, ErrInvalidInput
			}
			hardMaximum = plan.rule.Capacity
			availableUnits = maximumBalance
			refillNumerator = plan.rule.RefillNumerator
			refillDenominator = plan.rule.RefillDenominator
			refilledAt = now
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO quota_buckets (
				quota_bucket_id, organization_id, application_id, environment_id,
				limit_plan_key, rule_key, metric, scope_type, scope_dimensions,
				scope_key, algorithm, window_key, hard_maximum,
				used_units, reserved_units, available_units, refill_numerator,
				refill_denominator, refilled_at, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9::text[], $10, $11, $12,
				$13, 0, 0, $14, $15, $16, $17, $18, $18
			)
			ON CONFLICT ON CONSTRAINT quota_buckets_identity_key DO NOTHING
		`, plan.bucketID, prepared.OrganizationID, prepared.ApplicationID,
			prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
			plan.rule.Metric, plan.rule.scopeType, plan.rule.scopeDimensions,
			plan.rule.scopeKey, plan.rule.Algorithm, plan.period.key,
			hardMaximum, availableUnits, refillNumerator, refillDenominator,
			refilledAt, now); err != nil {
			return retryMaterialization{}, mapWriteError("materialize retry quota bucket", err)
		}
	}
	plans, err := resolveRetryTargetPlans(ctx, tx, prepared, plans)
	if err != nil {
		return retryMaterialization{}, err
	}
	newEntries := make(map[string]struct{})
	leaseIDs := make(map[string]string)
	var existingCount int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM quota_reservation_entries
		WHERE organization_id = $1 AND application_id = $2
		  AND environment_id = $3 AND quota_reservation_id = $4
	`, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.reservationID).Scan(&existingCount); err != nil {
		return retryMaterialization{}, persistenceFailure("count retry reservation entries", err)
	}
	for index := range plans {
		plan := &plans[index]
		var existingEntryID string
		err := tx.QueryRow(ctx, `
			SELECT quota_reservation_entry_id
			FROM quota_reservation_entries
			WHERE environment_id = $1 AND quota_reservation_id = $2
			  AND quota_bucket_id = $3
		`, reservation.environmentID, reservation.reservationID, plan.bucketID).Scan(&existingEntryID)
		if err == nil {
			if id.Validate(existingEntryID, id.QuotaEntry) != nil {
				return retryMaterialization{}, ErrInvalidState
			}
			plan.entryID = existingEntryID
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return retryMaterialization{}, persistenceFailure("find retry reservation entry", err)
		}
		if existingCount+int64(len(newEntries)) >= int64(maximumReservationEntries) {
			return retryMaterialization{}, ErrInvalidState
		}
		entryID, err := store.newID(id.QuotaEntry)
		if err != nil {
			return retryMaterialization{}, fmt.Errorf("generate retry quota-entry identifier: %w", err)
		}
		plan.entryID = entryID
		if _, err := tx.Exec(ctx, `
			INSERT INTO quota_reservation_entries (
				quota_reservation_entry_id, organization_id, application_id,
				environment_id, quota_reservation_id, quota_bucket_id,
				origin_attempt_number, initial_reserved_units, reserved_units,
				settled_units, released_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, 0, 0)
		`, entryID, reservation.organizationID, reservation.applicationID,
			reservation.environmentID, reservation.reservationID, plan.bucketID,
			originAttempt, plan.reservedUnits); err != nil {
			return retryMaterialization{}, mapWriteError("insert retry reservation entry", err)
		}
		newEntries[entryID] = struct{}{}
		if isConcurrencyMetric(plan.rule.Metric) {
			leaseID, err := store.newID(id.ConcurrencyLease)
			if err != nil {
				return retryMaterialization{}, fmt.Errorf("generate retry concurrency-lease identifier: %w", err)
			}
			leaseIDs[plan.bucketID] = leaseID
		}
	}
	return retryMaterialization{plans: plans, newEntries: newEntries, leaseIDs: leaseIDs}, nil
}

// BeginRetryAttempt atomically reserves the next attempt's trusted token and
// cost allocations and records its physical target. The returned owner is the
// only caller permitted to dispatch. Replaying the exact previous-attempt and
// input pair returns the same attempt with owner false.
func (store *Store) BeginRetryAttempt(
	ctx context.Context,
	previous Attempt,
	input RetryAttemptInput,
) (Attempt, bool, error) {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil ||
		previous.validate() != nil || previous.number >= maximumAttemptsPerRequest {
		return Attempt{}, false, ErrInvalidInput
	}
	preparedInput, err := prepareRetryAttemptInput(input)
	if err != nil {
		return Attempt{}, false, err
	}
	prepared, allocationByMetric, err := prepareRetryRuleSet(previous.reservation, preparedInput)
	if err != nil {
		return Attempt{}, false, err
	}
	nextNumber := previous.number + 1
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Attempt{}, false, persistenceFailure("begin retry attempt", err)
	}
	defer rollback(tx)
	reservation, err := lockReservation(ctx, tx, previous.reservation)
	if err != nil {
		return Attempt{}, false, err
	}
	logical, err := lockLogicalRequest(ctx, tx, previous.reservation)
	if err != nil {
		return Attempt{}, false, err
	}
	attempts, err := loadAttemptsForUpdate(ctx, tx, previous.reservation.logicalRequestID)
	if err != nil {
		return Attempt{}, false, err
	}
	if previous.number > int32(len(attempts)) ||
		attempts[previous.number-1].id != previous.attemptID {
		return Attempt{}, false, ErrNotFound
	}
	storedPrevious := attempts[previous.number-1]
	if previous.number == 1 &&
		(!storedInitialInputPreflightMatches(storedPrevious, previous.reservation.inputPreflight) ||
			!storedInitialRequestMeasurementsMatch(storedPrevious, previous.reservation.requestMeasurements)) {
		return Attempt{}, false, ErrInvalidState
	}
	if logical.protocol != prepared.Protocol || logical.configRevisionID != prepared.ConfigRevisionID {
		return Attempt{}, false, ErrInvalidState
	}
	targetPlans, err := retryTargetPlansAt(prepared, logical.requestedAt.UTC())
	if err != nil {
		return Attempt{}, false, err
	}
	if err := validateRetryInputPreflight(
		preparedInput, logical.protocol, allocationByMetric,
	); err != nil {
		return Attempt{}, false, err
	}
	perRequestOutputBound, err := perRequestOutputTokenBound(prepared.Rules)
	if err != nil {
		return Attempt{}, false, err
	}
	var storedNext storedAttempt
	nextFound := nextNumber <= int32(len(attempts))
	if nextFound {
		storedNext = attempts[nextNumber-1]
		targetPlans, err = resolveRetryTargetPlans(ctx, tx, prepared, targetPlans)
		if err != nil {
			return Attempt{}, false, err
		}
		entries, lockErr := lockEntries(ctx, tx, reservation)
		if lockErr != nil {
			return Attempt{}, false, lockErr
		}
		leases, lockErr := lockConcurrencyLeases(ctx, tx, reservation, entries)
		if lockErr != nil {
			return Attempt{}, false, lockErr
		}
		previousQuota, loadErr := loadAttemptQuotaEntriesForUpdate(
			ctx, tx, reservation, storedPrevious,
		)
		if loadErr != nil {
			return Attempt{}, false, loadErr
		}
		if (storedPrevious.status != AttemptFailed && storedPrevious.status != AttemptTimedOut) ||
			!attemptQuotaEntriesSettled(previousQuota) ||
			!attemptQuotaEntriesMatchReservation(reservation, storedPrevious, previousQuota, entries) {
			return Attempt{}, false, ErrInvalidState
		}
		targetEntries, targetErr := retryTargetEntries(prepared, targetPlans, entries, nextNumber)
		if targetErr != nil {
			return Attempt{}, false, targetErr
		}
		if nextNumber != storedNext.number || !retryAttemptMatches(
			storedNext, preparedInput, logical.configRevisionID, perRequestOutputBound,
		) {
			return Attempt{}, false, ErrInvalidState
		}
		nextQuota, loadErr := loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, storedNext)
		if loadErr != nil {
			return Attempt{}, false, loadErr
		}
		if !attemptQuotaAllocationsMatch(
			reservation, storedNext, nextQuota, allocationByMetric, targetEntries,
		) {
			return Attempt{}, false, ErrInvalidState
		}
		switch reservation.status {
		case "pending":
			lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
				ctx, tx, reservation, logical.status, entries, attempts,
			)
			if lifecycleErr != nil {
				return Attempt{}, false, lifecycleErr
			}
			if !pendingEntriesMatch(logical.status, reservation, entries, leases) ||
				!lifecycleMatches {
				return Attempt{}, false, ErrInvalidState
			}
		case "settled":
			aggregateMatches, aggregateErr := retryAggregateMatchesEntries(
				ctx, tx, reservation, entries,
			)
			if aggregateErr != nil {
				return Attempt{}, false, aggregateErr
			}
			logicalUsageMatches, usageErr := logicalUsageRecordMatches(ctx, tx, reservation)
			if usageErr != nil {
				return Attempt{}, false, usageErr
			}
			accountingMatches, accountingErr := terminalAttemptAccountingSequenceMatches(
				ctx, tx, reservation, logical.status, entries, attempts,
			)
			if accountingErr != nil {
				return Attempt{}, false, accountingErr
			}
			if !terminalEntriesMatch(logical.status, reservation.status, entries, leases) ||
				!aggregateMatches || !logicalUsageMatches || !accountingMatches {
				return Attempt{}, false, ErrInvalidState
			}
		default:
			return Attempt{}, false, ErrInvalidState
		}
		return Attempt{
			reservation: previous.reservation,
			attemptID:   storedNext.id,
			number:      nextNumber,
		}, false, nil
	}
	if requestBoundsExceeded := requestBoundExceededRules(prepared.rules); len(requestBoundsExceeded) != 0 {
		return Attempt{}, false, requestBoundExceededError(
			reservation.logicalRequestID, requestBoundsExceeded,
		)
	}
	materializedAt, err := transactionTime(ctx, tx)
	if err != nil {
		return Attempt{}, false, err
	}
	materialized, err := store.materializeRetryTarget(
		ctx, tx, reservation, prepared, targetPlans, nextNumber, materializedAt,
	)
	if err != nil {
		return Attempt{}, false, err
	}
	entries, err := lockEntries(ctx, tx, reservation)
	if err != nil {
		return Attempt{}, false, err
	}
	priorEntries := entriesBeforeAttempt(entries, nextNumber)
	priorLeases, err := lockConcurrencyLeases(ctx, tx, reservation, priorEntries)
	if err != nil {
		return Attempt{}, false, err
	}
	previousQuota, err := loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, storedPrevious)
	if err != nil {
		return Attempt{}, false, err
	}
	if (storedPrevious.status != AttemptFailed && storedPrevious.status != AttemptTimedOut) ||
		!attemptQuotaEntriesSettled(previousQuota) ||
		!attemptQuotaEntriesMatchReservation(reservation, storedPrevious, previousQuota, priorEntries) {
		return Attempt{}, false, ErrInvalidState
	}
	lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
		ctx, tx, reservation, logical.status, priorEntries, attempts,
	)
	if lifecycleErr != nil {
		return Attempt{}, false, lifecycleErr
	}
	if int32(len(attempts)) != previous.number || reservation.status != "pending" ||
		(logical.status != "dispatched" && logical.status != "streaming") ||
		!pendingEntriesMatch(logical.status, reservation, priorEntries, priorLeases) ||
		!lifecycleMatches {
		return Attempt{}, false, ErrInvalidState
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return Attempt{}, false, err
	}
	if !reservation.expiresAt.After(now) {
		return Attempt{}, false, ErrExpired
	}
	targetEntries, err := retryTargetEntries(
		prepared, materialized.plans, entries, nextNumber,
	)
	if err != nil {
		return Attempt{}, false, err
	}
	if err := reserveRetryAllocations(
		ctx, tx, reservation.logicalRequestID, targetEntries, materialized.plans, allocationByMetric,
		materialized.newEntries, now,
	); err != nil {
		return Attempt{}, false, err
	}
	if err := reserveRetryConcurrency(
		ctx, tx, reservation, targetEntries, materialized.plans, materialized.newEntries,
		materialized.leaseIDs, now,
	); err != nil {
		return Attempt{}, false, err
	}
	attemptID, err := store.newID(id.UpstreamAttempt)
	if err != nil {
		return Attempt{}, false, fmt.Errorf("generate retry upstream-attempt identifier: %w", err)
	}
	pricing := retrySelectedPricing(preparedInput.Pricing, logical.configRevisionID)
	var accountingMethod, accountingProfileID, accountingProfileDigest any
	var rewrittenBodyDigest, inputBound, outputBound, totalBound any
	if preparedInput.InputPreflight != nil {
		binding := preparedInput.InputPreflight
		accountingMethod = binding.Method
		accountingProfileID = binding.ProfileID
		accountingProfileDigest = binding.ProfileDigest[:]
		rewrittenBodyDigest = binding.RewrittenBodySHA256[:]
		inputBound = binding.InputTokenBound
		outputBound = binding.OutputTokenBound
		totalBound = binding.TotalTokenBound
	}
	decisionAttempt := newStoredAttemptDecision(
		attemptID, nextNumber, preparedInput.RouteKey, preparedInput.UpstreamKey,
		preparedInput.ModelKey, preparedInput.PhysicalModel, pricing,
		preparedInput.InputPreflight, preparedInput.RequestMeasurements, perRequestOutputBound,
	)
	decisionDigest, err := attemptDecisionDigest(
		reservation, decisionAttempt,
		attemptQuotaRowsForDecision(targetEntries, allocationByMetric),
	)
	if err != nil {
		return Attempt{}, false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO upstream_attempts (
			upstream_attempt_id, organization_id, application_id, environment_id,
			logical_request_id, attempt_number, route_key, upstream_key,
			physical_model, model_key, attempt_decision_binding_version,
			attempt_decision_sha256, per_request_output_token_bound,
			input_accounting_binding_version,
			status, started_at, currency, price_revision, pricing_source,
			cost_confidence, input_accounting_method,
			input_accounting_profile_id, input_accounting_profile_digest,
			rewritten_body_sha256, input_token_bound, output_token_bound,
			total_token_bound, request_measurement_binding_version,
			request_measurement_sha256, measured_request_bytes,
			measured_image_units, measured_tool_calls
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 2, $11, $12, 1,
			'started', $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
			1, $25, $26, $27, $28
		)
	`, attemptID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID, nextNumber,
		preparedInput.RouteKey, preparedInput.UpstreamKey, preparedInput.PhysicalModel,
		preparedInput.ModelKey, decisionDigest[:], perRequestOutputBound, now,
		nullableString(pricing.currency), nullableString(pricing.revision),
		nullableString(pricing.source), nullableString(initialCostConfidence(pricing)),
		accountingMethod, accountingProfileID, accountingProfileDigest,
		rewrittenBodyDigest, inputBound, outputBound, totalBound,
		decisionAttempt.requestMeasurementSHA256,
		decisionAttempt.measuredRequestBytes, decisionAttempt.measuredImageUnits,
		decisionAttempt.measuredToolCalls); err != nil {
		return Attempt{}, false, mapWriteError("insert retry upstream attempt", err)
	}
	if err := insertAttemptQuotaEntries(
		ctx, tx, reservation, attemptID, targetEntries, allocationByMetric,
	); err != nil {
		return Attempt{}, false, err
	}
	entries, err = lockEntries(ctx, tx, reservation)
	if err != nil {
		return Attempt{}, false, err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, reservation, entries)
	if err != nil {
		return Attempt{}, false, err
	}
	attempts, err = loadAttemptsForUpdate(ctx, tx, reservation.logicalRequestID)
	if err != nil {
		return Attempt{}, false, err
	}
	lifecycleMatches, lifecycleErr = retryPendingLifecycleMatches(
		ctx, tx, reservation, logical.status, entries, attempts,
	)
	if lifecycleErr != nil {
		return Attempt{}, false, lifecycleErr
	}
	if !pendingEntriesMatch(logical.status, reservation, entries, leases) || !lifecycleMatches {
		return Attempt{}, false, ErrInvalidState
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, false, persistenceFailure("commit retry attempt", err)
	}
	return Attempt{
		reservation: previous.reservation,
		attemptID:   attemptID,
		number:      nextNumber,
	}, true, nil
}

type lockedAttemptQuotaEntry struct {
	entryID   string
	bucketID  string
	metric    string
	allocated int64
	charged   *int64
	released  *int64
	settledAt *time.Time
}

func newStoredAttemptDecision(
	attemptID string,
	number int32,
	routeKey string,
	upstreamKey string,
	modelKey string,
	physicalModel string,
	pricing selectedPricing,
	binding *InputPreflightBinding,
	measurements *RequestMeasurementBinding,
	perRequestOutputBound *int64,
) storedAttempt {
	physicalModelCopy := physicalModel
	modelKeyCopy := modelKey
	result := storedAttempt{
		id: attemptID, number: number, routeKey: routeKey, upstreamKey: upstreamKey,
		physicalModel: &physicalModelCopy, modelKey: &modelKeyCopy,
		attemptDecisionBindingVersion: 2, inputAccountingBindingVersion: 1,
		requestMeasurementBindingVersion: 1,
	}
	if perRequestOutputBound != nil {
		value := *perRequestOutputBound
		result.perRequestOutputTokenBound = &value
	}
	if pricing.present() {
		currency, revision, source := pricing.currency, pricing.revision, pricing.source
		confidence := initialCostConfidence(pricing)
		result.currency = &currency
		result.priceRevision = &revision
		result.pricingSource = &source
		result.costConfidence = &confidence
	}
	if binding != nil {
		method, profileID := binding.Method, binding.ProfileID
		input, output, total := binding.InputTokenBound, binding.OutputTokenBound, binding.TotalTokenBound
		result.inputAccountingMethod = &method
		result.inputAccountingProfileID = &profileID
		result.inputAccountingProfileDigest = append([]byte(nil), binding.ProfileDigest[:]...)
		result.rewrittenBodySHA256 = append([]byte(nil), binding.RewrittenBodySHA256[:]...)
		result.inputTokenBound = &input
		result.outputTokenBound = &output
		result.totalTokenBound = &total
	}
	if measurements != nil {
		requestBytes := measurements.RequestBytes
		result.requestMeasurementSHA256 = append(
			[]byte(nil), measurements.RewrittenBodySHA256[:]...,
		)
		result.measuredRequestBytes = &requestBytes
		if measurements.ImageUnitsKnown {
			imageUnits := measurements.ImageUnits
			result.measuredImageUnits = &imageUnits
		}
		if measurements.ToolCallsKnown {
			toolCalls := measurements.ToolCalls
			result.measuredToolCalls = &toolCalls
		}
	}
	return result
}

func attemptQuotaRowsForDecision(
	entries []lockedEntry,
	allocations map[string]int64,
) []lockedAttemptQuotaEntry {
	result := make([]lockedAttemptQuotaEntry, 0, len(entries))
	for _, entry := range entries {
		units, ok := allocations[entry.metric]
		if !ok {
			continue
		}
		result = append(result, lockedAttemptQuotaEntry{
			entryID: entry.id, bucketID: entry.bucketID, metric: entry.metric, allocated: units,
		})
	}
	return result
}

func attemptDecisionDigest(
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
) ([sha256.Size]byte, error) {
	pricing, err := attempt.selectedPricing()
	if err != nil || attempt.physicalModel == nil || attempt.modelKey == nil {
		return [sha256.Size]byte{}, ErrInvalidState
	}
	optionalStringValue := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	optionalInt64Value := func(value *int64) string {
		if value == nil {
			return ""
		}
		return strconv.FormatInt(*value, 10)
	}
	rows := append([]lockedAttemptQuotaEntry(nil), quotaEntries...)
	sort.Slice(rows, func(left, right int) bool {
		if rows[left].entryID != rows[right].entryID {
			return rows[left].entryID < rows[right].entryID
		}
		if rows[left].bucketID != rows[right].bucketID {
			return rows[left].bucketID < rows[right].bucketID
		}
		return rows[left].metric < rows[right].metric
	})
	parts := []string{
		strconv.FormatInt(int64(attempt.attemptDecisionBindingVersion), 10),
		reservation.organizationID,
		reservation.applicationID,
		reservation.environmentID,
		reservation.logicalRequestID,
		reservation.reservationID,
		attempt.id,
		strconv.FormatInt(int64(attempt.number), 10),
		attempt.routeKey,
		attempt.upstreamKey,
		*attempt.modelKey,
		*attempt.physicalModel,
		pricing.source,
		pricing.currency,
		pricing.revision,
		optionalInt64Value(attempt.perRequestOutputTokenBound),
		strconv.FormatInt(int64(attempt.inputAccountingBindingVersion), 10),
		optionalStringValue(attempt.inputAccountingMethod),
		optionalStringValue(attempt.inputAccountingProfileID),
		base64.RawURLEncoding.EncodeToString(attempt.inputAccountingProfileDigest),
		base64.RawURLEncoding.EncodeToString(attempt.rewrittenBodySHA256),
		optionalInt64Value(attempt.inputTokenBound),
		optionalInt64Value(attempt.outputTokenBound),
		optionalInt64Value(attempt.totalTokenBound),
	}
	if attempt.attemptDecisionBindingVersion >= 2 {
		parts = append(parts,
			strconv.FormatInt(int64(attempt.requestMeasurementBindingVersion), 10),
			base64.RawURLEncoding.EncodeToString(attempt.requestMeasurementSHA256),
			optionalInt64Value(attempt.measuredRequestBytes),
			optionalInt64Value(attempt.measuredImageUnits),
			optionalInt64Value(attempt.measuredToolCalls),
		)
	}
	parts = append(parts, strconv.Itoa(len(rows)))
	for _, row := range rows {
		parts = append(parts,
			row.entryID, row.bucketID, row.metric, strconv.FormatInt(row.allocated, 10),
		)
	}
	return canonicalDigestBytes(attemptDecisionBindingDomain, parts), nil
}

const lockUpstreamAttemptsSQL = `
	SELECT upstream_attempt_id, attempt_number, route_key, upstream_key,
	       physical_model, model_key, status, first_byte_at, completed_at,
	       http_status, failure_code, billed_cost_nano_usd, currency,
	       price_revision, pricing_source, cost_confidence,
	       attempt_decision_binding_version, attempt_decision_sha256,
	       per_request_output_token_bound,
	       input_accounting_binding_version,
	       input_accounting_method, input_accounting_profile_id,
	       input_accounting_profile_digest, rewritten_body_sha256,
	       input_token_bound, output_token_bound, total_token_bound,
	       request_measurement_binding_version, request_measurement_sha256,
	       measured_request_bytes, measured_image_units, measured_tool_calls
	FROM upstream_attempts
	WHERE logical_request_id = $1
	ORDER BY attempt_number
	FOR UPDATE
`

func loadAttemptsForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	logicalRequestID string,
) ([]storedAttempt, error) {
	rows, err := tx.Query(ctx, lockUpstreamAttemptsSQL, logicalRequestID)
	if err != nil {
		return nil, persistenceFailure("lock upstream attempts", err)
	}
	return scanStoredAttempts(rows)
}

func scanStoredAttempts(rows pgx.Rows) ([]storedAttempt, error) {
	defer rows.Close()
	result := make([]storedAttempt, 0, maximumAttemptsPerRequest)
	for rows.Next() {
		if len(result) == maximumAttemptsPerRequest {
			return nil, ErrInvalidState
		}
		var attempt storedAttempt
		if err := rows.Scan(
			&attempt.id, &attempt.number, &attempt.routeKey, &attempt.upstreamKey,
			&attempt.physicalModel, &attempt.modelKey, &attempt.status, &attempt.firstByteAt,
			&attempt.completedAt, &attempt.httpStatus, &attempt.failureCode,
			&attempt.billedCost, &attempt.currency, &attempt.priceRevision,
			&attempt.pricingSource, &attempt.costConfidence,
			&attempt.attemptDecisionBindingVersion, &attempt.attemptDecisionSHA256,
			&attempt.perRequestOutputTokenBound,
			&attempt.inputAccountingBindingVersion,
			&attempt.inputAccountingMethod, &attempt.inputAccountingProfileID,
			&attempt.inputAccountingProfileDigest, &attempt.rewrittenBodySHA256,
			&attempt.inputTokenBound, &attempt.outputTokenBound, &attempt.totalTokenBound,
			&attempt.requestMeasurementBindingVersion, &attempt.requestMeasurementSHA256,
			&attempt.measuredRequestBytes, &attempt.measuredImageUnits, &attempt.measuredToolCalls,
		); err != nil {
			return nil, persistenceFailure("scan upstream attempt", err)
		}
		if id.Validate(attempt.id, id.UpstreamAttempt) != nil || attempt.validate() != nil ||
			attempt.number != int32(len(result)+1) {
			return nil, ErrInvalidState
		}
		result = append(result, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, persistenceFailure("iterate upstream attempts", err)
	}
	return result, nil
}

func loadAttemptQuotaEntriesForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
) ([]lockedAttemptQuotaEntry, error) {
	rows, err := tx.Query(ctx, lockAttemptQuotaEntriesSQL,
		reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		attempt.id, reservation.reservationID)
	if err != nil {
		return nil, persistenceFailure("lock upstream attempt quota entries", err)
	}
	return scanLockedAttemptQuotaEntries(rows, reservation)
}

const lockAttemptQuotaEntriesSQL = `
	SELECT quota_reservation_entry_id, quota_bucket_id, metric,
	       allocated_units, charged_units, released_units, settled_at
	FROM upstream_attempt_quota_entries
	WHERE organization_id = $1 AND application_id = $2
	  AND environment_id = $3 AND logical_request_id = $4
	  AND upstream_attempt_id = $5 AND quota_reservation_id = $6
	ORDER BY quota_bucket_id COLLATE "C"
	FOR UPDATE
`

func scanLockedAttemptQuotaEntries(
	rows pgx.Rows,
	reservation lockedReservation,
) ([]lockedAttemptQuotaEntry, error) {
	defer rows.Close()
	result := make([]lockedAttemptQuotaEntry, 0, len(reservation.entries))
	for rows.Next() {
		var entry lockedAttemptQuotaEntry
		if err := rows.Scan(
			&entry.entryID, &entry.bucketID, &entry.metric, &entry.allocated,
			&entry.charged, &entry.released, &entry.settledAt,
		); err != nil {
			return nil, persistenceFailure("scan upstream attempt quota entry", err)
		}
		if id.Validate(entry.entryID, id.QuotaEntry) != nil ||
			id.Validate(entry.bucketID, id.QuotaBucket) != nil ||
			!validAttemptQuotaEntry(entry) ||
			(len(result) > 0 && result[len(result)-1].bucketID >= entry.bucketID) {
			return nil, ErrInvalidState
		}
		result = append(result, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, persistenceFailure("iterate upstream attempt quota entries", err)
	}
	return result, nil
}

func validAttemptQuotaEntry(entry lockedAttemptQuotaEntry) bool {
	if attemptAllocationOrder(entry.metric) == math.MaxInt ||
		(entry.metric == CostNanoUSDMetric && entry.allocated < 0) ||
		(entry.metric != CostNanoUSDMetric && entry.allocated <= 0) {
		return false
	}
	if entry.charged == nil || entry.released == nil || entry.settledAt == nil {
		return entry.charged == nil && entry.released == nil && entry.settledAt == nil
	}
	return *entry.charged >= 0 && *entry.charged <= entry.allocated &&
		*entry.released == entry.allocated-*entry.charged && !entry.settledAt.IsZero()
}

func attemptQuotaEntriesSettled(entries []lockedAttemptQuotaEntry) bool {
	for _, entry := range entries {
		if entry.charged == nil || entry.released == nil || entry.settledAt == nil {
			return false
		}
	}
	return true
}

func attemptQuotaEntriesUnsettled(entries []lockedAttemptQuotaEntry) bool {
	for _, entry := range entries {
		if entry.charged != nil || entry.released != nil || entry.settledAt != nil {
			return false
		}
	}
	return true
}

func attemptUsageSetEmpty(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
) (bool, error) {
	var count int64
	if err := tx.QueryRow(ctx, countAttemptUsageSQL,
		reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID, attempt.id).Scan(&count); err != nil {
		return false, persistenceFailure("count started attempt usage", err)
	}
	return count == 0, nil
}

const countAttemptUsageSQL = `
	SELECT count(*)
	FROM usage_records
	WHERE organization_id = $1 AND application_id = $2
	  AND environment_id = $3 AND logical_request_id = $4
	  AND upstream_attempt_id = $5
`

func retrySelectedPricing(input PricingSelection, revision string) selectedPricing {
	if input.CatalogID == "" {
		return selectedPricing{}
	}
	return selectedPricing{source: input.CatalogID, currency: input.Currency, revision: revision}
}

func retryAttemptMatches(
	attempt storedAttempt,
	input RetryAttemptInput,
	revision string,
	perRequestOutputBound *int64,
) bool {
	wantPricing := retrySelectedPricing(input.Pricing, revision)
	gotPricing, err := attempt.selectedPricing()
	return err == nil && gotPricing == wantPricing && attempt.routeKey == input.RouteKey &&
		attempt.upstreamKey == input.UpstreamKey && attempt.physicalModel != nil &&
		*attempt.physicalModel == input.PhysicalModel && attempt.modelKey != nil &&
		*attempt.modelKey == input.ModelKey &&
		optionalInt64Matches(attempt.perRequestOutputTokenBound, perRequestOutputBound) &&
		storedInputPreflightMatches(attempt, input.InputPreflight) &&
		storedRequestMeasurementsMatch(attempt, input.RequestMeasurements)
}

func (attempt storedAttempt) validate() error {
	if attempt.validatePricing() != nil || attempt.number < 1 ||
		attempt.number > maximumAttemptsPerRequest ||
		!identifierPattern.MatchString(attempt.routeKey) ||
		!identifierPattern.MatchString(attempt.upstreamKey) ||
		(attempt.inputAccountingBindingVersion != 0 &&
			attempt.inputAccountingBindingVersion != 1) {
		return ErrInvalidState
	}
	switch attempt.status {
	case "started":
		if attempt.completedAt != nil || attempt.httpStatus != nil ||
			attempt.failureCode != nil || attempt.billedCost != nil ||
			(attempt.costConfidence != nil && *attempt.costConfidence != UnknownCostConfidence) {
			return ErrInvalidState
		}
	case AttemptSucceeded, AttemptFailed, AttemptCancelled, AttemptTimedOut:
		if attempt.completedAt == nil {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	var zeroDigest [sha256.Size]byte
	switch attempt.attemptDecisionBindingVersion {
	case 0:
		if attempt.number != 1 || attempt.modelKey != nil || attempt.attemptDecisionSHA256 != nil ||
			attempt.perRequestOutputTokenBound != nil || attempt.requestMeasurementBindingVersion != 0 {
			return ErrInvalidState
		}
	case 1, 2:
		if attempt.modelKey == nil || !identifierPattern.MatchString(*attempt.modelKey) ||
			attempt.physicalModel == nil || !validPhysicalModel(*attempt.physicalModel) ||
			len(attempt.attemptDecisionSHA256) != sha256.Size ||
			bytes.Equal(attempt.attemptDecisionSHA256, zeroDigest[:]) ||
			(attempt.attemptDecisionBindingVersion == 1 && attempt.requestMeasurementBindingVersion != 0) ||
			(attempt.attemptDecisionBindingVersion == 2 && attempt.requestMeasurementBindingVersion != 1) ||
			(attempt.perRequestOutputTokenBound != nil &&
				*attempt.perRequestOutputTokenBound <= 0) {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	if err := attempt.validateInputAccounting(zeroDigest); err != nil {
		return err
	}
	return attempt.validateRequestMeasurements(zeroDigest)
}

func (attempt storedAttempt) validateInputAccounting(zeroDigest [sha256.Size]byte) error {
	allAbsent := attempt.inputAccountingMethod == nil &&
		attempt.inputAccountingProfileID == nil &&
		attempt.inputAccountingProfileDigest == nil &&
		attempt.rewrittenBodySHA256 == nil && attempt.inputTokenBound == nil &&
		attempt.outputTokenBound == nil && attempt.totalTokenBound == nil
	if attempt.inputAccountingBindingVersion == 0 {
		if attempt.number != 1 || !allAbsent {
			return ErrInvalidState
		}
		return nil
	}
	if allAbsent {
		return nil
	}
	if attempt.inputAccountingBindingVersion != 1 {
		return ErrInvalidState
	}
	if attempt.inputAccountingMethod == nil || attempt.inputAccountingProfileID == nil ||
		len(attempt.inputAccountingProfileDigest) != sha256.Size ||
		len(attempt.rewrittenBodySHA256) != sha256.Size ||
		attempt.inputTokenBound == nil || attempt.outputTokenBound == nil ||
		attempt.totalTokenBound == nil ||
		*attempt.inputAccountingMethod != UTF8ByteBPEDeclaredFramingV1 ||
		!identifierPattern.MatchString(*attempt.inputAccountingProfileID) ||
		bytes.Equal(attempt.inputAccountingProfileDigest, zeroDigest[:]) ||
		bytes.Equal(attempt.rewrittenBodySHA256, zeroDigest[:]) ||
		// Stored attempts do not duplicate the logical protocol. Reservation
		// validation enforces zero only for Embeddings and positive bounds for
		// generative protocols, then proof matching preserves that decision here.
		*attempt.inputTokenBound <= 0 || *attempt.outputTokenBound < 0 ||
		*attempt.inputTokenBound > math.MaxInt64-*attempt.outputTokenBound ||
		*attempt.totalTokenBound != *attempt.inputTokenBound+*attempt.outputTokenBound {
		return ErrInvalidState
	}
	return nil
}

func (attempt storedAttempt) validateRequestMeasurements(zeroDigest [sha256.Size]byte) error {
	allAbsent := attempt.requestMeasurementSHA256 == nil &&
		attempt.measuredRequestBytes == nil && attempt.measuredImageUnits == nil &&
		attempt.measuredToolCalls == nil
	if attempt.requestMeasurementBindingVersion == 0 {
		if !allAbsent {
			return ErrInvalidState
		}
		return nil
	}
	if attempt.requestMeasurementBindingVersion != 1 {
		return ErrInvalidState
	}
	if allAbsent {
		return nil
	}
	if len(attempt.requestMeasurementSHA256) != sha256.Size ||
		bytes.Equal(attempt.requestMeasurementSHA256, zeroDigest[:]) ||
		attempt.measuredRequestBytes == nil || *attempt.measuredRequestBytes < 0 ||
		*attempt.measuredRequestBytes > protocol.MaximumMeasuredRequestBytes ||
		(attempt.measuredImageUnits != nil && (*attempt.measuredImageUnits < 0 ||
			*attempt.measuredImageUnits > protocol.MaximumRequestStructuredUnits)) ||
		(attempt.measuredToolCalls != nil && (*attempt.measuredToolCalls < 0 ||
			*attempt.measuredToolCalls > protocol.MaximumRequestStructuredUnits)) {
		return ErrInvalidState
	}
	return nil
}

func storedInputPreflightMatches(attempt storedAttempt, binding *InputPreflightBinding) bool {
	if binding == nil {
		return attempt.inputAccountingMethod == nil &&
			attempt.inputAccountingProfileID == nil &&
			attempt.inputAccountingProfileDigest == nil &&
			attempt.rewrittenBodySHA256 == nil && attempt.inputTokenBound == nil &&
			attempt.outputTokenBound == nil && attempt.totalTokenBound == nil
	}
	return attempt.inputAccountingMethod != nil &&
		*attempt.inputAccountingMethod == binding.Method &&
		attempt.inputAccountingProfileID != nil &&
		*attempt.inputAccountingProfileID == binding.ProfileID &&
		bytes.Equal(attempt.inputAccountingProfileDigest, binding.ProfileDigest[:]) &&
		bytes.Equal(attempt.rewrittenBodySHA256, binding.RewrittenBodySHA256[:]) &&
		attempt.inputTokenBound != nil && *attempt.inputTokenBound == binding.InputTokenBound &&
		attempt.outputTokenBound != nil && *attempt.outputTokenBound == binding.OutputTokenBound &&
		attempt.totalTokenBound != nil && *attempt.totalTokenBound == binding.TotalTokenBound
}

func storedInitialInputPreflightMatches(attempt storedAttempt, binding *InputPreflightBinding) bool {
	allAbsent := attempt.inputAccountingMethod == nil &&
		attempt.inputAccountingProfileID == nil &&
		attempt.inputAccountingProfileDigest == nil &&
		attempt.rewrittenBodySHA256 == nil && attempt.inputTokenBound == nil &&
		attempt.outputTokenBound == nil && attempt.totalTokenBound == nil
	if attempt.inputAccountingBindingVersion == 0 {
		// Schema-11 attempts were created before per-attempt proof columns
		// existed. Their logical request fingerprint remains the immutable
		// replay binding; every schema-12 BeginAttempt persists the full proof.
		return allAbsent
	}
	return storedInputPreflightMatches(attempt, binding)
}

func storedRequestMeasurementsMatch(
	attempt storedAttempt,
	binding *RequestMeasurementBinding,
) bool {
	if binding == nil {
		return attempt.requestMeasurementSHA256 == nil &&
			attempt.measuredRequestBytes == nil && attempt.measuredImageUnits == nil &&
			attempt.measuredToolCalls == nil
	}
	return bytes.Equal(attempt.requestMeasurementSHA256, binding.RewrittenBodySHA256[:]) &&
		attempt.measuredRequestBytes != nil && *attempt.measuredRequestBytes == binding.RequestBytes &&
		optionalKnownMeasurementMatches(attempt.measuredImageUnits, binding.ImageUnits, binding.ImageUnitsKnown) &&
		optionalKnownMeasurementMatches(attempt.measuredToolCalls, binding.ToolCalls, binding.ToolCallsKnown)
}

func optionalKnownMeasurementMatches(stored *int64, value int64, known bool) bool {
	if !known {
		return stored == nil
	}
	return stored != nil && *stored == value
}

func storedInitialRequestMeasurementsMatch(
	attempt storedAttempt,
	binding *RequestMeasurementBinding,
) bool {
	if attempt.attemptDecisionBindingVersion < 2 {
		// Attempts written before schema 18 are immutable under their historical
		// decision digest and cannot manufacture a post-rewrite measurement.
		return binding == nil && storedRequestMeasurementsMatch(attempt, nil)
	}
	return storedRequestMeasurementsMatch(attempt, binding)
}

func storedModelKeyMatches(attempt storedAttempt, modelKey string) bool {
	if attempt.attemptDecisionBindingVersion == 0 {
		return attempt.modelKey == nil
	}
	return attempt.modelKey != nil && *attempt.modelKey == modelKey
}

func validateRetryInputPreflight(
	input RetryAttemptInput,
	protocol string,
	allocations map[string]int64,
) error {
	_, hasInput := allocations[InputTokensMetric]
	_, hasTotal := allocations[TotalTokensMetric]
	_, hasCost := allocations[CostNanoUSDMetric]
	if hasCost && input.Pricing.CatalogID == "" {
		return ErrInvalidInput
	}
	requires := hasInput || hasTotal || (hasCost && input.InputNanoUSDPerMillion != 0)
	if input.InputPreflight == nil {
		if requires {
			return ErrInvalidInput
		}
		return nil
	}
	binding := input.InputPreflight
	if !validInputPreflightBinding(binding, protocol, input.PhysicalModel) {
		return ErrInvalidInput
	}
	for metric, units := range allocations {
		var want int64
		switch metric {
		case InputTokensMetric:
			want = binding.InputTokenBound
		case OutputTokensMetric:
			want = binding.OutputTokenBound
		case TotalTokensMetric:
			want = binding.TotalTokenBound
		case CostNanoUSDMetric:
			continue
		}
		if units != want {
			return ErrInvalidInput
		}
	}
	return nil
}

func attemptExistsAfter(ctx context.Context, tx pgx.Tx, logicalRequestID string, number int32) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM upstream_attempts
			WHERE logical_request_id = $1 AND attempt_number > $2
		)
	`, logicalRequestID, number).Scan(&exists); err != nil {
		return false, persistenceFailure("check later upstream attempts", err)
	}
	return exists, nil
}

func retryTargetEntries(
	prepared preparedRequest,
	plans []plannedBucket,
	entries []lockedEntry,
	attemptNumber int32,
) ([]lockedEntry, error) {
	if len(plans) > maximumRulesPerRequest || attemptNumber < 1 ||
		attemptNumber > maximumAttemptsPerRequest {
		return nil, ErrInvalidState
	}
	byBucket := make(map[string]lockedEntry, len(entries))
	for _, entry := range entries {
		byBucket[entry.bucketID] = entry
	}
	result := make([]lockedEntry, 0, len(plans))
	for _, plan := range plans {
		entry, ok := byBucket[plan.bucketID]
		if !ok || entry.limitPlanKey != prepared.LimitPlanKey ||
			entry.ruleKey != plan.rule.ruleKey || entry.metric != plan.rule.Metric ||
			entry.algorithm != plan.rule.Algorithm || entry.windowKey != plan.period.key ||
			entry.scopeType != plan.rule.scopeType ||
			!slicesEqual(entry.scopeDimensions, plan.rule.scopeDimensions) ||
			entry.scopeKey != plan.rule.scopeKey || entry.originAttemptNumber > attemptNumber {
			return nil, ErrInvalidState
		}
		result = append(result, entry)
	}
	return result, nil
}

func entriesBeforeAttempt(entries []lockedEntry, attemptNumber int32) []lockedEntry {
	result := make([]lockedEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.originAttemptNumber < attemptNumber {
			result = append(result, entry)
		}
	}
	return result
}

func attemptQuotaAllocationsMatch(
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
	byMetric map[string]int64,
	entries []lockedEntry,
) bool {
	expectedEntries := 0
	entryByID := make(map[string]lockedEntry, len(entries))
	for _, entry := range entries {
		entryByID[entry.id] = entry
		if _, ok := byMetric[entry.metric]; ok {
			expectedEntries++
		}
	}
	if len(quotaEntries) != expectedEntries {
		return false
	}
	for _, quotaEntry := range quotaEntries {
		entry, ok := entryByID[quotaEntry.entryID]
		if !ok || entry.bucketID != quotaEntry.bucketID || entry.metric != quotaEntry.metric ||
			quotaEntry.allocated != byMetric[quotaEntry.metric] {
			return false
		}
	}
	return attemptQuotaDecisionMatches(reservation, attempt, quotaEntries)
}

func reserveRetryAllocations(
	ctx context.Context,
	tx pgx.Tx,
	logicalRequestID string,
	entries []lockedEntry,
	plans []plannedBucket,
	allocations map[string]int64,
	newEntries map[string]struct{},
	now time.Time,
) error {
	if len(entries) != len(plans) {
		return ErrInvalidState
	}
	type retryAllocationReservation struct {
		allocated         bool
		newlyMaterialized bool
		units             int64
		tokenState        tokenBucketState
	}
	reservations := make([]retryAllocationReservation, len(entries))
	exceeded := make([]int, 0, len(entries))
	for index, entry := range entries {
		plan := &plans[index]
		if entry.bucketID != plan.bucketID || entry.metric != plan.rule.Metric ||
			entry.algorithm != plan.rule.Algorithm {
			return ErrInvalidState
		}
		units, allocated := allocations[entry.metric]
		if !allocated {
			continue
		}
		_, newlyMaterialized := newEntries[entry.id]
		reservation := &reservations[index]
		reservation.allocated = true
		reservation.newlyMaterialized = newlyMaterialized
		reservation.units = units
		outstanding := entry.reservedUnits - entry.settledUnits - entry.releasedUnits
		if (!newlyMaterialized && outstanding != 0) ||
			(newlyMaterialized && (outstanding != units || entry.initialReservedUnits != units)) ||
			(!newlyMaterialized && entry.reservedUnits > math.MaxInt64-units) {
			return ErrInvalidState
		}
		if entry.algorithm == TokenBucketAlgorithm {
			state, err := tokenStateFromLockedEntry(entry)
			if err != nil {
				return err
			}
			reconciled, err := reconcileTokenBucket(
				state, plan.rule.Capacity, plan.rule.RefillNumerator,
				plan.rule.RefillDenominator, now,
			)
			if err != nil {
				return err
			}
			plan.tokenState = reconciled
			plan.retryAt, err = tokenRetryAt(reconciled, units, now)
			if err != nil {
				return err
			}
			reserved, accepted, err := reserveTokenBalance(reconciled, units)
			if err != nil {
				return err
			}
			reservation.tokenState = reserved
			if !accepted {
				exceeded = append(exceeded, index)
			}
		} else {
			maximum := plan.rule.Maximum
			if entry.hardMaximum == nil || maximum <= 0 || entry.bucketUsed < 0 ||
				entry.bucketReserved < 0 || entry.bucketUsed > maximum ||
				entry.bucketReserved > maximum-entry.bucketUsed {
				return ErrInvalidState
			}
			plan.locked = lockedBucket{
				id: entry.bucketID, hardMaximum: entry.hardMaximum,
				used: entry.bucketUsed, reserved: entry.bucketReserved,
			}
			if units > maximum-entry.bucketUsed-entry.bucketReserved {
				exceeded = append(exceeded, index)
			}
		}
	}
	if len(exceeded) != 0 {
		return exceededError(logicalRequestID, plans, exceeded)
	}
	for index, entry := range entries {
		reservation := reservations[index]
		if !reservation.allocated {
			continue
		}
		plan := plans[index]
		if entry.algorithm == TokenBucketAlgorithm {
			if err := persistTokenBucketEntry(
				ctx, tx, entry, reservation.tokenState, now, "reserve retry token allocation",
			); err != nil {
				return err
			}
		} else {
			maximum := plan.rule.Maximum
			command, err := tx.Exec(ctx, `
					UPDATE quota_buckets
					SET hard_maximum = $2,
					    reserved_units = reserved_units + $3::bigint,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $4)
				WHERE quota_bucket_id = $1
				  AND used_units = $5 AND reserved_units = $6
				  AND ($3::bigint > 0 OR (
				        $3::bigint = 0 AND metric = 'cost_nano_usd' AND algorithm = 'calendar'
				      ))
				  AND $2 >= used_units
				  AND $3::bigint <= $2 - used_units - reserved_units
				`, entry.bucketID, maximum, reservation.units, now, entry.bucketUsed, entry.bucketReserved)
			if err != nil {
				return persistenceFailure("reserve retry calendar allocation", err)
			}
			if command.RowsAffected() != 1 {
				return ErrInvalidState
			}
		}
		if reservation.newlyMaterialized {
			continue
		}
		command, err := tx.Exec(ctx, `
			UPDATE quota_reservation_entries
			SET reserved_units = reserved_units + $2::bigint
			WHERE quota_reservation_entry_id = $1
			  AND initial_reserved_units = $3
			  AND reserved_units = $4
			  AND settled_units = $5
			  AND released_units = $6
		`, entry.id, reservation.units, entry.initialReservedUnits, entry.reservedUnits,
			entry.settledUnits, entry.releasedUnits)
		if err != nil {
			return persistenceFailure("extend retry quota reservation entry", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	return nil
}

func reserveRetryConcurrency(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	entries []lockedEntry,
	plans []plannedBucket,
	newEntries map[string]struct{},
	leaseIDs map[string]string,
	now time.Time,
) error {
	if len(entries) != len(plans) {
		return ErrInvalidState
	}
	for index, entry := range entries {
		plan := plans[index]
		if entry.bucketID != plan.bucketID || entry.metric != plan.rule.Metric ||
			entry.algorithm != plan.rule.Algorithm {
			return ErrInvalidState
		}
		if !isConcurrencyMetric(entry.metric) {
			continue
		}
		if _, newlyMaterialized := newEntries[entry.id]; !newlyMaterialized {
			continue
		}
		leaseID, ok := leaseIDs[entry.bucketID]
		maximum := plan.rule.Maximum
		if !ok || entry.algorithm != ConcurrencyAlgorithm ||
			entry.initialReservedUnits != 1 || entry.reservedUnits != 1 ||
			entry.settledUnits != 0 || entry.releasedUnits != 0 ||
			entry.hardMaximum == nil || *entry.hardMaximum <= 0 || maximum <= 0 ||
			entry.bucketUsed != 0 || entry.bucketReserved < 0 ||
			entry.bucketReserved > *entry.hardMaximum {
			return ErrInvalidState
		}
		if entry.bucketReserved >= maximum {
			return ErrConcurrencyExceeded
		}
		command, err := tx.Exec(ctx, `
			UPDATE quota_buckets
			SET hard_maximum = $2,
			    reserved_units = reserved_units + 1,
			    version = version + 1,
			    updated_at = GREATEST(updated_at, $3)
			WHERE quota_bucket_id = $1 AND metric = $4 AND algorithm = 'concurrency'
			  AND used_units = 0 AND reserved_units = $5
			  AND reserved_units < $2
		`, entry.bucketID, maximum, now, entry.metric, entry.bucketReserved)
		if err != nil {
			return persistenceFailure("reserve retry concurrency bucket", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO concurrency_leases (
				concurrency_lease_id, organization_id, application_id,
				environment_id, quota_bucket_id, logical_request_id,
				acquired_at, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, leaseID, reservation.organizationID, reservation.applicationID,
			reservation.environmentID, entry.bucketID, reservation.logicalRequestID,
			now, reservation.expiresAt); err != nil {
			return mapWriteError("insert retry concurrency lease", err)
		}
	}
	return nil
}

func insertAttemptQuotaEntries(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attemptID string,
	entries []lockedEntry,
	allocations map[string]int64,
) error {
	for _, entry := range entries {
		units, allocated := allocations[entry.metric]
		if !allocated {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO upstream_attempt_quota_entries (
				organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, quota_reservation_id,
				quota_reservation_entry_id, quota_bucket_id, metric, allocated_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, reservation.organizationID, reservation.applicationID,
			reservation.environmentID, reservation.logicalRequestID, attemptID,
			reservation.reservationID, entry.id, entry.bucketID, entry.metric, units); err != nil {
			return mapWriteError("insert upstream attempt quota entry", err)
		}
	}
	return nil
}

func (store *Store) settleRetryLifecycle(
	ctx context.Context,
	attempt Attempt,
	outcome Outcome,
	final bool,
) error {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil ||
		attempt.validate() != nil || outcome.validate() != nil ||
		(!final && outcome.Status != AttemptFailed && outcome.Status != AttemptTimedOut) {
		return ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return persistenceFailure("begin retry quota settlement", err)
	}
	defer rollback(tx)
	reservation, err := lockReservation(ctx, tx, attempt.reservation)
	if err != nil {
		return err
	}
	logical, err := lockLogicalRequest(ctx, tx, attempt.reservation)
	if err != nil {
		return err
	}
	stored, found, err := loadAttemptForUpdate(
		ctx, tx, attempt.reservation.logicalRequestID, attempt.number,
	)
	if err != nil {
		return err
	}
	if !found || stored.id != attempt.attemptID {
		return ErrNotFound
	}
	if attempt.number == 1 &&
		(!storedInitialInputPreflightMatches(stored, attempt.reservation.inputPreflight) ||
			!storedInitialRequestMeasurementsMatch(stored, attempt.reservation.requestMeasurements)) {
		return ErrInvalidState
	}
	pricing, err := stored.selectedPricing()
	if err != nil {
		return err
	}
	outcome, err = normalizeOutcomeForPricing(outcome, pricing)
	if err != nil {
		return err
	}
	entries, err := lockEntries(ctx, tx, reservation)
	if err != nil {
		return err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, reservation, entries)
	if err != nil {
		return err
	}
	quotaEntries, err := loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, stored)
	if err != nil {
		return err
	}
	if len(quotaEntries) == 0 && attempt.number == 1 && stored.status == "started" {
		initialAllocations, allocationErr := initialAttemptAllocations(entries)
		if allocationErr != nil {
			return allocationErr
		}
		if err := insertAttemptQuotaEntries(
			ctx, tx, reservation, stored.id, entries, initialAllocations,
		); err != nil {
			return err
		}
		quotaEntries, err = loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, stored)
		if err != nil {
			return err
		}
	}
	if !attemptQuotaEntriesMatchReservation(reservation, stored, quotaEntries, entries) {
		return ErrInvalidState
	}
	var usageIDs settlementUsageIDs
	if stored.status == "started" {
		attempts, attemptsErr := loadAttemptsForUpdate(
			ctx, tx, reservation.logicalRequestID,
		)
		if attemptsErr != nil {
			return attemptsErr
		}
		lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
			ctx, tx, reservation, logical.status, entries, attempts,
		)
		if lifecycleErr != nil {
			return lifecycleErr
		}
		if reservation.status != "pending" ||
			(logical.status != "dispatched" && logical.status != "streaming") ||
			!pendingEntriesMatch(logical.status, reservation, entries, leases) ||
			!lifecycleMatches {
			return ErrInvalidState
		}
		reservations, reservationErr := attemptTokenReservationUnits(quotaEntries)
		if reservationErr != nil {
			return reservationErr
		}
		usageIDs, err = store.newSettlementUsageIDsForTokenMetrics(
			outcome.Usage, reservations, outcome.Cost, pricing,
		)
		if err != nil {
			return err
		}
		now, timeErr := statementTime(ctx, tx)
		if timeErr != nil {
			return timeErr
		}
		if stored.firstByteAt != nil && stored.firstByteAt.After(now) {
			now = stored.firstByteAt.UTC()
		}
		if err := settleRetryAttemptLocked(
			ctx, tx, reservation, stored, entries, quotaEntries,
			outcome, usageIDs, pricing, now,
		); err != nil {
			return err
		}
		stored.status = outcome.Status
		stored.httpStatus = optionalHTTPStatus(outcome.HTTPStatus)
		stored.failureCode = optionalText(outcome.FailureCode)
		stored.billedCost, stored.costConfidence = storedSettlementCost(pricing, outcome.Cost)
		completedAt := now
		stored.completedAt = &completedAt
		entries, err = lockEntries(ctx, tx, reservation)
		if err != nil {
			return err
		}
		if _, err := loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, stored); err != nil {
			return err
		}
	} else {
		if !terminalAttemptMatches(stored, outcome, pricing) ||
			!attemptQuotaEntriesSettled(quotaEntries) {
			return ErrFinalized
		}
		matches, matchErr := retryAttemptUsageMatches(
			ctx, tx, reservation, stored, quotaEntries, outcome,
		)
		if matchErr != nil {
			return matchErr
		}
		if !matches {
			return ErrFinalized
		}
	}
	if !final {
		if err := tx.Commit(ctx); err != nil {
			return persistenceFailure("commit retryable attempt settlement", err)
		}
		return nil
	}
	if later, loadErr := attemptExistsAfter(
		ctx, tx, reservation.logicalRequestID, attempt.number,
	); loadErr != nil {
		return loadErr
	} else if later {
		return ErrFinalized
	}
	attempts, err := loadAttemptsForUpdate(ctx, tx, reservation.logicalRequestID)
	if err != nil {
		return err
	}
	if len(attempts) == 0 || attempts[len(attempts)-1].id != stored.id {
		return ErrInvalidState
	}
	if reservation.status == "settled" {
		aggregateMatches, aggregateErr := retryAggregateMatchesEntries(ctx, tx, reservation, entries)
		if aggregateErr != nil {
			return aggregateErr
		}
		logicalUsageMatches, usageErr := logicalUsageRecordMatches(ctx, tx, reservation)
		if usageErr != nil {
			return usageErr
		}
		accountingMatches, accountingErr := terminalAttemptAccountingSequenceMatches(
			ctx, tx, reservation, logical.status, entries, attempts,
		)
		if accountingErr != nil {
			return accountingErr
		}
		if !terminalEntriesMatch(logical.status, reservation.status, entries, leases) ||
			!aggregateMatches || !logicalUsageMatches || !accountingMatches {
			return ErrInvalidState
		}
		return nil
	}
	aggregateMatches, aggregateErr := retryAggregateMatchesEntries(ctx, tx, reservation, entries)
	if aggregateErr != nil {
		return aggregateErr
	}
	accountingMatches, accountingErr := attemptAccountingSequenceMatches(
		ctx, tx, reservation, entries, attempts,
	)
	if accountingErr != nil {
		return accountingErr
	}
	if reservation.status != "pending" ||
		(logical.status != "dispatched" && logical.status != "streaming") ||
		!pendingEntriesMatch(logical.status, reservation, entries, leases) ||
		!aggregateMatches || !accountingMatches {
		return ErrInvalidState
	}
	logicalUsageID := usageIDs.logical
	if logicalUsageID == "" {
		logicalUsageID, err = store.newID(id.UsageRecord)
		if err != nil {
			return fmt.Errorf("generate logical usage-record identifier: %w", err)
		}
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := finalizeRetryReservationLocked(
		ctx, tx, reservation, logical, entries, leases, stored,
		outcome, logicalUsageID, now,
	); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistenceFailure("commit final retry settlement", err)
	}
	return nil
}

func optionalHTTPStatus(value int) *int32 {
	if value == 0 {
		return nil
	}
	result := int32(value)
	return &result
}

func optionalText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func storedSettlementCost(pricing selectedPricing, cost Cost) (*int64, *string) {
	billed, confidence := settlementCostValues(pricing, cost)
	var billedResult *int64
	if value, ok := billed.(int64); ok {
		billedResult = &value
	}
	var confidenceResult *string
	if value, ok := confidence.(string); ok {
		confidenceResult = &value
	}
	return billedResult, confidenceResult
}

func initialAttemptAllocations(entries []lockedEntry) (map[string]int64, error) {
	result := make(map[string]int64, len(reservedTokenMetricOrder)+1)
	for _, entry := range entries {
		if entry.originAttemptNumber != 1 || attemptAllocationOrder(entry.metric) == math.MaxInt {
			continue
		}
		if existing, ok := result[entry.metric]; ok && existing != entry.initialReservedUnits {
			return nil, ErrInvalidState
		}
		result[entry.metric] = entry.initialReservedUnits
	}
	return result, nil
}

func attemptQuotaEntriesMatchReservation(
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
	entries []lockedEntry,
) bool {
	byID := make(map[string]lockedEntry, len(entries))
	for _, entry := range entries {
		byID[entry.id] = entry
	}
	expected, ok := applicableAttemptQuotaEntries(reservation, attempt, entries)
	if !ok || len(quotaEntries) != len(expected) {
		return false
	}
	for _, quotaEntry := range quotaEntries {
		entry, ok := byID[quotaEntry.entryID]
		if !ok || quotaEntry.bucketID != entry.bucketID || quotaEntry.metric != entry.metric ||
			entry.originAttemptNumber > attempt.number ||
			(entry.originAttemptNumber == attempt.number &&
				quotaEntry.allocated != entry.initialReservedUnits) {
			return false
		}
		if _, ok := expected[quotaEntry.entryID]; !ok {
			return false
		}
		delete(expected, quotaEntry.entryID)
	}
	return len(expected) == 0 && attemptQuotaDecisionMatches(reservation, attempt, quotaEntries)
}

func applicableAttemptQuotaEntries(
	reservation lockedReservation,
	attempt storedAttempt,
	entries []lockedEntry,
) (map[string]struct{}, bool) {
	result := make(map[string]struct{})
	if attempt.attemptDecisionBindingVersion == 0 {
		if attempt.number != 1 {
			return nil, false
		}
		for _, entry := range entries {
			if entry.originAttemptNumber == 1 && attemptAllocationOrder(entry.metric) != math.MaxInt {
				result[entry.id] = struct{}{}
			}
		}
		return result, true
	}
	if attempt.modelKey == nil || reservation.applicationUserID == "" ||
		reservation.installationID == "" || reservation.featureKey == "" {
		return nil, false
	}
	values := map[string]string{
		"organization": reservation.organizationID,
		"application":  reservation.applicationID,
		"environment":  reservation.environmentID,
		"user":         reservation.applicationUserID,
		"installation": reservation.installationID,
		"feature":      reservation.featureKey,
		"route":        attempt.routeKey,
		"upstream":     attempt.upstreamKey,
		"model":        *attempt.modelKey,
	}
	for _, entry := range entries {
		if entry.originAttemptNumber > attempt.number ||
			attemptAllocationOrder(entry.metric) == math.MaxInt {
			continue
		}
		parts := make([]string, 0, len(entry.scopeDimensions)*2)
		for _, dimension := range entry.scopeDimensions {
			value := values[dimension]
			if value == "" {
				return nil, false
			}
			parts = append(parts, dimension, value)
		}
		if canonicalDigest(scopeDigestDomain, parts) == entry.scopeKey {
			result[entry.id] = struct{}{}
		}
	}
	return result, true
}

func storedAttemptScopeKeyMatches(
	prepared preparedRequest,
	attempt storedAttempt,
	dimensions []string,
	want string,
) bool {
	modelKey := prepared.ModelKey
	if attempt.attemptDecisionBindingVersion != 0 {
		if attempt.modelKey == nil {
			return false
		}
		modelKey = *attempt.modelKey
	}
	values := map[string]string{
		"organization": prepared.OrganizationID,
		"application":  prepared.ApplicationID,
		"environment":  prepared.EnvironmentID,
		"user":         prepared.ApplicationUserID,
		"installation": prepared.InstallationID,
		"feature":      prepared.FeatureKey,
		"route":        attempt.routeKey,
		"upstream":     attempt.upstreamKey,
		"model":        modelKey,
	}
	parts := make([]string, 0, len(dimensions)*2)
	for _, dimension := range dimensions {
		value := values[dimension]
		if value == "" {
			return false
		}
		parts = append(parts, dimension, value)
	}
	return canonicalDigest(scopeDigestDomain, parts) == want
}

func attemptQuotaDecisionMatches(
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
) bool {
	if !attemptInputAccountingMatchesQuota(attempt, quotaEntries) {
		return false
	}
	if attempt.attemptDecisionBindingVersion == 0 {
		return attempt.number == 1 && attempt.attemptDecisionSHA256 == nil
	}
	digest, err := attemptDecisionDigest(reservation, attempt, quotaEntries)
	return err == nil && bytes.Equal(attempt.attemptDecisionSHA256, digest[:])
}

func attemptInputAccountingMatchesQuota(
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
) bool {
	if attempt.inputAccountingBindingVersion == 0 {
		return attempt.number == 1
	}
	proofPresent := attempt.inputAccountingMethod != nil
	requiresProof := false
	pricing, err := attempt.selectedPricing()
	if err != nil {
		return false
	}
	for _, quotaEntry := range quotaEntries {
		switch quotaEntry.metric {
		case InputTokensMetric:
			requiresProof = true
			if proofPresent && (attempt.inputTokenBound == nil ||
				quotaEntry.allocated != *attempt.inputTokenBound) {
				return false
			}
		case OutputTokensMetric:
			if proofPresent && (attempt.outputTokenBound == nil ||
				quotaEntry.allocated != *attempt.outputTokenBound) {
				return false
			}
		case TotalTokensMetric:
			requiresProof = true
			if proofPresent && (attempt.totalTokenBound == nil ||
				quotaEntry.allocated != *attempt.totalTokenBound) {
				return false
			}
		case CostNanoUSDMetric:
			if !pricing.present() {
				return false
			}
		default:
			return false
		}
	}
	return !requiresProof || proofPresent
}

func attemptTokenReservationUnits(entries []lockedAttemptQuotaEntry) ([]reservedTokenMetric, error) {
	byMetric := make(map[string]int64, len(reservedTokenMetricOrder))
	for _, entry := range entries {
		if entry.metric == CostNanoUSDMetric {
			continue
		}
		if existing, ok := byMetric[entry.metric]; ok && existing != entry.allocated {
			return nil, ErrInvalidState
		}
		byMetric[entry.metric] = entry.allocated
	}
	result := make([]reservedTokenMetric, 0, len(byMetric))
	for _, metric := range reservedTokenMetricOrder {
		if units, ok := byMetric[metric]; ok {
			result = append(result, reservedTokenMetric{metric: metric, units: units})
		}
	}
	if !validReservedTokenMetrics(result) {
		return nil, ErrInvalidState
	}
	return result, nil
}

func settleRetryAttemptLocked(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	entries []lockedEntry,
	quotaEntries []lockedAttemptQuotaEntry,
	outcome Outcome,
	identifiers settlementUsageIDs,
	pricing selectedPricing,
	now time.Time,
) error {
	entryByID := make(map[string]lockedEntry, len(entries))
	for _, entry := range entries {
		entryByID[entry.id] = entry
	}
	for _, quotaEntry := range quotaEntries {
		entry, ok := entryByID[quotaEntry.entryID]
		if !ok || quotaEntry.charged != nil || quotaEntry.released != nil ||
			quotaEntry.settledAt != nil {
			return ErrInvalidState
		}
		charged, err := retryAttemptChargedUnits(quotaEntry, outcome)
		if err != nil {
			return err
		}
		released := quotaEntry.allocated - charged
		outstanding := entry.reservedUnits - entry.settledUnits - entry.releasedUnits
		if outstanding < quotaEntry.allocated || entry.settledUnits > math.MaxInt64-charged ||
			entry.releasedUnits > math.MaxInt64-released {
			return ErrInvalidState
		}
		if entry.algorithm == TokenBucketAlgorithm {
			if released > 0 {
				state, stateErr := tokenStateFromLockedEntry(entry)
				if stateErr != nil {
					return stateErr
				}
				refunded, stateErr := refundTokenBalance(state, released, now)
				if stateErr != nil {
					return stateErr
				}
				if err := persistTokenBucketEntry(
					ctx, tx, entry, refunded, now,
					"refund retry attempt token allocation",
				); err != nil {
					return err
				}
			}
		} else {
			if entry.hardMaximum == nil || entry.bucketUsed < 0 ||
				entry.bucketReserved < quotaEntry.allocated ||
				entry.bucketUsed > *entry.hardMaximum ||
				charged > *entry.hardMaximum-entry.bucketUsed {
				return ErrInvalidState
			}
			command, updateErr := tx.Exec(ctx, `
				UPDATE quota_buckets
				SET used_units = used_units + $2::bigint,
				    reserved_units = reserved_units - $3::bigint,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $4)
				WHERE quota_bucket_id = $1
				  AND used_units = $5 AND reserved_units = $6
				  AND hard_maximum = $7
				  AND ($3::bigint > 0 OR (
				        $3::bigint = 0 AND metric = 'cost_nano_usd' AND algorithm = 'calendar'
				      ))
				  AND reserved_units >= $3::bigint
				  AND $2::bigint <= hard_maximum - used_units
			`, entry.bucketID, charged, quotaEntry.allocated, now,
				entry.bucketUsed, entry.bucketReserved, *entry.hardMaximum)
			if updateErr != nil {
				return persistenceFailure("settle retry calendar allocation", updateErr)
			}
			if command.RowsAffected() != 1 {
				return ErrInvalidState
			}
		}
		command, updateErr := tx.Exec(ctx, `
			UPDATE quota_reservation_entries
			SET settled_units = settled_units + $2::bigint,
			    released_units = released_units + $3::bigint
			WHERE quota_reservation_entry_id = $1
			  AND initial_reserved_units = $4
			  AND reserved_units = $5
			  AND settled_units = $6 AND released_units = $7
			  AND $2::bigint <= reserved_units - settled_units - released_units
			  AND $3::bigint = $8::bigint - $2::bigint
		`, entry.id, charged, released, entry.initialReservedUnits,
			entry.reservedUnits, entry.settledUnits, entry.releasedUnits,
			quotaEntry.allocated)
		if updateErr != nil {
			return persistenceFailure("settle retry quota reservation entry", updateErr)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
		command, updateErr = tx.Exec(ctx, `
			UPDATE upstream_attempt_quota_entries
			SET charged_units = $2, released_units = $3, settled_at = $4
			WHERE environment_id = $5 AND upstream_attempt_id = $6
			  AND quota_reservation_entry_id = $1
			  AND allocated_units = $7
			  AND charged_units IS NULL AND released_units IS NULL AND settled_at IS NULL
		`, quotaEntry.entryID, charged, released, now, reservation.environmentID,
			attempt.id, quotaEntry.allocated)
		if updateErr != nil {
			return persistenceFailure("complete upstream attempt quota entry", updateErr)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if err := insertRetryAttemptUsage(
		ctx, tx, reservation, attempt, quotaEntries, outcome, identifiers, pricing, now,
	); err != nil {
		return err
	}
	billedCost, confidence := settlementCostValues(pricing, outcome.Cost)
	command, err := tx.Exec(ctx, `
		UPDATE upstream_attempts
		SET status = $2,
		    completed_at = GREATEST(started_at, COALESCE(first_byte_at, started_at), $3),
		    http_status = $4,
		    failure_code = $5,
		    billed_cost_nano_usd = $6,
		    cost_confidence = $7
		WHERE upstream_attempt_id = $1 AND status = 'started'
		  AND currency IS NOT DISTINCT FROM $8
		  AND price_revision IS NOT DISTINCT FROM $9
		  AND pricing_source IS NOT DISTINCT FROM $10
		  AND billed_cost_nano_usd IS NULL
		  AND cost_confidence IS NOT DISTINCT FROM $11
	`, attempt.id, outcome.Status, now, nullableInt(outcome.HTTPStatus),
		nullableString(outcome.FailureCode), billedCost, confidence,
		nullableString(pricing.currency), nullableString(pricing.revision),
		nullableString(pricing.source), nullableString(initialCostConfidence(pricing)))
	if err != nil {
		return persistenceFailure("complete retry upstream attempt", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	return nil
}

func retryAttemptChargedUnits(entry lockedAttemptQuotaEntry, outcome Outcome) (int64, error) {
	if entry.metric == CostNanoUSDMetric {
		if !outcome.Cost.Known {
			return entry.allocated, nil
		}
		if outcome.Cost.NanoUSD > entry.allocated {
			return 0, ErrInvalidInput
		}
		return outcome.Cost.NanoUSD, nil
	}
	actual, ok := tokenMetricUsageUnits(outcome.Usage, entry.metric)
	if !ok {
		return 0, ErrInvalidState
	}
	if outcome.Status == AttemptSucceeded && outcome.Usage.Known && actual > entry.allocated {
		return 0, ErrInvalidInput
	}
	if outcome.Status == AttemptSucceeded && outcome.Usage.Known {
		return actual, nil
	}
	return entry.allocated, nil
}

func insertRetryAttemptUsage(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
	outcome Outcome,
	identifiers settlementUsageIDs,
	pricing selectedPricing,
	now time.Time,
) error {
	insert := func(
		usageID string,
		metric string,
		units int64,
		cost any,
		currency any,
		revision any,
		source any,
		confidence string,
		provenance string,
	) error {
		if id.Validate(usageID, id.UsageRecord) != nil || units < 0 {
			return ErrInvalidState
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				cost_nano_usd, currency, price_revision, pricing_source,
				confidence, provenance_key, recorded_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8,
				$9, $10, $11, $12, $13, $14, $15
			)
		`, usageID, reservation.organizationID, reservation.applicationID,
			reservation.environmentID, reservation.logicalRequestID, attempt.id,
			metric, units, cost, currency, revision, source, confidence, provenance, now); err != nil {
			return mapWriteError("insert retry attempt usage", err)
		}
		return nil
	}
	if outcome.Usage.Known {
		for _, record := range []struct {
			id     string
			metric string
			units  int64
		}{
			{id: identifiers.providerInput, metric: InputTokensMetric, units: outcome.Usage.InputTokens},
			{id: identifiers.providerOutput, metric: OutputTokensMetric, units: outcome.Usage.OutputTokens},
			{id: identifiers.providerTotal, metric: TotalTokensMetric, units: outcome.Usage.TotalTokens},
		} {
			if err := insert(
				record.id, record.metric, record.units, nil, nil, nil, nil,
				"reported", providerUsageProvenanceKey(attempt.id, record.metric),
			); err != nil {
				return err
			}
		}
	} else {
		reservations, err := attemptTokenReservationUnits(quotaEntries)
		if err != nil {
			return err
		}
		for _, reservationEntry := range reservations {
			usageID, ok := identifiers.unknownToken(reservationEntry.metric)
			if !ok || usageID == "" {
				return ErrInvalidState
			}
			if err := insert(
				usageID, reservationEntry.metric, reservationEntry.units,
				nil, nil, nil, nil, UnknownCostConfidence,
				retryUnknownTokenUsageProvenanceKey(
					reservation.reservationID, attempt, reservationEntry.metric,
				),
			); err != nil {
				return err
			}
		}
	}
	if !outcome.Cost.Known {
		return nil
	}
	if identifiers.cost == "" || !pricing.present() && outcome.Cost.Confidence != ProviderReportedCostConfidence {
		return ErrInvalidState
	}
	amount := outcome.Cost.NanoUSD
	attribution := settlementCostUsageAttribution(pricing, outcome.Cost)
	return insert(
		identifiers.cost, CostNanoUSDMetric, amount, amount, attribution.currency,
		attribution.priceRevision, attribution.pricingSource, outcome.Cost.Confidence,
		costUsageProvenanceKey(attempt.id, outcome.Cost),
	)
}

func retryAttemptUsageMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
	outcome Outcome,
) (bool, error) {
	type expectedUsage struct {
		metric     string
		units      int64
		cost       *int64
		currency   *string
		revision   *string
		source     *string
		confidence string
	}
	expected := make(map[string]expectedUsage)
	if outcome.Usage.Known {
		for _, record := range []struct {
			metric string
			units  int64
		}{
			{metric: InputTokensMetric, units: outcome.Usage.InputTokens},
			{metric: OutputTokensMetric, units: outcome.Usage.OutputTokens},
			{metric: TotalTokensMetric, units: outcome.Usage.TotalTokens},
		} {
			expected[providerUsageProvenanceKey(attempt.id, record.metric)] = expectedUsage{
				metric: record.metric, units: record.units, confidence: "reported",
			}
		}
	} else {
		reservations, err := attemptTokenReservationUnits(quotaEntries)
		if err != nil {
			return false, err
		}
		for _, tokenReservation := range reservations {
			expected[retryUnknownTokenUsageProvenanceKey(
				reservation.reservationID, attempt, tokenReservation.metric,
			)] = expectedUsage{
				metric: tokenReservation.metric, units: tokenReservation.units,
				confidence: UnknownCostConfidence,
			}
		}
	}
	pricing, err := attempt.selectedPricing()
	if err != nil {
		return false, err
	}
	if outcome.Cost.Known {
		amount := outcome.Cost.NanoUSD
		attribution := settlementCostUsageAttribution(pricing, outcome.Cost)
		expected[costUsageProvenanceKey(attempt.id, outcome.Cost)] = expectedUsage{
			metric: CostNanoUSDMetric, units: amount, cost: &amount,
			currency: attribution.currency, revision: attribution.priceRevision,
			source:     attribution.pricingSource,
			confidence: outcome.Cost.Confidence,
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT usage_record_id, metric, units, cost_nano_usd, currency,
		       price_revision, pricing_source, confidence, provenance_key
		FROM usage_records
		WHERE environment_id = $1 AND logical_request_id = $2
		  AND upstream_attempt_id = $3
		ORDER BY provenance_key COLLATE "C"
	`, reservation.environmentID, reservation.logicalRequestID, attempt.id)
	if err != nil {
		return false, persistenceFailure("load retry attempt usage", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var usageID, metric, confidence, provenance string
		var units int64
		var cost *int64
		var currency, revision, source *string
		if err := rows.Scan(
			&usageID, &metric, &units, &cost, &currency, &revision,
			&source, &confidence, &provenance,
		); err != nil {
			return false, persistenceFailure("scan retry attempt usage", err)
		}
		want, ok := expected[provenance]
		if !ok || id.Validate(usageID, id.UsageRecord) != nil || metric != want.metric ||
			units != want.units || confidence != want.confidence ||
			!optionalInt64Matches(cost, want.cost) ||
			!optionalStringMatches(currency, want.currency) ||
			!optionalStringMatches(revision, want.revision) ||
			!optionalStringMatches(source, want.source) {
			return false, nil
		}
		if _, duplicate := seen[provenance]; duplicate {
			return false, nil
		}
		seen[provenance] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, persistenceFailure("iterate retry attempt usage", err)
	}
	return len(seen) == len(expected), nil
}

func storedRetryAttemptAccountingMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	quotaEntries []lockedAttemptQuotaEntry,
) (bool, error) {
	tokenAllocations := make(map[string]int64, len(reservedTokenMetricOrder))
	for _, entry := range quotaEntries {
		if entry.metric != CostNanoUSDMetric {
			tokenAllocations[entry.metric] = entry.allocated
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT usage_record_id, metric, units, confidence, provenance_key
		FROM usage_records
		WHERE environment_id = $1 AND logical_request_id = $2
		  AND upstream_attempt_id = $3 AND metric = ANY($4::text[])
		ORDER BY metric COLLATE "C", provenance_key COLLATE "C"
	`, reservation.environmentID, reservation.logicalRequestID,
		attempt.id, reservedTokenMetricOrder[:])
	if err != nil {
		return false, persistenceFailure("load stored retry token usage", err)
	}
	defer rows.Close()
	reported := make(map[string]int64, len(reservedTokenMetricOrder))
	unknown := make(map[string]int64, len(tokenAllocations))
	mode := ""
	for rows.Next() {
		var usageID, metric, confidence, provenance string
		var units int64
		if err := rows.Scan(&usageID, &metric, &units, &confidence, &provenance); err != nil {
			return false, persistenceFailure("scan stored retry token usage", err)
		}
		if id.Validate(usageID, id.UsageRecord) != nil || units < 0 {
			return false, nil
		}
		switch confidence {
		case "reported":
			if mode == "unknown" ||
				provenance != providerUsageProvenanceKey(attempt.id, metric) {
				return false, nil
			}
			mode = "reported"
			if _, duplicate := reported[metric]; duplicate {
				return false, nil
			}
			reported[metric] = units
		case UnknownCostConfidence:
			allocated, expected := tokenAllocations[metric]
			if mode == "reported" || !expected || units != allocated ||
				provenance != retryUnknownTokenUsageProvenanceKey(
					reservation.reservationID, attempt, metric,
				) {
				return false, nil
			}
			mode = "unknown"
			if _, duplicate := unknown[metric]; duplicate {
				return false, nil
			}
			unknown[metric] = units
		default:
			return false, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, persistenceFailure("iterate stored retry token usage", err)
	}
	outcome := Outcome{Status: attempt.status}
	if attempt.httpStatus != nil {
		outcome.HTTPStatus = int(*attempt.httpStatus)
	}
	if attempt.failureCode != nil {
		outcome.FailureCode = *attempt.failureCode
	}
	switch mode {
	case "reported":
		if len(reported) != len(reservedTokenMetricOrder) {
			return false, nil
		}
		var found bool
		if outcome.Usage.InputTokens, found = reported[InputTokensMetric]; !found {
			return false, nil
		}
		if outcome.Usage.OutputTokens, found = reported[OutputTokensMetric]; !found {
			return false, nil
		}
		if outcome.Usage.TotalTokens, found = reported[TotalTokensMetric]; !found {
			return false, nil
		}
		outcome.Usage.Known = true
		outcome.Usage.Provenance = ProviderReportedProvenance
	case "unknown":
		if len(unknown) != len(tokenAllocations) {
			return false, nil
		}
		outcome.Usage = Usage{Provenance: UnknownUsageProvenance}
	case "":
		if len(tokenAllocations) != 0 {
			return false, nil
		}
		outcome.Usage = Usage{Provenance: UnknownUsageProvenance}
	default:
		return false, nil
	}
	pricing, err := attempt.selectedPricing()
	if err != nil {
		return false, err
	}
	if attempt.billedCost != nil {
		outcome.Cost = Cost{
			NanoUSD: *attempt.billedCost, Known: true,
			Confidence: *attempt.costConfidence,
		}
		if outcome.Cost.Confidence == ProviderReportedCostConfidence {
			outcome.Cost.Currency = USDCurrency
			outcome.Cost.Source = ProviderReportedCostSource
		}
	} else if pricing.present() {
		outcome.Cost = Cost{Confidence: UnknownCostConfidence}
	}
	if outcome.validate() != nil || !terminalAttemptMatches(attempt, outcome, pricing) {
		return false, nil
	}
	for _, quotaEntry := range quotaEntries {
		if quotaEntry.charged == nil || quotaEntry.released == nil ||
			quotaEntry.settledAt == nil {
			return false, nil
		}
		expected, chargeErr := retryAttemptChargedUnits(quotaEntry, outcome)
		if chargeErr != nil || *quotaEntry.charged != expected ||
			*quotaEntry.released != quotaEntry.allocated-expected {
			return false, nil
		}
	}
	return retryAttemptUsageMatches(ctx, tx, reservation, attempt, quotaEntries, outcome)
}

func retryUnknownTokenUsageProvenanceKey(
	reservationID string,
	attempt storedAttempt,
	metric string,
) string {
	if attempt.number == 1 {
		return unknownTokenUsageProvenanceKey(reservationID, metric)
	}
	prefix := "quota-attempt:" + attempt.id + ":unknown-"
	switch metric {
	case InputTokensMetric:
		return prefix + "input"
	case OutputTokensMetric:
		return prefix + "output"
	case TotalTokensMetric:
		return prefix + "total"
	default:
		return ""
	}
}

func retryAggregateMatchesEntries(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	entries []lockedEntry,
) (bool, error) {
	type aggregate struct {
		allocated int64
		charged   int64
		released  int64
		first     int64
		origin    int32
		seen      bool
	}
	byEntry := make(map[string]aggregate, len(entries))
	rows, err := tx.Query(ctx, `
		SELECT quota.quota_reservation_entry_id, attempt.attempt_number,
		       quota.allocated_units, quota.charged_units,
		       quota.released_units, quota.settled_at
		FROM upstream_attempt_quota_entries AS quota
		JOIN upstream_attempts AS attempt
		  ON attempt.organization_id = quota.organization_id
		 AND attempt.application_id = quota.application_id
		 AND attempt.environment_id = quota.environment_id
		 AND attempt.logical_request_id = quota.logical_request_id
		 AND attempt.upstream_attempt_id = quota.upstream_attempt_id
		WHERE quota.organization_id = $1 AND quota.application_id = $2
		  AND quota.environment_id = $3 AND quota.logical_request_id = $4
		  AND quota.quota_reservation_id = $5
		ORDER BY attempt.attempt_number, quota.quota_bucket_id COLLATE "C"
	`, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		reservation.reservationID)
	if err != nil {
		return false, persistenceFailure("load retry quota aggregate", err)
	}
	defer rows.Close()
	for rows.Next() {
		var entryID string
		var attemptNumber int32
		var allocated int64
		var charged, released *int64
		var settledAt *time.Time
		if err := rows.Scan(
			&entryID, &attemptNumber, &allocated, &charged, &released, &settledAt,
		); err != nil {
			return false, persistenceFailure("scan retry quota aggregate", err)
		}
		if charged == nil || released == nil || settledAt == nil ||
			*charged < 0 || *released != allocated-*charged {
			return false, nil
		}
		current := byEntry[entryID]
		if !current.seen {
			current.first = allocated
			current.origin = attemptNumber
			current.seen = true
		}
		if current.allocated > math.MaxInt64-allocated ||
			current.charged > math.MaxInt64-*charged ||
			current.released > math.MaxInt64-*released {
			return false, nil
		}
		current.allocated += allocated
		current.charged += *charged
		current.released += *released
		byEntry[entryID] = current
	}
	if err := rows.Err(); err != nil {
		return false, persistenceFailure("iterate retry quota aggregate", err)
	}
	expected := 0
	for _, entry := range entries {
		if attemptAllocationOrder(entry.metric) == math.MaxInt {
			continue
		}
		expected++
		got, ok := byEntry[entry.id]
		if !ok || !got.seen || got.origin != entry.originAttemptNumber ||
			got.first != entry.initialReservedUnits ||
			got.allocated != entry.reservedUnits ||
			got.charged != entry.settledUnits || got.released != entry.releasedUnits {
			return false, nil
		}
	}
	return len(byEntry) == expected, nil
}

func retryPendingLifecycleMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logicalStatus string,
	entries []lockedEntry,
	attempts []storedAttempt,
) (bool, error) {
	if logicalStatus == "reserved" {
		return len(attempts) == 0, nil
	}
	if (logicalStatus != "dispatched" && logicalStatus != "streaming") || len(attempts) == 0 {
		return false, nil
	}
	type aggregate struct {
		allocated int64
		charged   int64
		released  int64
		first     int64
		origin    int32
		seen      bool
	}
	byEntry := make(map[string]aggregate, len(entries))
	for index, attempt := range attempts {
		last := index == len(attempts)-1
		if !last && attempt.status != AttemptFailed && attempt.status != AttemptTimedOut {
			return false, nil
		}
		if last && attempt.status != "started" && attempt.status != AttemptFailed &&
			attempt.status != AttemptTimedOut {
			return false, nil
		}
		quotaEntries, err := loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, attempt)
		if err != nil {
			return false, err
		}
		if !attemptQuotaEntriesMatchReservation(reservation, attempt, quotaEntries, entries) {
			return false, nil
		}
		if attempt.status == "started" {
			usageEmpty, usageErr := attemptUsageSetEmpty(ctx, tx, reservation, attempt)
			if usageErr != nil {
				return false, usageErr
			}
			if !attemptQuotaEntriesUnsettled(quotaEntries) || !usageEmpty {
				return false, nil
			}
		} else {
			if !attemptQuotaEntriesSettled(quotaEntries) {
				return false, nil
			}
			accountingMatches, accountingErr := storedRetryAttemptAccountingMatches(
				ctx, tx, reservation, attempt, quotaEntries,
			)
			if accountingErr != nil {
				return false, accountingErr
			}
			if !accountingMatches {
				return false, nil
			}
		}
		for _, quotaEntry := range quotaEntries {
			current := byEntry[quotaEntry.entryID]
			if !current.seen {
				current.first = quotaEntry.allocated
				current.origin = attempt.number
				current.seen = true
			}
			if current.allocated > math.MaxInt64-quotaEntry.allocated {
				return false, nil
			}
			current.allocated += quotaEntry.allocated
			if quotaEntry.charged != nil {
				if current.charged > math.MaxInt64-*quotaEntry.charged ||
					current.released > math.MaxInt64-*quotaEntry.released {
					return false, nil
				}
				current.charged += *quotaEntry.charged
				current.released += *quotaEntry.released
			} else if !last || attempt.status != "started" {
				return false, nil
			}
			byEntry[quotaEntry.entryID] = current
		}
	}
	expected := 0
	for _, entry := range entries {
		if attemptAllocationOrder(entry.metric) == math.MaxInt {
			continue
		}
		expected++
		got, ok := byEntry[entry.id]
		if !ok || !got.seen || got.origin != entry.originAttemptNumber ||
			got.first != entry.initialReservedUnits ||
			got.allocated != entry.reservedUnits ||
			got.charged != entry.settledUnits || got.released != entry.releasedUnits {
			return false, nil
		}
	}
	return len(byEntry) == expected, nil
}

func terminalAttemptSequenceMatches(logicalStatus string, attempts []storedAttempt) bool {
	if len(attempts) == 0 {
		return false
	}
	for _, attempt := range attempts[:len(attempts)-1] {
		if attempt.status != AttemptFailed && attempt.status != AttemptTimedOut ||
			attempt.completedAt == nil {
			return false
		}
	}
	last := attempts[len(attempts)-1]
	if last.completedAt == nil {
		return false
	}
	switch logicalStatus {
	case "succeeded":
		return last.status == AttemptSucceeded
	case "cancelled":
		return last.status == AttemptCancelled
	case "failed":
		return last.status == AttemptFailed || last.status == AttemptTimedOut
	default:
		return false
	}
}

func terminalAttemptAccountingSequenceMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logicalStatus string,
	entries []lockedEntry,
	attempts []storedAttempt,
) (bool, error) {
	if !terminalAttemptSequenceMatches(logicalStatus, attempts) {
		return false, nil
	}
	return attemptAccountingSequenceMatches(ctx, tx, reservation, entries, attempts)
}

func attemptAccountingSequenceMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	entries []lockedEntry,
	attempts []storedAttempt,
) (bool, error) {
	for _, attempt := range attempts {
		quotaEntries, err := loadAttemptQuotaEntriesForUpdate(ctx, tx, reservation, attempt)
		if err != nil {
			return false, err
		}
		if !attemptQuotaEntriesMatchReservation(reservation, attempt, quotaEntries, entries) ||
			!attemptQuotaEntriesSettled(quotaEntries) {
			return false, nil
		}
		matches, matchErr := storedRetryAttemptAccountingMatches(
			ctx, tx, reservation, attempt, quotaEntries,
		)
		if matchErr != nil {
			return false, matchErr
		}
		if !matches {
			return false, nil
		}
	}
	return true, nil
}

func logicalUsageRecordMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
) (bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT usage_record_id, metric, units, cost_nano_usd, currency,
		       price_revision, pricing_source, confidence, provenance_key
		FROM usage_records
		WHERE environment_id = $1 AND logical_request_id = $2
		  AND upstream_attempt_id IS NULL
		ORDER BY provenance_key COLLATE "C"
	`, reservation.environmentID, reservation.logicalRequestID)
	if err != nil {
		return false, persistenceFailure("load retry logical usage set", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var usageID, metric, confidence, provenance string
		var units int64
		var cost *int64
		var currency, revision, source *string
		if err := rows.Scan(
			&usageID, &metric, &units, &cost, &currency, &revision,
			&source, &confidence, &provenance,
		); err != nil {
			return false, persistenceFailure("scan retry logical usage set", err)
		}
		if count != 1 || id.Validate(usageID, id.UsageRecord) != nil ||
			metric != LogicalRequestsMetric || units != 1 || cost != nil ||
			currency != nil || revision != nil || source != nil ||
			confidence != "calculated" ||
			provenance != logicalUsageProvenanceKey(reservation.logicalRequestID) {
			return false, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, persistenceFailure("iterate retry logical usage set", err)
	}
	return count == 1, nil
}

func finalizeRetryReservationLocked(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logical lockedLogical,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
	finalAttempt storedAttempt,
	outcome Outcome,
	logicalUsageID string,
	now time.Time,
) error {
	if reservation.status != "pending" ||
		(logical.status != "dispatched" && logical.status != "streaming") ||
		!attemptQuotaEntriesSettledOrAbsentForFinal(entries) ||
		id.Validate(logicalUsageID, id.UsageRecord) != nil {
		return ErrInvalidState
	}
	for _, entry := range entries {
		if attemptAllocationOrder(entry.metric) != math.MaxInt {
			if entry.settledUnits+entry.releasedUnits != entry.reservedUnits {
				return ErrInvalidState
			}
			continue
		}
		if entry.metric != LogicalRequestsMetric && !isConcurrencyMetric(entry.metric) {
			continue
		}
		if entry.settledUnits != 0 || entry.releasedUnits != 0 ||
			entry.reservedUnits != entry.initialReservedUnits {
			return ErrInvalidState
		}
		charged := entry.reservedUnits
		released := int64(0)
		if isConcurrencyMetric(entry.metric) {
			charged = 0
			released = entry.reservedUnits
		}
		if entry.algorithm != TokenBucketAlgorithm {
			if entry.hardMaximum == nil || entry.bucketReserved < entry.reservedUnits ||
				entry.bucketUsed > *entry.hardMaximum || charged > *entry.hardMaximum-entry.bucketUsed {
				return ErrInvalidState
			}
			command, err := tx.Exec(ctx, `
				UPDATE quota_buckets
				SET used_units = used_units + $2::bigint,
				    reserved_units = reserved_units - $3::bigint,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $4)
				WHERE quota_bucket_id = $1
				  AND used_units = $5 AND reserved_units = $6
				  AND hard_maximum = $7
				  AND reserved_units >= $3::bigint
				  AND $2::bigint <= hard_maximum - used_units
			`, entry.bucketID, charged, entry.reservedUnits, now,
				entry.bucketUsed, entry.bucketReserved, *entry.hardMaximum)
			if err != nil {
				return persistenceFailure("finalize retry logical quota bucket", err)
			}
			if command.RowsAffected() != 1 {
				return ErrInvalidState
			}
		}
		command, err := tx.Exec(ctx, `
			UPDATE quota_reservation_entries
			SET settled_units = $2, released_units = $3
			WHERE quota_reservation_entry_id = $1
			  AND initial_reserved_units = $4 AND reserved_units = $4
			  AND settled_units = 0 AND released_units = 0
		`, entry.id, charged, released, entry.reservedUnits)
		if err != nil {
			return persistenceFailure("finalize retry logical quota entry", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if err := releaseLockedConcurrencyLeases(ctx, tx, reservation, leases, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO usage_records (
			usage_record_id, organization_id, application_id, environment_id,
			logical_request_id, upstream_attempt_id, metric, units,
			confidence, provenance_key, recorded_at
		) VALUES ($1, $2, $3, $4, $5, NULL, 'logical_requests', 1,
		          'calculated', $6, $7)
	`, logicalUsageID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		logicalUsageProvenanceKey(reservation.logicalRequestID), now); err != nil {
		return mapWriteError("insert retry logical usage", err)
	}
	logicalStatus := "failed"
	switch outcome.Status {
	case AttemptSucceeded:
		logicalStatus = "succeeded"
	case AttemptCancelled:
		logicalStatus = "cancelled"
	}
	command, err := tx.Exec(ctx, `
		UPDATE logical_requests
		SET status = $2,
		    completed_at = GREATEST(requested_at, COALESCE(dispatched_at, requested_at), $3),
		    failure_code = $4
		WHERE logical_request_id = $1 AND status IN ('dispatched', 'streaming')
	`, reservation.logicalRequestID, logicalStatus, now,
		nullableString(outcome.FailureCode))
	if err != nil {
		return persistenceFailure("complete retry logical request", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	command, err = tx.Exec(ctx, `
		UPDATE quota_reservations
		SET status = 'settled', settled_at = GREATEST(created_at, $2)
		WHERE quota_reservation_id = $1 AND status = 'pending'
	`, reservation.reservationID, now)
	if err != nil {
		return persistenceFailure("complete retry quota reservation", err)
	}
	if command.RowsAffected() != 1 || finalAttempt.completedAt == nil {
		return ErrInvalidState
	}
	return nil
}

func attemptQuotaEntriesSettledOrAbsentForFinal(entries []lockedEntry) bool {
	for _, entry := range entries {
		if attemptAllocationOrder(entry.metric) != math.MaxInt &&
			entry.settledUnits+entry.releasedUnits != entry.reservedUnits {
			return false
		}
	}
	return true
}
