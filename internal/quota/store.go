package quota

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

const (
	defaultReservationTTL = 15 * time.Minute
	minimumReservationTTL = time.Minute
	maximumReservationTTL = 24 * time.Hour
	maximumExpiryBatch    = 500
	expiryFailureCode     = "reservation_expired"
)

type identifierSource func(id.Prefix) (string, error)

type StoreConfig struct {
	Pool           *pgxpool.Pool
	ReservationTTL time.Duration
	NewID          func(id.Prefix) (string, error)
	OnDenial       func(context.Context, DenialObservation)
}

// DenialObservation contains only bounded configuration dimensions. It omits
// user, installation, request, and external-identity values by construction.
type DenialObservation struct {
	ApplicationID string
	EnvironmentID string
	Feature       string
	LimitPlan     string
	Concurrency   bool
}

// Store persists quota and request lifecycle state. No method accepts an
// upstream callback, response body, or transport, which makes it structurally
// impossible for this package to retain a transaction during upstream I/O.
type Store struct {
	pool           *pgxpool.Pool
	reservationTTL time.Duration
	newID          identifierSource
	onDenial       func(context.Context, DenialObservation)
}

func NewStore(config StoreConfig) (*Store, error) {
	if config.Pool == nil {
		return nil, ErrInvalidInput
	}
	if config.ReservationTTL == 0 {
		config.ReservationTTL = defaultReservationTTL
	}
	if config.ReservationTTL < minimumReservationTTL || config.ReservationTTL > maximumReservationTTL {
		return nil, ErrInvalidInput
	}
	if config.NewID == nil {
		config.NewID = id.New
	}
	return &Store{
		pool: config.Pool, reservationTTL: config.ReservationTTL, newID: config.NewID,
		onDenial: config.OnDenial,
	}, nil
}

type reserveIDs struct {
	reservation string
	buckets     []string
	entries     []string
	leases      []string
}

func (store *Store) newReserveIDs(ruleCount int, concurrencyCounts ...int) (reserveIDs, error) {
	if ruleCount < 0 || ruleCount > maximumRulesPerRequest || len(concurrencyCounts) > 1 {
		return reserveIDs{}, ErrInvalidInput
	}
	concurrencyCount := 0
	if len(concurrencyCounts) == 1 {
		concurrencyCount = concurrencyCounts[0]
	}
	if concurrencyCount < 0 || concurrencyCount > ruleCount {
		return reserveIDs{}, ErrInvalidInput
	}
	result := reserveIDs{
		buckets: make([]string, ruleCount),
		entries: make([]string, ruleCount),
		leases:  make([]string, concurrencyCount),
	}
	// Keep the historical single-rule generation order: bucket, reservation,
	// entry. Multiple bucket and entry identifiers are generated in canonical
	// prepared-rule order.
	for index := range result.buckets {
		value, err := store.newID(id.QuotaBucket)
		if err != nil {
			return reserveIDs{}, fmt.Errorf("generate %s identifier: %w", id.QuotaBucket, err)
		}
		result.buckets[index] = value
	}
	reservationID, err := store.newID(id.QuotaReservation)
	if err != nil {
		return reserveIDs{}, fmt.Errorf("generate %s identifier: %w", id.QuotaReservation, err)
	}
	result.reservation = reservationID
	for index := range result.entries {
		value, err := store.newID(id.QuotaEntry)
		if err != nil {
			return reserveIDs{}, fmt.Errorf("generate %s identifier: %w", id.QuotaEntry, err)
		}
		result.entries[index] = value
	}
	// Lease IDs are deliberately appended after the historical
	// bucket/reservation/entry sequence, so plans without concurrency consume
	// exactly the same identifier stream as before this feature existed.
	for index := range result.leases {
		value, err := store.newID(id.ConcurrencyLease)
		if err != nil {
			return reserveIDs{}, fmt.Errorf("generate %s identifier: %w", id.ConcurrencyLease, err)
		}
		result.leases[index] = value
	}
	return result, nil
}

type plannedBucket struct {
	rule          preparedRule
	period        calendarPeriod
	reservedUnits int64
	bucketID      string
	entryID       string
	leaseID       string
	locked        lockedBucket
	tokenState    tokenBucketState
	retryAt       time.Time
}

// Reserve records one logical request and atomically reserves the trusted
// units in every applicable calendar or token bucket and concurrency lease.
// Per-request-only decisions still create the durable logical-request and
// reservation lifecycle with no bucket entries. Quota denial is committed as
// a denied logical request but consumes no units and creates neither a
// reservation, lease, nor upstream attempt. Token refill and policy
// reconciliation may still be persisted with the denial.
func (store *Store) Reserve(ctx context.Context, input ReserveInput) (Reservation, error) {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil {
		return Reservation{}, ErrInvalidInput
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		return Reservation{}, err
	}
	logicalRequestID := prepared.LogicalRequestID.String()
	fingerprint := requestFingerprint(prepared)
	pricing := pricingForRequest(prepared)
	reservationKey := reservationIdempotencyKey(fingerprint, pricing, hasHardCostReservation(prepared.rules))

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reservation{}, persistenceFailure("begin quota reservation", err)
	}
	defer rollback(tx)

	requestedAt, err := transactionTime(ctx, tx)
	if err != nil {
		return Reservation{}, err
	}
	requestBoundsExceeded := requestBoundExceededRules(prepared.rules)
	var plans []plannedBucket
	if len(requestBoundsExceeded) == 0 {
		plans, err = plannedBucketsAt(prepared, requestedAt)
		if err != nil {
			return Reservation{}, err
		}
	}

	command, err := tx.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, session_grant_id,
			config_revision_id, feature_key, protocol, client_request_id,
			trusted_decision_fingerprint, status, requested_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			$12, 'reserved', $13
		)
		ON CONFLICT DO NOTHING
	`, logicalRequestID, prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, prepared.ApplicationUserID, prepared.InstallationID,
		prepared.SessionGrantID, prepared.ConfigRevisionID, prepared.FeatureKey,
		prepared.Protocol, nullableString(prepared.ClientRequestID), fingerprint, requestedAt)
	if err != nil {
		return Reservation{}, mapWriteError("insert logical request", err)
	}
	if command.RowsAffected() == 0 {
		return loadExistingReserve(ctx, tx, prepared, fingerprint)
	}
	if command.RowsAffected() != 1 {
		return Reservation{}, ErrInvalidState
	}
	if len(requestBoundsExceeded) != 0 {
		decisionAt, timeErr := statementTime(ctx, tx)
		if timeErr != nil {
			return Reservation{}, timeErr
		}
		command, updateErr := tx.Exec(ctx, `
			UPDATE logical_requests
			SET status = 'denied', completed_at = GREATEST(requested_at, $2),
			    failure_code = 'quota_exceeded'
			WHERE logical_request_id = $1 AND status = 'reserved'
		`, logicalRequestID, decisionAt)
		if updateErr != nil {
			return Reservation{}, persistenceFailure("record request-bound quota denial", updateErr)
		}
		if command.RowsAffected() != 1 {
			return Reservation{}, ErrInvalidState
		}
		if err := tx.Commit(ctx); err != nil {
			return Reservation{}, persistenceFailure("commit request-bound quota denial", err)
		}
		if store.onDenial != nil {
			store.onDenial(ctx, DenialObservation{
				ApplicationID: prepared.ApplicationID, EnvironmentID: prepared.EnvironmentID,
				Feature: prepared.FeatureKey, LimitPlan: prepared.LimitPlanKey,
			})
		}
		return Reservation{}, requestBoundExceededError(logicalRequestID, requestBoundsExceeded)
	}

	identifiers, err := store.newReserveIDs(len(plans), concurrencyPlanCount(plans))
	if err != nil {
		return Reservation{}, err
	}
	leaseIndex := 0
	for index := range plans {
		plans[index].bucketID = identifiers.buckets[index]
		plans[index].entryID = identifiers.entries[index]
		if isConcurrencyMetric(plans[index].rule.Metric) {
			plans[index].leaseID = identifiers.leases[leaseIndex]
			leaseIndex++
		}
		plan := &plans[index]
		hardMaximum := plan.rule.Maximum
		var availableUnits, refillNumerator, refillDenominator, refilledAt any
		if plan.rule.Algorithm == TokenBucketAlgorithm {
			maximumBalance, ok := tokenCapacityBalance(plan.rule.Capacity)
			if !ok {
				return Reservation{}, ErrInvalidInput
			}
			hardMaximum = plan.rule.Capacity
			availableUnits = maximumBalance
			refillNumerator = plan.rule.RefillNumerator
			refillDenominator = plan.rule.RefillDenominator
			refilledAt = requestedAt
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
			refilledAt, requestedAt); err != nil {
			return Reservation{}, mapWriteError("materialize quota bucket", err)
		}
	}
	if err := lockPlannedBuckets(ctx, tx, prepared, plans); err != nil {
		return Reservation{}, err
	}
	// The request stays attributed to the calendar window in which it arrived,
	// but lock contention must not consume its reservation lifetime or backdate
	// the quota decision. Capture a fresh database time only after ownership of
	// the bucket state is established.
	decisionAt, err := statementTime(ctx, tx)
	if err != nil {
		return Reservation{}, err
	}
	expiresAt := decisionAt.Add(store.reservationTTL)
	if !expiresAt.After(decisionAt) {
		return Reservation{}, ErrInvalidInput
	}
	quotaExceeded := make([]int, 0, len(plans))
	concurrencyExceeded := make([]int, 0, len(plans))
	occupancies := make([]int64, len(plans))
	for index := range plans {
		plan := &plans[index]
		bucket := plan.locked
		if plan.rule.Algorithm == TokenBucketAlgorithm {
			stored, stateErr := tokenStateFromLockedBucket(bucket)
			if stateErr != nil {
				return Reservation{}, stateErr
			}
			reconciled, stateErr := reconcileTokenBucket(
				stored, plan.rule.Capacity, plan.rule.RefillNumerator,
				plan.rule.RefillDenominator, decisionAt,
			)
			if stateErr != nil {
				return Reservation{}, stateErr
			}
			plan.tokenState = reconciled
			plan.retryAt, stateErr = tokenRetryAt(reconciled, plan.reservedUnits, decisionAt)
			if stateErr != nil {
				return Reservation{}, stateErr
			}
			_, accepted, reserveErr := reserveTokenBalance(reconciled, plan.reservedUnits)
			if reserveErr != nil {
				return Reservation{}, reserveErr
			}
			if !accepted {
				quotaExceeded = append(quotaExceeded, index)
			}
			continue
		}
		if bucket.hardMaximum == nil || bucket.used < 0 || bucket.reserved < 0 ||
			!validReservationEntryUnits(plan.rule.Metric, plan.rule.Algorithm, plan.reservedUnits) ||
			bucket.used > math.MaxInt64-bucket.reserved ||
			(isConcurrencyMetric(plan.rule.Metric) && bucket.used != 0) {
			return Reservation{}, ErrInvalidState
		}
		occupancy := bucket.used + bucket.reserved
		occupancies[index] = occupancy
		if plan.rule.Maximum < occupancy || plan.rule.Maximum-occupancy < plan.reservedUnits {
			if isConcurrencyMetric(plan.rule.Metric) {
				concurrencyExceeded = append(concurrencyExceeded, index)
			} else {
				quotaExceeded = append(quotaExceeded, index)
			}
		}
	}
	if len(quotaExceeded) != 0 || len(concurrencyExceeded) != 0 {
		for index := range plans {
			plan := &plans[index]
			if plan.rule.Algorithm == TokenBucketAlgorithm {
				if err := persistTokenBucket(ctx, tx, plan.locked, plan.tokenState, decisionAt, "refresh denied token bucket"); err != nil {
					return Reservation{}, err
				}
				continue
			}
			if plan.rule.Maximum < occupancies[index] || *plan.locked.hardMaximum == plan.rule.Maximum {
				continue
			}
			command, updateErr := tx.Exec(ctx, `
				UPDATE quota_buckets
				SET hard_maximum = $2,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $3)
				WHERE quota_bucket_id = $1
			`, plan.locked.id, plan.rule.Maximum, decisionAt)
			if updateErr != nil {
				return Reservation{}, persistenceFailure("refresh denied quota maximum", updateErr)
			}
			if command.RowsAffected() != 1 {
				return Reservation{}, ErrInvalidState
			}
		}
		failureCode := "concurrency_exceeded"
		if len(quotaExceeded) != 0 {
			failureCode = "quota_exceeded"
		}
		command, updateErr := tx.Exec(ctx, `
			UPDATE logical_requests
			SET status = 'denied', completed_at = GREATEST(requested_at, $2),
			    failure_code = $3
			WHERE logical_request_id = $1 AND status = 'reserved'
		`, logicalRequestID, decisionAt, failureCode)
		if updateErr != nil {
			return Reservation{}, persistenceFailure("record quota denial", updateErr)
		}
		if command.RowsAffected() != 1 {
			return Reservation{}, ErrInvalidState
		}
		if err := tx.Commit(ctx); err != nil {
			return Reservation{}, persistenceFailure("commit quota denial", err)
		}
		if store.onDenial != nil {
			store.onDenial(ctx, DenialObservation{
				ApplicationID: prepared.ApplicationID, EnvironmentID: prepared.EnvironmentID,
				Feature: prepared.FeatureKey, LimitPlan: prepared.LimitPlanKey,
				Concurrency: len(quotaExceeded) == 0,
			})
		}
		if len(quotaExceeded) != 0 {
			return Reservation{}, exceededError(logicalRequestID, plans, quotaExceeded)
		}
		return Reservation{}, concurrencyExceededError(logicalRequestID, plans, concurrencyExceeded)
	}

	for index := range plans {
		plan := &plans[index]
		if plan.rule.Algorithm == TokenBucketAlgorithm {
			reservedState, accepted, stateErr := reserveTokenBalance(plan.tokenState, plan.reservedUnits)
			if stateErr != nil || !accepted {
				return Reservation{}, ErrInvalidState
			}
			if err := persistTokenBucket(ctx, tx, plan.locked, reservedState, decisionAt, "reserve token bucket"); err != nil {
				return Reservation{}, err
			}
			continue
		}
		bucket := plan.locked
		command, err = tx.Exec(ctx, `
			UPDATE quota_buckets
			SET hard_maximum = $2,
			    reserved_units = reserved_units + $3::bigint,
			    version = version + 1,
			    updated_at = GREATEST(updated_at, $4)
			WHERE quota_bucket_id = $1
			  AND used_units = $5
			  AND reserved_units = $6
			  AND ($3::bigint > 0 OR (
			        $3::bigint = 0 AND metric = 'cost_nano_usd' AND algorithm = 'calendar'
			      ))
			  AND $2 >= used_units
			  AND $3::bigint <= $2 - used_units - reserved_units
		`, bucket.id, plan.rule.Maximum, plan.reservedUnits, decisionAt,
			bucket.used, bucket.reserved)
		if err != nil {
			return Reservation{}, persistenceFailure("reserve quota bucket", err)
		}
		if command.RowsAffected() != 1 {
			return Reservation{}, ErrInvalidState
		}
	}
	for index := range plans {
		plan := plans[index]
		if !isConcurrencyMetric(plan.rule.Metric) {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO concurrency_leases (
				concurrency_lease_id, organization_id, application_id,
				environment_id, quota_bucket_id, logical_request_id,
				acquired_at, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, plan.leaseID, prepared.OrganizationID, prepared.ApplicationID,
			prepared.EnvironmentID, plan.locked.id, logicalRequestID,
			decisionAt, expiresAt); err != nil {
			return Reservation{}, mapWriteError("insert concurrency lease", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO quota_reservations (
			quota_reservation_id, organization_id, application_id, environment_id,
			logical_request_id, idempotency_key, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
	`, identifiers.reservation, prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, logicalRequestID, reservationKey, decisionAt, expiresAt); err != nil {
		return Reservation{}, mapWriteError("insert quota reservation", err)
	}
	for index := range plans {
		plan := &plans[index]
		if _, err := tx.Exec(ctx, `
			INSERT INTO quota_reservation_entries (
				quota_reservation_entry_id, organization_id, application_id,
				environment_id, quota_reservation_id, quota_bucket_id,
				initial_reserved_units, reserved_units, settled_units, released_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 0, 0)
		`, plan.entryID, prepared.OrganizationID, prepared.ApplicationID,
			prepared.EnvironmentID, identifiers.reservation, plan.locked.id,
			plan.reservedUnits); err != nil {
			return Reservation{}, mapWriteError("insert quota reservation entry", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Reservation{}, persistenceFailure("commit quota reservation", err)
	}
	entries := reservationEntries(plans)
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID: prepared.EnvironmentID, logicalRequestID: logicalRequestID,
		reservationID: identifiers.reservation, entries: entries,
		routeKey: prepared.RouteKey, upstreamKey: prepared.UpstreamKey,
		modelKey: prepared.ModelKey, physicalModel: prepared.PhysicalModel,
		protocol: prepared.Protocol, pricing: pricing,
		inputPreflight: cloneInputPreflightBinding(prepared.InputPreflight),
		retryPlan:      retryPlanForRequest(prepared),
		windowResetAt:  maximumResetAt(entries), expiresAt: expiresAt,
	}, nil
}

// loadExistingReserve implements logical-request idempotency after the
// INSERT ... ON CONFLICT statement has waited for the winning transaction to
// commit. A caller may replay only the exact same trusted request. The client
// correlation hint is compared as durable data, never used as the lookup key.
//
// Lifecycle transactions take locks in this order for a request that has a
// reservation: quota_reservations, logical_requests, upstream_attempts, then
// quota_reservation_entries, quota_buckets when capacity is mutated, and
// finally concurrency_leases. BeginAttempt and MarkFirstByte skip the shared
// bucket lock but never reverse this order. Bucket and lease families are each
// visited in stable identifier order. Taking the reservation lock before
// reading the logical row keeps later READ COMMITTED statements on one stable
// lifecycle state. Denied requests have no reservation and are immutable, so
// they lock logical_requests first.
func loadExistingReserve(ctx context.Context, tx pgx.Tx, prepared preparedRequest, fingerprint string) (Reservation, error) {
	pricing := pricingForRequest(prepared)
	reservationKey := reservationIdempotencyKey(fingerprint, pricing, hasHardCostReservation(prepared.rules))
	var lockedReservationID string
	reservationErr := tx.QueryRow(ctx, `
		SELECT quota_reservation_id
		FROM quota_reservations
		WHERE environment_id = $1 AND logical_request_id = $2
		FOR UPDATE
	`, prepared.EnvironmentID, prepared.LogicalRequestID.String()).Scan(&lockedReservationID)
	if reservationErr != nil && !errors.Is(reservationErr, pgx.ErrNoRows) {
		return Reservation{}, persistenceFailure("lock existing quota reservation", reservationErr)
	}

	type existingLogical struct {
		organizationID, applicationID, environmentID string
		applicationUserID, installationID            string
		sessionGrantID, configRevisionID             string
		featureKey, protocol, status                 string
		clientRequestID, fingerprint, failureCode    *string
		requestedAt                                  time.Time
	}
	var logical existingLogical
	err := tx.QueryRow(ctx, `
		SELECT organization_id, application_id, environment_id,
		       application_user_id, installation_id, session_grant_id,
		       config_revision_id, feature_key, protocol, client_request_id,
		       trusted_decision_fingerprint, status, failure_code, requested_at
		FROM logical_requests
		WHERE logical_request_id = $1
		FOR UPDATE
	`, prepared.LogicalRequestID.String()).Scan(
		&logical.organizationID, &logical.applicationID, &logical.environmentID,
		&logical.applicationUserID, &logical.installationID, &logical.sessionGrantID,
		&logical.configRevisionID, &logical.featureKey, &logical.protocol,
		&logical.clientRequestID, &logical.fingerprint, &logical.status,
		&logical.failureCode, &logical.requestedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Reservation{}, ErrInvalidState
	}
	if err != nil {
		return Reservation{}, persistenceFailure("load existing logical request", err)
	}
	if logical.organizationID != prepared.OrganizationID ||
		logical.applicationID != prepared.ApplicationID ||
		logical.environmentID != prepared.EnvironmentID ||
		logical.applicationUserID != prepared.ApplicationUserID ||
		logical.installationID != prepared.InstallationID ||
		logical.sessionGrantID != prepared.SessionGrantID ||
		logical.configRevisionID != prepared.ConfigRevisionID ||
		logical.featureKey != prepared.FeatureKey ||
		logical.protocol != prepared.Protocol ||
		!nullableStringMatches(logical.clientRequestID, prepared.ClientRequestID) ||
		logical.fingerprint == nil || *logical.fingerprint != fingerprint {
		return Reservation{}, ErrInvalidInput
	}
	requestBoundsExceeded := requestBoundExceededRules(prepared.rules)
	var plans []plannedBucket
	if len(requestBoundsExceeded) == 0 {
		plans, err = plannedBucketsAt(prepared, logical.requestedAt.UTC())
		if err != nil {
			return Reservation{}, ErrInvalidState
		}
	}
	attempts, err := loadAttemptsForUpdate(ctx, tx, prepared.LogicalRequestID.String())
	if err != nil {
		return Reservation{}, err
	}

	if logical.status == "denied" {
		if reservationErr == nil || len(attempts) != 0 {
			return Reservation{}, ErrInvalidState
		}
		if logical.failureCode == nil ||
			(*logical.failureCode != "quota_exceeded" && *logical.failureCode != "concurrency_exceeded") {
			return Reservation{}, ErrInvalidState
		}
		if len(requestBoundsExceeded) != 0 {
			if *logical.failureCode != "quota_exceeded" {
				return Reservation{}, ErrInvalidState
			}
			return Reservation{}, requestBoundExceededError(
				prepared.LogicalRequestID.String(), requestBoundsExceeded,
			)
		}
		if len(plans) == 0 {
			return Reservation{}, ErrInvalidState
		}
		if err := lockPlannedBuckets(ctx, tx, prepared, plans); err != nil {
			return Reservation{}, err
		}
		replayAt, err := statementTime(ctx, tx)
		if err != nil {
			return Reservation{}, err
		}
		quotaPlans := make([]int, 0, len(plans))
		quotaExceeded := make([]int, 0, len(plans))
		concurrencyPlans := make([]int, 0, len(plans))
		concurrencyExceeded := make([]int, 0, len(plans))
		for index := range plans {
			plan := &plans[index]
			bucket := plan.locked
			if plan.rule.Algorithm == TokenBucketAlgorithm {
				stored, stateErr := tokenStateFromLockedBucket(bucket)
				if stateErr != nil {
					return Reservation{}, stateErr
				}
				plan.tokenState, stateErr = reconcileTokenBucket(
					stored, plan.rule.Capacity, plan.rule.RefillNumerator,
					plan.rule.RefillDenominator, replayAt,
				)
				if stateErr != nil {
					return Reservation{}, stateErr
				}
				plan.retryAt, stateErr = tokenRetryAt(plan.tokenState, plan.reservedUnits, replayAt)
				if stateErr != nil {
					return Reservation{}, stateErr
				}
				quotaPlans = append(quotaPlans, index)
				_, accepted, reserveErr := reserveTokenBalance(plan.tokenState, plan.reservedUnits)
				if reserveErr != nil {
					return Reservation{}, reserveErr
				}
				if !accepted {
					quotaExceeded = append(quotaExceeded, index)
				}
				continue
			}
			if bucket.hardMaximum == nil || bucket.used < 0 || bucket.reserved < 0 ||
				!validReservationEntryUnits(plan.rule.Metric, plan.rule.Algorithm, plan.reservedUnits) ||
				bucket.used > math.MaxInt64-bucket.reserved ||
				(isConcurrencyMetric(plan.rule.Metric) && bucket.used != 0) {
				return Reservation{}, ErrInvalidState
			}
			if isConcurrencyMetric(plan.rule.Metric) {
				concurrencyPlans = append(concurrencyPlans, index)
			} else {
				quotaPlans = append(quotaPlans, index)
			}
			occupancy := bucket.used + bucket.reserved
			if plan.rule.Maximum < occupancy ||
				plan.rule.Maximum-occupancy < plan.reservedUnits {
				if isConcurrencyMetric(plan.rule.Metric) {
					concurrencyExceeded = append(concurrencyExceeded, index)
				} else {
					quotaExceeded = append(quotaExceeded, index)
				}
			}
		}
		// The durable failure code is authoritative for an exact replay. Active
		// leases may have been released since the original decision, so current
		// occupancy must not turn a stored denial into an acceptance or change
		// its class.
		if *logical.failureCode == "quota_exceeded" {
			if len(quotaPlans) == 0 {
				return Reservation{}, ErrInvalidState
			}
			if len(quotaExceeded) == 0 {
				quotaExceeded = quotaPlans
			}
			return Reservation{}, exceededError(prepared.LogicalRequestID.String(), plans, quotaExceeded)
		}
		if len(concurrencyPlans) == 0 {
			return Reservation{}, ErrInvalidState
		}
		if len(concurrencyExceeded) == 0 {
			concurrencyExceeded = concurrencyPlans
		}
		return Reservation{}, concurrencyExceededError(
			prepared.LogicalRequestID.String(), plans, concurrencyExceeded,
		)
	}
	if len(requestBoundsExceeded) != 0 {
		return Reservation{}, ErrInvalidState
	}
	if reservationErr != nil {
		return Reservation{}, ErrInvalidState
	}

	if len(plans) == 0 {
		return loadExistingEntrylessReservation(ctx, tx, prepared, reservationKey, logical.status, lockedReservationID)
	}

	type existingReservation struct {
		organizationID, applicationID, environmentID string
		logicalRequestID, reservationID, idempotency string
		status, entryID, bucketID                    string
		expiresAt                                    time.Time
		initialReservedUnits, reservedUnits          int64
		originAttemptNumber                          int32
		settledUnits, releasedUnits                  int64
		bucketOrganizationID, bucketApplicationID    string
		limitPlanKey, ruleKey, metric, scopeType     string
		scopeDimensions                              []string
		scopeKey, algorithm, windowKey               string
		bucketUsed                                   int64
	}
	rows, err := tx.Query(ctx, `
		SELECT reservation.organization_id, reservation.application_id,
		       reservation.environment_id, reservation.logical_request_id,
		       reservation.quota_reservation_id, reservation.idempotency_key,
		       reservation.status, reservation.expires_at,
		       entry.quota_reservation_entry_id, entry.quota_bucket_id,
		       entry.origin_attempt_number, entry.initial_reserved_units,
		       entry.reserved_units,
		       entry.settled_units, entry.released_units,
		       bucket.organization_id, bucket.application_id,
		       bucket.limit_plan_key, bucket.rule_key, bucket.metric,
		       bucket.scope_type, bucket.scope_dimensions, bucket.scope_key,
		       bucket.algorithm, bucket.window_key, bucket.used_units
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
		WHERE reservation.logical_request_id = $1
		  AND reservation.quota_reservation_id = $2
		ORDER BY bucket.quota_bucket_id COLLATE "C"
	`, prepared.LogicalRequestID.String(), lockedReservationID)
	if err != nil {
		return Reservation{}, persistenceFailure("load existing quota reservation", err)
	}
	defer rows.Close()
	planIndexes := make(map[string]int, len(plans))
	plansByRule := make(map[string]plannedBucket, len(plans))
	for index := range plans {
		planIndexes[plannedBucketIdentity(plans[index].rule.ruleKey, plans[index].rule.scopeKey)] = index
		plansByRule[plans[index].rule.ruleKey] = plans[index]
	}
	matchedPlans := make([]bool, len(plans))
	entries := make([]reservationEntry, 0, len(plans))
	var reservationID, reservationStatus string
	var expiresAt time.Time
	for rows.Next() {
		var existing existingReservation
		if err := rows.Scan(
			&existing.organizationID, &existing.applicationID, &existing.environmentID,
			&existing.logicalRequestID, &existing.reservationID, &existing.idempotency,
			&existing.status, &existing.expiresAt, &existing.entryID, &existing.bucketID,
			&existing.originAttemptNumber, &existing.initialReservedUnits, &existing.reservedUnits,
			&existing.settledUnits, &existing.releasedUnits,
			&existing.bucketOrganizationID, &existing.bucketApplicationID,
			&existing.limitPlanKey, &existing.ruleKey, &existing.metric,
			&existing.scopeType, &existing.scopeDimensions, &existing.scopeKey,
			&existing.algorithm, &existing.windowKey, &existing.bucketUsed,
		); err != nil {
			return Reservation{}, persistenceFailure("scan existing quota reservation", err)
		}
		planIndex, initial := planIndexes[plannedBucketIdentity(existing.ruleKey, existing.scopeKey)]
		plan, sourceRule := plansByRule[existing.ruleKey]
		if initial {
			if matchedPlans[planIndex] || existing.originAttemptNumber != 1 {
				return Reservation{}, ErrInvalidInput
			}
			plan = plans[planIndex]
		} else if !sourceRule || existing.originAttemptNumber < 2 ||
			existing.originAttemptNumber > int32(len(attempts)) ||
			plan.rule.Metric == LogicalRequestsMetric ||
			!storedAttemptScopeKeyMatches(
				prepared, attempts[existing.originAttemptNumber-1],
				plan.rule.scopeDimensions, existing.scopeKey,
			) {
			return Reservation{}, ErrInvalidInput
		}
		if existing.organizationID != prepared.OrganizationID ||
			existing.applicationID != prepared.ApplicationID ||
			existing.environmentID != prepared.EnvironmentID ||
			existing.logicalRequestID != prepared.LogicalRequestID.String() ||
			existing.idempotency != reservationKey ||
			existing.bucketOrganizationID != prepared.OrganizationID ||
			existing.bucketApplicationID != prepared.ApplicationID ||
			existing.limitPlanKey != prepared.LimitPlanKey ||
			existing.metric != plan.rule.Metric || existing.scopeType != plan.rule.scopeType ||
			!slicesEqual(existing.scopeDimensions, plan.rule.scopeDimensions) ||
			existing.algorithm != plan.rule.Algorithm || existing.windowKey != plan.period.key ||
			(isConcurrencyMetric(existing.metric) && existing.bucketUsed != 0) {
			return Reservation{}, ErrInvalidInput
		}
		expectedInitial := existing.initialReservedUnits
		if initial {
			expectedInitial = plan.reservedUnits
		}
		if id.Validate(existing.reservationID, id.QuotaReservation) != nil ||
			id.Validate(existing.entryID, id.QuotaEntry) != nil ||
			id.Validate(existing.bucketID, id.QuotaBucket) != nil ||
			!existingReservationStateMatches(logical.status, existing.status,
				plan.rule.Metric, plan.rule.Algorithm, expectedInitial,
				existing.initialReservedUnits, existing.reservedUnits,
				existing.settledUnits, existing.releasedUnits) {
			return Reservation{}, ErrInvalidState
		}
		if reservationID == "" {
			reservationID = existing.reservationID
			reservationStatus = existing.status
			expiresAt = existing.expiresAt
		} else if reservationID != existing.reservationID || reservationStatus != existing.status ||
			!expiresAt.Equal(existing.expiresAt) {
			return Reservation{}, ErrInvalidState
		}
		if initial {
			matchedPlans[planIndex] = true
			entries = append(entries, reservationEntry{
				bucketID: existing.bucketID, entryID: existing.entryID,
				metric: plan.rule.Metric, algorithm: plan.rule.Algorithm,
				reservedUnits: plan.reservedUnits,
				resetAt:       plan.period.end,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return Reservation{}, persistenceFailure("iterate existing quota reservation", err)
	}
	if reservationID == "" || len(entries) != len(plans) {
		return Reservation{}, ErrInvalidState
	}
	for _, matched := range matchedPlans {
		if !matched {
			return Reservation{}, ErrInvalidState
		}
	}
	attemptExists := len(attempts) != 0
	if !existingAttemptPresenceMatches(logical.status, reservationStatus, attemptExists) {
		return Reservation{}, ErrInvalidState
	}
	if attemptExists && (attempts[0].routeKey != prepared.RouteKey ||
		attempts[0].upstreamKey != prepared.UpstreamKey || attempts[0].physicalModel == nil ||
		*attempts[0].physicalModel != prepared.PhysicalModel ||
		!storedModelKeyMatches(attempts[0], prepared.ModelKey) ||
		!attemptPricingMatchesReservation(attempts[0], Reservation{pricing: pricing}) ||
		!storedInitialInputPreflightMatches(attempts[0], prepared.InputPreflight)) {
		return Reservation{}, ErrInvalidState
	}
	replayed := lockedReservation{
		Reservation: Reservation{
			organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
			environmentID: prepared.EnvironmentID, logicalRequestID: prepared.LogicalRequestID.String(),
			reservationID: reservationID, entries: entries, protocol: prepared.Protocol,
			inputPreflight: cloneInputPreflightBinding(prepared.InputPreflight),
			retryPlan:      retryPlanForRequest(prepared), expiresAt: expiresAt,
		},
		status: reservationStatus, expiresAt: expiresAt,
		applicationUserID: prepared.ApplicationUserID,
		installationID:    prepared.InstallationID,
		featureKey:        prepared.FeatureKey,
	}
	lockedEntries, err := lockEntries(ctx, tx, replayed)
	if err != nil {
		return Reservation{}, err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, replayed, lockedEntries)
	if err != nil {
		return Reservation{}, err
	}
	leaseIDsByBucket := make(map[string]string, len(leases))
	for _, lease := range leases {
		leaseIDsByBucket[lease.bucketID] = lease.id
	}
	for index := range entries {
		entries[index].leaseID = leaseIDsByBucket[entries[index].bucketID]
	}
	if reservationStatus == "pending" {
		replayed.entries = entries
		lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
			ctx, tx, replayed, logical.status, lockedEntries, attempts,
		)
		if lifecycleErr != nil {
			return Reservation{}, lifecycleErr
		}
		if !pendingEntriesMatch(logical.status, replayed, lockedEntries, leases) ||
			!lifecycleMatches {
			return Reservation{}, ErrInvalidState
		}
	} else {
		if !terminalEntriesMatch(logical.status, reservationStatus, lockedEntries, leases) {
			return Reservation{}, ErrInvalidState
		}
		if reservationStatus == "settled" && attemptExists {
			aggregateMatches, aggregateErr := retryAggregateMatchesEntries(
				ctx, tx, replayed, lockedEntries,
			)
			if aggregateErr != nil {
				return Reservation{}, aggregateErr
			}
			logicalUsageMatches, usageErr := logicalUsageRecordMatches(ctx, tx, replayed)
			if usageErr != nil {
				return Reservation{}, usageErr
			}
			accountingMatches, accountingErr := terminalAttemptAccountingSequenceMatches(
				ctx, tx, replayed, logical.status, lockedEntries, attempts,
			)
			if accountingErr != nil {
				return Reservation{}, accountingErr
			}
			if !aggregateMatches || !logicalUsageMatches || !accountingMatches {
				return Reservation{}, ErrInvalidState
			}
		}
	}
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID:    prepared.EnvironmentID,
		logicalRequestID: prepared.LogicalRequestID.String(),
		reservationID:    reservationID, entries: entries, routeKey: prepared.RouteKey,
		upstreamKey: prepared.UpstreamKey, modelKey: prepared.ModelKey,
		physicalModel: prepared.PhysicalModel, protocol: prepared.Protocol, pricing: pricing,
		inputPreflight: cloneInputPreflightBinding(prepared.InputPreflight),
		retryPlan:      retryPlanForRequest(prepared),
		windowResetAt:  maximumResetAt(entries),
		expiresAt:      expiresAt,
	}, nil
}

func loadExistingEntrylessReservation(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	reservationKey string,
	logicalStatus string,
	lockedReservationID string,
) (Reservation, error) {
	type existingReservation struct {
		organizationID, applicationID, environmentID string
		logicalRequestID, reservationID, idempotency string
		status                                       string
		expiresAt                                    time.Time
		entryCount, leaseCount                       int64
	}
	var existing existingReservation
	err := tx.QueryRow(ctx, `
		SELECT reservation.organization_id, reservation.application_id,
		       reservation.environment_id, reservation.logical_request_id,
		       reservation.quota_reservation_id, reservation.idempotency_key,
		       reservation.status, reservation.expires_at,
		       (SELECT count(*)
		          FROM quota_reservation_entries AS entry
		         WHERE entry.environment_id = reservation.environment_id
		           AND entry.quota_reservation_id = reservation.quota_reservation_id),
		       (SELECT count(*)
		          FROM concurrency_leases AS lease
		         WHERE lease.environment_id = reservation.environment_id
		           AND lease.logical_request_id = reservation.logical_request_id)
		FROM quota_reservations AS reservation
		WHERE reservation.logical_request_id = $1
		  AND reservation.quota_reservation_id = $2
	`, prepared.LogicalRequestID.String(), lockedReservationID).Scan(
		&existing.organizationID, &existing.applicationID, &existing.environmentID,
		&existing.logicalRequestID, &existing.reservationID, &existing.idempotency,
		&existing.status, &existing.expiresAt, &existing.entryCount, &existing.leaseCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Reservation{}, ErrInvalidState
	}
	if err != nil {
		return Reservation{}, persistenceFailure("load existing entryless quota reservation", err)
	}
	if existing.organizationID != prepared.OrganizationID ||
		existing.applicationID != prepared.ApplicationID ||
		existing.environmentID != prepared.EnvironmentID ||
		existing.logicalRequestID != prepared.LogicalRequestID.String() ||
		existing.reservationID != lockedReservationID || existing.idempotency != reservationKey {
		return Reservation{}, ErrInvalidInput
	}
	attempts, err := loadAttemptsForUpdate(ctx, tx, prepared.LogicalRequestID.String())
	if err != nil {
		return Reservation{}, err
	}
	attemptExists := len(attempts) != 0
	if attemptExists && (attempts[0].routeKey != prepared.RouteKey ||
		attempts[0].upstreamKey != prepared.UpstreamKey || attempts[0].physicalModel == nil ||
		*attempts[0].physicalModel != prepared.PhysicalModel ||
		!storedModelKeyMatches(attempts[0], prepared.ModelKey) ||
		!attemptPricingMatchesReservation(attempts[0], Reservation{pricing: pricingForRequest(prepared)}) ||
		!storedInitialInputPreflightMatches(attempts[0], prepared.InputPreflight)) {
		return Reservation{}, ErrInvalidState
	}
	validLifecycle := false
	switch existing.status {
	case "pending":
		validLifecycle = logicalStatus == "reserved" || logicalStatus == "dispatched" || logicalStatus == "streaming"
	case "settled":
		validLifecycle = logicalStatus == "succeeded" || logicalStatus == "failed" || logicalStatus == "cancelled"
	case "released", "expired":
		validLifecycle = logicalStatus == "failed"
	}
	replayed := lockedReservation{Reservation: Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID: prepared.EnvironmentID, logicalRequestID: prepared.LogicalRequestID.String(),
		reservationID: existing.reservationID, protocol: prepared.Protocol,
		inputPreflight: cloneInputPreflightBinding(prepared.InputPreflight),
		retryPlan:      retryPlanForRequest(prepared),
	}, status: existing.status, expiresAt: existing.expiresAt,
		applicationUserID: prepared.ApplicationUserID,
		installationID:    prepared.InstallationID,
		featureKey:        prepared.FeatureKey,
	}
	terminalAccountingMatches := true
	if existing.status == "settled" {
		terminalAccountingMatches, err = terminalAttemptAccountingSequenceMatches(
			ctx, tx, replayed, logicalStatus, nil, attempts,
		)
		if err != nil {
			return Reservation{}, err
		}
	}
	if id.Validate(existing.reservationID, id.QuotaReservation) != nil ||
		existing.entryCount != 0 || existing.leaseCount != 0 || !validLifecycle ||
		!existingAttemptPresenceMatches(logicalStatus, existing.status, attemptExists) ||
		!terminalAccountingMatches {
		return Reservation{}, ErrInvalidState
	}
	if existing.status == "pending" {
		pendingMatches, pendingErr := retryPendingLifecycleMatches(
			ctx, tx, replayed, logicalStatus, nil, attempts,
		)
		if pendingErr != nil {
			return Reservation{}, pendingErr
		}
		if !pendingMatches {
			return Reservation{}, ErrInvalidState
		}
	}
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID: prepared.EnvironmentID, logicalRequestID: prepared.LogicalRequestID.String(),
		reservationID: existing.reservationID, routeKey: prepared.RouteKey,
		upstreamKey: prepared.UpstreamKey, modelKey: prepared.ModelKey,
		physicalModel: prepared.PhysicalModel, protocol: prepared.Protocol,
		pricing:        pricingForRequest(prepared),
		inputPreflight: cloneInputPreflightBinding(prepared.InputPreflight),
		retryPlan:      retryPlanForRequest(prepared),
		expiresAt:      existing.expiresAt,
	}, nil
}

func existingReservationStateMatches(
	logicalStatus string,
	reservationStatus string,
	metric string,
	algorithm string,
	expected int64,
	initialReserved int64,
	reserved int64,
	settled int64,
	released int64,
) bool {
	if !validReservationEntryUnits(metric, algorithm, expected) ||
		initialReserved != expected || reserved < initialReserved || settled < 0 || released < 0 ||
		settled > reserved || released > reserved-settled ||
		(metric == LogicalRequestsMetric || isConcurrencyMetric(metric)) && reserved != initialReserved {
		return false
	}
	switch reservationStatus {
	case "pending":
		if logicalStatus == "reserved" {
			return reserved == initialReserved && settled == 0 && released == 0
		}
		if logicalStatus != "dispatched" && logicalStatus != "streaming" {
			return false
		}
		if metric == LogicalRequestsMetric || isConcurrencyMetric(metric) {
			return settled == 0 && released == 0
		}
		return true
	case "settled":
		if logicalStatus != "succeeded" && logicalStatus != "failed" && logicalStatus != "cancelled" {
			return false
		}
		if isConcurrencyMetric(metric) {
			return settled == 0 && released == reserved
		}
		if metric == LogicalRequestsMetric {
			return settled == reserved && released == 0
		}
		return settled+released == reserved
	case "released", "expired":
		return reserved == initialReserved && settled == 0 && released == reserved && logicalStatus == "failed"
	default:
		return false
	}
}

func existingAttemptPresenceMatches(logicalStatus, reservationStatus string, attemptExists bool) bool {
	switch reservationStatus {
	case "pending":
		if logicalStatus == "reserved" {
			return !attemptExists
		}
		return attemptExists && (logicalStatus == "dispatched" || logicalStatus == "streaming")
	case "settled":
		return attemptExists &&
			(logicalStatus == "succeeded" || logicalStatus == "failed" || logicalStatus == "cancelled")
	case "released", "expired":
		return !attemptExists && logicalStatus == "failed"
	default:
		return false
	}
}

func nullableStringMatches(stored *string, expected string) bool {
	if expected == "" {
		return stored == nil
	}
	return stored != nil && *stored == expected
}

type lockedBucket struct {
	id                string
	hardMaximum       *int64
	used              int64
	reserved          int64
	available         *int64
	refillNumerator   *int64
	refillDenominator *int64
	refilledAt        *time.Time
	version           int64
	scopeType         string
	scopeDimensions   []string
}

func plannedBucketsAt(prepared preparedRequest, at time.Time) ([]plannedBucket, error) {
	if len(prepared.rules) < 1 || len(prepared.rules) > maximumRulesPerRequest {
		return nil, ErrInvalidInput
	}
	plans := make([]plannedBucket, 0, len(prepared.rules))
	for index := range prepared.rules {
		rule := prepared.rules[index]
		if !rule.stateful {
			continue
		}
		reservedUnits, applicable := ProjectedReservationUnits(rule.Rule, prepared.Streaming)
		if !applicable {
			continue
		}
		var period calendarPeriod
		if isConcurrencyMetric(rule.Metric) {
			period.key = "active"
		} else if rule.Algorithm == TokenBucketAlgorithm {
			period.key = tokenBucketWindowKey
		} else {
			var err error
			period, err = calendarWindowIn(at, rule.Window, rule.Timezone)
			if err != nil {
				return nil, err
			}
		}
		if !validReservationEntryUnits(rule.Metric, rule.Algorithm, reservedUnits) {
			return nil, ErrInvalidInput
		}
		plans = append(plans, plannedBucket{rule: rule, period: period, reservedUnits: reservedUnits})
	}
	return plans, nil
}

func concurrencyPlanCount(plans []plannedBucket) int {
	count := 0
	for index := range plans {
		if isConcurrencyMetric(plans[index].rule.Metric) {
			count++
		}
	}
	return count
}

func plannedBucketIdentity(ruleKey, scopeKey string) string {
	return ruleKey + "\x00" + scopeKey
}

// lockPlannedBuckets first resolves immutable bucket identifiers without
// locking, then acquires every row lock in quota_bucket_id order. All reserve,
// settle, release, replay, and recovery paths use that same global order.
func lockPlannedBuckets(ctx context.Context, tx pgx.Tx, prepared preparedRequest, plans []plannedBucket) error {
	if len(plans) > maximumRulesPerRequest {
		return ErrInvalidInput
	}
	for index := range plans {
		plan := &plans[index]
		bucketID, err := findBucketID(ctx, tx, prepared, *plan)
		if err != nil {
			return err
		}
		plan.bucketID = bucketID
	}
	sort.Slice(plans, func(left, right int) bool { return plans[left].bucketID < plans[right].bucketID })
	for index := range plans {
		if index > 0 && plans[index-1].bucketID == plans[index].bucketID {
			return ErrInvalidState
		}
		bucket, err := lockBucket(ctx, tx, prepared, plans[index])
		if err != nil {
			return err
		}
		plans[index].locked = bucket
	}
	return nil
}

func findBucketID(ctx context.Context, tx pgx.Tx, prepared preparedRequest, plan plannedBucket) (string, error) {
	var bucketID string
	err := tx.QueryRow(ctx, `
		SELECT quota_bucket_id
		FROM quota_buckets
		WHERE environment_id = $1
		  AND limit_plan_key = $2
		  AND rule_key = $3
		  AND metric = $4
		  AND algorithm = $5
		  AND window_key = $6
		  AND scope_key = $7
	`, prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
		plan.rule.Metric, plan.rule.Algorithm, plan.period.key,
		plan.rule.scopeKey).Scan(&bucketID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidState
	}
	if err != nil {
		return "", persistenceFailure("find quota bucket", err)
	}
	if id.Validate(bucketID, id.QuotaBucket) != nil {
		return "", ErrInvalidState
	}
	return bucketID, nil
}

func lockBucket(ctx context.Context, tx pgx.Tx, prepared preparedRequest, plan plannedBucket) (lockedBucket, error) {
	var result lockedBucket
	var organizationID, applicationID string
	err := tx.QueryRow(ctx, `
		SELECT quota_bucket_id, organization_id, application_id,
		       hard_maximum, used_units, reserved_units, available_units,
		       refill_numerator, refill_denominator, refilled_at, version,
		       scope_type, scope_dimensions
		FROM quota_buckets
		WHERE quota_bucket_id = $1
		  AND environment_id = $2
		  AND limit_plan_key = $3
		  AND rule_key = $4
		  AND metric = $5
		  AND algorithm = $6
		  AND window_key = $7
		  AND scope_key = $8
		FOR UPDATE
	`, plan.bucketID, prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
		plan.rule.Metric, plan.rule.Algorithm, plan.period.key,
		plan.rule.scopeKey).Scan(
		&result.id, &organizationID, &applicationID,
		&result.hardMaximum, &result.used, &result.reserved, &result.available,
		&result.refillNumerator, &result.refillDenominator, &result.refilledAt,
		&result.version,
		&result.scopeType, &result.scopeDimensions,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedBucket{}, ErrInvalidState
	}
	if err != nil {
		return lockedBucket{}, persistenceFailure("lock quota bucket", err)
	}
	if organizationID != prepared.OrganizationID || applicationID != prepared.ApplicationID ||
		result.id != plan.bucketID || result.scopeType != plan.rule.scopeType ||
		!slicesEqual(result.scopeDimensions, plan.rule.scopeDimensions) ||
		id.Validate(result.id, id.QuotaBucket) != nil || result.version < 0 {
		return lockedBucket{}, ErrInvalidState
	}
	if plan.rule.Algorithm == TokenBucketAlgorithm {
		if _, err := tokenStateFromLockedBucket(result); err != nil {
			return lockedBucket{}, err
		}
	} else if result.available != nil || result.refillNumerator != nil ||
		result.refillDenominator != nil || result.refilledAt != nil {
		return lockedBucket{}, ErrInvalidState
	}
	return result, nil
}

func tokenStateFromLockedBucket(bucket lockedBucket) (tokenBucketState, error) {
	if bucket.hardMaximum == nil || bucket.available == nil || bucket.refillNumerator == nil ||
		bucket.refillDenominator == nil || bucket.refilledAt == nil ||
		bucket.used != 0 || bucket.reserved != 0 || bucket.version < 0 {
		return tokenBucketState{}, ErrInvalidState
	}
	state := tokenBucketState{
		capacity: *bucket.hardMaximum, balance: *bucket.available,
		numerator: *bucket.refillNumerator, denominator: *bucket.refillDenominator,
		refilledAt: bucket.refilledAt.UTC(),
	}
	if validatePersistedTokenBucket(state) != nil {
		return tokenBucketState{}, ErrInvalidState
	}
	return state, nil
}

func persistTokenBucket(
	ctx context.Context,
	tx pgx.Tx,
	bucket lockedBucket,
	state tokenBucketState,
	now time.Time,
	operation string,
) error {
	stored, err := tokenStateFromLockedBucket(bucket)
	if err != nil || validatePersistedTokenBucket(state) != nil || now.IsZero() || bucket.version == math.MaxInt64 {
		return ErrInvalidState
	}
	command, err := tx.Exec(ctx, `
		UPDATE quota_buckets
		SET hard_maximum = $2,
		    available_units = $3,
		    refill_numerator = $4,
		    refill_denominator = $5,
		    refilled_at = $6,
		    version = version + 1,
		    updated_at = GREATEST(updated_at, $7)
		WHERE quota_bucket_id = $1
		  AND algorithm = 'token_bucket'
		  AND used_units = 0 AND reserved_units = 0
		  AND hard_maximum = $8
		  AND available_units = $9
		  AND refill_numerator = $10
		  AND refill_denominator = $11
		  AND refilled_at = $12
		  AND version = $13
	`, bucket.id, state.capacity, state.balance, state.numerator, state.denominator,
		state.refilledAt, now, stored.capacity, stored.balance, stored.numerator,
		stored.denominator, stored.refilledAt, bucket.version)
	if err != nil {
		return persistenceFailure(operation, err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	return nil
}

func reservationEntries(plans []plannedBucket) []reservationEntry {
	entries := make([]reservationEntry, len(plans))
	for index := range plans {
		entries[index] = reservationEntry{
			bucketID:      plans[index].locked.id,
			entryID:       plans[index].entryID,
			leaseID:       plans[index].leaseID,
			metric:        plans[index].rule.Metric,
			algorithm:     plans[index].rule.Algorithm,
			reservedUnits: plans[index].reservedUnits,
			resetAt:       plans[index].period.end,
		}
	}
	return entries
}

func maximumResetAt(entries []reservationEntry) time.Time {
	var maximum time.Time
	for _, entry := range entries {
		if entry.resetAt.After(maximum) {
			maximum = entry.resetAt
		}
	}
	return maximum
}

func exceededError(logicalRequestID string, plans []plannedBucket, exceeded []int) *ExceededError {
	selected := exceeded[0]
	for _, index := range exceeded[1:] {
		candidate, current := plans[index], plans[selected]
		candidateRetryAt := planRetryAt(candidate)
		currentRetryAt := planRetryAt(current)
		if candidateRetryAt.After(currentRetryAt) ||
			(candidateRetryAt.Equal(currentRetryAt) &&
				(candidate.rule.ruleKey < current.rule.ruleKey ||
					(candidate.rule.ruleKey == current.rule.ruleKey &&
						candidate.rule.scopeKey < current.rule.scopeKey))) {
			selected = index
		}
	}
	plan := plans[selected]
	if plan.rule.Algorithm == TokenBucketAlgorithm {
		return &ExceededError{
			logicalRequestID: logicalRequestID,
			retryAt:          plan.retryAt,
			maximum:          plan.rule.Capacity,
			used:             plan.rule.Capacity - plan.tokenState.balance/tokenBalanceScale,
			reserved:         0,
		}
	}
	return &ExceededError{
		logicalRequestID: logicalRequestID,
		retryAt:          plan.period.end,
		maximum:          plan.rule.Maximum,
		used:             plan.locked.used,
		reserved:         plan.locked.reserved,
	}
}

func planRetryAt(plan plannedBucket) time.Time {
	if plan.rule.Algorithm == TokenBucketAlgorithm {
		return plan.retryAt
	}
	return plan.period.end
}

func concurrencyExceededError(logicalRequestID string, plans []plannedBucket, exceeded []int) *ConcurrencyExceededError {
	selected := exceeded[0]
	for _, index := range exceeded[1:] {
		candidate, current := plans[index], plans[selected]
		if candidate.rule.ruleKey < current.rule.ruleKey ||
			(candidate.rule.ruleKey == current.rule.ruleKey && candidate.rule.scopeKey < current.rule.scopeKey) {
			selected = index
		}
	}
	plan := plans[selected]
	return &ConcurrencyExceededError{
		logicalRequestID: logicalRequestID,
		maximum:          plan.rule.Maximum,
		active:           plan.locked.reserved,
	}
}

// BeginAttempt atomically marks the logical request dispatched and records the
// single bounded upstream attempt. Call it only after every pre-dispatch step
// succeeds and immediately before invoking the HTTP transport. dispatchOwner
// is true for exactly the caller whose transaction created the attempt; only
// that caller is authorized to invoke the transport. Replays receive the same
// opaque handle with dispatchOwner false, including after terminal settlement.
func (store *Store) BeginAttempt(ctx context.Context, reservation Reservation) (attempt Attempt, dispatchOwner bool, err error) {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil || reservation.validate() != nil {
		return Attempt{}, false, ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Attempt{}, false, persistenceFailure("begin upstream attempt", err)
	}
	defer rollback(tx)
	lockedReservation, err := lockReservation(ctx, tx, reservation)
	if err != nil {
		return Attempt{}, false, err
	}
	logical, err := lockLogicalRequest(ctx, tx, reservation)
	if err != nil {
		return Attempt{}, false, err
	}
	attempts, err := loadAttemptsForUpdate(ctx, tx, reservation.logicalRequestID)
	if err != nil {
		return Attempt{}, false, err
	}
	found := len(attempts) != 0
	var perRequestOutputBound *int64
	if reservation.retryPlan != nil {
		perRequestOutputBound, err = perRequestOutputTokenBound(reservation.retryPlan.rules)
		if err != nil {
			return Attempt{}, false, err
		}
	}
	entries, err := lockLifecycleEntries(ctx, tx, lockedReservation)
	if err != nil {
		return Attempt{}, false, err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, lockedReservation, entries)
	if err != nil {
		return Attempt{}, false, err
	}
	if found {
		existing := attempts[0]
		if existing.routeKey != reservation.routeKey || existing.upstreamKey != reservation.upstreamKey ||
			existing.physicalModel == nil || *existing.physicalModel != reservation.physicalModel ||
			!storedModelKeyMatches(existing, reservation.modelKey) ||
			(existing.attemptDecisionBindingVersion == 1 &&
				!optionalInt64Matches(existing.perRequestOutputTokenBound, perRequestOutputBound)) ||
			!attemptPricingMatchesReservation(existing, reservation) ||
			!storedInitialInputPreflightMatches(existing, reservation.inputPreflight) {
			return Attempt{}, false, ErrInvalidState
		}
		switch lockedReservation.status {
		case "pending":
			lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
				ctx, tx, lockedReservation, logical.status, entries, attempts,
			)
			if lifecycleErr != nil {
				return Attempt{}, false, lifecycleErr
			}
			if !pendingEntriesMatch(logical.status, lockedReservation, entries, leases) ||
				!lifecycleMatches {
				return Attempt{}, false, ErrInvalidState
			}
		case "settled":
			aggregateMatches, aggregateErr := retryAggregateMatchesEntries(
				ctx, tx, lockedReservation, entries,
			)
			if aggregateErr != nil {
				return Attempt{}, false, aggregateErr
			}
			logicalUsageMatches, usageErr := logicalUsageRecordMatches(ctx, tx, lockedReservation)
			if usageErr != nil {
				return Attempt{}, false, usageErr
			}
			accountingMatches, accountingErr := terminalAttemptAccountingSequenceMatches(
				ctx, tx, lockedReservation, logical.status, entries, attempts,
			)
			if accountingErr != nil {
				return Attempt{}, false, accountingErr
			}
			if !terminalEntriesMatch(logical.status, lockedReservation.status, entries, leases) ||
				!aggregateMatches || !logicalUsageMatches || !accountingMatches {
				return Attempt{}, false, ErrInvalidState
			}
		default:
			return Attempt{}, false, ErrInvalidState
		}
		return Attempt{reservation: reservation, attemptID: existing.id, number: 1}, false, nil
	}
	if lockedReservation.status != "pending" {
		return Attempt{}, false, ErrFinalized
	}
	if logical.status != "reserved" {
		return Attempt{}, false, ErrInvalidState
	}
	if !pendingEntriesMatch(logical.status, lockedReservation, entries, leases) {
		return Attempt{}, false, ErrInvalidState
	}
	attemptID, err := store.newID(id.UpstreamAttempt)
	if err != nil {
		return Attempt{}, false, fmt.Errorf("generate upstream-attempt identifier: %w", err)
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return Attempt{}, false, err
	}
	if !lockedReservation.expiresAt.After(now) {
		return Attempt{}, false, ErrExpired
	}
	command, err := tx.Exec(ctx, `
		UPDATE logical_requests
		SET status = 'dispatched', dispatched_at = GREATEST(requested_at, $2)
		WHERE logical_request_id = $1 AND status = 'reserved'
	`, reservation.logicalRequestID, now)
	if err != nil {
		return Attempt{}, false, persistenceFailure("mark logical request dispatched", err)
	}
	if command.RowsAffected() != 1 {
		return Attempt{}, false, ErrInvalidState
	}
	var accountingMethod, accountingProfileID, accountingProfileDigest any
	var rewrittenBodyDigest, inputBound, outputBound, totalBound any
	if binding := reservation.inputPreflight; binding != nil {
		accountingMethod = binding.Method
		accountingProfileID = binding.ProfileID
		accountingProfileDigest = binding.ProfileDigest[:]
		rewrittenBodyDigest = binding.RewrittenBodySHA256[:]
		inputBound = binding.InputTokenBound
		outputBound = binding.OutputTokenBound
		totalBound = binding.TotalTokenBound
	}
	initialAllocations, err := initialAttemptAllocations(entries)
	if err != nil {
		return Attempt{}, false, err
	}
	decisionAttempt := newStoredAttemptDecision(
		attemptID, 1, reservation.routeKey, reservation.upstreamKey,
		reservation.modelKey, reservation.physicalModel, reservation.pricing,
		reservation.inputPreflight, perRequestOutputBound,
	)
	decisionDigest, err := attemptDecisionDigest(
		lockedReservation, decisionAttempt,
		attemptQuotaRowsForDecision(entries, initialAllocations),
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
			total_token_bound
		) VALUES (
			$1, $2, $3, $4, $5, 1, $6, $7, $8, $9, 1, $10, $11, 1,
			'started', $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)
	`, attemptID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		reservation.routeKey, reservation.upstreamKey, reservation.physicalModel,
		reservation.modelKey, decisionDigest[:], perRequestOutputBound, now,
		nullableString(reservation.pricing.currency),
		nullableString(reservation.pricing.revision), nullableString(reservation.pricing.source),
		nullableString(initialCostConfidence(reservation.pricing)), accountingMethod,
		accountingProfileID, accountingProfileDigest, rewrittenBodyDigest,
		inputBound, outputBound, totalBound); err != nil {
		return Attempt{}, false, mapWriteError("insert upstream attempt", err)
	}
	if err := insertAttemptQuotaEntries(
		ctx, tx, lockedReservation, attemptID, entries, initialAllocations,
	); err != nil {
		return Attempt{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, false, persistenceFailure("commit upstream attempt", err)
	}
	return Attempt{reservation: reservation, attemptID: attemptID, number: 1}, true, nil
}

// MarkFirstByte records the first response boundary once. It uses its own
// short transaction and performs no stream reads.
func (store *Store) MarkFirstByte(ctx context.Context, attempt Attempt) error {
	if store == nil || store.pool == nil || ctx == nil || attempt.validate() != nil {
		return ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return persistenceFailure("begin first-byte record", err)
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
	attempts, err := loadAttemptsForUpdate(ctx, tx, attempt.reservation.logicalRequestID)
	if err != nil {
		return err
	}
	if attempt.number > int32(len(attempts)) ||
		attempts[attempt.number-1].id != attempt.attemptID {
		return ErrNotFound
	}
	stored := attempts[attempt.number-1]
	if attempt.number == 1 && (!attemptPricingMatchesReservation(stored, reservation.Reservation) ||
		!storedModelKeyMatches(stored, reservation.modelKey) ||
		!storedInitialInputPreflightMatches(stored, reservation.inputPreflight)) {
		return ErrInvalidState
	}
	entries, err := lockLifecycleEntries(ctx, tx, reservation)
	if err != nil {
		return err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, reservation, entries)
	if err != nil {
		return err
	}
	switch reservation.status {
	case "pending":
		lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
			ctx, tx, reservation, logical.status, entries, attempts,
		)
		if lifecycleErr != nil {
			return lifecycleErr
		}
		if !pendingEntriesMatch(logical.status, reservation, entries, leases) ||
			!lifecycleMatches {
			return ErrInvalidState
		}
	case "settled":
		aggregateMatches, aggregateErr := retryAggregateMatchesEntries(
			ctx, tx, reservation, entries,
		)
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
	default:
		return ErrInvalidState
	}
	if stored.firstByteAt != nil {
		return nil
	}
	if reservation.status != "pending" || stored.status != "started" ||
		(logical.status != "dispatched" && logical.status != "streaming") {
		return ErrFinalized
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE upstream_attempts
		SET first_byte_at = GREATEST(started_at, $2)
		WHERE upstream_attempt_id = $1 AND status = 'started' AND first_byte_at IS NULL
	`, attempt.attemptID, now)
	if err != nil {
		return persistenceFailure("record upstream first byte", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	if logical.status == "dispatched" {
		command, err = tx.Exec(ctx, `
			UPDATE logical_requests
			SET status = 'streaming'
			WHERE logical_request_id = $1 AND status = 'dispatched'
		`, attempt.reservation.logicalRequestID)
		if err != nil {
			return persistenceFailure("mark logical request streaming", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return persistenceFailure("commit first-byte record", err)
	}
	return nil
}

// Settle finalizes the last attempt and charges exactly one logical-request
// unit. The schema-12 attempt ledger makes this path identical for a one-
// attempt request and a request completed after retries.
func (store *Store) Settle(ctx context.Context, attempt Attempt, outcome Outcome) error {
	return store.SettleFinalAttempt(ctx, attempt, outcome)
}

// settleSingleLegacy retains the pre-schema-12 implementation as a narrowly
// scoped recovery primitive while rolling-upgrade paths are validated. New
// requests always use the attempt ledger through SettleFinalAttempt.
func (store *Store) settleSingleLegacy(ctx context.Context, attempt Attempt, outcome Outcome) error {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil || attempt.validate() != nil || outcome.validate() != nil {
		return ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return persistenceFailure("begin quota settlement", err)
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
	storedAttempt, found, err := loadAttemptForUpdate(ctx, tx, attempt.reservation.logicalRequestID, 1)
	if err != nil {
		return err
	}
	if !found || storedAttempt.id != attempt.attemptID {
		return ErrNotFound
	}
	outcome, err = normalizeOutcomeForPricing(outcome, reservation.pricing)
	if err != nil {
		return err
	}
	if !attemptPricingMatchesReservation(storedAttempt, reservation.Reservation) {
		return ErrInvalidState
	}
	if reservation.status == "settled" {
		entries, entryErr := lockEntries(ctx, tx, reservation)
		if entryErr != nil {
			return entryErr
		}
		leases, leaseErr := lockConcurrencyLeases(ctx, tx, reservation, entries)
		if leaseErr != nil {
			return leaseErr
		}
		if !terminalEntriesMatch(logical.status, reservation.status, entries, leases) {
			return ErrInvalidState
		}
		if validationErr := validateCostSettlement(entries, outcome.Cost); validationErr != nil {
			return validationErr
		}
		if !terminalCostEntriesMatch(entries, outcome.Cost) {
			return ErrInvalidState
		}
		matches, matchErr := terminalSettlementMatches(ctx, tx, reservation, storedAttempt, outcome)
		if matchErr != nil {
			return matchErr
		}
		if !matches {
			return ErrFinalized
		}
		if !terminalTokenEntriesMatch(entries, outcome) {
			return ErrInvalidState
		}
		return nil
	}
	if reservation.status != "pending" {
		return ErrFinalized
	}
	if storedAttempt.status != "started" ||
		(logical.status != "dispatched" && logical.status != "streaming") {
		return ErrInvalidState
	}
	entries, err := lockEntries(ctx, tx, reservation)
	if err != nil {
		return err
	}
	if err := validateCostSettlement(entries, outcome.Cost); err != nil {
		return err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, reservation, entries)
	if err != nil {
		return err
	}
	tokenReservations, err := lockedTokenReservationUnits(entries)
	if err != nil {
		return err
	}
	usageIDs, err := store.newSettlementUsageIDsForTokenMetrics(
		outcome.Usage, tokenReservations, outcome.Cost, reservation.pricing,
	)
	if err != nil {
		return err
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := settleLocked(ctx, tx, reservation, logical, storedAttempt, entries, leases, outcome, usageIDs, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistenceFailure("commit quota settlement", err)
	}
	return nil
}

// ReleaseBeforeDispatch returns every reserved unit only when the logical
// request has no upstream-attempt row. The logical-request lock serializes this
// proof with BeginAttempt.
func (store *Store) ReleaseBeforeDispatch(ctx context.Context, reservation Reservation, failureCode string) error {
	if store == nil || store.pool == nil || ctx == nil || reservation.validate() != nil || !validFailureCode(failureCode) {
		return ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return persistenceFailure("begin quota release", err)
	}
	defer rollback(tx)
	lockedReservation, err := lockReservation(ctx, tx, reservation)
	if err != nil {
		return err
	}
	logical, err := lockLogicalRequest(ctx, tx, reservation)
	if err != nil {
		return err
	}
	attempts, err := loadAttemptsForUpdate(ctx, tx, reservation.logicalRequestID)
	if err != nil {
		return err
	}
	attemptExists := len(attempts) != 0
	entries, err := lockEntries(ctx, tx, lockedReservation)
	if err != nil {
		return err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, lockedReservation, entries)
	if err != nil {
		return err
	}
	if lockedReservation.status == "released" {
		if !attemptExists && logical.status == "failed" && logical.failureCode != nil &&
			*logical.failureCode == failureCode &&
			terminalEntriesMatch(logical.status, lockedReservation.status, entries, leases) {
			return nil
		}
		return ErrFinalized
	}
	if lockedReservation.status != "pending" {
		return ErrFinalized
	}
	if attemptExists {
		return ErrFinalized
	}
	if logical.status != "reserved" {
		return ErrInvalidState
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := releaseLocked(ctx, tx, lockedReservation, logical, entries, leases, "released", failureCode, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistenceFailure("commit quota release", err)
	}
	return nil
}

// ExpirePendingBatch recovers at most limit abandoned reservations. Each row
// is handled in its own short SKIP LOCKED transaction. A row with an attempt is
// conservatively settled; a row without one is released and marked expired.
func (store *Store) ExpirePendingBatch(ctx context.Context, limit int) (int64, error) {
	return store.expirePendingBatch(ctx, limit, pendingExpiryAny)
}

// ReleaseExpiredUndispatchedBatch releases reservations that expired before
// any upstream dispatch. Separating this queue lane from reconciliation keeps
// multi-replica workers from repeatedly selecting work another lane cannot
// process.
func (store *Store) ReleaseExpiredUndispatchedBatch(ctx context.Context, limit int) (int64, error) {
	return store.expirePendingBatch(ctx, limit, pendingExpiryUndispatched)
}

// ReconcilePendingUsageBatch conservatively settles expired dispatched
// reservations according to the configured unknown-usage policy, preventing
// client disconnects from bypassing hard budgets.
func (store *Store) ReconcilePendingUsageBatch(ctx context.Context, limit int) (int64, error) {
	return store.expirePendingBatch(ctx, limit, pendingExpiryDispatched)
}

type pendingExpiryMode string

const (
	pendingExpiryAny          pendingExpiryMode = "any"
	pendingExpiryUndispatched pendingExpiryMode = "undispatched"
	pendingExpiryDispatched   pendingExpiryMode = "dispatched"
)

func (store *Store) expirePendingBatch(ctx context.Context, limit int, mode pendingExpiryMode) (int64, error) {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil || limit < 1 || limit > maximumExpiryBatch {
		return 0, ErrInvalidInput
	}
	if mode != pendingExpiryAny && mode != pendingExpiryUndispatched && mode != pendingExpiryDispatched {
		return 0, ErrInvalidInput
	}
	var processed int64
	for processed < int64(limit) {
		didProcess, err := store.expireOne(ctx, mode)
		if err != nil {
			return processed, err
		}
		if !didProcess {
			break
		}
		processed++
	}
	return processed, nil
}

func (store *Store) expireOne(ctx context.Context, mode pendingExpiryMode) (bool, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, persistenceFailure("begin expired reservation recovery", err)
	}
	defer rollback(tx)
	now, err := transactionTime(ctx, tx)
	if err != nil {
		return false, err
	}
	var selected Reservation
	var selectedIdempotencyKey string
	err = tx.QueryRow(ctx, `
		SELECT organization_id, application_id, environment_id,
		       logical_request_id, quota_reservation_id, idempotency_key, expires_at
		FROM quota_reservations
		WHERE status = 'pending' AND expires_at <= $1
		  AND (
		    $2 = 'any'
		    OR ($2 = 'dispatched') = EXISTS (
		      SELECT 1 FROM upstream_attempts
		      WHERE upstream_attempts.logical_request_id = quota_reservations.logical_request_id
		    )
		  )
		ORDER BY expires_at, quota_reservation_id
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`, now, string(mode)).Scan(
		&selected.organizationID, &selected.applicationID, &selected.environmentID,
		&selected.logicalRequestID, &selected.reservationID,
		&selectedIdempotencyKey, &selected.expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, persistenceFailure("claim expired quota reservation", err)
	}
	lockedReservation := lockedReservation{
		Reservation: selected, status: "pending", expiresAt: selected.expiresAt,
	}
	logical, err := lockLogicalRequest(ctx, tx, selected)
	if err != nil {
		return false, err
	}
	lockedReservation.applicationUserID = logical.applicationUserID
	lockedReservation.installationID = logical.installationID
	lockedReservation.featureKey = logical.featureKey
	attempts, err := loadAttemptsForUpdate(ctx, tx, selected.logicalRequestID)
	if err != nil {
		return false, err
	}
	attemptExists := len(attempts) != 0
	entries, err := lockEntries(ctx, tx, lockedReservation)
	if err != nil {
		return false, err
	}
	leases, err := lockConcurrencyLeases(ctx, tx, lockedReservation, entries)
	if err != nil {
		return false, err
	}
	lifecycleMatches, lifecycleErr := retryPendingLifecycleMatches(
		ctx, tx, lockedReservation, logical.status, entries, attempts,
	)
	if lifecycleErr != nil {
		return false, lifecycleErr
	}
	if !pendingEntriesMatch(logical.status, lockedReservation, entries, leases) ||
		!lifecycleMatches {
		return false, ErrInvalidState
	}
	var logicalUsageID string
	if attemptExists {
		if logical.status != "dispatched" && logical.status != "streaming" {
			return false, ErrInvalidState
		}
		hasCostReservation := false
		for _, entry := range entries {
			if entry.metric == CostNanoUSDMetric {
				hasCostReservation = true
				break
			}
		}
		firstPricing, pricingErr := attempts[0].selectedPricing()
		if pricingErr != nil {
			return false, pricingErr
		}
		if hasCostReservation && (!firstPricing.present() ||
			firstPricing.revision != logical.configRevisionID ||
			logical.trustedDecisionFingerprint == nil ||
			reservationIdempotencyKey(
				*logical.trustedDecisionFingerprint, firstPricing, true,
			) != selectedIdempotencyKey) {
			return false, ErrInvalidState
		}
		for index := range attempts[:len(attempts)-1] {
			if attempts[index].status != AttemptFailed && attempts[index].status != AttemptTimedOut {
				return false, ErrInvalidState
			}
			quotaEntries, quotaErr := loadAttemptQuotaEntriesForUpdate(
				ctx, tx, lockedReservation, attempts[index],
			)
			if quotaErr != nil || !attemptQuotaEntriesSettled(quotaEntries) {
				if quotaErr != nil {
					return false, quotaErr
				}
				return false, ErrInvalidState
			}
		}
		last := &attempts[len(attempts)-1]
		lastQuota, quotaErr := loadAttemptQuotaEntriesForUpdate(ctx, tx, lockedReservation, *last)
		if quotaErr != nil {
			return false, quotaErr
		}
		if last.status == "started" {
			pricing, pricingErr := last.selectedPricing()
			if pricingErr != nil {
				return false, pricingErr
			}
			recoveredOutcome, normalizeErr := normalizeOutcomeForPricing(Outcome{
				Status: AttemptTimedOut, FailureCode: expiryFailureCode,
				Usage: Usage{Provenance: UnknownUsageProvenance},
			}, pricing)
			if normalizeErr != nil {
				return false, normalizeErr
			}
			tokenReservations, tokenErr := attemptTokenReservationUnits(lastQuota)
			if tokenErr != nil {
				return false, tokenErr
			}
			usageIDs, idErr := store.newSettlementUsageIDsForTokenMetrics(
				recoveredOutcome.Usage, tokenReservations, recoveredOutcome.Cost, pricing,
			)
			if idErr != nil {
				return false, idErr
			}
			now, err = statementTime(ctx, tx)
			if err != nil {
				return false, err
			}
			if err := settleRetryAttemptLocked(
				ctx, tx, lockedReservation, *last, entries, lastQuota,
				recoveredOutcome, usageIDs, pricing, now,
			); err != nil {
				return false, err
			}
			last.status = AttemptTimedOut
			last.failureCode = optionalText(expiryFailureCode)
			last.billedCost, last.costConfidence = storedSettlementCost(pricing, recoveredOutcome.Cost)
			completedAt := now
			last.completedAt = &completedAt
			logicalUsageID = usageIDs.logical
			entries, err = lockEntries(ctx, tx, lockedReservation)
			if err != nil {
				return false, err
			}
		} else if (last.status != AttemptFailed && last.status != AttemptTimedOut) ||
			!attemptQuotaEntriesSettled(lastQuota) {
			return false, ErrInvalidState
		}
		aggregateMatches, aggregateErr := retryAggregateMatchesEntries(
			ctx, tx, lockedReservation, entries,
		)
		if aggregateErr != nil {
			return false, aggregateErr
		}
		if !aggregateMatches {
			return false, ErrInvalidState
		}
		if logicalUsageID == "" {
			logicalUsageID, err = store.newID(id.UsageRecord)
			if err != nil {
				return false, fmt.Errorf("generate expired logical usage identifier: %w", err)
			}
		}
		now, err = statementTime(ctx, tx)
		if err != nil {
			return false, err
		}
		if err := finalizeRetryReservationLocked(
			ctx, tx, lockedReservation, logical, entries, leases, *last,
			Outcome{Status: AttemptTimedOut, FailureCode: expiryFailureCode},
			logicalUsageID, now,
		); err != nil {
			return false, err
		}
	} else if logical.status != "reserved" {
		return false, ErrInvalidState
	} else {
		now, err = statementTime(ctx, tx)
		if err != nil {
			return false, err
		}
		if err := releaseLocked(ctx, tx, lockedReservation, logical, entries, leases, "expired", expiryFailureCode, now); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, persistenceFailure("commit expired reservation recovery", err)
	}
	return true, nil
}

type lockedReservation struct {
	Reservation
	status            string
	expiresAt         time.Time
	applicationUserID string
	installationID    string
	featureKey        string
}

func lockReservation(ctx context.Context, tx pgx.Tx, expected Reservation) (lockedReservation, error) {
	var result lockedReservation
	err := tx.QueryRow(ctx, `
		SELECT reservation.organization_id, reservation.application_id,
		       reservation.environment_id, reservation.logical_request_id,
		       reservation.quota_reservation_id, reservation.status,
		       reservation.expires_at, logical.application_user_id,
		       logical.installation_id, logical.feature_key
		FROM quota_reservations AS reservation
		JOIN logical_requests AS logical
		  ON logical.organization_id = reservation.organization_id
		 AND logical.application_id = reservation.application_id
		 AND logical.environment_id = reservation.environment_id
		 AND logical.logical_request_id = reservation.logical_request_id
		WHERE reservation.organization_id = $1 AND reservation.application_id = $2
		  AND reservation.environment_id = $3
		  AND reservation.logical_request_id = $4
		  AND reservation.quota_reservation_id = $5
		FOR UPDATE OF reservation
	`, expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID, expected.reservationID).Scan(
		&result.organizationID, &result.applicationID, &result.environmentID,
		&result.logicalRequestID, &result.reservationID, &result.status, &result.expiresAt,
		&result.applicationUserID, &result.installationID, &result.featureKey,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedReservation{}, ErrNotFound
	}
	if err != nil {
		return lockedReservation{}, persistenceFailure("lock quota reservation", err)
	}
	if id.Validate(result.applicationUserID, id.ApplicationUser) != nil ||
		id.Validate(result.installationID, id.Installation) != nil ||
		!identifierPattern.MatchString(result.featureKey) {
		return lockedReservation{}, ErrInvalidState
	}
	result.Reservation.entries = append([]reservationEntry(nil), expected.entries...)
	result.Reservation.routeKey = expected.routeKey
	result.Reservation.upstreamKey = expected.upstreamKey
	result.Reservation.modelKey = expected.modelKey
	result.Reservation.physicalModel = expected.physicalModel
	result.Reservation.protocol = expected.protocol
	result.Reservation.pricing = expected.pricing
	result.Reservation.inputPreflight = cloneInputPreflightBinding(expected.inputPreflight)
	result.Reservation.retryPlan = cloneReservationRetryPlan(expected.retryPlan)
	result.Reservation.windowResetAt = expected.windowResetAt
	return result, nil
}

type lockedLogical struct {
	status                     string
	failureCode                *string
	protocol                   string
	configRevisionID           string
	trustedDecisionFingerprint *string
	applicationUserID          string
	installationID             string
	sessionGrantID             string
	featureKey                 string
	requestedAt                time.Time
}

func lockLogicalRequest(ctx context.Context, tx pgx.Tx, expected Reservation) (lockedLogical, error) {
	var result lockedLogical
	err := tx.QueryRow(ctx, `
		SELECT status, failure_code, protocol, config_revision_id,
		       trusted_decision_fingerprint, application_user_id, installation_id,
		       session_grant_id, feature_key, requested_at
		FROM logical_requests
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND logical_request_id = $4
		FOR UPDATE
	`, expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID).Scan(
		&result.status, &result.failureCode, &result.protocol, &result.configRevisionID,
		&result.trustedDecisionFingerprint, &result.applicationUserID,
		&result.installationID, &result.sessionGrantID, &result.featureKey,
		&result.requestedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedLogical{}, ErrNotFound
	}
	if err != nil {
		return lockedLogical{}, persistenceFailure("lock logical request", err)
	}
	if id.Validate(result.configRevisionID, id.ConfigRevision) != nil {
		return lockedLogical{}, ErrInvalidState
	}
	if plan := expected.retryPlan; plan != nil &&
		(result.applicationUserID != plan.applicationUserID ||
			result.installationID != plan.installationID ||
			result.sessionGrantID != plan.sessionGrantID ||
			result.configRevisionID != plan.configRevisionID ||
			result.featureKey != plan.featureKey) {
		return lockedLogical{}, ErrInvalidState
	}
	return result, nil
}

type storedAttempt struct {
	id                            string
	number                        int32
	routeKey                      string
	upstreamKey                   string
	physicalModel                 *string
	modelKey                      *string
	status                        string
	firstByteAt                   *time.Time
	completedAt                   *time.Time
	httpStatus                    *int32
	failureCode                   *string
	billedCost                    *int64
	currency                      *string
	priceRevision                 *string
	pricingSource                 *string
	costConfidence                *string
	attemptDecisionBindingVersion int16
	attemptDecisionSHA256         []byte
	perRequestOutputTokenBound    *int64
	inputAccountingBindingVersion int16
	inputAccountingMethod         *string
	inputAccountingProfileID      *string
	inputAccountingProfileDigest  []byte
	rewrittenBodySHA256           []byte
	inputTokenBound               *int64
	outputTokenBound              *int64
	totalTokenBound               *int64
}

func initialCostConfidence(pricing selectedPricing) string {
	if !pricing.present() {
		return ""
	}
	return UnknownCostConfidence
}

func settlementCostValues(pricing selectedPricing, cost Cost) (billed any, confidence any) {
	if !pricing.present() {
		return nil, nil
	}
	if cost.Known {
		return cost.NanoUSD, CalculatedCostConfidence
	}
	return nil, UnknownCostConfidence
}

func (attempt storedAttempt) selectedPricing() (selectedPricing, error) {
	selectionAbsent := attempt.currency == nil && attempt.priceRevision == nil && attempt.pricingSource == nil
	if selectionAbsent {
		if attempt.billedCost != nil || attempt.costConfidence != nil {
			return selectedPricing{}, ErrInvalidState
		}
		return selectedPricing{}, nil
	}
	if attempt.currency == nil || attempt.priceRevision == nil || attempt.pricingSource == nil {
		return selectedPricing{}, ErrInvalidState
	}
	pricing := selectedPricing{
		source: *attempt.pricingSource, currency: *attempt.currency,
		revision: *attempt.priceRevision,
	}
	if pricing.validate() != nil || attempt.costConfidence == nil {
		return selectedPricing{}, ErrInvalidState
	}
	switch *attempt.costConfidence {
	case UnknownCostConfidence:
		if attempt.billedCost != nil {
			return selectedPricing{}, ErrInvalidState
		}
	case CalculatedCostConfidence:
		if attempt.billedCost == nil || *attempt.billedCost < 0 {
			return selectedPricing{}, ErrInvalidState
		}
	default:
		return selectedPricing{}, ErrInvalidState
	}
	return pricing, nil
}

func (attempt storedAttempt) validatePricing() error {
	_, err := attempt.selectedPricing()
	return err
}

func attemptPricingMatchesReservation(attempt storedAttempt, reservation Reservation) bool {
	pricing, err := attempt.selectedPricing()
	return err == nil && pricing == reservation.pricing
}

func loadAttemptForUpdate(ctx context.Context, tx pgx.Tx, logicalRequestID string, number int32) (storedAttempt, bool, error) {
	var result storedAttempt
	err := tx.QueryRow(ctx, `
		SELECT upstream_attempt_id, attempt_number, route_key, upstream_key,
		       physical_model, model_key, status, first_byte_at, completed_at,
		       http_status, failure_code, billed_cost_nano_usd, currency,
		       price_revision, pricing_source, cost_confidence,
		       attempt_decision_binding_version, attempt_decision_sha256,
		       per_request_output_token_bound,
		       input_accounting_binding_version,
		       input_accounting_method, input_accounting_profile_id,
		       input_accounting_profile_digest, rewritten_body_sha256,
		       input_token_bound, output_token_bound, total_token_bound
		FROM upstream_attempts
		WHERE logical_request_id = $1 AND attempt_number = $2
		FOR UPDATE
	`, logicalRequestID, number).Scan(
		&result.id, &result.number, &result.routeKey, &result.upstreamKey,
		&result.physicalModel, &result.modelKey, &result.status, &result.firstByteAt,
		&result.completedAt, &result.httpStatus, &result.failureCode,
		&result.billedCost, &result.currency, &result.priceRevision,
		&result.pricingSource, &result.costConfidence,
		&result.attemptDecisionBindingVersion, &result.attemptDecisionSHA256,
		&result.perRequestOutputTokenBound,
		&result.inputAccountingBindingVersion,
		&result.inputAccountingMethod, &result.inputAccountingProfileID,
		&result.inputAccountingProfileDigest, &result.rewrittenBodySHA256,
		&result.inputTokenBound, &result.outputTokenBound, &result.totalTokenBound,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedAttempt{}, false, nil
	}
	if err != nil {
		return storedAttempt{}, false, persistenceFailure("lock upstream attempt", err)
	}
	if id.Validate(result.id, id.UpstreamAttempt) != nil || result.number != number || result.validate() != nil {
		return storedAttempt{}, false, ErrInvalidState
	}
	return result, true, nil
}

func loadOnlyAttemptForUpdate(ctx context.Context, tx pgx.Tx, logicalRequestID string) (storedAttempt, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT upstream_attempt_id, attempt_number, route_key, upstream_key,
		       physical_model, model_key, status, first_byte_at, completed_at,
		       http_status, failure_code, billed_cost_nano_usd, currency,
		       price_revision, pricing_source, cost_confidence,
		       attempt_decision_binding_version, attempt_decision_sha256,
		       per_request_output_token_bound,
		       input_accounting_binding_version,
		       input_accounting_method, input_accounting_profile_id,
		       input_accounting_profile_digest, rewritten_body_sha256,
		       input_token_bound, output_token_bound, total_token_bound
		FROM upstream_attempts
		WHERE logical_request_id = $1
		ORDER BY attempt_number
		FOR UPDATE
	`, logicalRequestID)
	if err != nil {
		return storedAttempt{}, false, persistenceFailure("lock recovered upstream attempts", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return storedAttempt{}, false, persistenceFailure("read recovered upstream attempts", err)
		}
		return storedAttempt{}, false, nil
	}
	var result storedAttempt
	if err := rows.Scan(
		&result.id, &result.number, &result.routeKey, &result.upstreamKey,
		&result.physicalModel, &result.modelKey, &result.status, &result.firstByteAt,
		&result.completedAt, &result.httpStatus, &result.failureCode,
		&result.billedCost, &result.currency, &result.priceRevision,
		&result.pricingSource, &result.costConfidence,
		&result.attemptDecisionBindingVersion, &result.attemptDecisionSHA256,
		&result.perRequestOutputTokenBound,
		&result.inputAccountingBindingVersion,
		&result.inputAccountingMethod, &result.inputAccountingProfileID,
		&result.inputAccountingProfileDigest, &result.rewrittenBodySHA256,
		&result.inputTokenBound, &result.outputTokenBound, &result.totalTokenBound,
	); err != nil {
		return storedAttempt{}, false, persistenceFailure("scan recovered upstream attempt", err)
	}
	if rows.Next() || result.number != 1 || id.Validate(result.id, id.UpstreamAttempt) != nil || result.validate() != nil {
		return storedAttempt{}, false, ErrInvalidState
	}
	if err := rows.Err(); err != nil {
		return storedAttempt{}, false, persistenceFailure("iterate recovered upstream attempts", err)
	}
	return result, true, nil
}

type lockedEntry struct {
	id                   string
	bucketID             string
	limitPlanKey         string
	ruleKey              string
	metric               string
	algorithm            string
	windowKey            string
	scopeType            string
	scopeDimensions      []string
	scopeKey             string
	originAttemptNumber  int32
	initialReservedUnits int64
	reservedUnits        int64
	settledUnits         int64
	releasedUnits        int64
	bucketUsed           int64
	bucketReserved       int64
	hardMaximum          *int64
	available            *int64
	refillNumerator      *int64
	refillDenominator    *int64
	refilledAt           *time.Time
	version              int64
}

// lockEntries locks both the request-private reservation entries and their
// shared quota buckets. Capacity-mutating settlement and recovery paths use
// this form so every bucket mutation remains serialized in canonical order.
func lockEntries(ctx context.Context, tx pgx.Tx, reservation lockedReservation) ([]lockedEntry, error) {
	return lockEntriesWithScope(ctx, tx, reservation, true)
}

// lockLifecycleEntries locks only request-private reservation entries while
// reading the committed bucket state needed for fail-closed validation.
// BeginAttempt and MarkFirstByte already serialize on the request-private
// reservation row and never mutate bucket capacity, so taking shared bucket
// row locks here would unnecessarily serialize unrelated requests that share
// a quota scope.
func lockLifecycleEntries(ctx context.Context, tx pgx.Tx, reservation lockedReservation) ([]lockedEntry, error) {
	return lockEntriesWithScope(ctx, tx, reservation, false)
}

func lockEntriesWithScope(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	lockBuckets bool,
) ([]lockedEntry, error) {
	lockClause := "FOR UPDATE OF entry"
	if lockBuckets {
		lockClause = "FOR UPDATE OF entry, bucket"
	}
	rows, err := tx.Query(ctx, `
		SELECT entry.quota_reservation_entry_id, entry.quota_bucket_id,
		       bucket.limit_plan_key, bucket.rule_key, bucket.metric,
		       bucket.algorithm, bucket.window_key, bucket.scope_type,
		       bucket.scope_dimensions, bucket.scope_key,
		       entry.origin_attempt_number,
		       entry.initial_reserved_units, entry.reserved_units,
		       entry.settled_units, entry.released_units,
		       bucket.used_units, bucket.reserved_units, bucket.hard_maximum,
		       bucket.available_units, bucket.refill_numerator,
		       bucket.refill_denominator, bucket.refilled_at, bucket.version
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket
		  ON bucket.organization_id = entry.organization_id
		 AND bucket.application_id = entry.application_id
		 AND bucket.environment_id = entry.environment_id
		 AND bucket.quota_bucket_id = entry.quota_bucket_id
		WHERE entry.organization_id = $1 AND entry.application_id = $2
		  AND entry.environment_id = $3 AND entry.quota_reservation_id = $4
		ORDER BY bucket.quota_bucket_id COLLATE "C"
		`+lockClause, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.reservationID)
	if err != nil {
		return nil, persistenceFailure("lock quota reservation entries", err)
	}
	defer rows.Close()
	entries := make([]lockedEntry, 0, len(reservation.entries))
	for rows.Next() {
		if len(entries) == maximumReservationEntries {
			return nil, ErrInvalidState
		}
		var entry lockedEntry
		if err := rows.Scan(
			&entry.id, &entry.bucketID, &entry.limitPlanKey, &entry.ruleKey,
			&entry.metric, &entry.algorithm, &entry.windowKey, &entry.scopeType,
			&entry.scopeDimensions, &entry.scopeKey, &entry.originAttemptNumber,
			&entry.initialReservedUnits, &entry.reservedUnits,
			&entry.settledUnits, &entry.releasedUnits, &entry.bucketUsed,
			&entry.bucketReserved, &entry.hardMaximum, &entry.available,
			&entry.refillNumerator, &entry.refillDenominator, &entry.refilledAt,
			&entry.version,
		); err != nil {
			return nil, persistenceFailure("scan quota reservation entry", err)
		}
		canonicalDimensions, dimensionsErr := canonicalScopeDimensions(entry.scopeDimensions)
		if id.Validate(entry.id, id.QuotaEntry) != nil || id.Validate(entry.bucketID, id.QuotaBucket) != nil ||
			dimensionsErr != nil || !slicesEqual(canonicalDimensions, entry.scopeDimensions) ||
			!identifierPattern.MatchString(entry.limitPlanKey) ||
			entry.ruleKey == "" || entry.scopeKey == "" ||
			entry.originAttemptNumber < 1 || entry.originAttemptNumber > maximumAttemptsPerRequest ||
			entry.reservedUnits < 0 ||
			!validReservationEntryUnits(entry.metric, entry.algorithm, entry.initialReservedUnits) ||
			entry.initialReservedUnits > entry.reservedUnits ||
			((entry.metric == LogicalRequestsMetric || isConcurrencyMetric(entry.metric)) &&
				entry.reservedUnits != entry.initialReservedUnits) ||
			entry.version < 0 ||
			(isConcurrencyMetric(entry.metric) !=
				(entry.algorithm == ConcurrencyAlgorithm && entry.windowKey == "active")) ||
			(entry.algorithm == CalendarAlgorithm && entry.windowKey == "") ||
			(entry.algorithm == TokenBucketAlgorithm && entry.windowKey != tokenBucketWindowKey) ||
			(len(entries) > 0 && entries[len(entries)-1].bucketID >= entry.bucketID) {
			return nil, ErrInvalidState
		}
		if entry.algorithm == TokenBucketAlgorithm {
			if _, err := tokenStateFromLockedEntry(entry); err != nil {
				return nil, err
			}
		} else if entry.available != nil || entry.refillNumerator != nil ||
			entry.refillDenominator != nil || entry.refilledAt != nil {
			return nil, ErrInvalidState
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, persistenceFailure("iterate quota reservation entries", err)
	}
	if len(entries) == 0 {
		if len(reservation.entries) == 0 {
			return entries, nil
		}
		return nil, ErrInvalidState
	}
	if len(reservation.entries) != 0 {
		byID := make(map[string]lockedEntry, len(entries))
		for _, entry := range entries {
			byID[entry.id] = entry
		}
		for _, expected := range reservation.entries {
			entry, ok := byID[expected.entryID]
			if !ok || entry.id != expected.entryID || entry.bucketID != expected.bucketID ||
				entry.metric != expected.metric || entry.algorithm != expected.algorithm ||
				entry.originAttemptNumber != 1 ||
				entry.initialReservedUnits != expected.reservedUnits {
				return nil, ErrInvalidState
			}
		}
	}
	return entries, nil
}

func tokenStateFromLockedEntry(entry lockedEntry) (tokenBucketState, error) {
	return tokenStateFromLockedBucket(lockedBucket{
		id: entry.bucketID, hardMaximum: entry.hardMaximum,
		used: entry.bucketUsed, reserved: entry.bucketReserved,
		available: entry.available, refillNumerator: entry.refillNumerator,
		refillDenominator: entry.refillDenominator, refilledAt: entry.refilledAt,
		version: entry.version,
	})
}

func persistTokenBucketEntry(
	ctx context.Context,
	tx pgx.Tx,
	entry lockedEntry,
	state tokenBucketState,
	now time.Time,
	operation string,
) error {
	return persistTokenBucket(ctx, tx, lockedBucket{
		id: entry.bucketID, hardMaximum: entry.hardMaximum,
		used: entry.bucketUsed, reserved: entry.bucketReserved,
		available: entry.available, refillNumerator: entry.refillNumerator,
		refillDenominator: entry.refillDenominator, refilledAt: entry.refilledAt,
		version: entry.version,
	}, state, now, operation)
}

type lockedConcurrencyLease struct {
	id         string
	bucketID   string
	acquiredAt time.Time
	expiresAt  time.Time
	releasedAt *time.Time
}

// lockConcurrencyLeases is always called after lockEntries, and acquires
// lease rows in their globally stable identifier order.
func lockConcurrencyLeases(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	entries []lockedEntry,
) ([]lockedConcurrencyLease, error) {
	expectedBuckets := make(map[string]struct{})
	for _, entry := range entries {
		if isConcurrencyMetric(entry.metric) {
			expectedBuckets[entry.bucketID] = struct{}{}
		}
	}
	expectedIDs := make(map[string]string)
	for _, entry := range reservation.entries {
		if isConcurrencyMetric(entry.metric) && entry.leaseID != "" {
			expectedIDs[entry.bucketID] = entry.leaseID
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT concurrency_lease_id, organization_id, application_id,
		       environment_id, quota_bucket_id, logical_request_id,
		       acquired_at, expires_at, released_at
		FROM concurrency_leases
		WHERE environment_id = $1 AND logical_request_id = $2
		ORDER BY concurrency_lease_id COLLATE "C"
		FOR UPDATE
	`, reservation.environmentID, reservation.logicalRequestID)
	if err != nil {
		return nil, persistenceFailure("lock concurrency leases", err)
	}
	defer rows.Close()
	leases := make([]lockedConcurrencyLease, 0, len(expectedBuckets))
	seenBuckets := make(map[string]struct{}, len(expectedBuckets))
	for rows.Next() {
		var lease lockedConcurrencyLease
		var organizationID, applicationID, environmentID, logicalRequestID string
		if err := rows.Scan(
			&lease.id, &organizationID, &applicationID, &environmentID,
			&lease.bucketID, &logicalRequestID, &lease.acquiredAt,
			&lease.expiresAt, &lease.releasedAt,
		); err != nil {
			return nil, persistenceFailure("scan concurrency lease", err)
		}
		_, expectedBucket := expectedBuckets[lease.bucketID]
		_, duplicateBucket := seenBuckets[lease.bucketID]
		if !expectedBucket || duplicateBucket || id.Validate(lease.id, id.ConcurrencyLease) != nil ||
			organizationID != reservation.organizationID || applicationID != reservation.applicationID ||
			environmentID != reservation.environmentID || logicalRequestID != reservation.logicalRequestID ||
			!lease.expiresAt.Equal(reservation.expiresAt) || !lease.expiresAt.After(lease.acquiredAt) {
			return nil, ErrInvalidState
		}
		if expectedID, ok := expectedIDs[lease.bucketID]; ok && expectedID != lease.id {
			return nil, ErrInvalidState
		}
		if reservation.status == "pending" {
			if lease.releasedAt != nil {
				return nil, ErrInvalidState
			}
		} else if lease.releasedAt == nil {
			return nil, ErrInvalidState
		}
		seenBuckets[lease.bucketID] = struct{}{}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, persistenceFailure("iterate concurrency leases", err)
	}
	if len(leases) != len(expectedBuckets) {
		return nil, ErrInvalidState
	}
	return leases, nil
}

type settlementUsageIDs struct {
	logical        string
	providerInput  string
	providerOutput string
	providerTotal  string
	unknownInput   string
	unknownOutput  string
	unknownTotal   string
	cost           string
}

type reservedTokenMetric struct {
	metric string
	units  int64
}

// This order fixes unknown-usage identifier allocation independently of
// bucket identifier order. Skipping absent metrics keeps output-only
// settlements byte-for-byte compatible with their historical sequence.
var reservedTokenMetricOrder = [...]string{
	InputTokensMetric,
	OutputTokensMetric,
	TotalTokensMetric,
}

func (store *Store) newSettlementUsageIDs(
	usage Usage,
	hasOutputReservation bool,
	cost Cost,
	pricing selectedPricing,
) (settlementUsageIDs, error) {
	// Retain the historical helper contract for output-only callers and tests.
	var reservations []reservedTokenMetric
	if hasOutputReservation {
		reservations = []reservedTokenMetric{{metric: OutputTokensMetric, units: 1}}
	}
	return store.newSettlementUsageIDsForTokenMetrics(usage, reservations, cost, pricing)
}

func (store *Store) newSettlementUsageIDsForTokenMetrics(
	usage Usage,
	reservations []reservedTokenMetric,
	cost Cost,
	pricing selectedPricing,
) (settlementUsageIDs, error) {
	result := settlementUsageIDs{}
	generate := func(destination *string) error {
		value, err := store.newID(id.UsageRecord)
		if err != nil {
			return fmt.Errorf("generate usage-record identifier: %w", err)
		}
		*destination = value
		return nil
	}
	if err := generate(&result.logical); err != nil {
		return settlementUsageIDs{}, err
	}
	if usage.Known {
		for _, destination := range []*string{
			&result.providerInput, &result.providerOutput, &result.providerTotal,
		} {
			if err := generate(destination); err != nil {
				return settlementUsageIDs{}, err
			}
		}
	} else {
		if !validReservedTokenMetrics(reservations) {
			return settlementUsageIDs{}, ErrInvalidState
		}
		for _, reservation := range reservations {
			destination, ok := result.unknownTokenDestination(reservation.metric)
			if !ok {
				return settlementUsageIDs{}, ErrInvalidState
			}
			if err := generate(destination); err != nil {
				return settlementUsageIDs{}, err
			}
		}
	}
	// Preserve all historical usage-ID generation sequences. A configured,
	// known cost appends exactly one new identifier after existing records.
	if cost.Known {
		if !usage.Known || !pricing.present() || pricing.validate() != nil {
			return settlementUsageIDs{}, ErrInvalidState
		}
		if err := generate(&result.cost); err != nil {
			return settlementUsageIDs{}, err
		}
	}
	return result, nil
}

func (identifiers *settlementUsageIDs) unknownTokenDestination(metric string) (*string, bool) {
	switch metric {
	case InputTokensMetric:
		return &identifiers.unknownInput, true
	case OutputTokensMetric:
		return &identifiers.unknownOutput, true
	case TotalTokensMetric:
		return &identifiers.unknownTotal, true
	default:
		return nil, false
	}
}

func (identifiers settlementUsageIDs) unknownToken(metric string) (string, bool) {
	switch metric {
	case InputTokensMetric:
		return identifiers.unknownInput, true
	case OutputTokensMetric:
		return identifiers.unknownOutput, true
	case TotalTokensMetric:
		return identifiers.unknownTotal, true
	default:
		return "", false
	}
}

func validReservedTokenMetrics(reservations []reservedTokenMetric) bool {
	if len(reservations) > len(reservedTokenMetricOrder) {
		return false
	}
	orderIndex := 0
	for _, reservation := range reservations {
		for orderIndex < len(reservedTokenMetricOrder) &&
			reservedTokenMetricOrder[orderIndex] != reservation.metric {
			orderIndex++
		}
		if orderIndex == len(reservedTokenMetricOrder) || reservation.units <= 0 {
			return false
		}
		orderIndex++
	}
	byMetric := make(map[string]int64, len(reservations))
	for _, reservation := range reservations {
		byMetric[reservation.metric] = reservation.units
	}
	return validTokenReservationRelationship(byMetric)
}

func lockedTokenReservationUnits(entries []lockedEntry) ([]reservedTokenMetric, error) {
	reservations := make([]reservedTokenMetric, 0, len(reservedTokenMetricOrder))
	for _, metric := range reservedTokenMetricOrder {
		var units int64
		found := false
		for _, entry := range entries {
			if entry.metric != metric {
				continue
			}
			if !validReservationEntryUnits(entry.metric, entry.algorithm, entry.reservedUnits) ||
				found && entry.reservedUnits != units {
				return nil, ErrInvalidState
			}
			units = entry.reservedUnits
			found = true
		}
		if found {
			reservations = append(reservations, reservedTokenMetric{metric: metric, units: units})
		}
	}
	if !validReservedTokenMetrics(reservations) {
		return nil, ErrInvalidState
	}
	return reservations, nil
}

func lockedCostReservationUnits(entries []lockedEntry) (int64, bool, error) {
	var units int64
	found := false
	for _, entry := range entries {
		if entry.metric != CostNanoUSDMetric {
			continue
		}
		if !validReservationEntryUnits(entry.metric, entry.algorithm, entry.reservedUnits) ||
			found && entry.reservedUnits != units {
			return 0, false, ErrInvalidState
		}
		units = entry.reservedUnits
		found = true
	}
	return units, found, nil
}

func validateCostSettlement(entries []lockedEntry, cost Cost) error {
	reserved, found, err := lockedCostReservationUnits(entries)
	if err != nil || !found || !cost.Known {
		return err
	}
	if cost.NanoUSD > reserved {
		return ErrInvalidInput
	}
	return nil
}

func terminalCostEntriesMatch(entries []lockedEntry, cost Cost) bool {
	reserved, found, err := lockedCostReservationUnits(entries)
	if err != nil || !found {
		return err == nil
	}
	settled := reserved
	if cost.Known {
		if cost.NanoUSD > reserved {
			return false
		}
		settled = cost.NanoUSD
	}
	for _, entry := range entries {
		if entry.metric == CostNanoUSDMetric &&
			(entry.settledUnits != settled || entry.releasedUnits != entry.reservedUnits-settled) {
			return false
		}
	}
	return true
}

func reservationTokenReservationUnits(entries []reservationEntry) ([]reservedTokenMetric, error) {
	reservations := make([]reservedTokenMetric, 0, len(reservedTokenMetricOrder))
	for _, metric := range reservedTokenMetricOrder {
		var units int64
		found := false
		for _, entry := range entries {
			if entry.metric != metric {
				continue
			}
			if !validReservationEntryUnits(entry.metric, entry.algorithm, entry.reservedUnits) ||
				found && entry.reservedUnits != units {
				return nil, ErrInvalidState
			}
			units = entry.reservedUnits
			found = true
		}
		if found {
			reservations = append(reservations, reservedTokenMetric{metric: metric, units: units})
		}
	}
	if !validReservedTokenMetrics(reservations) {
		return nil, ErrInvalidState
	}
	return reservations, nil
}

func tokenMetricUsageUnits(usage Usage, metric string) (int64, bool) {
	switch metric {
	case InputTokensMetric:
		return usage.InputTokens, true
	case OutputTokensMetric:
		return usage.OutputTokens, true
	case TotalTokensMetric:
		return usage.TotalTokens, true
	default:
		return 0, false
	}
}

func terminalTokenEntriesMatch(entries []lockedEntry, outcome Outcome) bool {
	for _, entry := range entries {
		actual, tokenMetric := tokenMetricUsageUnits(outcome.Usage, entry.metric)
		if !tokenMetric {
			continue
		}
		settled := entry.reservedUnits
		if outcome.Status == AttemptSucceeded && outcome.Usage.Known {
			if actual < 0 || actual > entry.reservedUnits {
				return false
			}
			settled = actual
		}
		if entry.settledUnits != settled || entry.releasedUnits != entry.reservedUnits-settled {
			return false
		}
	}
	return true
}

func insertSettlementUsage(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	entries []lockedEntry,
	outcome Outcome,
	identifiers settlementUsageIDs,
	now time.Time,
) error {
	if id.Validate(identifiers.logical, id.UsageRecord) != nil {
		return ErrInvalidState
	}
	pricing, err := attempt.selectedPricing()
	if err != nil || pricing != reservation.pricing {
		return ErrInvalidState
	}
	type priceFields struct {
		cost     any
		currency any
		revision any
		source   any
	}
	insert := func(
		usageID string,
		attemptID any,
		metric string,
		units int64,
		price priceFields,
		confidence string,
		provenanceKey string,
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
			reservation.environmentID, reservation.logicalRequestID, attemptID,
			metric, units, price.cost, price.currency, price.revision, price.source,
			confidence, provenanceKey, now); err != nil {
			return mapWriteError("insert quota usage", err)
		}
		return nil
	}
	if err := insert(
		identifiers.logical, nil, LogicalRequestsMetric, 1, priceFields{}, "calculated",
		logicalUsageProvenanceKey(reservation.logicalRequestID),
	); err != nil {
		return err
	}
	if outcome.Usage.Known {
		records := []struct {
			id     string
			metric string
			units  int64
		}{
			{id: identifiers.providerInput, metric: InputTokensMetric, units: outcome.Usage.InputTokens},
			{id: identifiers.providerOutput, metric: OutputTokensMetric, units: outcome.Usage.OutputTokens},
			{id: identifiers.providerTotal, metric: TotalTokensMetric, units: outcome.Usage.TotalTokens},
		}
		for _, record := range records {
			if err := insert(
				record.id, attempt.id, record.metric, record.units, priceFields{}, "reported",
				providerUsageProvenanceKey(attempt.id, record.metric),
			); err != nil {
				return err
			}
		}
	} else {
		reservations, reservationErr := lockedTokenReservationUnits(entries)
		if reservationErr != nil {
			return reservationErr
		}
		seen := make(map[string]struct{}, len(reservations))
		for _, tokenReservation := range reservations {
			usageID, ok := identifiers.unknownToken(tokenReservation.metric)
			if !ok || usageID == "" {
				return ErrInvalidState
			}
			if err := insert(
				usageID, attempt.id, tokenReservation.metric, tokenReservation.units,
				priceFields{}, UnknownCostConfidence,
				unknownTokenUsageProvenanceKey(reservation.reservationID, tokenReservation.metric),
			); err != nil {
				return err
			}
			seen[tokenReservation.metric] = struct{}{}
		}
		for _, metric := range reservedTokenMetricOrder {
			usageID, ok := identifiers.unknownToken(metric)
			if !ok {
				return ErrInvalidState
			}
			if _, expected := seen[metric]; (usageID != "") != expected {
				return ErrInvalidState
			}
		}
		if identifiers.providerInput != "" || identifiers.providerOutput != "" ||
			identifiers.providerTotal != "" {
			return ErrInvalidState
		}
	}
	if !outcome.Cost.Known {
		if identifiers.cost != "" {
			return ErrInvalidState
		}
		return nil
	}
	if !pricing.present() || !outcome.Usage.Known {
		return ErrInvalidState
	}
	amount := outcome.Cost.NanoUSD
	return insert(
		identifiers.cost, attempt.id, CostNanoUSDMetric, amount,
		priceFields{
			cost: amount, currency: pricing.currency,
			revision: pricing.revision, source: pricing.source,
		},
		CalculatedCostConfidence, configuredCostProvenanceKey(attempt.id),
	)
}

func logicalUsageProvenanceKey(logicalRequestID string) string {
	return "logical-request:" + logicalRequestID
}

func providerUsageProvenanceKey(attemptID, metric string) string {
	return ProviderReportedProvenance + ":" + attemptID + ":" + metric
}

func unknownOutputUsageProvenanceKey(reservationID string) string {
	return "quota-reservation:" + reservationID + ":unknown-output"
}

func unknownTokenUsageProvenanceKey(reservationID, metric string) string {
	switch metric {
	case InputTokensMetric:
		return "quota-reservation:" + reservationID + ":unknown-input"
	case OutputTokensMetric:
		return unknownOutputUsageProvenanceKey(reservationID)
	case TotalTokensMetric:
		return "quota-reservation:" + reservationID + ":unknown-total"
	default:
		return ""
	}
}

func configuredCostProvenanceKey(attemptID string) string {
	return "configured_flat_rate:" + attemptID
}

func terminalSettlementMatches(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	outcome Outcome,
) (bool, error) {
	if !terminalAttemptMatches(attempt, outcome, reservation.pricing) {
		return false, nil
	}
	tokenReservations, err := reservationTokenReservationUnits(reservation.entries)
	if err != nil {
		return false, err
	}
	type expectedUsage struct {
		attemptID     *string
		metric        string
		units         int64
		costNanoUSD   *int64
		currency      *string
		priceRevision *string
		pricingSource *string
		confidence    string
	}
	expected := map[string]expectedUsage{
		logicalUsageProvenanceKey(reservation.logicalRequestID): {
			metric: LogicalRequestsMetric, units: 1, confidence: "calculated",
		},
	}
	if outcome.Usage.Known {
		attemptID := attempt.id
		for _, record := range []struct {
			metric string
			units  int64
		}{
			{metric: InputTokensMetric, units: outcome.Usage.InputTokens},
			{metric: OutputTokensMetric, units: outcome.Usage.OutputTokens},
			{metric: TotalTokensMetric, units: outcome.Usage.TotalTokens},
		} {
			expected[providerUsageProvenanceKey(attempt.id, record.metric)] = expectedUsage{
				attemptID: &attemptID, metric: record.metric, units: record.units, confidence: "reported",
			}
		}
	} else {
		attemptID := attempt.id
		for _, tokenReservation := range tokenReservations {
			expected[unknownTokenUsageProvenanceKey(
				reservation.reservationID, tokenReservation.metric,
			)] = expectedUsage{
				attemptID: &attemptID, metric: tokenReservation.metric,
				units: tokenReservation.units, confidence: "unknown",
			}
		}
	}
	if outcome.Cost.Known {
		attemptID := attempt.id
		amount := outcome.Cost.NanoUSD
		currency := reservation.pricing.currency
		revision := reservation.pricing.revision
		source := reservation.pricing.source
		expected[configuredCostProvenanceKey(attempt.id)] = expectedUsage{
			attemptID: &attemptID, metric: CostNanoUSDMetric, units: amount,
			costNanoUSD: &amount, currency: &currency, priceRevision: &revision,
			pricingSource: &source, confidence: CalculatedCostConfidence,
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT usage_record_id, upstream_attempt_id, metric, units,
		       cost_nano_usd, currency, price_revision, pricing_source,
		       confidence, provenance_key
		FROM usage_records
		WHERE environment_id = $1 AND logical_request_id = $2
		ORDER BY provenance_key COLLATE "C"
	`, reservation.environmentID, reservation.logicalRequestID)
	if err != nil {
		return false, persistenceFailure("load terminal quota usage", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var usageID, metric, confidence, provenanceKey string
		var attemptID *string
		var costNanoUSD *int64
		var currency, priceRevision, pricingSource *string
		var units int64
		if err := rows.Scan(
			&usageID, &attemptID, &metric, &units, &costNanoUSD, &currency,
			&priceRevision, &pricingSource, &confidence, &provenanceKey,
		); err != nil {
			return false, persistenceFailure("scan terminal quota usage", err)
		}
		want, ok := expected[provenanceKey]
		if !ok || id.Validate(usageID, id.UsageRecord) != nil ||
			(attemptID == nil) != (want.attemptID == nil) || metric != want.metric ||
			units != want.units || confidence != want.confidence ||
			!optionalInt64Matches(costNanoUSD, want.costNanoUSD) ||
			!optionalStringMatches(currency, want.currency) ||
			!optionalStringMatches(priceRevision, want.priceRevision) ||
			!optionalStringMatches(pricingSource, want.pricingSource) {
			return false, nil
		}
		if attemptID != nil && *attemptID != *want.attemptID {
			return false, nil
		}
		if _, duplicate := seen[provenanceKey]; duplicate {
			return false, nil
		}
		seen[provenanceKey] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, persistenceFailure("iterate terminal quota usage", err)
	}
	return len(seen) == len(expected), nil
}

func terminalStoredTokenEntriesMatch(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	attempt storedAttempt,
	entries []lockedEntry,
) (bool, error) {
	// BeginAttempt and Reserve replays do not carry the original Outcome. The
	// exact terminal usage rows are the durable source for reconstructing the
	// token settlement split and detecting entry tampering.
	tokenReservations, err := lockedTokenReservationUnits(entries)
	if err != nil {
		return false, err
	}
	if len(tokenReservations) == 0 {
		return true, nil
	}
	reservedByMetric := make(map[string]int64, len(tokenReservations))
	for _, tokenReservation := range tokenReservations {
		reservedByMetric[tokenReservation.metric] = tokenReservation.units
	}
	rows, err := tx.Query(ctx, `
		SELECT usage_record_id, upstream_attempt_id, metric, units,
		       cost_nano_usd, currency, price_revision, pricing_source,
		       confidence, provenance_key
		FROM usage_records
		WHERE environment_id = $1 AND logical_request_id = $2
		  AND metric = ANY($3::text[])
		ORDER BY metric COLLATE "C", provenance_key COLLATE "C"
	`, reservation.environmentID, reservation.logicalRequestID, reservedTokenMetricOrder[:])
	if err != nil {
		return false, persistenceFailure("load stored terminal token usage", err)
	}
	defer rows.Close()
	mode := ""
	reported := make(map[string]int64, len(reservedTokenMetricOrder))
	unknown := make(map[string]struct{}, len(tokenReservations))
	for rows.Next() {
		var usageID, metric, confidence, provenanceKey string
		var attemptID *string
		var units int64
		var costNanoUSD *int64
		var currency, priceRevision, pricingSource *string
		if err := rows.Scan(
			&usageID, &attemptID, &metric, &units, &costNanoUSD, &currency,
			&priceRevision, &pricingSource, &confidence, &provenanceKey,
		); err != nil {
			return false, persistenceFailure("scan stored terminal token usage", err)
		}
		if id.Validate(usageID, id.UsageRecord) != nil || attemptID == nil || *attemptID != attempt.id || units < 0 ||
			costNanoUSD != nil || currency != nil || priceRevision != nil || pricingSource != nil {
			return false, nil
		}
		switch confidence {
		case "reported":
			if mode == "unknown" || provenanceKey != providerUsageProvenanceKey(attempt.id, metric) {
				return false, nil
			}
			mode = "reported"
			if _, duplicate := reported[metric]; duplicate {
				return false, nil
			}
			reported[metric] = units
		case UnknownCostConfidence:
			reserved, expected := reservedByMetric[metric]
			if mode == "reported" || !expected || units != reserved ||
				provenanceKey != unknownTokenUsageProvenanceKey(reservation.reservationID, metric) {
				return false, nil
			}
			mode = "unknown"
			if _, duplicate := unknown[metric]; duplicate {
				return false, nil
			}
			unknown[metric] = struct{}{}
		default:
			return false, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, persistenceFailure("iterate stored terminal token usage", err)
	}
	var usage Usage
	switch mode {
	case "reported":
		if len(reported) != len(reservedTokenMetricOrder) {
			return false, nil
		}
		var ok bool
		if usage.InputTokens, ok = reported[InputTokensMetric]; !ok {
			return false, nil
		}
		if usage.OutputTokens, ok = reported[OutputTokensMetric]; !ok {
			return false, nil
		}
		if usage.TotalTokens, ok = reported[TotalTokensMetric]; !ok {
			return false, nil
		}
		usage.Known = true
		usage.Provenance = ProviderReportedProvenance
		if usage.validate() != nil {
			return false, nil
		}
	case "unknown":
		if len(unknown) != len(tokenReservations) {
			return false, nil
		}
		usage = Usage{Provenance: UnknownUsageProvenance}
	default:
		return false, nil
	}
	return terminalTokenEntriesMatch(entries, Outcome{Status: attempt.status, Usage: usage}), nil
}

func terminalEntriesMatch(
	logicalStatus string,
	reservationStatus string,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
) bool {
	concurrencyEntries := 0
	for _, entry := range entries {
		if !lockedEntryBucketValid(entry) ||
			!existingReservationStateMatches(
				logicalStatus, reservationStatus, entry.metric, entry.algorithm,
				entry.initialReservedUnits,
				entry.initialReservedUnits, entry.reservedUnits,
				entry.settledUnits, entry.releasedUnits,
			) {
			return false
		}
		if isConcurrencyMetric(entry.metric) {
			concurrencyEntries++
			if entry.bucketUsed != 0 {
				return false
			}
		}
	}
	return len(leases) == concurrencyEntries
}

func pendingEntriesMatch(
	logicalStatus string,
	reservation lockedReservation,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
) bool {
	for _, entry := range entries {
		outstanding := entry.reservedUnits - entry.settledUnits - entry.releasedUnits
		if !lockedEntryBucketValid(entry) ||
			outstanding < 0 ||
			(entry.algorithm != TokenBucketAlgorithm && entry.bucketReserved < outstanding) ||
			!existingReservationStateMatches(
				logicalStatus, reservation.status, entry.metric, entry.algorithm,
				entry.initialReservedUnits, entry.initialReservedUnits, entry.reservedUnits,
				entry.settledUnits, entry.releasedUnits,
			) || (isConcurrencyMetric(entry.metric) && entry.bucketUsed != 0) {
			return false
		}
	}
	return pendingConcurrencyLeasesMatch(reservation, entries, leases)
}

func lockedEntryBucketValid(entry lockedEntry) bool {
	if entry.algorithm == TokenBucketAlgorithm {
		_, err := tokenStateFromLockedEntry(entry)
		return err == nil
	}
	return entry.hardMaximum != nil && *entry.hardMaximum > 0 &&
		entry.bucketUsed >= 0 && entry.bucketReserved >= 0 &&
		entry.bucketUsed <= *entry.hardMaximum &&
		entry.bucketReserved <= *entry.hardMaximum-entry.bucketUsed &&
		entry.available == nil && entry.refillNumerator == nil &&
		entry.refillDenominator == nil && entry.refilledAt == nil
}

func pendingConcurrencyLeasesMatch(
	reservation lockedReservation,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
) bool {
	expectedBuckets := make(map[string]struct{})
	for _, entry := range entries {
		if isConcurrencyMetric(entry.metric) {
			expectedBuckets[entry.bucketID] = struct{}{}
		}
	}
	if len(leases) != len(expectedBuckets) {
		return false
	}
	for _, lease := range leases {
		if _, ok := expectedBuckets[lease.bucketID]; !ok || lease.releasedAt != nil ||
			!lease.expiresAt.Equal(reservation.expiresAt) || !lease.expiresAt.After(lease.acquiredAt) {
			return false
		}
		delete(expectedBuckets, lease.bucketID)
	}
	return len(expectedBuckets) == 0
}

func releaseLockedConcurrencyLeases(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	leases []lockedConcurrencyLease,
	now time.Time,
) error {
	for _, lease := range leases {
		command, err := tx.Exec(ctx, `
			UPDATE concurrency_leases
			SET released_at = GREATEST(acquired_at, $2)
			WHERE concurrency_lease_id = $1
			  AND environment_id = $3
			  AND logical_request_id = $4
			  AND quota_bucket_id = $5
			  AND expires_at = $6
			  AND released_at IS NULL
		`, lease.id, now, reservation.environmentID, reservation.logicalRequestID,
			lease.bucketID, reservation.expiresAt)
		if err != nil {
			return persistenceFailure("release concurrency lease", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	return nil
}

func settleLocked(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logical lockedLogical,
	attempt storedAttempt,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
	outcome Outcome,
	usageIDs settlementUsageIDs,
	now time.Time,
) error {
	normalized, normalizeErr := normalizeOutcomeForPricing(outcome, reservation.pricing)
	if reservation.status != "pending" || attempt.status != "started" ||
		(logical.status != "dispatched" && logical.status != "streaming") ||
		len(entries) > maximumRulesPerRequest || normalizeErr != nil || normalized != outcome ||
		!attemptPricingMatchesReservation(attempt, reservation.Reservation) {
		return ErrInvalidState
	}
	if err := validateCostSettlement(entries, outcome.Cost); err != nil {
		return err
	}
	settledUnits := make([]int64, len(entries))
	releasedUnits := make([]int64, len(entries))
	for _, entry := range entries {
		if !validReservationEntryUnits(entry.metric, entry.algorithm, entry.reservedUnits) ||
			entry.settledUnits != 0 || entry.releasedUnits != 0 ||
			!lockedEntryBucketValid(entry) ||
			(entry.algorithm != TokenBucketAlgorithm && entry.bucketReserved < entry.reservedUnits) ||
			(isConcurrencyMetric(entry.metric) && entry.bucketUsed != 0) {
			return ErrInvalidState
		}
	}
	if !pendingConcurrencyLeasesMatch(reservation, entries, leases) {
		return ErrInvalidState
	}
	for index, entry := range entries {
		settled := entry.reservedUnits
		if isConcurrencyMetric(entry.metric) {
			settled = 0
		} else if entry.metric == CostNanoUSDMetric && outcome.Cost.Known {
			settled = outcome.Cost.NanoUSD
			if settled > entry.reservedUnits {
				return ErrInvalidInput
			}
		} else if actual, tokenMetric := tokenMetricUsageUnits(outcome.Usage, entry.metric); tokenMetric && outcome.Status == AttemptSucceeded && outcome.Usage.Known {
			settled = actual
			if settled > entry.reservedUnits {
				return ErrInvalidInput
			}
		}
		if settled < 0 {
			return ErrInvalidState
		}
		if entry.algorithm != TokenBucketAlgorithm &&
			(entry.bucketUsed > *entry.hardMaximum || settled > *entry.hardMaximum-entry.bucketUsed) {
			return ErrInvalidState
		}
		settledUnits[index] = settled
		releasedUnits[index] = entry.reservedUnits - settled
	}
	if attempt.firstByteAt != nil && attempt.firstByteAt.After(now) {
		now = attempt.firstByteAt.UTC()
	}
	for index, entry := range entries {
		var command pgconn.CommandTag
		var err error
		if entry.algorithm == TokenBucketAlgorithm {
			if releasedUnits[index] > 0 {
				state, stateErr := tokenStateFromLockedEntry(entry)
				if stateErr != nil {
					return stateErr
				}
				refunded, stateErr := refundTokenBalance(state, releasedUnits[index], now)
				if stateErr != nil {
					return stateErr
				}
				if err := persistTokenBucketEntry(
					ctx, tx, entry, refunded, now, "refund unused token bucket reservation",
				); err != nil {
					return err
				}
			}
		} else {
			command, err = tx.Exec(ctx, `
				UPDATE quota_buckets
				SET used_units = used_units + $2::bigint,
				    reserved_units = reserved_units - $3::bigint,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $4)
				WHERE quota_bucket_id = $1
				  AND $2::bigint >= 0
				  AND ($3::bigint > 0 OR (
				        $3::bigint = 0 AND metric = 'cost_nano_usd' AND algorithm = 'calendar'
				      ))
				  AND reserved_units >= $3::bigint
				  AND hard_maximum IS NOT NULL
				  AND used_units <= hard_maximum
				  AND $2::bigint <= hard_maximum - used_units
			`, entry.bucketID, settledUnits[index], entry.reservedUnits, now)
			if err != nil {
				return persistenceFailure("settle quota bucket", err)
			}
			if command.RowsAffected() != 1 {
				return ErrInvalidState
			}
		}
		command, err = tx.Exec(ctx, `
			UPDATE quota_reservation_entries
			SET settled_units = $2, released_units = $3
			WHERE quota_reservation_entry_id = $1
			  AND reserved_units = $4 AND settled_units = 0 AND released_units = 0
		`, entry.id, settledUnits[index], releasedUnits[index], entry.reservedUnits)
		if err != nil {
			return persistenceFailure("settle quota reservation entry", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if err := releaseLockedConcurrencyLeases(ctx, tx, reservation, leases, now); err != nil {
		return err
	}
	var command pgconn.CommandTag
	var err error
	if err := insertSettlementUsage(ctx, tx, reservation, attempt, entries, outcome, usageIDs, now); err != nil {
		return err
	}
	billedCost, settledCostConfidence := settlementCostValues(reservation.pricing, outcome.Cost)
	command, err = tx.Exec(ctx, `
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
		nullableString(outcome.FailureCode), billedCost, settledCostConfidence,
		nullableString(reservation.pricing.currency), nullableString(reservation.pricing.revision),
		nullableString(reservation.pricing.source),
		nullableString(initialCostConfidence(reservation.pricing)))
	if err != nil {
		return persistenceFailure("complete upstream attempt", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	logicalStatus := "failed"
	if outcome.Status == AttemptSucceeded {
		logicalStatus = "succeeded"
	} else if outcome.Status == AttemptCancelled {
		logicalStatus = "cancelled"
	}
	command, err = tx.Exec(ctx, `
		UPDATE logical_requests
		SET status = $2,
		    completed_at = GREATEST(requested_at, COALESCE(dispatched_at, requested_at), $3),
		    failure_code = $4
		WHERE logical_request_id = $1 AND status IN ('dispatched', 'streaming')
	`, reservation.logicalRequestID, logicalStatus, now,
		nullableString(outcome.FailureCode))
	if err != nil {
		return persistenceFailure("complete logical request", err)
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
		return persistenceFailure("complete quota reservation", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	return nil
}

func releaseLocked(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logical lockedLogical,
	entries []lockedEntry,
	leases []lockedConcurrencyLease,
	reservationStatus string,
	failureCode string,
	now time.Time,
) error {
	if reservation.status != "pending" || logical.status != "reserved" ||
		len(entries) > maximumRulesPerRequest {
		return ErrInvalidState
	}
	if _, _, err := lockedCostReservationUnits(entries); err != nil {
		return err
	}
	if _, err := lockedTokenReservationUnits(entries); err != nil {
		return err
	}
	for _, entry := range entries {
		if !validReservationEntryUnits(entry.metric, entry.algorithm, entry.reservedUnits) ||
			entry.settledUnits != 0 || entry.releasedUnits != 0 ||
			!lockedEntryBucketValid(entry) ||
			(entry.algorithm != TokenBucketAlgorithm && entry.bucketReserved < entry.reservedUnits) ||
			(isConcurrencyMetric(entry.metric) && entry.bucketUsed != 0) {
			return ErrInvalidState
		}
	}
	if !pendingConcurrencyLeasesMatch(reservation, entries, leases) {
		return ErrInvalidState
	}
	for _, entry := range entries {
		var command pgconn.CommandTag
		var err error
		if entry.algorithm == TokenBucketAlgorithm {
			state, stateErr := tokenStateFromLockedEntry(entry)
			if stateErr != nil {
				return stateErr
			}
			refunded, stateErr := refundTokenBalance(state, entry.reservedUnits, now)
			if stateErr != nil {
				return stateErr
			}
			if err := persistTokenBucketEntry(ctx, tx, entry, refunded, now, "refund token bucket"); err != nil {
				return err
			}
		} else {
			command, err = tx.Exec(ctx, `
				UPDATE quota_buckets
				SET reserved_units = reserved_units - $2::bigint,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $3)
				WHERE quota_bucket_id = $1
				  AND ($2::bigint > 0 OR (
				        $2::bigint = 0 AND metric = 'cost_nano_usd' AND algorithm = 'calendar'
				      ))
				  AND reserved_units >= $2::bigint
			`, entry.bucketID, entry.reservedUnits, now)
			if err != nil {
				return persistenceFailure("release quota bucket", err)
			}
			if command.RowsAffected() != 1 {
				return ErrInvalidState
			}
		}
		command, err = tx.Exec(ctx, `
			UPDATE quota_reservation_entries
			SET settled_units = 0, released_units = $2
			WHERE quota_reservation_entry_id = $1
			  AND reserved_units = $2 AND settled_units = 0 AND released_units = 0
		`, entry.id, entry.reservedUnits)
		if err != nil {
			return persistenceFailure("release quota reservation entry", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
		}
	}
	if err := releaseLockedConcurrencyLeases(ctx, tx, reservation, leases, now); err != nil {
		return err
	}
	var command pgconn.CommandTag
	var err error
	command, err = tx.Exec(ctx, `
		UPDATE logical_requests
		SET status = 'failed', completed_at = GREATEST(requested_at, $2),
		    failure_code = $3
		WHERE logical_request_id = $1 AND status = 'reserved'
	`, reservation.logicalRequestID, now, failureCode)
	if err != nil {
		return persistenceFailure("complete released logical request", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	command, err = tx.Exec(ctx, `
		UPDATE quota_reservations
		SET status = $2, released_at = GREATEST(created_at, $3)
		WHERE quota_reservation_id = $1 AND status = 'pending'
	`, reservation.reservationID, reservationStatus, now)
	if err != nil {
		return persistenceFailure("complete released quota reservation", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	return nil
}

func terminalAttemptMatches(stored storedAttempt, outcome Outcome, pricing selectedPricing) bool {
	storedPricing, err := stored.selectedPricing()
	if err != nil || storedPricing != pricing {
		return false
	}
	if !pricing.present() {
		if stored.billedCost != nil || stored.costConfidence != nil || outcome.Cost != (Cost{}) {
			return false
		}
	} else if outcome.Cost.Known {
		if stored.billedCost == nil || *stored.billedCost != outcome.Cost.NanoUSD ||
			stored.costConfidence == nil || *stored.costConfidence != CalculatedCostConfidence {
			return false
		}
	} else if stored.billedCost != nil || stored.costConfidence == nil ||
		*stored.costConfidence != UnknownCostConfidence {
		return false
	}
	if stored.status != outcome.Status {
		return false
	}
	if (stored.httpStatus == nil) != (outcome.HTTPStatus == 0) ||
		(stored.failureCode == nil) != (outcome.FailureCode == "") {
		return false
	}
	if stored.httpStatus != nil && int(*stored.httpStatus) != outcome.HTTPStatus {
		return false
	}
	return stored.failureCode == nil || *stored.failureCode == outcome.FailureCode
}

func optionalInt64Matches(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func optionalStringMatches(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func transactionTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&now); err != nil {
		return time.Time{}, persistenceFailure("read PostgreSQL transaction time", err)
	}
	now = now.UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalidState
	}
	return now, nil
}

// statementTime is read only after all lifecycle locks are held. Unlike
// transaction_timestamp, it cannot be older merely because this transaction
// waited behind a first-byte or completion writer.
func statementTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&now); err != nil {
		return time.Time{}, persistenceFailure("read PostgreSQL statement time", err)
	}
	now = now.UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalidState
	}
	return now, nil
}

func mapWriteError(operation string, err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23503", "23514", "22001", "22P02":
			return fmt.Errorf("%s: %w", operation, ErrInvalidInput)
		case "23505":
			return fmt.Errorf("%s: %w", operation, ErrInvalidState)
		}
	}
	return persistenceFailure(operation, err)
}

type persistenceError struct {
	operation string
}

func (failure *persistenceError) Error() string {
	return failure.operation + ": " + ErrDependency.Error()
}

func (failure *persistenceError) Unwrap() error { return ErrDependency }

func persistenceFailure(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &persistenceError{operation: operation}
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
