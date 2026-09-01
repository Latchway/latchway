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

const materializeQuotaBucketSQL = `
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
`

func materializePlannedBuckets(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	plans []plannedBucket,
	requestedAt time.Time,
) error {
	if len(plans) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for index := range plans {
		plan := &plans[index]
		hardMaximum := plan.rule.Maximum
		var availableUnits, refillNumerator, refillDenominator, refilledAt any
		if plan.rule.Algorithm == TokenBucketAlgorithm {
			maximumBalance, ok := tokenCapacityBalance(plan.rule.Capacity)
			if !ok {
				return ErrInvalidInput
			}
			hardMaximum = plan.rule.Capacity
			availableUnits = maximumBalance
			refillNumerator = plan.rule.RefillNumerator
			refillDenominator = plan.rule.RefillDenominator
			refilledAt = requestedAt
		}
		batch.Queue(
			materializeQuotaBucketSQL,
			plan.bucketID, prepared.OrganizationID, prepared.ApplicationID,
			prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
			plan.rule.Metric, plan.rule.scopeType, plan.rule.scopeDimensions,
			plan.rule.scopeKey, plan.rule.Algorithm, plan.period.key,
			hardMaximum, availableUnits, refillNumerator, refillDenominator,
			refilledAt, requestedAt,
		)
	}
	results := tx.SendBatch(ctx, batch)
	for range plans {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return mapWriteError("materialize quota bucket", err)
		}
	}
	if err := results.Close(); err != nil {
		return mapWriteError("materialize quota bucket", err)
	}
	return nil
}

type reservationBatchCommand struct {
	operation string
	query     string
	arguments []any
	mapWrite  bool
	expectOne bool
}

const reserveCalendarBucketSQL = `
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
`

const insertConcurrencyLeaseSQL = `
	INSERT INTO concurrency_leases (
		concurrency_lease_id, organization_id, application_id,
		environment_id, quota_bucket_id, logical_request_id,
		acquired_at, expires_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`

const insertQuotaReservationSQL = `
	INSERT INTO quota_reservations (
		quota_reservation_id, organization_id, application_id, environment_id,
		logical_request_id, idempotency_key, status, created_at, expires_at
	) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
`

const insertQuotaReservationEntrySQL = `
	INSERT INTO quota_reservation_entries (
		quota_reservation_entry_id, organization_id, application_id,
		environment_id, quota_reservation_id, quota_bucket_id,
		initial_reserved_units, reserved_units, settled_units, released_units,
		cost_retry_treatment
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 0, 0, $8)
`

func persistAcceptedReservation(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	plans []plannedBucket,
	reservationID string,
	logicalRequestID string,
	reservationKey string,
	decisionAt time.Time,
	expiresAt time.Time,
) error {
	commands := make([]reservationBatchCommand, 0, 2*len(plans)+2)
	for index := range plans {
		plan := &plans[index]
		if plan.rule.Algorithm == TokenBucketAlgorithm {
			reservedState, accepted, err := reserveTokenBalance(plan.tokenState, plan.reservedUnits)
			if err != nil || !accepted {
				return ErrInvalidState
			}
			query, arguments, err := tokenBucketPersistenceCommand(
				plan.locked, reservedState, decisionAt,
			)
			if err != nil {
				return err
			}
			commands = append(commands, reservationBatchCommand{
				operation: "reserve token bucket", query: query, arguments: arguments, expectOne: true,
			})
			continue
		}
		commands = append(commands, reservationBatchCommand{
			operation: "reserve quota bucket", query: reserveCalendarBucketSQL,
			arguments: []any{
				plan.locked.id, plan.rule.Maximum, plan.reservedUnits, decisionAt,
				plan.locked.used, plan.locked.reserved,
			},
			expectOne: true,
		})
	}
	for index := range plans {
		plan := &plans[index]
		if !isConcurrencyMetric(plan.rule.Metric) {
			continue
		}
		commands = append(commands, reservationBatchCommand{
			operation: "insert concurrency lease", query: insertConcurrencyLeaseSQL,
			arguments: []any{
				plan.leaseID, prepared.OrganizationID, prepared.ApplicationID,
				prepared.EnvironmentID, plan.locked.id, logicalRequestID,
				decisionAt, expiresAt,
			},
			mapWrite: true,
		})
	}
	commands = append(commands, reservationBatchCommand{
		operation: "insert quota reservation", query: insertQuotaReservationSQL,
		arguments: []any{
			reservationID, prepared.OrganizationID, prepared.ApplicationID,
			prepared.EnvironmentID, logicalRequestID, reservationKey, decisionAt, expiresAt,
		},
		mapWrite: true,
	})
	for index := range plans {
		plan := &plans[index]
		commands = append(commands, reservationBatchCommand{
			operation: "insert quota reservation entry", query: insertQuotaReservationEntrySQL,
			arguments: []any{
				plan.entryID, prepared.OrganizationID, prepared.ApplicationID,
				prepared.EnvironmentID, reservationID, plan.locked.id, plan.reservedUnits,
				plan.rule.CostRetryTreatment,
			},
			mapWrite: true,
		})
	}

	batch := &pgx.Batch{}
	for _, command := range commands {
		batch.Queue(command.query, command.arguments...)
	}
	results := tx.SendBatch(ctx, batch)
	for _, command := range commands {
		tag, err := results.Exec()
		if err != nil {
			_ = results.Close()
			if command.mapWrite {
				return mapWriteError(command.operation, err)
			}
			return persistenceFailure(command.operation, err)
		}
		if command.expectOne && tag.RowsAffected() != 1 {
			_ = results.Close()
			return ErrInvalidState
		}
	}
	if err := results.Close(); err != nil {
		return persistenceFailure("complete quota reservation writes", err)
	}
	return nil
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
			application_user_id, installation_id,
			installation_family_id, client_component_id, component_definition_id,
			component_kind, trust_source, session_grant_id,
			config_revision_id, feature_key, selected_limit_plan_key,
			selected_route_key, selected_upstream_key, selected_model_key,
			selected_physical_model,
			protocol, client_request_id, framework, framework_version,
			trusted_decision_fingerprint, status, requested_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24,
			'reserved', $25
		)
		ON CONFLICT DO NOTHING
	`, logicalRequestID, prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, prepared.ApplicationUserID, prepared.InstallationID,
		nullableString(prepared.InstallationFamilyID), nullableString(prepared.ClientComponentID),
		nullableString(prepared.ComponentDefinitionID), nullableString(prepared.ComponentKind),
		nullableString(prepared.TrustSource), prepared.SessionGrantID, prepared.ConfigRevisionID,
		prepared.FeatureKey, prepared.LimitPlanKey, prepared.RouteKey, prepared.UpstreamKey,
		prepared.ModelKey, prepared.PhysicalModel, prepared.Protocol,
		nullableString(prepared.ClientRequestID), nullableString(prepared.Framework),
		nullableString(prepared.FrameworkVersion), fingerprint, requestedAt)
	if err != nil {
		return Reservation{}, mapWriteError("insert logical request", err)
	}
	if command.RowsAffected() == 0 {
		claimed, claimErr := claimAuthenticatedRequest(ctx, tx, prepared, fingerprint)
		if claimErr != nil {
			return Reservation{}, claimErr
		}
		if !claimed {
			return loadExistingReserve(ctx, tx, prepared, fingerprint)
		}
	} else if command.RowsAffected() != 1 || len(prepared.DecisionStages) != 0 {
		return Reservation{}, ErrInvalidState
	}
	if len(requestBoundsExceeded) != 0 {
		decisionAt, timeErr := statementTime(ctx, tx)
		if timeErr != nil {
			return Reservation{}, timeErr
		}
		if stageErr := appendQuotaDecisionStages(
			ctx, tx, prepared, requestedAt, decisionAt,
			requestBoundEvaluatedRuleKeySet(prepared.rules),
			deniedRuleKeySet(requestBoundsExceeded), "quota_exceeded",
		); stageErr != nil {
			return Reservation{}, stageErr
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
	}
	if err := materializePlannedBuckets(ctx, tx, prepared, plans, requestedAt); err != nil {
		return Reservation{}, err
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
		deniedKeys, stageErr := deniedPlanRuleKeySet(plans, quotaExceeded, concurrencyExceeded)
		if stageErr != nil {
			return Reservation{}, stageErr
		}
		if stageErr := appendQuotaDecisionStages(
			ctx, tx, prepared, requestedAt, decisionAt,
			evaluatedReservationRuleKeySet(prepared.rules, plans), deniedKeys, failureCode,
		); stageErr != nil {
			return Reservation{}, stageErr
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

	if err := appendQuotaDecisionStages(
		ctx, tx, prepared, requestedAt, decisionAt,
		evaluatedReservationRuleKeySet(prepared.rules, plans), nil, "",
	); err != nil {
		return Reservation{}, err
	}
	if err := persistAcceptedReservation(
		ctx, tx, prepared, plans, identifiers.reservation, logicalRequestID,
		reservationKey, decisionAt, expiresAt,
	); err != nil {
		return Reservation{}, err
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
		inputPreflight:      cloneInputPreflightBinding(prepared.InputPreflight),
		requestMeasurements: cloneRequestMeasurementBinding(prepared.RequestMeasurements),
		retryPlan:           retryPlanForRequest(prepared),
		windowResetAt:       maximumResetAt(entries), expiresAt: expiresAt,
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
		installationFamilyID, clientComponentID      *string
		componentDefinitionID, componentKind         *string
		trustSource, framework, frameworkVersion     *string
		clientRequestID, fingerprint, failureCode    *string
		requestedAt                                  time.Time
	}
	var logical existingLogical
	err := tx.QueryRow(ctx, `
		SELECT organization_id, application_id, environment_id,
		       application_user_id, installation_id,
		       installation_family_id, client_component_id,
		       component_definition_id, component_kind, trust_source,
		       session_grant_id,
		       config_revision_id, feature_key, protocol, client_request_id,
		       framework, framework_version,
		       trusted_decision_fingerprint, status, failure_code, requested_at
		FROM logical_requests
		WHERE logical_request_id = $1
		FOR UPDATE
	`, prepared.LogicalRequestID.String()).Scan(
		&logical.organizationID, &logical.applicationID, &logical.environmentID,
		&logical.applicationUserID, &logical.installationID,
		&logical.installationFamilyID, &logical.clientComponentID,
		&logical.componentDefinitionID, &logical.componentKind, &logical.trustSource,
		&logical.sessionGrantID,
		&logical.configRevisionID, &logical.featureKey, &logical.protocol,
		&logical.clientRequestID, &logical.framework, &logical.frameworkVersion,
		&logical.fingerprint, &logical.status,
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
		!nullableStringMatches(logical.installationFamilyID, prepared.InstallationFamilyID) ||
		!nullableStringMatches(logical.clientComponentID, prepared.ClientComponentID) ||
		!nullableStringMatches(logical.componentDefinitionID, prepared.ComponentDefinitionID) ||
		!nullableStringMatches(logical.componentKind, prepared.ComponentKind) ||
		!nullableStringMatches(logical.trustSource, prepared.TrustSource) ||
		logical.sessionGrantID != prepared.SessionGrantID ||
		logical.configRevisionID != prepared.ConfigRevisionID ||
		logical.featureKey != prepared.FeatureKey ||
		logical.protocol != prepared.Protocol ||
		!nullableStringMatches(logical.clientRequestID, prepared.ClientRequestID) ||
		!nullableStringMatches(logical.framework, prepared.Framework) ||
		!nullableStringMatches(logical.frameworkVersion, prepared.FrameworkVersion) ||
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
		costRetryTreatment                           string
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
		       entry.cost_retry_treatment,
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
			&existing.costRetryTreatment,
			&existing.bucketOrganizationID, &existing.bucketApplicationID,
			&existing.limitPlanKey, &existing.ruleKey, &existing.metric,
			&existing.scopeType, &existing.scopeDimensions, &existing.scopeKey,
			&existing.algorithm, &existing.windowKey, &existing.bucketUsed,
		); err != nil {
			return Reservation{}, persistenceFailure("scan existing quota reservation", err)
		}
		var treatmentOK bool
		existing.costRetryTreatment, treatmentOK = canonicalStoredCostRetryTreatment(
			existing.metric, existing.costRetryTreatment,
		)
		if !treatmentOK {
			return Reservation{}, ErrInvalidState
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
			existing.costRetryTreatment != plan.rule.CostRetryTreatment ||
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
				costRetryTreatment: plan.rule.CostRetryTreatment,
				reservedUnits:      plan.reservedUnits,
				resetAt:            plan.period.end,
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
		!storedInitialInputPreflightMatches(attempts[0], prepared.InputPreflight) ||
		!storedInitialRequestMeasurementsMatch(attempts[0], prepared.RequestMeasurements)) {
		return Reservation{}, ErrInvalidState
	}
	replayed := lockedReservation{
		Reservation: Reservation{
			organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
			environmentID: prepared.EnvironmentID, logicalRequestID: prepared.LogicalRequestID.String(),
			reservationID: reservationID, entries: entries, protocol: prepared.Protocol,
			inputPreflight:      cloneInputPreflightBinding(prepared.InputPreflight),
			requestMeasurements: cloneRequestMeasurementBinding(prepared.RequestMeasurements),
			retryPlan:           retryPlanForRequest(prepared), expiresAt: expiresAt,
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
		inputPreflight:      cloneInputPreflightBinding(prepared.InputPreflight),
		requestMeasurements: cloneRequestMeasurementBinding(prepared.RequestMeasurements),
		retryPlan:           retryPlanForRequest(prepared),
		windowResetAt:       maximumResetAt(entries),
		expiresAt:           expiresAt,
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
		!storedInitialInputPreflightMatches(attempts[0], prepared.InputPreflight) ||
		!storedInitialRequestMeasurementsMatch(attempts[0], prepared.RequestMeasurements)) {
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
		inputPreflight:      cloneInputPreflightBinding(prepared.InputPreflight),
		requestMeasurements: cloneRequestMeasurementBinding(prepared.RequestMeasurements),
		retryPlan:           retryPlanForRequest(prepared),
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
		pricing:             pricingForRequest(prepared),
		inputPreflight:      cloneInputPreflightBinding(prepared.InputPreflight),
		requestMeasurements: cloneRequestMeasurementBinding(prepared.RequestMeasurements),
		retryPlan:           retryPlanForRequest(prepared),
		expiresAt:           existing.expiresAt,
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
	if err := findPlannedBucketIDs(ctx, tx, prepared, plans); err != nil {
		return err
	}
	sort.Slice(plans, func(left, right int) bool { return plans[left].bucketID < plans[right].bucketID })
	for index := range plans {
		if index > 0 && plans[index-1].bucketID == plans[index].bucketID {
			return ErrInvalidState
		}
	}
	return lockPlannedBucketRows(ctx, tx, prepared, plans)
}

const findQuotaBucketIDSQL = `
	SELECT quota_bucket_id
	FROM quota_buckets
	WHERE environment_id = $1
	  AND limit_plan_key = $2
	  AND rule_key = $3
	  AND metric = $4
	  AND algorithm = $5
	  AND window_key = $6
	  AND scope_key = $7
`

func findPlannedBucketIDs(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	plans []plannedBucket,
) error {
	if len(plans) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for index := range plans {
		plan := &plans[index]
		batch.Queue(
			findQuotaBucketIDSQL,
			prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
			plan.rule.Metric, plan.rule.Algorithm, plan.period.key, plan.rule.scopeKey,
		)
	}
	results := tx.SendBatch(ctx, batch)
	for index := range plans {
		var bucketID string
		err := results.QueryRow().Scan(&bucketID)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = results.Close()
			return ErrInvalidState
		}
		if err != nil {
			_ = results.Close()
			return persistenceFailure("find quota bucket", err)
		}
		if id.Validate(bucketID, id.QuotaBucket) != nil {
			_ = results.Close()
			return ErrInvalidState
		}
		plans[index].bucketID = bucketID
	}
	if err := results.Close(); err != nil {
		return persistenceFailure("find quota bucket", err)
	}
	return nil
}

func findBucketID(ctx context.Context, tx pgx.Tx, prepared preparedRequest, plan plannedBucket) (string, error) {
	var bucketID string
	err := tx.QueryRow(ctx, findQuotaBucketIDSQL,
		prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
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

const lockQuotaBucketSQL = `
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
`

func lockPlannedBucketRows(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	plans []plannedBucket,
) error {
	if len(plans) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for index := range plans {
		plan := &plans[index]
		batch.Queue(
			lockQuotaBucketSQL,
			plan.bucketID, prepared.EnvironmentID, prepared.LimitPlanKey,
			plan.rule.ruleKey, plan.rule.Metric, plan.rule.Algorithm,
			plan.period.key, plan.rule.scopeKey,
		)
	}
	results := tx.SendBatch(ctx, batch)
	for index := range plans {
		bucket, err := scanLockedBucket(results.QueryRow(), prepared, plans[index])
		if err != nil {
			_ = results.Close()
			return err
		}
		plans[index].locked = bucket
	}
	if err := results.Close(); err != nil {
		return persistenceFailure("lock quota bucket", err)
	}
	return nil
}

func scanLockedBucket(row pgx.Row, prepared preparedRequest, plan plannedBucket) (lockedBucket, error) {
	var result lockedBucket
	var organizationID, applicationID string
	err := row.Scan(
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
	query, arguments, err := tokenBucketPersistenceCommand(bucket, state, now)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, query, arguments...)
	if err != nil {
		return persistenceFailure(operation, err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	return nil
}

const persistTokenBucketSQL = `
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
`

func tokenBucketPersistenceCommand(
	bucket lockedBucket,
	state tokenBucketState,
	now time.Time,
) (string, []any, error) {
	stored, err := tokenStateFromLockedBucket(bucket)
	if err != nil || validatePersistedTokenBucket(state) != nil || now.IsZero() || bucket.version == math.MaxInt64 {
		return "", nil, ErrInvalidState
	}
	return persistTokenBucketSQL, []any{
		bucket.id, state.capacity, state.balance, state.numerator, state.denominator,
		state.refilledAt, now, stored.capacity, stored.balance, stored.numerator,
		stored.denominator, stored.refilledAt, bucket.version,
	}, nil
}

func reservationEntries(plans []plannedBucket) []reservationEntry {
	entries := make([]reservationEntry, len(plans))
	for index := range plans {
		entries[index] = reservationEntry{
			bucketID:           plans[index].locked.id,
			entryID:            plans[index].entryID,
			leaseID:            plans[index].leaseID,
			metric:             plans[index].rule.Metric,
			algorithm:          plans[index].rule.Algorithm,
			costRetryTreatment: plans[index].rule.CostRetryTreatment,
			reservedUnits:      plans[index].reservedUnits,
			resetAt:            plans[index].period.end,
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
			(existing.attemptDecisionBindingVersion >= 1 &&
				!optionalInt64Matches(existing.perRequestOutputTokenBound, perRequestOutputBound)) ||
			!attemptPricingMatchesReservation(existing, reservation) ||
			!storedInitialInputPreflightMatches(existing, reservation.inputPreflight) ||
			!storedInitialRequestMeasurementsMatch(existing, reservation.requestMeasurements) {
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
		reservation.inputPreflight, reservation.requestMeasurements, perRequestOutputBound,
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
			total_token_bound, request_measurement_binding_version,
			request_measurement_sha256, measured_request_bytes,
			measured_image_units, measured_tool_calls
		) VALUES (
			$1, $2, $3, $4, $5, 1, $6, $7, $8, $9, 2, $10, $11, 1,
			'started', $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
			1, $24, $25, $26, $27
		)
	`, attemptID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		reservation.routeKey, reservation.upstreamKey, reservation.physicalModel,
		reservation.modelKey, decisionDigest[:], perRequestOutputBound, now,
		nullableString(reservation.pricing.currency),
		nullableString(reservation.pricing.revision), nullableString(reservation.pricing.source),
		nullableString(initialCostConfidence(reservation.pricing)), accountingMethod,
		accountingProfileID, accountingProfileDigest, rewrittenBodyDigest,
		inputBound, outputBound, totalBound,
		decisionAttempt.requestMeasurementSHA256,
		decisionAttempt.measuredRequestBytes, decisionAttempt.measuredImageUnits,
		decisionAttempt.measuredToolCalls); err != nil {
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

// MarkFirstByte records the first response boundary once. A newly dispatched
// first attempt uses one ordered PostgreSQL batch: every row is locked and
// scanned through the same validators as the general lifecycle path, while
// the two writes remain tentative until validation succeeds and the
// transaction commits. Replays, retries, terminal attempts, and any
// noncanonical state roll back the tentative batch and use the exhaustive
// classifier below.
func (store *Store) MarkFirstByte(ctx context.Context, attempt Attempt) error {
	if store == nil || store.pool == nil || ctx == nil || attempt.validate() != nil {
		return ErrInvalidInput
	}
	if attempt.number == 1 {
		handled, err := store.markInitialFirstByte(ctx, attempt)
		if handled {
			return err
		}
	}
	return store.markFirstByteSlow(ctx, attempt)
}

// MarkFirstToken records the first protocol-validated generated-content
// boundary. Unlike MarkFirstByte it does not mutate the logical-request state:
// the client-visible streaming transition remains a transport/accounting
// concern, while this nullable timestamp is telemetry only.
func (store *Store) MarkFirstToken(ctx context.Context, attempt Attempt) error {
	if store == nil || store.pool == nil || ctx == nil || attempt.validate() != nil {
		return ErrInvalidInput
	}
	var firstTokenAt time.Time
	err := store.pool.QueryRow(ctx, `
		UPDATE upstream_attempts
		SET first_token_at = GREATEST(started_at, first_byte_at, statement_timestamp())
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND logical_request_id = $4 AND upstream_attempt_id = $5 AND attempt_number = $6
		  AND status = 'started' AND completed_at IS NULL
		  AND first_byte_at IS NOT NULL AND first_token_at IS NULL
		RETURNING first_token_at
	`, attempt.reservation.organizationID, attempt.reservation.applicationID,
		attempt.reservation.environmentID, attempt.reservation.logicalRequestID,
		attempt.attemptID, attempt.number).Scan(&firstTokenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidState
	}
	if err != nil {
		return mapWriteError("record first token", err)
	}
	if firstTokenAt.IsZero() {
		return ErrInvalidState
	}
	return nil
}

const markInitialAttemptFirstByteSQL = `
	UPDATE upstream_attempts
	SET first_byte_at = GREATEST(started_at, statement_timestamp())
	WHERE upstream_attempt_id = $1 AND logical_request_id = $2
	  AND attempt_number = 1 AND status = 'started' AND first_byte_at IS NULL
	RETURNING first_byte_at
`

const markInitialLogicalStreamingSQL = `
	UPDATE logical_requests
	SET status = 'streaming'
	WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
	  AND logical_request_id = $4 AND status = 'dispatched'
	RETURNING status
`

func (store *Store) markInitialFirstByte(ctx context.Context, attempt Attempt) (bool, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return true, persistenceFailure("begin first-byte record", err)
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
		lockReservationEntriesQuery(false),
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
		countAttemptUsageSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID, attempt.attemptID,
	)
	batch.Queue(markInitialAttemptFirstByteSQL, attempt.attemptID, expected.logicalRequestID)
	batch.Queue(
		markInitialLogicalStreamingSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID,
	)

	results := tx.SendBatch(ctx, batch)
	reservation, scanErr := scanLockedReservation(results.QueryRow(), expected)
	if scanErr != nil {
		return store.finishInitialFirstByteMismatch(results, scanErr)
	}
	logical, scanErr := scanLockedLogicalRequest(results.QueryRow(), expected)
	if scanErr != nil {
		return store.finishInitialFirstByteMismatch(results, scanErr)
	}
	attemptRows, queryErr := results.Query()
	if queryErr != nil {
		_ = results.Close()
		return true, persistenceFailure("lock upstream attempts", queryErr)
	}
	attempts, scanErr := scanStoredAttempts(attemptRows)
	if scanErr != nil {
		return store.finishInitialFirstByteMismatch(results, scanErr)
	}
	entryRows, queryErr := results.Query()
	if queryErr != nil {
		_ = results.Close()
		return true, persistenceFailure("lock quota reservation entries", queryErr)
	}
	entries, scanErr := scanLockedReservationEntries(entryRows, reservation)
	if scanErr != nil {
		return store.finishInitialFirstByteMismatch(results, scanErr)
	}
	leaseRows, queryErr := results.Query()
	if queryErr != nil {
		_ = results.Close()
		return true, persistenceFailure("lock concurrency leases", queryErr)
	}
	expectedBuckets, expectedIDs := expectedConcurrencyLeaseState(reservation, entries)
	leases, scanErr := scanLockedConcurrencyLeases(
		leaseRows, reservation, expectedBuckets, expectedIDs,
	)
	if scanErr != nil {
		return store.finishInitialFirstByteMismatch(results, scanErr)
	}
	quotaRows, queryErr := results.Query()
	if queryErr != nil {
		_ = results.Close()
		return true, persistenceFailure("lock upstream attempt quota entries", queryErr)
	}
	attemptQuota, scanErr := scanLockedAttemptQuotaEntries(quotaRows, reservation)
	if scanErr != nil {
		return store.finishInitialFirstByteMismatch(results, scanErr)
	}
	var usageCount int64
	if scanErr = results.QueryRow().Scan(&usageCount); scanErr != nil {
		_ = results.Close()
		return true, persistenceFailure("count started attempt usage", scanErr)
	}
	var firstByteAt time.Time
	attemptUpdateErr := results.QueryRow().Scan(&firstByteAt)
	var logicalStatus string
	logicalUpdateErr := results.QueryRow().Scan(&logicalStatus)
	if closeErr := results.Close(); closeErr != nil {
		return true, persistenceFailure("complete first-byte batch", closeErr)
	}
	if attemptUpdateErr != nil && !errors.Is(attemptUpdateErr, pgx.ErrNoRows) {
		return true, persistenceFailure("record upstream first byte", attemptUpdateErr)
	}
	if logicalUpdateErr != nil && !errors.Is(logicalUpdateErr, pgx.ErrNoRows) {
		return true, persistenceFailure("mark logical request streaming", logicalUpdateErr)
	}

	common := reservation.status == "pending" && logical.status == "dispatched" &&
		logicalStatus == "streaming" && !firstByteAt.IsZero() &&
		attemptUpdateErr == nil && logicalUpdateErr == nil && len(attempts) == 1
	if common {
		stored := attempts[0]
		common = stored.id == attempt.attemptID && stored.number == 1 &&
			stored.status == "started" && stored.firstByteAt == nil &&
			attemptPricingMatchesReservation(stored, reservation.Reservation) &&
			storedModelKeyMatches(stored, reservation.modelKey) &&
			storedInitialInputPreflightMatches(stored, reservation.inputPreflight) &&
			storedInitialRequestMeasurementsMatch(stored, reservation.requestMeasurements) &&
			pendingEntriesMatch(logical.status, reservation, entries, leases) &&
			initialAttemptEntriesUnchanged(entries) &&
			attemptQuotaEntriesUnsettled(attemptQuota) && usageCount == 0 &&
			attemptQuotaEntriesMatchReservation(reservation, stored, attemptQuota, entries)
	}
	if !common {
		return false, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return true, persistenceFailure("commit first-byte record", err)
	}
	return true, nil
}

func (store *Store) finishInitialFirstByteMismatch(
	results pgx.BatchResults,
	err error,
) (bool, error) {
	if closeErr := results.Close(); closeErr != nil {
		return true, persistenceFailure("complete first-byte batch", closeErr)
	}
	if errors.Is(err, ErrInvalidState) || errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return true, err
}

func initialAttemptEntriesUnchanged(entries []lockedEntry) bool {
	for _, entry := range entries {
		if entry.originAttemptNumber != 1 ||
			entry.reservedUnits != entry.initialReservedUnits ||
			entry.settledUnits != 0 || entry.releasedUnits != 0 {
			return false
		}
	}
	return true
}

func (store *Store) markFirstByteSlow(ctx context.Context, attempt Attempt) error {
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
		!storedInitialInputPreflightMatches(stored, reservation.inputPreflight) ||
		!storedInitialRequestMeasurementsMatch(stored, reservation.requestMeasurements)) {
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
// any upstream dispatch and do not own concurrency capacity. Separating this
// queue lane from reconciliation and concurrency recovery keeps multi-replica
// workers from repeatedly selecting work another lane owns.
func (store *Store) ReleaseExpiredUndispatchedBatch(ctx context.Context, limit int) (int64, error) {
	return store.expirePendingBatch(ctx, limit, pendingExpiryUndispatched)
}

// ReconcilePendingUsageBatch conservatively settles expired dispatched
// non-concurrency reservations according to the configured unknown-usage
// policy, preventing client disconnects from bypassing hard budgets.
func (store *Store) ReconcilePendingUsageBatch(ctx context.Context, limit int) (int64, error) {
	return store.expirePendingBatch(ctx, limit, pendingExpiryDispatched)
}

// ReleaseExpiredConcurrencyLeasesBatch recovers expired reservations that own
// concurrency capacity. The reservation, bucket entries, attempt accounting,
// and every lease are finalized in the same transaction; the job never frees
// a lease independently of the durable reservation lifecycle.
func (store *Store) ReleaseExpiredConcurrencyLeasesBatch(ctx context.Context, limit int) (int64, error) {
	return store.expirePendingBatch(ctx, limit, pendingExpiryConcurrency)
}

type pendingExpiryMode string

const (
	pendingExpiryAny          pendingExpiryMode = "any"
	pendingExpiryUndispatched pendingExpiryMode = "undispatched"
	pendingExpiryDispatched   pendingExpiryMode = "dispatched"
	pendingExpiryConcurrency  pendingExpiryMode = "concurrency"
)

func (store *Store) expirePendingBatch(ctx context.Context, limit int, mode pendingExpiryMode) (int64, error) {
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil || limit < 1 || limit > maximumExpiryBatch {
		return 0, ErrInvalidInput
	}
	if mode != pendingExpiryAny && mode != pendingExpiryUndispatched &&
		mode != pendingExpiryDispatched && mode != pendingExpiryConcurrency {
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
		SELECT reservation.organization_id, reservation.application_id,
		       reservation.environment_id, reservation.logical_request_id,
		       reservation.quota_reservation_id, reservation.idempotency_key,
		       reservation.expires_at
		FROM quota_reservations AS reservation
		WHERE reservation.status = 'pending' AND reservation.expires_at <= $1
		  AND (
		    $2 = 'any'
		    OR (
		      $2 = 'concurrency' AND EXISTS (
		          SELECT 1
		          FROM quota_reservation_entries AS entry
		          JOIN quota_buckets AS bucket
		            ON bucket.organization_id = entry.organization_id
		           AND bucket.application_id = entry.application_id
		           AND bucket.environment_id = entry.environment_id
		           AND bucket.quota_bucket_id = entry.quota_bucket_id
		          WHERE entry.organization_id = reservation.organization_id
		            AND entry.application_id = reservation.application_id
		            AND entry.environment_id = reservation.environment_id
		            AND entry.quota_reservation_id = reservation.quota_reservation_id
		            AND bucket.algorithm = 'concurrency'
		      )
		    )
		    OR (
		      $2 IN ('undispatched', 'dispatched')
		      AND NOT EXISTS (
		        SELECT 1
		        FROM quota_reservation_entries AS entry
		        JOIN quota_buckets AS bucket
		          ON bucket.organization_id = entry.organization_id
		         AND bucket.application_id = entry.application_id
		         AND bucket.environment_id = entry.environment_id
		         AND bucket.quota_bucket_id = entry.quota_bucket_id
		        WHERE entry.organization_id = reservation.organization_id
		          AND entry.application_id = reservation.application_id
		          AND entry.environment_id = reservation.environment_id
		          AND entry.quota_reservation_id = reservation.quota_reservation_id
		          AND bucket.algorithm = 'concurrency'
		      )
		      AND ($2 = 'dispatched') = EXISTS (
		        SELECT 1 FROM upstream_attempts AS attempt
		        WHERE attempt.organization_id = reservation.organization_id
		          AND attempt.application_id = reservation.application_id
		          AND attempt.environment_id = reservation.environment_id
		          AND attempt.logical_request_id = reservation.logical_request_id
		      )
		    )
		  )
		ORDER BY reservation.expires_at, reservation.quota_reservation_id
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

const lockQuotaReservationSQL = `
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
`

func lockReservation(ctx context.Context, tx pgx.Tx, expected Reservation) (lockedReservation, error) {
	return scanLockedReservation(tx.QueryRow(
		ctx, lockQuotaReservationSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID, expected.reservationID,
	), expected)
}

func scanLockedReservation(row pgx.Row, expected Reservation) (lockedReservation, error) {
	var result lockedReservation
	err := row.Scan(
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
	result.entries = append([]reservationEntry(nil), expected.entries...)
	result.routeKey = expected.routeKey
	result.upstreamKey = expected.upstreamKey
	result.modelKey = expected.modelKey
	result.physicalModel = expected.physicalModel
	result.protocol = expected.protocol
	result.pricing = expected.pricing
	result.inputPreflight = cloneInputPreflightBinding(expected.inputPreflight)
	result.requestMeasurements = cloneRequestMeasurementBinding(expected.requestMeasurements)
	result.retryPlan = cloneReservationRetryPlan(expected.retryPlan)
	result.windowResetAt = expected.windowResetAt
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

const lockLogicalRequestSQL = `
	SELECT status, failure_code, protocol, config_revision_id,
	       trusted_decision_fingerprint, application_user_id, installation_id,
	       session_grant_id, feature_key, requested_at
	FROM logical_requests
	WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
	  AND logical_request_id = $4
	FOR UPDATE
`

func lockLogicalRequest(ctx context.Context, tx pgx.Tx, expected Reservation) (lockedLogical, error) {
	return scanLockedLogicalRequest(tx.QueryRow(
		ctx, lockLogicalRequestSQL,
		expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID,
	), expected)
}

func scanLockedLogicalRequest(row pgx.Row, expected Reservation) (lockedLogical, error) {
	var result lockedLogical
	err := row.Scan(
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
	id                               string
	number                           int32
	routeKey                         string
	upstreamKey                      string
	physicalModel                    *string
	modelKey                         *string
	status                           string
	firstByteAt                      *time.Time
	completedAt                      *time.Time
	httpStatus                       *int32
	failureCode                      *string
	billedCost                       *int64
	currency                         *string
	priceRevision                    *string
	pricingSource                    *string
	costConfidence                   *string
	attemptDecisionBindingVersion    int16
	attemptDecisionSHA256            []byte
	perRequestOutputTokenBound       *int64
	inputAccountingBindingVersion    int16
	inputAccountingMethod            *string
	inputAccountingProfileID         *string
	inputAccountingProfileDigest     []byte
	rewrittenBodySHA256              []byte
	inputTokenBound                  *int64
	outputTokenBound                 *int64
	totalTokenBound                  *int64
	requestMeasurementBindingVersion int16
	requestMeasurementSHA256         []byte
	measuredRequestBytes             *int64
	measuredImageUnits               *int64
	measuredToolCalls                *int64
}

func initialCostConfidence(pricing selectedPricing) string {
	if !pricing.present() {
		return ""
	}
	return UnknownCostConfidence
}

func settlementCostValues(pricing selectedPricing, cost Cost) (billed any, confidence any) {
	if cost.Known {
		return cost.NanoUSD, cost.Confidence
	}
	if !pricing.present() {
		return nil, nil
	}
	return nil, UnknownCostConfidence
}

func (attempt storedAttempt) selectedPricing() (selectedPricing, error) {
	selectionAbsent := attempt.currency == nil && attempt.priceRevision == nil && attempt.pricingSource == nil
	if selectionAbsent {
		if attempt.billedCost == nil && attempt.costConfidence == nil {
			return selectedPricing{}, nil
		}
		if attempt.billedCost == nil || *attempt.billedCost < 0 || attempt.costConfidence == nil ||
			*attempt.costConfidence != ProviderReportedCostConfidence {
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
	case CalculatedCostConfidence, ProviderReportedCostConfidence:
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
		       input_token_bound, output_token_bound, total_token_bound,
		       request_measurement_binding_version, request_measurement_sha256,
		       measured_request_bytes, measured_image_units, measured_tool_calls
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
		&result.requestMeasurementBindingVersion, &result.requestMeasurementSHA256,
		&result.measuredRequestBytes, &result.measuredImageUnits, &result.measuredToolCalls,
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

type lockedEntry struct {
	id                   string
	bucketID             string
	limitPlanKey         string
	ruleKey              string
	metric               string
	algorithm            string
	costRetryTreatment   string
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

const lockReservationEntriesSQL = `
	SELECT entry.quota_reservation_entry_id, entry.quota_bucket_id,
	       bucket.limit_plan_key, bucket.rule_key, bucket.metric,
	       bucket.algorithm, bucket.window_key, bucket.scope_type,
	       bucket.scope_dimensions, bucket.scope_key,
	       entry.origin_attempt_number,
	       entry.initial_reserved_units, entry.reserved_units,
	       entry.settled_units, entry.released_units,
	       entry.cost_retry_treatment,
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
`

func lockReservationEntriesQuery(lockBuckets bool) string {
	if lockBuckets {
		return lockReservationEntriesSQL + " FOR UPDATE OF entry, bucket"
	}
	return lockReservationEntriesSQL + " FOR UPDATE OF entry"
}

func lockEntriesWithScope(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	lockBuckets bool,
) ([]lockedEntry, error) {
	rows, err := tx.Query(ctx, lockReservationEntriesQuery(lockBuckets),
		reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.reservationID)
	if err != nil {
		return nil, persistenceFailure("lock quota reservation entries", err)
	}
	return scanLockedReservationEntries(rows, reservation)
}

func scanLockedReservationEntries(rows pgx.Rows, reservation lockedReservation) ([]lockedEntry, error) {
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
			&entry.settledUnits, &entry.releasedUnits, &entry.costRetryTreatment,
			&entry.bucketUsed,
			&entry.bucketReserved, &entry.hardMaximum, &entry.available,
			&entry.refillNumerator, &entry.refillDenominator, &entry.refilledAt,
			&entry.version,
		); err != nil {
			return nil, persistenceFailure("scan quota reservation entry", err)
		}
		var treatmentOK bool
		entry.costRetryTreatment, treatmentOK = canonicalStoredCostRetryTreatment(
			entry.metric, entry.costRetryTreatment,
		)
		canonicalDimensions, dimensionsErr := canonicalScopeDimensions(entry.scopeDimensions)
		if id.Validate(entry.id, id.QuotaEntry) != nil || id.Validate(entry.bucketID, id.QuotaBucket) != nil ||
			dimensionsErr != nil || !slicesEqual(canonicalDimensions, entry.scopeDimensions) ||
			!identifierPattern.MatchString(entry.limitPlanKey) ||
			entry.ruleKey == "" || entry.scopeKey == "" ||
			entry.originAttemptNumber < 1 || entry.originAttemptNumber > maximumAttemptsPerRequest ||
			entry.reservedUnits < 0 ||
			!treatmentOK ||
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
				entry.costRetryTreatment != expected.costRetryTreatment ||
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

const lockConcurrencyLeasesSQL = `
	SELECT concurrency_lease_id, organization_id, application_id,
	       environment_id, quota_bucket_id, logical_request_id,
	       acquired_at, expires_at, released_at
	FROM concurrency_leases
	WHERE environment_id = $1 AND logical_request_id = $2
	ORDER BY concurrency_lease_id COLLATE "C"
	FOR UPDATE
`

// lockConcurrencyLeases is always called after lockEntries, and acquires
// lease rows in their globally stable identifier order.
func lockConcurrencyLeases(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	entries []lockedEntry,
) ([]lockedConcurrencyLease, error) {
	expectedBuckets, expectedIDs := expectedConcurrencyLeaseState(reservation, entries)
	rows, err := tx.Query(ctx, lockConcurrencyLeasesSQL,
		reservation.environmentID, reservation.logicalRequestID)
	if err != nil {
		return nil, persistenceFailure("lock concurrency leases", err)
	}
	return scanLockedConcurrencyLeases(rows, reservation, expectedBuckets, expectedIDs)
}

func expectedConcurrencyLeaseState(
	reservation lockedReservation,
	entries []lockedEntry,
) (map[string]struct{}, map[string]string) {
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
	return expectedBuckets, expectedIDs
}

func scanLockedConcurrencyLeases(
	rows pgx.Rows,
	reservation lockedReservation,
	expectedBuckets map[string]struct{},
	expectedIDs map[string]string,
) ([]lockedConcurrencyLease, error) {
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
	// Preserve all historical usage-ID generation sequences. A known cost
	// appends exactly one new identifier after existing records. Calculated cost
	// remains bound to provider token usage and a configured catalog, while an
	// explicitly trusted provider report is independent of both.
	if cost.Known {
		if cost.validate() != nil ||
			cost.Confidence == CalculatedCostConfidence &&
				(!usage.Known || !pricing.present() || pricing.validate() != nil) {
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

func costUsageProvenanceKey(attemptID string, cost Cost) string {
	switch cost.Confidence {
	case CalculatedCostConfidence:
		return configuredCostProvenanceKey(attemptID)
	case ProviderReportedCostConfidence:
		return providerUsageProvenanceKey(attemptID, CostNanoUSDMetric)
	default:
		return ""
	}
}

type costUsageAttribution struct {
	currency      *string
	priceRevision *string
	pricingSource *string
}

func settlementCostUsageAttribution(pricing selectedPricing, cost Cost) costUsageAttribution {
	if cost.Confidence == ProviderReportedCostConfidence {
		currency, source := cost.Currency, cost.Source
		return costUsageAttribution{currency: &currency, pricingSource: &source}
	}
	if !pricing.present() {
		return costUsageAttribution{}
	}
	currency, revision, source := pricing.currency, pricing.revision, pricing.source
	return costUsageAttribution{
		currency: &currency, priceRevision: &revision, pricingSource: &source,
	}
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
		if outcome.Cost.Known {
			if outcome.Cost.Confidence != ProviderReportedCostConfidence || stored.billedCost == nil ||
				*stored.billedCost != outcome.Cost.NanoUSD || stored.costConfidence == nil ||
				*stored.costConfidence != outcome.Cost.Confidence {
				return false
			}
		} else if stored.billedCost != nil || stored.costConfidence != nil || outcome.Cost != (Cost{}) {
			return false
		}
	} else if outcome.Cost.Known {
		if stored.billedCost == nil || *stored.billedCost != outcome.Cost.NanoUSD ||
			stored.costConfidence == nil || *stored.costConfidence != outcome.Cost.Confidence {
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
