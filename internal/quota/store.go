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
}

// Store persists quota and request lifecycle state. No method accepts an
// upstream callback, response body, or transport, which makes it structurally
// impossible for this package to retain a transaction during upstream I/O.
type Store struct {
	pool           *pgxpool.Pool
	reservationTTL time.Duration
	newID          identifierSource
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
	}, nil
}

type reserveIDs struct {
	reservation string
	buckets     []string
	entries     []string
}

func (store *Store) newReserveIDs(ruleCount int) (reserveIDs, error) {
	if ruleCount < 0 || ruleCount > maximumRulesPerRequest {
		return reserveIDs{}, ErrInvalidInput
	}
	result := reserveIDs{
		buckets: make([]string, ruleCount),
		entries: make([]string, ruleCount),
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
	return result, nil
}

type plannedBucket struct {
	rule          preparedRule
	period        calendarPeriod
	reservedUnits int64
	bucketID      string
	entryID       string
	locked        lockedBucket
}

// Reserve records one logical request and atomically reserves the trusted
// units in every applicable calendar bucket. Per-request-only decisions still
// create the durable logical-request and reservation lifecycle with no bucket
// entries. Quota denial is committed as a denied logical request but changes
// no bucket counters and creates neither a reservation nor an upstream attempt.
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

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reservation{}, persistenceFailure("begin quota reservation", err)
	}
	defer rollback(tx)

	requestedAt, err := transactionTime(ctx, tx)
	if err != nil {
		return Reservation{}, err
	}
	plans, err := plannedBucketsAt(prepared, requestedAt)
	if err != nil {
		return Reservation{}, err
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

	identifiers, err := store.newReserveIDs(len(plans))
	if err != nil {
		return Reservation{}, err
	}
	for index := range plans {
		plans[index].bucketID = identifiers.buckets[index]
		plans[index].entryID = identifiers.entries[index]
		plan := &plans[index]
		if _, err := tx.Exec(ctx, `
			INSERT INTO quota_buckets (
				quota_bucket_id, organization_id, application_id, environment_id,
				limit_plan_key, rule_key, metric, scope_type, scope_dimensions,
				scope_key, algorithm, window_key, hard_maximum,
				used_units, reserved_units, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9::text[], $10, $11, $12,
				$13, 0, 0, $14, $14
			)
			ON CONFLICT ON CONSTRAINT quota_buckets_identity_key DO NOTHING
		`, plan.bucketID, prepared.OrganizationID, prepared.ApplicationID,
			prepared.EnvironmentID, prepared.LimitPlanKey, plan.rule.ruleKey,
			plan.rule.Metric, plan.rule.scopeType, plan.rule.scopeDimensions,
			plan.rule.scopeKey, plan.rule.Algorithm, plan.period.key,
			plan.rule.Maximum, requestedAt); err != nil {
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
	exceeded := make([]int, 0, len(plans))
	occupancies := make([]int64, len(plans))
	for index := range plans {
		plan := &plans[index]
		bucket := plan.locked
		if bucket.hardMaximum == nil || bucket.used < 0 || bucket.reserved < 0 ||
			plan.reservedUnits <= 0 ||
			bucket.used > math.MaxInt64-bucket.reserved {
			return Reservation{}, ErrInvalidState
		}
		occupancy := bucket.used + bucket.reserved
		occupancies[index] = occupancy
		if plan.rule.Maximum < occupancy || plan.rule.Maximum-occupancy < plan.reservedUnits {
			exceeded = append(exceeded, index)
		}
	}
	if len(exceeded) != 0 {
		for index := range plans {
			plan := &plans[index]
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
		command, updateErr := tx.Exec(ctx, `
			UPDATE logical_requests
			SET status = 'denied', completed_at = GREATEST(requested_at, $2),
			    failure_code = 'quota_exceeded'
			WHERE logical_request_id = $1 AND status = 'reserved'
		`, logicalRequestID, decisionAt)
		if updateErr != nil {
			return Reservation{}, persistenceFailure("record quota denial", updateErr)
		}
		if command.RowsAffected() != 1 {
			return Reservation{}, ErrInvalidState
		}
		if err := tx.Commit(ctx); err != nil {
			return Reservation{}, persistenceFailure("commit quota denial", err)
		}
		return Reservation{}, exceededError(logicalRequestID, plans, exceeded)
	}

	for index := range plans {
		plan := &plans[index]
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
			  AND $3::bigint > 0
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

	if _, err := tx.Exec(ctx, `
		INSERT INTO quota_reservations (
			quota_reservation_id, organization_id, application_id, environment_id,
			logical_request_id, idempotency_key, status, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)
	`, identifiers.reservation, prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, logicalRequestID, fingerprint, decisionAt, expiresAt); err != nil {
		return Reservation{}, mapWriteError("insert quota reservation", err)
	}
	for index := range plans {
		plan := &plans[index]
		if _, err := tx.Exec(ctx, `
			INSERT INTO quota_reservation_entries (
				quota_reservation_entry_id, organization_id, application_id,
				environment_id, quota_reservation_id, quota_bucket_id,
				reserved_units, settled_units, released_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 0)
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
		pricing:       pricingForRequest(prepared),
		windowResetAt: maximumResetAt(entries), expiresAt: expiresAt,
	}, nil
}

// loadExistingReserve implements logical-request idempotency after the
// INSERT ... ON CONFLICT statement has waited for the winning transaction to
// commit. A caller may replay only the exact same trusted request. The client
// correlation hint is compared as durable data, never used as the lookup key.
//
// All lifecycle transactions take locks in this order for a request that has
// a reservation: quota_reservations, logical_requests, upstream_attempts, then
// quota_reservation_entries/quota_buckets. Taking the reservation lock before
// reading the logical row keeps later READ COMMITTED statements on one stable
// lifecycle state without reversing that order. Denied requests have no
// reservation and are immutable, so they lock logical_requests first.
func loadExistingReserve(ctx context.Context, tx pgx.Tx, prepared preparedRequest, fingerprint string) (Reservation, error) {
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
	plans, err := plannedBucketsAt(prepared, logical.requestedAt.UTC())
	if err != nil {
		return Reservation{}, ErrInvalidState
	}

	if logical.status == "denied" {
		if reservationErr == nil || len(plans) == 0 {
			return Reservation{}, ErrInvalidState
		}
		if logical.failureCode == nil || *logical.failureCode != "quota_exceeded" {
			return Reservation{}, ErrInvalidState
		}
		if err := lockPlannedBuckets(ctx, tx, prepared, plans); err != nil {
			return Reservation{}, err
		}
		exceeded := make([]int, 0, len(plans))
		for index := range plans {
			bucket := plans[index].locked
			if bucket.hardMaximum == nil || bucket.used < 0 || bucket.reserved < 0 ||
				plans[index].reservedUnits <= 0 ||
				bucket.used > math.MaxInt64-bucket.reserved {
				return Reservation{}, ErrInvalidState
			}
			occupancy := bucket.used + bucket.reserved
			if plans[index].rule.Maximum < occupancy ||
				plans[index].rule.Maximum-occupancy < plans[index].reservedUnits {
				exceeded = append(exceeded, index)
			}
		}
		if len(exceeded) == 0 {
			exceeded = make([]int, len(plans))
			for index := range plans {
				exceeded[index] = index
			}
		}
		return Reservation{}, exceededError(prepared.LogicalRequestID.String(), plans, exceeded)
	}
	if reservationErr != nil {
		return Reservation{}, ErrInvalidState
	}

	if len(plans) == 0 {
		return loadExistingEntrylessReservation(ctx, tx, prepared, fingerprint, logical.status, lockedReservationID)
	}

	type existingReservation struct {
		organizationID, applicationID, environmentID string
		logicalRequestID, reservationID, idempotency string
		status, entryID, bucketID                    string
		expiresAt                                    time.Time
		reservedUnits, settledUnits, releasedUnits   int64
		bucketOrganizationID, bucketApplicationID    string
		limitPlanKey, ruleKey, metric, scopeType     string
		scopeDimensions                              []string
		scopeKey, algorithm, windowKey               string
	}
	rows, err := tx.Query(ctx, `
		SELECT reservation.organization_id, reservation.application_id,
		       reservation.environment_id, reservation.logical_request_id,
		       reservation.quota_reservation_id, reservation.idempotency_key,
		       reservation.status, reservation.expires_at,
		       entry.quota_reservation_entry_id, entry.quota_bucket_id,
		       entry.reserved_units, entry.settled_units, entry.released_units,
		       bucket.organization_id, bucket.application_id,
		       bucket.limit_plan_key, bucket.rule_key, bucket.metric,
		       bucket.scope_type, bucket.scope_dimensions, bucket.scope_key,
		       bucket.algorithm, bucket.window_key
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
	for index := range plans {
		planIndexes[plannedBucketIdentity(plans[index].rule.ruleKey, plans[index].rule.scopeKey)] = index
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
			&existing.reservedUnits, &existing.settledUnits, &existing.releasedUnits,
			&existing.bucketOrganizationID, &existing.bucketApplicationID,
			&existing.limitPlanKey, &existing.ruleKey, &existing.metric,
			&existing.scopeType, &existing.scopeDimensions, &existing.scopeKey,
			&existing.algorithm, &existing.windowKey,
		); err != nil {
			return Reservation{}, persistenceFailure("scan existing quota reservation", err)
		}
		planIndex, ok := planIndexes[plannedBucketIdentity(existing.ruleKey, existing.scopeKey)]
		if !ok || matchedPlans[planIndex] {
			return Reservation{}, ErrInvalidInput
		}
		plan := plans[planIndex]
		if existing.organizationID != prepared.OrganizationID ||
			existing.applicationID != prepared.ApplicationID ||
			existing.environmentID != prepared.EnvironmentID ||
			existing.logicalRequestID != prepared.LogicalRequestID.String() ||
			existing.idempotency != fingerprint ||
			existing.bucketOrganizationID != prepared.OrganizationID ||
			existing.bucketApplicationID != prepared.ApplicationID ||
			existing.limitPlanKey != prepared.LimitPlanKey ||
			existing.metric != plan.rule.Metric || existing.scopeType != plan.rule.scopeType ||
			!slicesEqual(existing.scopeDimensions, plan.rule.scopeDimensions) ||
			existing.algorithm != plan.rule.Algorithm || existing.windowKey != plan.period.key {
			return Reservation{}, ErrInvalidInput
		}
		if id.Validate(existing.reservationID, id.QuotaReservation) != nil ||
			id.Validate(existing.entryID, id.QuotaEntry) != nil ||
			id.Validate(existing.bucketID, id.QuotaBucket) != nil ||
			!existingReservationStateMatches(logical.status, existing.status,
				plan.rule.Metric, plan.reservedUnits, existing.reservedUnits,
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
		matchedPlans[planIndex] = true
		entries = append(entries, reservationEntry{
			bucketID: existing.bucketID, entryID: existing.entryID,
			metric: plan.rule.Metric, reservedUnits: plan.reservedUnits,
			resetAt: plan.period.end,
		})
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
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID:    prepared.EnvironmentID,
		logicalRequestID: prepared.LogicalRequestID.String(),
		reservationID:    reservationID, entries: entries, routeKey: prepared.RouteKey,
		upstreamKey: prepared.UpstreamKey, modelKey: prepared.ModelKey,
		physicalModel: prepared.PhysicalModel, pricing: pricingForRequest(prepared),
		windowResetAt: maximumResetAt(entries),
		expiresAt:     expiresAt,
	}, nil
}

func loadExistingEntrylessReservation(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedRequest,
	fingerprint string,
	logicalStatus string,
	lockedReservationID string,
) (Reservation, error) {
	type existingReservation struct {
		organizationID, applicationID, environmentID string
		logicalRequestID, reservationID, idempotency string
		status                                       string
		expiresAt                                    time.Time
		entryCount                                   int64
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
		           AND entry.quota_reservation_id = reservation.quota_reservation_id)
		FROM quota_reservations AS reservation
		WHERE reservation.logical_request_id = $1
		  AND reservation.quota_reservation_id = $2
	`, prepared.LogicalRequestID.String(), lockedReservationID).Scan(
		&existing.organizationID, &existing.applicationID, &existing.environmentID,
		&existing.logicalRequestID, &existing.reservationID, &existing.idempotency,
		&existing.status, &existing.expiresAt, &existing.entryCount,
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
		existing.reservationID != lockedReservationID || existing.idempotency != fingerprint {
		return Reservation{}, ErrInvalidInput
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
	if id.Validate(existing.reservationID, id.QuotaReservation) != nil ||
		existing.entryCount != 0 || !validLifecycle {
		return Reservation{}, ErrInvalidState
	}
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID: prepared.EnvironmentID, logicalRequestID: prepared.LogicalRequestID.String(),
		reservationID: existing.reservationID, routeKey: prepared.RouteKey,
		upstreamKey: prepared.UpstreamKey, modelKey: prepared.ModelKey,
		physicalModel: prepared.PhysicalModel, pricing: pricingForRequest(prepared),
		expiresAt: existing.expiresAt,
	}, nil
}

func existingReservationStateMatches(
	logicalStatus string,
	reservationStatus string,
	metric string,
	expected int64,
	reserved int64,
	settled int64,
	released int64,
) bool {
	if expected <= 0 || reserved != expected || settled < 0 || released < 0 ||
		settled > reserved || released > reserved-settled ||
		(metric != LogicalRequestsMetric && metric != OutputTokensMetric) ||
		(metric == LogicalRequestsMetric && reserved != 1) {
		return false
	}
	switch reservationStatus {
	case "pending":
		return settled == 0 && released == 0 &&
			(logicalStatus == "reserved" || logicalStatus == "dispatched" || logicalStatus == "streaming")
	case "settled":
		if logicalStatus != "succeeded" && logicalStatus != "failed" && logicalStatus != "cancelled" {
			return false
		}
		if metric == LogicalRequestsMetric || logicalStatus != "succeeded" {
			return settled == reserved && released == 0
		}
		return settled+released == reserved
	case "released", "expired":
		return settled == 0 && released == reserved && logicalStatus == "failed"
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
	id              string
	hardMaximum     *int64
	used            int64
	reserved        int64
	scopeType       string
	scopeDimensions []string
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
		period, err := calendarWindow(at, rule.Window)
		if err != nil {
			return nil, err
		}
		reservedUnits := rule.ReservedUnits
		if rule.Metric == LogicalRequestsMetric {
			reservedUnits = 1
		}
		if reservedUnits <= 0 {
			return nil, ErrInvalidInput
		}
		plans = append(plans, plannedBucket{rule: rule, period: period, reservedUnits: reservedUnits})
	}
	return plans, nil
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
		       hard_maximum, used_units, reserved_units,
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
		&result.hardMaximum, &result.used, &result.reserved,
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
		id.Validate(result.id, id.QuotaBucket) != nil {
		return lockedBucket{}, ErrInvalidState
	}
	return result, nil
}

func reservationEntries(plans []plannedBucket) []reservationEntry {
	entries := make([]reservationEntry, len(plans))
	for index := range plans {
		entries[index] = reservationEntry{
			bucketID:      plans[index].locked.id,
			entryID:       plans[index].entryID,
			metric:        plans[index].rule.Metric,
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
		if candidate.period.end.After(current.period.end) ||
			(candidate.period.end.Equal(current.period.end) &&
				(candidate.rule.ruleKey < current.rule.ruleKey ||
					(candidate.rule.ruleKey == current.rule.ruleKey &&
						candidate.rule.scopeKey < current.rule.scopeKey))) {
			selected = index
		}
	}
	plan := plans[selected]
	return &ExceededError{
		logicalRequestID: logicalRequestID,
		retryAt:          plan.period.end,
		maximum:          plan.rule.Maximum,
		used:             plan.locked.used,
		reserved:         plan.locked.reserved,
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
	existing, found, err := loadAttemptForUpdate(ctx, tx, reservation.logicalRequestID, 1)
	if err != nil {
		return Attempt{}, false, err
	}
	if found {
		if existing.routeKey != reservation.routeKey || existing.upstreamKey != reservation.upstreamKey ||
			existing.physicalModel == nil || *existing.physicalModel != reservation.physicalModel ||
			!attemptPricingMatchesReservation(existing, reservation) {
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO upstream_attempts (
			upstream_attempt_id, organization_id, application_id, environment_id,
			logical_request_id, attempt_number, route_key, upstream_key,
			physical_model, status, started_at, currency, price_revision,
			pricing_source, cost_confidence
		) VALUES (
			$1, $2, $3, $4, $5, 1, $6, $7, $8, 'started', $9,
			$10, $11, $12, $13
		)
	`, attemptID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		reservation.routeKey, reservation.upstreamKey, reservation.physicalModel,
		now, nullableString(reservation.pricing.currency),
		nullableString(reservation.pricing.revision), nullableString(reservation.pricing.source),
		nullableString(initialCostConfidence(reservation.pricing))); err != nil {
		return Attempt{}, false, mapWriteError("insert upstream attempt", err)
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
	stored, found, err := loadAttemptForUpdate(ctx, tx, attempt.reservation.logicalRequestID, 1)
	if err != nil {
		return err
	}
	if !found || stored.id != attempt.attemptID {
		return ErrNotFound
	}
	if !attemptPricingMatchesReservation(stored, reservation.Reservation) {
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

// Settle consumes exactly one logical-request unit for every attempt that was
// committed by BeginAttempt, including failed, timed-out, and cancelled work.
func (store *Store) Settle(ctx context.Context, attempt Attempt, outcome Outcome) error {
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
	if reservation.status == "settled" {
		matches, matchErr := terminalSettlementMatches(ctx, tx, reservation, storedAttempt, outcome)
		if matchErr != nil {
			return matchErr
		}
		if matches {
			return nil
		}
		return ErrFinalized
	}
	if !attemptPricingMatchesReservation(storedAttempt, reservation.Reservation) {
		return ErrInvalidState
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
	_, hasOutputReservation, err := lockedOutputReservationUnits(entries)
	if err != nil {
		return err
	}
	usageIDs, err := store.newSettlementUsageIDs(
		outcome.Usage, hasOutputReservation, outcome.Cost, reservation.pricing,
	)
	if err != nil {
		return err
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := settleLocked(ctx, tx, reservation, logical, storedAttempt, entries, outcome, usageIDs, now); err != nil {
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
	_, attemptExists, err := loadAttemptForUpdate(ctx, tx, reservation.logicalRequestID, 1)
	if err != nil {
		return err
	}
	if lockedReservation.status == "released" {
		if !attemptExists && logical.status == "failed" && logical.failureCode != nil && *logical.failureCode == failureCode {
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
	entries, err := lockEntries(ctx, tx, lockedReservation)
	if err != nil {
		return err
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := releaseLocked(ctx, tx, lockedReservation, logical, entries, "released", failureCode, now); err != nil {
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
	if store == nil || store.pool == nil || store.newID == nil || ctx == nil || limit < 1 || limit > maximumExpiryBatch {
		return 0, ErrInvalidInput
	}
	var processed int64
	for processed < int64(limit) {
		didProcess, err := store.expireOne(ctx)
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

func (store *Store) expireOne(ctx context.Context) (bool, error) {
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
	err = tx.QueryRow(ctx, `
		SELECT organization_id, application_id, environment_id,
		       logical_request_id, quota_reservation_id, expires_at
		FROM quota_reservations
		WHERE status = 'pending' AND expires_at <= $1
		ORDER BY expires_at, quota_reservation_id
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`, now).Scan(
		&selected.organizationID, &selected.applicationID, &selected.environmentID,
		&selected.logicalRequestID, &selected.reservationID, &selected.expiresAt,
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
	storedAttempt, attemptExists, err := loadOnlyAttemptForUpdate(ctx, tx, selected.logicalRequestID)
	if err != nil {
		return false, err
	}
	entries, err := lockEntries(ctx, tx, lockedReservation)
	if err != nil {
		return false, err
	}
	var usageIDs settlementUsageIDs
	var recoveredOutcome Outcome
	if attemptExists {
		if storedAttempt.status != "started" ||
			(logical.status != "dispatched" && logical.status != "streaming") {
			return false, ErrInvalidState
		}
		pricing, pricingErr := storedAttempt.selectedPricing()
		if pricingErr != nil {
			return false, pricingErr
		}
		lockedReservation.pricing = pricing
		recoveredOutcome, err = normalizeOutcomeForPricing(Outcome{
			Status: AttemptTimedOut, FailureCode: expiryFailureCode,
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}, pricing)
		if err != nil {
			return false, err
		}
		_, hasOutputReservation, outputErr := lockedOutputReservationUnits(entries)
		if outputErr != nil {
			return false, outputErr
		}
		generatedUsageIDs, idErr := store.newSettlementUsageIDs(
			recoveredOutcome.Usage, hasOutputReservation, recoveredOutcome.Cost,
			lockedReservation.pricing,
		)
		if idErr != nil {
			return false, idErr
		}
		usageIDs = generatedUsageIDs
	} else if logical.status != "reserved" {
		return false, ErrInvalidState
	}
	now, err = statementTime(ctx, tx)
	if err != nil {
		return false, err
	}
	if attemptExists {
		if err := settleLocked(ctx, tx, lockedReservation, logical, storedAttempt, entries, recoveredOutcome, usageIDs, now); err != nil {
			return false, err
		}
	} else {
		if err := releaseLocked(ctx, tx, lockedReservation, logical, entries, "expired", expiryFailureCode, now); err != nil {
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
	status    string
	expiresAt time.Time
}

func lockReservation(ctx context.Context, tx pgx.Tx, expected Reservation) (lockedReservation, error) {
	var result lockedReservation
	err := tx.QueryRow(ctx, `
		SELECT organization_id, application_id, environment_id,
		       logical_request_id, quota_reservation_id, status, expires_at
		FROM quota_reservations
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND logical_request_id = $4 AND quota_reservation_id = $5
		FOR UPDATE
	`, expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID, expected.reservationID).Scan(
		&result.organizationID, &result.applicationID, &result.environmentID,
		&result.logicalRequestID, &result.reservationID, &result.status, &result.expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedReservation{}, ErrNotFound
	}
	if err != nil {
		return lockedReservation{}, persistenceFailure("lock quota reservation", err)
	}
	result.Reservation.entries = append([]reservationEntry(nil), expected.entries...)
	result.Reservation.routeKey = expected.routeKey
	result.Reservation.upstreamKey = expected.upstreamKey
	result.Reservation.modelKey = expected.modelKey
	result.Reservation.physicalModel = expected.physicalModel
	result.Reservation.pricing = expected.pricing
	result.Reservation.windowResetAt = expected.windowResetAt
	return result, nil
}

type lockedLogical struct {
	status      string
	failureCode *string
}

func lockLogicalRequest(ctx context.Context, tx pgx.Tx, expected Reservation) (lockedLogical, error) {
	var result lockedLogical
	err := tx.QueryRow(ctx, `
		SELECT status, failure_code
		FROM logical_requests
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
		  AND logical_request_id = $4
		FOR UPDATE
	`, expected.organizationID, expected.applicationID, expected.environmentID,
		expected.logicalRequestID).Scan(&result.status, &result.failureCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedLogical{}, ErrNotFound
	}
	if err != nil {
		return lockedLogical{}, persistenceFailure("lock logical request", err)
	}
	return result, nil
}

type storedAttempt struct {
	id             string
	number         int32
	routeKey       string
	upstreamKey    string
	physicalModel  *string
	status         string
	firstByteAt    *time.Time
	completedAt    *time.Time
	httpStatus     *int32
	failureCode    *string
	billedCost     *int64
	currency       *string
	priceRevision  *string
	pricingSource  *string
	costConfidence *string
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
		       physical_model, status, first_byte_at, completed_at,
		       http_status, failure_code, billed_cost_nano_usd, currency,
		       price_revision, pricing_source, cost_confidence
		FROM upstream_attempts
		WHERE logical_request_id = $1 AND attempt_number = $2
		FOR UPDATE
	`, logicalRequestID, number).Scan(
		&result.id, &result.number, &result.routeKey, &result.upstreamKey,
		&result.physicalModel, &result.status, &result.firstByteAt,
		&result.completedAt, &result.httpStatus, &result.failureCode,
		&result.billedCost, &result.currency, &result.priceRevision,
		&result.pricingSource, &result.costConfidence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedAttempt{}, false, nil
	}
	if err != nil {
		return storedAttempt{}, false, persistenceFailure("lock upstream attempt", err)
	}
	if id.Validate(result.id, id.UpstreamAttempt) != nil || result.number != number || result.validatePricing() != nil {
		return storedAttempt{}, false, ErrInvalidState
	}
	return result, true, nil
}

func loadOnlyAttemptForUpdate(ctx context.Context, tx pgx.Tx, logicalRequestID string) (storedAttempt, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT upstream_attempt_id, attempt_number, route_key, upstream_key,
		       physical_model, status, first_byte_at, completed_at,
		       http_status, failure_code, billed_cost_nano_usd, currency,
		       price_revision, pricing_source, cost_confidence
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
		&result.physicalModel, &result.status, &result.firstByteAt,
		&result.completedAt, &result.httpStatus, &result.failureCode,
		&result.billedCost, &result.currency, &result.priceRevision,
		&result.pricingSource, &result.costConfidence,
	); err != nil {
		return storedAttempt{}, false, persistenceFailure("scan recovered upstream attempt", err)
	}
	if rows.Next() || result.number != 1 || id.Validate(result.id, id.UpstreamAttempt) != nil || result.validatePricing() != nil {
		return storedAttempt{}, false, ErrInvalidState
	}
	if err := rows.Err(); err != nil {
		return storedAttempt{}, false, persistenceFailure("iterate recovered upstream attempts", err)
	}
	return result, true, nil
}

type lockedEntry struct {
	id             string
	bucketID       string
	metric         string
	reservedUnits  int64
	settledUnits   int64
	releasedUnits  int64
	bucketUsed     int64
	bucketReserved int64
	hardMaximum    *int64
}

func lockEntries(ctx context.Context, tx pgx.Tx, reservation lockedReservation) ([]lockedEntry, error) {
	rows, err := tx.Query(ctx, `
		SELECT entry.quota_reservation_entry_id, entry.quota_bucket_id,
		       bucket.metric,
		       entry.reserved_units, entry.settled_units, entry.released_units,
		       bucket.used_units, bucket.reserved_units, bucket.hard_maximum
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket
		  ON bucket.organization_id = entry.organization_id
		 AND bucket.application_id = entry.application_id
		 AND bucket.environment_id = entry.environment_id
		 AND bucket.quota_bucket_id = entry.quota_bucket_id
		WHERE entry.organization_id = $1 AND entry.application_id = $2
		  AND entry.environment_id = $3 AND entry.quota_reservation_id = $4
		ORDER BY bucket.quota_bucket_id COLLATE "C"
		FOR UPDATE OF entry, bucket
	`, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.reservationID)
	if err != nil {
		return nil, persistenceFailure("lock quota reservation entries", err)
	}
	defer rows.Close()
	entries := make([]lockedEntry, 0, len(reservation.entries))
	for rows.Next() {
		if len(entries) == maximumRulesPerRequest {
			return nil, ErrInvalidState
		}
		var entry lockedEntry
		if err := rows.Scan(
			&entry.id, &entry.bucketID, &entry.metric, &entry.reservedUnits,
			&entry.settledUnits, &entry.releasedUnits, &entry.bucketUsed,
			&entry.bucketReserved, &entry.hardMaximum,
		); err != nil {
			return nil, persistenceFailure("scan quota reservation entry", err)
		}
		if id.Validate(entry.id, id.QuotaEntry) != nil || id.Validate(entry.bucketID, id.QuotaBucket) != nil ||
			(entry.metric != LogicalRequestsMetric && entry.metric != OutputTokensMetric) ||
			(len(entries) > 0 && entries[len(entries)-1].bucketID >= entry.bucketID) {
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
		if len(entries) != len(reservation.entries) {
			return nil, ErrInvalidState
		}
		for index := range entries {
			if entries[index].id != reservation.entries[index].entryID ||
				entries[index].bucketID != reservation.entries[index].bucketID ||
				entries[index].metric != reservation.entries[index].metric ||
				entries[index].reservedUnits != reservation.entries[index].reservedUnits {
				return nil, ErrInvalidState
			}
		}
	}
	return entries, nil
}

type settlementUsageIDs struct {
	logical        string
	providerInput  string
	providerOutput string
	providerTotal  string
	unknownOutput  string
	cost           string
}

func (store *Store) newSettlementUsageIDs(
	usage Usage,
	hasOutputReservation bool,
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
	} else if hasOutputReservation {
		if err := generate(&result.unknownOutput); err != nil {
			return settlementUsageIDs{}, err
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

func lockedOutputReservationUnits(entries []lockedEntry) (int64, bool, error) {
	var units int64
	found := false
	for _, entry := range entries {
		if entry.metric != OutputTokensMetric {
			continue
		}
		if entry.reservedUnits <= 0 || found && entry.reservedUnits != units {
			return 0, false, ErrInvalidState
		}
		units = entry.reservedUnits
		found = true
	}
	return units, found, nil
}

func reservationOutputReservationUnits(entries []reservationEntry) (int64, bool, error) {
	var units int64
	found := false
	for _, entry := range entries {
		if entry.metric != OutputTokensMetric {
			continue
		}
		if entry.reservedUnits <= 0 || found && entry.reservedUnits != units {
			return 0, false, ErrInvalidState
		}
		units = entry.reservedUnits
		found = true
	}
	return units, found, nil
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
			{id: identifiers.providerInput, metric: "input_tokens", units: outcome.Usage.InputTokens},
			{id: identifiers.providerOutput, metric: OutputTokensMetric, units: outcome.Usage.OutputTokens},
			{id: identifiers.providerTotal, metric: "total_tokens", units: outcome.Usage.TotalTokens},
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
		outputUnits, hasOutputReservation, outputErr := lockedOutputReservationUnits(entries)
		if outputErr != nil {
			return outputErr
		}
		if hasOutputReservation {
			if err := insert(
				identifiers.unknownOutput, attempt.id, OutputTokensMetric, outputUnits,
				priceFields{}, UnknownCostConfidence,
				unknownOutputUsageProvenanceKey(reservation.reservationID),
			); err != nil {
				return err
			}
		} else if identifiers.unknownOutput != "" {
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
	outputUnits, hasOutputReservation, err := reservationOutputReservationUnits(reservation.entries)
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
			{metric: "input_tokens", units: outcome.Usage.InputTokens},
			{metric: OutputTokensMetric, units: outcome.Usage.OutputTokens},
			{metric: "total_tokens", units: outcome.Usage.TotalTokens},
		} {
			expected[providerUsageProvenanceKey(attempt.id, record.metric)] = expectedUsage{
				attemptID: &attemptID, metric: record.metric, units: record.units, confidence: "reported",
			}
		}
	} else if hasOutputReservation {
		attemptID := attempt.id
		expected[unknownOutputUsageProvenanceKey(reservation.reservationID)] = expectedUsage{
			attemptID: &attemptID, metric: OutputTokensMetric, units: outputUnits, confidence: "unknown",
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

func settleLocked(
	ctx context.Context,
	tx pgx.Tx,
	reservation lockedReservation,
	logical lockedLogical,
	attempt storedAttempt,
	entries []lockedEntry,
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
	settledUnits := make([]int64, len(entries))
	releasedUnits := make([]int64, len(entries))
	for _, entry := range entries {
		if entry.reservedUnits <= 0 || entry.settledUnits != 0 || entry.releasedUnits != 0 ||
			entry.bucketReserved < entry.reservedUnits || entry.hardMaximum == nil ||
			entry.bucketUsed < 0 || entry.metric != LogicalRequestsMetric && entry.metric != OutputTokensMetric ||
			(entry.metric == LogicalRequestsMetric && entry.reservedUnits != 1) {
			return ErrInvalidState
		}
	}
	for index, entry := range entries {
		settled := entry.reservedUnits
		if entry.metric == OutputTokensMetric && outcome.Status == AttemptSucceeded && outcome.Usage.Known {
			settled = outcome.Usage.OutputTokens
			if settled > entry.reservedUnits {
				return ErrInvalidInput
			}
		}
		if settled < 0 || entry.bucketUsed > *entry.hardMaximum ||
			settled > *entry.hardMaximum-entry.bucketUsed {
			return ErrInvalidState
		}
		settledUnits[index] = settled
		releasedUnits[index] = entry.reservedUnits - settled
	}
	if attempt.firstByteAt != nil && attempt.firstByteAt.After(now) {
		now = attempt.firstByteAt.UTC()
	}
	for index, entry := range entries {
		command, err := tx.Exec(ctx, `
			UPDATE quota_buckets
			SET used_units = used_units + $2::bigint,
			    reserved_units = reserved_units - $3::bigint,
			    version = version + 1,
			    updated_at = GREATEST(updated_at, $4)
			WHERE quota_bucket_id = $1
			  AND $2::bigint >= 0 AND $3::bigint > 0
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

func releaseLocked(ctx context.Context, tx pgx.Tx, reservation lockedReservation, logical lockedLogical, entries []lockedEntry, reservationStatus, failureCode string, now time.Time) error {
	if reservation.status != "pending" || logical.status != "reserved" ||
		len(entries) > maximumRulesPerRequest {
		return ErrInvalidState
	}
	for _, entry := range entries {
		if entry.reservedUnits <= 0 || entry.settledUnits != 0 || entry.releasedUnits != 0 ||
			entry.bucketReserved < entry.reservedUnits ||
			(entry.metric != LogicalRequestsMetric && entry.metric != OutputTokensMetric) ||
			(entry.metric == LogicalRequestsMetric && entry.reservedUnits != 1) {
			return ErrInvalidState
		}
	}
	for _, entry := range entries {
		command, err := tx.Exec(ctx, `
			UPDATE quota_buckets
			SET reserved_units = reserved_units - $2::bigint,
			    version = version + 1,
			    updated_at = GREATEST(updated_at, $3)
			WHERE quota_bucket_id = $1 AND $2::bigint > 0 AND reserved_units >= $2::bigint
		`, entry.bucketID, entry.reservedUnits, now)
		if err != nil {
			return persistenceFailure("release quota bucket", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidState
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
