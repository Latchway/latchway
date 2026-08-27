package quota

import (
	"context"
	"errors"
	"fmt"
	"math"
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
	bucket      string
	reservation string
	entry       string
}

func (store *Store) newReserveIDs() (reserveIDs, error) {
	values := []id.Prefix{id.QuotaBucket, id.QuotaReservation, id.QuotaEntry}
	generated := make([]string, len(values))
	for index := range values {
		value, err := store.newID(values[index])
		if err != nil {
			return reserveIDs{}, fmt.Errorf("generate %s identifier: %w", values[index], err)
		}
		generated[index] = value
	}
	return reserveIDs{
		bucket: generated[0], reservation: generated[1], entry: generated[2],
	}, nil
}

// Reserve records one logical request and atomically reserves exactly one
// logical-request unit. Quota denial is committed as a denied logical request
// but creates neither a reservation nor an upstream attempt.
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
	period, err := calendarWindow(requestedAt, prepared.rule.Window)
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

	identifiers, err := store.newReserveIDs()
	if err != nil {
		return Reservation{}, err
	}

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
	`, identifiers.bucket, prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, prepared.LimitPlanKey, prepared.ruleKey,
		prepared.rule.Metric, prepared.scopeType, prepared.scopeDimensions,
		prepared.scopeKey, prepared.rule.Algorithm, period.key,
		prepared.rule.Maximum, requestedAt); err != nil {
		return Reservation{}, mapWriteError("materialize quota bucket", err)
	}

	bucket, err := lockBucket(ctx, tx, prepared, period.key)
	if err != nil {
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
	if bucket.hardMaximum == nil || bucket.used < 0 || bucket.reserved < 0 ||
		bucket.used > math.MaxInt64-bucket.reserved {
		return Reservation{}, ErrInvalidState
	}
	occupancy := bucket.used + bucket.reserved
	if prepared.rule.Maximum < occupancy || prepared.rule.Maximum-occupancy < 1 {
		if prepared.rule.Maximum >= occupancy && *bucket.hardMaximum != prepared.rule.Maximum {
			command, updateErr := tx.Exec(ctx, `
				UPDATE quota_buckets
				SET hard_maximum = $2,
				    version = version + 1,
				    updated_at = GREATEST(updated_at, $3)
				WHERE quota_bucket_id = $1
			`, bucket.id, prepared.rule.Maximum, decisionAt)
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
		return Reservation{}, &ExceededError{
			logicalRequestID: logicalRequestID, retryAt: period.end,
			maximum: prepared.rule.Maximum, used: bucket.used, reserved: bucket.reserved,
		}
	}

	command, err = tx.Exec(ctx, `
		UPDATE quota_buckets
		SET hard_maximum = $2,
		    reserved_units = reserved_units + 1,
		    version = version + 1,
		    updated_at = GREATEST(updated_at, $3)
		WHERE quota_bucket_id = $1
		  AND used_units = $4
		  AND reserved_units = $5
		  AND $2 > used_units
		  AND reserved_units < $2 - used_units
	`, bucket.id, prepared.rule.Maximum, decisionAt, bucket.used, bucket.reserved)
	if err != nil {
		return Reservation{}, persistenceFailure("reserve quota bucket", err)
	}
	if command.RowsAffected() != 1 {
		return Reservation{}, ErrInvalidState
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO quota_reservation_entries (
			quota_reservation_entry_id, organization_id, application_id,
			environment_id, quota_reservation_id, quota_bucket_id,
			reserved_units, settled_units, released_units
		) VALUES ($1, $2, $3, $4, $5, $6, 1, 0, 0)
	`, identifiers.entry, prepared.OrganizationID, prepared.ApplicationID,
		prepared.EnvironmentID, identifiers.reservation, bucket.id); err != nil {
		return Reservation{}, mapWriteError("insert quota reservation entry", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Reservation{}, persistenceFailure("commit quota reservation", err)
	}
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID: prepared.EnvironmentID, logicalRequestID: logicalRequestID,
		reservationID: identifiers.reservation, bucketID: bucket.id, entryID: identifiers.entry,
		routeKey: prepared.RouteKey, upstreamKey: prepared.UpstreamKey,
		modelKey: prepared.ModelKey, physicalModel: prepared.PhysicalModel,
		windowResetAt: period.end, expiresAt: expiresAt,
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
	period, err := calendarWindow(logical.requestedAt.UTC(), prepared.rule.Window)
	if err != nil {
		return Reservation{}, ErrInvalidState
	}

	if logical.status == "denied" {
		if reservationErr == nil {
			return Reservation{}, ErrInvalidState
		}
		if logical.failureCode == nil || *logical.failureCode != "quota_exceeded" {
			return Reservation{}, ErrInvalidState
		}
		bucket, err := lockBucket(ctx, tx, prepared, period.key)
		if err != nil {
			return Reservation{}, err
		}
		if bucket.hardMaximum == nil || bucket.used < 0 || bucket.reserved < 0 ||
			bucket.used > math.MaxInt64-bucket.reserved {
			return Reservation{}, ErrInvalidState
		}
		return Reservation{}, &ExceededError{
			logicalRequestID: prepared.LogicalRequestID.String(), retryAt: period.end,
			maximum: prepared.rule.Maximum, used: bucket.used, reserved: bucket.reserved,
		}
	}
	if reservationErr != nil {
		return Reservation{}, ErrInvalidState
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
		ORDER BY entry.quota_reservation_entry_id
	`, prepared.LogicalRequestID.String(), lockedReservationID)
	if err != nil {
		return Reservation{}, persistenceFailure("load existing quota reservation", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Reservation{}, persistenceFailure("read existing quota reservation", err)
		}
		return Reservation{}, ErrInvalidState
	}
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
	if rows.Next() {
		return Reservation{}, ErrInvalidState
	}
	if err := rows.Err(); err != nil {
		return Reservation{}, persistenceFailure("iterate existing quota reservation", err)
	}
	if existing.organizationID != prepared.OrganizationID ||
		existing.applicationID != prepared.ApplicationID ||
		existing.environmentID != prepared.EnvironmentID ||
		existing.logicalRequestID != prepared.LogicalRequestID.String() ||
		existing.idempotency != fingerprint ||
		existing.bucketOrganizationID != prepared.OrganizationID ||
		existing.bucketApplicationID != prepared.ApplicationID ||
		existing.limitPlanKey != prepared.LimitPlanKey ||
		existing.ruleKey != prepared.ruleKey || existing.metric != prepared.rule.Metric ||
		existing.scopeType != prepared.scopeType ||
		!slicesEqual(existing.scopeDimensions, prepared.scopeDimensions) ||
		existing.scopeKey != prepared.scopeKey ||
		existing.algorithm != prepared.rule.Algorithm || existing.windowKey != period.key {
		return Reservation{}, ErrInvalidInput
	}
	if id.Validate(existing.reservationID, id.QuotaReservation) != nil ||
		id.Validate(existing.entryID, id.QuotaEntry) != nil ||
		id.Validate(existing.bucketID, id.QuotaBucket) != nil ||
		!existingReservationStateMatches(logical.status, existing.status,
			existing.reservedUnits, existing.settledUnits, existing.releasedUnits) {
		return Reservation{}, ErrInvalidState
	}
	return Reservation{
		organizationID: prepared.OrganizationID, applicationID: prepared.ApplicationID,
		environmentID:    prepared.EnvironmentID,
		logicalRequestID: prepared.LogicalRequestID.String(),
		reservationID:    existing.reservationID, bucketID: existing.bucketID,
		entryID: existing.entryID, routeKey: prepared.RouteKey,
		upstreamKey: prepared.UpstreamKey, modelKey: prepared.ModelKey,
		physicalModel: prepared.PhysicalModel, windowResetAt: period.end,
		expiresAt: existing.expiresAt,
	}, nil
}

func existingReservationStateMatches(logicalStatus, reservationStatus string, reserved, settled, released int64) bool {
	if reserved != 1 {
		return false
	}
	switch reservationStatus {
	case "pending":
		return settled == 0 && released == 0 &&
			(logicalStatus == "reserved" || logicalStatus == "dispatched" || logicalStatus == "streaming")
	case "settled":
		return settled == 1 && released == 0 &&
			(logicalStatus == "succeeded" || logicalStatus == "failed" || logicalStatus == "cancelled")
	case "released", "expired":
		return settled == 0 && released == 1 && logicalStatus == "failed"
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

func lockBucket(ctx context.Context, tx pgx.Tx, prepared preparedRequest, windowKey string) (lockedBucket, error) {
	var result lockedBucket
	var organizationID, applicationID string
	err := tx.QueryRow(ctx, `
		SELECT quota_bucket_id, organization_id, application_id,
		       hard_maximum, used_units, reserved_units,
		       scope_type, scope_dimensions
		FROM quota_buckets
		WHERE environment_id = $1
		  AND limit_plan_key = $2
		  AND rule_key = $3
		  AND metric = $4
		  AND algorithm = $5
		  AND window_key = $6
		  AND scope_key = $7
		FOR UPDATE
	`, prepared.EnvironmentID, prepared.LimitPlanKey, prepared.ruleKey,
		prepared.rule.Metric, prepared.rule.Algorithm, windowKey,
		prepared.scopeKey).Scan(
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
		result.scopeType != prepared.scopeType || !slicesEqual(result.scopeDimensions, prepared.scopeDimensions) ||
		id.Validate(result.id, id.QuotaBucket) != nil {
		return lockedBucket{}, ErrInvalidState
	}
	return result, nil
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
			existing.physicalModel == nil || *existing.physicalModel != reservation.physicalModel {
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
			physical_model, status, started_at
		) VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8, 'started', $9)
	`, attemptID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		reservation.routeKey, reservation.upstreamKey, reservation.physicalModel,
		now); err != nil {
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
	if reservation.status == "settled" {
		if terminalAttemptMatches(storedAttempt, outcome) {
			return nil
		}
		return ErrFinalized
	}
	if reservation.status != "pending" {
		return ErrFinalized
	}
	if storedAttempt.status != "started" ||
		(logical.status != "dispatched" && logical.status != "streaming") {
		return ErrInvalidState
	}
	entry, err := lockSingleEntry(ctx, tx, reservation)
	if err != nil {
		return err
	}
	usageID, err := store.newID(id.UsageRecord)
	if err != nil {
		return fmt.Errorf("generate usage-record identifier: %w", err)
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := settleLocked(ctx, tx, reservation, logical, storedAttempt, entry, outcome, usageID, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistenceFailure("commit quota settlement", err)
	}
	return nil
}

// ReleaseBeforeDispatch returns the reserved unit only when the logical
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
	entry, err := lockSingleEntry(ctx, tx, lockedReservation)
	if err != nil {
		return err
	}
	now, err := statementTime(ctx, tx)
	if err != nil {
		return err
	}
	if err := releaseLocked(ctx, tx, lockedReservation, logical, entry, "released", failureCode, now); err != nil {
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
	entry, err := lockSingleEntry(ctx, tx, lockedReservation)
	if err != nil {
		return false, err
	}
	var usageID string
	if attemptExists {
		if storedAttempt.status != "started" ||
			(logical.status != "dispatched" && logical.status != "streaming") {
			return false, ErrInvalidState
		}
		generatedUsageID, idErr := store.newID(id.UsageRecord)
		if idErr != nil {
			return false, fmt.Errorf("generate recovered usage-record identifier: %w", idErr)
		}
		usageID = generatedUsageID
	} else if logical.status != "reserved" {
		return false, ErrInvalidState
	}
	now, err = statementTime(ctx, tx)
	if err != nil {
		return false, err
	}
	if attemptExists {
		outcome := Outcome{Status: AttemptTimedOut, FailureCode: expiryFailureCode}
		if err := settleLocked(ctx, tx, lockedReservation, logical, storedAttempt, entry, outcome, usageID, now); err != nil {
			return false, err
		}
	} else {
		if err := releaseLocked(ctx, tx, lockedReservation, logical, entry, "expired", expiryFailureCode, now); err != nil {
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
	result.Reservation.bucketID = expected.bucketID
	result.Reservation.entryID = expected.entryID
	result.Reservation.routeKey = expected.routeKey
	result.Reservation.upstreamKey = expected.upstreamKey
	result.Reservation.modelKey = expected.modelKey
	result.Reservation.physicalModel = expected.physicalModel
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
	id            string
	number        int32
	routeKey      string
	upstreamKey   string
	physicalModel *string
	status        string
	firstByteAt   *time.Time
	completedAt   *time.Time
	httpStatus    *int32
	failureCode   *string
}

func loadAttemptForUpdate(ctx context.Context, tx pgx.Tx, logicalRequestID string, number int32) (storedAttempt, bool, error) {
	var result storedAttempt
	err := tx.QueryRow(ctx, `
		SELECT upstream_attempt_id, attempt_number, route_key, upstream_key,
		       physical_model, status, first_byte_at, completed_at,
		       http_status, failure_code
		FROM upstream_attempts
		WHERE logical_request_id = $1 AND attempt_number = $2
		FOR UPDATE
	`, logicalRequestID, number).Scan(
		&result.id, &result.number, &result.routeKey, &result.upstreamKey,
		&result.physicalModel, &result.status, &result.firstByteAt,
		&result.completedAt, &result.httpStatus, &result.failureCode,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedAttempt{}, false, nil
	}
	if err != nil {
		return storedAttempt{}, false, persistenceFailure("lock upstream attempt", err)
	}
	if id.Validate(result.id, id.UpstreamAttempt) != nil || result.number != number {
		return storedAttempt{}, false, ErrInvalidState
	}
	return result, true, nil
}

func loadOnlyAttemptForUpdate(ctx context.Context, tx pgx.Tx, logicalRequestID string) (storedAttempt, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT upstream_attempt_id, attempt_number, route_key, upstream_key,
		       physical_model, status, first_byte_at, completed_at,
		       http_status, failure_code
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
	); err != nil {
		return storedAttempt{}, false, persistenceFailure("scan recovered upstream attempt", err)
	}
	if rows.Next() || result.number != 1 || id.Validate(result.id, id.UpstreamAttempt) != nil {
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
	reservedUnits  int64
	settledUnits   int64
	releasedUnits  int64
	bucketUsed     int64
	bucketReserved int64
	hardMaximum    *int64
}

func lockSingleEntry(ctx context.Context, tx pgx.Tx, reservation lockedReservation) (lockedEntry, error) {
	rows, err := tx.Query(ctx, `
		SELECT entry.quota_reservation_entry_id, entry.quota_bucket_id,
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
		ORDER BY bucket.quota_bucket_id
		FOR UPDATE OF entry, bucket
	`, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.reservationID)
	if err != nil {
		return lockedEntry{}, persistenceFailure("lock quota reservation entries", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return lockedEntry{}, persistenceFailure("read quota reservation entries", err)
		}
		return lockedEntry{}, ErrInvalidState
	}
	var result lockedEntry
	if err := rows.Scan(
		&result.id, &result.bucketID, &result.reservedUnits,
		&result.settledUnits, &result.releasedUnits, &result.bucketUsed,
		&result.bucketReserved, &result.hardMaximum,
	); err != nil {
		return lockedEntry{}, persistenceFailure("scan quota reservation entry", err)
	}
	if rows.Next() {
		return lockedEntry{}, ErrInvalidState
	}
	if err := rows.Err(); err != nil {
		return lockedEntry{}, persistenceFailure("iterate quota reservation entries", err)
	}
	if reservation.entryID != "" && result.id != reservation.entryID {
		return lockedEntry{}, ErrInvalidState
	}
	if reservation.bucketID != "" && result.bucketID != reservation.bucketID {
		return lockedEntry{}, ErrInvalidState
	}
	if id.Validate(result.id, id.QuotaEntry) != nil || id.Validate(result.bucketID, id.QuotaBucket) != nil {
		return lockedEntry{}, ErrInvalidState
	}
	return result, nil
}

func settleLocked(ctx context.Context, tx pgx.Tx, reservation lockedReservation, logical lockedLogical, attempt storedAttempt, entry lockedEntry, outcome Outcome, usageID string, now time.Time) error {
	if reservation.status != "pending" || attempt.status != "started" ||
		(logical.status != "dispatched" && logical.status != "streaming") ||
		entry.reservedUnits != 1 || entry.settledUnits != 0 || entry.releasedUnits != 0 ||
		entry.bucketReserved < 1 || entry.hardMaximum == nil || entry.bucketUsed < 0 ||
		entry.bucketUsed >= *entry.hardMaximum {
		return ErrInvalidState
	}
	if attempt.firstByteAt != nil && attempt.firstByteAt.After(now) {
		now = attempt.firstByteAt.UTC()
	}
	command, err := tx.Exec(ctx, `
		UPDATE quota_buckets
		SET used_units = used_units + 1,
		    reserved_units = reserved_units - 1,
		    version = version + 1,
		    updated_at = GREATEST(updated_at, $2)
		WHERE quota_bucket_id = $1
		  AND reserved_units >= 1
		  AND hard_maximum IS NOT NULL
		  AND used_units < hard_maximum
	`, entry.bucketID, now)
	if err != nil {
		return persistenceFailure("settle quota bucket", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	command, err = tx.Exec(ctx, `
		UPDATE quota_reservation_entries
		SET settled_units = 1, released_units = 0
		WHERE quota_reservation_entry_id = $1
		  AND reserved_units = 1 AND settled_units = 0 AND released_units = 0
	`, entry.id)
	if err != nil {
		return persistenceFailure("settle quota reservation entry", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO usage_records (
			usage_record_id, organization_id, application_id, environment_id,
			logical_request_id, upstream_attempt_id, metric, units,
			confidence, provenance_key, recorded_at
		) VALUES ($1, $2, $3, $4, $5, NULL, 'logical_requests', 1,
		          'calculated', $6, $7)
	`, usageID, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, reservation.logicalRequestID,
		"logical-request:"+reservation.logicalRequestID, now); err != nil {
		return mapWriteError("insert logical-request usage", err)
	}
	command, err = tx.Exec(ctx, `
		UPDATE upstream_attempts
		SET status = $2,
		    completed_at = GREATEST(started_at, COALESCE(first_byte_at, started_at), $3),
		    http_status = $4,
		    failure_code = $5
		WHERE upstream_attempt_id = $1 AND status = 'started'
	`, attempt.id, outcome.Status, now, nullableInt(outcome.HTTPStatus),
		nullableString(outcome.FailureCode))
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

func releaseLocked(ctx context.Context, tx pgx.Tx, reservation lockedReservation, logical lockedLogical, entry lockedEntry, reservationStatus, failureCode string, now time.Time) error {
	if reservation.status != "pending" || logical.status != "reserved" ||
		entry.reservedUnits != 1 || entry.settledUnits != 0 || entry.releasedUnits != 0 ||
		entry.bucketReserved < 1 {
		return ErrInvalidState
	}
	command, err := tx.Exec(ctx, `
		UPDATE quota_buckets
		SET reserved_units = reserved_units - 1,
		    version = version + 1,
		    updated_at = GREATEST(updated_at, $2)
		WHERE quota_bucket_id = $1 AND reserved_units >= 1
	`, entry.bucketID, now)
	if err != nil {
		return persistenceFailure("release quota bucket", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
	command, err = tx.Exec(ctx, `
		UPDATE quota_reservation_entries
		SET settled_units = 0, released_units = 1
		WHERE quota_reservation_entry_id = $1
		  AND reserved_units = 1 AND settled_units = 0 AND released_units = 0
	`, entry.id)
	if err != nil {
		return persistenceFailure("release quota reservation entry", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidState
	}
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

func terminalAttemptMatches(stored storedAttempt, outcome Outcome) bool {
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
