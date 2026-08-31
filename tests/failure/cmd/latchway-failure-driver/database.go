package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

type provisionSummary struct {
	SchemaVersion               int       `json:"schema_version"`
	Kind                        string    `json:"kind"`
	CreatedAt                   time.Time `json:"created_at"`
	Commit                      string    `json:"commit"`
	LocalDockerImageID          *string   `json:"local_docker_image_id"`
	ReleaseOCIReference         *string   `json:"release_oci_reference"`
	ReleaseOCIPlatformReference *string   `json:"release_oci_platform_reference"`
	OrganizationID              string    `json:"organization_id"`
	ApplicationID               string    `json:"application_id"`
	EnvironmentID               string    `json:"environment_id"`
	ConfigurationRevisionID     string    `json:"configuration_revision_id"`
	InstallationID              string    `json:"installation_id"`
	Platform                    string    `json:"platform"`
	TrustProvider               string    `json:"trust_provider"`
	TrustLevel                  string    `json:"trust_level"`
	DPoPThumbprint              string    `json:"dpop_thumbprint"`
	TokenType                   string    `json:"token_type"`
}

type requestState struct {
	LogicalID             string
	LogicalStatus         string
	FailureCode           string
	ReservationID         string
	ReservationStatus     string
	AttemptCount          int64
	TerminalAttemptCount  int64
	FirstByteAttemptCount int64
	UsageRows             int64
	DuplicateProvenance   int64
	UsageUnits            int64
	EntryCount            int64
	UnbalancedEntries     int64
	ActiveLeases          int64
}

func loadProvision(path string) (provisionSummary, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
		return provisionSummary{}, errors.New("failure provision summary is invalid")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return provisionSummary{}, errors.New("read failure provision summary")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var value provisionSummary
	if err := decoder.Decode(&value); err != nil {
		return provisionSummary{}, errors.New("decode failure provision summary")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return provisionSummary{}, errors.New("failure provision summary has trailing data")
	}
	if value.SchemaVersion != 1 || value.Kind != "latchway_load_provision" || value.EnvironmentID == "" || value.ConfigurationRevisionID == "" {
		return provisionSummary{}, errors.New("failure provision summary contract is invalid")
	}
	return value, nil
}

func newDatabase(ctx context.Context, rawURL string) (*pgxpool.Pool, error) {
	if len(rawURL) < 64 || len(rawURL) > 4096 || strings.ContainsAny(rawURL, "\r\n\x00") {
		return nil, errors.New("failure database URL is invalid")
	}
	config, err := pgxpool.ParseConfig(rawURL)
	if err != nil {
		return nil, errors.New("parse failure database URL")
	}
	address := net.ParseIP(config.ConnConfig.Host)
	if address == nil || !address.IsPrivate() || config.ConnConfig.Port != 5432 || config.ConnConfig.Database != "latchway" || config.ConnConfig.User != "latchway" || len(config.ConnConfig.Password) < 32 || config.ConnConfig.TLSConfig != nil {
		return nil, errors.New("failure database URL must name the isolated PostgreSQL service")
	}
	config.MaxConns = 6
	config.MinConns = 1
	config.MaxConnLifetime = 10 * time.Minute
	config.MaxConnIdleTime = time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("create failure database pool")
	}
	ping, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(ping); err != nil {
		pool.Close()
		return nil, errors.New("failure database is unavailable")
	}
	return pool, nil
}

func readRequestState(ctx context.Context, pool *pgxpool.Pool, clientRequestID string) (requestState, error) {
	var result requestState
	err := pool.QueryRow(ctx, `
		SELECT logical_request_id, status, COALESCE(failure_code, '')
		FROM logical_requests
		WHERE client_request_id = $1
		ORDER BY requested_at DESC, logical_request_id DESC
		LIMIT 1
	`, clientRequestID).Scan(&result.LogicalID, &result.LogicalStatus, &result.FailureCode)
	if err != nil {
		return requestState{}, err
	}
	err = pool.QueryRow(ctx, `
		SELECT quota_reservation_id, status
		FROM quota_reservations
		WHERE logical_request_id = $1
	`, result.LogicalID).Scan(&result.ReservationID, &result.ReservationStatus)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return requestState{}, err
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status <> 'started'),
		       count(*) FILTER (WHERE first_byte_at IS NOT NULL)
		FROM upstream_attempts WHERE logical_request_id = $1
	`, result.LogicalID).Scan(&result.AttemptCount, &result.TerminalAttemptCount, &result.FirstByteAttemptCount); err != nil {
		return requestState{}, err
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*), count(*) - count(DISTINCT provenance_key), COALESCE(sum(units), 0)
		FROM usage_records WHERE logical_request_id = $1
	`, result.LogicalID).Scan(&result.UsageRows, &result.DuplicateProvenance, &result.UsageUnits); err != nil {
		return requestState{}, err
	}
	if result.ReservationID != "" {
		if err := pool.QueryRow(ctx, `
			SELECT count(*), count(*) FILTER (
				WHERE settled_units + released_units <> reserved_units
			)
			FROM quota_reservation_entries WHERE quota_reservation_id = $1
		`, result.ReservationID).Scan(&result.EntryCount, &result.UnbalancedEntries); err != nil {
			return requestState{}, err
		}
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM concurrency_leases
		WHERE logical_request_id = $1 AND released_at IS NULL
	`, result.LogicalID).Scan(&result.ActiveLeases); err != nil {
		return requestState{}, err
	}
	return result, nil
}

func backdateReservation(ctx context.Context, pool *pgxpool.Pool, state requestState) error {
	if state.LogicalID == "" || state.ReservationID == "" || state.ReservationStatus != "pending" {
		return errors.New("failure reservation is not an exact pending target")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("begin failure reservation expiry fixture")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var reservationCount, leaseCount int64
	err = tx.QueryRow(ctx, `
		WITH boundary AS (
			SELECT reservation.quota_reservation_id,
			       GREATEST(
				reservation.created_at,
				COALESCE(max(lease.acquired_at), reservation.created_at)
			) + interval '1 microsecond' AS expires_at
			FROM quota_reservations AS reservation
			LEFT JOIN concurrency_leases AS lease
			  ON lease.logical_request_id = reservation.logical_request_id
			 AND lease.released_at IS NULL
			WHERE reservation.quota_reservation_id = $1
			  AND reservation.logical_request_id = $2
			  AND reservation.status = 'pending'
			GROUP BY reservation.quota_reservation_id, reservation.created_at
		), reservation_update AS (
			UPDATE quota_reservations AS reservation
			SET expires_at = boundary.expires_at
			FROM boundary
			WHERE reservation.quota_reservation_id = boundary.quota_reservation_id
			  AND boundary.expires_at < statement_timestamp()
			RETURNING reservation.logical_request_id, reservation.expires_at
		), lease_update AS (
			UPDATE concurrency_leases AS lease
			SET expires_at = reservation.expires_at
			FROM reservation_update AS reservation
			WHERE lease.logical_request_id = reservation.logical_request_id
			  AND lease.released_at IS NULL
			RETURNING lease.concurrency_lease_id
		)
		SELECT (SELECT count(*) FROM reservation_update),
		       (SELECT count(*) FROM lease_update)
	`, state.ReservationID, state.LogicalID).Scan(&reservationCount, &leaseCount)
	if err != nil || reservationCount != 1 || leaseCount != state.ActiveLeases {
		return errors.New("backdate exact failure reservation")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("commit failure reservation expiry fixture")
	}
	return nil
}

func hardQuotaViolations(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM quota_buckets
		WHERE hard_maximum IS NOT NULL
		  AND (used_units > hard_maximum OR reserved_units > hard_maximum - used_units)
	`).Scan(&count)
	return count, err
}

func liveWorkerCount(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM runtime_instances
		WHERE role = 'worker' AND heartbeat_at >= statement_timestamp() - interval '90 seconds'
	`).Scan(&count)
	return count, err
}

func activeSigningKey(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var keyID string
	err := pool.QueryRow(ctx, `SELECT key_id FROM gateway_signing_keys WHERE status = 'active'`).Scan(&keyID)
	return keyID, err
}

func forceSigningRotationBoundary(ctx context.Context, pool *pgxpool.Pool, expectedKeyID string) error {
	command, err := pool.Exec(ctx, `
		UPDATE gateway_signing_keys
		SET not_after = statement_timestamp() + interval '2 hours'
		WHERE status = 'active' AND key_id = $1
		  AND not_before < statement_timestamp()
		  AND not_after > statement_timestamp() + interval '24 hours'
	`, expectedKeyID)
	if err != nil || command.RowsAffected() != 1 {
		return errors.New("force exact signing rotation boundary")
	}
	return nil
}

func activeConfigurationRevision(ctx context.Context, pool *pgxpool.Pool, environmentID string) (string, error) {
	var revisionID string
	err := pool.QueryRow(ctx, `
		SELECT config_revision_id FROM active_config_revisions WHERE environment_id = $1
	`, environmentID).Scan(&revisionID)
	return revisionID, err
}

func cloneAndActivateConfiguration(ctx context.Context, pool *pgxpool.Pool, provision provisionSummary) (string, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", errors.New("begin failure configuration activation")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var organizationID, applicationID, currentRevisionID, createdBy string
	var document, compiled, validationErrors, validationReport []byte
	if err := tx.QueryRow(ctx, `
		SELECT revision.organization_id, revision.application_id, revision.config_revision_id,
		       revision.document, revision.compiled_document, revision.validation_errors,
		       revision.validation_report, revision.created_by_admin_user_id
		FROM active_config_revisions AS active
		JOIN config_revisions AS revision
		  ON revision.environment_id = active.environment_id
		 AND revision.config_revision_id = active.config_revision_id
		WHERE active.environment_id = $1
		FOR UPDATE OF active
	`, provision.EnvironmentID).Scan(
		&organizationID, &applicationID, &currentRevisionID, &document, &compiled,
		&validationErrors, &validationReport, &createdBy,
	); err != nil {
		return "", errors.New("lock active failure configuration")
	}
	if currentRevisionID == "" || len(document) == 0 || len(compiled) == 0 || len(validationReport) == 0 {
		return "", errors.New("active failure configuration is incomplete")
	}
	newRevisionID, err := id.New(id.ConfigRevision)
	if err != nil {
		return "", errors.New("allocate failure configuration revision")
	}
	var revisionNumber int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(revision_number), 0) + 1 FROM config_revisions WHERE environment_id = $1
	`, provision.EnvironmentID).Scan(&revisionNumber); err != nil {
		return "", errors.New("allocate failure configuration number")
	}
	etag := `"failure-` + newRevisionID + `"`
	if _, err := tx.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_errors, validation_report, created_by_admin_user_id,
			created_at, validated_at, base_config_revision_id, description,
			edit_version, activated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, 'valid', $7, $8, $9, $10, $11,
			statement_timestamp(), statement_timestamp(), $12,
			'isolated destructive replica convergence fixture', 1, statement_timestamp()
		)
	`, newRevisionID, organizationID, applicationID, provision.EnvironmentID,
		revisionNumber, etag, document, compiled, validationErrors, validationReport,
		createdBy, currentRevisionID); err != nil {
		return "", errors.New("insert failure configuration revision")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE active_config_revisions
		SET config_revision_id = $2, revision_status = 'valid',
		    activated_by_admin_user_id = $3, activated_at = statement_timestamp()
		WHERE environment_id = $1 AND config_revision_id = $4
	`, provision.EnvironmentID, newRevisionID, createdBy, currentRevisionID); err != nil {
		return "", errors.New("activate failure configuration revision")
	}
	payload, err := json.Marshal(map[string]string{
		"organization_id": organizationID, "application_id": applicationID,
		"environment_id": provision.EnvironmentID, "revision_id": newRevisionID,
	})
	if err != nil {
		return "", errors.New("encode failure configuration notification")
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify('latchway_config_changed', $1)", string(payload)); err != nil {
		return "", errors.New("notify failure configuration activation")
	}
	if err := tx.Commit(ctx); err != nil {
		return "", errors.New("commit failure configuration activation")
	}
	return newRevisionID, nil
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
