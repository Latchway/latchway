package database

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	quotaMigrationOrganizationID = "org_00000000000000000000000001"
	quotaMigrationApplicationID  = "app_00000000000000000000000001"
	quotaMigrationEnvironmentID  = "env_00000000000000000000000001"
)

func TestMigratorPostgreSQLQuotaIdentityUpgradeFailsClosed(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 7)
	seedQuotaMigrationTenant(t, ctx, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_buckets (
			quota_bucket_id, organization_id, application_id, environment_id,
			metric, scope_type, scope_key, algorithm, window_key, hard_maximum
		) VALUES (
			'qbk_00000000000000000000000001', $1, $2, $3,
			'logical_requests', 'user', 'legacy-user-value', 'calendar', '2026-08-27', 100
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID, quotaMigrationEnvironmentID); err != nil {
		t.Fatalf("insert legacy quota bucket: %v", err)
	}

	migrator := NewMigrator(pool)
	err := migrator.Up(ctx)
	expectPostgreSQLConstraintError(t, err, "23514", "")

	var versionApplied bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 8)
	`).Scan(&versionApplied); err != nil {
		t.Fatalf("read rejected quota migration status: %v", err)
	}
	if versionApplied {
		t.Fatal("quota identity migration was recorded after rejecting legacy buckets")
	}

	var newColumnPresent bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = 'quota_buckets'
			  AND column_name = 'limit_plan_key'
		)
	`).Scan(&newColumnPresent); err != nil {
		t.Fatalf("read rejected quota schema: %v", err)
	}
	if newColumnPresent {
		t.Fatal("quota bucket columns survived the rejected transactional migration")
	}

	var legacyClientIndexUnique bool
	if err := pool.QueryRow(ctx, `
		SELECT index_entry.indisunique
		FROM pg_index AS index_entry
		JOIN pg_class AS index_relation ON index_relation.oid = index_entry.indexrelid
		WHERE index_relation.oid = 'logical_requests_client_request_idx'::regclass
	`).Scan(&legacyClientIndexUnique); err != nil {
		t.Fatalf("read rolled-back client correlation index: %v", err)
	}
	if !legacyClientIndexUnique {
		t.Fatal("client correlation index change survived the rejected transactional migration")
	}

	if _, err := pool.Exec(ctx, `
		DELETE FROM quota_buckets
		WHERE quota_bucket_id = 'qbk_00000000000000000000000001'
	`); err != nil {
		t.Fatalf("remove test legacy bucket before explicit retry: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply quota identity migration after operator repair: %v", err)
	}
	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatalf("read repaired quota migration status: %v", err)
	}
	if current != 16 || available != 16 {
		t.Fatalf("schema versions after repaired upgrade current=%d available=%d", current, available)
	}
}

func TestMigratorPostgreSQLLogicalRequestFingerprintUpgrade(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 8)
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	const legacyRequestID = "req_00000000000000000000000001"
	if err := insertQuotaMigrationLogicalRequest(ctx, pool, legacyRequestID, "chat"); err != nil {
		t.Fatalf("insert legacy logical request: %v", err)
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply logical request fingerprint migration: %v", err)
	}

	var legacyFingerprint *string
	if err := pool.QueryRow(ctx, `
		SELECT trusted_decision_fingerprint
		FROM logical_requests
		WHERE logical_request_id = $1
	`, legacyRequestID).Scan(&legacyFingerprint); err != nil {
		t.Fatalf("read legacy fingerprint: %v", err)
	}
	if legacyFingerprint != nil {
		t.Fatalf("legacy fingerprint = %q, want NULL", *legacyFingerprint)
	}
	var constraintValidated bool
	if err := pool.QueryRow(ctx, `
		SELECT convalidated
		FROM pg_constraint
		WHERE conrelid = 'logical_requests'::regclass
		  AND conname = 'logical_requests_trusted_decision_fingerprint_check'
	`).Scan(&constraintValidated); err != nil {
		t.Fatalf("read fingerprint constraint validation state: %v", err)
	}
	if constraintValidated {
		t.Fatal("fingerprint constraint performed eager legacy-table validation")
	}

	const validFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests
		SET trusted_decision_fingerprint = $2
		WHERE logical_request_id = $1
	`, legacyRequestID, validFingerprint); err != nil {
		t.Fatalf("store bounded fingerprint: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, session_grant_id,
			config_revision_id, feature_key, protocol,
			trusted_decision_fingerprint, status
		) VALUES (
			'req_00000000000000000000000002', $1, $2, $3,
			'usr_00000000000000000000000001',
			'ins_00000000000000000000000001',
			'sgr_00000000000000000000000001',
			'rev_00000000000000000000000001',
			'chat', 'openai_chat', $4, 'reserved'
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, strings.Repeat("x", 42)); err == nil {
		t.Fatal("invalid fingerprint passed NOT VALID constraint on insert")
	} else {
		expectPostgreSQLConstraintError(
			t,
			err,
			"23514",
			"logical_requests_trusted_decision_fingerprint_check",
		)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests
		SET trusted_decision_fingerprint = $2
		WHERE logical_request_id = $1
	`, legacyRequestID, strings.Repeat("x", 42)); err == nil {
		t.Fatal("short trusted decision fingerprint passed schema constraint")
	} else {
		expectPostgreSQLConstraintError(
			t,
			err,
			"23514",
			"logical_requests_trusted_decision_fingerprint_check",
		)
	}

	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatalf("read fingerprint migration status: %v", err)
	}
	if current != 16 || available != 16 {
		t.Fatalf("fingerprint schema versions current=%d available=%d", current, available)
	}
}

func TestMigratorPostgreSQLSecretNameContractUpgrade(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 9)
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	insert := func(recordID, name string) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO secret_records (
				secret_record_id, organization_id, application_id, environment_id,
				name, version, encryption_format_version, algorithm,
				master_key_identifier, ciphertext, nonce, created_by_admin_user_id
			) VALUES ($1, $2, $3, $4, $5, 1, 1, 'aes-256-gcm',
			          'env_test-key', $6, $7, 'adm_00000000000000000000000001')
		`, recordID, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, name, bytes.Repeat([]byte{0x51}, 17), bytes.Repeat([]byte{0x52}, 12))
		return err
	}
	if err := insert("sec_00000000000000000000000001", "legacy.name"); err != nil {
		t.Fatalf("insert legacy broader secret name: %v", err)
	}
	if err := insert("sec_00000000000000000000000002", "a"); err == nil {
		t.Fatal("schema v9 unexpectedly accepted the one-character contract name")
	} else {
		expectPostgreSQLConstraintError(t, err, "23514", "secret_records_name_check")
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err == nil {
		t.Fatal("secret-name contract migration accepted an unmanageable legacy row")
	} else {
		expectPostgreSQLConstraintError(t, err, "23514", "secret_records_name_check")
	}
	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatalf("read rejected secret-name migration status: %v", err)
	}
	if current != 9 || available != 16 {
		t.Fatalf("rejected secret-name migration status current=%d available=%d", current, available)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE secret_records SET name = 'legacy-name'
		WHERE secret_record_id = 'sec_00000000000000000000000001'
	`); err != nil {
		t.Fatalf("repair legacy secret name under schema v9: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply secret-name contract migration after repair: %v", err)
	}
	if err := insert("sec_00000000000000000000000002", "a"); err != nil {
		t.Fatalf("schema v10 rejected one-character contract name: %v", err)
	}
	if err := insert("sec_00000000000000000000000003", "new.name"); err == nil {
		t.Fatal("schema v10 accepted a noncanonical new secret name")
	} else {
		expectPostgreSQLConstraintError(t, err, "23514", "secret_records_name_check")
	}
	var repairedRows int
	var validated bool
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM secret_records WHERE name = 'legacy-name'`).Scan(&repairedRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT convalidated FROM pg_constraint
		WHERE conrelid = 'secret_records'::regclass
		  AND conname = 'secret_records_name_check'
	`).Scan(&validated); err != nil {
		t.Fatal(err)
	}
	if repairedRows != 1 || !validated {
		t.Fatalf("repaired rows=%d constraint validated=%t", repairedRows, validated)
	}
	current, available, err = migrator.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current != 16 || available != 16 {
		t.Fatalf("secret-name schema versions current=%d available=%d", current, available)
	}
}

func TestMigratorPostgreSQLAuditIndeterminateOutcomeUpgrade(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 10)

	insert := func(eventID, outcome string) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO audit_events (
				audit_event_id, actor_kind, action, resource_type,
				resource_id, outcome, request_id, occurred_at
			) VALUES ($1, 'system', 'admin.secret_rotate', 'admin_request',
			          'arq_00000000000000000000000001', $2,
			          'arq_00000000000000000000000001', clock_timestamp())
		`, eventID, outcome)
		return err
	}
	if err := insert("aud_00000000000000000000000001", "indeterminate"); err == nil {
		t.Fatal("schema v10 unexpectedly accepted an indeterminate audit outcome")
	} else {
		expectPostgreSQLConstraintError(t, err, "23514", "audit_events_outcome_check")
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply indeterminate audit-outcome migration: %v", err)
	}
	if err := insert("aud_00000000000000000000000001", "indeterminate"); err != nil {
		t.Fatalf("schema v11 rejected indeterminate audit outcome: %v", err)
	}
	if err := insert("aud_00000000000000000000000002", "unknown"); err == nil {
		t.Fatal("schema v11 accepted an unknown audit outcome")
	} else {
		expectPostgreSQLConstraintError(t, err, "23514", "audit_events_outcome_check")
	}
	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current != 16 || available != 16 {
		t.Fatalf("audit-outcome schema versions current=%d available=%d", current, available)
	}
}

func TestMigratorPostgreSQLUpstreamAttemptAccountingUpgrade(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 11)
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	legacy := seedQuotaAttemptAccountingV11(t, ctx, pool, 1, true)
	legacyProvenance := "quota-reservation:" + legacy.reservationID + ":unknown-output"
	if _, err := pool.Exec(ctx, `
		INSERT INTO usage_records (
			usage_record_id, organization_id, application_id, environment_id,
			logical_request_id, upstream_attempt_id, metric, units,
			confidence, provenance_key
		) VALUES (
			'usg_00000000000000000000000001', $1, $2, $3,
			$4, $5, 'output_tokens', 7, 'unknown', $6
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, legacy.logicalRequestID, legacy.attemptID,
		legacyProvenance); err != nil {
		t.Fatalf("insert legacy unknown usage: %v", err)
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply upstream-attempt accounting migration: %v", err)
	}
	var initial, reserved int64
	if err := pool.QueryRow(ctx, `
		SELECT initial_reserved_units, reserved_units
		FROM quota_reservation_entries
		WHERE quota_reservation_entry_id = $1
	`, legacy.entryID).Scan(&initial, &reserved); err != nil {
		t.Fatalf("read upgraded reservation entry: %v", err)
	}
	if initial != 7 || reserved != 7 {
		t.Fatalf("upgraded reservation units = %d/%d, want 7/7", initial, reserved)
	}
	var allocated, charged, released int64
	if err := pool.QueryRow(ctx, `
		SELECT allocated_units, charged_units, released_units
		FROM upstream_attempt_quota_entries
		WHERE upstream_attempt_id = $1 AND quota_reservation_entry_id = $2
	`, legacy.attemptID, legacy.entryID).Scan(&allocated, &charged, &released); err != nil {
		t.Fatalf("read backfilled attempt allocation: %v", err)
	}
	if allocated != 7 || charged != 7 || released != 0 {
		t.Fatalf("backfilled attempt allocation = %d/%d/%d, want 7/7/0", allocated, charged, released)
	}
	var storedProvenance string
	if err := pool.QueryRow(ctx, `
		SELECT provenance_key FROM usage_records
		WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
	`, legacy.attemptID).Scan(&storedProvenance); err != nil {
		t.Fatalf("read upgraded legacy provenance: %v", err)
	}
	if storedProvenance != legacyProvenance {
		t.Fatalf("legacy provenance = %q, want byte-exact %q", storedProvenance, legacyProvenance)
	}
	var legacyBindingVersion, legacyDecisionVersion int16
	var legacyModelKey *string
	var legacyDecisionDigest []byte
	if err := pool.QueryRow(ctx, `
		SELECT input_accounting_binding_version, attempt_decision_binding_version,
		       model_key, attempt_decision_sha256
		FROM upstream_attempts
		WHERE upstream_attempt_id = $1
	`, legacy.attemptID).Scan(
		&legacyBindingVersion, &legacyDecisionVersion, &legacyModelKey, &legacyDecisionDigest,
	); err != nil {
		t.Fatalf("read legacy attempt binding version: %v", err)
	}
	if legacyBindingVersion != 0 || legacyDecisionVersion != 0 ||
		legacyModelKey != nil || legacyDecisionDigest != nil {
		t.Fatalf("legacy attempt bindings = input:%d decision:%d model:%v digest:%x, want 0/0/nil/nil",
			legacyBindingVersion, legacyDecisionVersion, legacyModelKey, legacyDecisionDigest)
	}

	second := seedQuotaAttemptAccountingV12(t, ctx, pool, 2)
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*) FROM upstream_attempts
		WHERE upstream_attempt_id = $1 AND input_accounting_binding_version = 1
		  AND attempt_decision_binding_version = 1
		  AND model_key = 'model-v1'
		  AND octet_length(attempt_decision_sha256) = 32
	`, second.attemptID); got != 1 {
		t.Fatalf("new attempt binding-version rows = %d, want 1", got)
	}

	rollingRetry := seedQuotaAttemptAccountingV11(t, ctx, pool, 3, false)
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*)
		FROM quota_reservation_entries AS entry
		JOIN upstream_attempt_quota_entries AS quota
		  ON quota.quota_reservation_entry_id = entry.quota_reservation_entry_id
		WHERE entry.quota_reservation_entry_id = $1
		  AND entry.origin_attempt_number = 1
		  AND entry.initial_reserved_units = 7
		  AND quota.upstream_attempt_id = $2
		  AND quota.allocated_units = 7
		  AND quota.charged_units IS NULL
	`, rollingRetry.entryID, rollingRetry.attemptID); got != 1 {
		t.Fatalf("schema-11 rolling insert compatibility rows = %d, want 1", got)
	}
	retryTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin schema-12 settlement of rolling attempt: %v", err)
	}
	defer func() { _ = retryTx.Rollback(ctx) }()
	if _, err := retryTx.Exec(ctx, `
		UPDATE quota_buckets
		SET used_units = 7, reserved_units = 0
		WHERE quota_bucket_id = $1
	`, rollingRetry.bucketID); err != nil {
		t.Fatalf("settle rolling retry bucket: %v", err)
	}
	if _, err := retryTx.Exec(ctx, `
		UPDATE quota_reservation_entries
		SET settled_units = 7, released_units = 0
		WHERE quota_reservation_entry_id = $1
	`, rollingRetry.entryID); err != nil {
		t.Fatalf("settle rolling retry reservation entry: %v", err)
	}
	if _, err := retryTx.Exec(ctx, `
		UPDATE upstream_attempt_quota_entries
		SET charged_units = 7, released_units = 0, settled_at = CURRENT_TIMESTAMP
		WHERE upstream_attempt_id = $1
	`, rollingRetry.attemptID); err != nil {
		t.Fatalf("settle rolling retry allocation: %v", err)
	}
	if _, err := retryTx.Exec(ctx, `
		UPDATE upstream_attempts
		SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
		    http_status = 503, failure_code = 'retryable_failure'
		WHERE upstream_attempt_id = $1
	`, rollingRetry.attemptID); err != nil {
		t.Fatalf("complete rolling retry attempt: %v", err)
	}
	if err := retryTx.Commit(ctx); err != nil {
		t.Fatalf("commit schema-12 settlement of rolling attempt: %v", err)
	}
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*)
		FROM quota_reservations AS reservation
		JOIN logical_requests AS logical USING (logical_request_id)
		WHERE reservation.quota_reservation_id = $1
		  AND reservation.status = 'pending'
		  AND logical.status = 'dispatched'
	`, rollingRetry.reservationID); got != 1 {
		t.Fatalf("schema-12 rolling retry aggregate rows = %d, want pending/dispatched", got)
	}

	rollingFinal := seedQuotaAttemptAccountingV11(t, ctx, pool, 4, false)
	settleQuotaAttemptAccountingWithSchema11Writer(t, ctx, pool, rollingFinal)
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*)
		FROM upstream_attempt_quota_entries AS quota
		JOIN upstream_attempts AS attempt USING (upstream_attempt_id)
		WHERE quota.upstream_attempt_id = $1
		  AND quota.metric = 'output_tokens'
		  AND quota.allocated_units = 7
		  AND quota.charged_units = 7
		  AND quota.released_units = 0
		  AND quota.settled_at = attempt.completed_at
	`, rollingFinal.attemptID); got != 1 {
		t.Fatalf("schema-11 rolling terminal ledger rows = %d, want 1", got)
	}

	mixedFinal := seedQuotaAttemptAccountingV12(t, ctx, pool, 5)
	settleQuotaAttemptAccountingWithSchema11Writer(t, ctx, pool, mixedFinal)
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*)
		FROM upstream_attempt_quota_entries AS quota
		JOIN upstream_attempts AS attempt USING (upstream_attempt_id)
		WHERE quota.upstream_attempt_id = $1
		  AND attempt.attempt_decision_binding_version = 1
		  AND quota.allocated_units = 7
		  AND quota.charged_units = 7
		  AND quota.released_units = 0
		  AND quota.settled_at = attempt.completed_at
	`, mixedFinal.attemptID); got != 1 {
		t.Fatalf("schema-11 settler on schema-12 first attempt rows = %d, want 1", got)
	}

	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				confidence, provenance_key
			) VALUES (
				'usg_00000000000000000000000002', $1, $2, $3,
				$4, $5, 'output_tokens', 1, 'reported',
				'provider-attempt:cross-request-output'
			)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, legacy.logicalRequestID, second.attemptID)
		return err
	}(), "23503", "usage_records_request_attempt_fkey")
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempt_quota_entries (
				organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, quota_reservation_id,
				quota_reservation_entry_id, quota_bucket_id, metric, allocated_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'output_tokens', 5)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, legacy.logicalRequestID, legacy.attemptID,
			second.reservationID, second.entryID, second.bucketID)
		return err
	}(), "23503", "upstream_attempt_quota_entries_request_reservation_fkey")
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*) FROM upstream_attempt_quota_entries
		WHERE upstream_attempt_id = $1 AND quota_reservation_entry_id = $2
	`, legacy.attemptID, second.entryID); got != 0 {
		t.Fatalf("cross-bound attempt allocation rows = %d, want 0", got)
	}
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempt_quota_entries (
				organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, quota_reservation_id,
				quota_reservation_entry_id, quota_bucket_id, metric, allocated_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'output_tokens', 5)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, legacy.logicalRequestID, legacy.attemptID,
			legacy.reservationID, second.entryID, second.bucketID)
		return err
	}(), "23503", "upstream_attempt_quota_entries_reservation_entry_fkey")

	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempts (
				upstream_attempt_id, organization_id, application_id, environment_id,
				logical_request_id, attempt_number, route_key, upstream_key,
				physical_model, model_key, attempt_decision_sha256, status
			) VALUES (
				'atm_00000000000000000000000033', $1, $2, $3,
				$4, 33, 'overflow', 'provider', 'provider/model-v3', 'model-v3',
				decode(repeat('33', 32), 'hex'), 'started'
			)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, second.logicalRequestID)
		return err
	}(), "23514", "upstream_attempts_attempt_number_check")
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempts (
				upstream_attempt_id, organization_id, application_id, environment_id,
				logical_request_id, attempt_number, route_key, upstream_key,
				physical_model, status, attempt_decision_binding_version
			) VALUES (
				'atm_00000000000000000000000029', $1, $2, $3,
				$4, 2, 'legacy-decision', 'provider', 'provider/model-v3', 'started', 0
			)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, second.logicalRequestID)
		return err
	}(), "23514", "upstream_attempts_decision_binding_check")
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			UPDATE upstream_attempts
			SET attempt_decision_sha256 = decode(repeat('00', 32), 'hex')
			WHERE upstream_attempt_id = $1
		`, second.attemptID)
		return err
	}(), "23514", "upstream_attempts_decision_binding_check")
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempts (
				upstream_attempt_id, organization_id, application_id, environment_id,
				logical_request_id, attempt_number, route_key, upstream_key,
				physical_model, model_key, attempt_decision_binding_version,
				attempt_decision_sha256,
				status, input_accounting_binding_version
			) VALUES (
				'atm_00000000000000000000000030', $1, $2, $3,
				$4, 2, 'legacy-retry', 'provider', 'provider/model-v3', 'model-v3',
				1, decode(repeat('30', 32), 'hex'), 'started', 0
			)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, second.logicalRequestID)
		return err
	}(), "23514", "upstream_attempts_input_accounting_binding_check")
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempts (
				upstream_attempt_id, organization_id, application_id, environment_id,
				logical_request_id, attempt_number, route_key, upstream_key,
				physical_model, model_key, attempt_decision_binding_version,
				attempt_decision_sha256,
				status, input_accounting_binding_version,
				input_accounting_method, input_accounting_profile_id,
				input_accounting_profile_digest, rewritten_body_sha256,
				input_token_bound, output_token_bound, total_token_bound
			) VALUES (
				'atm_00000000000000000000000031', $1, $2, $3,
				$4, 2, 'zero-proof', 'provider', 'provider/model-v3', 'model-v3',
				1, decode(repeat('31', 32), 'hex'), 'started', 1,
				'utf8_byte_bpe_declared_framing_v1', 'profile_v1',
				decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'),
				4, 6, 10
			)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, second.logicalRequestID)
		return err
	}(), "23514", "upstream_attempts_input_accounting_binding_check")
	expectPostgreSQLConstraintError(t, func() error {
		_, err := pool.Exec(ctx, `
			UPDATE upstream_attempts
			SET input_accounting_method = 'utf8_byte_bpe_declared_framing_v1'
			WHERE upstream_attempt_id = $1
		`, legacy.attemptID)
		return err
	}(), "23514", "upstream_attempts_input_accounting_binding_check")
}

func TestMigratorPostgreSQLUpstreamAttemptAccountingRejectsAmbiguousLegacyRows(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 11)
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	legacy := seedQuotaAttemptAccountingV11(t, ctx, pool, 1, false)
	if _, err := pool.Exec(ctx, `
		INSERT INTO upstream_attempts (
			upstream_attempt_id, organization_id, application_id, environment_id,
			logical_request_id, attempt_number, route_key, upstream_key,
			physical_model, status
		) VALUES (
			'atm_00000000000000000000000002', $1, $2, $3,
			$4, 2, 'secondary', 'backup', 'provider/model-v2', 'started'
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, legacy.logicalRequestID); err != nil {
		t.Fatalf("insert ambiguous second legacy attempt: %v", err)
	}

	err := NewMigrator(pool).Up(ctx)
	expectPostgreSQLConstraintError(t, err, "23514", "")
	var versionApplied, newTablePresent, newColumnPresent bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 12),
		       to_regclass('upstream_attempt_quota_entries') IS NOT NULL,
		       EXISTS (
			   SELECT 1 FROM information_schema.columns
			   WHERE table_schema = current_schema()
			     AND table_name = 'quota_reservation_entries'
			     AND column_name = 'initial_reserved_units'
		       )
	`).Scan(&versionApplied, &newTablePresent, &newColumnPresent); err != nil {
		t.Fatalf("read rejected attempt-accounting migration state: %v", err)
	}
	if versionApplied || newTablePresent || newColumnPresent {
		t.Fatalf("rejected migration survived version=%t table=%t column=%t",
			versionApplied, newTablePresent, newColumnPresent)
	}
}

func TestMigratorPostgreSQLUpstreamAttemptAccountingRejectsOrphanLegacyAttempt(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 11)
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	const logicalRequestID = "req_00000000000000000000000009"
	if err := insertQuotaMigrationLogicalRequest(
		ctx, pool, logicalRequestID, "attempt-accounting",
	); err != nil {
		t.Fatalf("insert orphan-attempt logical request: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests
		SET status = 'dispatched', dispatched_at = CURRENT_TIMESTAMP
		WHERE logical_request_id = $1
	`, logicalRequestID); err != nil {
		t.Fatalf("dispatch orphan-attempt logical request: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO upstream_attempts (
			upstream_attempt_id, organization_id, application_id, environment_id,
			logical_request_id, attempt_number, route_key, upstream_key,
			physical_model, status
		) VALUES (
			'atm_00000000000000000000000009', $1, $2, $3, $4,
			1, 'primary', 'provider', 'provider/model-v1', 'started'
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, logicalRequestID); err != nil {
		t.Fatalf("insert orphan legacy attempt: %v", err)
	}

	err := NewMigrator(pool).Up(ctx)
	expectPostgreSQLConstraintError(t, err, "23514", "")
	if got := countDatabaseRows(t, ctx, pool, `
		SELECT count(*) FROM schema_migrations WHERE version = 12
	`); got != 0 {
		t.Fatalf("orphan-attempt rejected migration rows = %d, want 0", got)
	}
}

func TestMigratorPostgreSQLQuotaIdentityConstraints(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	seedQuotaMigrationTenant(t, ctx, pool)

	assertQuotaMigrationCatalog(t, ctx, pool)

	base := quotaBucketFixture{
		ID:              "qbk_00000000000000000000000001",
		LimitPlanKey:    "standard",
		RuleKey:         strings.Repeat("r", 43),
		Metric:          "logical_requests",
		ScopeType:       "user",
		ScopeDimensions: []string{"user"},
		ScopeKey:        strings.Repeat("s", 43),
		Algorithm:       "calendar",
		WindowKey:       "2026-08-27",
		HardMaximum:     100,
	}
	if err := insertQuotaMigrationBucket(ctx, pool, base); err != nil {
		t.Fatalf("insert singular quota bucket: %v", err)
	}

	composite := base
	composite.ID = "qbk_00000000000000000000000002"
	composite.RuleKey = strings.Repeat("c", 43)
	composite.ScopeType = "composite"
	composite.ScopeDimensions = []string{"user", "feature"}
	composite.ScopeKey = strings.Repeat("d", 43)
	if err := insertQuotaMigrationBucket(ctx, pool, composite); err != nil {
		t.Fatalf("insert composite quota bucket: %v", err)
	}

	route := base
	route.ID = "qbk_00000000000000000000000003"
	route.RuleKey = strings.Repeat("e", 43)
	route.ScopeType = "route"
	route.ScopeDimensions = []string{"route"}
	route.ScopeKey = strings.Repeat("f", 43)
	if err := insertQuotaMigrationBucket(ctx, pool, route); err != nil {
		t.Fatalf("insert route-scoped quota bucket: %v", err)
	}

	duplicateIdentity := base
	duplicateIdentity.ID = "qbk_00000000000000000000000004"
	duplicateIdentity.HardMaximum = 200
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, duplicateIdentity),
		"23505",
		"quota_buckets_identity_key",
	)

	invalidPlan := base
	invalidPlan.ID = "qbk_00000000000000000000000005"
	invalidPlan.LimitPlanKey = "Standard"
	invalidPlan.RuleKey = strings.Repeat("g", 43)
	invalidPlan.ScopeKey = strings.Repeat("h", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, invalidPlan),
		"23514",
		"quota_buckets_limit_plan_key_identifier_check",
	)

	invalidRuleHash := base
	invalidRuleHash.ID = "qbk_00000000000000000000000006"
	invalidRuleHash.RuleKey = strings.Repeat("i", 42)
	invalidRuleHash.ScopeKey = strings.Repeat("j", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, invalidRuleHash),
		"23514",
		"quota_buckets_rule_key_hash_check",
	)

	duplicateDimensions := base
	duplicateDimensions.ID = "qbk_00000000000000000000000007"
	duplicateDimensions.RuleKey = strings.Repeat("k", 43)
	duplicateDimensions.ScopeType = "composite"
	duplicateDimensions.ScopeDimensions = []string{"user", "user"}
	duplicateDimensions.ScopeKey = strings.Repeat("m", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, duplicateDimensions),
		"23514",
		"quota_buckets_scope_dimensions_check",
	)

	mismatchedSingularScope := base
	mismatchedSingularScope.ID = "qbk_00000000000000000000000008"
	mismatchedSingularScope.RuleKey = strings.Repeat("n", 43)
	mismatchedSingularScope.ScopeType = "feature"
	mismatchedSingularScope.ScopeDimensions = []string{"user"}
	mismatchedSingularScope.ScopeKey = strings.Repeat("o", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, mismatchedSingularScope),
		"23514",
		"quota_buckets_scope_type_dimensions_check",
	)

	invalidScopeHash := base
	invalidScopeHash.ID = "qbk_00000000000000000000000009"
	invalidScopeHash.RuleKey = strings.Repeat("p", 43)
	invalidScopeHash.ScopeKey = strings.Repeat("q", 42)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, invalidScopeHash),
		"23514",
		"quota_buckets_scope_key_hash_check",
	)

	zeroBasedDimensions := base
	zeroBasedDimensions.ID = "qbk_00000000000000000000000010"
	zeroBasedDimensions.RuleKey = strings.Repeat("t", 43)
	zeroBasedDimensions.ScopeDimensions = pgtype.Array[string]{
		Elements: []string{"user"},
		Dims:     []pgtype.ArrayDimension{{Length: 1, LowerBound: 0}},
		Valid:    true,
	}
	zeroBasedDimensions.ScopeKey = strings.Repeat("u", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, zeroBasedDimensions),
		"23514",
		"quota_buckets_scope_dimensions_check",
	)

	multidimensionalScope := base
	multidimensionalScope.ID = "qbk_00000000000000000000000011"
	multidimensionalScope.RuleKey = strings.Repeat("v", 43)
	multidimensionalScope.ScopeType = "composite"
	multidimensionalScope.ScopeDimensions = pgtype.Array[string]{
		Elements: []string{"user", "feature"},
		Dims: []pgtype.ArrayDimension{
			{Length: 1, LowerBound: 1},
			{Length: 2, LowerBound: 1},
		},
		Valid: true,
	}
	multidimensionalScope.ScopeKey = strings.Repeat("w", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, multidimensionalScope),
		"23514",
		"quota_buckets_scope_dimensions_check",
	)
}

func TestMigratorPostgreSQLLogicalRequestFeatureIdentifierBounds(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	var featureConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'logical_requests'::regclass
		  AND conname = 'logical_requests_feature_key_identifier_check'
	`).Scan(&featureConstraint); err != nil {
		t.Fatalf("read logical request feature constraint: %v", err)
	}
	if !strings.Contains(featureConstraint, "{0,62}") {
		t.Fatalf("logical request feature constraint = %q", featureConstraint)
	}

	if err := insertQuotaMigrationLogicalRequest(
		ctx,
		pool,
		"req_00000000000000000000000001",
		"a",
	); err != nil {
		t.Fatalf("insert one-character feature identifier: %v", err)
	}

	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationLogicalRequest(
			ctx,
			pool,
			"req_00000000000000000000000002",
			strings.Repeat("a", 64),
		),
		"23514",
		"logical_requests_feature_key_identifier_check",
	)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationLogicalRequest(
			ctx,
			pool,
			"req_00000000000000000000000003",
			"Not_Canonical",
		),
		"23514",
		"logical_requests_feature_key_identifier_check",
	)
}

type quotaBucketFixture struct {
	ID              string
	LimitPlanKey    string
	RuleKey         string
	Metric          string
	ScopeType       string
	ScopeDimensions any
	ScopeKey        string
	Algorithm       string
	WindowKey       string
	HardMaximum     int64
}

type quotaAttemptAccountingFixture struct {
	logicalRequestID string
	reservationID    string
	entryID          string
	bucketID         string
	attemptID        string
}

func seedQuotaAttemptAccountingV11(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixtureNumber int,
	terminal bool,
) quotaAttemptAccountingFixture {
	t.Helper()
	return seedQuotaAttemptAccounting(t, ctx, pool, fixtureNumber, terminal, false)
}

func seedQuotaAttemptAccounting(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixtureNumber int,
	terminal bool,
	schema12Writer bool,
) quotaAttemptAccountingFixture {
	t.Helper()
	fixture := quotaAttemptAccountingIDs(fixtureNumber)
	if err := insertQuotaMigrationLogicalRequest(
		ctx, pool, fixture.logicalRequestID, "attempt-accounting",
	); err != nil {
		t.Fatalf("insert attempt-accounting logical request: %v", err)
	}
	logicalStatus := "dispatched"
	if terminal {
		logicalStatus = "failed"
	}
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests
		SET status = $2,
		    requested_at = statement_timestamp() - interval '3 minutes',
		    dispatched_at = statement_timestamp() - interval '2 minutes',
		    completed_at = CASE WHEN $2 = 'failed' THEN statement_timestamp() ELSE NULL END,
		    failure_code = CASE WHEN $2 = 'failed' THEN 'legacy_failure' ELSE NULL END
		WHERE logical_request_id = $1
	`, fixture.logicalRequestID, logicalStatus); err != nil {
		t.Fatalf("prepare attempt-accounting logical request: %v", err)
	}
	bucket := quotaBucketFixture{
		ID: fixture.bucketID, LimitPlanKey: "attempt-accounting",
		RuleKey: strings.Repeat(string(rune('a'+fixtureNumber)), 43),
		Metric:  "output_tokens", ScopeType: "user", ScopeDimensions: []string{"user"},
		ScopeKey:  strings.Repeat(string(rune('m'+fixtureNumber)), 43),
		Algorithm: "calendar", WindowKey: "2026-08-28", HardMaximum: 100,
	}
	if err := insertQuotaMigrationBucket(ctx, pool, bucket); err != nil {
		t.Fatalf("insert attempt-accounting bucket: %v", err)
	}
	used, reserved := int64(0), int64(7)
	if terminal {
		used, reserved = 7, 0
	}
	if _, err := pool.Exec(ctx, `
		UPDATE quota_buckets SET used_units = $2, reserved_units = $3
		WHERE quota_bucket_id = $1
	`, fixture.bucketID, used, reserved); err != nil {
		t.Fatalf("prepare attempt-accounting bucket: %v", err)
	}
	reservationStatus := "pending"
	if terminal {
		reservationStatus = "settled"
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_reservations (
			quota_reservation_id, organization_id, application_id, environment_id,
			logical_request_id, idempotency_key, status, created_at, expires_at, settled_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			statement_timestamp() - interval '3 minutes',
			statement_timestamp() + interval '1 hour',
			CASE WHEN $7 = 'settled' THEN statement_timestamp() ELSE NULL END
		)
	`, fixture.reservationID, quotaMigrationOrganizationID,
		quotaMigrationApplicationID, quotaMigrationEnvironmentID,
		fixture.logicalRequestID, "attempt-accounting-"+fixture.reservationID,
		reservationStatus); err != nil {
		t.Fatalf("insert attempt-accounting reservation: %v", err)
	}
	settled, released := int64(0), int64(0)
	if terminal {
		settled = 7
	}
	entryStatement := `
		INSERT INTO quota_reservation_entries (
			quota_reservation_entry_id, organization_id, application_id,
			environment_id, quota_reservation_id, quota_bucket_id,
			reserved_units, settled_units, released_units
		) VALUES ($1, $2, $3, $4, $5, $6, 7, $7, $8)
	`
	if schema12Writer {
		entryStatement = `
			INSERT INTO quota_reservation_entries (
				quota_reservation_entry_id, organization_id, application_id,
				environment_id, quota_reservation_id, quota_bucket_id,
				origin_attempt_number, initial_reserved_units, reserved_units,
				settled_units, released_units
			) VALUES ($1, $2, $3, $4, $5, $6, 1, 7, 7, $7, $8)
		`
	}
	if _, err := pool.Exec(ctx, entryStatement, fixture.entryID,
		quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, fixture.reservationID, fixture.bucketID,
		settled, released); err != nil {
		t.Fatalf("insert attempt-accounting reservation entry: %v", err)
	}
	attemptStatus := "started"
	if terminal {
		attemptStatus = "failed"
	}
	attemptStatement := `
		INSERT INTO upstream_attempts (
			upstream_attempt_id, organization_id, application_id, environment_id,
			logical_request_id, attempt_number, route_key, upstream_key,
			physical_model, status, started_at, completed_at, http_status, failure_code
		) VALUES (
			$1, $2, $3, $4, $5, 1, 'primary', 'provider', 'provider/model-v1', $6,
			statement_timestamp() - interval '2 minutes',
			CASE WHEN $6 = 'failed' THEN statement_timestamp() ELSE NULL END,
			CASE WHEN $6 = 'failed' THEN 502 ELSE NULL END,
			CASE WHEN $6 = 'failed' THEN 'legacy_failure' ELSE NULL END
		)
	`
	if schema12Writer {
		attemptStatement = `
			INSERT INTO upstream_attempts (
				upstream_attempt_id, organization_id, application_id, environment_id,
				logical_request_id, attempt_number, route_key, upstream_key,
				physical_model, model_key, attempt_decision_binding_version,
				attempt_decision_sha256, input_accounting_binding_version,
				status, started_at, completed_at, http_status, failure_code
			) VALUES (
				$1, $2, $3, $4, $5, 1, 'primary', 'provider',
				'provider/model-v1', 'model-v1', 1,
				decode(repeat('22', 32), 'hex'), 1, $6,
				statement_timestamp() - interval '2 minutes',
				CASE WHEN $6 = 'failed' THEN statement_timestamp() ELSE NULL END,
				CASE WHEN $6 = 'failed' THEN 502 ELSE NULL END,
				CASE WHEN $6 = 'failed' THEN 'legacy_failure' ELSE NULL END
			)
		`
	}
	if _, err := pool.Exec(ctx, attemptStatement, fixture.attemptID,
		quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, fixture.logicalRequestID, attemptStatus); err != nil {
		t.Fatalf("insert attempt-accounting upstream attempt: %v", err)
	}
	if schema12Writer {
		if _, err := pool.Exec(ctx, `
			INSERT INTO upstream_attempt_quota_entries (
				organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, quota_reservation_id,
				quota_reservation_entry_id, quota_bucket_id, metric, allocated_units
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'output_tokens', 7)
		`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
			quotaMigrationEnvironmentID, fixture.logicalRequestID, fixture.attemptID,
			fixture.reservationID, fixture.entryID, fixture.bucketID); err != nil {
			t.Fatalf("insert schema-12 attempt allocation: %v", err)
		}
	}
	return fixture
}

func seedQuotaAttemptAccountingV12(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixtureNumber int,
) quotaAttemptAccountingFixture {
	t.Helper()
	return seedQuotaAttemptAccounting(t, ctx, pool, fixtureNumber, false, true)
}

func settleQuotaAttemptAccountingWithSchema11Writer(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture quotaAttemptAccountingFixture,
) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin schema-11 final settlement: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(operation, statement string, arguments ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	exec("settle schema-11 bucket", `
		UPDATE quota_buckets
		SET used_units = 7, reserved_units = 0
		WHERE quota_bucket_id = $1
	`, fixture.bucketID)
	exec("settle schema-11 reservation entry", `
		UPDATE quota_reservation_entries
		SET settled_units = 7, released_units = 0
		WHERE quota_reservation_entry_id = $1
	`, fixture.entryID)
	exec("settle schema-11 reservation", `
		UPDATE quota_reservations
		SET status = 'settled', settled_at = CURRENT_TIMESTAMP
		WHERE quota_reservation_id = $1
	`, fixture.reservationID)
	exec("complete schema-11 logical request", `
		UPDATE logical_requests
		SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
		    failure_code = 'legacy_failure'
		WHERE logical_request_id = $1
	`, fixture.logicalRequestID)
	exec("complete schema-11 upstream attempt", `
		UPDATE upstream_attempts
		SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
		    http_status = 502, failure_code = 'legacy_failure'
		WHERE upstream_attempt_id = $1
	`, fixture.attemptID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit schema-11 final settlement: %v", err)
	}
}

func quotaAttemptAccountingIDs(fixtureNumber int) quotaAttemptAccountingFixture {
	suffix := func(prefix string) string {
		return fmt.Sprintf("%s_%026d", prefix, fixtureNumber)
	}
	return quotaAttemptAccountingFixture{
		logicalRequestID: suffix("req"), reservationID: suffix("qrs"),
		entryID: suffix("qre"), bucketID: suffix("qbk"), attemptID: suffix("atm"),
	}
}

func countDatabaseRows(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	statement string,
	arguments ...any,
) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, statement, arguments...).Scan(&count); err != nil {
		t.Fatalf("count database rows: %v", err)
	}
	return count
}

func insertQuotaMigrationBucket(ctx context.Context, pool *pgxpool.Pool, fixture quotaBucketFixture) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO quota_buckets (
			quota_bucket_id,
			organization_id,
			application_id,
			environment_id,
			limit_plan_key,
			rule_key,
			metric,
			scope_type,
			scope_dimensions,
			scope_key,
			algorithm,
			window_key,
			hard_maximum
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text[], $10, $11, $12, $13)
	`,
		fixture.ID,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		fixture.LimitPlanKey,
		fixture.RuleKey,
		fixture.Metric,
		fixture.ScopeType,
		fixture.ScopeDimensions,
		fixture.ScopeKey,
		fixture.Algorithm,
		fixture.WindowKey,
		fixture.HardMaximum,
	)
	return err
}

func insertQuotaMigrationLogicalRequest(
	ctx context.Context,
	pool *pgxpool.Pool,
	logicalRequestID string,
	featureKey string,
) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id,
			organization_id,
			application_id,
			environment_id,
			application_user_id,
			installation_id,
			session_grant_id,
			config_revision_id,
			feature_key,
			protocol,
			status
		) VALUES (
			$1, $2, $3, $4,
			'usr_00000000000000000000000001',
			'ins_00000000000000000000000001',
			'sgr_00000000000000000000000001',
			'rev_00000000000000000000000001',
			$5, 'openai_chat', 'reserved'
		)
	`,
		logicalRequestID,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		featureKey,
	)
	return err
}

func assertQuotaMigrationCatalog(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	var (
		clientRequestUnique    bool
		clientRequestPredicate string
	)
	if err := pool.QueryRow(ctx, `
		SELECT
			index_entry.indisunique,
			pg_get_expr(index_entry.indpred, index_entry.indrelid)
		FROM pg_index AS index_entry
		JOIN pg_class AS index_relation ON index_relation.oid = index_entry.indexrelid
		WHERE index_relation.oid = 'logical_requests_client_request_idx'::regclass
	`).Scan(&clientRequestUnique, &clientRequestPredicate); err != nil {
		t.Fatalf("read client request correlation index: %v", err)
	}
	if clientRequestUnique || !strings.Contains(clientRequestPredicate, "client_request_id IS NOT NULL") {
		t.Fatalf(
			"client correlation index unique=%t predicate=%q",
			clientRequestUnique,
			clientRequestPredicate,
		)
	}

	var reservationConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'quota_reservations'::regclass
		  AND conname = 'quota_reservations_logical_request_key'
	`).Scan(&reservationConstraint); err != nil {
		t.Fatalf("read reservation request identity constraint: %v", err)
	}
	if reservationConstraint != "UNIQUE (environment_id, logical_request_id)" {
		t.Fatalf("reservation request identity constraint = %q", reservationConstraint)
	}

	var bucketIdentityConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'quota_buckets'::regclass
		  AND conname = 'quota_buckets_identity_key'
	`).Scan(&bucketIdentityConstraint); err != nil {
		t.Fatalf("read bucket identity constraint: %v", err)
	}
	if bucketIdentityConstraint != "UNIQUE (environment_id, limit_plan_key, rule_key, metric, algorithm, window_key, scope_key)" {
		t.Fatalf("bucket identity constraint = %q", bucketIdentityConstraint)
	}

	var tenantScopeIndexPresent bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('quota_buckets_tenant_scope_idx') IS NOT NULL
	`).Scan(&tenantScopeIndexPresent); err != nil {
		t.Fatalf("read tenant scope index: %v", err)
	}
	if !tenantScopeIndexPresent {
		t.Fatal("tenant scope lookup index is missing")
	}
}

func seedQuotaMigrationTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name)
		VALUES ($1, 'quota-migration', 'Quota Migration')
	`, quotaMigrationOrganizationID); err != nil {
		t.Fatalf("insert quota migration organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name)
		VALUES ($1, $2, 'quota-app', 'Quota App')
	`, quotaMigrationApplicationID, quotaMigrationOrganizationID); err != nil {
		t.Fatalf("insert quota migration application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind
		) VALUES ($1, $2, $3, 'production', 'Production', 'production')
	`, quotaMigrationEnvironmentID, quotaMigrationOrganizationID, quotaMigrationApplicationID); err != nil {
		t.Fatalf("insert quota migration environment: %v", err)
	}
}

func seedQuotaMigrationRequestDependencies(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name
		) VALUES (
			'adm_00000000000000000000000001',
			'quota@example.test',
			'quota@example.test',
			'Quota Admin'
		)
	`); err != nil {
		t.Fatalf("insert quota migration admin: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role
		) VALUES (
			'amb_00000000000000000000000001',
			$1,
			'adm_00000000000000000000000001',
			'owner'
		)
	`, quotaMigrationOrganizationID); err != nil {
		t.Fatalf("insert quota migration admin membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id,
			organization_id,
			application_id,
			environment_id,
			revision_number,
			etag,
			status,
			document,
			created_by_admin_user_id
		) VALUES (
			'rev_00000000000000000000000001',
			$1, $2, $3, 1, 'feature-etag-001', 'draft', '{}'::jsonb,
			'adm_00000000000000000000000001'
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID, quotaMigrationEnvironmentID); err != nil {
		t.Fatalf("insert quota migration config revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id
		) VALUES (
			'usr_00000000000000000000000001', $1, $2
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID); err != nil {
		t.Fatalf("insert quota migration application user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id,
			organization_id,
			application_id,
			environment_id,
			application_user_id,
			platform,
			dpop_jkt,
			dpop_public_jwk,
			key_storage,
			trust_level
		) VALUES (
			'ins_00000000000000000000000001',
			$1, $2, $3,
			'usr_00000000000000000000000001',
			'ios', $4, '{}'::jsonb, 'unknown', 'debug'
		)
	`,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		strings.Repeat("j", 43),
	); err != nil {
		t.Fatalf("insert quota migration installation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id,
			organization_id,
			application_id,
			environment_id,
			application_user_id,
			installation_id,
			access_token_jti_hash,
			dpop_jkt,
			policy_revision_id,
			trust_level,
			identity_verified_at,
			issued_at,
			expires_at
		) VALUES (
			'sgr_00000000000000000000000001',
			$1, $2, $3,
			'usr_00000000000000000000000001',
			'ins_00000000000000000000000001',
			decode(repeat('11', 32), 'hex'),
			$4,
			'rev_00000000000000000000000001',
			'debug',
			CURRENT_TIMESTAMP - interval '1 minute',
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP + interval '1 hour'
		)
	`,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		strings.Repeat("j", 43),
	); err != nil {
		t.Fatalf("insert quota migration session grant: %v", err)
	}
}

func expectPostgreSQLConstraintError(t *testing.T, err error, code, constraint string) {
	t.Helper()

	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		t.Fatalf("database error = %v, want PostgreSQL %s", err, code)
	}
	if pgError.Code != code {
		t.Fatalf("database error code = %s, want %s: %v", pgError.Code, code, err)
	}
	if constraint != "" && pgError.ConstraintName != constraint {
		t.Fatalf("database constraint = %q, want %q: %v", pgError.ConstraintName, constraint, err)
	}
}
