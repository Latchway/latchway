package database

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database/dbsql"
)

func TestGeneratedAppAttestKeyPersistenceShape(t *testing.T) {
	t.Parallel()
	typeOf := reflect.TypeOf(dbsql.AttestationKey{})
	for fieldName, columnName := range map[string]string{
		"ApplicationUserID":     "application_user_id",
		"BindingEnvironment":    "binding_environment",
		"Platform":              "platform",
		"DpopJkt":               "dpop_jkt",
		"ProviderKeyHash":       "provider_key_hash",
		"AppIDHash":             "app_id_hash",
		"LastAssertionHash":     "last_assertion_hash",
		"ExtensionsPresent":     "extensions_present",
		"ValidationCategory":    "validation_category",
		"BundleVersion":         "bundle_version",
		"AttestedAtUnixSeconds": "attested_at_unix_seconds",
		"AttestedAtNanosecond":  "attested_at_nanosecond",
		"LinkedAt":              "linked_at",
	} {
		field, ok := typeOf.FieldByName(fieldName)
		if !ok || field.Tag.Get("db") != columnName {
			t.Errorf("generated AttestationKey.%s db tag=%q want=%q",
				fieldName, field.Tag.Get("db"), columnName)
		}
	}
	installation, ok := typeOf.FieldByName("InstallationID")
	if !ok || installation.Type.Kind() != reflect.Pointer {
		t.Fatalf("generated nullable installation field = %#v", installation)
	}
	receiptType := reflect.TypeOf(dbsql.AppAttestKeyCommitReceipt{})
	for fieldName, columnName := range map[string]string{
		"CommitToken":      "commit_token",
		"OrganizationID":   "organization_id",
		"ApplicationID":    "application_id",
		"EnvironmentID":    "environment_id",
		"AttestationKeyID": "attestation_key_id",
		"SignCount":        "sign_count",
		"CommittedAt":      "committed_at",
		"ExpiresAt":        "expires_at",
	} {
		field, exists := receiptType.FieldByName(fieldName)
		if !exists || field.Tag.Get("db") != columnName {
			t.Errorf("generated AppAttestKeyCommitReceipt.%s db tag=%q want=%q",
				fieldName, field.Tag.Get("db"), columnName)
		}
	}
}

func TestMigratorPostgreSQLUpgradeV12AppAttestKeyPersistence(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 12)

	const (
		organizationID    = "org_00000000000000000000000081"
		applicationID     = "app_00000000000000000000000081"
		productionID      = "env_00000000000000000000000081"
		stagingID         = "env_00000000000000000000000082"
		applicationUserID = "usr_00000000000000000000000081"
		legacyInstallID   = "ins_00000000000000000000000081"
		matchingInstallID = "ins_00000000000000000000000082"
		wrongInstallID    = "ins_00000000000000000000000083"
		legacyDebugKeyID  = "aky_00000000000000000000000081"
		legacyAppleKeyID  = "aky_00000000000000000000000082"
		preSessionKeyID   = "aky_00000000000000000000000083"
	)
	anchor := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	legacyDPoPJKT := strings.Repeat("d", 43)
	appAttestDPoPJKT := strings.Repeat("p", 43)
	wrongDPoPJKT := strings.Repeat("w", 43)
	seedAppAttestMigrationTenant(t, ctx, pool, appAttestMigrationTenant{
		organizationID: organizationID, applicationID: applicationID,
		productionID: productionID, stagingID: stagingID,
		applicationUserID: applicationUserID, createdAt: anchor,
	})
	insertAppAttestMigrationInstallation(t, ctx, pool, organizationID, applicationID,
		productionID, applicationUserID, legacyInstallID, "ios", legacyDPoPJKT, anchor)
	for _, legacy := range []struct {
		id       string
		provider string
		keyID    string
	}{
		{id: legacyDebugKeyID, provider: "debug", keyID: "legacy-debug"},
		{id: legacyAppleKeyID, provider: "app_attest", keyID: "legacy-app-attest"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO attestation_keys (
				attestation_key_id, organization_id, application_id, environment_id,
				installation_id, provider, provider_key_id, public_key,
				environment, sign_count, status, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'production', 0, 'active', $9, $9)
		`, legacy.id, organizationID, applicationID, productionID, legacyInstallID,
			legacy.provider, legacy.keyID, bytes.Repeat([]byte{0x44}, 65), anchor); err != nil {
			t.Fatalf("insert legacy %s key: %v", legacy.provider, err)
		}
	}

	if err := NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("upgrade through App Attest key persistence: %v", err)
	}
	current, available, err := NewMigrator(pool).Status(ctx)
	if err != nil || current != 16 || available != 16 {
		t.Fatalf("migration status current=%d available=%d err=%v", current, available, err)
	}

	var principal, bindingEnvironment, platform, dpopJKT, debugStatus string
	var linkedAt *time.Time
	if err := pool.QueryRow(ctx, `
		SELECT application_user_id, binding_environment, platform, dpop_jkt,
		       status, linked_at
		FROM attestation_keys WHERE attestation_key_id = $1
	`, legacyDebugKeyID).Scan(
		&principal, &bindingEnvironment, &platform, &dpopJKT, &debugStatus, &linkedAt,
	); err != nil {
		t.Fatalf("read upgraded debug key: %v", err)
	}
	if principal != applicationUserID || bindingEnvironment != "production" || platform != "ios" ||
		dpopJKT != legacyDPoPJKT || debugStatus != "active" || linkedAt == nil || !linkedAt.Equal(anchor) {
		t.Fatalf("unexpected upgraded debug key principal=%q binding=%q platform=%q dpop=%q status=%q linked=%v",
			principal, bindingEnvironment, platform, dpopJKT, debugStatus, linkedAt)
	}
	var appleStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM attestation_keys WHERE attestation_key_id = $1`, legacyAppleKeyID).Scan(&appleStatus); err != nil || appleStatus != "invalid" {
		t.Fatalf("legacy App Attest status=%q err=%v want invalid", appleStatus, err)
	}

	providerHash := bytes.Repeat([]byte{0x51}, 32)
	providerKeyID := base64.StdEncoding.EncodeToString(providerHash)
	publicKey := append([]byte{4}, bytes.Repeat([]byte{0x61}, 64)...)
	appIDHash := bytes.Repeat([]byte{0x71}, 32)
	if err := insertPreSessionAppAttestMigrationKey(t, ctx, pool, preSessionKeyID,
		organizationID, applicationID, productionID, applicationUserID,
		"production", "react_native_ios", appAttestDPoPJKT,
		providerKeyID, providerHash, publicKey, appIDHash, anchor); err != nil {
		t.Fatalf("insert pre-session App Attest key: %v", err)
	}
	var installationID *string
	if err := pool.QueryRow(ctx, `
		SELECT installation_id FROM attestation_keys WHERE attestation_key_id = $1
	`, preSessionKeyID).Scan(&installationID); err != nil || installationID != nil {
		t.Fatalf("pre-session installation=%v err=%v want NULL", installationID, err)
	}
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, provider, environment,
			binding_environment, platform, dpop_jkt, sign_count, status,
			created_at, updated_at, linked_at
		) VALUES (
			'aky_00000000000000000000000089', $1, $2, $3, $4, NULL,
			'debug', 'production', 'production', 'react_native_ios', $5,
			0, 'active', $6, $6, NULL
		)
	`, []any{organizationID, applicationID, productionID, applicationUserID,
		strings.Repeat("n", 43), anchor}, "23514", "attestation_keys_pre_session_provider_check")

	for index, nullable := range []struct {
		attestedSeconds any
		attestedNanos   any
		category        any
	}{
		{attestedSeconds: nil, attestedNanos: int32(123456789), category: int64(4)},
		{attestedSeconds: anchor.Unix(), attestedNanos: nil, category: int64(4)},
		{attestedSeconds: anchor.Unix(), attestedNanos: int32(123456789), category: nil},
	} {
		nullHash := bytes.Repeat([]byte{byte(0x61 + index)}, 32)
		err := insertNullableStateAppAttestMigrationKey(
			ctx, pool, "aky_0000000000000000000000008"+string(rune('6'+index)),
			organizationID, applicationID, productionID, applicationUserID,
			base64.StdEncoding.EncodeToString(nullHash), nullHash, publicKey, appIDHash,
			strings.Repeat(string(rune('q'+index)), 43), nullable.attestedSeconds,
			nullable.attestedNanos, nullable.category, anchor,
		)
		var constraintError *pgconn.PgError
		if !errors.As(err, &constraintError) || constraintError.Code != "23514" ||
			constraintError.ConstraintName != "attestation_keys_app_attest_state_check" {
			t.Fatalf("nullable App Attest state %d error=%v", index, err)
		}
	}

	receiptToken := bytes.Repeat([]byte{0x91}, 32)
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_attest_key_commit_receipts (
			commit_token, organization_id, application_id, environment_id,
			attestation_key_id, sign_count
		) VALUES ($1, $2, $3, $4, $5, 0)
	`, receiptToken, organizationID, applicationID, productionID, preSessionKeyID); err != nil {
		t.Fatalf("insert exact App Attest commit receipt scope: %v", err)
	}
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		INSERT INTO app_attest_key_commit_receipts (
			commit_token, organization_id, application_id, environment_id,
			attestation_key_id, sign_count
		) VALUES ($1, $2, $3, $4, $5, 0)
	`, []any{bytes.Repeat([]byte{0x92}, 32), organizationID, applicationID, stagingID, preSessionKeyID},
		"23503", "app_attest_key_commit_receipts_key_scope_fkey")
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		INSERT INTO app_attest_key_commit_receipts (
			commit_token, organization_id, application_id, environment_id,
			attestation_key_id, sign_count
		) VALUES ($1, $2, $3, $4, $5, 0)
	`, []any{make([]byte, 32), organizationID, applicationID, productionID, preSessionKeyID},
		"23514", "app_attest_key_commit_receipts_token_check")

	assertAppAttestMigrationConstraint(t, ctx, pool,
		`UPDATE attestation_keys SET environment_id = $2 WHERE attestation_key_id = $1`,
		[]any{preSessionKeyID, stagingID}, "23514", "attestation_keys_immutable_scope_check")

	mismatchedHash := bytes.Repeat([]byte{0x52}, 32)
	err = insertPreSessionAppAttestMigrationKey(t, ctx, pool,
		"aky_00000000000000000000000085", organizationID, applicationID,
		productionID, applicationUserID, "staging", "react_native_ios",
		strings.Repeat("m", 43), base64.StdEncoding.EncodeToString(mismatchedHash),
		mismatchedHash, publicKey, appIDHash, anchor)
	var constraintError *pgconn.PgError
	if !errors.As(err, &constraintError) || constraintError.Code != "23503" ||
		constraintError.ConstraintName != "attestation_keys_binding_environment_fkey" {
		t.Fatalf("mismatched binding environment error=%v", err)
	}

	duplicateKeyID := "aky_00000000000000000000000084"
	_, err = pool.Exec(ctx, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, provider, provider_key_id,
			provider_key_hash, public_key, app_id_hash, environment,
			binding_environment, platform, dpop_jkt, sign_count, status,
			extensions_present, validation_category, bundle_version,
			attested_at_unix_seconds, attested_at_nanosecond, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, NULL, 'app_attest', $6,
			$7, $8, $9, 'production', 'staging', 'react_native_ios', $10,
			0, 'active', true, 4, '1.0', $11, 0, $12, $12
		)
	`, duplicateKeyID, organizationID, applicationID, stagingID, applicationUserID,
		providerKeyID, providerHash, publicKey, appIDHash, appAttestDPoPJKT,
		anchor.Unix(), anchor)
	constraintError = nil
	if !errors.As(err, &constraintError) || constraintError.Code != "23505" ||
		constraintError.ConstraintName != "attestation_keys_app_attest_provider_key_hash_idx" {
		t.Fatalf("duplicate global App Attest key error=%v", err)
	}

	insertAppAttestMigrationInstallation(t, ctx, pool, organizationID, applicationID,
		productionID, applicationUserID, wrongInstallID, "react_native_ios", wrongDPoPJKT, anchor.Add(time.Minute))
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		UPDATE attestation_keys SET installation_id = $2, linked_at = $3
		WHERE attestation_key_id = $1
	`, []any{preSessionKeyID, wrongInstallID, anchor.Add(2 * time.Minute)},
		"23503", "attestation_keys_installation_scope_fkey")

	insertAppAttestMigrationInstallation(t, ctx, pool, organizationID, applicationID,
		productionID, applicationUserID, matchingInstallID, "react_native_ios", appAttestDPoPJKT, anchor.Add(time.Minute))
	if _, err := pool.Exec(ctx, `
		UPDATE attestation_keys SET installation_id = $2, linked_at = $3
		WHERE attestation_key_id = $1
	`, preSessionKeyID, matchingInstallID, anchor.Add(2*time.Minute)); err != nil {
		t.Fatalf("link exact App Attest installation scope: %v", err)
	}
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		UPDATE attestation_keys SET installation_id = NULL, linked_at = NULL
		WHERE attestation_key_id = $1
	`, []any{preSessionKeyID}, "23514", "attestation_keys_immutable_link_check")

	firstAssertionHash := bytes.Repeat([]byte{0xa1}, 32)
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		UPDATE attestation_keys SET last_assertion_hash = $2, updated_at = $3
		WHERE attestation_key_id = $1
	`, []any{preSessionKeyID, firstAssertionHash, anchor.Add(3 * time.Minute)},
		"23514", "attestation_keys_app_attest_same_counter_state_check")
	if _, err := pool.Exec(ctx, `
		UPDATE attestation_keys
		SET sign_count = 5, last_assertion_hash = $2, updated_at = $3
		WHERE attestation_key_id = $1
	`, preSessionKeyID, firstAssertionHash, anchor.Add(3*time.Minute)); err != nil {
		t.Fatalf("advance App Attest migration counter: %v", err)
	}
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		UPDATE attestation_keys SET sign_count = 6, updated_at = $2
		WHERE attestation_key_id = $1
	`, []any{preSessionKeyID, anchor.Add(4 * time.Minute)},
		"23514", "attestation_keys_app_attest_counter_hash_check")
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		UPDATE attestation_keys SET sign_count = 4, updated_at = $2
		WHERE attestation_key_id = $1
	`, []any{preSessionKeyID, anchor.Add(5 * time.Minute)},
		"23514", "attestation_keys_app_attest_counter_monotonic_check")
	assertAppAttestMigrationConstraint(t, ctx, pool, `
		UPDATE attestation_keys SET status = 'active'
		WHERE attestation_key_id = $1
	`, []any{legacyAppleKeyID}, "23514", "attestation_keys_terminal_status_check")
}

type appAttestMigrationTenant struct {
	organizationID    string
	applicationID     string
	productionID      string
	stagingID         string
	applicationUserID string
	createdAt         time.Time
}

func seedAppAttestMigrationTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant appAttestMigrationTenant) {
	t.Helper()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at)
		  VALUES ($1, 'attest-upgrade', 'Attest Upgrade', $2, $2)`, []any{tenant.organizationID, tenant.createdAt}},
		{`INSERT INTO applications (application_id, organization_id, slug, display_name, created_at, updated_at)
		  VALUES ($1, $2, 'mobile-app', 'Mobile App', $3, $3)`, []any{tenant.applicationID, tenant.organizationID, tenant.createdAt}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, created_at, updated_at)
		  VALUES ($1, $2, $3, 'production', 'Production', 'production', $4, $4)`, []any{tenant.productionID, tenant.organizationID, tenant.applicationID, tenant.createdAt}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, created_at, updated_at)
		  VALUES ($1, $2, $3, 'staging', 'Staging', 'staging', $4, $4)`, []any{tenant.stagingID, tenant.organizationID, tenant.applicationID, tenant.createdAt}},
		{`INSERT INTO application_users (application_user_id, organization_id, application_id, created_at, updated_at)
		  VALUES ($1, $2, $3, $4, $4)`, []any{tenant.applicationUserID, tenant.organizationID, tenant.applicationID, tenant.createdAt}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed App Attest migration tenant: %v", err)
		}
	}
}

func insertAppAttestMigrationInstallation(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	organizationID, applicationID, environmentID, applicationUserID,
	installationID, platform, dpopJKT string,
	createdAt time.Time,
) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id,
			application_user_id, platform, dpop_jkt, dpop_public_jwk,
			key_storage, trust_level, created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, '{}'::jsonb,
		          'secure_enclave', 'app_verified', $8, $8, $8)
	`, installationID, organizationID, applicationID, environmentID,
		applicationUserID, platform, dpopJKT, createdAt); err != nil {
		t.Fatalf("insert App Attest migration installation: %v", err)
	}
}

func insertPreSessionAppAttestMigrationKey(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	attestationKeyID, organizationID, applicationID, environmentID, applicationUserID,
	bindingEnvironment, platform, dpopJKT, providerKeyID string,
	providerHash, publicKey, appIDHash []byte,
	createdAt time.Time,
) error {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, provider, provider_key_id,
			provider_key_hash, public_key, app_id_hash, environment,
			binding_environment, platform, dpop_jkt, sign_count, status,
			extensions_present, validation_category, bundle_version,
			attested_at_unix_seconds, attested_at_nanosecond, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, NULL, 'app_attest', $6,
			$7, $8, $9, 'production', $10, $11, $12, 0, 'active',
			true, 4, '1.0', $13, 123456789, $14, $14
		)
	`, attestationKeyID, organizationID, applicationID, environmentID,
		applicationUserID, providerKeyID, providerHash, publicKey, appIDHash,
		bindingEnvironment, platform, dpopJKT, createdAt.Unix(), createdAt)
	return err
}

func insertNullableStateAppAttestMigrationKey(
	ctx context.Context,
	pool *pgxpool.Pool,
	attestationKeyID, organizationID, applicationID, environmentID, applicationUserID,
	providerKeyID string,
	providerHash, publicKey, appIDHash []byte,
	dpopJKT string,
	attestedSeconds, attestedNanosecond, validationCategory any,
	createdAt time.Time,
) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, provider, provider_key_id,
			provider_key_hash, public_key, app_id_hash, environment,
			binding_environment, platform, dpop_jkt, sign_count, status,
			extensions_present, validation_category, bundle_version,
			attested_at_unix_seconds, attested_at_nanosecond, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, NULL, 'app_attest', $6,
			$7, $8, $9, 'production', 'production', 'react_native_ios', $10,
			0, 'active', true, $11, '1.0', $12, $13, $14, $14
		)
	`, attestationKeyID, organizationID, applicationID, environmentID,
		applicationUserID, providerKeyID, providerHash, publicKey, appIDHash, dpopJKT,
		validationCategory, attestedSeconds, attestedNanosecond, createdAt)
	return err
}

func assertAppAttestMigrationConstraint(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	statement string,
	args []any,
	code, constraint string,
) {
	t.Helper()
	_, err := pool.Exec(ctx, statement, args...)
	var constraintError *pgconn.PgError
	if !errors.As(err, &constraintError) || constraintError.Code != code ||
		constraintError.ConstraintName != constraint {
		t.Fatalf("constraint %s error=%v", constraint, err)
	}
}
