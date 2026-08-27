package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

var secretIntegrationSchemaPattern = regexp.MustCompile(`^latchway_secret_test_[0-9]+$`)

func TestMasterKeyConsistencyPostgreSQL(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	provider := testEnvironmentMasterKey(t, 0xa1)
	wrongProvider := testEnvironmentMasterKey(t, 0xa2)

	if err := CheckMasterKeyConsistency(ctx, pool, provider); err != nil {
		t.Fatalf("check empty secret store: %v", err)
	}
	scope, adminUserID := insertSecretTenant(t, ctx, pool, now.Add(-time.Hour))
	insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "startup-key", 1,
		[]byte("startup-consistency-fixture"), now.Add(-time.Minute), "", provider.KeyID())
	if err := CheckMasterKeyConsistency(ctx, pool, provider); err != nil {
		t.Fatalf("check matching persisted secret: %v", err)
	}
	err := CheckMasterKeyConsistency(ctx, pool, wrongProvider)
	if !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("changed master key error = %v", err)
	}
	if strings.Contains(err.Error(), provider.KeyID()) || strings.Contains(err.Error(), wrongProvider.KeyID()) {
		t.Fatalf("changed master-key error exposed key metadata: %v", err)
	}
}

func TestStorePostgreSQLActiveRotationAndIsolation(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, now.Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xb1)
	observedNow := now
	store, err := NewStore(StoreConfig{Pool: pool, Provider: provider, Now: func() time.Time { return observedNow }})
	if err != nil {
		t.Fatalf("construct PostgreSQL secret store: %v", err)
	}

	firstID := insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "identity-key", 1,
		[]byte("identity-v1"), now.Add(-30*time.Minute), "", provider.KeyID())
	value, retained, err := captureSecret(ctx, store, scope, "secret/identity-key")
	if err != nil || string(value) != "identity-v1" {
		t.Fatalf("read active v1 value=%q err=%v", value, err)
	}
	if !allZero(retained) {
		t.Fatalf("PostgreSQL callback retained plaintext: %x", retained)
	}
	clear(value)

	wrongOrganization := scope
	wrongOrganization.OrganizationID = mustSecretID(t, id.Organization)
	if err := store.Use(ctx, wrongOrganization, "secret/identity-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("cross-organization lookup error = %v", err)
	}
	wrongApplication := scope
	wrongApplication.ApplicationID = mustSecretID(t, id.Application)
	if err := store.Use(ctx, wrongApplication, "secret/identity-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("cross-application lookup error = %v", err)
	}
	wrongIDType := scope
	wrongIDType.OrganizationID = scope.ApplicationID
	if err := store.Use(ctx, wrongIDType, "secret/identity-key", func([]byte) error { return nil }); err != ErrInvalid {
		t.Fatalf("wrong identifier type error = %v", err)
	}
	if err := store.Use(ctx, scope, "identity-key", func([]byte) error { return nil }); err != ErrInvalid {
		t.Fatalf("untyped reference error = %v", err)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin secret rotation: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE secret_records
		SET rotated_at = $2
		WHERE secret_record_id = $1 AND rotated_at IS NULL AND destroyed_at IS NULL
	`, firstID, now.Add(-10*time.Minute)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("rotate first secret version: %v", err)
	}
	secondID := insertEncryptedSecret(t, ctx, tx, provider, scope, adminUserID, "identity-key", 2,
		[]byte("identity-v2"), now.Add(-5*time.Minute), "", provider.KeyID())
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit secret rotation: %v", err)
	}
	value, retained, err = captureSecret(ctx, store, scope, "secret/identity-key")
	if err != nil || string(value) != "identity-v2" {
		t.Fatalf("read active v2 value=%q err=%v", value, err)
	}
	if !allZero(retained) {
		t.Fatalf("rotated callback retained plaintext: %x", retained)
	}
	clear(value)

	wrongMasterStore, err := NewStore(StoreConfig{Pool: pool, Provider: testEnvironmentMasterKey(t, 0xb2), Now: func() time.Time { return observedNow }})
	if err != nil {
		t.Fatalf("construct wrong-master store: %v", err)
	}
	if err := wrongMasterStore.Use(ctx, scope, "secret/identity-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("wrong master key error = %v", err)
	}

	insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "wrong-aad", 1,
		[]byte("wrong-aad-value"), now.Add(-time.Minute), mustSecretID(t, id.SecretRecord), provider.KeyID())
	if err := store.Use(ctx, scope, "secret/wrong-aad", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("wrong AAD error = %v", err)
	}
	insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "wrong-key-id", 1,
		[]byte("wrong-key-value"), now.Add(-time.Minute), "", "env_wrong-key")
	if err := store.Use(ctx, scope, "secret/wrong-key-id", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("wrong key identifier error = %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE secret_records SET destroyed_at = $2 WHERE secret_record_id = $1`, secondID, now); err != nil {
		t.Fatalf("destroy active secret: %v", err)
	}
	if err := store.Use(ctx, scope, "secret/identity-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("destroyed active version error = %v", err)
	}
}

func TestStorePostgreSQLLifecycleWindowsFailClosed(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, now.Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xc1)
	observedNow := now
	store, err := NewStore(StoreConfig{Pool: pool, Provider: provider, Now: func() time.Time { return observedNow }})
	if err != nil {
		t.Fatalf("construct PostgreSQL secret store: %v", err)
	}

	rotatedID := insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "rotated-key", 1,
		[]byte("rotated"), now.Add(-10*time.Minute), "", provider.KeyID())
	if _, err := pool.Exec(ctx, `UPDATE secret_records SET rotated_at = $2 WHERE secret_record_id = $1`, rotatedID, now.Add(-time.Minute)); err != nil {
		t.Fatalf("mark secret rotated: %v", err)
	}
	if err := store.Use(ctx, scope, "secret/rotated-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("rotated record error = %v", err)
	}

	destroyedID := insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "destroyed-key", 1,
		[]byte("destroyed"), now.Add(-10*time.Minute), "", provider.KeyID())
	if _, err := pool.Exec(ctx, `UPDATE secret_records SET destroyed_at = $2 WHERE secret_record_id = $1`, destroyedID, now.Add(-time.Minute)); err != nil {
		t.Fatalf("mark secret destroyed: %v", err)
	}
	if err := store.Use(ctx, scope, "secret/destroyed-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("destroyed record error = %v", err)
	}

	insertEncryptedSecret(t, ctx, pool, provider, scope, adminUserID, "future-key", 1,
		[]byte("future"), now.Add(time.Minute), "", provider.KeyID())
	if err := store.Use(ctx, scope, "secret/future-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("future record error = %v", err)
	}
	observedNow = now.Add(2 * time.Minute)
	value, retained, err := captureSecret(ctx, store, scope, "secret/future-key")
	if err != nil || string(value) != "future" || !allZero(retained) {
		t.Fatalf("matured future record value=%q retained=%x err=%v", value, retained, err)
	}
	clear(value)

	if _, err := pool.Exec(ctx, `
		UPDATE environments
		SET status = 'disabled', disabled_at = $2, updated_at = $2
		WHERE environment_id = $1
	`, scope.EnvironmentID, observedNow); err != nil {
		t.Fatalf("disable environment: %v", err)
	}
	if err := store.Use(ctx, scope, "secret/future-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("disabled environment error = %v", err)
	}
}

type secretFixtureExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertEncryptedSecret(t *testing.T, ctx context.Context, executor secretFixtureExecutor, provider Provider, scope Scope, adminUserID, name string, version int64, plaintext []byte, createdAt time.Time, aadSecretID, storedMasterKeyID string) string {
	t.Helper()
	recordID := mustSecretID(t, id.SecretRecord)
	if aadSecretID == "" {
		aadSecretID = recordID
	}
	envelope, err := provider.Encrypt(plaintext, AssociatedData{
		OrganizationID: scope.OrganizationID,
		EnvironmentID:  scope.EnvironmentID,
		SecretID:       aadSecretID,
		SecretVersion:  version,
		FormatVersion:  formatVersion,
	})
	if err != nil {
		t.Fatalf("encrypt PostgreSQL secret fixture: %v", err)
	}
	if storedMasterKeyID == "" {
		storedMasterKeyID = envelope.KeyID
	}
	if _, err := executor.Exec(ctx, `
		INSERT INTO secret_records (
			secret_record_id, organization_id, application_id, environment_id,
			name, version, encryption_format_version, algorithm,
			master_key_identifier, ciphertext, nonce, created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'aes-256-gcm', $8, $9, $10, $11, $12)
	`, recordID, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID, name, version,
		int16(envelope.FormatVersion), storedMasterKeyID, envelope.Ciphertext, envelope.Nonce, adminUserID, createdAt); err != nil {
		t.Fatalf("insert PostgreSQL secret fixture: %v", err)
	}
	return recordID
}

func insertSecretTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, createdAt time.Time) (Scope, string) {
	t.Helper()
	scope := testSecretScope(t)
	adminUserID := mustSecretID(t, id.AdminUser)
	adminMembershipID := mustSecretID(t, id.AdminMembership)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin secret tenant fixtures: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, 'secret-test', 'Secret Test', $2, $2)
	`, scope.OrganizationID, createdAt); err != nil {
		t.Fatalf("insert secret organization fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, $2, 'secret-app', 'Secret App', $3, $3)
	`, scope.ApplicationID, scope.OrganizationID, createdAt); err != nil {
		t.Fatalf("insert secret application fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind, created_at, updated_at
		) VALUES ($1, $2, $3, 'secret-env', 'Secret Environment', 'production', $4, $4)
	`, scope.EnvironmentID, scope.OrganizationID, scope.ApplicationID, createdAt); err != nil {
		t.Fatalf("insert secret environment fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name, created_at, updated_at)
		VALUES ($1, 'secret-test@example.test', 'secret-test@example.test', 'Secret Admin', $2, $2)
	`, adminUserID, createdAt); err != nil {
		t.Fatalf("insert secret admin fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, created_at, updated_at
		) VALUES ($1, $2, $3, 'owner', $4, $4)
	`, adminMembershipID, scope.OrganizationID, adminUserID, createdAt); err != nil {
		t.Fatalf("insert secret membership fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit secret tenant fixtures: %v", err)
	}
	return scope, adminUserID
}

func captureSecret(ctx context.Context, store *Store, scope Scope, reference string) (copyOfValue, retained []byte, err error) {
	err = store.Use(ctx, scope, reference, func(value []byte) error {
		retained = value
		copyOfValue = append([]byte(nil), value...)
		return nil
	})
	return copyOfValue, retained, err
}

func isolatedSecretPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_secret_test_%d", time.Now().UnixNano())
	if !secretIntegrationSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create secret test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsedURL.String(), 4)
	if err != nil {
		t.Fatalf("open isolated secret database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, ctx
}
