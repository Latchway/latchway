package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

func TestManagerPostgreSQLLifecycleRuntimeAndRedaction(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	fixtureNow := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, fixtureNow)
	provider := testEnvironmentMasterKey(t, 0xe1)
	manager := newTestSecretManager(t, pool, provider)
	principal := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleOwner)
	reader, err := NewStore(StoreConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatalf("construct runtime secret reader: %v", err)
	}

	createPlaintext := "lifecycle-create-plaintext-9347"
	createValue := []byte(createPlaintext)
	created, err := manager.Create(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID,
		Name:          "provider-key",
		Value:         createValue,
		RequestID:     mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !allZero(createValue) {
		t.Fatalf("Create() retained caller plaintext: %x", createValue)
	}
	if created.EnvironmentID != scope.EnvironmentID || created.Name != "provider-key" ||
		created.Version != 1 || created.Algorithm != storedEnvelopeAlgorithm ||
		created.MasterKeyID != provider.KeyID() || created.RotatedAt != nil {
		t.Fatalf("Create() metadata = %+v", created)
	}
	assertRuntimeSecret(t, ctx, reader, scope, "secret/provider-key", createPlaintext)

	rotatePlaintext := "lifecycle-rotate-plaintext-8251"
	rotateValue := []byte(rotatePlaintext)
	rotated, err := manager.Rotate(ctx, principal, RotateInput{
		SecretID: created.ID,
		Value:    rotateValue, RequestID: mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !allZero(rotateValue) {
		t.Fatalf("Rotate() retained caller plaintext: %x", rotateValue)
	}
	if rotated.ID == created.ID || rotated.Name != created.Name || rotated.Version != 2 ||
		rotated.CreatedAt.Before(created.CreatedAt) {
		t.Fatalf("Rotate() metadata = %+v after %+v", rotated, created)
	}
	assertRuntimeSecret(t, ctx, reader, scope, "secret/provider-key", rotatePlaintext)

	items, err := manager.List(ctx, principal, scope.EnvironmentID, PageRequest{Size: 50})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 || items[0].ID != rotated.ID || items[0].Version != 2 {
		t.Fatalf("List() items = %+v", items)
	}

	// Historical record IDs cannot delete a newer credential.
	if err := manager.Destroy(ctx, principal, DestroyInput{
		SecretID: created.ID, RequestID: mustSecretID(t, id.AdminRequest),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Destroy() through stale original version error = %v", err)
	}
	deleteInput := DestroyInput{SecretID: rotated.ID, RequestID: mustSecretID(t, id.AdminRequest)}
	if err := manager.Destroy(ctx, principal, deleteInput); err != nil {
		t.Fatalf("Destroy() through current version = %v", err)
	}
	if err := reader.Use(ctx, scope, "secret/provider-key", func([]byte) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("runtime read after Destroy() error = %v", err)
	}
	if err := manager.Destroy(ctx, principal, DestroyInput{
		SecretID: rotated.ID, RequestID: mustSecretID(t, id.AdminRequest),
	}); err != nil {
		t.Fatalf("idempotent Destroy() through tombstoned current version = %v", err)
	}

	// Tombstones are permanent: a logical name cannot be silently reset to v1.
	recreateValue := []byte("recreate-must-not-persist")
	_, err = manager.Create(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID, Name: "provider-key", Value: recreateValue,
		RequestID: mustSecretID(t, id.AdminRequest),
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() over tombstone error = %v", err)
	}
	if !allZero(recreateValue) || strings.Contains(err.Error(), "recreate-must-not-persist") {
		t.Fatalf("tombstone conflict retained or exposed plaintext: value=%x err=%v", recreateValue, err)
	}

	items, err = manager.List(ctx, principal, scope.EnvironmentID, PageRequest{Size: 50})
	if err != nil || len(items) != 0 {
		t.Fatalf("List() after destroy items=%+v err=%v", items, err)
	}
	var totalVersions, currentVersions, destroyedVersions int
	if err := pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE rotated_at IS NULL AND destroyed_at IS NULL),
		       count(*) FILTER (WHERE destroyed_at IS NOT NULL)
		FROM secret_records
		WHERE environment_id = $1 AND name = 'provider-key'
	`, scope.EnvironmentID).Scan(&totalVersions, &currentVersions, &destroyedVersions); err != nil {
		t.Fatalf("inspect destroyed versions: %v", err)
	}
	if totalVersions != 2 || currentVersions != 0 || destroyedVersions != 2 {
		t.Fatalf("version counts total=%d current=%d destroyed=%d", totalVersions, currentVersions, destroyedVersions)
	}

	assertSecretAuditShape(t, ctx, pool, scope.EnvironmentID, 1, 1, 2)
	assertPlaintextAbsentFromSecretPersistence(t, ctx, pool, createPlaintext, rotatePlaintext, "recreate-must-not-persist")
}

func TestManagerPostgreSQLAuthorizationAndTenantAntiEnumeration(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, time.Now().UTC().Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xe2)
	manager := newTestSecretManager(t, pool, provider)
	owner := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleOwner)
	created, err := manager.Create(ctx, owner, CreateInput{
		EnvironmentID: scope.EnvironmentID, Name: "tenant-key", Value: []byte("tenant-secret"),
		RequestID: mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("seed tenant secret: %v", err)
	}

	viewer := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleViewer)
	if _, err := manager.List(ctx, viewer, scope.EnvironmentID, PageRequest{Size: 50}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer List() error = %v", err)
	}
	deniedValue := []byte("viewer-secret")
	if _, err := manager.Rotate(ctx, viewer, RotateInput{
		SecretID: created.ID, Value: deniedValue, RequestID: mustSecretID(t, id.AdminRequest),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer Rotate() error = %v", err)
	}
	if !allZero(deniedValue) {
		t.Fatalf("viewer Rotate() retained plaintext: %x", deniedValue)
	}

	crossTenant := owner
	crossTenant.OrganizationID = mustSecretID(t, id.Organization)
	if _, err := manager.List(ctx, crossTenant, scope.EnvironmentID, PageRequest{Size: 50}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant List() error = %v", err)
	}
	crossCreateValue := []byte("cross-tenant-create")
	if _, err := manager.Create(ctx, crossTenant, CreateInput{
		EnvironmentID: scope.EnvironmentID, Name: "cross-key", Value: crossCreateValue,
		RequestID: mustSecretID(t, id.AdminRequest),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Create() error = %v", err)
	}
	if !allZero(crossCreateValue) {
		t.Fatalf("cross-tenant Create() retained plaintext: %x", crossCreateValue)
	}
	crossRotateValue := []byte("cross-tenant-rotate")
	if _, err := manager.Rotate(ctx, crossTenant, RotateInput{
		SecretID: created.ID, Value: crossRotateValue, RequestID: mustSecretID(t, id.AdminRequest),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Rotate() error = %v", err)
	}
	if !allZero(crossRotateValue) {
		t.Fatalf("cross-tenant Rotate() retained plaintext: %x", crossRotateValue)
	}
	if err := manager.Destroy(ctx, crossTenant, DestroyInput{
		SecretID: created.ID, RequestID: mustSecretID(t, id.AdminRequest),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Destroy() error = %v", err)
	}
	if err := manager.Destroy(ctx, owner, DestroyInput{
		SecretID: mustSecretID(t, id.SecretRecord), RequestID: mustSecretID(t, id.AdminRequest),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown Destroy() error = %v", err)
	}

	var crossRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM secret_records WHERE name = 'cross-key'`).Scan(&crossRows); err != nil {
		t.Fatalf("count cross-tenant records: %v", err)
	}
	if crossRows != 0 {
		t.Fatalf("cross-tenant mutation persisted %d rows", crossRows)
	}
}

func TestManagerPostgreSQLConcurrentRotationAndPostLockTime(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, time.Now().UTC().Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xe3)
	manager := newTestSecretManager(t, pool, provider)
	principal := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleOwner)
	created, err := manager.Create(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID, Name: "rotating-key", Value: []byte("rotation-v1"),
		RequestID: mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("seed rotating secret: %v", err)
	}

	const rotations = 8
	type rotateResult struct {
		metadata Metadata
		value    string
		cleared  bool
		err      error
	}
	results := make(chan rotateResult, rotations)
	requestIDs := make([]string, rotations)
	for index := range requestIDs {
		requestIDs[index] = mustSecretID(t, id.AdminRequest)
	}
	for index := range rotations {
		index := index
		go func() {
			expected := fmt.Sprintf("concurrent-rotation-%d", index)
			value := []byte(expected)
			metadata, rotateErr := manager.Rotate(ctx, principal, RotateInput{
				SecretID: created.ID, Value: value, RequestID: requestIDs[index],
			})
			results <- rotateResult{metadata: metadata, value: expected, cleared: allZero(value), err: rotateErr}
		}()
	}
	var winner rotateResult
	successes := 0
	conflicts := 0
	for range rotations {
		result := <-results
		if !result.cleared {
			t.Fatalf("concurrent Rotate() retained caller plaintext: err=%v", result.err)
		}
		switch {
		case result.err == nil:
			successes++
			winner = result
		case errors.Is(result.err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Rotate() unexpected error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != rotations-1 || winner.metadata.Version != 2 {
		t.Fatalf("concurrent rotations successes=%d conflicts=%d winner=%+v", successes, conflicts, winner.metadata)
	}
	var total, current int
	var maximumVersion int64
	if err := pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE rotated_at IS NULL AND destroyed_at IS NULL), max(version)
		FROM secret_records WHERE environment_id = $1 AND name = 'rotating-key'
	`, scope.EnvironmentID).Scan(&total, &current, &maximumVersion); err != nil {
		t.Fatalf("inspect concurrent rotations: %v", err)
	}
	if total != 2 || current != 1 || maximumVersion != 2 {
		t.Fatalf("rotations total=%d current=%d max=%d", total, current, maximumVersion)
	}
	reader, err := NewStore(StoreConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatalf("construct runtime reader: %v", err)
	}
	assertRuntimeSecret(t, ctx, reader, scope, "secret/rotating-key", winner.value)

	// Hold the same environment row used by configuration and secret writers,
	// prove Rotate is waiting on it, then verify its timestamp was captured only
	// after the lock became available.
	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire environment blocker: %v", err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin environment blocker: %v", err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	if _, err := blockerTx.Exec(ctx, `SELECT 1 FROM environments WHERE environment_id = $1 FOR UPDATE`, scope.EnvironmentID); err != nil {
		t.Fatalf("lock environment blocker: %v", err)
	}
	blockedResult := make(chan rotateResult, 1)
	go func() {
		expected := "post-lock-time-value"
		value := []byte(expected)
		metadata, rotateErr := manager.Rotate(ctx, principal, RotateInput{
			SecretID: winner.metadata.ID, Value: value, RequestID: mustIntegrationID(id.AdminRequest),
		})
		blockedResult <- rotateResult{metadata: metadata, value: expected, cleared: allZero(value), err: rotateErr}
	}()
	waitForSecretEnvironmentLock(t, ctx, pool)
	var beforeUnlock time.Time
	if err := blockerTx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&beforeUnlock); err != nil {
		t.Fatalf("read pre-unlock database time: %v", err)
	}
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release environment blocker: %v", err)
	}
	result := <-blockedResult
	if result.err != nil || !result.cleared {
		t.Fatalf("post-lock Rotate() err=%v cleared=%t", result.err, result.cleared)
	}
	if result.metadata.CreatedAt.Before(beforeUnlock.UTC()) {
		t.Fatalf("post-lock created_at=%s before unlock=%s", result.metadata.CreatedAt, beforeUnlock)
	}
}

func TestManagerPostgreSQLLifecycleSurvivesDatabaseClockRegression(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, time.Now().UTC().Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xea)
	manager := newTestSecretManager(t, pool, provider)
	principal := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleOwner)
	created, err := manager.Create(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID, Name: "clock-key", Value: []byte("clock-v1"),
		RequestID: mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("seed clock-regression secret: %v", err)
	}
	var futureCreatedAt time.Time
	if err := pool.QueryRow(ctx, `
		UPDATE secret_records
		SET created_at = clock_timestamp() + interval '2 hours'
		WHERE secret_record_id = $1
		RETURNING created_at
	`, created.ID).Scan(&futureCreatedAt); err != nil {
		t.Fatalf("move current secret timestamp into future: %v", err)
	}
	rotated, err := manager.Rotate(ctx, principal, RotateInput{
		SecretID: created.ID, Value: []byte("clock-v2"), RequestID: mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("Rotate() across backward database clock = %v", err)
	}
	if rotated.CreatedAt.Before(futureCreatedAt.UTC()) {
		t.Fatalf("rotated created_at=%s precedes persisted floor=%s", rotated.CreatedAt, futureCreatedAt)
	}
	reader, err := NewStore(StoreConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatalf("construct skewed-clock runtime reader: %v", err)
	}
	assertRuntimeSecret(t, ctx, reader, scope, "secret/clock-key", "clock-v2")
	if _, err := pool.Exec(ctx, `
		UPDATE secret_records
		SET created_at = created_at + interval '1 hour'
		WHERE secret_record_id = $1
	`, rotated.ID); err != nil {
		t.Fatalf("advance rotated secret timestamp: %v", err)
	}
	if err := manager.Destroy(ctx, principal, DestroyInput{
		SecretID: rotated.ID, RequestID: mustSecretID(t, id.AdminRequest),
	}); err != nil {
		t.Fatalf("Destroy() across backward database clock = %v", err)
	}
}

func TestManagerPostgreSQLConcurrentDestroyIsIdempotent(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, time.Now().UTC().Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xeb)
	manager := newTestSecretManager(t, pool, provider)
	principal := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleOwner)
	created, err := manager.Create(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID, Name: "delete-key", Value: []byte("delete-me"),
		RequestID: mustSecretID(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("seed concurrently deleted secret: %v", err)
	}

	const deletes = 8
	results := make(chan error, deletes)
	for range deletes {
		requestID := mustSecretID(t, id.AdminRequest)
		go func() {
			results <- manager.Destroy(ctx, principal, DestroyInput{SecretID: created.ID, RequestID: requestID})
		}()
	}
	for range deletes {
		if err := <-results; err != nil {
			t.Fatalf("concurrent Destroy() error = %v", err)
		}
	}
	var destroyed, deletionAudits int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM secret_records
		WHERE secret_record_id = $1 AND destroyed_at IS NOT NULL
	`, created.ID).Scan(&destroyed); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE action = 'admin.secret_delete' AND outcome = 'succeeded'
	`).Scan(&deletionAudits); err != nil {
		t.Fatal(err)
	}
	if destroyed != 1 || deletionAudits != deletes {
		t.Fatalf("destroyed rows=%d deletion audits=%d", destroyed, deletionAudits)
	}
}

func TestManagerPostgreSQLReferenceAwareDestroy(t *testing.T) {
	pool, ctx := isolatedSecretPool(t)
	scope, adminUserID := insertSecretTenant(t, ctx, pool, time.Now().UTC().Add(-time.Hour))
	provider := testEnvironmentMasterKey(t, 0xe4)
	manager := newTestSecretManager(t, pool, provider)
	principal := testSecretPrincipal(scope.OrganizationID, adminUserID, adminauth.RoleOwner)

	secretsByState := make(map[string]Metadata)
	for _, state := range []string{"valid", "active", "superseded", "attestation", "static", "symmetric", "draft", "description", "free"} {
		name := state + "-key"
		metadata, err := manager.Create(ctx, principal, CreateInput{
			EnvironmentID: scope.EnvironmentID, Name: name, Value: []byte("value-for-" + state),
			RequestID: mustSecretID(t, id.AdminRequest),
		})
		if err != nil {
			t.Fatalf("create %s secret: %v", state, err)
		}
		secretsByState[state] = metadata
	}

	validID := insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 1, "valid-key", "upstream", "valid", false)
	activeID := insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 2, "active-key", "upstream", "valid", true)
	_ = insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 3, "superseded-key", "upstream", "valid", true)
	_ = insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 4, "attestation-key", "attestation", "valid", false)
	_ = insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 5, "static-key", "static", "valid", false)
	_ = insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 6, "symmetric-key", "symmetric", "valid", false)
	_ = insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 7, "draft-key", "upstream", "draft", false)
	_ = insertSecretReferencingRevision(t, ctx, pool, scope, adminUserID, 8, "description-key", "static_header", "valid", false)
	if _, err := pool.Exec(ctx, `
		INSERT INTO active_config_revisions (
			organization_id, application_id, environment_id, config_revision_id,
			revision_status, activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, 'valid', $5, clock_timestamp())
	`, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID, activeID, adminUserID); err != nil {
		t.Fatalf("install active configuration pointer: %v", err)
	}
	_ = validID

	for _, state := range []string{"valid", "active", "superseded", "attestation", "static", "symmetric"} {
		err := manager.Destroy(ctx, principal, DestroyInput{
			SecretID: secretsByState[state].ID, RequestID: mustSecretID(t, id.AdminRequest),
		})
		if !errors.Is(err, ErrReferenced) {
			t.Fatalf("Destroy(%s) error = %v", state, err)
		}
		var current int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM secret_records
			WHERE secret_record_id = $1 AND rotated_at IS NULL AND destroyed_at IS NULL
		`, secretsByState[state].ID).Scan(&current); err != nil {
			t.Fatalf("inspect %s secret after conflict: %v", state, err)
		}
		if current != 1 {
			t.Fatalf("%s reference conflict mutated current secret", state)
		}
	}
	for _, state := range []string{"draft", "description", "free"} {
		if err := manager.Destroy(ctx, principal, DestroyInput{
			SecretID: secretsByState[state].ID, RequestID: mustSecretID(t, id.AdminRequest),
		}); err != nil {
			t.Fatalf("Destroy(%s) error = %v", state, err)
		}
	}
}

func newTestSecretManager(t *testing.T, pool *pgxpool.Pool, provider Provider) *Manager {
	t.Helper()
	manager, err := NewManager(ManagerConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatalf("construct secret manager: %v", err)
	}
	return manager
}

func testSecretPrincipal(organizationID, adminUserID string, role adminauth.Role) adminauth.Principal {
	return adminauth.Principal{
		OrganizationID: organizationID,
		AdminUserID:    adminUserID,
		Role:           role,
		Method:         adminauth.AuthenticationSession,
	}
}

func assertRuntimeSecret(t *testing.T, ctx context.Context, reader *Store, scope Scope, reference, want string) {
	t.Helper()
	value, retained, err := captureSecret(ctx, reader, scope, reference)
	if err != nil || string(value) != want {
		t.Fatalf("runtime Use(%q) value=%q err=%v", reference, value, err)
	}
	if !allZero(retained) {
		t.Fatalf("runtime Use(%q) retained plaintext: %x", reference, retained)
	}
	clear(value)
}

func assertSecretAuditShape(t *testing.T, ctx context.Context, pool *pgxpool.Pool, environmentID string, creates, rotates, deletes int) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event.action, change.field_name, change.operation, change.classification
		FROM audit_events AS event
		JOIN audit_event_changes AS change ON change.audit_event_id = event.audit_event_id
		WHERE event.environment_id = $1 AND event.resource_type = 'secret_record'
	`, environmentID)
	if err != nil {
		t.Fatalf("list secret audit evidence: %v", err)
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var action, field, operation, classification string
		if err := rows.Scan(&action, &field, &operation, &classification); err != nil {
			t.Fatalf("scan secret audit evidence: %v", err)
		}
		if field != "value" || classification != string(adminauth.AuditSensitive) {
			t.Fatalf("unsafe secret audit change action=%s field=%s operation=%s classification=%s", action, field, operation, classification)
		}
		counts[action+"/"+operation]++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate secret audit evidence: %v", err)
	}
	if counts["admin.secret_create/set"] != creates ||
		counts["admin.secret_rotate/rotate"] != rotates ||
		counts["admin.secret_delete/clear"] != deletes {
		t.Fatalf("secret audit counts = %+v", counts)
	}
}

func assertPlaintextAbsentFromSecretPersistence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, plaintexts ...string) {
	t.Helper()
	var secretDump, auditDump, changeDump string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(string_agg(to_jsonb(record)::text, ''), '') FROM secret_records AS record`).Scan(&secretDump); err != nil {
		t.Fatalf("serialize secret records for redaction assertion: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(string_agg(to_jsonb(event)::text, ''), '') FROM audit_events AS event`).Scan(&auditDump); err != nil {
		t.Fatalf("serialize audit events for redaction assertion: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(string_agg(to_jsonb(change)::text, ''), '') FROM audit_event_changes AS change`).Scan(&changeDump); err != nil {
		t.Fatalf("serialize audit changes for redaction assertion: %v", err)
	}
	for _, plaintext := range plaintexts {
		for label, dump := range map[string]string{"secret_records": secretDump, "audit_events": auditDump, "audit_event_changes": changeDump} {
			if strings.Contains(dump, plaintext) {
				t.Fatalf("%s persisted plaintext %q", label, plaintext)
			}
		}
	}
}

func waitForSecretEnvironmentLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database()
				  AND pid <> pg_backend_pid()
				  AND wait_event_type = 'Lock'
				  AND query LIKE '%FROM secret_records AS secret%'
				  AND query LIKE '%FOR UPDATE OF environment%'
			)
		`).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect secret environment lock waiter: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("secret rotation did not wait for the environment lock")
}

func mustIntegrationID(prefix id.Prefix) string {
	value, err := id.New(prefix)
	if err != nil {
		panic(err)
	}
	return value
}

func insertSecretReferencingRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool, scope Scope, adminUserID string, revisionNumber int64, secretName, referencePath, status string, activated bool) string {
	t.Helper()
	revisionID := mustSecretID(t, id.ConfigRevision)
	reference := "secret/" + secretName
	var documentObject map[string]any
	switch referencePath {
	case "upstream":
		documentObject = map[string]any{"spec": map[string]any{"upstreams": []any{map[string]any{"authentication": map[string]any{"secretRef": reference}}}}}
	case "attestation":
		documentObject = map[string]any{"spec": map[string]any{"attestationPolicies": []any{map[string]any{"platforms": map[string]any{"ios": map[string]any{"secretRef": reference}}}}}}
	case "static":
		documentObject = map[string]any{"spec": map[string]any{"identityProviders": []any{map[string]any{"staticPublicKeySecretRef": reference}}}}
	case "symmetric":
		documentObject = map[string]any{"spec": map[string]any{"identityProviders": []any{map[string]any{"symmetricSecretRef": reference}}}}
	case "static_header":
		documentObject = map[string]any{"spec": map[string]any{"upstreams": []any{map[string]any{"staticHeaders": map[string]any{"secretRef": reference}}}}}
	default:
		t.Fatalf("unknown secret reference test path %q", referencePath)
	}
	document, err := json.Marshal(documentObject)
	if err != nil {
		t.Fatalf("encode referencing configuration: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var compiled any
	var validation any
	var validatedAt any
	var activatedAt any
	if status == "valid" {
		compiled = []byte(`{}`)
		validation = []byte(`{"valid":true,"checked_at":"2026-08-28T00:00:00Z","issues":[]}`)
		validatedAt = now
		if activated {
			activatedAt = now
		}
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_report, created_by_admin_user_id, created_at,
			validated_at, activated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, revisionID, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID,
		revisionNumber, "cfg-secret-test-"+revisionID, status, document, compiled,
		validation, adminUserID, now.Add(-time.Minute), validatedAt, activatedAt)
	if err != nil {
		t.Fatalf("insert %s referencing revision: %v", status, err)
	}
	return revisionID
}
