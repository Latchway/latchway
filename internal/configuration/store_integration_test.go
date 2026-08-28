package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	secretstore "github.com/latchway/latchway/internal/secrets"
)

var configurationIntegrationSchemaPattern = regexp.MustCompile(`^latchway_configuration_test_[0-9]+$`)

func TestStorePostgreSQLRevisionRacesValidationActivationAndRollback(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedConfigurationPool(t, ctx, databaseURL)
	principal, scope := seedConfigurationTenant(t, ctx, pool)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	instant := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return instant }

	initial, err := store.CreateRevision(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID, Document: validConfigurationDocument(t), Description: "initial",
	})
	if err != nil {
		t.Fatalf("CreateRevision(initial) error = %v", err)
	}
	initialReport, err := store.ValidateRevision(ctx, principal, initial.ID)
	if err != nil || !initialReport.Valid {
		t.Fatalf("ValidateRevision(initial) report=%+v error=%v", initialReport, err)
	}
	initial, err = store.ActivateRevision(ctx, principal, initial.ID, initial.ETag)
	if err != nil || initial.State != StateActive {
		t.Fatalf("ActivateRevision(initial) revision=%+v error=%v", initial, err)
	}
	initialSnapshot, err := store.ActiveSnapshot(ctx, scope)
	if err != nil {
		t.Fatalf("ActiveSnapshot(initial) error = %v", err)
	}

	editDraft, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, BaseRevisionID: initial.ID})
	if err != nil {
		t.Fatalf("CreateRevision(edit race) error = %v", err)
	}
	leftDocument := documentWithDescription(t, "left editor")
	rightDocument := documentWithDescription(t, "right editor")
	type editResult struct {
		revision Revision
		err      error
	}
	edits := make(chan editResult, 2)
	var editWait sync.WaitGroup
	for _, document := range []json.RawMessage{leftDocument, rightDocument} {
		document := document
		editWait.Add(1)
		go func() {
			defer editWait.Done()
			revision, updateErr := store.ReplaceDraft(ctx, principal, editDraft.ID, editDraft.ETag, document)
			edits <- editResult{revision: revision, err: updateErr}
		}()
	}
	editWait.Wait()
	close(edits)
	editSuccesses, editMismatches := 0, 0
	for result := range edits {
		switch {
		case result.err == nil:
			editSuccesses++
		case errors.Is(result.err, ErrETagMismatch):
			editMismatches++
		default:
			t.Fatalf("competing ReplaceDraft() error = %v", result.err)
		}
	}
	if editSuccesses != 1 || editMismatches != 1 {
		t.Fatalf("edit race successes=%d ETag mismatches=%d", editSuccesses, editMismatches)
	}

	left, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, BaseRevisionID: initial.ID, Description: "left activation"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, BaseRevisionID: initial.ID, Description: "right activation"})
	if err != nil {
		t.Fatal(err)
	}
	left, err = store.ReplaceDraft(ctx, principal, left.ID, left.ETag, leftDocument)
	if err != nil {
		t.Fatal(err)
	}
	right, err = store.ReplaceDraft(ctx, principal, right.ID, right.ETag, rightDocument)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []Revision{left, right} {
		report, validationErr := store.ValidateRevision(ctx, principal, revision.ID)
		if validationErr != nil || !report.Valid {
			t.Fatalf("ValidateRevision(%s) report=%+v error=%v", revision.ID, report, validationErr)
		}
	}
	type activationResult struct {
		revision Revision
		err      error
	}
	activations := make(chan activationResult, 2)
	var activationWait sync.WaitGroup
	for _, revision := range []Revision{left, right} {
		revision := revision
		activationWait.Add(1)
		go func() {
			defer activationWait.Done()
			activated, activationErr := store.ActivateRevision(ctx, principal, revision.ID, revision.ETag)
			activations <- activationResult{revision: activated, err: activationErr}
		}()
	}
	activationWait.Wait()
	close(activations)
	activationSuccesses, activationConflicts := 0, 0
	var current Revision
	for result := range activations {
		switch {
		case result.err == nil:
			activationSuccesses++
			current = result.revision
		case errors.Is(result.err, ErrConflict):
			activationConflicts++
		default:
			t.Fatalf("competing ActivateRevision() error = %v", result.err)
		}
	}
	if activationSuccesses != 1 || activationConflicts != 1 {
		t.Fatalf("activation race successes=%d conflicts=%d", activationSuccesses, activationConflicts)
	}

	invalidDocument := configurationObject(t)
	feature := objectArray(objectValue(invalidDocument, "spec"), "features")[0]
	objectValue(feature, "access")["expression"] = "principal.authenticated &&"
	invalidJSON, _ := json.Marshal(invalidDocument)
	invalid, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, Document: invalidJSON})
	if err != nil {
		t.Fatalf("CreateRevision(invalid policy) error = %v", err)
	}
	invalidReport, err := store.ValidateRevision(ctx, principal, invalid.ID)
	if err != nil || invalidReport.Valid || !hasIssue(invalidReport.Issues, "cel_invalid") {
		t.Fatalf("invalid policy report=%+v error=%v", invalidReport, err)
	}
	if _, err := store.ActivateRevision(ctx, principal, invalid.ID, invalid.ETag); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("ActivateRevision(invalid policy) error = %v", err)
	}

	opaqueDocument := configurationObject(t)
	opaqueSpec := objectValue(opaqueDocument, "spec")
	opaqueFeature := objectArray(opaqueSpec, "features")[0]
	opaqueFeature["protocol"] = "opaque_http"
	delete(opaqueFeature, "output")
	opaqueFeature["opaqueHttp"] = map[string]any{
		"allowedMethods": []any{"POST"}, "pathPrefixes": []any{"/safe"},
		"maxBodyBytes": json.Number("1024"),
	}
	objectArray(opaqueSpec, "models")[0]["capabilities"] = []any{"opaque_http"}
	opaqueJSON, _ := json.Marshal(opaqueDocument)
	if issues := store.validator.SchemaIssues(opaqueJSON); len(issues) != 0 {
		t.Fatalf("opaque-protocol draft is not schema-valid: %+v", issues)
	}
	opaque, err := store.CreateRevision(ctx, principal, CreateInput{
		EnvironmentID: scope.EnvironmentID, Document: opaqueJSON,
		Description: "opaque protocol without executable adapter",
	})
	if err != nil {
		t.Fatalf("CreateRevision(opaque protocol) error = %v", err)
	}
	opaqueReport, err := store.ValidateRevision(ctx, principal, opaque.ID)
	if err != nil || opaqueReport.Valid || !hasIssue(opaqueReport.Issues, "protocol_endpoint_unavailable") {
		t.Fatalf("opaque protocol report=%+v error=%v", opaqueReport, err)
	}
	if _, err := store.ActivateRevision(ctx, principal, opaque.ID, opaque.ETag); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("ActivateRevision(opaque protocol) error = %v", err)
	}
	activeBeforeRollback, err := store.GetActiveRevision(ctx, principal, scope.EnvironmentID)
	if err != nil || activeBeforeRollback.ID != current.ID {
		t.Fatalf("active revision before rollback=%+v error=%v", activeBeforeRollback, err)
	}

	rolledBack, err := store.Rollback(ctx, principal, scope.EnvironmentID, initial.ID, activeBeforeRollback.ETag)
	if err != nil || rolledBack.ID != initial.ID || rolledBack.State != StateActive {
		t.Fatalf("Rollback() revision=%+v error=%v", rolledBack, err)
	}
	rolledBackSnapshot, err := store.ActiveSnapshot(ctx, scope)
	if err != nil {
		t.Fatalf("ActiveSnapshot(rollback) error = %v", err)
	}
	if !bytes.Equal(initialSnapshot.CompiledJSON(), rolledBackSnapshot.CompiledJSON()) {
		t.Fatal("rollback did not restore the exact prior compiled snapshot")
	}

	if _, err := pool.Exec(ctx, `UPDATE config_revisions SET document = '{}'::jsonb WHERE config_revision_id = $1`, initial.ID); err == nil {
		t.Fatal("database allowed an activated revision document to mutate")
	} else {
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) || databaseError.Code != "55000" {
			t.Fatalf("immutable revision update error = %v", err)
		}
	}
	var activationAudits, rollbackAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'admin.configuration_activate'`).Scan(&activationAudits); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'admin.configuration_rollback'`).Scan(&rollbackAudits); err != nil {
		t.Fatal(err)
	}
	if activationAudits != 2 || rollbackAudits != 1 {
		t.Fatalf("activation audits=%d rollback audits=%d", activationAudits, rollbackAudits)
	}
}

func TestStorePostgreSQLActiveUserOverridePlanGuards(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedConfigurationPool(t, ctx, databaseURL)
	principal, scope := seedConfigurationTenant(t, ctx, pool)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	store.now = func() time.Time { return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC) }

	createValidated := func(baseRevisionID string, document json.RawMessage, description string) Revision {
		t.Helper()
		input := CreateInput{EnvironmentID: scope.EnvironmentID, Description: description}
		if baseRevisionID == "" {
			input.Document = document
		} else {
			input.BaseRevisionID = baseRevisionID
		}
		revision, createErr := store.CreateRevision(ctx, principal, input)
		if createErr != nil {
			t.Fatalf("CreateRevision(%s) error = %v", description, createErr)
		}
		if baseRevisionID != "" {
			revision, createErr = store.ReplaceDraft(ctx, principal, revision.ID, revision.ETag, document)
			if createErr != nil {
				t.Fatalf("ReplaceDraft(%s) error = %v", description, createErr)
			}
		}
		report, validationErr := store.ValidateRevision(ctx, principal, revision.ID)
		if validationErr != nil || !report.Valid {
			t.Fatalf("ValidateRevision(%s) report=%+v error=%v", description, report, validationErr)
		}
		return revision
	}
	activate := func(revision Revision) Revision {
		t.Helper()
		activated, activationErr := store.ActivateRevision(ctx, principal, revision.ID, revision.ETag)
		if activationErr != nil {
			t.Fatalf("ActivateRevision(%s) error = %v", revision.ID, activationErr)
		}
		return activated
	}
	assertActive := func(wantRevisionID string) Revision {
		t.Helper()
		active, activeErr := store.GetActiveRevision(ctx, principal, scope.EnvironmentID)
		if activeErr != nil || active.ID != wantRevisionID {
			t.Fatalf("active revision=%+v error=%v, want %s", active, activeErr, wantRevisionID)
		}
		return active
	}

	initial := activate(createValidated("", validConfigurationDocument(t), "initial without premium"))
	premium := activate(createValidated(initial.ID, configurationDocumentWithPremiumPlan(t, "premium active"), "add premium"))

	userID := mustConfigID(t, id.ApplicationUser)
	overrideID := mustConfigID(t, id.UserOverride)
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (application_user_id, organization_id, application_id)
		VALUES ($1, $2, $3)
	`, userID, scope.OrganizationID, scope.ApplicationID); err != nil {
		t.Fatalf("insert application user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_overrides (
			user_override_id, organization_id, application_id, environment_id,
			application_user_id, override_document, reason,
			created_by_admin_user_id, created_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, '{"limit_plan":"premium"}'::jsonb,
			'configuration guard test', $6,
			clock_timestamp() - interval '1 minute', clock_timestamp() + interval '1 hour'
		)
	`, overrideID, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID, userID, principal.AdminUserID); err != nil {
		t.Fatalf("insert active user override: %v", err)
	}

	removing := createValidated(premium.ID, validConfigurationDocument(t), "remove premium")
	if _, err := store.ActivateRevision(ctx, principal, removing.ID, removing.ETag); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("ActivateRevision(removing active override plan) error = %v", err)
	}
	assertActive(premium.ID)

	retaining := createValidated(premium.ID, configurationDocumentWithPremiumPlan(t, "premium retained"), "retain premium")
	if _, err := pool.Exec(ctx, `
		UPDATE user_overrides
		SET override_document = '{"limit_plan":"premium","unexpected":true}'::jsonb
		WHERE user_override_id = $1
	`, overrideID); err != nil {
		t.Fatalf("corrupt active user override: %v", err)
	}
	if _, err := store.ActivateRevision(ctx, principal, retaining.ID, retaining.ETag); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("ActivateRevision(corrupt active override) error = %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE user_overrides
		SET override_document = '{"limit_plan":"premium"}'::jsonb
		WHERE user_override_id = $1
	`, overrideID); err != nil {
		t.Fatalf("restore active user override: %v", err)
	}
	retaining = activate(retaining)

	if _, err := store.Rollback(ctx, principal, scope.EnvironmentID, initial.ID, retaining.ETag); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("Rollback(to revision missing active override plan) error = %v", err)
	}
	assertActive(retaining.ID)

	if _, err := pool.Exec(ctx, `
		UPDATE user_overrides SET revoked_at = clock_timestamp() WHERE user_override_id = $1
	`, overrideID); err != nil {
		t.Fatalf("revoke active user override: %v", err)
	}
	rolledBack, err := store.Rollback(ctx, principal, scope.EnvironmentID, initial.ID, retaining.ETag)
	if err != nil || rolledBack.ID != initial.ID {
		t.Fatalf("Rollback(with revoked override) revision=%+v error=%v", rolledBack, err)
	}

	expiredOverrideID := mustConfigID(t, id.UserOverride)
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_overrides (
			user_override_id, organization_id, application_id, environment_id,
			application_user_id, override_document, reason,
			created_by_admin_user_id, created_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, '{"limit_plan":"premium"}'::jsonb,
			'expired configuration guard test', $6,
			clock_timestamp() - interval '2 hours', clock_timestamp() - interval '1 hour'
		)
	`, expiredOverrideID, scope.OrganizationID, scope.ApplicationID, scope.EnvironmentID, userID, principal.AdminUserID); err != nil {
		t.Fatalf("insert expired user override: %v", err)
	}
	afterExpiry := createValidated(initial.ID, documentWithDescription(t, "expired override ignored"), "expired override ignored")
	afterExpiry = activate(afterExpiry)
	assertActive(afterExpiry.ID)
}

func TestStorePostgreSQLSecretValidationDestroySerialization(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedConfigurationPool(t, ctx, databaseURL)
	principal, scope := seedConfigurationTenant(t, ctx, pool)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := secretstore.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xd7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := secretstore.NewManager(secretstore.ManagerConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}

	createSecretAndDraft := func(name string) (secretstore.Metadata, Revision) {
		t.Helper()
		metadata, createErr := manager.Create(ctx, principal, secretstore.CreateInput{
			EnvironmentID: scope.EnvironmentID, Name: name, Value: []byte("value-for-" + name),
		})
		if createErr != nil {
			t.Fatalf("create secret %s: %v", name, createErr)
		}
		revision, createErr := store.CreateRevision(ctx, principal, CreateInput{
			EnvironmentID: scope.EnvironmentID, Document: configurationDocumentWithSecret(t, name),
		})
		if createErr != nil {
			t.Fatalf("create referencing draft %s: %v", name, createErr)
		}
		return metadata, revision
	}

	// When validation queues first, it makes the immutable revision usable
	// before deletion checks references, so deletion must fail closed.
	firstSecret, firstDraft := createSecretAndDraft("validation-first")
	blocker := lockConfigurationEnvironment(t, ctx, pool, scope.EnvironmentID)
	type validationResult struct {
		report ValidationReport
		err    error
	}
	validated := make(chan validationResult, 1)
	go func() {
		report, validationErr := store.ValidateRevision(ctx, principal, firstDraft.ID)
		validated <- validationResult{report: report, err: validationErr}
	}()
	waitForConfigurationSecretLockWaiters(t, ctx, pool, 1)
	deleted := make(chan error, 1)
	go func() {
		deleted <- manager.Destroy(ctx, principal, secretstore.DestroyInput{SecretID: firstSecret.ID})
	}()
	waitForConfigurationSecretLockWaiters(t, ctx, pool, 2)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release validation-first blocker: %v", err)
	}
	validation := <-validated
	if validation.err != nil || !validation.report.Valid {
		t.Fatalf("validation-first report=%+v err=%v", validation.report, validation.err)
	}
	if err := <-deleted; !errors.Is(err, secretstore.ErrReferenced) {
		t.Fatalf("validation-first Destroy() error=%v", err)
	}

	// When deletion queues first, validation observes the tombstone after it
	// acquires the same row and must keep the revision unusable.
	secondSecret, secondDraft := createSecretAndDraft("deletion-first")
	blocker = lockConfigurationEnvironment(t, ctx, pool, scope.EnvironmentID)
	deleted = make(chan error, 1)
	go func() {
		deleted <- manager.Destroy(ctx, principal, secretstore.DestroyInput{SecretID: secondSecret.ID})
	}()
	waitForConfigurationSecretLockWaiters(t, ctx, pool, 1)
	validated = make(chan validationResult, 1)
	go func() {
		report, validationErr := store.ValidateRevision(ctx, principal, secondDraft.ID)
		validated <- validationResult{report: report, err: validationErr}
	}()
	waitForConfigurationSecretLockWaiters(t, ctx, pool, 2)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release deletion-first blocker: %v", err)
	}
	if err := <-deleted; err != nil {
		t.Fatalf("deletion-first Destroy() error=%v", err)
	}
	validation = <-validated
	if validation.err != nil || validation.report.Valid || !hasIssue(validation.report.Issues, "secret_reference_missing") {
		t.Fatalf("deletion-first report=%+v err=%v", validation.report, validation.err)
	}
}

func lockConfigurationEnvironment(t *testing.T, ctx context.Context, pool *pgxpool.Pool, environmentID string) pgx.Tx {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin environment blocker: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, `SELECT 1 FROM environments WHERE environment_id = $1 FOR UPDATE`, environmentID); err != nil {
		t.Fatalf("lock environment blocker: %v", err)
	}
	return tx
}

func waitForConfigurationSecretLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database()
			  AND application_name = current_setting('application_name')
			  AND pid <> pg_backend_pid()
			  AND wait_event_type = 'Lock'
			  AND query LIKE '%FOR UPDATE OF environment%'
		`).Scan(&waiting); err != nil {
			t.Fatalf("inspect configuration/secret lock waiters: %v", err)
		}
		if waiting >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("environment lock waiters never reached %d", want)
}

func isolatedConfigurationPool(t *testing.T, ctx context.Context, databaseURL string) *pgxpool.Pool {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_configuration_test_%d", time.Now().UnixNano())
	if !configurationIntegrationSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	query.Set("application_name", schema)
	parsedURL.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsedURL.String(), 8)
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func seedConfigurationTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (adminauth.Principal, TenantScope) {
	t.Helper()
	organizationID := mustConfigID(t, id.Organization)
	applicationID := mustConfigID(t, id.Application)
	environmentID := mustConfigID(t, id.Environment)
	adminUserID := mustConfigID(t, id.AdminUser)
	membershipID := mustConfigID(t, id.AdminMembership)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (organization_id, slug, display_name, status, created_at, updated_at) VALUES ($1, 'example', 'Example', 'active', $2, $2)`, []any{organizationID, now}},
		{`INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name, status, created_at, updated_at) VALUES ($1, 'owner@example.test', 'owner@example.test', 'Owner', 'active', $2, $2)`, []any{adminUserID, now}},
		{`INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role, status, created_by_admin_user_id, created_at, updated_at) VALUES ($1, $2, $3, 'owner', 'active', $3, $4, $4)`, []any{membershipID, organizationID, adminUserID, now}},
		{`INSERT INTO applications (application_id, organization_id, slug, display_name, status, created_at, updated_at) VALUES ($1, $2, 'habits', 'Habits', 'active', $3, $3)`, []any{applicationID, organizationID, now}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, status, created_at, updated_at) VALUES ($1, $2, $3, 'production', 'Production', 'production', 'active', $4, $4)`, []any{environmentID, organizationID, applicationID, now}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed configuration tenant: %v", err)
		}
	}
	return adminauth.Principal{
		OrganizationID: organizationID, AdminUserID: adminUserID,
		Role: adminauth.RoleOwner, Method: adminauth.AuthenticationSession,
	}, TenantScope{OrganizationID: organizationID, ApplicationID: applicationID, EnvironmentID: environmentID}
}

func documentWithDescription(t *testing.T, description string) json.RawMessage {
	t.Helper()
	document := configurationObject(t)
	objectValue(document, "metadata")["description"] = description
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func configurationDocumentWithPremiumPlan(t *testing.T, description string) json.RawMessage {
	t.Helper()
	document := configurationObject(t)
	objectValue(document, "metadata")["description"] = description
	spec := objectValue(document, "spec")
	plans, ok := spec["limitPlans"].([]any)
	if !ok {
		t.Fatal("configuration fixture has no limitPlans array")
	}
	spec["limitPlans"] = append(plans, map[string]any{
		"id": "premium",
		"limits": []any{map[string]any{
			"metric": "logical_requests", "scope": []any{"user", "feature"},
			"window": "1d", "maximum": 100,
		}},
	})
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func configurationDocumentWithSecret(t *testing.T, name string) json.RawMessage {
	t.Helper()
	document := configurationObject(t)
	upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
	upstream["authentication"] = map[string]any{"type": "bearer", "secretRef": "secret/" + name}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustConfigID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
