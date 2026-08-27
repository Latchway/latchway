package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
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

func mustConfigID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
