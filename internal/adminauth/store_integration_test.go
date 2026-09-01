package adminauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

var adminAuthIntegrationSchemaPattern = regexp.MustCompile("^latchway_adminauth_test_[0-9]+$")

func TestStorePostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer adminPool.Close()

	schema := fmt.Sprintf("latchway_adminauth_test_%d", time.Now().UnixNano())
	if !adminAuthIntegrationSchemaPattern.MatchString(schema) {
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
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()

	pool, err := database.Open(ctx, parsedURL.String(), 4)
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	defer pool.Close()
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	tokenEntropy := make([]byte, 512)
	for index := range tokenEntropy {
		tokenEntropy[index] = byte(index)
	}
	issuer, err := NewTokenIssuer(bytes.NewReader(tokenEntropy))
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}
	instant := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store, err := newStore(pool, idNew, issuer, func() time.Time { return instant })
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	passwordHasher, err := NewPasswordHasher(
		testPasswordParameters(),
		bytes.NewReader(bytes.Repeat([]byte{0x55}, 16)),
	)
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v", err)
	}
	passwordHash, err := passwordHasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	bootstrapToken := strings.Repeat("bootstrap-secure-value-", 2)
	bootstrapExpiry := instant.Add(time.Minute)
	initializations := make(chan error, 2)
	var initializationWait sync.WaitGroup
	for range 2 {
		initializationWait.Add(1)
		go func() {
			defer initializationWait.Done()
			initializations <- store.InitializeBootstrapToken(ctx, bootstrapToken, &bootstrapExpiry)
		}()
	}
	initializationWait.Wait()
	close(initializations)
	for initializationErr := range initializations {
		if initializationErr != nil {
			t.Fatalf("concurrent idempotent InitializeBootstrapToken() error = %v", initializationErr)
		}
	}
	if err := store.InitializeBootstrapToken(ctx, strings.Repeat("different-bootstrap-value-", 2), nil); !errors.Is(err, ErrBootstrapAlreadyInitialized) {
		t.Fatalf("different InitializeBootstrapToken() error = %v", err)
	}
	instant = instant.Add(2 * time.Minute)
	replacementToken := strings.Repeat("replacement-bootstrap-value-", 2)
	replacementExpiry := instant.Add(time.Hour)
	if err := store.InitializeBootstrapToken(ctx, replacementToken, &replacementExpiry); err != nil {
		t.Fatalf("replace expired InitializeBootstrapToken() error = %v", err)
	}
	if _, err := store.BootstrapOwner(ctx, bootstrapToken, BootstrapOwnerInput{
		OrganizationSlug: "example",
		OrganizationName: "Example",
		Email:            "owner@example.com",
		DisplayName:      "Owner",
		PasswordHash:     passwordHash,
	}); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("BootstrapOwner(replaced token) error = %v", err)
	}
	bootstrapToken = replacementToken
	if err := store.ValidateBootstrapToken(ctx, strings.Repeat("wrong-bootstrap-value-", 2)); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ValidateBootstrapToken(wrong token) error = %v", err)
	}
	if err := store.ValidateBootstrapToken(ctx, bootstrapToken); err != nil {
		t.Fatalf("ValidateBootstrapToken(valid token) error = %v", err)
	}
	if _, err := store.BootstrapOwner(ctx, strings.Repeat("wrong-bootstrap-value-", 2), BootstrapOwnerInput{
		OrganizationSlug: "example",
		OrganizationName: "Example",
		Email:            "owner@example.com",
		DisplayName:      "Owner",
		PasswordHash:     passwordHash,
	}); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("BootstrapOwner(wrong token) error = %v", err)
	}

	input := BootstrapOwnerInput{
		OrganizationSlug: "example",
		OrganizationName: "Example",
		Email:            "owner@example.com",
		DisplayName:      "Owner",
		PasswordHash:     passwordHash,
		RequestID:        mustIdentifier(t, id.AdminRequest),
	}
	type bootstrapAttempt struct {
		result BootstrapResult
		err    error
	}
	attempts := make(chan bootstrapAttempt, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, bootstrapErr := store.BootstrapOwner(ctx, bootstrapToken, input)
			attempts <- bootstrapAttempt{result: result, err: bootstrapErr}
		}()
	}
	wait.Wait()
	close(attempts)

	var bootstrap BootstrapResult
	successes := 0
	disabled := 0
	for attempt := range attempts {
		switch {
		case attempt.err == nil:
			successes++
			bootstrap = attempt.result
		case errors.Is(attempt.err, ErrBootstrapDisabled):
			disabled++
		default:
			t.Fatalf("concurrent BootstrapOwner() error = %v", attempt.err)
		}
	}
	if successes != 1 || disabled != 1 {
		t.Fatalf("bootstrap outcomes successes=%d disabled=%d", successes, disabled)
	}
	if _, err := store.BootstrapOwner(ctx, bootstrapToken, input); !errors.Is(err, ErrBootstrapDisabled) {
		t.Fatalf("reused BootstrapOwner() error = %v", err)
	}
	if err := store.ValidateBootstrapToken(ctx, bootstrapToken); !errors.Is(err, ErrBootstrapDisabled) {
		t.Fatalf("ValidateBootstrapToken(consumed token) error = %v", err)
	}

	adminUserID, storedPassword, err := store.PasswordCredentialByEmail(ctx, "OWNER@example.com")
	if err != nil {
		t.Fatalf("PasswordCredentialByEmail() error = %v", err)
	}
	if adminUserID != bootstrap.AdminUserID {
		t.Fatalf("admin user ID = %q, want %q", adminUserID, bootstrap.AdminUserID)
	}
	verification, err := passwordHasher.Verify([]byte("correct horse battery staple"), storedPassword)
	if err != nil || !verification.Match {
		t.Fatalf("stored password verification = %+v, error = %v", verification, err)
	}

	viewerUserID := mustIdentifier(t, id.AdminUser)
	viewerMembershipID := mustIdentifier(t, id.AdminMembership)
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name, status, created_at, updated_at
		) VALUES ($1, 'viewer@example.com', 'viewer@example.com', 'Viewer', 'active', $2, $2)
	`, viewerUserID, instant); err != nil {
		t.Fatalf("create viewer user fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, status, created_at, updated_at
		) VALUES ($1, $2, $3, 'viewer', 'active', $4, $4)
	`, viewerMembershipID, bootstrap.OrganizationID, viewerUserID, instant); err != nil {
		t.Fatalf("create viewer membership fixture: %v", err)
	}
	viewerScope, err := NewCapabilitySet(InspectUsers)
	if err != nil {
		t.Fatalf("NewCapabilitySet(viewer) error = %v", err)
	}
	viewerToken, err := store.CreateAPIToken(ctx, CreateAPITokenInput{
		OrganizationID:       bootstrap.OrganizationID,
		AdminUserID:          viewerUserID,
		CreatedByAdminUserID: viewerUserID,
		Name:                 "viewer-self",
		Scope:                viewerScope,
		RequestID:            mustIdentifier(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("CreateAPIToken(viewer self) error = %v", err)
	}
	if _, err := store.CreateAPIToken(ctx, CreateAPITokenInput{
		OrganizationID:       bootstrap.OrganizationID,
		AdminUserID:          bootstrap.AdminUserID,
		CreatedByAdminUserID: viewerUserID,
		Name:                 "privilege-escalation",
		Scope:                viewerScope,
		RequestID:            mustIdentifier(t, id.AdminRequest),
	}); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("CreateAPIToken(viewer for owner) error = %v", err)
	}

	session, err := store.CreateSession(ctx, CreateSessionInput{
		OrganizationID: bootstrap.OrganizationID,
		AdminUserID:    bootstrap.AdminUserID,
		Lifetime:       time.Hour,
		RequestID:      mustIdentifier(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	principal, err := store.AuthenticateSession(ctx, session.Token.Reveal())
	if err != nil {
		t.Fatalf("AuthenticateSession() error = %v", err)
	}
	if principal.Role != RoleOwner || principal.AdminUserID != bootstrap.AdminUserID {
		t.Fatalf("session principal = %+v", principal)
	}
	refreshedPrincipal, err := store.RevalidatePrincipal(ctx, principal)
	if err != nil || refreshedPrincipal.OrganizationID != principal.OrganizationID ||
		refreshedPrincipal.AdminUserID != principal.AdminUserID ||
		refreshedPrincipal.CredentialID != principal.CredentialID ||
		refreshedPrincipal.Role != principal.Role ||
		refreshedPrincipal.Method != AuthenticationSession ||
		refreshedPrincipal.CredentialExpiresAt == nil ||
		!refreshedPrincipal.CredentialExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("RevalidatePrincipal(session) = %+v, error = %v", refreshedPrincipal, err)
	}
	if err := store.ValidateSessionCSRF(ctx, session.SessionID, session.CSRFToken.Reveal()); err != nil {
		t.Fatalf("ValidateSessionCSRF() error = %v", err)
	}
	if err := store.ValidateSessionCSRF(ctx, session.SessionID, session.Token.Reveal()); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("ValidateSessionCSRF(wrong token) error = %v", err)
	}
	expiringSession, err := store.CreateSession(ctx, CreateSessionInput{
		OrganizationID: bootstrap.OrganizationID,
		AdminUserID:    bootstrap.AdminUserID,
		Lifetime:       5 * time.Minute,
		RequestID:      mustIdentifier(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("CreateSession(expiring) error = %v", err)
	}
	revokedSession, err := store.CreateSession(ctx, CreateSessionInput{
		OrganizationID: bootstrap.OrganizationID,
		AdminUserID:    bootstrap.AdminUserID,
		Lifetime:       time.Hour,
		RequestID:      mustIdentifier(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("CreateSession(managed revocation) error = %v", err)
	}
	revokedPrincipal, err := store.AuthenticateSession(ctx, revokedSession.Token.Reveal())
	if err != nil {
		t.Fatalf("AuthenticateSession(managed revocation) error = %v", err)
	}
	managedRevokeRequestID := mustIdentifier(t, id.AdminRequest)
	if err := store.RevokeManagedAdminSession(ctx, principal, revokedSession.SessionID, managedRevokeRequestID); err != nil {
		t.Fatalf("RevokeManagedAdminSession() error = %v", err)
	}
	if _, err := store.RevalidatePrincipal(ctx, revokedPrincipal); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("RevalidatePrincipal(revoked session) error = %v", err)
	}
	if err := store.RevokeManagedAdminSession(ctx, principal, revokedSession.SessionID, mustIdentifier(t, id.AdminRequest)); err != nil {
		t.Fatalf("RevokeManagedAdminSession(idempotent) error = %v", err)
	}
	instant = instant.Add(6 * time.Minute)
	principal, err = store.AuthenticateSession(ctx, session.Token.Reveal())
	if err != nil {
		t.Fatalf("AuthenticateSession(current after clock advance) error = %v", err)
	}
	sessions, err := store.ListAdminSessions(ctx, principal, AdminSessionPageRequest{Size: 200})
	if err != nil {
		t.Fatalf("ListAdminSessions() error = %v", err)
	}
	statuses := make(map[string]AdminSessionMetadata, len(sessions))
	currentCount := 0
	for _, item := range sessions {
		statuses[item.ID] = item
		if item.Current {
			currentCount++
		}
		if item.Administrator.ID != bootstrap.AdminUserID || item.Administrator.Email != "owner@example.com" {
			t.Fatalf("ListAdminSessions() administrator = %+v", item.Administrator)
		}
	}
	if statuses[session.SessionID].Status != AdminSessionActive || !statuses[session.SessionID].Current ||
		statuses[expiringSession.SessionID].Status != AdminSessionExpired || statuses[expiringSession.SessionID].Current ||
		statuses[revokedSession.SessionID].Status != AdminSessionRevoked || statuses[revokedSession.SessionID].Current ||
		currentCount != 1 {
		t.Fatalf("ListAdminSessions() statuses=%+v current_count=%d", statuses, currentCount)
	}
	var storedManagedReason string
	var managedAuditCount int
	if err := pool.QueryRow(ctx, `
		SELECT revoke_reason
		FROM admin_sessions
		WHERE admin_session_id = $1
	`, revokedSession.SessionID).Scan(&storedManagedReason); err != nil {
		t.Fatalf("read managed session revoke reason: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM audit_events
		WHERE action = 'admin.session_revoke'
		  AND resource_type = 'admin_session'
		  AND resource_id = $1
	`, revokedSession.SessionID).Scan(&managedAuditCount); err != nil {
		t.Fatalf("count managed session revoke audits: %v", err)
	}
	if storedManagedReason != managedSessionRevokeReason || managedAuditCount != 1 {
		t.Fatalf("managed session reason=%q audit_count=%d", storedManagedReason, managedAuditCount)
	}
	viewerPrincipal, err := store.AuthenticateAPIToken(ctx, viewerToken.Token.Reveal())
	if err != nil {
		t.Fatalf("AuthenticateAPIToken(viewer session-list authorization) error = %v", err)
	}
	if _, err := store.ListAdminSessions(ctx, viewerPrincipal, AdminSessionPageRequest{Size: 50}); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("ListAdminSessions(viewer) error = %v", err)
	}

	otherOrganizationID := mustIdentifier(t, id.Organization)
	otherMembershipID := mustIdentifier(t, id.AdminMembership)
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (
			organization_id, slug, display_name, status, created_at, updated_at
		) VALUES ($1, 'other-organization', 'Other Organization', 'active', $2, $2)
	`, otherOrganizationID, instant); err != nil {
		t.Fatalf("create cross-tenant organization fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, status,
			created_by_admin_user_id, created_at, updated_at
		) VALUES ($1, $2, $3, 'admin', 'active', $3, $4, $4)
	`, otherMembershipID, otherOrganizationID, bootstrap.AdminUserID, instant); err != nil {
		t.Fatalf("create cross-tenant membership fixture: %v", err)
	}
	otherSession, err := store.CreateSession(ctx, CreateSessionInput{
		OrganizationID: otherOrganizationID,
		AdminUserID:    bootstrap.AdminUserID,
		Lifetime:       time.Hour,
		RequestID:      mustIdentifier(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("CreateSession(cross-tenant) error = %v", err)
	}
	if err := store.RevokeManagedAdminSession(ctx, principal, otherSession.SessionID, mustIdentifier(t, id.AdminRequest)); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("RevokeManagedAdminSession(cross-tenant) error = %v", err)
	}
	if _, err := store.AuthenticateSession(ctx, otherSession.Token.Reveal()); err != nil {
		t.Fatalf("cross-tenant session changed by revocation probe: %v", err)
	}
	actor, err := NewAdminUserActor(bootstrap.AdminUserID)
	if err != nil {
		t.Fatalf("NewAdminUserActor() error = %v", err)
	}
	viewerActor, err := NewAdminUserActor(viewerUserID)
	if err != nil {
		t.Fatalf("NewAdminUserActor(viewer) error = %v", err)
	}
	if err := store.RevokeSession(
		ctx,
		session.SessionID,
		viewerActor,
		mustIdentifier(t, id.AdminRequest),
		"unauthorized",
	); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("RevokeSession(cross-user viewer) error = %v", err)
	}
	if _, err := store.AuthenticateSession(ctx, session.Token.Reveal()); err != nil {
		t.Fatalf("session changed by unauthorized revocation: %v", err)
	}
	if err := store.RevokeSession(ctx, session.SessionID, actor, mustIdentifier(t, id.AdminRequest), "owner logout"); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if _, err := store.AuthenticateSession(ctx, session.Token.Reveal()); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("AuthenticateSession(revoked) error = %v", err)
	}

	scope, err := NewCapabilitySet(ManageSecrets, InspectUsers)
	if err != nil {
		t.Fatalf("NewCapabilitySet() error = %v", err)
	}
	apiToken, err := store.CreateAPIToken(ctx, CreateAPITokenInput{
		OrganizationID:       bootstrap.OrganizationID,
		AdminUserID:          bootstrap.AdminUserID,
		CreatedByAdminUserID: bootstrap.AdminUserID,
		Name:                 "automation",
		Scope:                scope,
		RequestID:            mustIdentifier(t, id.AdminRequest),
	})
	if err != nil {
		t.Fatalf("CreateAPIToken() error = %v", err)
	}
	apiPrincipal, err := store.AuthenticateAPIToken(ctx, apiToken.Token.Reveal())
	if err != nil {
		t.Fatalf("AuthenticateAPIToken() error = %v", err)
	}
	if !apiPrincipal.Allows(ManageSecrets, AuthorizationContext{}) ||
		apiPrincipal.Allows(RunSelfTests, AuthorizationContext{}) {
		t.Fatalf("API principal scope is incorrect")
	}
	refreshedAPIPrincipal, err := store.RevalidatePrincipal(ctx, apiPrincipal)
	if err != nil || !refreshedAPIPrincipal.Allows(ManageSecrets, AuthorizationContext{}) ||
		refreshedAPIPrincipal.Allows(RunSelfTests, AuthorizationContext{}) ||
		refreshedAPIPrincipal.CredentialID != apiPrincipal.CredentialID ||
		refreshedAPIPrincipal.Method != AuthenticationAPIToken {
		t.Fatalf("RevalidatePrincipal(API token) = %+v, error = %v", refreshedAPIPrincipal, err)
	}
	if err := store.RevokeAPIToken(
		ctx,
		apiToken.APITokenID,
		viewerActor,
		mustIdentifier(t, id.AdminRequest),
		"unauthorized",
	); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("RevokeAPIToken(cross-user viewer) error = %v", err)
	}
	if _, err := store.AuthenticateAPIToken(ctx, apiToken.Token.Reveal()); err != nil {
		t.Fatalf("API token changed by unauthorized revocation: %v", err)
	}
	if err := store.RevokeAPIToken(ctx, apiToken.APITokenID, actor, mustIdentifier(t, id.AdminRequest), "rotation"); err != nil {
		t.Fatalf("RevokeAPIToken() error = %v", err)
	}
	if _, err := store.RevalidatePrincipal(ctx, apiPrincipal); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("RevalidatePrincipal(revoked API token) error = %v", err)
	}
	if _, err := store.AuthenticateAPIToken(ctx, apiToken.Token.Reveal()); !errors.Is(err, ErrAdminAuthentication) {
		t.Fatalf("AuthenticateAPIToken(revoked) error = %v", err)
	}
	if err := store.RevokeAPIToken(
		ctx,
		viewerToken.APITokenID,
		viewerActor,
		mustIdentifier(t, id.AdminRequest),
		"self rotation",
	); err != nil {
		t.Fatalf("RevokeAPIToken(viewer self) error = %v", err)
	}

	var eventID string
	if err := pool.QueryRow(ctx, `
		SELECT audit_event_id
		FROM audit_events
		WHERE action = 'admin.bootstrap_owner'
	`).Scan(&eventID); err != nil {
		t.Fatalf("read bootstrap audit event: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_event_changes (
			audit_event_id, ordinal, field_name, operation, classification
		) VALUES ($1, 99, 'refresh_token', 'set', 'public')
	`, eventID); err == nil {
		t.Fatal("database accepted public sensitive audit field")
	}

	var bootstrapRows int
	var ownerRows int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM admin_bootstrap_tokens WHERE consumed_at IS NOT NULL").Scan(&bootstrapRows); err != nil {
		t.Fatalf("count consumed bootstrap tokens: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM admin_memberships WHERE role = 'owner'").Scan(&ownerRows); err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if bootstrapRows != 1 || ownerRows != 1 {
		t.Fatalf("bootstrap rows=%d owners=%d", bootstrapRows, ownerRows)
	}
}

func idNew(prefix id.Prefix) (string, error) {
	return id.New(prefix)
}
