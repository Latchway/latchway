package identity

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

var identityIntegrationSchemaPattern = regexp.MustCompile(`^latchway_identity_test_[0-9]+$`)

func TestUserStorePostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer adminPool.Close()
	schema := fmt.Sprintf("latchway_identity_test_%d", time.Now().UnixNano())
	if !identityIntegrationSchemaPattern.MatchString(schema) {
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
	pool, err := database.Open(ctx, parsedURL.String(), 8)
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	defer pool.Close()
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	organizationID := mustPrivacyID(t, id.Organization)
	applicationID := mustPrivacyID(t, id.Application)
	secondApplicationID := mustPrivacyID(t, id.Application)
	instant := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, 'identity-test', 'Identity Test', $2, $2)
	`, organizationID, instant); err != nil {
		t.Fatalf("create organization fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, $2, 'primary-app', 'Primary App', $3, $3),
		       ($4, $2, 'second-app', 'Second App', $3, $3)
	`, applicationID, organizationID, instant, secondApplicationID); err != nil {
		t.Fatalf("create application fixtures: %v", err)
	}

	protector, err := NewSubjectProtector(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatalf("construct protector: %v", err)
	}
	store, err := newUserStore(pool, protector, id.New, func() time.Time { return instant })
	if err != nil {
		t.Fatalf("construct user store: %v", err)
	}
	scope := UserScope{OrganizationID: organizationID, ApplicationID: applicationID}
	principal := VerifiedPrincipal{
		ProviderID: "firebase", Issuer: "https://securetoken.google.com/example", Subject: "raw-provider-user-123",
		Audience: []string{"example"}, AuthenticatedAt: instant.Add(-time.Minute), ExpiresAt: instant.Add(time.Hour),
		Claims: map[string]any{"plan": "free", "email_verified": true},
	}

	first, err := store.Resolve(ctx, scope, principal)
	if err != nil {
		t.Fatalf("resolve first identity: %v", err)
	}
	if id.Validate(first.ID, id.ApplicationUser) != nil || first.Status != "active" || first.Claims["plan"] != "free" {
		t.Fatalf("unexpected first user: %#v", first)
	}
	instant = instant.Add(time.Minute)
	principal.Claims = map[string]any{"plan": "pro"}
	second, err := store.Resolve(ctx, scope, principal)
	if err != nil {
		t.Fatalf("resolve repeated identity: %v", err)
	}
	if second.ID != first.ID || second.Claims["plan"] != "pro" {
		t.Fatalf("identity was not stable or claims did not refresh: first=%#v second=%#v", first, second)
	}
	if _, retained := second.Claims["email_verified"]; retained {
		t.Fatal("removed normalized claim remained on the user")
	}
	assertIdentityRowCounts(t, ctx, pool, applicationID, 1, 1)

	var issuerHash, subjectHMAC []byte
	var selectedClaims string
	if err := pool.QueryRow(ctx, `
		SELECT issuer_hash, subject_hmac, selected_claims::text
		FROM external_identities
		WHERE application_id = $1
	`, applicationID).Scan(&issuerHash, &subjectHMAC, &selectedClaims); err != nil {
		t.Fatalf("read privacy fields: %v", err)
	}
	if len(issuerHash) != 32 || len(subjectHMAC) != 32 || bytes.Contains(issuerHash, []byte(principal.Issuer)) || bytes.Contains(subjectHMAC, []byte(principal.Subject)) {
		t.Fatal("stored external identity fields are not fixed-size pseudonyms")
	}
	if strings.Contains(selectedClaims, principal.Subject) || strings.Contains(selectedClaims, principal.Issuer) || strings.Contains(selectedClaims, "email_verified") {
		t.Fatalf("unselected identity data persisted: %s", selectedClaims)
	}

	concurrentPrincipal := principal
	concurrentPrincipal.Subject = "concurrent-provider-user"
	const workers = 16
	results := make(chan ApplicationUser, workers)
	failures := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			resolved, resolveErr := store.Resolve(ctx, scope, concurrentPrincipal)
			results <- resolved
			failures <- resolveErr
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	var concurrentUserID string
	for resolveErr := range failures {
		if resolveErr != nil {
			t.Fatalf("concurrent identity resolution: %v", resolveErr)
		}
	}
	for resolved := range results {
		if concurrentUserID == "" {
			concurrentUserID = resolved.ID
		}
		if resolved.ID != concurrentUserID {
			t.Fatalf("concurrent resolution produced multiple users: %q and %q", concurrentUserID, resolved.ID)
		}
	}
	assertIdentityRowCounts(t, ctx, pool, applicationID, 2, 2)

	if err := store.SetBlocked(ctx, scope, first.ID, true); err != nil {
		t.Fatalf("block user: %v", err)
	}
	if _, err := store.Resolve(ctx, scope, principal); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("blocked identity should fail closed: %v", err)
	}
	if err := store.SetBlocked(ctx, scope, first.ID, false); err != nil {
		t.Fatalf("unblock user: %v", err)
	}
	if resolved, err := store.Resolve(ctx, scope, principal); err != nil || resolved.ID != first.ID {
		t.Fatalf("unblocked identity did not recover: user=%#v err=%v", resolved, err)
	}

	otherProvider := principal
	otherProvider.ProviderID = "clerk"
	providerUser, err := store.Resolve(ctx, scope, otherProvider)
	if err != nil || providerUser.ID == first.ID {
		t.Fatalf("provider namespace did not separate users: user=%#v err=%v", providerUser, err)
	}
	otherIssuer := principal
	otherIssuer.Issuer = "https://securetoken.google.com/other"
	issuerUser, err := store.Resolve(ctx, scope, otherIssuer)
	if err != nil || issuerUser.ID == first.ID {
		t.Fatalf("issuer namespace did not separate users: user=%#v err=%v", issuerUser, err)
	}
	otherScope := UserScope{OrganizationID: organizationID, ApplicationID: secondApplicationID}
	applicationUser, err := store.Resolve(ctx, otherScope, principal)
	if err != nil || applicationUser.ID == first.ID {
		t.Fatalf("application namespace did not separate users: user=%#v err=%v", applicationUser, err)
	}
	firstMAC := subjectHMAC
	var secondMAC []byte
	if err := pool.QueryRow(ctx, `SELECT subject_hmac FROM external_identities WHERE application_id = $1 AND provider_key = 'firebase' AND issuer_hash = $2`, secondApplicationID, issuerHash).Scan(&secondMAC); err != nil {
		t.Fatalf("read second app subject HMAC: %v", err)
	}
	if bytes.Equal(firstMAC, secondMAC) {
		t.Fatal("subject lookup value correlated across applications")
	}

	if _, err := pool.Exec(ctx, `UPDATE applications SET status = 'disabled', disabled_at = $2, updated_at = $2 WHERE application_id = $1`, applicationID, instant); err != nil {
		t.Fatalf("disable application fixture: %v", err)
	}
	if _, err := store.Resolve(ctx, scope, principal); !errors.Is(err, ErrIdentityScope) {
		t.Fatalf("disabled application should fail closed: %v", err)
	}
}

func assertIdentityRowCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, applicationID string, wantUsers, wantIdentities int) {
	t.Helper()
	var users, identities int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM application_users WHERE application_id = $1", applicationID).Scan(&users); err != nil {
		t.Fatalf("count application users: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM external_identities WHERE application_id = $1", applicationID).Scan(&identities); err != nil {
		t.Fatalf("count external identities: %v", err)
	}
	if users != wantUsers || identities != wantIdentities {
		t.Fatalf("identity row counts users=%d/%d identities=%d/%d", users, wantUsers, identities, wantIdentities)
	}
}
