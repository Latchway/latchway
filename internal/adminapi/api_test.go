package adminapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/problem"
	secretstore "github.com/latchway/latchway/internal/secrets"
)

var adminAPIIntegrationSchemaPattern = regexp.MustCompile(`^latchway_adminapi_test_[0-9]+$`)

func TestDecodeJSONRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "missing content type", body: `{"slug":"valid-name","display_name":"Valid"}`},
		{name: "duplicate key", contentType: "application/json", body: `{"slug":"valid-name","slug":"other-name","display_name":"Valid"}`},
		{name: "unknown field", contentType: "application/json", body: `{"slug":"valid-name","display_name":"Valid","secret":"unexpected"}`},
		{name: "trailing document", contentType: "application/json", body: `{"slug":"valid-name","display_name":"Valid"} {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, "/organizations", strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if _, err := decodeJSON[struct {
				Slug        string `json:"slug"`
				DisplayName string `json:"display_name"`
			}](request); err == nil {
				t.Fatal("decodeJSON() accepted unsafe or ambiguous input")
			}
		})
	}
}

func TestWithConfigurationStore(t *testing.T) {
	t.Parallel()

	api := &API{}
	store := new(configuration.Store)
	if err := WithConfigurationStore(store)(api); err != nil {
		t.Fatalf("WithConfigurationStore() error = %v", err)
	}
	if api.configurations != store {
		t.Fatal("WithConfigurationStore() did not retain the supplied store")
	}
	if err := WithConfigurationStore(nil)(api); err == nil {
		t.Fatal("WithConfigurationStore(nil) succeeded")
	}
}

func TestFailureLimiterUsesSlidingWindow(t *testing.T) {
	t.Parallel()

	limiter := newFailureLimiter(2, time.Minute)
	key := [32]byte{1}
	instant := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	if !limiter.allow(key, instant) {
		t.Fatal("new key should be allowed")
	}
	limiter.failure(key, instant)
	limiter.failure(key, instant.Add(time.Second))
	if limiter.allow(key, instant.Add(2*time.Second)) {
		t.Fatal("key at the failure limit should be rejected")
	}
	if !limiter.allow(key, instant.Add(2*time.Minute)) {
		t.Fatal("expired failures should be pruned")
	}
}

func TestAdminAPIPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	api, err := New(pool, "https://console.example.test", 12*time.Hour, logger, testAdminSecretManager(t, pool))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	bootstrapToken := strings.Repeat("api-bootstrap-secret-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatalf("InitializeBootstrap() error = %v", err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)

	bootstrapBody := map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "example-org",
		"organization_name": "Example Organization", "email": "owner@example.test",
		"display_name": "Example Owner", "password": "correct horse battery staple",
	}
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", bootstrapBody, nil, "", "https://console.example.test")
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status = %d, body = %s", bootstrap.Code, bootstrap.Body.String())
	}
	csrf := bootstrap.Header().Get(csrfHeader)
	if csrf == "" {
		t.Fatal("bootstrap response did not include a CSRF token")
	}
	cookies := bootstrap.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != adminCookieName || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode ||
		cookies[1].Name != csrfCookieName || cookies[1].HttpOnly || !cookies[1].Secure || cookies[1].SameSite != http.SameSiteStrictMode || cookies[1].Value != csrf {
		t.Fatalf("bootstrap cookie attributes are not secure: count=%d", len(cookies))
	}

	var session struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &session)
	if session.OrganizationID == "" {
		t.Fatal("bootstrap response omitted the active organization")
	}

	secondBootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", bootstrapBody, nil, "", "https://console.example.test")
	if secondBootstrap.Code != http.StatusConflict {
		t.Fatalf("second bootstrap status = %d, want %d", secondBootstrap.Code, http.StatusConflict)
	}

	applicationBody := map[string]string{
		"organization_id": session.OrganizationID,
		"slug":            "example-app",
		"display_name":    "Example Application",
	}
	application := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", applicationBody, cookies[0], csrf, "https://console.example.test")
	if application.Code != http.StatusCreated {
		t.Fatalf("create application status = %d, body = %s", application.Code, application.Body.String())
	}
	var applicationDocument struct {
		ID string `json:"id"`
	}
	decodeResponse(t, application, &applicationDocument)
	secondApplicationBody := map[string]string{
		"organization_id": session.OrganizationID,
		"slug":            "second-app",
		"display_name":    "Second Application",
	}
	secondApplication := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", secondApplicationBody, cookies[0], csrf, "https://console.example.test")
	if secondApplication.Code != http.StatusCreated {
		t.Fatalf("create second application status = %d, body = %s", secondApplication.Code, secondApplication.Body.String())
	}

	firstPage := performGET(handler, "/admin/v1/applications?organization_id="+url.QueryEscape(session.OrganizationID)+"&page_size=1", cookies[0])
	if firstPage.Code != http.StatusOK {
		t.Fatalf("first application page status = %d, body = %s", firstPage.Code, firstPage.Body.String())
	}
	var firstPageDocument struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Page struct {
			HasMore    bool   `json:"has_more"`
			NextCursor string `json:"next_cursor"`
		} `json:"page"`
	}
	decodeResponse(t, firstPage, &firstPageDocument)
	if len(firstPageDocument.Items) != 1 || !firstPageDocument.Page.HasMore || firstPageDocument.Page.NextCursor == "" {
		t.Fatalf("unexpected first application page: %+v", firstPageDocument)
	}
	secondPage := performGET(handler, "/admin/v1/applications?organization_id="+url.QueryEscape(session.OrganizationID)+"&page_size=1&cursor="+url.QueryEscape(firstPageDocument.Page.NextCursor), cookies[0])
	if secondPage.Code != http.StatusOK {
		t.Fatalf("second application page status = %d, body = %s", secondPage.Code, secondPage.Body.String())
	}
	var secondPageDocument struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Page struct {
			HasMore bool `json:"has_more"`
		} `json:"page"`
	}
	decodeResponse(t, secondPage, &secondPageDocument)
	if len(secondPageDocument.Items) != 1 || secondPageDocument.Page.HasMore || secondPageDocument.Items[0].ID == firstPageDocument.Items[0].ID {
		t.Fatalf("unexpected second application page: %+v", secondPageDocument)
	}

	environmentBody := map[string]string{"slug": "production", "display_name": "Production", "kind": "production"}
	environment := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+applicationDocument.ID+"/environments", environmentBody, cookies[0], csrf, "https://console.example.test")
	if environment.Code != http.StatusCreated {
		t.Fatalf("create environment status = %d, body = %s", environment.Code, environment.Body.String())
	}

	secondLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": bootstrapBody["email"], "password": bootstrapBody["password"],
		"organization_id": session.OrganizationID,
	}, nil, "", "https://console.example.test")
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("second login status = %d, body = %s", secondLogin.Code, secondLogin.Body.String())
	}
	secondCookies := secondLogin.Result().Cookies()
	if len(secondCookies) != 2 {
		t.Fatalf("second login cookie count = %d", len(secondCookies))
	}
	type adminSessionItem struct {
		ID            string `json:"id"`
		Administrator struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"administrator"`
		CreatedAt  time.Time `json:"created_at"`
		LastSeenAt time.Time `json:"last_seen_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		Status     string    `json:"status"`
		Current    bool      `json:"current"`
	}
	type adminSessionPage struct {
		Items []adminSessionItem `json:"items"`
		Page  struct {
			HasMore    bool   `json:"has_more"`
			NextCursor string `json:"next_cursor"`
		} `json:"page"`
	}
	firstSessionPageResponse := performGET(handler, "/admin/v1/admin-sessions?page_size=1", cookies[0])
	if firstSessionPageResponse.Code != http.StatusOK {
		t.Fatalf("first administrator-session page status/body = %d %s", firstSessionPageResponse.Code, firstSessionPageResponse.Body.String())
	}
	var firstSessionPage adminSessionPage
	decodeResponse(t, firstSessionPageResponse, &firstSessionPage)
	if len(firstSessionPage.Items) != 1 || !firstSessionPage.Page.HasMore || firstSessionPage.Page.NextCursor == "" {
		t.Fatalf("unexpected first administrator-session page: %+v", firstSessionPage)
	}
	secondSessionPageResponse := performGET(handler, "/admin/v1/admin-sessions?page_size=1&cursor="+url.QueryEscape(firstSessionPage.Page.NextCursor), cookies[0])
	if secondSessionPageResponse.Code != http.StatusOK {
		t.Fatalf("second administrator-session page status/body = %d %s", secondSessionPageResponse.Code, secondSessionPageResponse.Body.String())
	}
	var secondSessionPage adminSessionPage
	decodeResponse(t, secondSessionPageResponse, &secondSessionPage)
	if len(secondSessionPage.Items) != 1 || secondSessionPage.Page.HasMore || secondSessionPage.Items[0].ID == firstSessionPage.Items[0].ID {
		t.Fatalf("unexpected second administrator-session page: %+v", secondSessionPage)
	}
	allSessions := append(firstSessionPage.Items, secondSessionPage.Items...)
	currentSessionID := ""
	otherSessionID := ""
	for _, item := range allSessions {
		if item.ID == "" || item.Administrator.ID == "" || item.Administrator.Email != bootstrapBody["email"] ||
			item.CreatedAt.IsZero() || item.LastSeenAt.IsZero() || item.ExpiresAt.IsZero() || item.Status != "active" {
			t.Fatalf("unsafe or incomplete administrator-session item: %+v", item)
		}
		if item.Current {
			if currentSessionID != "" {
				t.Fatal("administrator-session page identified multiple current sessions")
			}
			currentSessionID = item.ID
		} else {
			otherSessionID = item.ID
		}
	}
	if currentSessionID == "" || otherSessionID == "" {
		t.Fatalf("administrator-session current mapping is incomplete: %+v", allSessions)
	}
	for _, forbidden := range []string{"token_hint", "token_hash", "csrf_token", "revoke_reason", "ip_address"} {
		if bytes.Contains(firstSessionPageResponse.Body.Bytes(), []byte(forbidden)) || bytes.Contains(secondSessionPageResponse.Body.Bytes(), []byte(forbidden)) {
			t.Fatalf("administrator-session response exposed forbidden field %q", forbidden)
		}
	}
	if invalidSessionPage := performGET(handler, "/admin/v1/admin-sessions?page_size=201", cookies[0]); invalidSessionPage.Code != http.StatusBadRequest {
		t.Fatalf("invalid administrator-session page status/body = %d %s", invalidSessionPage.Code, invalidSessionPage.Body.String())
	}
	unauthenticatedSessions := performGET(handler, "/admin/v1/admin-sessions", nil)
	if unauthenticatedSessions.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated administrator-session list status = %d", unauthenticatedSessions.Code)
	}
	systemStatus := performGET(handler, "/admin/v1/system", cookies[0])
	if systemStatus.Code != http.StatusOK {
		t.Fatalf("system status = %d, body = %s", systemStatus.Code, systemStatus.Body.String())
	}
	var systemDocument struct {
		ServerCapabilities []serverCapability `json:"server_capabilities"`
	}
	decodeResponse(t, systemStatus, &systemDocument)
	if !reflect.DeepEqual(systemDocument.ServerCapabilities, serverCapabilities()) {
		t.Fatalf("system server capabilities = %q, want %q", systemDocument.ServerCapabilities, serverCapabilities())
	}
	if unauthenticatedSystem := performGET(handler, "/admin/v1/system", nil); unauthenticatedSystem.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated system status = %d", unauthenticatedSystem.Code)
	}

	apiTokenResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{
		"name": "automation", "scopes": []string{"inspect_users"},
	}, cookies[0], csrf, "https://console.example.test")
	if apiTokenResponse.Code != http.StatusCreated {
		t.Fatalf("create API token status = %d, body = %s", apiTokenResponse.Code, apiTokenResponse.Body.String())
	}
	var createdToken struct {
		Token    string `json:"token"`
		Metadata struct {
			ID string `json:"id"`
		} `json:"metadata"`
	}
	decodeResponse(t, apiTokenResponse, &createdToken)
	if createdToken.Token == "" || createdToken.Metadata.ID == "" {
		t.Fatal("created API token response omitted one-time token material or metadata")
	}
	bearerSession := performBearerGET(handler, "/admin/v1/auth/session", createdToken.Token)
	if bearerSession.Code != http.StatusOK || !bytes.Contains(bearerSession.Body.Bytes(), []byte(`"expires_at":null`)) {
		t.Fatalf("API-token session status/body = %d %s", bearerSession.Code, bearerSession.Body.String())
	}
	escalation := performBearerJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{
		"name": "scope-escalation", "scopes": []string{"manage_owners"},
	}, createdToken.Token)
	if escalation.Code != http.StatusForbidden {
		t.Fatalf("API-token scope escalation status/body = %d %s", escalation.Code, escalation.Body.String())
	}
	unauthorizedSessionList := performBearerGET(handler, "/admin/v1/admin-sessions", createdToken.Token)
	if unauthorizedSessionList.Code != http.StatusForbidden {
		t.Fatalf("API-token administrator-session list status/body = %d %s", unauthorizedSessionList.Code, unauthorizedSessionList.Body.String())
	}
	managerTokenResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{
		"name": "session-manager", "scopes": []string{"manage_owners"},
	}, cookies[0], csrf, "https://console.example.test")
	if managerTokenResponse.Code != http.StatusCreated {
		t.Fatalf("create session-manager token status/body = %d %s", managerTokenResponse.Code, managerTokenResponse.Body.String())
	}
	var managerToken struct {
		Token string `json:"token"`
	}
	decodeResponse(t, managerTokenResponse, &managerToken)
	managedSessionListResponse := performBearerGET(handler, "/admin/v1/admin-sessions", managerToken.Token)
	if managedSessionListResponse.Code != http.StatusOK {
		t.Fatalf("manage_owners API-token session list status/body = %d %s", managedSessionListResponse.Code, managedSessionListResponse.Body.String())
	}
	var managedSessionList adminSessionPage
	decodeResponse(t, managedSessionListResponse, &managedSessionList)
	if len(managedSessionList.Items) != 2 {
		t.Fatalf("manage_owners API-token session list = %+v", managedSessionList)
	}
	for _, item := range managedSessionList.Items {
		if item.Current {
			t.Fatalf("API-token-authenticated session list marked a cookie session current: %+v", item)
		}
	}
	tokenList := performGET(handler, "/admin/v1/api-tokens", cookies[0])
	if tokenList.Code != http.StatusOK || bytes.Contains(tokenList.Body.Bytes(), []byte(createdToken.Token)) {
		t.Fatalf("API token metadata list status/body = %d %s", tokenList.Code, tokenList.Body.String())
	}
	revoked := performJSON(t, handler, http.MethodDelete, "/admin/v1/api-tokens/"+createdToken.Metadata.ID, nil, cookies[0], csrf, "https://console.example.test")
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke API token status = %d, body = %s", revoked.Code, revoked.Body.String())
	}
	if afterRevoke := performBearerGET(handler, "/admin/v1/auth/session", createdToken.Token); afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked API token session status = %d, want %d", afterRevoke.Code, http.StatusUnauthorized)
	}

	missingSessionCSRF := performJSON(t, handler, http.MethodPost, "/admin/v1/admin-sessions/"+otherSessionID+"/revoke", nil, cookies[0], "", "https://console.example.test")
	if missingSessionCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing-CSRF administrator-session revoke status/body = %d %s", missingSessionCSRF.Code, missingSessionCSRF.Body.String())
	}
	revokedSession := performBearerJSON(t, handler, http.MethodPost, "/admin/v1/admin-sessions/"+otherSessionID+"/revoke", nil, managerToken.Token)
	if revokedSession.Code != http.StatusNoContent {
		t.Fatalf("administrator-session revoke status/body = %d %s", revokedSession.Code, revokedSession.Body.String())
	}
	idempotentSessionRevoke := performJSON(t, handler, http.MethodPost, "/admin/v1/admin-sessions/"+otherSessionID+"/revoke", nil, cookies[0], csrf, "https://console.example.test")
	if idempotentSessionRevoke.Code != http.StatusNoContent {
		t.Fatalf("idempotent administrator-session revoke status/body = %d %s", idempotentSessionRevoke.Code, idempotentSessionRevoke.Body.String())
	}
	if afterSessionRevoke := performGET(handler, "/admin/v1/auth/session", secondCookies[0]); afterSessionRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked administrator cookie session status = %d, want %d", afterSessionRevoke.Code, http.StatusUnauthorized)
	}

	missingCSRF := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", applicationBody, cookies[0], "", "https://console.example.test")
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing-CSRF mutation status = %d, want %d", missingCSRF.Code, http.StatusForbidden)
	}
	selfRevoked := performJSON(t, handler, http.MethodPost, "/admin/v1/admin-sessions/"+currentSessionID+"/revoke", nil, cookies[0], csrf, "https://console.example.test")
	if selfRevoked.Code != http.StatusNoContent {
		t.Fatalf("current administrator-session revoke status/body = %d %s", selfRevoked.Code, selfRevoked.Body.String())
	}
	clearedCookies := selfRevoked.Result().Cookies()
	if len(clearedCookies) != 2 || clearedCookies[0].MaxAge != -1 || clearedCookies[1].MaxAge != -1 {
		t.Fatalf("current administrator-session revoke did not clear both cookies: %+v", clearedCookies)
	}
	if afterSelfRevoke := performGET(handler, "/admin/v1/auth/session", cookies[0]); afterSelfRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("self-revoked administrator session status = %d, want %d", afterSelfRevoke.Code, http.StatusUnauthorized)
	}

	assertAdministrativePersistence(t, ctx, pool, bootstrapToken, bootstrapBody["password"], createdToken.Token, managerToken.Token)
}

func TestAuditRejectedMutationPostgreSQLIndeterminateCorrelation(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(
		pool, "https://console.example.test", 12*time.Hour,
		slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool),
	)
	if err != nil {
		t.Fatal(err)
	}
	operationIDs := make(chan string, 1)
	handler := api.auditRejectedMutation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operationID, operationErr := newMutationOperationID(r.Context())
		if operationErr != nil {
			t.Fatalf("create operation ID: %v", operationErr)
		}
		markMutationIndeterminate(r.Context())
		operationIDs <- operationID
		api.writeProblem(w, r, problem.Error{
			Code: "operation_indeterminate", OperationID: operationID,
			Detail: "The commit acknowledgement was lost.",
		})
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/admin/v1/secrets", nil))
	operationID := <-operationIDs
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var outcome, requestID, resourceID string
	if err := pool.QueryRow(ctx, `
		SELECT outcome, request_id, resource_id
		FROM audit_events
		WHERE action = 'admin.secret_create'
	`).Scan(&outcome, &requestID, &resourceID); err != nil {
		t.Fatal(err)
	}
	if outcome != string(adminauth.AuditIndeterminate) || requestID != operationID || resourceID != operationID {
		t.Fatalf("audit outcome=%q request_id=%q resource_id=%q operation_id=%q", outcome, requestID, resourceID, operationID)
	}
}

func isolatedAdminAPIPool(t *testing.T, ctx context.Context, databaseURL string) *pgxpool.Pool {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)

	schema := fmt.Sprintf("latchway_adminapi_test_%d", time.Now().UnixNano())
	if !adminAPIIntegrationSchemaPattern.MatchString(schema) {
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
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func testAdminSecretManager(t *testing.T, pool *pgxpool.Pool) *secretstore.Manager {
	t.Helper()
	provider, err := secretstore.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xc7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := secretstore.NewManager(secretstore.ManagerConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func performJSON(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if csrf != "" {
		request.Header.Set(csrfHeader, csrf)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func performGET(handler http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func performBearerGET(handler http.Handler, path, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func assertAdministrativePersistence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, secrets ...string) {
	t.Helper()
	var owners, applications, environments int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM admin_memberships WHERE role = 'owner' AND status = 'active'").Scan(&owners); err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM applications").Scan(&applications); err != nil {
		t.Fatalf("count applications: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM environments").Scan(&environments); err != nil {
		t.Fatalf("count environments: %v", err)
	}
	if owners != 1 || applications != 2 || environments != 1 {
		t.Fatalf("persisted owners=%d applications=%d environments=%d", owners, applications, environments)
	}

	expectedEvents := map[string]int{
		"admin.bootstrap_owner:succeeded":    1,
		"admin.session_create:succeeded":     2,
		"admin.session_revoke:succeeded":     2,
		"admin.session_revoke:denied":        1,
		"admin.application_create:succeeded": 2,
		"admin.environment_create:succeeded": 1,
		"admin.api_token_create:succeeded":   2,
		"admin.api_token_create:denied":      1,
		"admin.api_token_revoke:succeeded":   1,
		"admin.bootstrap_owner:denied":       1,
		"admin.application_create:denied":    1,
	}
	rows, err := pool.Query(ctx, `
		SELECT action, outcome, count(*)
		FROM audit_events
		GROUP BY action, outcome
	`)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, outcome string
		var count int
		if err := rows.Scan(&action, &outcome, &count); err != nil {
			t.Fatalf("scan audit event: %v", err)
		}
		key := action + ":" + outcome
		expectedCount, ok := expectedEvents[key]
		if !ok {
			t.Fatalf("unexpected audit outcome %s with count %d", key, count)
		}
		if count != expectedCount {
			t.Fatalf("audit outcome %s count = %d, want %d", key, count, expectedCount)
		}
		delete(expectedEvents, key)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit events: %v", err)
	}
	if len(expectedEvents) != 0 {
		t.Fatalf("missing expected audit outcomes: %v", expectedEvents)
	}

	var auditText string
	if err := pool.QueryRow(ctx, `
		SELECT coalesce(string_agg(row_to_json(event)::text || row_to_json(change)::text, ''), '')
		FROM audit_events AS event
		LEFT JOIN audit_event_changes AS change USING (audit_event_id)
	`).Scan(&auditText); err != nil {
		t.Fatalf("read redaction evidence: %v", err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(auditText, secret) {
			t.Fatal("audit records contain a plaintext credential")
		}
	}
}
