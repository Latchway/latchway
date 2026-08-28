package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
)

func TestUserLimitOverrideAdminAPIPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(pool, "https://console.example.test", 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("override-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)

	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "override-org",
		"organization_name": "Override Org", "email": "owner-override@example.test",
		"display_name": "Override Owner", "password": "correct horse battery staple",
	}, nil, "", "https://console.example.test")
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var session struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &session)
	cookie := bootstrap.Result().Cookies()[0]
	csrf := bootstrap.Header().Get(csrfHeader)

	applicationResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", map[string]string{
		"organization_id": session.OrganizationID, "slug": "override-app", "display_name": "Override App",
	}, cookie, csrf, "https://console.example.test")
	var application struct {
		ID string `json:"id"`
	}
	decodeResponse(t, applicationResponse, &application)
	environmentResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{
		"slug": "production", "display_name": "Production", "kind": "production",
	}, cookie, csrf, "https://console.example.test")
	var environment struct {
		ID string `json:"id"`
	}
	decodeResponse(t, environmentResponse, &environment)

	document := configurationObjectForAPI(t, "user override")
	document["metadata"].(map[string]any)["organization"] = "override-org"
	document["metadata"].(map[string]any)["application"] = "override-app"
	created := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/environments/"+environment.ID+"/config-revisions",
		map[string]any{"document": document}, cookie, csrf, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("create config status=%d body=%s", created.Code, created.Body.String())
	}
	var revision configuration.Revision
	decodeResponse(t, created, &revision)
	validated := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+revision.ID+"/validate", nil, cookie, csrf, "")
	if validated.Code != http.StatusOK {
		t.Fatalf("validate config status=%d body=%s", validated.Code, validated.Body.String())
	}
	activated := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+revision.ID+"/activate", nil, cookie, csrf, created.Header().Get("ETag"))
	if activated.Code != http.StatusOK {
		t.Fatalf("activate config status=%d body=%s", activated.Code, activated.Body.String())
	}

	userID := id.Must(id.ApplicationUser)
	externalIdentityID := id.Must(id.ExternalIdentity)
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id, status, normalized_claims
		) VALUES ($1, $2, $3, 'active', '{"tier":"free"}'::jsonb)
	`, userID, session.OrganizationID, application.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO external_identities (
			external_identity_id, organization_id, application_id, application_user_id,
			provider_key, issuer_hash, subject_hmac, selected_claims
		) VALUES ($1, $2, $3, $4, 'firebase', $5, $6, '{"tier":"free"}'::jsonb)
	`, externalIdentityID, session.OrganizationID, application.ID, userID, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}

	endpoint := "/admin/v1/users/" + userID + "/limit-override?environment_id=" + url.QueryEscape(environment.ID)
	body := map[string]any{"limit_plan": "free", "reason": "support-approved change"}
	missingEnvironment := performJSON(t, handler, http.MethodPut, "/admin/v1/users/"+userID+"/limit-override", body, cookie, csrf, "https://console.example.test")
	if missingEnvironment.Code != http.StatusBadRequest {
		t.Fatalf("missing environment status=%d body=%s", missingEnvironment.Code, missingEnvironment.Body.String())
	}
	missingCSRF := performJSON(t, handler, http.MethodPut, endpoint, body, cookie, "", "https://console.example.test")
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}
	missingPlan := performJSON(t, handler, http.MethodPut, endpoint, map[string]any{
		"limit_plan": "missing", "reason": "must fail closed",
	}, cookie, csrf, "https://console.example.test")
	if missingPlan.Code != http.StatusBadRequest {
		t.Fatalf("missing plan status=%d body=%s", missingPlan.Code, missingPlan.Body.String())
	}
	nullExpiry := performJSON(t, handler, http.MethodPut, endpoint, map[string]any{
		"limit_plan": "free", "reason": "explicit null is not a date-time", "expires_at": nil,
	}, cookie, csrf, "https://console.example.test")
	if nullExpiry.Code != http.StatusBadRequest {
		t.Fatalf("null expiry status=%d body=%s", nullExpiry.Code, nullExpiry.Body.String())
	}

	first := performJSON(t, handler, http.MethodPut, endpoint, body, cookie, csrf, "https://console.example.test")
	if first.Code != http.StatusOK {
		t.Fatalf("first override status=%d body=%s", first.Code, first.Body.String())
	}
	var firstUser userOverrideAPIUser
	decodeResponse(t, first, &firstUser)
	if firstUser.ID != userID || firstUser.EnvironmentID != environment.ID || firstUser.LimitPlanOverride == nil ||
		firstUser.LimitPlanOverride.LimitPlan != "free" || len(firstUser.IdentityProviders) != 1 || firstUser.IdentityProviders[0] != "firebase" {
		t.Fatalf("first override response=%+v", firstUser)
	}
	identical := performJSON(t, handler, http.MethodPut, endpoint, body, cookie, csrf, "https://console.example.test")
	var identicalUser userOverrideAPIUser
	decodeResponse(t, identical, &identicalUser)
	if identical.Code != http.StatusOK || identicalUser.LimitPlanOverride == nil || identicalUser.LimitPlanOverride.ID != firstUser.LimitPlanOverride.ID {
		t.Fatalf("identical PUT was not idempotent: status=%d body=%s", identical.Code, identical.Body.String())
	}

	inspectToken := createUserOverrideAPIToken(t, handler, cookie, csrf, "inspect-only", []string{"inspect_users"})
	denied := performBearerJSON(t, handler, http.MethodPut, endpoint, map[string]any{
		"limit_plan": "free", "reason": "viewer-like token must not mutate",
	}, inspectToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("inspect token mutation status=%d body=%s", denied.Code, denied.Body.String())
	}
	activateToken := createUserOverrideAPIToken(t, handler, cookie, csrf, "override-automation", []string{"activate_configuration"})
	replaced := performBearerJSON(t, handler, http.MethodPut, endpoint, map[string]any{
		"limit_plan": "free", "reason": "automated replacement",
	}, activateToken)
	if replaced.Code != http.StatusOK {
		t.Fatalf("activate token replacement status=%d body=%s", replaced.Code, replaced.Body.String())
	}
	var replacedUser userOverrideAPIUser
	decodeResponse(t, replaced, &replacedUser)
	if replacedUser.LimitPlanOverride == nil || replacedUser.LimitPlanOverride.ID == firstUser.LimitPlanOverride.ID {
		t.Fatalf("replacement did not create history: %s", replaced.Body.String())
	}

	cleared := performBearerJSON(t, handler, http.MethodDelete, endpoint, nil, activateToken)
	if cleared.Code != http.StatusNoContent || cleared.Body.Len() != 0 {
		t.Fatalf("clear status=%d body=%s", cleared.Code, cleared.Body.String())
	}
	clearedAgain := performBearerJSON(t, handler, http.MethodDelete, endpoint, nil, activateToken)
	if clearedAgain.Code != http.StatusNoContent || clearedAgain.Body.Len() != 0 {
		t.Fatalf("idempotent clear status=%d body=%s", clearedAgain.Code, clearedAgain.Body.String())
	}
	var ownerID string
	if err := pool.QueryRow(ctx, `
		SELECT admin_user_id FROM admin_memberships
		WHERE organization_id = $1 AND role = 'owner' AND status = 'active'
	`, session.OrganizationID).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	expiredID := id.Must(id.UserOverride)
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_overrides (
			user_override_id, organization_id, application_id, environment_id,
			application_user_id, override_document, reason, created_by_admin_user_id,
			created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, '{"limit_plan":"free"}'::jsonb,
		          'expired retained row', $6, transaction_timestamp() - interval '2 hours',
		          transaction_timestamp() - interval '1 hour')
	`, expiredID, session.OrganizationID, application.ID, environment.ID, userID, ownerID); err != nil {
		t.Fatal(err)
	}
	healed := performJSON(t, handler, http.MethodPut, endpoint, map[string]any{
		"limit_plan": "free", "reason": "replace expired retained row",
	}, cookie, csrf, "https://console.example.test")
	if healed.Code != http.StatusOK {
		t.Fatalf("expired-row replacement status=%d body=%s", healed.Code, healed.Body.String())
	}
	finalClear := performJSON(t, handler, http.MethodDelete, endpoint, nil, cookie, csrf, "https://console.example.test")
	if finalClear.Code != http.StatusNoContent || finalClear.Body.Len() != 0 {
		t.Fatalf("final clear status=%d body=%s", finalClear.Code, finalClear.Body.String())
	}
	const writers = 8
	statuses := make(chan int, writers)
	for index := 0; index < writers; index++ {
		go func(index int) {
			request := httptest.NewRequest(http.MethodPut, endpoint, strings.NewReader(fmt.Sprintf(
				`{"limit_plan":"free","reason":"concurrent replacement %d"}`, index,
			)))
			request.Header.Set("Authorization", "Bearer "+activateToken)
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			statuses <- recorder.Code
		}(index)
	}
	for index := 0; index < writers; index++ {
		if status := <-statuses; status != http.StatusOK {
			t.Fatalf("concurrent replacement status=%d", status)
		}
	}
	var activeRows int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM user_overrides
		WHERE environment_id = $1 AND application_user_id = $2 AND revoked_at IS NULL
	`, environment.ID, userID).Scan(&activeRows); err != nil {
		t.Fatal(err)
	}
	if activeRows != 1 {
		t.Fatalf("concurrent active rows=%d", activeRows)
	}
	concurrentClear := performBearerJSON(t, handler, http.MethodDelete, endpoint, nil, activateToken)
	if concurrentClear.Code != http.StatusNoContent || concurrentClear.Body.Len() != 0 {
		t.Fatalf("concurrent final clear status=%d body=%s", concurrentClear.Code, concurrentClear.Body.String())
	}

	// DELETE has no ApplicationUser response body, so cleanup must not depend
	// on the separate identity-provider projection being populated.
	providerlessUserID := id.Must(id.ApplicationUser)
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (application_user_id, organization_id, application_id)
		VALUES ($1, $2, $3)
	`, providerlessUserID, session.OrganizationID, application.ID); err != nil {
		t.Fatal(err)
	}
	providerlessEndpoint := "/admin/v1/users/" + providerlessUserID +
		"/limit-override?environment_id=" + url.QueryEscape(environment.ID)
	providerlessClear := performBearerJSON(
		t, handler, http.MethodDelete, providerlessEndpoint, nil, activateToken,
	)
	if providerlessClear.Code != http.StatusNoContent || providerlessClear.Body.Len() != 0 {
		t.Fatalf("providerless clear status=%d body=%s", providerlessClear.Code, providerlessClear.Body.String())
	}

	assertUserOverridePersistence(t, ctx, pool, environment.ID, userID)
}

type userOverrideAPIUser struct {
	ID                string   `json:"id"`
	EnvironmentID     string   `json:"environment_id"`
	IdentityProviders []string `json:"identity_providers"`
	LimitPlanOverride *struct {
		ID        string `json:"id"`
		LimitPlan string `json:"limit_plan"`
	} `json:"limit_plan_override"`
}

func createUserOverrideAPIToken(t *testing.T, handler http.Handler, cookie *http.Cookie, csrf, name string, scopes []string) string {
	t.Helper()
	response := performJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{
		"name": name, "scopes": scopes,
	}, cookie, csrf, "https://console.example.test")
	if response.Code != http.StatusCreated {
		t.Fatalf("create API token status=%d body=%s", response.Code, response.Body.String())
	}
	var document struct {
		Token string `json:"token"`
	}
	decodeResponse(t, response, &document)
	return document.Token
}

func performBearerJSON(t *testing.T, handler http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func assertUserOverridePersistence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, environmentID, userID string) {
	t.Helper()
	var rows, unrevoked int
	if err := pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE revoked_at IS NULL)
		FROM user_overrides WHERE environment_id = $1 AND application_user_id = $2
	`, environmentID, userID).Scan(&rows, &unrevoked); err != nil {
		t.Fatal(err)
	}
	if rows != 12 || unrevoked != 0 {
		t.Fatalf("override rows=%d unrevoked=%d", rows, unrevoked)
	}
	var replacementAudits, clearAudits int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE action = 'admin.user_limit_override_replace' AND outcome = 'succeeded'),
		       count(*) FILTER (WHERE action = 'admin.user_limit_override_clear' AND outcome = 'succeeded')
		FROM audit_events
	`).Scan(&replacementAudits, &clearAudits); err != nil {
		t.Fatal(err)
	}
	if replacementAudits != 12 || clearAudits != 5 {
		t.Fatalf("replacement audits=%d clear audits=%d", replacementAudits, clearAudits)
	}
	var deniedActorKind, deniedActorID, deniedOrganizationID string
	if err := pool.QueryRow(ctx, `
		SELECT actor_kind, actor_id, organization_id
		FROM audit_events
		WHERE action = 'admin.user_limit_override_replace'
		  AND outcome = 'denied' AND actor_kind = 'admin_api_token'
		ORDER BY occurred_at DESC, audit_event_id DESC
		LIMIT 1
	`).Scan(&deniedActorKind, &deniedActorID, &deniedOrganizationID); err != nil {
		t.Fatal(err)
	}
	if deniedActorKind != "admin_api_token" || id.Validate(deniedActorID, id.AdminAPIToken) != nil ||
		deniedOrganizationID == "" {
		t.Fatalf("denied override audit actor=%s/%s organization=%s",
			deniedActorKind, deniedActorID, deniedOrganizationID)
	}
}
