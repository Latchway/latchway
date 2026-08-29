package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/configuration"
)

func TestConfigurationAdminAPIPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(pool, "https://console.example.test", 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("configuration-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)

	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "example",
		"organization_name": "Example", "email": "owner-config@example.test",
		"display_name": "Owner", "password": "correct horse battery staple",
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
		"organization_id": session.OrganizationID, "slug": "habits", "display_name": "Habits",
	}, cookie, csrf, "https://console.example.test")
	if applicationResponse.Code != http.StatusCreated {
		t.Fatalf("application status=%d body=%s", applicationResponse.Code, applicationResponse.Body.String())
	}
	var application struct {
		ID string `json:"id"`
	}
	decodeResponse(t, applicationResponse, &application)
	environmentResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{
		"slug": "production", "display_name": "Production", "kind": "production",
	}, cookie, csrf, "https://console.example.test")
	if environmentResponse.Code != http.StatusCreated {
		t.Fatalf("environment status=%d body=%s", environmentResponse.Code, environmentResponse.Body.String())
	}
	var environment struct {
		ID string `json:"id"`
	}
	decodeResponse(t, environmentResponse, &environment)

	initialDocument := configurationObjectForAPI(t, "initial")
	create := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/environments/"+environment.ID+"/config-revisions",
		map[string]any{"document": initialDocument, "description": "initial"}, cookie, csrf, "")
	if create.Code != http.StatusCreated || create.Header().Get("ETag") == "" {
		t.Fatalf("create revision status=%d ETag=%q body=%s", create.Code, create.Header().Get("ETag"), create.Body.String())
	}
	var initial configuration.Revision
	decodeResponse(t, create, &initial)
	initialETag := create.Header().Get("ETag")
	validation := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+initial.ID+"/validate", nil, cookie, csrf, "")
	var initialReport configuration.ValidationReport
	decodeResponse(t, validation, &initialReport)
	if validation.Code != http.StatusOK || !initialReport.Valid {
		t.Fatalf("validate initial status=%d report=%+v", validation.Code, initialReport)
	}
	authenticated := true
	simulation := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+initial.ID+"/simulate", map[string]any{
			"feature": "assistant", "platform": "ios", "trust_level": "app_verified",
			"principal": map[string]any{"authenticated": authenticated, "claims": map[string]any{}},
			"request":   map[string]any{"streaming": true},
		}, cookie, csrf, "")
	if simulation.Code != http.StatusOK || !bytes.Contains(simulation.Body.Bytes(), []byte(`"allowed":true`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"route":"primary"`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"limit_plan":"free"`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"application_id":"`+application.ID+`"`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"environment_id":"`+environment.ID+`"`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"revision_id":"`+initial.ID+`"`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"applied_output_maximum":800`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"metric":"logical_requests","algorithm":"calendar","units":1,"applicable":true,"durable":true`)) ||
		!bytes.Contains(simulation.Body.Bytes(), []byte(`"fact":"requested_input_tokens","role":"explanatory","affects_cel":false`)) ||
		bytes.Contains(simulation.Body.Bytes(), []byte("api.example.test")) {
		t.Fatalf("route simulation status=%d body=%s", simulation.Code, simulation.Body.String())
	}
	unknownSimulationFact := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+initial.ID+"/simulate", map[string]any{
			"feature": "assistant", "platform": "ios", "trust_level": "app_verified",
			"principal": map[string]any{"authenticated": authenticated, "claims": map[string]any{}},
			"request":   map[string]any{"streaming": true, "untrusted_decision": true},
		}, cookie, csrf, "")
	if unknownSimulationFact.Code != http.StatusBadRequest {
		t.Fatalf("unknown route-simulation fact status=%d body=%s", unknownSimulationFact.Code, unknownSimulationFact.Body.String())
	}
	unauthenticated := false
	deniedSimulation := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+initial.ID+"/simulate", map[string]any{
			"feature": "assistant", "platform": "ios",
			"principal": map[string]any{"authenticated": unauthenticated, "claims": map[string]any{}},
		}, cookie, csrf, "")
	if deniedSimulation.Code != http.StatusOK || !bytes.Contains(deniedSimulation.Body.Bytes(), []byte(`"allowed":false`)) {
		t.Fatalf("denied route simulation status=%d body=%s", deniedSimulation.Code, deniedSimulation.Body.String())
	}
	activate := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+initial.ID+"/activate", nil, cookie, csrf, initialETag)
	if activate.Code != http.StatusOK {
		t.Fatalf("activate initial status=%d body=%s", activate.Code, activate.Body.String())
	}

	clone := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/environments/"+environment.ID+"/config-revisions",
		map[string]any{"base_revision_id": initial.ID, "description": "second"}, cookie, csrf, "")
	if clone.Code != http.StatusCreated {
		t.Fatalf("clone status=%d body=%s", clone.Code, clone.Body.String())
	}
	var second configuration.Revision
	decodeResponse(t, clone, &second)
	cloneETag := clone.Header().Get("ETag")
	secondDocument := configurationObjectForAPI(t, "second")
	replace := performConfigurationJSON(t, handler, http.MethodPatch,
		"/admin/v1/config-revisions/"+second.ID, secondDocument, cookie, csrf, cloneETag)
	if replace.Code != http.StatusOK || replace.Header().Get("ETag") == cloneETag {
		t.Fatalf("replace status=%d old=%q new=%q body=%s", replace.Code, cloneETag, replace.Header().Get("ETag"), replace.Body.String())
	}
	secondETag := replace.Header().Get("ETag")
	staleReplace := performConfigurationJSON(t, handler, http.MethodPatch,
		"/admin/v1/config-revisions/"+second.ID, secondDocument, cookie, csrf, cloneETag)
	if staleReplace.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale replace status=%d body=%s", staleReplace.Code, staleReplace.Body.String())
	}
	validation = performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+second.ID+"/validate", nil, cookie, csrf, "")
	if validation.Code != http.StatusOK {
		t.Fatalf("validate second status=%d body=%s", validation.Code, validation.Body.String())
	}
	plan := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+second.ID+"/plan", nil, cookie, csrf, "")
	if plan.Code != http.StatusOK || strings.Contains(plan.Body.String(), "second") {
		t.Fatalf("redacted plan status=%d body=%s", plan.Code, plan.Body.String())
	}
	activate = performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+second.ID+"/activate", nil, cookie, csrf, secondETag)
	if activate.Code != http.StatusOK {
		t.Fatalf("activate second status=%d body=%s", activate.Code, activate.Body.String())
	}
	active := performGET(handler, "/admin/v1/environments/"+environment.ID+"/config", cookie)
	if active.Code != http.StatusOK || active.Header().Get("ETag") != secondETag {
		t.Fatalf("active status=%d ETag=%q body=%s", active.Code, active.Header().Get("ETag"), active.Body.String())
	}
	rollback := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/environments/"+environment.ID+"/rollback", map[string]string{"revision_id": initial.ID},
		cookie, csrf, active.Header().Get("ETag"))
	if rollback.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	var restored configuration.Revision
	decodeResponse(t, rollback, &restored)
	if restored.ID != initial.ID || !equalJSONDocuments(t, restored.Document, initialDocument) {
		t.Fatalf("rollback did not restore initial revision: %+v", restored)
	}

	invalidDocument := configurationObjectForAPI(t, "invalid")
	feature := invalidDocument["spec"].(map[string]any)["features"].([]any)[0].(map[string]any)
	feature["access"].(map[string]any)["expression"] = "principal.authenticated &&"
	invalidCreate := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/environments/"+environment.ID+"/config-revisions",
		map[string]any{"document": invalidDocument}, cookie, csrf, "")
	if invalidCreate.Code != http.StatusCreated {
		t.Fatalf("invalid-policy draft status=%d body=%s", invalidCreate.Code, invalidCreate.Body.String())
	}
	var invalid configuration.Revision
	decodeResponse(t, invalidCreate, &invalid)
	invalidValidation := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+invalid.ID+"/validate", nil, cookie, csrf, "")
	var invalidReport configuration.ValidationReport
	decodeResponse(t, invalidValidation, &invalidReport)
	if invalidValidation.Code != http.StatusOK || invalidReport.Valid {
		t.Fatalf("invalid-policy validation status=%d report=%+v", invalidValidation.Code, invalidReport)
	}
	invalidSimulation := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+invalid.ID+"/simulate", map[string]any{
			"feature": "assistant", "platform": "ios", "trust_level": "app_verified",
			"principal": map[string]any{"authenticated": true, "claims": map[string]any{}},
		}, cookie, csrf, "")
	if invalidSimulation.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid-policy simulation status=%d body=%s", invalidSimulation.Code, invalidSimulation.Body.String())
	}
	invalidActivation := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+invalid.ID+"/activate", nil, cookie, csrf, invalidCreate.Header().Get("ETag"))
	if invalidActivation.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid-policy activation status=%d body=%s", invalidActivation.Code, invalidActivation.Body.String())
	}
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	value := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if value == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	return value
}

func performConfigurationJSON(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie, csrf, etag string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set(csrfHeader, csrf)
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func configurationObjectForAPI(t *testing.T, description string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(`{
		"apiVersion":"latchway.dev/v1alpha1",
		"kind":"EnvironmentConfig",
		"metadata":{"organization":"example","application":"habits","environment":"production"},
		"spec":{
			"identityProviders":[{"id":"firebase","type":"firebase","projectId":"habits-production"}],
			"attestationPolicies":[{"id":"native","platforms":{"ios":{"provider":"app_attest","mode":"required","appAttest":{"appIdPrefix":"TEAM1234","bundleId":"com.example.habits","environment":"production","allowedValidationCategories":[1],"allowedBundleVersions":["1.0"]}}}}],
			"upstreams":[{"id":"primary","type":"openai_compatible","baseUrl":"https://api.example.test/v1","authentication":{"type":"none"}}],
			"models":[{"id":"fast","upstream":"primary","upstreamModel":"configured-fast-model"}],
			"limitPlans":[{"id":"free","limits":[{"metric":"logical_requests","window":"1d","maximum":5,"scope":["user","feature"]}]}],
			"features":[{"id":"assistant","protocol":"openai_chat","attestationPolicy":"native","access":{"expression":"principal.authenticated"},"limitPlan":{"expression":"'free'"},"output":{"defaultMaximumTokens":800,"absoluteMaximumTokens":1500},"routes":[{"id":"primary","when":"true","model":"fast","priority":10}]}]
		}
	}`), &document); err != nil {
		t.Fatal(err)
	}
	document["metadata"].(map[string]any)["description"] = description
	return document
}

func equalJSONDocuments(t *testing.T, left json.RawMessage, right map[string]any) bool {
	t.Helper()
	var leftValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatal(err)
	}
	leftJSON, _ := json.Marshal(leftValue)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}
