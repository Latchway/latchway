package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
)

func attemptRoutes() []policy.RouteDecision {
	primary := configuration.Route{
		ID: "primary", FallbackOn: []string{"status_503"},
		RetryPolicy: &configuration.RetryPolicy{
			MaxAttempts: 3, RetryOn: []string{"timeout_before_headers"},
			InitialBackoff: 200 * time.Millisecond, MaximumBackoff: 300 * time.Millisecond,
		},
	}
	backup := configuration.Route{ID: "backup"}
	return []policy.RouteDecision{
		{Route: primary, Model: configuration.Model{ID: "fast"}, Upstream: configuration.Upstream{ID: "openai"}},
		{Route: backup, Model: configuration.Model{ID: "slow"}, Upstream: configuration.Upstream{ID: "anthropic"}},
	}
}

func TestSimulateAttemptsFollowsRetryThenFallback(t *testing.T) {
	t.Parallel()
	routes := attemptRoutes()
	retried := simulateAttempts(routes, []routeSimulationFailure{{Route: "primary", Condition: "timeout_before_headers"}}, protocol.OpenAIChatID, "")
	if retried.Outcome != "failed" || len(retried.Attempts) != 3 || retried.Attempts[0].Next != "retry" ||
		*retried.Attempts[0].RetryDelayMaxMS != 200 || *retried.Attempts[1].RetryDelayMaxMS != 300 ||
		retried.Attempts[2].Next != "stop" || retried.FailureCondition != "timeout_before_headers" {
		t.Fatalf("retry exhaustion plan = %+v", retried)
	}
	fellBack := simulateAttempts(routes, []routeSimulationFailure{{Route: "primary", Condition: "status_503"}}, protocol.OpenAIChatID, "")
	if fellBack.Outcome != "served" || fellBack.ServedByRoute != "backup" || len(fellBack.Attempts) != 2 ||
		fellBack.Attempts[0].Next != "fallback" || fellBack.Attempts[1].Upstream != "anthropic" {
		t.Fatalf("fallback plan = %+v", fellBack)
	}
	recovered := simulateAttempts(routes, []routeSimulationFailure{{Route: "primary", Condition: "timeout_before_headers", Attempts: 1}}, protocol.OpenAIChatID, "")
	if recovered.Outcome != "served" || recovered.ServedByRoute != "primary" || len(recovered.Attempts) != 2 {
		t.Fatalf("recovered plan = %+v", recovered)
	}
	stopped := simulateAttempts(routes, []routeSimulationFailure{{Route: "primary", Condition: nonRetryableSimulationCondition}}, protocol.OpenAIChatID, "")
	if stopped.Outcome != "failed" || len(stopped.Attempts) != 1 || stopped.Attempts[0].Next != "stop" {
		t.Fatalf("non-retryable plan = %+v", stopped)
	}
	unsafe := simulateAttempts(routes, []routeSimulationFailure{{Route: "primary", Condition: "status_503"}}, protocol.OpaqueHTTPID, "")
	if unsafe.Outcome != "failed" || len(unsafe.Attempts) != 1 || len(unsafe.Assumptions) != 3 {
		t.Fatalf("opaque unsafe-method plan = %+v", unsafe)
	}
	safe := simulateAttempts(routes, []routeSimulationFailure{{Route: "primary", Condition: "status_503"}}, protocol.OpaqueHTTPID, http.MethodGet)
	if safe.Outcome != "served" || safe.ServedByRoute != "backup" {
		t.Fatalf("opaque GET plan = %+v", safe)
	}
}

type recordingQuotaSnapshots struct {
	inputs []quota.SnapshotInput
}

func (reader *recordingQuotaSnapshots) Snapshot(_ context.Context, input quota.SnapshotInput) (quota.Snapshot, error) {
	reader.inputs = append(reader.inputs, input)
	used := int64(len(reader.inputs) * 10)
	maximum := input.Rules[0].Maximum
	remaining := maximum - used
	resets := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	return quota.Snapshot{
		Feature: input.FeatureKey, ObservedAt: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		Limits: []quota.LimitSnapshot{{Metric: input.Rules[0].Metric, Maximum: &maximum, Used: &used, Remaining: &remaining, ResetsAt: &resets, Hard: true}},
	}, nil
}

func TestAttachQuotaUsageReadsEachLimitInPlanOrder(t *testing.T) {
	t.Parallel()
	reader := &recordingQuotaSnapshots{}
	api := &API{quotaSnapshots: reader}
	feature := configuration.Feature{
		ID: "assistant", Protocol: protocol.OpenAIChatID,
		Output: &configuration.OutputPolicy{DefaultMaximumTokens: 800, AbsoluteMaximumTokens: 1500},
	}
	plan := configuration.LimitPlan{ID: "free", Limits: []configuration.Limit{
		{Metric: "logical_requests", Algorithm: "calendar", Scope: []string{"user", "feature"}, Window: "1d", Maximum: 50, Hard: true},
		{Metric: "total_tokens", Algorithm: "calendar", Scope: []string{"user"}, Window: "1mo", Maximum: 100000, Hard: true},
	}}
	document := effectiveConfigurationDocument{Limits: effectiveLimits(plan)}
	err := api.attachQuotaUsage(context.Background(), &document, configuration.SimulationSnapshot{
		Scope: configuration.TenantScope{OrganizationID: "org_00000000000000000000000000", ApplicationID: "app_00000000000000000000000000", EnvironmentID: "env_00000000000000000000000000"},
	}, effectiveUserBasis{UserID: "usr_00000000000000000000000000", InstallationID: "ins_00000000000000000000000000"}, "assistant",
		policy.DecisionPlan{Feature: feature, LimitPlan: plan, Scopes: policy.QuotaScopeFacts{Platform: "ios"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.inputs) != 2 || reader.inputs[0].Rules[0].Metric != "logical_requests" || reader.inputs[1].Rules[0].Metric != "total_tokens" ||
		reader.inputs[0].Platform != "ios" || reader.inputs[0].ApplicationUserID != "usr_00000000000000000000000000" {
		t.Fatalf("snapshot inputs = %+v", reader.inputs)
	}
	if *document.Limits[0].Usage.Used != 10 || *document.Limits[1].Usage.Used != 20 || *document.Limits[1].Usage.Remaining != 99980 ||
		document.Limits[0].Usage.ResetsAt == nil {
		t.Fatalf("limit usage = %+v / %+v", document.Limits[0].Usage, document.Limits[1].Usage)
	}

	routed := configuration.LimitPlan{ID: "free", Limits: []configuration.Limit{
		{Metric: "logical_requests", Algorithm: "calendar", Scope: []string{"route"}, Window: "1d", Maximum: 50, Hard: true},
	}}
	document = effectiveConfigurationDocument{Limits: effectiveLimits(routed)}
	if err := api.attachQuotaUsage(context.Background(), &document, configuration.SimulationSnapshot{}, effectiveUserBasis{}, "assistant",
		policy.DecisionPlan{Feature: feature, LimitPlan: routed}); err != nil {
		t.Fatal(err)
	}
	if document.Limits[0].Usage != nil || len(document.Warnings) != 1 || !strings.Contains(document.Warnings[0], "route") {
		t.Fatalf("route-scoped usage = %+v warnings=%v", document.Limits[0].Usage, document.Warnings)
	}
}

func simulationDocumentForPolicyInsights(t *testing.T) map[string]any {
	t.Helper()
	document := configurationObjectForAPI(t, "policy insights")
	feature := document["spec"].(map[string]any)["features"].([]any)[0].(map[string]any)
	feature["routes"] = []any{
		map[string]any{
			"id": "primary", "when": "true", "model": "fast", "priority": 1, "fallbackOn": []any{"status_503"},
			"retryPolicy": map[string]any{"maxAttempts": 2, "retryOn": []any{"timeout_before_headers"}, "initialBackoffMilliseconds": 200, "maximumBackoffMilliseconds": 1000},
		},
		map[string]any{"id": "backup", "when": "true", "model": "fast", "priority": 10},
	}
	return document
}

func TestRouteSimulationFailuresBatchAndScenariosPostgreSQL(t *testing.T) {
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
	bootstrapToken := strings.Repeat("policy-insights-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "example",
		"organization_name": "Example", "email": "owner-policy@example.test",
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
	request := func(method, path string, body any) (int, []byte) {
		t.Helper()
		response := performConfigurationJSON(t, handler, method, path, body, cookie, csrf, "")
		return response.Code, response.Body.Bytes()
	}
	status, body := request(http.MethodPost, "/admin/v1/applications", map[string]string{"organization_id": session.OrganizationID, "slug": "habits", "display_name": "Habits"})
	var application struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &application) != nil {
		t.Fatalf("application status=%d body=%s", status, body)
	}
	status, body = request(http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{"slug": "production", "display_name": "Production", "kind": "production"})
	var environment struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &environment) != nil {
		t.Fatalf("environment status=%d body=%s", status, body)
	}
	status, body = request(http.MethodPost, "/admin/v1/environments/"+environment.ID+"/config-revisions", map[string]any{"document": simulationDocumentForPolicyInsights(t)})
	var revision struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &revision) != nil {
		t.Fatalf("revision status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/validate", nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"valid":true`)) {
		t.Fatalf("validate status=%d body=%s", status, body)
	}
	simulation := func(failures []map[string]any) map[string]any {
		input := map[string]any{
			"feature": "assistant", "platform": "ios", "trust_level": "app_verified",
			"principal": map[string]any{"authenticated": true, "claims": map[string]any{}},
			"request":   map[string]any{"streaming": false, "rewritten_request_bytes": 1024, "requested_output_max": 100},
		}
		if failures != nil {
			input["failures"] = failures
		}
		return input
	}

	status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/simulate", simulation([]map[string]any{{"route": "primary", "condition": "status_503"}}))
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"attempt_plan":{"attempts":[{"number":1,"route":"primary"`)) ||
		!bytes.Contains(body, []byte(`"next":"fallback"`)) || !bytes.Contains(body, []byte(`"served_by_route":"backup"`)) {
		t.Fatalf("fallback simulation status=%d body=%s", status, body)
	}
	status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/simulate", simulation([]map[string]any{{"route": "primary", "condition": "timeout_before_headers"}}))
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"next":"retry","retry_delay_max_ms":200`)) ||
		!bytes.Contains(body, []byte(`"outcome":"failed","failure_condition":"timeout_before_headers"`)) {
		t.Fatalf("retry simulation status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/simulate", simulation(nil)); status != http.StatusOK || bytes.Contains(body, []byte("attempt_plan")) {
		t.Fatalf("plain simulation status=%d body=%s", status, body)
	}
	for name, failures := range map[string][]map[string]any{
		"unknown route": {{"route": "elsewhere", "condition": "status_503"}},
		"bad condition": {{"route": "primary", "condition": "status_418"}},
		"duplicate":     {{"route": "primary", "condition": "status_503"}, {"route": "primary", "condition": "status_429"}},
	} {
		if status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/simulate", simulation(failures)); status != http.StatusBadRequest {
			t.Fatalf("%s simulation status=%d body=%s", name, status, body)
		}
	}

	invalid := simulation(nil)
	invalid["principal"] = map[string]any{"authenticated": true}
	status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/simulate-batch", map[string]any{"requests": []any{
		simulation(nil), invalid, simulation([]map[string]any{{"route": "primary", "condition": "status_503"}}),
	}})
	var batch struct {
		Items []struct {
			Index   int             `json:"index"`
			Result  json.RawMessage `json:"result"`
			Problem *struct {
				Code string `json:"code"`
			} `json:"problem"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &batch) != nil || len(batch.Items) != 3 ||
		batch.Items[0].Result == nil || batch.Items[1].Problem == nil || batch.Items[1].Problem.Code != "invalid_request" ||
		!bytes.Contains(batch.Items[2].Result, []byte(`"served_by_route":"backup"`)) {
		t.Fatalf("batch status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/simulate-batch", map[string]any{"requests": []any{}}); status != http.StatusBadRequest {
		t.Fatalf("empty batch status=%d body=%s", status, body)
	}

	scenarios := "/admin/v1/applications/" + application.ID + "/simulation-scenarios"
	saved := map[string]any{"name": "Free user on iOS", "input": simulation([]map[string]any{{"route": "primary", "condition": "status_503"}})}
	status, body = request(http.MethodPost, scenarios, saved)
	var scenario simulationScenarioDocument
	if status != http.StatusCreated || json.Unmarshal(body, &scenario) != nil || scenario.Version != 1 || scenario.Input.Feature != "assistant" ||
		len(scenario.Input.Failures) != 1 {
		t.Fatalf("create scenario status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodPost, scenarios, saved); status != http.StatusConflict {
		t.Fatalf("duplicate scenario status=%d body=%s", status, body)
	}
	scoped := simulation(nil)
	scoped["environment_id"] = environment.ID
	if status, body = request(http.MethodPost, scenarios, map[string]any{"name": "Scoped", "input": scoped}); status != http.StatusBadRequest {
		t.Fatalf("scenario with an environment status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodPost, scenarios, map[string]any{"name": " padded ", "input": simulation(nil)}); status != http.StatusBadRequest {
		t.Fatalf("scenario with a padded name status=%d body=%s", status, body)
	}
	status, body = request(http.MethodPut, "/admin/v1/simulation-scenarios/"+scenario.ID, map[string]any{"name": "Free user, iOS", "input": simulation(nil), "version": 1})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"version":2`)) || bytes.Contains(body, []byte(`"failures"`)) {
		t.Fatalf("replace scenario status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodPut, "/admin/v1/simulation-scenarios/"+scenario.ID, map[string]any{"name": "Stale", "input": simulation(nil), "version": 1}); status != http.StatusConflict {
		t.Fatalf("stale scenario replace status=%d body=%s", status, body)
	}
	status, body = request(http.MethodGet, scenarios, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"name":"Free user, iOS"`)) {
		t.Fatalf("list scenarios status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodDelete, "/admin/v1/simulation-scenarios/"+scenario.ID+"?version=1", nil); status != http.StatusConflict {
		t.Fatalf("stale scenario delete status=%d body=%s", status, body)
	}
	if status, body = request(http.MethodDelete, "/admin/v1/simulation-scenarios/"+scenario.ID+"?version=2", nil); status != http.StatusNoContent {
		t.Fatalf("delete scenario status=%d body=%s", status, body)
	}
	for action, want := range map[string]int{"admin.simulation_scenario_create": 1, "admin.simulation_scenario_update": 1, "admin.simulation_scenario_delete": 1} {
		if count := auditActionCount(t, ctx, pool, action); count != want {
			t.Fatalf("%s audit events = %d", action, count)
		}
	}
	var leaked int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM audit_events AS event WHERE to_jsonb(event)::text LIKE '%Free user%')
		     + (SELECT count(*) FROM audit_event_changes AS change WHERE to_jsonb(change)::text LIKE '%status_503%')
	`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("scenario name or input reached the audit log in %d rows (err=%v)", leaked, err)
	}
}

// assertUserOverrideList pages through one user's ended overrides.
func assertUserOverrideList(t *testing.T, handler http.Handler, cookie *http.Cookie, environmentID, userID string, ended int) {
	t.Helper()
	base := "/admin/v1/user-overrides?" + url.Values{"environment_id": {environmentID}, "user_id": {userID}}.Encode()
	if active := performGET(handler, base+"&status=active", cookie); active.Code != http.StatusOK || !bytes.Contains(active.Body.Bytes(), []byte(`"items":[]`)) {
		t.Fatalf("active overrides status/body=%d %s", active.Code, active.Body.String())
	}
	seen, cursor := 0, ""
	for page := 0; page < 10; page++ {
		path := base + "&status=ended&limit_plan=free&page_size=5"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		response := performGET(handler, path, cookie)
		var document struct {
			Items []userOverrideDocument `json:"items"`
			Page  struct {
				HasMore    bool   `json:"has_more"`
				NextCursor string `json:"next_cursor"`
			} `json:"page"`
		}
		decodeResponse(t, response, &document)
		if response.Code != http.StatusOK {
			t.Fatalf("ended overrides status/body=%d %s", response.Code, response.Body.String())
		}
		for _, item := range document.Items {
			if item.UserID != userID || item.LimitPlan != "free" || (item.Status != "revoked" && item.Status != "expired") || item.Reason == "" {
				t.Fatalf("ended override = %+v", item)
			}
		}
		seen += len(document.Items)
		if !document.Page.HasMore {
			break
		}
		cursor = document.Page.NextCursor
	}
	if seen != ended {
		t.Fatalf("ended overrides listed = %d, want %d", seen, ended)
	}
	for name, query := range map[string]string{"status": "&status=current", "plan": "&limit_plan=Free", "unknown": "&sort=newest"} {
		if response := performGET(handler, base+query, cookie); response.Code != http.StatusBadRequest {
			t.Fatalf("%s override query status=%d", name, response.Code)
		}
	}
}

// assertUsageDistribution checks the per-user distribution against the
// operational fixture's single request.
func assertUsageDistribution(t *testing.T, handler http.Handler, cookie *http.Cookie, environmentID string, recordedAt time.Time, totalTokens int64) {
	t.Helper()
	query := url.Values{
		"environment_id": {environmentID}, "metric": {"total_tokens"}, "window": {"1d"},
		"start": {recordedAt.Add(-48 * time.Hour).Format(time.RFC3339)}, "end": {recordedAt.Add(48 * time.Hour).Format(time.RFC3339)},
		"maximum": {strconv.FormatInt(totalTokens-1, 10)}, "scope": {"user,feature"},
	}
	response := performGET(handler, "/admin/v1/usage/distribution?"+query.Encode(), cookie)
	var document usageDistributionDocument
	decodeResponse(t, response, &document)
	if response.Code != http.StatusOK || document.Subjects != 1 || document.Users != 1 || document.Peaks.Max != totalTokens ||
		document.Periods < 4 || document.OverSubjects == nil || *document.OverSubjects != 1 || *document.OverUsers != 1 ||
		len(document.Histogram) != 1 || document.Histogram[0].Subjects != 1 || document.Histogram[0].From > totalTokens ||
		strings.Contains(response.Body.String(), "usr_") {
		t.Fatalf("usage distribution status/body=%d %s", response.Code, response.Body.String())
	}
	query.Set("maximum", strconv.FormatInt(totalTokens, 10))
	query.Set("limit_plan", "someone_else")
	response = performGET(handler, "/admin/v1/usage/distribution?"+query.Encode(), cookie)
	decodeResponse(t, response, &document)
	if response.Code != http.StatusOK || document.Subjects != 0 || *document.OverSubjects != 0 {
		t.Fatalf("filtered usage distribution status/body=%d %s", response.Code, response.Body.String())
	}
	for name, change := range map[string][2]string{
		"metric": {"metric", "concurrent_requests"}, "window": {"window", "1day"}, "scope": {"scope", "route"},
		"range": {"start", recordedAt.Add(-100 * 24 * time.Hour).Format(time.RFC3339)}, "periods": {"window", "1m"},
	} {
		bad := url.Values{}
		for key, values := range query {
			bad[key] = values
		}
		bad.Set(change[0], change[1])
		if response := performGET(handler, "/admin/v1/usage/distribution?"+bad.Encode(), cookie); response.Code != http.StatusBadRequest {
			t.Fatalf("%s distribution status/body=%d %s", name, response.Code, response.Body.String())
		}
	}
}
