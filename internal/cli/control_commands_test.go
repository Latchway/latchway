package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	controlTestEnvironment = "env_00000000000000000000000000"
	controlTestRevision    = "rev_00000000000000000000000000"
)

func TestConfigApplyDryRunUsesCanonicalAPIAndDoesNotActivate(t *testing.T) {
	token := strings.Repeat("config-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_CONFIG_TOKEN", token)
	requests := make([]string, 0, 3)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("Origin") != "" {
			t.Fatal("configuration request did not use scoped non-browser bearer authentication")
		}
		requests = append(requests, request.Method+" "+request.URL.Path)
		switch request.URL.Path {
		case "/admin/v1/environments/" + controlTestEnvironment + "/config-revisions":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			if _, present := body["document"]; !present {
				t.Fatal("configuration document missing from create request")
			}
			return controlHTTPResponse(request, http.StatusCreated, revisionJSON("draft"), http.Header{"ETag": []string{`"revision-etag"`}}), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/validate":
			return controlHTTPResponse(request, http.StatusOK, `{"valid":true,"checked_at":"2026-08-29T00:00:00Z","issues":[]}`, nil), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/plan":
			return controlHTTPResponse(request, http.StatusOK, `{"from_revision_id":"rev_00000000000000000000000001","to_revision_id":"`+controlTestRevision+`","changes":[],"warnings":[]}`, nil), nil
		default:
			t.Fatalf("unexpected configuration request: %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	var stdout bytes.Buffer
	opts := &options{output: "json", stdin: strings.NewReader(`{"apiVersion":"latchway.dev/v1alpha1"}`), stdout: &stdout, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "config", "apply",
		"--environment", controlTestEnvironment, "--from-stdin", "--dry-run",
		"--api-token-env", "TEST_LATCHWAY_CONFIG_TOKEN",
	}, opts)
	if err != nil {
		t.Fatalf("config dry-run error = %v", err)
	}
	if len(requests) != 3 || strings.Contains(strings.Join(requests, " "), "/activate") {
		t.Fatalf("dry-run requests = %#v", requests)
	}
	if strings.Contains(stdout.String(), token) || !strings.Contains(stdout.String(), `"dry_run": true`) || !strings.Contains(stdout.String(), `"activated": false`) {
		t.Fatalf("unsafe or incomplete dry-run output = %q", stdout.String())
	}
}

func TestConfigApplyCarriesDraftETagIntoActivation(t *testing.T) {
	token := strings.Repeat("activate-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_ACTIVATE_TOKEN", token)
	activated := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/admin/v1/environments/" + controlTestEnvironment + "/config-revisions":
			return controlHTTPResponse(request, http.StatusCreated, revisionJSON("draft"), http.Header{"ETag": []string{`"revision-etag"`}}), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/validate":
			return controlHTTPResponse(request, http.StatusOK, `{"valid":true,"checked_at":"2026-08-29T00:00:00Z","issues":[]}`, nil), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/plan":
			return controlHTTPResponse(request, http.StatusNotFound, problemJSONForControl("resource_not_found", http.StatusNotFound), nil), nil
		case "/admin/v1/config-revisions/" + controlTestRevision + "/activate":
			activated = true
			if request.Header.Get("If-Match") != `"revision-etag"` {
				t.Fatalf("activation If-Match = %q", request.Header.Get("If-Match"))
			}
			return controlHTTPResponse(request, http.StatusOK, revisionJSON("active"), nil), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})}
	var stdout bytes.Buffer
	opts := &options{output: "json", stdin: strings.NewReader(`{"apiVersion":"latchway.dev/v1alpha1"}`), stdout: &stdout, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "config", "apply",
		"--environment", controlTestEnvironment, "--from-stdin", "--api-token-env", "TEST_LATCHWAY_ACTIVATE_TOKEN",
	}, opts); err != nil {
		t.Fatalf("config apply error = %v", err)
	}
	if !activated || !strings.Contains(stdout.String(), `"activated": true`) || strings.Contains(stdout.String(), token) {
		t.Fatalf("activation output = %q, activated = %t", stdout.String(), activated)
	}
}

func TestRouteSimulationUsesServerResolverAndClaimsFile(t *testing.T) {
	token := strings.Repeat("route-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_ROUTE_TOKEN", token)
	claimsPath := filepath.Join(t.TempDir(), "claims.json")
	if err := os.WriteFile(claimsPath, []byte(`{"plan":"premium"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/config-revisions/"+controlTestRevision+"/simulate" {
			t.Fatalf("simulation request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		principal, _ := body["principal"].(map[string]any)
		claims, _ := principal["claims"].(map[string]any)
		facts, _ := body["request"].(map[string]any)
		if body["platform"] != "react_native_ios" || claims["plan"] != "premium" ||
			facts["rewritten_request_bytes"] != float64(1024) || facts["framing_unit_count"] != float64(1) ||
			facts["image_units"] != float64(2) || facts["tool_calls"] != float64(3) ||
			facts["requested_output_max"] != float64(64) {
			t.Fatalf("simulation body = %#v", body)
		}
		return controlHTTPResponse(request, http.StatusOK, `{"allowed":true,"application_id":"app_0123456789abcdef","environment_id":"env_0123456789abcdef","revision_id":"rev_0123456789abcdef","environment_kind":"production","facts":{"feature":"assistant"},"fact_usage":[{"fact":"requested_input_tokens","role":"explanatory","affects_cel":false,"explanation":"estimate only"}],"feature":"assistant","protocol":"openai_responses","matched_access_expression":"principal.authenticated","limit_plan":"premium","route":"primary","upstream":"openai","model":"assistant_default","physical_model":"gpt-5-mini","pricing_confidence":"configured","reservation":{"applied_output_maximum":64,"total_token_bound":1092,"cost_nano_usd_bound":25,"cost_bound_known":true,"pricing_catalog":"default","input_accounting":{"required":true},"allocations":[{"metric":"total_tokens","algorithm":"calendar","units":1092,"applicable":true,"durable":true}]},"fallback_sequence":[],"explanation":["The exact compiled production CEL policy allowed the simulated principal."]}`, nil), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "routes", "simulate", controlTestRevision,
		"--feature", "assistant", "--platform", "react_native_ios", "--trust-level", "app_verified",
		"--requested-output-max", "64", "--rewritten-request-bytes", "1024", "--framing-unit-count", "1",
		"--image-units", "2", "--tool-calls", "3",
		"--claims-file", claimsPath, "--api-token-env", "TEST_LATCHWAY_ROUTE_TOKEN",
	}, opts); err != nil {
		t.Fatalf("routes simulate error = %v", err)
	}
	if strings.Contains(output.String(), token) || !strings.Contains(output.String(), `"physical_model": "gpt-5-mini"`) ||
		!strings.Contains(output.String(), `"total_token_bound": 1092`) {
		t.Fatalf("simulation output = %q", output.String())
	}
}

func TestVerifyOpenRouterSendsOnlyServerOwnedSelectionAndDefaultCostCeiling(t *testing.T) {
	token := strings.Repeat("self-test-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_SELF_TEST_TOKEN", token)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/self-tests" ||
			request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("self-test request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]any
		decoder := json.NewDecoder(request.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["kind"] != "openrouter" || body["environment_id"] != controlTestEnvironment ||
			body["upstream"] != "openrouter" || body["model"] != "canary" ||
			body["max_cost_nano_usd"] != json.Number("10000000") {
			t.Fatalf("self-test body = %#v", body)
		}
		if _, present := body["api_key"]; present {
			t.Fatal("provider credential entered Admin API request")
		}
		return controlHTTPResponse(request, http.StatusAccepted,
			`{"id":"tst_00000000000000000000000000","kind":"openrouter","state":"passed","created_at":"2026-08-29T00:00:00Z","completed_at":"2026-08-29T00:00:01Z","checks":[{"name":"usage","state":"passed","safe_detail":"Usage passed."}]}`, nil), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "verify", "openrouter",
		"--server-owned", "--environment", controlTestEnvironment, "--upstream", "openrouter", "--model", "canary",
		"--api-token-env", "TEST_LATCHWAY_SELF_TEST_TOKEN",
	}, opts); err != nil {
		t.Fatalf("verify openrouter error = %v", err)
	}
	if strings.Contains(output.String(), token) || !strings.Contains(output.String(), `"state": "passed"`) {
		t.Fatalf("unsafe or incomplete self-test output = %q", output.String())
	}
}

func TestVerifyScheduleManagesExactDurableBindingsWithoutCredentialMaterial(t *testing.T) {
	token := strings.Repeat("scheduled-self-test-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_SCHEDULE_TOKEN", token)
	const scheduleID = "sts_00000000000000000000000000"
	const revisionID = "rev_00000000000000000000000000"
	const credentialID = "tok_00000000000000000000000000"
	active := `{"id":"` + scheduleID + `","environment_id":"` + controlTestEnvironment + `","application_id":"app_00000000000000000000000000","config_revision_id":"` + revisionID + `","authorization_credential_id":"` + credentialID + `","kind":"upstream","upstream":"primary","model":"canary","max_cost_nano_usd":10000000,"daily_cost_limit_nano_usd":240000000,"interval_seconds":3600,"status":"active","next_run_at":"2026-08-29T01:00:00Z","created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	disabled := `{"id":"` + scheduleID + `","environment_id":"` + controlTestEnvironment + `","application_id":"app_00000000000000000000000000","config_revision_id":"` + revisionID + `","authorization_credential_id":"` + credentialID + `","kind":"upstream","upstream":"primary","model":"canary","max_cost_nano_usd":10000000,"daily_cost_limit_nano_usd":240000000,"interval_seconds":3600,"status":"disabled","disabled_at":"2026-08-29T00:10:00Z","disabled_reason_code":"operator_disabled","created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:10:00Z"}`
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("Cookie") != "" || request.Header.Get("Origin") != "" {
			t.Fatal("scheduled self-test command did not use only the scoped bearer")
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/self-test-schedules":
			var body map[string]any
			decoder := json.NewDecoder(request.Body)
			decoder.UseNumber()
			if err := decoder.Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["environment_id"] != controlTestEnvironment || body["kind"] != "upstream" ||
				body["upstream"] != "primary" || body["model"] != "canary" ||
				body["max_cost_nano_usd"] != json.Number("10000000") ||
				body["daily_cost_limit_nano_usd"] != json.Number("240000000") ||
				body["interval_seconds"] != json.Number("3600") {
				t.Fatalf("schedule create body=%#v", body)
			}
			if _, exists := body["authorization_credential_id"]; exists || strings.Contains(fmt.Sprint(body), token) {
				t.Fatalf("schedule body contained credential material or substitution: %#v", body)
			}
			return controlHTTPResponse(request, http.StatusCreated, active, nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/self-test-schedules":
			if request.URL.Query().Get("environment_id") != controlTestEnvironment || request.URL.Query().Get("page_size") != "50" {
				t.Fatalf("schedule list query=%s", request.URL.RawQuery)
			}
			return controlHTTPResponse(request, http.StatusOK, `{"items":[`+active+`],"page":{"has_more":false}}`, nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/self-test-schedules/"+scheduleID:
			return controlHTTPResponse(request, http.StatusOK, active, nil), nil
		case request.Method == http.MethodDelete && request.URL.Path == "/admin/v1/self-test-schedules/"+scheduleID:
			return controlHTTPResponse(request, http.StatusOK, disabled, nil), nil
		default:
			t.Fatalf("unexpected schedule request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	common := []string{"--server", "http://127.0.0.1:8080", "--output", "json", "verify", "--api-token-env", "TEST_LATCHWAY_SCHEDULE_TOKEN", "schedule"}
	commands := [][]string{
		{"create", "--environment", controlTestEnvironment, "--upstream", "primary", "--model", "canary"},
		{"list", "--environment", controlTestEnvironment},
		{"get", scheduleID},
		{"disable", scheduleID},
	}
	for _, command := range commands {
		args := append(append([]string{}, common...), command...)
		if err := executeWithOptions(context.Background(), args, opts); err != nil {
			t.Fatalf("verify schedule %s: %v", command[0], err)
		}
	}
	if calls != 4 || !strings.Contains(output.String(), revisionID) ||
		!strings.Contains(output.String(), credentialID) || !strings.Contains(output.String(), `"status": "disabled"`) ||
		strings.Contains(output.String(), token) {
		t.Fatalf("schedule calls=%d output=%q", calls, output.String())
	}
}

func TestControlPlaneConsumerCommandsDoNotImportDatabaseStores(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"configuration_commands.go", "control_client.go", "operational_commands.go", "route_commands.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(source, []byte("internal/database")) || bytes.Contains(source, []byte("pgx")) || bytes.Contains(source, []byte("DATABASE_URL")) {
			t.Fatalf("%s bypasses the canonical Admin API", name)
		}
	}
}

func TestRequestOutputKeepsReportedCostSourceDistinctFromTokenUsage(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	request := logicalRequestCLI{
		ID: "req_00000000000000000000000000", Feature: "assistant",
		Status: "failed", StartedAt: "2026-08-29T00:00:00Z",
		Attempts: []upstreamAttemptCLI{{
			ID: "atm_00000000000000000000000000", AttemptNumber: 1, Route: "primary",
			Upstream: "openrouter", Model: "openai/gpt", Status: "failed",
			StartedAt: "2026-08-29T00:00:00Z", CompletedAt: "2026-08-29T00:00:02Z",
			HTTPStatus: 504, FailureCode: "timeout",
			UsageProvenance: "unknown", CostProvenance: "upstream_reported",
			CostSource: "openrouter_usage_cost",
		}},
	}
	if err := printRequest(&options{output: "table", stdout: &output}, request); err != nil {
		t.Fatalf("print request: %v", err)
	}
	if !strings.Contains(output.String(), "upstream_reported") ||
		!strings.Contains(output.String(), "openrouter_usage_cost") ||
		!strings.Contains(output.String(), "unknown") ||
		!strings.Contains(output.String(), "primary") ||
		!strings.Contains(output.String(), "504") ||
		!strings.Contains(output.String(), "timeout") {
		t.Fatalf("request cost provenance output = %q", output.String())
	}
}

func TestRequestsInspectJSONIncludesSanitizedAttemptLifecycle(t *testing.T) {
	token := strings.Repeat("request-inspect-token-", 2)
	t.Setenv("TEST_LATCHWAY_REQUEST_TOKEN", token)
	requestID := "req_00000000000000000000000000"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/requests/"+requestID ||
			request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("request inspect call = %s %s", request.Method, request.URL.Path)
		}
		return controlHTTPResponse(request, http.StatusOK, `{
			"id":"req_00000000000000000000000000",
			"environment_id":"env_00000000000000000000000000",
			"user_id":"usr_00000000000000000000000000",
			"installation_id":"ins_00000000000000000000000000",
			"feature":"assistant","protocol":"openai_chat",
			"started_at":"2026-08-29T00:00:00Z","completed_at":"2026-08-29T00:00:03Z","status":"failed",
			"attempts":[{
				"id":"atm_00000000000000000000000000","attempt_number":1,"route":"primary",
				"upstream":"openrouter","model":"openai/gpt","started_at":"2026-08-29T00:00:00Z",
				"first_byte_at":"2026-08-29T00:00:01Z","completed_at":"2026-08-29T00:00:02Z",
				"status":"failed","http_status":502,"failure_code":"protocol_error",
				"usage_provenance":"unknown","cost_provenance":"unknown"
			}]
		}`, nil), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "requests", "inspect", requestID,
		"--api-token-env", "TEST_LATCHWAY_REQUEST_TOKEN",
	}, opts); err != nil {
		t.Fatalf("requests inspect error = %v", err)
	}
	for _, field := range []string{
		`"attempt_number": 1`, `"route": "primary"`, `"first_byte_at": "2026-08-29T00:00:01Z"`,
		`"http_status": 502`, `"failure_code": "protocol_error"`,
	} {
		if !strings.Contains(output.String(), field) {
			t.Fatalf("request JSON omitted %s: %s", field, output.String())
		}
	}
	if strings.Contains(output.String(), token) || strings.Contains(output.String(), "provider body") {
		t.Fatalf("request JSON exposed unsafe material: %s", output.String())
	}
}

func TestRequestDocumentValidationRejectsRawFailureAndCorruptOrdering(t *testing.T) {
	t.Parallel()
	request := logicalRequestCLI{
		ID: "req_00000000000000000000000000", EnvironmentID: controlTestEnvironment,
		UserID: "usr_00000000000000000000000000", InstallationID: "ins_00000000000000000000000000",
		Feature: "assistant", Protocol: "openai_chat", Status: "failed",
		StartedAt: "2026-08-29T00:00:00Z", CompletedAt: "2026-08-29T00:00:03Z",
		Attempts: []upstreamAttemptCLI{{
			ID: "atm_00000000000000000000000000", AttemptNumber: 1,
			Route: "primary", Upstream: "openrouter", Model: "openai/gpt",
			StartedAt: "2026-08-29T00:00:00Z", FirstByteAt: "2026-08-29T00:00:01Z",
			CompletedAt: "2026-08-29T00:00:02Z", Status: "failed", HTTPStatus: 502,
			FailureCode: "protocol_error", UsageProvenance: "unknown", CostProvenance: "unknown",
		}},
	}
	if !validLogicalRequestCLI(request) {
		t.Fatal("valid public request detail was rejected")
	}
	for name, mutate := range map[string]func(*logicalRequestCLI){
		"raw internal failure": func(value *logicalRequestCLI) {
			value.Attempts[0].FailureCode = "upstream_protocol_error"
		},
		"attempt gap": func(value *logicalRequestCLI) { value.Attempts[0].AttemptNumber = 2 },
		"timestamp inversion": func(value *logicalRequestCLI) {
			value.Attempts[0].FirstByteAt = "2026-08-29T00:00:02.500Z"
		},
		"success with failure": func(value *logicalRequestCLI) { value.Attempts[0].Status = "succeeded" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.Attempts = append([]upstreamAttemptCLI(nil), request.Attempts...)
			mutate(&candidate)
			if validLogicalRequestCLI(candidate) {
				t.Fatal("corrupt or unsafe request detail was accepted")
			}
		})
	}
}

func controlHTTPResponse(request *http.Request, status int, body string, extra http.Header) *http.Response {
	header := http.Header{"Content-Type": []string{"application/json"}}
	if status >= 400 {
		header.Set("Content-Type", "application/problem+json")
	}
	for name, values := range extra {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func revisionJSON(state string) string {
	activated := ""
	if state == "active" {
		activated = `,"activated_at":"2026-08-29T00:00:00Z"`
	}
	return `{"id":"` + controlTestRevision + `","environment_id":"` + controlTestEnvironment + `","state":"` + state + `","version":1,"document":{"apiVersion":"latchway.dev/v1alpha1"},"created_at":"2026-08-29T00:00:00Z","created_by":"adm_00000000000000000000000000"` + activated + `}`
}

func problemJSONForControl(code string, status int) string {
	title := "Resource not found"
	return `{"type":"https://latchway.dev/problems/` + code + `","title":"` + title + `","status":` + strconv.Itoa(status) + `,"detail":"The resource does not exist.","code":"` + code + `","request_id":"request_test_123456","retryable":false}`
}
