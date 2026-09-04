package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	problemcontract "github.com/latchway/latchway/internal/problem"
)

const (
	controlTestEnvironment = "env_00000000000000000000000000"
	controlTestRevision    = "rev_00000000000000000000000000"
	controlTestAuditEvent  = "aud_00000000000000000000000000"
	controlTestUser        = "usr_00000000000000000000000000"
)

func TestUserEffectiveConfigurationAndReviewedMutationUseCanonicalAPI(t *testing.T) {
	token := strings.Repeat("effective-user-token-", 2)
	t.Setenv("TEST_LATCHWAY_EFFECTIVE_TOKEN", token)
	impactToken := strings.Repeat("A", 43)
	requests := make([]string, 0, 3)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("X-Latchway-Admin-Source") != "cli" {
			t.Fatal("effective-user request authentication or attribution is invalid")
		}
		requests = append(requests, request.Method+" "+request.URL.Path)
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/effective-configuration"):
			if request.URL.Query().Get("environment_id") != controlTestEnvironment ||
				request.URL.Query().Get("feature") != "assistant" ||
				request.URL.Query().Get("estimated_input_tokens") != "120" {
				t.Fatalf("effective query = %s", request.URL.RawQuery)
			}
			return controlHTTPResponse(request, http.StatusOK, `{
				"subject":{"kind":"user","id":"`+controlTestUser+`","user_id":"`+controlTestUser+`"},
				"evaluation_mode":"current_user_projection","environment_id":"`+controlTestEnvironment+`",
				"environment_kind":"production","revision_id":"`+controlTestRevision+`",
				"feature":"assistant","protocol":"openai_chat","policy_outcome":"allowed",
				"limit_plan":"paid","limit_plan_source":"feature_limit_plan_expression",
				"inputs":[{"fact":"normalized_claims","source":"current_application_user","availability":"available","keys":["tier"],"detail":"values omitted"}],
				"limits":[],"routes":[],"decision_stages":[],"warnings":[]
			}`, nil), nil
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/operation-impact"):
			if request.URL.Query().Get("action") != "block" || request.URL.Query().Get("environment_id") != controlTestEnvironment {
				t.Fatalf("impact query = %s", request.URL.RawQuery)
			}
			return controlHTTPResponse(request, http.StatusOK, `{
				"action":"block","immediate":true,"reversible":false,"applicable":true,
				"current_status":"active","access_effect":"existing_sessions_revoked_and_future_sessions_denied",
				"summary":"Application-wide credentials are revoked.",
				"counts":{"active_session_grants":2,"active_refresh_tokens":1,"active_component_sessions":1,"active_component_refresh_tokens":1,"active_installation_families":1,"active_client_components":1},
				"impact_token":"`+impactToken+`"
			}`, nil), nil
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/block"):
			if request.Header.Get("X-Latchway-Audit-Reason") != "operator_reason_provided" {
				t.Fatalf("block audit reason attribution = %q", request.Header.Get("X-Latchway-Audit-Reason"))
			}
			var body confirmedUserOperationCLI
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode block body: %v", err)
			}
			if body.Reason != "account-compromised" || body.ImpactToken != impactToken || !body.AcknowledgeImmediateEffect {
				t.Fatalf("confirmed block body = %+v", body)
			}
			return controlHTTPResponse(request, http.StatusOK, `{
				"id":"`+controlTestUser+`","environment_id":"`+controlTestEnvironment+`","status":"blocked",
				"identity_providers":["firebase"],"normalized_claims":{},"created_at":"2026-08-29T00:00:00Z"
			}`, nil), nil
		default:
			t.Fatalf("unexpected user request: %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}

	var effectiveOutput bytes.Buffer
	effectiveOptions := &options{output: "json", stdout: &effectiveOutput, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "users", "effective", controlTestUser,
		"--environment", controlTestEnvironment, "--feature", "assistant", "--estimated-input-tokens", "120",
		"--api-token-env", "TEST_LATCHWAY_EFFECTIVE_TOKEN",
	}, effectiveOptions); err != nil {
		t.Fatalf("users effective error = %v", err)
	}
	if !strings.Contains(effectiveOutput.String(), `"limit_plan": "paid"`) || strings.Contains(effectiveOutput.String(), token) {
		t.Fatalf("effective output = %q", effectiveOutput.String())
	}

	var mutationOutput bytes.Buffer
	mutationOptions := &options{output: "json", stdout: &mutationOutput, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "users", "block", controlTestUser,
		"--environment", controlTestEnvironment, "--confirm", controlTestUser, "--impact-token", impactToken,
		"--reason", "account-compromised",
		"--api-token-env", "TEST_LATCHWAY_EFFECTIVE_TOKEN",
	}, mutationOptions); err != nil {
		t.Fatalf("users block error = %v", err)
	}
	if !strings.Contains(mutationOutput.String(), `"status": "blocked"`) ||
		strings.Contains(mutationOutput.String(), token) || strings.Contains(mutationOutput.String(), "account-compromised") {
		t.Fatalf("block output = %q", mutationOutput.String())
	}
	if len(requests) != 3 {
		t.Fatalf("canonical user request sequence = %#v", requests)
	}

	noRequestClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("unconfirmed mutation made a request: %s", request.URL)
		return nil, nil
	})}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "users", "block", controlTestUser,
		"--environment", controlTestEnvironment, "--reason", "account-compromised",
		"--api-token-env", "TEST_LATCHWAY_EFFECTIVE_TOKEN",
	}, &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: noRequestClient})
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("unconfirmed mutation error = %v", err)
	}

	staleClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/operation-impact") {
			t.Fatalf("stale reviewed impact attempted mutation: %s %s", request.Method, request.URL.Path)
		}
		return controlHTTPResponse(request, http.StatusOK, `{
			"action":"block","immediate":true,"reversible":false,"applicable":true,
			"current_status":"active","access_effect":"existing_sessions_revoked_and_future_sessions_denied",
			"summary":"Application-wide credentials are revoked.",
			"counts":{"active_session_grants":3,"active_refresh_tokens":1,"active_component_sessions":1,"active_component_refresh_tokens":1,"active_installation_families":1,"active_client_components":1},
			"impact_token":"`+impactToken+`"
		}`, nil), nil
	})}
	err = executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "users", "block", controlTestUser,
		"--environment", controlTestEnvironment, "--confirm", controlTestUser,
		"--impact-token", strings.Repeat("B", 43), "--reason", "account-compromised",
		"--api-token-env", "TEST_LATCHWAY_EFFECTIVE_TOKEN",
	}, &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: staleClient})
	if err == nil || !strings.Contains(err.Error(), "impact changed") {
		t.Fatalf("stale impact error = %v", err)
	}
}

func TestRequestEffectiveConfigurationUsesRecordedRevisionWithoutCurrentClaims(t *testing.T) {
	token := strings.Repeat("effective-request-token-", 2)
	t.Setenv("TEST_LATCHWAY_EFFECTIVE_REQUEST_TOKEN", token)
	requestID := "req_00000000000000000000000000"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/requests/"+requestID+"/effective-configuration" ||
			request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("X-Latchway-Admin-Source") != "cli" {
			t.Fatalf("request effective call = %s %s", request.Method, request.URL.Path)
		}
		return controlHTTPResponse(request, http.StatusOK, `{
			"subject":{"kind":"request","id":"`+requestID+`","user_id":"`+controlTestUser+`"},
			"evaluation_mode":"recorded_request","environment_id":"`+controlTestEnvironment+`",
			"environment_kind":"production","revision_id":"`+controlTestRevision+`",
			"feature":"assistant","protocol":"openai_chat","request_status":"succeeded","policy_outcome":"allowed",
			"limit_plan":"paid","limit_plan_source":"durable_request_record",
			"inputs":[{"fact":"normalized_claims","source":"historical_request","availability":"unavailable","detail":"Historical values were not persisted and are not inferred."}],
			"limits":[],"routes":[],"decision_stages":[],
			"warnings":["Historical claim values and override identity remain unavailable."]
		}`, nil), nil
	})}
	var output bytes.Buffer
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "requests", "effective", requestID,
		"--api-token-env", "TEST_LATCHWAY_EFFECTIVE_REQUEST_TOKEN",
	}, &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}); err != nil {
		t.Fatalf("requests effective error = %v", err)
	}
	if !strings.Contains(output.String(), `"evaluation_mode": "recorded_request"`) ||
		!strings.Contains(output.String(), `"availability": "unavailable"`) ||
		strings.Contains(output.String(), token) || strings.Contains(output.String(), "current_application_user") {
		t.Fatalf("request effective output = %q", output.String())
	}
}

func TestAuditBrowseAndInspectUseCanonicalRedactionSafeContract(t *testing.T) {
	token := strings.Repeat("audit-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_AUDIT_TOKEN", token)
	organizationID := "org_00000000000000000000000000"
	eventJSON := `{
		"id":"` + controlTestAuditEvent + `","timestamp":"2026-08-29T00:00:00Z",
		"actor":"admin_user:adm_00000000000000000000000000","actor_kind":"admin_user",
		"actor_id":"adm_00000000000000000000000000","action":"configuration.activate",
		"target":"config_revision:` + controlTestRevision + `","resource_type":"config_revision",
		"resource_id":"` + controlTestRevision + `","environment_id":"` + controlTestEnvironment + `",
		"source":"console","reason":"planned_release","result":"succeeded",
		"request_id":"arq_00000000000000000000000000",
		"changes":[{"field":"status","operation":"set","classification":"public","redacted":false}],
		"summary":{"changes":[{"field":"status","operation":"set","classification":"public","redacted":false}]}
	}`
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Latchway-Admin-Source") != "cli" || request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("audit request attribution or authorization header is invalid")
		}
		switch request.URL.Path {
		case "/admin/v1/audit-events":
			query := request.URL.Query()
			if query.Get("organization_id") != organizationID || query.Get("environment_id") != controlTestEnvironment ||
				query.Get("actor_kind") != "admin_user" || query.Get("resource_id") != controlTestRevision ||
				query.Get("source") != "console" || query.Get("reason") != "planned_release" ||
				query.Get("result") != "succeeded" || query.Get("page_size") != "25" {
				t.Fatalf("audit filters = %s", request.URL.RawQuery)
			}
			return controlHTTPResponse(request, http.StatusOK, `{"items":[`+eventJSON+`],"page":{"has_more":false}}`, nil), nil
		case "/admin/v1/audit-events/" + controlTestAuditEvent:
			return controlHTTPResponse(request, http.StatusOK, eventJSON, nil), nil
		default:
			t.Fatalf("unexpected audit request: %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}

	var browse bytes.Buffer
	browseOptions := &options{output: "json", stdout: &browse, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "audit",
		"--organization", organizationID, "--environment", controlTestEnvironment,
		"--actor-kind", "admin_user", "--resource", controlTestRevision,
		"--source", "console", "--reason", "planned_release", "--result", "succeeded",
		"--page-size", "25", "--api-token-env", "TEST_LATCHWAY_AUDIT_TOKEN",
	}, browseOptions); err != nil {
		t.Fatalf("audit browse error = %v", err)
	}
	if strings.Contains(browse.String(), token) || !strings.Contains(browse.String(), `"reason": "planned_release"`) ||
		!strings.Contains(browse.String(), `"redacted": false`) {
		t.Fatalf("audit browse output = %q", browse.String())
	}

	var inspect bytes.Buffer
	inspectOptions := &options{output: "json", stdout: &inspect, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "audit", "inspect",
		controlTestAuditEvent, "--api-token-env", "TEST_LATCHWAY_AUDIT_TOKEN",
	}, inspectOptions); err != nil {
		t.Fatalf("audit inspect error = %v", err)
	}
	if strings.Contains(inspect.String(), token) || !strings.Contains(inspect.String(), `"field": "status"`) {
		t.Fatalf("audit inspect output = %q", inspect.String())
	}
}

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

func TestControlProblemPreservesRedactionSafeConfigurationIssues(t *testing.T) {
	token := strings.Repeat("validation-control-token-", 2)
	client := &controlAPIClient{token: token, tokenSensitive: secretSensitiveVariants(token)}
	body := []byte(`{
		"type":"https://docs.latchway.dev/errors/configuration-invalid",
		"documentation_url":"https://docs.latchway.dev/errors/configuration-invalid",
		"title":"Configuration invalid",
		"status":422,
		"detail":"The configuration has validation errors and cannot be used.",
		"code":"configuration_invalid",
		"request_id":"request_test_123456",
		"retryable":false,
		"errors":[{
			"severity":"error",
			"code":"schema_format",
			"path":"/spec/upstreams/0/baseUrl",
			"message":"A configuration member has an invalid format."
		}]
	}`)
	err := client.problem(http.StatusUnprocessableEntity, http.Header{
		"Content-Type": []string{"application/problem+json"},
	}, body)
	var problem controlProblemError
	if !errors.As(err, &problem) {
		t.Fatalf("problem error type = %T", err)
	}
	if len(problem.ValidationIssues) != 1 ||
		problem.ValidationIssues[0].Code != "schema_format" ||
		problem.ValidationIssues[0].Path != "/spec/upstreams/0/baseUrl" ||
		!strings.Contains(err.Error(), "A configuration member has an invalid format.") ||
		strings.Contains(err.Error(), token) {
		t.Fatalf("configuration problem = %#v, error = %q", problem, err)
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

func TestRouteSimulationHelpDistinguishesUntrustedEstimateFromTrustedProjection(t *testing.T) {
	command := newRoutesSimulateCommand(&options{}, &controlCommandOptions{})
	flag := command.Flags().Lookup("requested-input-tokens")
	if flag == nil || !strings.Contains(flag.Usage, "untrusted") ||
		!strings.Contains(flag.Usage, "policy and scheduling") ||
		strings.Contains(flag.Usage, "non-decisional") {
		t.Fatalf("requested-input-tokens help does not preserve the trust boundary: %#v", flag)
	}
}

func TestVerifyOpenRouterSendsOnlyServerOwnedSelectionAndDefaultCostCeiling(t *testing.T) {
	token := strings.Repeat("self-test-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_SELF_TEST_TOKEN", token)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("self-test request = %s %s", request.Method, request.URL.Path)
		}
		if request.Method == http.MethodGet && request.URL.Path == "/admin/v1/environments/"+controlTestEnvironment+"/config" {
			return controlHTTPResponse(request, http.StatusOK,
				`{"id":"`+controlTestRevision+`","environment_id":"`+controlTestEnvironment+`","state":"active"}`, nil), nil
		}
		if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/self-tests" {
			t.Fatalf("self-test request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]any
		decoder := json.NewDecoder(request.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["kind"] != "openrouter" || body["environment_id"] != controlTestEnvironment ||
			body["config_revision_id"] != controlTestRevision ||
			body["upstream"] != "openrouter" || body["model"] != "canary" ||
			body["max_cost_nano_usd"] != json.Number("10000000") {
			t.Fatalf("self-test body = %#v", body)
		}
		if _, present := body["api_key"]; present {
			t.Fatal("provider credential entered Admin API request")
		}
		return controlHTTPResponse(request, http.StatusAccepted,
			`{"id":"tst_00000000000000000000000000","environment_id":"`+controlTestEnvironment+`","config_revision_id":"`+controlTestRevision+`","kind":"openrouter","state":"passed","created_at":"2026-08-29T00:00:00Z","completed_at":"2026-08-29T00:00:01Z","checks":[{"name":"usage","state":"passed","safe_detail":"Usage passed."}]}`, nil), nil
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
	if strings.Contains(output.String(), token) || !strings.Contains(output.String(), `"state": "passed"`) ||
		!strings.Contains(output.String(), `"environment_id": "`+controlTestEnvironment+`"`) {
		t.Fatalf("unsafe or incomplete self-test output = %q", output.String())
	}
}

func TestVerifyOpenRouterRejectsMismatchedSelfTestContext(t *testing.T) {
	token := strings.Repeat("self-test-context-token-", 2)
	t.Setenv("TEST_LATCHWAY_SELF_TEST_CONTEXT_TOKEN", token)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return controlHTTPResponse(request, http.StatusOK,
				`{"id":"`+controlTestRevision+`","environment_id":"`+controlTestEnvironment+`","state":"active"}`, nil), nil
		}
		return controlHTTPResponse(request, http.StatusAccepted,
			`{"id":"tst_00000000000000000000000000","environment_id":"env_11111111111111111111111111","config_revision_id":"`+controlTestRevision+`","kind":"openrouter","state":"passed","created_at":"2026-08-29T00:00:00Z","checks":[]}`, nil), nil
	})}
	opts := &options{output: "json", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "verify", "openrouter", "--server-owned",
		"--environment", controlTestEnvironment, "--upstream", "openrouter", "--model", "canary",
		"--api-token-env", "TEST_LATCHWAY_SELF_TEST_CONTEXT_TOKEN",
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "exact requested environment") {
		t.Fatalf("mismatched self-test context error = %v", err)
	}
}

func TestStatusConsumesAndValidatesCompleteSystemDocument(t *testing.T) {
	token := strings.Repeat("system-status-token-", 2)
	t.Setenv("TEST_LATCHWAY_SYSTEM_STATUS_TOKEN", token)
	capabilities, err := json.Marshal(requiredServerCapabilitiesCLI)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"server_version":"1.0.0","contract_version":"1.0.0","protocol_versions":[1,2],"role":"all","database_schema_version":"000042","mutation_ready":true,"ready":true,"server_capabilities":` + string(capabilities) + `}`

	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "complete", body: valid},
		{name: "missing capabilities", body: strings.Replace(valid, `,"server_capabilities":`+string(capabilities), "", 1), wantErr: true},
		{name: "reordered capabilities", body: strings.Replace(valid, `"app_attest","play_integrity"`, `"play_integrity","app_attest"`, 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/system" ||
					request.Header.Get("Authorization") != "Bearer "+token {
					t.Fatalf("status request = %s %s", request.Method, request.URL.Path)
				}
				return controlHTTPResponse(request, http.StatusOK, test.body, nil), nil
			})}
			var output bytes.Buffer
			opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
			err := executeWithOptions(context.Background(), []string{
				"--server", "http://127.0.0.1:8080", "--output", "json", "status",
				"--api-token-env", "TEST_LATCHWAY_SYSTEM_STATUS_TOKEN",
			}, opts)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "incompatible system status") {
					t.Fatalf("status error = %v", err)
				}
				return
			}
			if err != nil || !strings.Contains(output.String(), `"server_capabilities"`) || strings.Contains(output.String(), token) {
				t.Fatalf("status result error/output = %v / %q", err, output.String())
			}
		})
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
	for _, name := range []string{"configuration_commands.go", "control_client.go", "family_commands.go", "operational_commands.go", "route_commands.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(source, []byte("internal/database")) || bytes.Contains(source, []byte("pgx")) || bytes.Contains(source, []byte("DATABASE_URL")) {
			t.Fatalf("%s bypasses the canonical Admin API", name)
		}
	}
}

func TestFamilyAndComponentCommandsUseCanonicalAPIWithoutCredentialMaterial(t *testing.T) {
	token := strings.Repeat("family-control-token-", 2)
	t.Setenv("TEST_LATCHWAY_FAMILY_TOKEN", token)
	const (
		familyID     = "fam_00000000000000000000000000"
		componentID  = "cmp_00000000000000000000000000"
		componentKey = "cky_00000000000000000000000000"
		sessionID    = "csf_00000000000000000000000000"
		userID       = "usr_00000000000000000000000000"
	)
	component := `{
		"id":"` + componentID + `","installation_family_id":"` + familyID + `",
		"user_id":"` + userID + `","environment_id":"` + controlTestEnvironment + `",
		"definition_id":"ios-main","kind":"main_app","platform":"ios","is_root":true,
		"status":"active","component_key_id":"` + componentKey + `",
		"dpop_jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","key_storage_claim":"secure_enclave",
		"trust_source":"direct_attested","attestation_provider":"app_attest",
		"granted_features":["assistant"],"session_family_id":"` + sessionID + `","session_status":"active",
		"session_failure_count":0,"refresh_reuse_count":0,"request_count":1,
		"usage":{"logical_requests":1,"input_tokens":10,"output_tokens":20,"total_tokens":30,"cost_nano_usd":40},
		"created_at":"2026-08-30T00:00:00Z","updated_at":"2026-08-30T00:00:00Z","last_seen_at":"2026-08-30T00:00:00Z"
	}`
	family := `{
		"id":"` + familyID + `","user_id":"` + userID + `",
		"environment_id":"` + controlTestEnvironment + `","platform":"ios","status":"active",
		"root_component_id":"` + componentID + `","root_trust_source":"direct_attested",
		"component_count":1,"request_count":1,
		"usage":{"logical_requests":1,"input_tokens":10,"output_tokens":20,"total_tokens":30,"cost_nano_usd":40},
		"created_at":"2026-08-30T00:00:00Z","updated_at":"2026-08-30T00:00:00Z","last_seen_at":"2026-08-30T00:00:00Z"
	}`
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Header.Get("Authorization") != "Bearer "+token ||
			request.Header.Get("Cookie") != "" || request.Header.Get("Origin") != "" {
			t.Fatal("family command did not use only the scoped bearer")
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/installation-families":
			if request.URL.Query().Get("environment_id") != controlTestEnvironment ||
				request.URL.Query().Get("user_id") != userID {
				t.Fatalf("family list query=%s", request.URL.RawQuery)
			}
			return controlHTTPResponse(request, http.StatusOK, `{"items":[`+family+`],"page":{"has_more":false}}`, nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/installation-families/"+familyID:
			return controlHTTPResponse(request, http.StatusOK, strings.TrimSuffix(family, "}")+`,"components":[`+component+`]}`, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/installation-families/"+familyID+"/require-renewal":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["reason"] != "operator-renewal" {
				t.Fatalf("family renewal body=%#v err=%v", body, err)
			}
			return controlHTTPResponse(request, http.StatusOK,
				strings.TrimSuffix(family, "}")+`,"root_trust_expires_at":"2026-08-30T01:00:00Z"}`, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/installation-families/"+familyID+"/revoke":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["reason"] != "operator-family" {
				t.Fatalf("family revoke body=%#v err=%v", body, err)
			}
			return controlHTTPResponse(request, http.StatusOK, strings.Replace(family, `"status":"active"`, `"status":"revoked"`, 1), nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/client-components":
			if request.URL.Query().Get("installation_family_id") != familyID {
				t.Fatalf("component list query=%s", request.URL.RawQuery)
			}
			return controlHTTPResponse(request, http.StatusOK, `{"items":[`+component+`],"page":{"has_more":false}}`, nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/client-components/"+componentID:
			return controlHTTPResponse(request, http.StatusOK, component, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/client-components/"+componentID+"/require-reattestation":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["reason"] != "operator-reattestation" {
				t.Fatalf("component re-attestation body=%#v err=%v", body, err)
			}
			return controlHTTPResponse(request, http.StatusOK,
				strings.TrimSuffix(component, "}")+`,"trust_expires_at":"2026-08-30T01:00:00Z"}`, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/client-components/"+componentID+"/revoke":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["reason"] != "component-compromised" {
				t.Fatalf("component revoke body=%#v err=%v", body, err)
			}
			return controlHTTPResponse(request, http.StatusOK, strings.Replace(component, `"status":"active"`, `"status":"revoked"`, 1), nil), nil
		default:
			t.Fatalf("unexpected family command request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	common := []string{"--server", "http://127.0.0.1:8080", "--output", "json"}
	commands := [][]string{
		{"installation-families", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "list", "--environment", controlTestEnvironment, "--user", userID},
		{"installation-families", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "inspect", familyID},
		{"installation-families", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "require-renewal", familyID, "--reason", "operator-renewal"},
		{"installation-families", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "revoke", familyID, "--reason", "operator-family"},
		{"components", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "list", "--environment", controlTestEnvironment, "--family", familyID},
		{"components", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "inspect", componentID},
		{"components", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "require-reattestation", componentID, "--reason", "operator-reattestation"},
		{"components", "--api-token-env", "TEST_LATCHWAY_FAMILY_TOKEN", "revoke", componentID, "--reason", "component-compromised"},
	}
	for _, command := range commands {
		args := append(append([]string{}, common...), command...)
		if err := executeWithOptions(context.Background(), args, opts); err != nil {
			t.Fatalf("family command %s: %v", strings.Join(command, " "), err)
		}
	}
	if calls != len(commands) || strings.Contains(output.String(), token) ||
		!strings.Contains(output.String(), componentID) ||
		!strings.Contains(output.String(), `"status": "revoked"`) {
		t.Fatalf("family calls=%d output=%q", calls, output.String())
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
			"config_revision_id":"`+controlTestRevision+`","selected_limit_plan":"paid",
			"feature":"assistant","protocol":"openai_chat",
			"started_at":"2026-08-29T00:00:00Z","completed_at":"2026-08-29T00:00:03Z","status":"failed",
			"decision_stages":[],
			"attempts":[{
				"id":"atm_00000000000000000000000000","attempt_number":1,"route":"primary",
				"upstream":"openrouter","model":"openai/gpt","started_at":"2026-08-29T00:00:00Z",
				"first_byte_at":"2026-08-29T00:00:01Z","first_token_at":"2026-08-29T00:00:01.500Z","completed_at":"2026-08-29T00:00:02Z",
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
		`"first_token_at": "2026-08-29T00:00:01.500Z"`,
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
		ConfigRevisionID: controlTestRevision, SelectedLimitPlan: "paid",
		Feature: "assistant", Protocol: "openai_chat", Status: "failed",
		StartedAt: "2026-08-29T00:00:00Z", CompletedAt: "2026-08-29T00:00:03Z",
		Attempts: []upstreamAttemptCLI{{
			ID: "atm_00000000000000000000000000", AttemptNumber: 1,
			Route: "primary", Upstream: "openrouter", Model: "openai/gpt",
			StartedAt: "2026-08-29T00:00:00Z", FirstByteAt: "2026-08-29T00:00:01Z",
			FirstTokenAt: "2026-08-29T00:00:01.500Z",
			CompletedAt:  "2026-08-29T00:00:02Z", Status: "failed", HTTPStatus: 502,
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
		"first token before first byte": func(value *logicalRequestCLI) {
			value.Attempts[0].FirstTokenAt = "2026-08-29T00:00:00.500Z"
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
	documentationURL := problemcontract.DocumentationURL(code)
	return `{"type":"` + documentationURL + `","documentation_url":"` + documentationURL + `","title":"` + title + `","status":` + strconv.Itoa(status) + `,"detail":"The resource does not exist.","code":"` + code + `","request_id":"request_test_123456","retryable":false}`
}
