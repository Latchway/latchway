package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
		if body["platform"] != "react_native_ios" || claims["plan"] != "premium" {
			t.Fatalf("simulation body = %#v", body)
		}
		return controlHTTPResponse(request, http.StatusOK, `{"allowed":true,"feature":"assistant","protocol":"openai_responses","matched_access_expression":"principal.authenticated","limit_plan":"premium","route":"primary","upstream":"openai","model":"assistant_default","physical_model":"gpt-5-mini","pricing_confidence":"configured","fallback_sequence":[],"explanation":["The exact compiled production CEL policy allowed the simulated principal."]}`, nil), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "routes", "simulate", controlTestRevision,
		"--feature", "assistant", "--platform", "react_native_ios", "--trust-level", "app_verified",
		"--claims-file", claimsPath, "--api-token-env", "TEST_LATCHWAY_ROUTE_TOKEN",
	}, opts); err != nil {
		t.Fatalf("routes simulate error = %v", err)
	}
	if strings.Contains(output.String(), token) || !strings.Contains(output.String(), `"physical_model": "gpt-5-mini"`) {
		t.Fatalf("simulation output = %q", output.String())
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
