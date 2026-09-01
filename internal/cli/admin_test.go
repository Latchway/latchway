package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAdminBootstrapUsesCanonicalAPIWithoutPrintingSecrets(t *testing.T) {
	bootstrapToken := strings.Repeat("cli-bootstrap-secret-", 2)
	password := "correct horse battery staple"
	t.Setenv("TEST_LATCHWAY_BOOTSTRAP_TOKEN", bootstrapToken)
	t.Setenv("TEST_LATCHWAY_ADMIN_PASSWORD", password)

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/v1/auth/bootstrap" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Origin") != "" {
			t.Fatal("CLI bootstrap unexpectedly sent a browser Origin header")
		}
		var request bootstrapCLIRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode bootstrap request: %v", err)
		}
		if request.BootstrapToken != bootstrapToken || request.Password != password {
			t.Fatal("bootstrap API did not receive the configured secret inputs")
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"administrator":{"id":"adm_00000000000000000000000000","email":"owner@example.test"},"organization_id":"org_00000000000000000000000000"}`)),
			Request:    r,
		}, nil
	})}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{output: "table", stdout: &stdout, stderr: &stderr, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080",
		"admin", "bootstrap",
		"--organization-slug", "example-org",
		"--organization-name", "Example Organization",
		"--email", "owner@example.test",
		"--display-name", "Example Owner",
		"--bootstrap-token-env", "TEST_LATCHWAY_BOOTSTRAP_TOKEN",
		"--password-env", "TEST_LATCHWAY_ADMIN_PASSWORD",
	}, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, bootstrapToken) || strings.Contains(output, password) {
		t.Fatal("CLI output disclosed a bootstrap credential or password")
	}
	if !strings.Contains(output, "status: created") {
		t.Fatalf("CLI output = %q", output)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestAdminEndpointRequiresHTTPSAwayFromLoopback(t *testing.T) {
	t.Parallel()

	if _, err := adminEndpoint("http://gateway.example.test", "/admin/v1/auth/bootstrap"); err == nil {
		t.Fatal("insecure remote administrative origin was accepted")
	}
	endpoint, err := adminEndpoint("https://gateway.example.test/", "/admin/v1/auth/bootstrap")
	if err != nil {
		t.Fatalf("adminEndpoint() error = %v", err)
	}
	if endpoint != "https://gateway.example.test/admin/v1/auth/bootstrap" {
		t.Fatalf("endpoint = %q", endpoint)
	}
}

func TestAdminUserLimitOverrideUsesScopedBearerAPIWithoutPrintingToken(t *testing.T) {
	token := strings.Repeat("admin-user-override-token-", 2)
	t.Setenv("TEST_LATCHWAY_ADMIN_API_TOKEN", token)
	userID := "usr_00000000000000000000000000"
	environmentID := "env_00000000000000000000000000"
	overrideID := "uov_00000000000000000000000000"

	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Path != "/admin/v1/users/"+userID+"/limit-override" || r.URL.Query().Get("environment_id") != environmentID {
			t.Fatalf("request URL = %s", r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Origin") != "" ||
			r.Header.Get("X-Latchway-Admin-Source") != "cli" {
			t.Fatal("user override request did not use the expected non-browser bearer authorization")
		}
		var response string
		status := http.StatusOK
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("X-Latchway-Audit-Reason") != "operator_reason_provided" {
				t.Fatalf("override audit reason attribution = %q", r.Header.Get("X-Latchway-Audit-Reason"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode override body: %v", err)
			}
			if body["limit_plan"] != "premium" || body["reason"] != "support-approved upgrade" {
				t.Fatalf("override body = %#v", body)
			}
			response = `{"id":"` + userID + `","environment_id":"` + environmentID + `","limit_plan_override":{"id":"` + overrideID + `","limit_plan":"premium","reason":"support-approved upgrade","created_at":"2026-08-28T00:00:00Z"}}`
		case http.MethodDelete:
			if r.Header.Get("X-Latchway-Audit-Reason") != "" {
				t.Fatal("reason-free override deletion carried audit reason attribution")
			}
			status = http.StatusNoContent
		default:
			t.Fatalf("request method = %s", r.Method)
		}
		return &http.Response{
			StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(response)), Request: r,
		}, nil
	})}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{output: "table", stdout: &stdout, stderr: &stderr, adminHTTPClient: client}
	common := []string{
		"--server", "http://127.0.0.1:8080", "admin", "users", "limit-override",
	}
	setArgs := append(append([]string{}, common...), "set", userID,
		"--environment", environmentID, "--limit-plan", "premium",
		"--reason", "support-approved upgrade", "--api-token-env", "TEST_LATCHWAY_ADMIN_API_TOKEN")
	if err := executeWithOptions(context.Background(), setArgs, opts); err != nil {
		t.Fatalf("set override error = %v", err)
	}
	clearArgs := append(append([]string{}, common...), "clear", userID,
		"--environment", environmentID, "--api-token-env", "TEST_LATCHWAY_ADMIN_API_TOKEN")
	if err := executeWithOptions(context.Background(), clearArgs, opts); err != nil {
		t.Fatalf("clear override error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d", requests)
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, token) {
		t.Fatal("CLI output disclosed the Admin API token")
	}
	if !strings.Contains(output, "status: set") || !strings.Contains(output, "status: cleared") {
		t.Fatalf("CLI output = %q", output)
	}
}
