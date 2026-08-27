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
