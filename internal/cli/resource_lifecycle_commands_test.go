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

func TestResourceLifecycleCommandsUseCanonicalAPI(t *testing.T) {
	token := strings.Repeat("resource-lifecycle-token-", 2)
	t.Setenv("TEST_RESOURCE_LIFECYCLE_TOKEN", token)
	applicationID := "app_00000000000000000000000000"
	environmentID := "env_00000000000000000000000000"
	organizationID := "org_00000000000000000000000000"
	disabledAt := "2026-09-01T12:00:00Z"
	createdAt := "2026-08-01T12:00:00Z"
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(cliAdminSourceHeader) != cliAuditSource {
			t.Fatal("resource lifecycle CLI did not use the scoped Admin API boundary")
		}
		action := "enable"
		status := "active"
		disabledField := ""
		if strings.HasSuffix(request.URL.Path, "/disable") {
			action, status = "disable", "disabled"
			disabledField = `,"disabled_at":"` + disabledAt + `"`
			var document map[string]string
			if err := json.NewDecoder(request.Body).Decode(&document); err != nil || document["reason"] != "incident-42" {
				t.Fatalf("disable request document=%#v error=%v", document, err)
			}
			if request.Header.Get(cliAuditReasonHeader) != cliReasonProvided {
				t.Fatal("disable request omitted reason-presence audit attribution")
			}
		} else if request.Header.Get(cliAuditReasonHeader) != "" || request.ContentLength > 0 {
			t.Fatalf("%s request unexpectedly carried reason metadata or a body", action)
		}
		var body string
		switch request.URL.Path {
		case "/admin/v1/applications/" + applicationID + "/" + action:
			body = `{"id":"` + applicationID + `","organization_id":"` + organizationID + `","slug":"mobile","display_name":"Mobile","status":"` + status + `"` + disabledField + `,"created_at":"` + createdAt + `"}`
		case "/admin/v1/environments/" + environmentID + "/" + action:
			body = `{"id":"` + environmentID + `","application_id":"` + applicationID + `","slug":"production","display_name":"Production","kind":"production","status":"` + status + `"` + disabledField + `,"created_at":"` + createdAt + `"}`
		default:
			t.Fatalf("unexpected resource lifecycle request %s %s", request.Method, request.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})}

	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: &output, adminHTTPClient: client}
	base := []string{"--server", "http://127.0.0.1:8080"}
	commands := [][]string{
		append(append([]string{}, base...), "applications", "--api-token-env", "TEST_RESOURCE_LIFECYCLE_TOKEN", "disable", applicationID, "--reason", "incident-42"),
		append(append([]string{}, base...), "applications", "--api-token-env", "TEST_RESOURCE_LIFECYCLE_TOKEN", "enable", applicationID),
		append(append([]string{}, base...), "environments", "--api-token-env", "TEST_RESOURCE_LIFECYCLE_TOKEN", "disable", environmentID, "--reason", "incident-42"),
		append(append([]string{}, base...), "environments", "--api-token-env", "TEST_RESOURCE_LIFECYCLE_TOKEN", "enable", environmentID),
	}
	for _, arguments := range commands {
		if err := executeWithOptions(context.Background(), arguments, opts); err != nil {
			t.Fatalf("%v: %v", arguments, err)
		}
	}
	if requests != len(commands) {
		t.Fatalf("resource lifecycle request count=%d, want %d", requests, len(commands))
	}
	if strings.Contains(output.String(), token) || strings.Contains(output.String(), "incident-42") {
		t.Fatalf("resource lifecycle output exposed token or reason: %s", output.String())
	}
}

func TestResourceLifecycleCommandsRejectUnsafeReasonBeforeNetwork(t *testing.T) {
	t.Setenv("TEST_RESOURCE_LIFECYCLE_TOKEN", strings.Repeat("resource-lifecycle-token-", 2))
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return nil, nil
	})}
	var output bytes.Buffer
	err := executeWithOptions(context.Background(), []string{
		"applications", "--api-token-env", "TEST_RESOURCE_LIFECYCLE_TOKEN", "disable",
		"app_00000000000000000000000000", "--reason", strings.Repeat("r", 501),
	}, &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client})
	if err == nil || requests != 0 || !strings.Contains(err.Error(), "1 to 500") {
		t.Fatalf("unsafe reason error=%v requests=%d", err, requests)
	}
}
