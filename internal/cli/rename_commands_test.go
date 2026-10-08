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

func TestApplicationsAndEnvironmentsRename(t *testing.T) {
	t.Setenv("TEST_LATCHWAY_RENAME_TOKEN", strings.Repeat("rename-control-token-", 2))
	const applicationID = "app_00000000000000000000000000"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || request.Method != http.MethodPatch {
			t.Fatalf("rename call %s %s body=%v err=%v", request.Method, request.URL.Path, body, err)
		}
		switch request.URL.Path {
		case "/admin/v1/applications/" + applicationID:
			return controlHTTPResponse(request, http.StatusOK, `{"id":"`+applicationID+`","organization_id":"org_00000000000000000000000000","slug":"mobile","display_name":"`+body["display_name"]+`","status":"active","created_at":"2026-10-08T00:00:00Z"}`, nil), nil
		case "/admin/v1/environments/" + controlTestEnvironment:
			return controlHTTPResponse(request, http.StatusOK, `{"id":"`+controlTestEnvironment+`","application_id":"`+applicationID+`","slug":"production","display_name":"Renamed","kind":"production","status":"active","created_at":"2026-10-08T00:00:00Z"}`, nil), nil
		}
		t.Fatalf("unexpected path %s", request.URL.Path)
		return nil, nil
	})}
	run := func(args ...string) (string, error) {
		var output bytes.Buffer
		opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
		err := executeWithOptions(context.Background(), append([]string{"--server", "http://127.0.0.1:8080"}, append(args, "--api-token-env", "TEST_LATCHWAY_RENAME_TOKEN")...), opts)
		return output.String(), err
	}
	if output, err := run("applications", "rename", applicationID, "--name", "  Mobile App  "); err != nil || !strings.Contains(output, "Mobile App") {
		t.Fatalf("application rename output=%q err=%v", output, err)
	}
	if _, err := run("environments", "rename", controlTestEnvironment, "--name", "Not what the server says"); err == nil {
		t.Fatal("environment rename accepted a response with another name")
	}
	if _, err := run("applications", "rename", applicationID, "--name", "two\nlines"); err == nil {
		t.Fatal("application rename accepted a multi-line name")
	}
}
