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

func TestAdministratorCommandsUseCanonicalAPIWithoutPrintingCredentials(t *testing.T) {
	token := strings.Repeat("administrator-cli-token-", 2)
	createPassword := "administrator create password"
	resetPassword := "administrator reset password"
	t.Setenv("TEST_ADMINISTRATOR_TOKEN", token)
	t.Setenv("TEST_ADMINISTRATOR_PASSWORD", createPassword)
	adminUserID := "adm_00000000000000000000000000"
	membershipID := "amb_00000000000000000000000000"
	organizationID := "org_00000000000000000000000000"
	instant := "2026-08-29T12:00:00Z"
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("Origin") != "" {
			t.Fatal("administrator CLI did not use the scoped bearer boundary")
		}
		role := "viewer"
		status := "active"
		statusCode := http.StatusOK
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/admin/v1/administrators":
			return administratorCLIResponse(request, http.StatusOK, `{"items":[],"page":{"has_more":false}}`), nil
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/administrators":
			statusCode = http.StatusCreated
			var document map[string]any
			if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			if document["email"] != "operator@example.test" || document["password"] != createPassword || document["role"] != "viewer" {
				t.Fatalf("create request=%#v", document)
			}
		case request.Method == http.MethodPut && request.URL.Path == "/admin/v1/administrators/"+adminUserID+"/role":
			role = "operator"
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/administrators/"+adminUserID+"/disable":
			status = "disabled"
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/administrators/"+adminUserID+"/enable":
		case request.Method == http.MethodPost && request.URL.Path == "/admin/v1/administrators/"+adminUserID+"/reset-password":
			var document map[string]string
			if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			if document["password"] != resetPassword {
				t.Fatal("reset request did not contain the selected password source")
			}
		default:
			t.Fatalf("unexpected administrator request %s %s", request.Method, request.URL.Path)
		}
		body := `{"id":"` + adminUserID + `","membership_id":"` + membershipID + `","organization_id":"` + organizationID + `","email":"operator@example.test","display_name":"Operator","role":"` + role + `","status":"` + status + `","password_reset_required":false,"created_at":"` + instant + `","updated_at":"` + instant + `"}`
		return administratorCLIResponse(request, statusCode, body), nil
	})}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{output: "table", stdout: &stdout, stderr: &stderr, adminHTTPClient: client}
	base := []string{"--server", "http://127.0.0.1:8080", "admin", "accounts", "--api-token-env", "TEST_ADMINISTRATOR_TOKEN"}
	commands := [][]string{
		append(append([]string{}, base...), "list"),
		append(append([]string{}, base...), "create", "--email", "operator@example.test", "--display-name", "Operator", "--role", "viewer", "--value-env", "TEST_ADMINISTRATOR_PASSWORD"),
		append(append([]string{}, base...), "role", adminUserID, "--role", "operator"),
		append(append([]string{}, base...), "disable", adminUserID),
		append(append([]string{}, base...), "enable", adminUserID),
	}
	for _, args := range commands {
		if err := executeWithOptions(context.Background(), args, opts); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	opts.stdin = strings.NewReader(resetPassword)
	if err := executeWithOptions(context.Background(), append(append([]string{}, base...), "reset-password", adminUserID, "--from-stdin"), opts); err != nil {
		t.Fatalf("reset-password: %v", err)
	}
	if requests != 6 {
		t.Fatalf("administrator request count=%d", requests)
	}
	output := stdout.String() + stderr.String()
	for _, sensitive := range []string{token, createPassword, resetPassword} {
		if strings.Contains(output, sensitive) {
			t.Fatal("administrator CLI output disclosed credential material")
		}
	}
}

func administratorCLIResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func TestAdministratorPasswordRequiresExplicitSafeSource(t *testing.T) {
	var stdout bytes.Buffer
	opts := &options{output: "table", stdout: &stdout, stderr: &stdout}
	err := executeWithOptions(context.Background(), []string{
		"admin", "accounts", "create", "--email", "operator@example.test", "--display-name", "Operator",
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "select exactly one secret value source") {
		t.Fatalf("missing password source error=%v", err)
	}
}
