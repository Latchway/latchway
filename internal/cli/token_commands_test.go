package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	tokenCommandAdministratorID = "adm_00000000000000000000000000"
	tokenCommandOrganizationID  = "org_00000000000000000000000000"
	tokenCommandTokenID         = "tok_00000000000000000000000000"
)

func TestTokenModeAndAPITokenCommandsUseCanonicalAPIWithoutPersistingOrPrintingCredentials(t *testing.T) {
	currentToken := strings.Repeat("current-token-mode-credential-", 2)
	createdToken := strings.Repeat("new-token-mode-credential-", 2)
	t.Setenv("TEST_LATCHWAY_TOKEN_MODE", currentToken)

	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+currentToken || request.Header.Get("Origin") != "" {
			t.Fatal("token-mode CLI did not use the environment credential as a non-browser bearer")
		}
		switch requests {
		case 1:
			if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/auth/session" {
				t.Fatalf("login request = %s %s", request.Method, request.URL.Path)
			}
			return tokenCommandResponse(request, http.StatusOK, `{"administrator":{"id":"`+tokenCommandAdministratorID+`","email":"owner@example.test","enabled":true},"organization_id":"`+tokenCommandOrganizationID+`","memberships":[{"organization_id":"`+tokenCommandOrganizationID+`","role":"owner"}],"capabilities":["inspect_users"],"expires_at":null}`), nil
		case 2:
			if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/api-tokens" {
				t.Fatalf("list request = %s %s", request.Method, request.URL.Path)
			}
			return tokenCommandResponse(request, http.StatusOK, `{"items":[{"id":"`+tokenCommandTokenID+`","name":"existing","scopes":["inspect_users"],"created_at":"2026-08-29T12:00:00Z","revoked":false}]}`), nil
		case 3:
			if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/api-tokens" {
				t.Fatalf("create request = %s %s", request.Method, request.URL.Path)
			}
			var document struct {
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
			}
			if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
				t.Fatalf("decode token create request: %v", err)
			}
			if document.Name != "mobile-ci" || strings.Join(document.Scopes, ",") != "inspect_users,run_self_tests" {
				t.Fatalf("token create document = %#v", document)
			}
			return tokenCommandResponse(request, http.StatusCreated, `{"token":"`+createdToken+`","metadata":{"id":"`+tokenCommandTokenID+`","name":"mobile-ci","scopes":["inspect_users","run_self_tests"],"created_at":"2026-08-29T12:00:00Z","revoked":false}}`), nil
		case 4:
			if request.Method != http.MethodDelete || request.URL.Path != "/admin/v1/api-tokens/"+tokenCommandTokenID {
				t.Fatalf("revoke request = %s %s", request.Method, request.URL.Path)
			}
			return tokenCommandResponse(request, http.StatusNoContent, ""), nil
		case 5:
			if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/auth/logout" {
				t.Fatalf("logout request = %s %s", request.Method, request.URL.Path)
			}
			return tokenCommandResponse(request, http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{output: "table", stdout: &stdout, stderr: &stderr, adminHTTPClient: client}
	common := []string{"--server", "http://127.0.0.1:8080"}
	if err := executeWithOptions(context.Background(), append(append([]string{}, common...), "login", "--api-token-env", "TEST_LATCHWAY_TOKEN_MODE"), opts); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := executeWithOptions(context.Background(), append(append([]string{}, common...), "admin", "api-tokens", "--api-token-env", "TEST_LATCHWAY_TOKEN_MODE", "list"), opts); err != nil {
		t.Fatalf("list: %v", err)
	}
	outputPath := filepath.Join(t.TempDir(), "issued-token")
	createArgs := append(append([]string{}, common...),
		"admin", "api-tokens", "--api-token-env", "TEST_LATCHWAY_TOKEN_MODE", "create",
		"--name", "mobile-ci", "--scope", "run_self_tests,inspect_users", "--token-output-file", outputPath,
	)
	if err := executeWithOptions(context.Background(), createArgs, opts); err != nil {
		t.Fatalf("create: %v", err)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read token output: %v", err)
	}
	if string(contents) != createdToken {
		t.Fatal("exclusive token output did not contain exactly the one-time credential")
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat token output: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("token output mode = %s", info.Mode())
	}
	if err := executeWithOptions(context.Background(), createArgs, opts); err == nil || !strings.Contains(err.Error(), "create exclusive token output file") {
		t.Fatalf("second create with existing output error = %v", err)
	}
	if requests != 3 {
		t.Fatalf("existing output file did not fail before API mutation: requests = %d", requests)
	}
	if err := executeWithOptions(context.Background(), append(append([]string{}, common...), "admin", "api-tokens", "--api-token-env", "TEST_LATCHWAY_TOKEN_MODE", "revoke", tokenCommandTokenID), opts); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := executeWithOptions(context.Background(), append(append([]string{}, common...), "logout", "--api-token-env", "TEST_LATCHWAY_TOKEN_MODE"), opts); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if requests != 5 {
		t.Fatalf("request count = %d", requests)
	}
	output := stdout.String() + stderr.String()
	for _, sensitive := range []string{currentToken, createdToken, outputPath} {
		if strings.Contains(output, sensitive) {
			t.Fatal("token-mode CLI output disclosed credential material or its output path")
		}
	}
}

func TestAPITokenCreateRemovesFileAndRevokesOnInvalidCreationDocument(t *testing.T) {
	currentToken := strings.Repeat("invalid-document-current-token-", 2)
	t.Setenv("TEST_LATCHWAY_TOKEN_ROLLBACK", currentToken)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/api-tokens" {
				t.Fatalf("create request = %s %s", request.Method, request.URL.Path)
			}
			return tokenCommandResponse(request, http.StatusCreated, `{"token":"short","metadata":{"id":"`+tokenCommandTokenID+`","name":"rollback","scopes":["inspect_users"],"created_at":"2026-08-29T12:00:00Z","revoked":false}}`), nil
		case 2:
			if request.Method != http.MethodDelete || request.URL.Path != "/admin/v1/api-tokens/"+tokenCommandTokenID {
				t.Fatalf("compensating revoke request = %s %s", request.Method, request.URL.Path)
			}
			return tokenCommandResponse(request, http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}
	outputPath := filepath.Join(t.TempDir(), "invalid-token")
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "admin", "api-tokens", "--api-token-env", "TEST_LATCHWAY_TOKEN_ROLLBACK",
		"create", "--name", "rollback", "--scope", "inspect_users", "--token-output-file", outputPath,
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "invalid token creation document") {
		t.Fatalf("invalid creation document error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d", requests)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("invalid token output file was retained: %v", err)
	}
	if strings.Contains(output.String(), currentToken) {
		t.Fatal("failure output disclosed the current API token")
	}
}

func tokenCommandResponse(request *http.Request, status int, body string) *http.Response {
	contentType := "application/json"
	if status == http.StatusNoContent {
		contentType = ""
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}
