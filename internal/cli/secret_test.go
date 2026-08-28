package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

const (
	secretTestEnvironmentID = "env_00000000000000000000000000"
	secretTestID            = "sec_00000000000000000000000000"
	secretTestRotatedID     = "sec_00000000000000000000000001"
)

func TestSecretSetReadsStdinAndUsesCanonicalAPI(t *testing.T) {
	token := strings.Repeat("secret-admin-token-", 2)
	plaintext := "provider credential with spaces\nand a newline"
	t.Setenv("TEST_LATCHWAY_SECRET_API_TOKEN", token)

	requests := 0
	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/secrets" || request.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("secret request did not use the named Admin API token")
		}
		if request.Header.Get("Origin") != "" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request headers: %#v", request.Header)
		}
		var body struct {
			EnvironmentID string `json:"environment_id"`
			Name          string `json:"name"`
			Value         string `json:"value"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Fatalf("decode secret request: %v", err)
		}
		if body.EnvironmentID != secretTestEnvironmentID || body.Name != "provider_key" || body.Value != plaintext {
			t.Fatalf("secret request metadata mismatch; value length = %d", len(body.Value))
		}
		return secretHTTPResponse(request, http.StatusCreated, "application/json", secretMetadataJSON(secretTestID, secretTestEnvironmentID, "provider_key", 1)), nil
	})}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{
		output: "table", server: "", stdin: strings.NewReader(plaintext), stdout: &stdout, stderr: &stderr,
		adminHTTPClient: client,
	}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json",
		"secret", "set", "provider_key", "--environment", secretTestEnvironmentID,
		"--from-stdin", "--api-token-env", "TEST_LATCHWAY_SECRET_API_TOKEN",
	}, opts)
	if err != nil {
		t.Fatalf("secret set error = %v, stderr = %s", err, stderr.String())
	}
	if requests != 1 {
		t.Fatalf("request count = %d", requests)
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, plaintext) || strings.Contains(output, token) {
		t.Fatal("secret set disclosed a plaintext value or Admin API token")
	}
	var metadata secretMetadataCLI
	if err := json.Unmarshal(stdout.Bytes(), &metadata); err != nil {
		t.Fatalf("decode CLI JSON output: %v", err)
	}
	if metadata.ID != secretTestID || metadata.Name != "provider_key" || metadata.Version != 1 {
		t.Fatalf("metadata output = %#v", metadata)
	}

	root := newRootCommand(&options{output: "table", stdout: io.Discard, stderr: io.Discard})
	resolved, _, err := root.Find([]string{"secret", "create"})
	if err != nil || resolved.Name() != "set" {
		t.Fatalf("secret create alias resolved to %v, error = %v", resolved, err)
	}
}

func TestSecretListAndDeleteUseMetadataOnlyEndpoints(t *testing.T) {
	token := strings.Repeat("list-delete-token-", 2)
	t.Setenv("TEST_LATCHWAY_LIST_TOKEN", token)

	requests := 0
	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("missing list/delete bearer token")
		}
		switch request.Method {
		case http.MethodGet:
			if request.URL.Path != "/admin/v1/secrets" || request.URL.Query().Get("environment_id") != secretTestEnvironmentID || request.URL.Query().Get("page_size") != "2" || request.URL.Query().Get("cursor") != "cursor-one" {
				t.Fatalf("list URL = %s", request.URL.String())
			}
			body := `{"items":[` + secretMetadataJSON(secretTestID, secretTestEnvironmentID, "provider_key", 2) + `],"page":{"has_more":true,"next_cursor":"cursor-two"}}`
			return secretHTTPResponse(request, http.StatusOK, "application/json; charset=utf-8", body), nil
		case http.MethodDelete:
			if request.URL.Path != "/admin/v1/secrets/"+secretTestID || request.URL.RawQuery != "" {
				t.Fatalf("delete URL = %s", request.URL.String())
			}
			if request.ContentLength > 0 {
				t.Fatalf("delete content length = %d", request.ContentLength)
			}
			return secretHTTPResponse(request, http.StatusNoContent, "", ""), nil
		default:
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	})}

	var listOutput bytes.Buffer
	listOptions := &options{output: "table", stdout: &listOutput, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "list",
		"--environment", secretTestEnvironmentID, "--page-size", "2", "--cursor", "cursor-one",
		"--api-token-env", "TEST_LATCHWAY_LIST_TOKEN",
	}, listOptions); err != nil {
		t.Fatalf("secret list error = %v", err)
	}
	if !strings.Contains(listOutput.String(), secretTestID) || !strings.Contains(listOutput.String(), "NEXT CURSOR") || strings.Contains(listOutput.String(), token) {
		t.Fatalf("unexpected list table output = %q", listOutput.String())
	}

	var deleteOutput bytes.Buffer
	deleteOptions := &options{output: "table", stdout: &deleteOutput, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "secret", "delete", secretTestID,
		"--api-token-env", "TEST_LATCHWAY_LIST_TOKEN",
	}, deleteOptions); err != nil {
		t.Fatalf("secret delete error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d", requests)
	}
	var deletion map[string]string
	if err := json.Unmarshal(deleteOutput.Bytes(), &deletion); err != nil {
		t.Fatalf("decode delete output: %v", err)
	}
	if deletion["status"] != "deleted" || deletion["secret_id"] != secretTestID || strings.Contains(deleteOutput.String(), token) {
		t.Fatalf("delete output = %q", deleteOutput.String())
	}
}

func TestSecretRotateRedactsMaliciousProblemResponse(t *testing.T) {
	token := strings.Repeat("rotate-admin-token-", 2)
	plaintext := "rotate-value\nthat-must-never-escape"
	t.Setenv("TEST_LATCHWAY_ROTATE_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_ROTATE_VALUE", plaintext)

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/secrets/"+secretTestID+"/rotate" {
			t.Fatalf("rotate request = %s %s", request.Method, request.URL.String())
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["value"] != plaintext {
			t.Fatal("rotate request did not carry the selected environment value")
		}
		problem := secretProblemJSON(t, http.StatusBadRequest, "request_invalid", "Invalid request",
			"upstream\r\nechoed token "+token+" and value "+plaintext+" and escaped value rotate-value\\nthat-must-never-escape",
			token, false, nil)
		return secretHTTPResponse(request, http.StatusBadRequest, "application/problem+json", problem), nil
	})}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	opts := &options{output: "table", stdout: &stdout, stderr: &stderr, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_ROTATE_VALUE", "--api-token-env", "TEST_LATCHWAY_ROTATE_TOKEN",
	}, opts)
	if err == nil {
		t.Fatal("malicious problem response was accepted")
	}
	diagnostics := err.Error() + stdout.String() + stderr.String()
	if strings.Contains(diagnostics, token) || strings.Contains(diagnostics, plaintext) || strings.Contains(diagnostics, "rotate-value\\nthat-must-never-escape") {
		t.Fatalf("secret diagnostics leaked sensitive input: %q", diagnostics)
	}
	if !strings.Contains(diagnostics, "[redacted]") {
		t.Fatalf("secret diagnostics did not preserve a safe redaction marker: %q", diagnostics)
	}
	if strings.ContainsAny(diagnostics, "\r\n") {
		t.Fatalf("secret diagnostics retained control characters: %q", diagnostics)
	}
}

func TestSecretProblemDiagnosticIncludesCanonicalFacts(t *testing.T) {
	token := strings.Repeat("complete-problem-token-", 2)
	t.Setenv("TEST_LATCHWAY_COMPLETE_PROBLEM_TOKEN", token)
	requestID := "req_00000000000000000000000000"

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := secretProblemJSON(t, http.StatusConflict, "conflict", "Resource conflict",
			"The requested secret name already has an active value.", requestID, false, map[string]any{
				"instance":                    "/admin/v1/secrets",
				"feature":                     "provider_key",
				"supported_protocol_versions": []int{1},
				"errors": []map[string]string{{
					"severity": "error", "code": "secret_conflict", "path": "/name", "message": "Choose a different name.",
				}},
			})
		return secretHTTPResponse(request, http.StatusConflict, "application/problem+json; charset=utf-8", body), nil
	})}

	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "delete", secretTestID,
		"--api-token-env", "TEST_LATCHWAY_COMPLETE_PROBLEM_TOKEN",
	}, opts)
	if err == nil {
		t.Fatal("canonical Problem response was unexpectedly accepted")
	}
	diagnostic := err.Error() + output.String()
	for _, expected := range []string{
		"HTTP 409", "Resource conflict", "(conflict)",
		"The requested secret name already has an active value.",
		"request_id=" + requestID, "retryable=false",
	} {
		if !strings.Contains(diagnostic, expected) {
			t.Fatalf("canonical Problem diagnostic %q does not contain %q", diagnostic, expected)
		}
	}
	if strings.Contains(diagnostic, token) || strings.Contains(diagnostic, "secret_conflict") {
		t.Fatalf("canonical Problem diagnostic included a credential or undisplayed validation issue: %q", diagnostic)
	}
}

func TestSecretProblemDiagnosticIncludesRetryFacts(t *testing.T) {
	token := strings.Repeat("retry-problem-token-", 2)
	t.Setenv("TEST_LATCHWAY_RETRY_PROBLEM_TOKEN", token)
	retryAfter := "2026-08-28T02:03:04Z"

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := secretProblemJSON(t, http.StatusTooManyRequests, "rate_limited", "Rate limited",
			"Administrative requests are temporarily rate limited.", "req_00000000000000000000000001", true,
			map[string]any{"retry_after": retryAfter})
		response := secretHTTPResponse(request, http.StatusTooManyRequests, "application/problem+json", body)
		response.Header.Set("Retry-After", "37")
		return response, nil
	})}

	opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "list", "--environment", secretTestEnvironmentID,
		"--api-token-env", "TEST_LATCHWAY_RETRY_PROBLEM_TOKEN",
	}, opts)
	if err == nil {
		t.Fatal("retryable Problem response was unexpectedly accepted")
	}
	for _, expected := range []string{"HTTP 429", "Rate limited", "(rate_limited)", "retryable=true", "retry_after=" + retryAfter, "retry_after_seconds=37"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("retry Problem diagnostic %q does not contain %q", err.Error(), expected)
		}
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("retry Problem diagnostic disclosed the API token")
	}
}

func TestSecretProblemDiagnosticIncludesValidatedOperationID(t *testing.T) {
	token := strings.Repeat("operation-problem-token-", 2)
	operationID := "arq_00000000000000000000000000"
	t.Setenv("TEST_LATCHWAY_OPERATION_PROBLEM_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_OPERATION_PROBLEM_VALUE", "0")

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := secretProblemJSON(t, http.StatusServiceUnavailable, "operation_indeterminate", "Operation outcome indeterminate",
			"The commit outcome could not be determined.", "req_11111111111111111111111111", true,
			map[string]any{"operation_id": operationID})
		return secretHTTPResponse(request, http.StatusServiceUnavailable, "application/problem+json", body), nil
	})}

	opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_OPERATION_PROBLEM_VALUE", "--api-token-env", "TEST_LATCHWAY_OPERATION_PROBLEM_TOKEN",
	}, opts)
	if err == nil {
		t.Fatal("indeterminate operation Problem was unexpectedly accepted")
	}
	for _, expected := range []string{
		"HTTP 503", "Operation outcome indeterminate", "(operation_indeterminate)",
		"retryable=true", "operation_id=" + operationID,
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("operation Problem diagnostic %q does not contain %q", err.Error(), expected)
		}
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("operation Problem diagnostic disclosed the Admin API token")
	}
}

func TestSecretProblemRejectsMalformedOrReflectedOperationID(t *testing.T) {
	token := strings.Repeat("invalid-operation-token-", 2)
	plaintext := "operation-secret-value"
	t.Setenv("TEST_LATCHWAY_INVALID_OPERATION_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_INVALID_OPERATION_VALUE", plaintext)

	for _, test := range []struct {
		name        string
		operationID any
		omit        bool
	}{
		{name: "missing", omit: true},
		{name: "wrong resource family", operationID: "req_00000000000000000000000000"},
		{name: "noncanonical payload", operationID: "arq_operation-secret-value"},
		{name: "null", operationID: nil},
		{name: "reflected token", operationID: token},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				optional := map[string]any{"operation_id": test.operationID}
				if test.omit {
					optional = nil
				}
				body := secretProblemJSON(t, http.StatusServiceUnavailable, "operation_indeterminate", "Operation outcome indeterminate",
					"The commit outcome could not be determined.", "req_11111111111111111111111111", true,
					optional)
				return secretHTTPResponse(request, http.StatusServiceUnavailable, "application/problem+json", body), nil
			})}
			opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
			err := executeWithOptions(context.Background(), []string{
				"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
				"--value-env", "TEST_LATCHWAY_INVALID_OPERATION_VALUE", "--api-token-env", "TEST_LATCHWAY_INVALID_OPERATION_TOKEN",
			}, opts)
			if err == nil || err.Error() != "secret API failed with HTTP status 503" {
				t.Fatalf("invalid operation ID fallback = %v", err)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), plaintext) {
				t.Fatalf("invalid operation ID diagnostic leaked sensitive input: %q", err.Error())
			}
		})
	}
}

func TestSecretProblemMalformedOrMismatchedFallsBackToHTTPStatus(t *testing.T) {
	token := strings.Repeat("fallback-problem-token-", 2)
	t.Setenv("TEST_LATCHWAY_FALLBACK_PROBLEM_TOKEN", token)
	valid := func(t *testing.T) map[string]any {
		t.Helper()
		var document map[string]any
		if err := json.Unmarshal([]byte(secretProblemJSON(t, http.StatusConflict, "conflict", "Resource conflict",
			"safe-detail-that-must-not-render-after-invalidity", "req_00000000000000000000000002", false, nil)), &document); err != nil {
			t.Fatal(err)
		}
		return document
	}

	for _, test := range []struct {
		name        string
		contentType string
		body        func(*testing.T) string
	}{
		{
			name: "status mismatch", contentType: "application/problem+json",
			body: func(t *testing.T) string {
				document := valid(t)
				document["status"] = http.StatusBadRequest
				return mustSecretTestJSON(t, document)
			},
		},
		{
			name: "missing required field", contentType: "application/problem+json",
			body: func(t *testing.T) string {
				document := valid(t)
				delete(document, "request_id")
				return mustSecretTestJSON(t, document)
			},
		},
		{
			name: "unknown member", contentType: "application/problem+json",
			body: func(t *testing.T) string {
				document := valid(t)
				document["plaintext"] = "safe-detail-that-must-not-render-after-invalidity"
				return mustSecretTestJSON(t, document)
			},
		},
		{
			name: "operation ID on ordinary problem", contentType: "application/problem+json",
			body: func(t *testing.T) string {
				document := valid(t)
				document["operation_id"] = "arq_00000000000000000000000000"
				return mustSecretTestJSON(t, document)
			},
		},
		{
			name: "duplicate member", contentType: "application/problem+json",
			body: func(t *testing.T) string {
				return strings.TrimSuffix(secretProblemJSON(t, http.StatusConflict, "conflict", "Resource conflict",
					"safe-detail-that-must-not-render-after-invalidity", "req_00000000000000000000000002", false, nil), "}") + `,"code":"conflict"}`
			},
		},
		{
			name: "detail exceeds schema bound", contentType: "application/problem+json",
			body: func(t *testing.T) string {
				document := valid(t)
				document["detail"] = strings.Repeat("x", 2049)
				return mustSecretTestJSON(t, document)
			},
		},
		{
			name: "wrong media type", contentType: "application/json",
			body: func(t *testing.T) string { return mustSecretTestJSON(t, valid(t)) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return secretHTTPResponse(request, http.StatusConflict, test.contentType, test.body(t)), nil
			})}
			opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
			err := executeWithOptions(context.Background(), []string{
				"--server", "http://127.0.0.1:8080", "secret", "delete", secretTestID,
				"--api-token-env", "TEST_LATCHWAY_FALLBACK_PROBLEM_TOKEN",
			}, opts)
			if err == nil || err.Error() != "secret API failed with HTTP status 409" {
				t.Fatalf("fallback diagnostic = %v", err)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "safe-detail-that-must-not-render-after-invalidity") {
				t.Fatalf("fallback diagnostic disclosed untrusted Problem fields: %q", err.Error())
			}
		})
	}
}

func TestSecretProblemRedactsSubmittedValueMatchingCanonicalOperationID(t *testing.T) {
	operationID := "arq_00000000000000000000000000"
	token := strings.Repeat("reflected-operation-token-", 2)
	t.Setenv("TEST_LATCHWAY_REFLECTED_OPERATION_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_REFLECTED_OPERATION_VALUE", operationID)
	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := secretProblemJSON(t, http.StatusServiceUnavailable, "operation_indeterminate", "Operation outcome indeterminate",
			"The commit outcome could not be determined.", "req_11111111111111111111111111", true,
			map[string]any{"operation_id": operationID})
		return secretHTTPResponse(request, http.StatusServiceUnavailable, "application/problem+json", body), nil
	})}
	opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_REFLECTED_OPERATION_VALUE", "--api-token-env", "TEST_LATCHWAY_REFLECTED_OPERATION_TOKEN",
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "operation_id=[redacted]") {
		t.Fatalf("reflected operation diagnostic = %v", err)
	}
	if strings.Contains(err.Error(), operationID) || strings.Contains(err.Error(), token) {
		t.Fatalf("reflected operation diagnostic leaked sensitive input: %q", err.Error())
	}
}

func TestSecretRotateAcceptsNewRecordMetadata(t *testing.T) {
	token := strings.Repeat("successful-rotate-token-", 2)
	plaintext := "successful-rotation-value"
	t.Setenv("TEST_LATCHWAY_SUCCESSFUL_ROTATE_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_SUCCESSFUL_ROTATE_VALUE", plaintext)

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/secrets/"+secretTestID+"/rotate" {
			t.Fatalf("rotate request = %s %s", request.Method, request.URL.String())
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["value"] != plaintext {
			t.Fatal("rotate request did not carry the selected value")
		}
		return secretHTTPResponse(request, http.StatusOK, "application/json", secretMetadataJSON(secretTestRotatedID, secretTestEnvironmentID, "provider_key", 2)), nil
	})}

	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "--output", "json", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_SUCCESSFUL_ROTATE_VALUE", "--api-token-env", "TEST_LATCHWAY_SUCCESSFUL_ROTATE_TOKEN",
	}, opts); err != nil {
		t.Fatalf("successful rotate error = %v", err)
	}
	var metadata secretMetadataCLI
	if err := json.Unmarshal(output.Bytes(), &metadata); err != nil {
		t.Fatalf("decode rotate output: %v", err)
	}
	if metadata.ID != secretTestRotatedID || metadata.ID == secretTestID || metadata.Version != 2 {
		t.Fatalf("rotate metadata = %#v", metadata)
	}
	if strings.Contains(output.String(), token) || strings.Contains(output.String(), plaintext) {
		t.Fatal("successful rotate output disclosed a secret or token")
	}
}

func TestSecretSuccessRejectsSubmittedValueMatchingValidatedMetadata(t *testing.T) {
	token := strings.Repeat("reflected-metadata-token-", 2)
	plaintext := "test-master-key"
	t.Setenv("TEST_LATCHWAY_REFLECTED_METADATA_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_REFLECTED_METADATA_VALUE", plaintext)
	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return secretHTTPResponse(request, http.StatusOK, "application/json",
			secretMetadataJSON(secretTestRotatedID, secretTestEnvironmentID, "provider_key", 2)), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_REFLECTED_METADATA_VALUE", "--api-token-env", "TEST_LATCHWAY_REFLECTED_METADATA_TOKEN",
	}, opts)
	if err == nil || err.Error() != "secret API returned unsafe metadata" {
		t.Fatalf("reflected metadata error = %v", err)
	}
	if output.Len() != 0 || strings.Contains(err.Error(), plaintext) || strings.Contains(err.Error(), token) {
		t.Fatalf("reflected metadata leaked sensitive input: output=%q error=%q", output.String(), err.Error())
	}
}

func TestSecretOneByteValuesPreserveExactSuccessMetadata(t *testing.T) {
	for _, test := range []struct {
		name       string
		value      string
		command    string
		status     int
		responseID string
		version    int64
	}{
		{name: "create letter", value: "a", command: "set", status: http.StatusCreated, responseID: secretTestID, version: 1},
		{name: "create dash", value: "-", command: "set", status: http.StatusCreated, responseID: secretTestID, version: 1},
		{name: "rotate zero", value: "0", command: "rotate", status: http.StatusOK, responseID: secretTestRotatedID, version: 2},
		{name: "rotate space", value: " ", command: "rotate", status: http.StatusOK, responseID: secretTestRotatedID, version: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := strings.Repeat("one-byte-value-token-", 2)
			t.Setenv("TEST_LATCHWAY_ONE_BYTE_TOKEN", token)
			t.Setenv("TEST_LATCHWAY_ONE_BYTE_VALUE", test.value)

			client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				var body map[string]string
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["value"] != test.value {
					t.Fatal("secret API did not receive the exact one-byte value")
				}
				if test.command == "set" {
					if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/secrets" || body["name"] != "provider_key" || body["environment_id"] != secretTestEnvironmentID {
						t.Fatalf("create request = %s %s body=%#v", request.Method, request.URL.String(), body)
					}
				} else if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/secrets/"+secretTestID+"/rotate" {
					t.Fatalf("rotate request = %s %s", request.Method, request.URL.String())
				}
				return secretHTTPResponse(request, test.status, "application/json",
					secretMetadataJSON(test.responseID, secretTestEnvironmentID, "provider_key", int(test.version))), nil
			})}

			args := []string{"--server", "http://127.0.0.1:8080", "--output", "json", "secret", test.command}
			if test.command == "set" {
				args = append(args, "provider_key", "--environment", secretTestEnvironmentID)
			} else {
				args = append(args, secretTestID)
			}
			args = append(args, "--value-env", "TEST_LATCHWAY_ONE_BYTE_VALUE", "--api-token-env", "TEST_LATCHWAY_ONE_BYTE_TOKEN")
			var output bytes.Buffer
			opts := &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client}
			if err := executeWithOptions(context.Background(), args, opts); err != nil {
				t.Fatalf("one-byte %s error = %v", test.command, err)
			}

			var metadata secretMetadataCLI
			if err := json.Unmarshal(output.Bytes(), &metadata); err != nil {
				t.Fatalf("decode metadata output: %v", err)
			}
			if metadata.ID != test.responseID || metadata.EnvironmentID != secretTestEnvironmentID || metadata.Name != "provider_key" ||
				metadata.Version != test.version || metadata.Algorithm != "aes-256-gcm" || metadata.MasterKeyID != "test-master-key" ||
				metadata.CreatedAt != "2026-08-28T01:02:03Z" || metadata.RotatedAt != nil {
				t.Fatalf("one-byte value corrupted metadata: %#v", metadata)
			}
			if strings.Contains(output.String(), token) {
				t.Fatal("one-byte success output disclosed the Admin API token")
			}
		})
	}
}

func TestSecretOneByteValuesRedactWholeMaliciousProblemField(t *testing.T) {
	requestID := "req_11111111111111111111111111"
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "letter", value: "a"},
		{name: "zero", value: "0"},
		{name: "dash", value: "-"},
		{name: "space", value: " "},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := strings.Repeat("one-byte-problem-token-", 2)
			t.Setenv("TEST_LATCHWAY_ONE_BYTE_PROBLEM_TOKEN", token)
			t.Setenv("TEST_LATCHWAY_ONE_BYTE_PROBLEM_VALUE", test.value)
			client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				body := secretProblemJSON(t, http.StatusBadRequest, "request_invalid", "Invalid request",
					"malicious server directly echoed one-byte value <"+test.value+">", requestID, false, nil)
				return secretHTTPResponse(request, http.StatusBadRequest, "application/problem+json", body), nil
			})}

			opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
			err := executeWithOptions(context.Background(), []string{
				"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
				"--value-env", "TEST_LATCHWAY_ONE_BYTE_PROBLEM_VALUE", "--api-token-env", "TEST_LATCHWAY_ONE_BYTE_PROBLEM_TOKEN",
			}, opts)
			want := "secret API failed: HTTP 400 Invalid request (request_invalid): [redacted] [request_id=" + requestID + " retryable=false]"
			if err == nil || err.Error() != want {
				t.Fatalf("one-byte Problem diagnostic = %v, want %q", err, want)
			}
			if strings.Contains(err.Error(), "malicious server directly echoed") || strings.Contains(err.Error(), token) {
				t.Fatalf("one-byte Problem diagnostic leaked or corrupted untrusted input: %q", err.Error())
			}
		})
	}
}

func TestSecretOneByteValueSuppressesWholeTransportError(t *testing.T) {
	token := strings.Repeat("one-byte-transport-token-", 2)
	t.Setenv("TEST_LATCHWAY_ONE_BYTE_TRANSPORT_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_ONE_BYTE_TRANSPORT_VALUE", "a")
	client := &http.Client{Transport: secretRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errorsForSecretTest("malicious transport echoed one-byte value a")
	})}
	opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_ONE_BYTE_TRANSPORT_VALUE", "--api-token-env", "TEST_LATCHWAY_ONE_BYTE_TRANSPORT_TOKEN",
	}, opts)
	if err == nil || err.Error() != "call secret API: [redacted]" {
		t.Fatalf("one-byte transport diagnostic = %v", err)
	}
}

func TestSecretValueSourcesAreExclusiveAndBounded(t *testing.T) {
	token := strings.Repeat("source-test-token-", 2)
	t.Setenv("TEST_LATCHWAY_SOURCE_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_SOURCE_VALUE", "environment-secret")

	requests := 0
	client := &http.Client{Transport: secretRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errorsForSecretTest("request must not be sent")
	})}
	baseArgs := []string{
		"--server", "http://127.0.0.1:8080", "secret", "set", "provider_key",
		"--environment", secretTestEnvironmentID, "--api-token-env", "TEST_LATCHWAY_SOURCE_TOKEN",
	}

	for _, test := range []struct {
		name      string
		args      []string
		stdin     string
		sensitive string
	}{
		{name: "no source"},
		{name: "two sources", args: []string{"--from-stdin", "--value-env", "TEST_LATCHWAY_SOURCE_VALUE"}, stdin: "stdin-secret"},
		{name: "oversized stdin", args: []string{"--from-stdin"}, stdin: strings.Repeat("x", maxSecretValueBytes+1)},
		{name: "plaintext value flag does not exist", args: []string{"--value", "argv-secret"}, sensitive: "argv-secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			opts := &options{output: "table", stdin: strings.NewReader(test.stdin), stdout: &output, stderr: &output, adminHTTPClient: client}
			args := append(append([]string(nil), baseArgs...), test.args...)
			err := executeWithOptions(context.Background(), args, opts)
			if err == nil {
				t.Fatal("invalid secret value selection was accepted")
			}
			diagnostics := err.Error() + output.String()
			if (test.stdin != "" && strings.Contains(diagnostics, test.stdin)) ||
				(test.sensitive != "" && strings.Contains(diagnostics, test.sensitive)) ||
				strings.Contains(diagnostics, "environment-secret") {
				t.Fatal("invalid source diagnostics disclosed a secret value")
			}
		})
	}
	if requests != 0 {
		t.Fatalf("invalid value selections sent %d HTTP requests", requests)
	}
}

func TestSecretCommandsRejectInvalidIDsAndNamesBeforeHTTP(t *testing.T) {
	token := strings.Repeat("validation-test-token-", 2)
	plaintext := "validation-test-secret"
	t.Setenv("TEST_LATCHWAY_VALIDATION_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_VALIDATION_VALUE", plaintext)

	requests := 0
	client := &http.Client{Transport: secretRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errorsForSecretTest("request must not be sent")
	})}
	for _, test := range []struct {
		name string
		args []string
	}{
		{
			name: "invalid name",
			args: []string{"secret", "set", "InvalidName", "--environment", secretTestEnvironmentID,
				"--value-env", "TEST_LATCHWAY_VALIDATION_VALUE"},
		},
		{
			name: "invalid environment ID",
			args: []string{"secret", "set", "provider_key", "--environment", "env_not-canonical",
				"--value-env", "TEST_LATCHWAY_VALIDATION_VALUE"},
		},
		{
			name: "invalid rotate ID family",
			args: []string{"secret", "rotate", secretTestEnvironmentID,
				"--value-env", "TEST_LATCHWAY_VALIDATION_VALUE"},
		},
		{
			name: "invalid delete ID",
			args: []string{"secret", "delete", "sec_not-canonical"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--server", "http://127.0.0.1:8080"}, test.args...)
			args = append(args, "--api-token-env", "TEST_LATCHWAY_VALIDATION_TOKEN")
			var output bytes.Buffer
			opts := &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}
			err := executeWithOptions(context.Background(), args, opts)
			if err == nil {
				t.Fatal("invalid identifier or name was accepted")
			}
			if strings.Contains(err.Error()+output.String(), token) || strings.Contains(err.Error()+output.String(), plaintext) {
				t.Fatal("validation diagnostics disclosed sensitive input")
			}
		})
	}
	if requests != 0 {
		t.Fatalf("invalid identifiers or names sent %d requests", requests)
	}
}

func TestSecretValueCanBeReadFromBoundedFileAndDescriptor(t *testing.T) {
	fileValue := "file-backed-secret"
	filePath := t.TempDir() + "/secret-value"
	if err := os.WriteFile(filePath, []byte(fileValue), 0o600); err != nil {
		t.Fatal(err)
	}

	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	descriptorValue := "descriptor-backed-secret"
	if _, err := io.WriteString(pipeWriter, descriptorValue); err != nil {
		t.Fatal(err)
	}
	if err := pipeWriter.Close(); err != nil {
		t.Fatal(err)
	}
	defer pipeReader.Close()

	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "regular file", args: []string{"--value-file", filePath}, want: fileValue},
		{name: "file descriptor", args: []string{"--value-fd", strconv.Itoa(int(pipeReader.Fd()))}, want: descriptorValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := secretValueCLIOptions{valueFD: -1}
			var got []byte
			command := &cobra.Command{
				Use: "source-test",
				RunE: func(command *cobra.Command, _ []string) error {
					var err error
					got, err = readSecretValue(command, values)
					return err
				},
			}
			addSecretValueFlags(command, &values)
			command.SetArgs(test.args)
			if err := command.Execute(); err != nil {
				t.Fatalf("read source: %v", err)
			}
			defer clear(got)
			if string(got) != test.want {
				t.Fatalf("value length = %d", len(got))
			}
		})
	}
}

func TestSecretClientRejectsRedirectsAndInsecureRemoteOrigins(t *testing.T) {
	token := strings.Repeat("redirect-test-token-", 2)
	t.Setenv("TEST_LATCHWAY_REDIRECT_TOKEN", token)

	requests := 0
	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests > 1 {
			t.Fatalf("secret client followed redirect to %s", request.URL.String())
		}
		response := secretHTTPResponse(request, http.StatusFound, "", "")
		response.Header.Set("Location", "http://127.0.0.1:8080/token-capture")
		return response, nil
	})}

	args := []string{
		"--server", "http://127.0.0.1:8080", "secret", "list", "--environment", secretTestEnvironmentID,
		"--api-token-env", "TEST_LATCHWAY_REDIRECT_TOKEN",
	}
	opts := &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: client}
	if err := executeWithOptions(context.Background(), args, opts); err == nil || !strings.Contains(err.Error(), "HTTP status 302") {
		t.Fatalf("redirect error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("redirect request count = %d", requests)
	}

	insecureArgs := append([]string(nil), args...)
	insecureArgs[1] = "http://gateway.example.test"
	if err := executeWithOptions(context.Background(), insecureArgs, opts); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("insecure remote origin error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("insecure origin reached transport; request count = %d", requests)
	}
}

func TestSecretClientBoundsResponseBeforeProblemParsing(t *testing.T) {
	token := strings.Repeat("bounded-response-token-", 2)
	t.Setenv("TEST_LATCHWAY_BOUNDED_RESPONSE_TOKEN", token)
	body := strings.Repeat(token, (maxSecretCLIResponse/len(token))+2)
	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return secretHTTPResponse(request, http.StatusBadRequest, "application/problem+json", body), nil
	})}

	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "list", "--environment", secretTestEnvironmentID,
		"--api-token-env", "TEST_LATCHWAY_BOUNDED_RESPONSE_TOKEN",
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "response exceeds the safety limit") {
		t.Fatalf("oversized response error = %v", err)
	}
	if strings.Contains(err.Error()+output.String(), token) {
		t.Fatal("oversized response diagnostics disclosed the API token")
	}
}

func TestSecretClientRedactsTransportErrors(t *testing.T) {
	token := strings.Repeat("transport-error-token-", 2)
	plaintext := "transport-value\nwith-a-newline"
	t.Setenv("TEST_LATCHWAY_TRANSPORT_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_TRANSPORT_VALUE", plaintext)
	escaped, err := json.Marshal(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: secretRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errorsForSecretTest("malicious transport echoed " + token + " " + plaintext + " " + string(escaped))
	})}
	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}
	err = executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "rotate", secretTestID,
		"--value-env", "TEST_LATCHWAY_TRANSPORT_VALUE", "--api-token-env", "TEST_LATCHWAY_TRANSPORT_TOKEN",
	}, opts)
	if err == nil {
		t.Fatal("transport failure was unexpectedly accepted")
	}
	diagnostics := err.Error() + output.String()
	if strings.Contains(diagnostics, token) || strings.Contains(diagnostics, plaintext) || strings.Contains(diagnostics, string(escaped)) {
		t.Fatalf("transport diagnostics disclosed sensitive input: %q", diagnostics)
	}
	if !strings.Contains(diagnostics, "[redacted]") {
		t.Fatalf("transport diagnostics did not contain redaction markers: %q", diagnostics)
	}
}

func TestSecretSuccessDocumentCannotReturnPlaintext(t *testing.T) {
	token := strings.Repeat("metadata-only-token-", 2)
	plaintext := "metadata-only-plaintext"
	t.Setenv("TEST_LATCHWAY_METADATA_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_METADATA_VALUE", plaintext)

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := strings.TrimSuffix(secretMetadataJSON(secretTestID, secretTestEnvironmentID, "provider_key", 1), "}") + `,"value":` + strconv.Quote(plaintext) + `}`
		return secretHTTPResponse(request, http.StatusCreated, "application/json", body), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: &output, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "set", "provider_key", "--environment", secretTestEnvironmentID,
		"--value-env", "TEST_LATCHWAY_METADATA_VALUE", "--api-token-env", "TEST_LATCHWAY_METADATA_TOKEN",
	}, opts)
	if err == nil {
		t.Fatal("success document containing plaintext was accepted")
	}
	if strings.Contains(output.String()+err.Error(), plaintext) || strings.Contains(output.String()+err.Error(), token) {
		t.Fatal("malformed metadata response disclosed sensitive input")
	}
}

func TestSecretSuccessMetadataReflectingTokenIsRejected(t *testing.T) {
	token := strings.Repeat("metadata-token-", 3)
	t.Setenv("TEST_LATCHWAY_REFLECTED_METADATA_TOKEN", token)
	t.Setenv("TEST_LATCHWAY_REFLECTED_METADATA_VALUE", "provider-secret")

	client := &http.Client{Transport: secretRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		document := map[string]any{
			"id": secretTestID, "environment_id": secretTestEnvironmentID, "name": "provider_key", "version": 1,
			"algorithm": "aes-256-gcm", "master_key_id": token, "created_at": "2026-08-28T01:02:03Z",
		}
		return secretHTTPResponse(request, http.StatusCreated, "application/json", mustSecretTestJSON(t, document)), nil
	})}
	var output bytes.Buffer
	opts := &options{output: "json", stdout: &output, stderr: &output, adminHTTPClient: client}
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "secret", "set", "provider_key", "--environment", secretTestEnvironmentID,
		"--value-env", "TEST_LATCHWAY_REFLECTED_METADATA_VALUE", "--api-token-env", "TEST_LATCHWAY_REFLECTED_METADATA_TOKEN",
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "unsafe metadata") {
		t.Fatalf("reflected token metadata error = %v", err)
	}
	if strings.Contains(output.String()+err.Error(), token) {
		t.Fatal("success metadata disclosed a reflected Admin API token")
	}
}

func TestSafeSecretProblemDetailPreservesUTF8AtBoundary(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("a", maxSecretProblemDetail-1)
	detail := safeSecretProblemDetail(prefix + "€tail")
	if !utf8.ValidString(detail) {
		t.Fatalf("truncated detail is invalid UTF-8: %q", detail[len(detail)-8:])
	}
	if len(detail) > maxSecretProblemDetail || detail != prefix {
		t.Fatalf("truncated detail length = %d, suffix = %q", len(detail), detail[len(detail)-8:])
	}
}

type secretRoundTripFunc func(*http.Request) (*http.Response, error)

func (function secretRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type secretTestError string

func (err secretTestError) Error() string { return string(err) }

func errorsForSecretTest(value string) error { return secretTestError(value) }

func secretHTTPResponse(request *http.Request, status int, contentType, body string) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func secretMetadataJSON(secretID, environmentID, name string, version int) string {
	return fmt.Sprintf(`{"id":%q,"environment_id":%q,"name":%q,"version":%d,"algorithm":"aes-256-gcm","master_key_id":"test-master-key","created_at":"2026-08-28T01:02:03Z"}`,
		secretID, environmentID, name, version)
}

func secretProblemJSON(t *testing.T, status int, code, title, detail, requestID string, retryable bool, optional map[string]any) string {
	t.Helper()
	document := map[string]any{
		"type":       "https://latchway.dev/problems/" + code,
		"title":      title,
		"status":     status,
		"detail":     detail,
		"code":       code,
		"request_id": requestID,
		"retryable":  retryable,
	}
	for key, value := range optional {
		document[key] = value
	}
	return mustSecretTestJSON(t, document)
}

func mustSecretTestJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
