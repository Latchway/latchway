package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	adminSessionCommandID1      = "asn_00000000000000000000000000"
	adminSessionCommandID2      = "asn_00000000000000000000000001"
	adminSessionAdministratorID = "adm_00000000000000000000000000"
)

func TestAdminSessionCommandsUseCanonicalAPIWithoutCredentialOrReasonDisclosure(t *testing.T) {
	token := strings.Repeat("admin-session-cli-token-", 2)
	t.Setenv("TEST_ADMIN_SESSION_TOKEN", token)

	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get(cliAdminSourceHeader) != cliAuditSource {
			t.Fatal("administrator-session CLI did not use the scoped bearer boundary")
		}
		if request.Header.Get("Origin") != "" || request.Header.Get(cliAuditReasonHeader) != "" {
			t.Fatal("administrator-session CLI sent browser or caller-controlled reason headers")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if len(body) != 0 || request.Header.Get("Content-Type") != "" {
			t.Fatalf("unexpected administrator-session request body=%q content-type=%q", body, request.Header.Get("Content-Type"))
		}
		switch requests {
		case 1:
			if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/admin-sessions" {
				t.Fatalf("list request = %s %s", request.Method, request.URL.Path)
			}
			if request.URL.Query().Get("cursor") != "cursor-one" || request.URL.Query().Get("page_size") != "2" || len(request.URL.Query()) != 2 {
				t.Fatalf("list query = %q", request.URL.RawQuery)
			}
			return adminSessionCommandResponse(request, http.StatusOK, `{
  "items": [
    {
      "id": "`+adminSessionCommandID1+`",
      "administrator": {"id": "`+adminSessionAdministratorID+`", "email": "owner@example.test"},
      "created_at": "2026-08-29T12:00:00Z",
      "last_seen_at": "2026-08-29T12:10:00Z",
      "expires_at": "2026-08-29T13:00:00Z",
      "status": "active",
      "current": false
    },
    {
      "id": "`+adminSessionCommandID2+`",
      "administrator": {"id": "`+adminSessionAdministratorID+`", "email": "owner@example.test"},
      "created_at": "2026-08-29T12:00:01Z",
      "last_seen_at": "2026-08-29T12:15:00Z",
      "expires_at": "2026-08-29T13:00:01Z",
      "status": "revoked",
      "current": false
    }
  ],
  "page": {"has_more": true, "next_cursor": "cursor-two"}
}`), nil
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/admin/v1/admin-sessions/"+adminSessionCommandID1+"/revoke" {
				t.Fatalf("revoke request = %s %s", request.Method, request.URL.Path)
			}
			if request.URL.RawQuery != "" {
				t.Fatalf("revoke query = %q", request.URL.RawQuery)
			}
			return adminSessionCommandResponse(request, http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}

	var output bytes.Buffer
	opts := &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}
	base := []string{
		"--server", "http://127.0.0.1:8080", "admin", "sessions", "--api-token-env", "TEST_ADMIN_SESSION_TOKEN",
	}
	if err := executeWithOptions(context.Background(), append(append([]string{}, base...), "list", "--page-size", "2", "--cursor", "cursor-one"), opts); err != nil {
		t.Fatalf("list administrator sessions: %v", err)
	}
	if err := executeWithOptions(context.Background(), append(append([]string{}, base...), "revoke", adminSessionCommandID1), opts); err != nil {
		t.Fatalf("revoke administrator session: %v", err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d", requests)
	}
	text := output.String()
	for _, expected := range []string{
		"SESSION", "ADMINISTRATOR", "EMAIL", "LAST SEEN", "CURRENT", adminSessionCommandID1,
		adminSessionCommandID2, "owner@example.test", "next cursor: cursor-two", "revoked",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("output missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, token) || strings.Contains(text, managedSessionRevokeReasonForTest) {
		t.Fatal("administrator-session output disclosed credential or server-owned revocation reason material")
	}
}

const managedSessionRevokeReasonForTest = "administrator_session_management"

func TestAdminSessionJSONAndTableOutputAreDeterministic(t *testing.T) {
	page := adminSessionPageCLI{
		Items: []adminSessionMetadataCLI{{
			ID: adminSessionCommandID1,
			Administrator: adminSessionAdministratorCLI{
				ID: adminSessionAdministratorID, Email: "owner@example.test",
			},
			CreatedAt: "2026-08-29T12:00:00+00:00", LastSeenAt: "2026-08-29T12:10:00Z",
			ExpiresAt: "2026-08-29T13:00:00Z", Status: "active", Current: false,
		}},
		Page: pageInfoCLI{HasMore: true, NextCursor: "cursor-two"},
	}

	for _, outputFormat := range []string{"json", "table"} {
		t.Run(outputFormat, func(t *testing.T) {
			var first bytes.Buffer
			var second bytes.Buffer
			if err := printAdminSessions(&options{output: outputFormat, stdout: &first}, page); err != nil {
				t.Fatalf("first output: %v", err)
			}
			if err := printAdminSessions(&options{output: outputFormat, stdout: &second}, page); err != nil {
				t.Fatalf("second output: %v", err)
			}
			if first.String() != second.String() {
				t.Fatalf("non-deterministic output:\nfirst=%q\nsecond=%q", first.String(), second.String())
			}
			if outputFormat == "json" {
				expected := "{\n" +
					"  \"items\": [\n" +
					"    {\n" +
					"      \"id\": \"" + adminSessionCommandID1 + "\",\n" +
					"      \"administrator\": {\n" +
					"        \"id\": \"" + adminSessionAdministratorID + "\",\n" +
					"        \"email\": \"owner@example.test\"\n" +
					"      },\n" +
					"      \"created_at\": \"2026-08-29T12:00:00+00:00\",\n" +
					"      \"last_seen_at\": \"2026-08-29T12:10:00Z\",\n" +
					"      \"expires_at\": \"2026-08-29T13:00:00Z\",\n" +
					"      \"status\": \"active\",\n" +
					"      \"current\": false\n" +
					"    }\n" +
					"  ],\n" +
					"  \"page\": {\n" +
					"    \"has_more\": true,\n" +
					"    \"next_cursor\": \"cursor-two\"\n" +
					"  }\n" +
					"}\n"
				if first.String() != expected {
					t.Fatalf("JSON output mismatch:\n%s", first.String())
				}
			} else {
				for _, expected := range []string{
					"SESSION", "ADMINISTRATOR", "2026-08-29 12:00:00Z", "2026-08-29 12:10:00Z",
					"2026-08-29 13:00:00Z", "active", "no", "next cursor: cursor-two",
				} {
					if !strings.Contains(first.String(), expected) {
						t.Fatalf("table output missing %q:\n%s", expected, first.String())
					}
				}
			}
		})
	}

	result := adminSessionRevocationCLI{SessionID: adminSessionCommandID1, Status: "revoked"}
	var output bytes.Buffer
	if err := printAdminSessionRevocation(&options{output: "json", stdout: &output}, result); err != nil {
		t.Fatalf("revocation JSON: %v", err)
	}
	expected := "{\n  \"session_id\": \"" + adminSessionCommandID1 + "\",\n  \"status\": \"revoked\"\n}\n"
	if output.String() != expected {
		t.Fatalf("revocation JSON mismatch:\n%s", output.String())
	}
}

func TestAdminSessionListRejectsInvalidAndCrossShapeDocuments(t *testing.T) {
	token := strings.Repeat("invalid-admin-session-response-", 2)
	t.Setenv("TEST_INVALID_ADMIN_SESSION_TOKEN", token)
	validItem := adminSessionTestItem(
		adminSessionCommandID1, adminSessionAdministratorID, "owner@example.test",
		"2026-08-29T12:00:00Z", "2026-08-29T12:10:00Z", "2026-08-29T13:00:00Z", "active", "false",
	)
	tests := map[string]string{
		"cross resource shape":      `{"items":[{"id":"tok_00000000000000000000000000","name":"ci","scopes":[],"created_at":"2026-08-29T12:00:00Z","revoked":false}],"page":{"has_more":false}}`,
		"unknown credential field":  strings.Replace(validItem, `"current":false`, `"current":false,"token_hint":"unsafe-shape"`, 1),
		"missing items":             `{"page":{"has_more":false}}`,
		"missing page":              `{"items":[]}`,
		"missing has more":          `{"items":[],"page":{}}`,
		"missing current":           adminSessionPage(strings.Replace(validItem, `,"current":false`, "", 1), `{"has_more":false}`),
		"current true for bearer":   adminSessionPage(strings.Replace(validItem, `"current":false`, `"current":true`, 1), `{"has_more":false}`),
		"invalid session ID":        adminSessionPage(strings.Replace(validItem, adminSessionCommandID1, "asn_not-canonical", 1), `{"has_more":false}`),
		"invalid administrator ID":  adminSessionPage(strings.Replace(validItem, adminSessionAdministratorID, "adm_not-canonical", 1), `{"has_more":false}`),
		"unsafe email":              adminSessionPage(strings.Replace(validItem, "owner@example.test", `owner@example.test\\tINJECTED`, 1), `{"has_more":false}`),
		"invalid created timestamp": adminSessionPage(strings.Replace(validItem, "2026-08-29T12:00:00Z", "not-a-timestamp", 1), `{"has_more":false}`),
		"last seen before created":  adminSessionPage(strings.Replace(validItem, "2026-08-29T12:10:00Z", "2026-08-29T11:59:59Z", 1), `{"has_more":false}`),
		"expires before last seen":  adminSessionPage(strings.Replace(validItem, "2026-08-29T13:00:00Z", "2026-08-29T12:05:00Z", 1), `{"has_more":false}`),
		"invalid status":            adminSessionPage(strings.Replace(validItem, `"status":"active"`, `"status":"unknown"`, 1), `{"has_more":false}`),
		"cursor without more":       adminSessionPage(validItem, `{"has_more":false,"next_cursor":"cursor"}`),
		"missing next cursor":       adminSessionPage(validItem, `{"has_more":true}`),
		"unsafe next cursor":        adminSessionPage(validItem, `{"has_more":true,"next_cursor":"unsafe\nvalue"}`),
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if !strings.HasPrefix(body, `{"items"`) {
				body = adminSessionPage(body, `{"has_more":false}`)
			}
			requests := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				return adminSessionCommandResponse(request, http.StatusOK, body), nil
			})}
			var output bytes.Buffer
			err := executeWithOptions(context.Background(), []string{
				"--server", "http://127.0.0.1:8080", "admin", "sessions", "--api-token-env", "TEST_INVALID_ADMIN_SESSION_TOKEN", "list",
			}, &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client})
			if err == nil {
				t.Fatalf("invalid response accepted: %s", body)
			}
			if requests != 1 {
				t.Fatalf("request count = %d", requests)
			}
			if output.Len() != 0 || strings.Contains(err.Error(), token) {
				t.Fatalf("unsafe invalid-response output=%q error=%q", output.String(), err)
			}
		})
	}

	outOfOrder := adminSessionPage(
		adminSessionTestItem(adminSessionCommandID2, adminSessionAdministratorID, "owner@example.test", "2026-08-29T12:00:01Z", "2026-08-29T12:10:01Z", "2026-08-29T13:00:01Z", "active", "false")+","+
			adminSessionTestItem(adminSessionCommandID1, adminSessionAdministratorID, "owner@example.test", "2026-08-29T12:00:00Z", "2026-08-29T12:10:00Z", "2026-08-29T13:00:00Z", "active", "false"),
		`{"has_more":false}`,
	)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return adminSessionCommandResponse(request, http.StatusOK, outOfOrder), nil
	})}
	var output bytes.Buffer
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "admin", "sessions", "--api-token-env", "TEST_INVALID_ADMIN_SESSION_TOKEN", "list",
	}, &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client})
	if err == nil || !strings.Contains(err.Error(), "canonical order") {
		t.Fatalf("out-of-order response error = %v", err)
	}
}

func TestAdminSessionCommandsRejectUnsafeInputBeforeRequest(t *testing.T) {
	t.Setenv(defaultAdminTokenEnvironment, "")
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		t.Fatal("unsafe administrator-session input reached the Admin API")
		return nil, nil
	})}
	base := []string{"--server", "http://127.0.0.1:8080", "admin", "sessions"}
	tests := [][]string{
		append(append([]string{}, base...), "list", "--page-size", "0"),
		append(append([]string{}, base...), "list", "--page-size", "201"),
		append(append([]string{}, base...), "list", "--cursor", "unsafe\nvalue"),
		append(append([]string{}, base...), "list", "--cursor", strings.Repeat("a", 2049)),
		append(append([]string{}, base...), "revoke", "asn_not-canonical"),
		append(append([]string{}, base...), "revoke", adminSessionCommandID1, "--reason", "caller-controlled"),
	}
	for _, args := range tests {
		var output bytes.Buffer
		if err := executeWithOptions(context.Background(), args, &options{output: "table", stdout: &output, stderr: &output, adminHTTPClient: client}); err == nil {
			t.Fatalf("unsafe arguments accepted: %q", args)
		}
	}
	if requests != 0 {
		t.Fatalf("unsafe input request count = %d", requests)
	}

	var output bytes.Buffer
	err := executeWithOptions(context.Background(), append(append([]string{}, base...), "revoke", adminSessionCommandID1), &options{
		output: "table", stdout: &output, stderr: &output, adminHTTPClient: client,
	})
	if err == nil || !strings.Contains(err.Error(), defaultAdminTokenEnvironment) {
		t.Fatalf("missing scoped API token error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("missing token request count = %d", requests)
	}
}

func adminSessionTestItem(sessionID, administratorID, email, createdAt, lastSeenAt, expiresAt, status, current string) string {
	return fmt.Sprintf(
		`{"id":%q,"administrator":{"id":%q,"email":%q},"created_at":%q,"last_seen_at":%q,"expires_at":%q,"status":%q,"current":%s}`,
		sessionID, administratorID, email, createdAt, lastSeenAt, expiresAt, status, current,
	)
}

func adminSessionPage(items, page string) string {
	return `{"items":[` + items + `],"page":` + page + `}`
}

func adminSessionCommandResponse(request *http.Request, status int, body string) *http.Response {
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
