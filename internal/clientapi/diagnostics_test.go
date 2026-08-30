package clientapi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestClientDiagnosticsUsesCanonicalAuthenticatedInputAndExactRedactedContract(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{diagnosticsResult: validDiagnosticsResult("ios")}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://Gateway.Example.Test/")
	request := validDiagnosticsRequest()
	request.Host = "attacker.invalid"
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Request-ID", logicalLookingHint)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertSuccessHeaders(t, response, "no-store")
	if response.Header().Get("X-Latchway-Request-ID") != logicalLookingHint {
		t.Fatalf("correlation response ID = %q", response.Header().Get("X-Latchway-Request-ID"))
	}
	if len(coordinator.diagnosticsInputs) != 1 {
		t.Fatalf("diagnostics calls = %d", len(coordinator.diagnosticsInputs))
	}
	input := coordinator.diagnosticsInputs[0]
	if err := id.Validate(input.Metadata.RequestID, id.LogicalRequest); err != nil {
		t.Fatalf("metadata logical request ID is not canonical: %v", err)
	}
	if input.Metadata.RequestID == logicalLookingHint || input.AccessToken.Reveal() != validAccessToken ||
		input.Metadata.DPoPProof.Reveal() != validProof || input.Metadata.SDK != "ios" ||
		input.Metadata.SDKVersion != "1.2.3" || input.Metadata.HTTPMethod != http.MethodGet ||
		input.Metadata.TargetURL.String() != "https://gateway.example.test"+diagnosticsPath {
		t.Fatalf("unexpected diagnostics input: %#v", input)
	}
	formatted := fmt.Sprintf("%#v", input)
	if strings.Contains(formatted, validAccessToken) || strings.Contains(formatted, validProof) {
		t.Fatalf("diagnostics input formatting exposed credentials: %s", formatted)
	}

	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document,
		"request_id", "server_version", "contract_version", "protocol_version",
		"installation", "session", "trust",
	)
	if document["request_id"] != logicalLookingHint || document["contract_version"] != "1.0.0" ||
		document["protocol_version"] != float64(2) {
		t.Fatalf("diagnostics identity = %#v", document)
	}
	installation := document["installation"].(map[string]any)
	assertExactKeys(t, installation, "id", "platform", "dpop_jkt", "status")
	if installation["id"] != validInstallation || installation["platform"] != "ios" ||
		installation["status"] != "active" {
		t.Fatalf("installation diagnostics = %#v", installation)
	}
	session := document["session"].(map[string]any)
	assertExactKeys(t, session, "expires_at", "refresh_available")
	if session["expires_at"] != testInstant.Add(10*time.Minute).Format(time.RFC3339) ||
		session["refresh_available"] != true {
		t.Fatalf("session diagnostics = %#v", session)
	}
	trust := document["trust"].(map[string]any)
	assertExactKeys(t, trust, "provider", "level", "verified_at", "expires_at")
	if trust["provider"] != "debug" || trust["level"] != "debug" {
		t.Fatalf("trust diagnostics = %#v", trust)
	}
	for _, forbidden := range []string{
		validAccessToken, validProof, "attacker.invalid", "organization_id", "application_user_id",
		"normalized_claims", "identity_provider", "policy_revision_id", "session_grant_id",
	} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("diagnostics response exposed forbidden value %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestClientDiagnosticsRejectsInvalidTransportBeforeCoordinator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
	}{
		{name: "wrong method", mutate: func(r *http.Request) { r.Method = http.MethodPost }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "missing authorization", mutate: func(r *http.Request) { r.Header.Del("Authorization") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "missing proof", mutate: func(r *http.Request) { r.Header.Del("DPoP") }, wantCode: "dpop_missing", wantStatus: http.StatusUnauthorized},
		{name: "body", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"secret":"must-not-echo"}`))
			r.ContentLength = int64(len(`{"secret":"must-not-echo"}`))
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "token=must-not-echo" }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "trailing slash", mutate: func(r *http.Request) { r.URL.Path += "/" }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{diagnosticsResult: validDiagnosticsResult("ios")}
			response := httptest.NewRecorder()
			request := validDiagnosticsRequest()
			test.mutate(request)
			newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test").ServeHTTP(response, request)
			assertProblem(t, response, test.wantCode, test.wantStatus)
			if len(coordinator.diagnosticsInputs) != 0 {
				t.Fatalf("coordinator called for rejected diagnostics: %#v", coordinator.diagnosticsInputs)
			}
			if strings.Contains(response.Body.String(), validAccessToken) ||
				strings.Contains(response.Body.String(), validProof) ||
				strings.Contains(response.Body.String(), "must-not-echo") {
				t.Fatalf("diagnostics problem exposed request material: %s", response.Body.String())
			}
		})
	}
}

func TestClientDiagnosticsFailuresAreCanonicalAndRedacted(t *testing.T) {
	t.Parallel()

	t.Run("dependency failure", func(t *testing.T) {
		t.Parallel()
		coordinator := &fakeCoordinator{diagnosticsErr: fmt.Errorf(
			"database-secret %s: %w", validAccessToken,
			&DependencyError{Code: "session_expired", RetryAfterSeconds: 7},
		)}
		response := httptest.NewRecorder()
		newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test").ServeHTTP(response, validDiagnosticsRequest())
		assertProblem(t, response, "session_expired", http.StatusUnauthorized)
		if response.Header().Get("Retry-After") != "7" || strings.Contains(response.Body.String(), "database-secret") ||
			strings.Contains(response.Body.String(), validAccessToken) {
			t.Fatalf("dependency diagnostics were not redacted: headers=%#v body=%s", response.Header(), response.Body.String())
		}
	})

	invalid := []DiagnosticsResult{
		{},
		func() DiagnosticsResult {
			result := validDiagnosticsResult("ios")
			result.Installation.ID = "private-subject-that-must-not-echo"
			return result
		}(),
		func() DiagnosticsResult {
			result := validDiagnosticsResult("ios")
			result.Installation.Status = "revoked"
			return result
		}(),
		func() DiagnosticsResult {
			result := validDiagnosticsResult("android")
			return result
		}(),
	}
	for index, result := range invalid {
		index, result := index, result
		t.Run(fmt.Sprintf("invalid result %d", index), func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{diagnosticsResult: result}
			response := httptest.NewRecorder()
			newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test").ServeHTTP(response, validDiagnosticsRequest())
			assertProblem(t, response, "internal_error", http.StatusInternalServerError)
			if strings.Contains(response.Body.String(), "private-subject") {
				t.Fatalf("invalid diagnostics result was disclosed: %s", response.Body.String())
			}
		})
	}
}

func TestClientDiagnosticsPreflightAndOpenAPIContractStayAligned(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{}
	request := httptest.NewRequest(http.MethodOptions, diagnosticsPath, nil)
	request.Header.Set("Origin", "https://app.example.test")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	request.Header.Set("Access-Control-Request-Headers", "authorization, dpop, x-latchway-sdk")
	response := httptest.NewRecorder()
	newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test").ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Methods") != http.MethodGet ||
		response.Header().Get("Access-Control-Allow-Origin") != "https://app.example.test" || response.Body.Len() != 0 {
		t.Fatalf("diagnostics preflight status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if len(coordinator.diagnosticsInputs) != 0 {
		t.Fatal("diagnostics preflight reached the coordinator")
	}

	contract, err := os.ReadFile("../../api/client.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contract)
	start := strings.Index(text, "  /client/v1/diagnostics:\n")
	if start < 0 {
		t.Fatal("client OpenAPI omitted the diagnostics operation")
	}
	section := text[start:]
	if end := strings.Index(section, "\n  /"); end >= 0 {
		section = section[:end]
	}
	for _, required := range []string{
		"operationId: getClientDiagnostics", "DPoPAccessToken: []", "DPoPProof: []",
		"$ref: '#/components/schemas/ClientDiagnostics'",
		"Safe diagnostics without tokens, raw evidence, subjects or credentials.",
	} {
		if !strings.Contains(section, required) {
			t.Fatalf("client OpenAPI diagnostics operation omitted %q", required)
		}
	}
	if !strings.Contains(text, "required: [request_id, server_version, contract_version, protocol_version, installation, session, trust]") ||
		!strings.Contains(text, "required: [expires_at, refresh_available]") {
		t.Fatal("client OpenAPI diagnostics schema no longer matches the production response")
	}
}

func validDiagnosticsRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, diagnosticsPath, nil)
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "ios")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("Authorization", "DPoP "+validAccessToken)
	request.Header.Set("DPoP", validProof)
	return request
}

func validDiagnosticsResult(platform string) DiagnosticsResult {
	return DiagnosticsResult{
		Installation: InstallationSummary{
			ID: validInstallation, Platform: platform,
			DPoPJKT: validGrantResult(platform).Installation.DPoPJKT, Status: "active",
		},
		SessionExpiresAt: testInstant.Add(10 * time.Minute), RefreshAvailable: true,
		Trust: TrustSummary{
			Provider: "debug", Level: "debug",
			VerifiedAt: testInstant, ExpiresAt: testInstant.Add(20 * time.Minute),
		},
	}
}
