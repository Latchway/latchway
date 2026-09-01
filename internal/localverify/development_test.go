package localverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestValidateDevelopmentListenAddressRequiresCanonicalLoopbackIP(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value    string
		wantHost string
		wantPort int
	}{
		{value: "127.0.0.1:0", wantHost: "127.0.0.1", wantPort: 0},
		{value: "127.0.0.2:8080", wantHost: "127.0.0.2", wantPort: 8080},
		{value: "127.0.0.1:65535", wantHost: "127.0.0.1", wantPort: 65535},
		{value: "[::1]:8080", wantHost: "::1", wantPort: 8080},
	} {
		host, port, err := validateDevelopmentListenAddress(test.value)
		if err != nil || host != test.wantHost || port != test.wantPort {
			t.Fatalf("validateDevelopmentListenAddress(%q) = %q, %d, %v", test.value, host, port, err)
		}
	}

	for _, value := range []string{
		"", "localhost:8080", "0.0.0.0:8080", "[::]:8080",
		"127.0.0.1", "127.0.0.1:", "127.0.0.1:-1", "127.0.0.1:65536",
		"127.0.0.1:08080", "[0:0:0:0:0:0:0:1]:8080",
	} {
		if _, _, err := validateDevelopmentListenAddress(value); err == nil {
			t.Fatalf("validateDevelopmentListenAddress(%q) accepted an unsafe or ambiguous address", value)
		}
	}
}

func TestRunDevelopmentRejectsInvalidBootstrapBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()

	valid := DevelopmentConfig{
		DatabaseURL:   "postgres://unused.invalid/latchway",
		ListenAddress: "127.0.0.1:0", BrowserOrigin: "http://localhost:5173",
	}
	var nilContext context.Context
	if err := RunDevelopment(nilContext, valid); err == nil || err.Error() != "local development requires a context" {
		t.Fatalf("nil context error = %v", err)
	}

	missingDatabase := valid
	missingDatabase.DatabaseURL = " "
	if err := RunDevelopment(context.Background(), missingDatabase); err == nil ||
		err.Error() != "local development requires a PostgreSQL database URL" {
		t.Fatalf("missing database error = %v", err)
	}

	invalidListen := valid
	invalidListen.ListenAddress = "0.0.0.0:8080"
	if err := RunDevelopment(context.Background(), invalidListen); err == nil ||
		!strings.Contains(err.Error(), "canonical loopback IP") {
		t.Fatalf("non-loopback listen error = %v", err)
	}

	invalidBrowser := valid
	invalidBrowser.BrowserOrigin = "https://localhost:5173"
	if err := RunDevelopment(context.Background(), invalidBrowser); err == nil ||
		!strings.Contains(err.Error(), "exact loopback HTTP origin") {
		t.Fatalf("non-development browser origin error = %v", err)
	}
}

func TestDevelopmentPasswordIsOpaqueAndUnique(t *testing.T) {
	t.Parallel()

	first, err := newDevelopmentPassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newDevelopmentPassword()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "local-") {
		t.Fatalf("development passwords are not opaque and unique: first length=%d second length=%d", len(first), len(second))
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(first, "local-"))
	if err != nil || len(decoded) != 24 {
		t.Fatalf("development password entropy encoding is invalid: length=%d error=%v", len(decoded), err)
	}
}

func TestDevelopmentIdentityHelperEnforcesExactCORS(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidc := &mockOIDC{
		privateKey: privateKey, kid: "development-cors-test",
		issuer: "https://issuer.local-verify.example.test",
	}
	fixture := &fixture{
		oidc: oidc, browserOrigin: "http://localhost:5173",
		nowFunction: func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) },
	}

	request := httptest.NewRequest(http.MethodGet, "/development/v1/identity-token", nil)
	request.Header.Set("Origin", fixture.browserOrigin)
	response := httptest.NewRecorder()
	fixture.serveDevelopment(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Access-Control-Allow-Origin") != fixture.browserOrigin ||
		response.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("allowed identity response: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var tokenDocument map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &tokenDocument); err != nil || len(tokenDocument["identity_token"]) < 64 {
		t.Fatalf("identity token response is invalid: document=%v error=%v", tokenDocument, err)
	}
	for _, target := range []string{
		"/identity-token",
		"/development/v1/identity-token/",
		"/development/v1/identity-token?unexpected=true",
		"/development/v1/%69dentity-token",
	} {
		aliasResponse := httptest.NewRecorder()
		fixture.serveDevelopment(aliasResponse, httptest.NewRequest(http.MethodGet, target, nil))
		if aliasResponse.Code != http.StatusNotFound {
			t.Fatalf("non-canonical helper target %q status = %d, want %d", target, aliasResponse.Code, http.StatusNotFound)
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{
			name: "different origin", status: http.StatusForbidden,
			mutate: func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:5173") },
		},
		{
			name: "duplicate origin", status: http.StatusForbidden,
			mutate: func(r *http.Request) {
				r.Header.Set("Origin", fixture.browserOrigin)
				r.Header.Add("Origin", fixture.browserOrigin)
			},
		},
		{
			name: "non-canonical origin", status: http.StatusForbidden,
			mutate: func(r *http.Request) { r.Header.Set("Origin", fixture.browserOrigin+"/") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rejectedRequest := httptest.NewRequest(http.MethodGet, "/development/v1/identity-token", nil)
			test.mutate(rejectedRequest)
			rejectedResponse := httptest.NewRecorder()
			fixture.developmentIdentityToken(rejectedResponse, rejectedRequest)
			if rejectedResponse.Code != test.status || rejectedResponse.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("rejected identity response: status=%d headers=%v body=%s", rejectedResponse.Code, rejectedResponse.Header(), rejectedResponse.Body.String())
			}
		})
	}
}

func TestDevelopmentHelpersEnforceBoundedPreflight(t *testing.T) {
	t.Parallel()

	fixture := &fixture{browserOrigin: "http://localhost:5173"}
	for _, test := range []struct {
		name             string
		requestedMethod  string
		requestedHeaders []string
		duplicateMethod  bool
		method           string
		headers          string
		wantStatus       int
	}{
		{name: "identity", requestedMethod: http.MethodGet, method: http.MethodGet, wantStatus: http.StatusNoContent},
		{name: "evidence", requestedMethod: http.MethodPost, requestedHeaders: []string{"Content-Type"}, method: http.MethodPost, headers: "content-type", wantStatus: http.StatusNoContent},
		{name: "missing requested method", method: http.MethodGet, wantStatus: http.StatusBadRequest},
		{name: "duplicate requested method", requestedMethod: http.MethodGet, duplicateMethod: true, method: http.MethodGet, wantStatus: http.StatusBadRequest},
		{name: "wrong requested method", requestedMethod: http.MethodDelete, method: http.MethodGet, wantStatus: http.StatusBadRequest},
		{name: "unexpected identity header", requestedMethod: http.MethodGet, requestedHeaders: []string{"authorization"}, method: http.MethodGet, wantStatus: http.StatusBadRequest},
		{name: "extra evidence header", requestedMethod: http.MethodPost, requestedHeaders: []string{"content-type, authorization"}, method: http.MethodPost, headers: "content-type", wantStatus: http.StatusBadRequest},
		{name: "duplicate evidence header", requestedMethod: http.MethodPost, requestedHeaders: []string{"content-type", "content-type"}, method: http.MethodPost, headers: "content-type", wantStatus: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, "/development/v1/helper", nil)
			request.Header.Set("Origin", fixture.browserOrigin)
			if test.requestedMethod != "" {
				request.Header.Set("Access-Control-Request-Method", test.requestedMethod)
			}
			if test.duplicateMethod {
				request.Header.Add("Access-Control-Request-Method", test.requestedMethod)
			}
			for _, value := range test.requestedHeaders {
				request.Header.Add("Access-Control-Request-Headers", value)
			}
			response := httptest.NewRecorder()
			allowed := fixture.developmentRequestAllowed(response, request, test.method, test.headers)
			if allowed || response.Code != test.wantStatus {
				t.Fatalf("preflight allowed=%t status=%d headers=%v body=%s", allowed, response.Code, response.Header(), response.Body.String())
			}
			if test.wantStatus == http.StatusNoContent {
				if response.Header().Get("Access-Control-Allow-Origin") != fixture.browserOrigin ||
					response.Header().Get("Access-Control-Allow-Methods") != test.method ||
					!strings.Contains(strings.Join(response.Header().Values("Vary"), ","), "Access-Control-Request-Method") ||
					!strings.Contains(strings.Join(response.Header().Values("Vary"), ","), "Access-Control-Request-Headers") {
					t.Fatalf("successful preflight headers = %v", response.Header())
				}
			}
		})
	}
}

func TestDevelopmentSampleHelperEnforcesExactOriginAndBoundedPreflight(t *testing.T) {
	t.Parallel()

	fixture := &fixture{
		publicOrigin:  "http://127.0.0.1:38080",
		browserOrigin: "http://localhost:5173",
	}
	for _, origin := range []string{fixture.publicOrigin, fixture.browserOrigin} {
		request := httptest.NewRequest(http.MethodOptions, "/development/v1/sample-request", nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("Access-Control-Request-Method", http.MethodPost)
		request.Header.Set("Access-Control-Request-Headers", "Content-Type")
		response := httptest.NewRecorder()
		if fixture.developmentConsoleRequestAllowed(response, request) || response.Code != http.StatusNoContent ||
			response.Header().Get("Access-Control-Allow-Origin") != origin ||
			response.Header().Get("Access-Control-Allow-Methods") != http.MethodPost ||
			response.Header().Get("Access-Control-Allow-Headers") != "content-type" {
			t.Fatalf("allowed sample preflight for %q: status=%d headers=%v body=%s", origin, response.Code, response.Header(), response.Body.String())
		}
	}

	for _, test := range []struct {
		name             string
		origin           string
		requestedMethod  string
		requestedHeaders string
		duplicateOrigin  bool
		duplicateHeaders bool
		wantCORS         bool
	}{
		{name: "missing origin", requestedMethod: http.MethodPost, requestedHeaders: "content-type"},
		{name: "different origin", origin: "http://127.0.0.2:5173", requestedMethod: http.MethodPost, requestedHeaders: "content-type"},
		{name: "duplicate origin", origin: fixture.browserOrigin, requestedMethod: http.MethodPost, requestedHeaders: "content-type", duplicateOrigin: true},
		{name: "wrong method", origin: fixture.browserOrigin, requestedMethod: http.MethodGet, requestedHeaders: "content-type", wantCORS: true},
		{name: "missing headers", origin: fixture.browserOrigin, requestedMethod: http.MethodPost, wantCORS: true},
		{name: "extra header", origin: fixture.browserOrigin, requestedMethod: http.MethodPost, requestedHeaders: "content-type, x-csrf-token", wantCORS: true},
		{name: "duplicate header field", origin: fixture.browserOrigin, requestedMethod: http.MethodPost, requestedHeaders: "content-type", duplicateHeaders: true, wantCORS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, "/development/v1/sample-request", nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
				if test.duplicateOrigin {
					request.Header.Add("Origin", test.origin)
				}
			}
			if test.requestedMethod != "" {
				request.Header.Set("Access-Control-Request-Method", test.requestedMethod)
			}
			if test.requestedHeaders != "" {
				request.Header.Set("Access-Control-Request-Headers", test.requestedHeaders)
				if test.duplicateHeaders {
					request.Header.Add("Access-Control-Request-Headers", test.requestedHeaders)
				}
			}
			response := httptest.NewRecorder()
			if fixture.developmentConsoleRequestAllowed(response, request) ||
				(response.Code != http.StatusBadRequest && response.Code != http.StatusForbidden) ||
				(response.Header().Get("Access-Control-Allow-Origin") == fixture.browserOrigin) != test.wantCORS {
				t.Fatalf("rejected sample preflight: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestDevelopmentSampleHelperRejectsInvalidRequestsBeforeRuntime(t *testing.T) {
	t.Parallel()

	fixture := &fixture{
		publicOrigin:  "http://127.0.0.1:38080",
		browserOrigin: "http://localhost:5173",
	}
	for _, test := range []struct {
		name         string
		method       string
		origin       string
		body         string
		contentTypes []string
		wantStatus   int
		wantCode     string
	}{
		{name: "missing origin", method: http.MethodPost, body: `{}`, contentTypes: []string{"application/json"}, wantStatus: http.StatusForbidden, wantCode: "development_origin_not_allowed"},
		{name: "different origin", method: http.MethodPost, origin: "http://127.0.0.2:5173", body: `{}`, contentTypes: []string{"application/json"}, wantStatus: http.StatusForbidden, wantCode: "development_origin_not_allowed"},
		{name: "wrong method", method: http.MethodGet, origin: fixture.publicOrigin, wantStatus: http.StatusMethodNotAllowed, wantCode: "development_method_not_allowed"},
		{name: "missing content type", method: http.MethodPost, origin: fixture.publicOrigin, body: `{}`, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "media type parameters", method: http.MethodPost, origin: fixture.publicOrigin, body: `{}`, contentTypes: []string{"application/json; charset=utf-8"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "duplicate content type", method: http.MethodPost, origin: fixture.publicOrigin, body: `{}`, contentTypes: []string{"application/json", "application/json"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "empty body", method: http.MethodPost, origin: fixture.publicOrigin, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "JSON null", method: http.MethodPost, origin: fixture.publicOrigin, body: `null`, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "unknown field", method: http.MethodPost, origin: fixture.publicOrigin, body: `{"secret":"forbidden"}`, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "trailing JSON", method: http.MethodPost, origin: fixture.publicOrigin, body: `{}{}`, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
		{name: "oversized", method: http.MethodPost, origin: fixture.publicOrigin, body: `{"padding":"` + strings.Repeat("x", 256) + `"}`, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "development_sample_request_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/development/v1/sample-request", strings.NewReader(test.body))
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			for _, value := range test.contentTypes {
				request.Header.Add("Content-Type", value)
			}
			response := httptest.NewRecorder()
			fixture.developmentSampleRequest(response, request)
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantCode) {
				t.Fatalf("invalid sample request: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}

	validRequest := httptest.NewRequest(http.MethodPost, "/development/v1/sample-request", strings.NewReader(`{}`))
	validRequest.Header.Set("Content-Type", "application/json")
	validRequest.Header.Set("Origin", fixture.publicOrigin)
	validResponse := httptest.NewRecorder()
	fixture.serveDevelopment(validResponse, validRequest)
	if validResponse.Code != http.StatusBadGateway ||
		!strings.Contains(validResponse.Body.String(), "development_sample_failed") {
		t.Fatalf("valid sample shape did not reach the isolated runtime: status=%d body=%s", validResponse.Code, validResponse.Body.String())
	}

	for _, target := range []string{
		"/sample-request",
		"/development/v1/sample-request/",
		"/development/v1/sample-request?unexpected=true",
		"/development/v1/%73ample-request",
	} {
		request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", fixture.publicOrigin)
		response := httptest.NewRecorder()
		fixture.serveDevelopment(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("non-canonical sample target %q status = %d, want %d", target, response.Code, http.StatusNotFound)
		}
	}
}

func TestDevelopmentSampleGateRejectsConcurrentWorkWithoutQueuing(t *testing.T) {
	t.Parallel()

	fixture := &fixture{}
	release, acquired := fixture.tryAcquireDevelopmentSample()
	if !acquired || release == nil {
		t.Fatal("first development sample did not acquire the gate")
	}
	if queuedRelease, queued := fixture.tryAcquireDevelopmentSample(); queued || queuedRelease != nil {
		t.Fatal("concurrent development sample was queued or admitted")
	}
	release()
	secondRelease, acquired := fixture.tryAcquireDevelopmentSample()
	if !acquired || secondRelease == nil {
		t.Fatal("development sample gate was not released")
	}
	secondRelease()
}

func TestDevelopmentHelperMethodsFailClosed(t *testing.T) {
	t.Parallel()

	fixture := &fixture{browserOrigin: "http://localhost:5173"}
	for _, test := range []struct {
		requestMethod string
		allowedMethod string
	}{
		{requestMethod: http.MethodPost, allowedMethod: http.MethodGet},
		{requestMethod: http.MethodGet, allowedMethod: http.MethodPost},
		{requestMethod: http.MethodPut, allowedMethod: http.MethodPost},
	} {
		request := httptest.NewRequest(test.requestMethod, "/development/v1/helper", nil)
		request.Header.Set("Origin", fixture.browserOrigin)
		response := httptest.NewRecorder()
		if fixture.developmentRequestAllowed(response, request, test.allowedMethod, "") ||
			response.Code != http.StatusMethodNotAllowed ||
			response.Header().Get("Allow") != test.allowedMethod+", "+http.MethodOptions {
			t.Fatalf("method %s for %s response: status=%d headers=%v body=%s",
				test.requestMethod, test.allowedMethod, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestDevelopmentEvidenceRejectsNonCanonicalJSONBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()

	applicationID, err := id.New(id.Application)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &fixture{tenant: tenant{applicationID: applicationID}, browserOrigin: "http://localhost:5173"}
	binding := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	dpopJKT := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	challengeID, err := id.New(id.SessionChallenge)
	if err != nil {
		t.Fatal(err)
	}
	validShape := `{"challenge_id":"invalid","binding_hash":"` + binding + `","application_id":"` + applicationID + `","environment":"development","dpop_jkt":"` + dpopJKT + `","platform":"ios"}`
	invalidDPoP := `{"challenge_id":"` + challengeID + `","binding_hash":"` + binding + `","application_id":"` + applicationID + `","environment":"development","dpop_jkt":"invalid","platform":"ios"}`
	invalidBinding := `{"challenge_id":"` + challengeID + `","binding_hash":"invalid","application_id":"` + applicationID + `","environment":"development","dpop_jkt":"` + dpopJKT + `","platform":"ios"}`

	for _, test := range []struct {
		name         string
		body         string
		contentTypes []string
	}{
		{name: "missing content type", body: validShape},
		{name: "media type parameters", body: validShape, contentTypes: []string{"application/json; charset=utf-8"}},
		{name: "duplicate content type", body: validShape, contentTypes: []string{"application/json", "application/json"}},
		{name: "unknown field", body: strings.TrimSuffix(validShape, "}") + `,"secret":"forbidden"}`, contentTypes: []string{"application/json"}},
		{name: "trailing JSON", body: validShape + `{}`, contentTypes: []string{"application/json"}},
		{name: "invalid challenge identifier", body: validShape, contentTypes: []string{"application/json"}},
		{name: "invalid DPoP thumbprint", body: invalidDPoP, contentTypes: []string{"application/json"}},
		{name: "invalid binding hash", body: invalidBinding, contentTypes: []string{"application/json"}},
		{name: "oversized", body: `{"padding":"` + strings.Repeat("x", 9<<10) + `"}`, contentTypes: []string{"application/json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/development/v1/attestation-evidence", strings.NewReader(test.body))
			request.Header.Set("Origin", fixture.browserOrigin)
			for _, contentType := range test.contentTypes {
				request.Header.Add("Content-Type", contentType)
			}
			response := httptest.NewRecorder()
			fixture.developmentEvidence(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "development_evidence_request_invalid") {
				t.Fatalf("invalid evidence response: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestDevelopmentHandlerRequiresCompleteLoopbackDependencies(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []*fixture{
		nil,
		{},
		{debugKey: privateKey, browserOrigin: "http://localhost:5173"},
		{debugKey: privateKey, browserOrigin: "https://localhost:5173"},
	} {
		if handler, err := fixture.developmentHandler(); err == nil || handler != nil {
			t.Fatalf("developmentHandler() = %v, %v; want dependency rejection", handler, err)
		}
	}
}
