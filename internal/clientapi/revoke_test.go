package clientapi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validAccessToken = "headerheaderheaderheaderheader.payloadpayloadpayloadpayloadpayload.signaturesignaturesignature"

func TestRevokeCurrentInstallationUsesBoundedCredentialsAndCanonicalTarget(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://Gateway.Example.Test/")
	request := validRevokeRequest()
	request.Host = "attacker.invalid"
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Request-ID", validRequestIDText)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Body.Len() != 0 || response.Header().Get("Content-Type") != "" || response.Header().Get("Content-Length") != "" {
		t.Fatalf("204 response unexpectedly carried a representation: headers=%#v body=%q", response.Header(), response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Latchway-Request-ID") != validRequestIDText {
		t.Fatalf("204 headers = %#v", response.Header())
	}
	if len(coordinator.revokeInputs) != 1 {
		t.Fatalf("revoke calls = %d", len(coordinator.revokeInputs))
	}
	input := coordinator.revokeInputs[0]
	if input.AccessToken.Reveal() != validAccessToken || input.Metadata.DPoPProof.Reveal() != validProof || input.Metadata.RequestID != validRequestIDText || input.Metadata.SDK != "ios" || input.Metadata.SDKVersion != "1.2.3" || input.Metadata.HTTPMethod != http.MethodDelete {
		t.Fatalf("unexpected revoke input: %#v", input)
	}
	if target := input.Metadata.TargetURL.String(); target != "https://gateway.example.test"+revokePath {
		t.Fatalf("target URL = %q", target)
	}
	formatted := fmt.Sprintf("%#v", input)
	if strings.Contains(formatted, validAccessToken) || strings.Contains(formatted, validProof) {
		t.Fatalf("revoke input formatting exposed credentials: %s", formatted)
	}
}

func TestRevokeCurrentInstallationAcceptsCaseInsensitiveAuthorizationScheme(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	request := validRevokeRequest()
	request.Header.Set("Authorization", "dpop "+validAccessToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || len(coordinator.revokeInputs) != 1 || coordinator.revokeInputs[0].AccessToken.Reveal() != validAccessToken {
		t.Fatalf("case-insensitive DPoP scheme was rejected: status=%d calls=%d body=%s", response.Code, len(coordinator.revokeInputs), response.Body.String())
	}
}

func TestDPoPAuthorizationCredentialBoundsAreInclusiveAndRemainOpaque(t *testing.T) {
	t.Parallel()

	for _, size := range []int{minimumAccessTokenBytes, maximumAccessTokenBytes} {
		size := size
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			t.Parallel()
			token := strings.Repeat("a", size)
			request := httptest.NewRequest(http.MethodDelete, revokePath, nil)
			request.Header.Set("Authorization", "DPoP "+token)
			credential, violation := parseDPoPAuthorization(request)
			if violation != nil || credential.Reveal() != token {
				t.Fatalf("parseDPoPAuthorization() violation=%#v bytes=%d", violation, len(credential.Reveal()))
			}
			formatted := fmt.Sprintf("%#v", credential)
			if strings.Contains(formatted, token) {
				t.Fatalf("credential formatting exposed a %d-byte token", size)
			}
		})
	}
}

func TestRevokeCurrentInstallationRejectsAdversarialTransportBeforeCoordinator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
		wantPath   string
	}{
		{name: "missing authorization", mutate: func(r *http.Request) { r.Header.Del("Authorization") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "duplicate authorization", mutate: func(r *http.Request) { r.Header.Add("Authorization", "DPoP "+validAccessToken) }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "combined authorization", mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP "+validAccessToken+", DPoP "+validAccessToken)
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "wrong authorization scheme", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+validAccessToken) }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "scheme separated by tab", mutate: func(r *http.Request) { r.Header.Set("Authorization", "DPoP\t"+validAccessToken) }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "multiple credential spaces", mutate: func(r *http.Request) { r.Header.Set("Authorization", "DPoP  "+validAccessToken) }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "short access token", mutate: func(r *http.Request) { r.Header.Set("Authorization", "DPoP short") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "oversized access token", mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP "+strings.Repeat("a", maximumAccessTokenBytes+1))
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "non ASCII access token", mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP "+strings.Repeat("a", minimumAccessTokenBytes)+"\u00a0")
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "missing proof", mutate: func(r *http.Request) { r.Header.Del("DPoP") }, wantCode: "dpop_missing", wantStatus: http.StatusUnauthorized},
		{name: "duplicate proof", mutate: func(r *http.Request) { r.Header.Add("DPoP", validProof) }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "malformed proof", mutate: func(r *http.Request) { r.Header.Set("DPoP", "not-a-compact-proof") }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "body", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"secret":"must-not-echo"}`))
			r.ContentLength = int64(len(`{"secret":"must-not-echo"}`))
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "body"},
		{name: "declared body without reader", mutate: func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "body"},
		{name: "chunked body declaration", mutate: func(r *http.Request) { r.Body = http.NoBody; r.TransferEncoding = []string{"chunked"} }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "body"},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "token=must-not-echo" }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "query"},
		{name: "empty query marker", mutate: func(r *http.Request) { r.URL.ForceQuery = true }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "query"},
		{name: "invalid protocol", mutate: func(r *http.Request) { r.Header.Set("X-Latchway-Protocol-Version", "2") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "invalid SDK", mutate: func(r *http.Request) { r.Header.Set("X-Latchway-SDK", "swift") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.X-Latchway-SDK"},
		{name: "invalid SDK version", mutate: func(r *http.Request) { r.Header.Set("X-Latchway-SDK-Version", "latest") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.X-Latchway-SDK-Version"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			request := validRevokeRequest()
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assertProblem(t, response, test.wantCode, test.wantStatus)
			if len(coordinator.revokeInputs) != 0 {
				t.Fatalf("coordinator called for rejected request: %#v", coordinator.revokeInputs)
			}
			if strings.Contains(response.Body.String(), validAccessToken) || strings.Contains(response.Body.String(), validProof) || strings.Contains(response.Body.String(), "must-not-echo") {
				t.Fatalf("problem leaked request credentials: %s", response.Body.String())
			}
			assertProblemErrorsMatchContract(t, response)
			if test.wantPath != "" {
				assertSingleProblemPath(t, response, test.wantPath)
			}
		})
	}
}

func TestRevokeCurrentInstallationRejectsWrongMethodAndNoncanonicalPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
	}{
		{name: "wrong method", mutate: func(r *http.Request) { r.Method = http.MethodPost }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "trailing slash", mutate: func(r *http.Request) { r.URL.Path += "/" }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "encoded path", mutate: func(r *http.Request) { r.URL.RawPath = "/client/v1/installations/%63urrent" }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			request := validRevokeRequest()
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.wantCode, test.wantStatus)
			if len(coordinator.revokeInputs) != 0 {
				t.Fatal("coordinator called for an invalid method or path")
			}
		})
	}
}

func TestRevokeCurrentInstallationDependencyFailureIsCanonicalAndRedacted(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{revokeErr: fmt.Errorf("database-secret %s: %w", validAccessToken, &DependencyError{Code: "session_expired", RetryAfterSeconds: 7})}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, validRevokeRequest())

	assertProblem(t, response, "session_expired", http.StatusUnauthorized)
	if response.Header().Get("Retry-After") != "7" || len(coordinator.revokeInputs) != 1 {
		t.Fatalf("dependency response headers=%#v calls=%d", response.Header(), len(coordinator.revokeInputs))
	}
	if strings.Contains(response.Body.String(), "database-secret") || strings.Contains(response.Body.String(), validAccessToken) || strings.Contains(response.Body.String(), validProof) {
		t.Fatalf("dependency problem leaked sensitive context: %s", response.Body.String())
	}
}

func validRevokeRequest() *http.Request {
	request := httptest.NewRequest(http.MethodDelete, revokePath, nil)
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "ios")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("Authorization", "DPoP "+validAccessToken)
	request.Header.Set("DPoP", validProof)
	return request
}

func assertSingleProblemPath(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	errorsValue, ok := document["errors"].([]any)
	if !ok || len(errorsValue) != 1 {
		t.Fatalf("problem errors = %#v", document["errors"])
	}
	field, ok := errorsValue[0].(map[string]any)
	if !ok || field["path"] != want {
		t.Fatalf("problem field = %#v, want path %q", errorsValue[0], want)
	}
}
