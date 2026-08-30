package clientapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/id"
)

func TestSessionTransportRejectsAmbiguousHeadersBodiesPathsAndQueries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
	}{
		{name: "unknown path", method: http.MethodPost, path: "/client/v1/not-a-session", body: validChallengeBody("ios"), wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "encoded path", method: http.MethodPost, path: "/client/v1/%73ession-challenges", body: validChallengeBody("ios"), wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "wrong method", method: http.MethodPut, path: challengePath, body: validChallengeBody("ios"), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "query", method: http.MethodPost, path: challengePath + "?unexpected=1", body: validChallengeBody("ios"), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "empty query marker", method: http.MethodPost, path: challengePath + "?", body: validChallengeBody("ios"), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "missing protocol", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Del("X-Latchway-Protocol-Version") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "unsupported protocol", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("X-Latchway-Protocol-Version", "2") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "noncanonical protocol", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("X-Latchway-Protocol-Version", "01") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "duplicate protocol", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Add("X-Latchway-Protocol-Version", "1") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "combined protocol", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("X-Latchway-Protocol-Version", "1, 1") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "missing sdk", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Del("X-Latchway-SDK") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "invalid sdk", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("X-Latchway-SDK", "swift") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "duplicate sdk", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Add("X-Latchway-SDK", "ios") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "missing sdk version", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Del("X-Latchway-SDK-Version") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "invalid sdk version", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("X-Latchway-SDK-Version", "v1") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "duplicate sdk version", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Add("X-Latchway-SDK-Version", "1.2.3") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "missing DPoP", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Del("DPoP") }, wantCode: "dpop_missing", wantStatus: http.StatusUnauthorized},
		{name: "empty DPoP", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("DPoP", "") }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "duplicate DPoP", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Add("DPoP", "other.proof.value") }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "combined DPoP", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("DPoP", validProof+","+validProof) }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "malformed DPoP", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("DPoP", "only-one-segment") }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "oversized DPoP", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("DPoP", "a."+strings.Repeat("b", maximumDPoPBytes)+".c") }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "missing media type", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Del("Content-Type") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "media type parameters", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "wrong media type", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("Content-Type", "text/json") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "duplicate media type", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "content encoding", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios"), mutate: func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "empty body", method: http.MethodPost, path: challengePath, body: "", wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "malformed JSON", method: http.MethodPost, path: challengePath, body: `{`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "root array", method: http.MethodPost, path: challengePath, body: `[]`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "duplicate JSON member", method: http.MethodPost, path: challengePath, body: `{"application_id":"first","application_id":"second","environment":"production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"ios","sdk_version":"1.2.3"}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", method: http.MethodPost, path: challengePath, body: validChallengeBody("ios") + `{}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "unknown body field", method: http.MethodPost, path: challengePath, body: `{"application_id":"app_public","environment":"production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"ios","sdk_version":"1.2.3","provider_secret":"must-not-echo"}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "missing body field", method: http.MethodPost, path: challengePath, body: `{"application_id":"app_public","environment":"production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"ios"}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "invalid environment", method: http.MethodPost, path: challengePath, body: `{"application_id":"app_public","environment":"Production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"ios","sdk_version":"1.2.3"}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "invalid identity provider", method: http.MethodPost, path: challengePath, body: `{"application_id":"app_public","environment":"production","identity_provider":"not.valid","identity_token":"identity-token-123","platform":"ios","sdk_version":"1.2.3"}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "short identity token", method: http.MethodPost, path: challengePath, body: `{"application_id":"app_public","environment":"production","identity_provider":"firebase","identity_token":"short","platform":"ios","sdk_version":"1.2.3"}`, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "invalid platform", method: http.MethodPost, path: challengePath, body: validChallengeBody("windows"), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "sdk body version mismatch", method: http.MethodPost, path: challengePath, body: strings.Replace(validChallengeBody("ios"), `"1.2.3"`, `"1.2.4"`, 1), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "sdk platform mismatch", method: http.MethodPost, path: challengePath, body: validChallengeBody("android"), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "oversized body", method: http.MethodPost, path: challengePath, body: strings.Repeat(" ", maximumChallengeBodyBytes+1), wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			request := validClientRequest(test.method, test.path, test.body, "ios", "1.2.3")
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.wantCode, test.wantStatus)
			if len(coordinator.challengeInputs) != 0 {
				t.Fatalf("coordinator called for rejected request: %#v", coordinator.challengeInputs)
			}
			if strings.Contains(response.Body.String(), "must-not-echo") || strings.Contains(response.Body.String(), "identity-token-123") || strings.Contains(response.Body.String(), validProof) {
				t.Fatalf("problem leaked request data: %s", response.Body.String())
			}
			assertProblemErrorsMatchContract(t, response)
		})
	}
}

func TestExchangeAndRefreshRejectInvalidNestedShapesAndEndpointCaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		body     string
		response int
	}{
		{name: "exchange duplicate nested field", path: exchangePath, body: `{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","provider":"app_attest","evidence":{}},"installation":{"app_version":"1"}}`, response: http.StatusBadRequest},
		{name: "exchange unknown attestation field", path: exchangePath, body: `{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":{},"secret":"hidden"},"installation":{"app_version":"1"}}`, response: http.StatusBadRequest},
		{name: "exchange evidence is array", path: exchangePath, body: `{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":[]},"installation":{"app_version":"1"}}`, response: http.StatusBadRequest},
		{name: "exchange unknown installation field", path: exchangePath, body: `{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":{}},"installation":{"app_version":"1","key_storage":"client-asserted"}}`, response: http.StatusBadRequest},
		{name: "exchange invalid challenge", path: exchangePath, body: `{"challenge_id":"chl_short","attestation":{"provider":"debug","evidence":{}},"installation":{"app_version":"1"}}`, response: http.StatusBadRequest},
		{name: "exchange null optional metadata", path: exchangePath, body: `{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":{}},"installation":{"app_version":"1","os_version":null}}`, response: http.StatusBadRequest},
		{name: "exchange body cap", path: exchangePath, body: strings.Repeat(" ", maximumExchangeBodyBytes+1), response: http.StatusBadRequest},
		{name: "refresh short token", path: refreshPath, body: `{"refresh_token":"short"}`, response: http.StatusBadRequest},
		{name: "refresh unknown field", path: refreshPath, body: `{"refresh_token":"` + strings.Repeat("r", 48) + `","policy_revision":"client-owned"}`, response: http.StatusBadRequest},
		{name: "refresh identity token", path: refreshPath, body: `{"refresh_token":"` + strings.Repeat("r", 48) + `","identity_token":"fresh-identity-token"}`, response: http.StatusBadRequest},
		{name: "refresh attestation", path: refreshPath, body: `{"refresh_token":"` + strings.Repeat("r", 48) + `","attestation":{"provider":"debug","evidence":{}}}`, response: http.StatusBadRequest},
		{name: "refresh body cap", path: refreshPath, body: strings.Repeat(" ", maximumRefreshBodyBytes+1), response: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{exchangeResult: validGrantResult("ios"), refreshResult: validGrantResult("ios")}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validClientRequest(http.MethodPost, test.path, test.body, "ios", "1.2.3"))
			assertProblem(t, response, "request_invalid", test.response)
			if len(coordinator.exchangeInputs) != 0 || len(coordinator.refreshInputs) != 0 {
				t.Fatal("coordinator called for rejected nested request")
			}
			if strings.Contains(response.Body.String(), "client-owned") || strings.Contains(response.Body.String(), "client-asserted") || strings.Contains(response.Body.String(), "hidden") {
				t.Fatalf("problem leaked rejected value: %s", response.Body.String())
			}
			assertProblemErrorsMatchContract(t, response)
		})
	}
}

func TestAllSDKPlatformPairsAreEnforced(t *testing.T) {
	t.Parallel()

	validPairs := []struct{ sdk, platform string }{
		{sdk: "ios", platform: "ios"},
		{sdk: "android", platform: "android"},
		{sdk: "javascript", platform: "web"},
		{sdk: "javascript", platform: "node"},
		{sdk: "react-native", platform: "react_native_ios"},
		{sdk: "react-native", platform: "react_native_android"},
	}
	for _, pair := range validPairs {
		pair := pair
		t.Run(pair.sdk+" "+pair.platform, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			request := validClientRequest(http.MethodPost, challengePath, validChallengeBody(pair.platform), pair.sdk, "1.2.3")
			if pair.platform == "web" {
				request.Header.Set("Origin", "https://app.example.test")
			}
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if len(coordinator.challengeInputs) != 1 || coordinator.challengeInputs[0].Platform != pair.platform {
				t.Fatalf("challenge inputs = %#v", coordinator.challengeInputs)
			}
		})
	}

	invalidPairs := []struct{ sdk, platform string }{
		{sdk: "ios", platform: "web"},
		{sdk: "android", platform: "react_native_android"},
		{sdk: "javascript", platform: "ios"},
		{sdk: "react-native", platform: "android"},
	}
	for _, pair := range invalidPairs {
		pair := pair
		t.Run("invalid "+pair.sdk+" "+pair.platform, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validClientRequest(http.MethodPost, challengePath, validChallengeBody(pair.platform), pair.sdk, "1.2.3"))
			assertProblem(t, response, "request_invalid", http.StatusBadRequest)
			if len(coordinator.challengeInputs) != 0 {
				t.Fatal("coordinator called for SDK/platform mismatch")
			}
		})
	}
}

func TestDPoPBoundIsInclusiveAndProofRemainsOpaque(t *testing.T) {
	t.Parallel()

	proof := "a." + strings.Repeat("b", maximumDPoPBytes-4) + ".c"
	if len(proof) != maximumDPoPBytes {
		t.Fatalf("test proof bytes = %d", len(proof))
	}
	coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3")
	request.Header.Set("DPoP", proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || len(coordinator.challengeInputs) != 1 || coordinator.challengeInputs[0].Metadata.DPoPProof.Reveal() != proof {
		t.Fatalf("bounded proof was not passed exactly: status=%d calls=%d", response.Code, len(coordinator.challengeInputs))
	}
	if strings.Contains(fmt.Sprintf("%#v", coordinator.challengeInputs[0].Metadata), proof) {
		t.Fatal("request metadata formatting exposed the DPoP proof")
	}
}

func TestEvidenceMemberAndByteLimitsAreEnforced(t *testing.T) {
	t.Parallel()

	members := make([]string, 0, maximumEvidenceMembers+1)
	for index := 0; index < maximumEvidenceMembers+1; index++ {
		members = append(members, fmt.Sprintf(`"k%d":"v"`, index))
	}
	tests := []string{
		`{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":{` + strings.Join(members, ",") + `}},"installation":{"app_version":"1"}}`,
		`{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":{"blob":"` + strings.Repeat("x", maximumEvidenceBytes) + `"}},"installation":{"app_version":"1"}}`,
	}
	for index, body := range tests {
		index, body := index, body
		t.Run(fmt.Sprintf("limit %d", index), func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{exchangeResult: validGrantResult("ios")}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validClientRequest(http.MethodPost, exchangePath, body, "ios", "1.2.3"))
			assertProblem(t, response, "request_invalid", http.StatusBadRequest)
			if len(coordinator.exchangeInputs) != 0 {
				t.Fatal("coordinator called for oversized evidence")
			}
		})
	}
}

func TestCorrelationIDSelectionUsesSafePrecedenceAndFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		clientID   []string
		contextID  string
		want       string
		wantPrefix string
	}{
		{name: "valid client hint", clientID: []string{validRequestIDText}, want: validRequestIDText},
		{name: "logical-looking client hint", clientID: []string{logicalLookingHint}, want: logicalLookingHint},
		{name: "middleware wins", clientID: []string{validRequestIDText}, contextID: "server-request-456", want: "server-request-456"},
		{name: "invalid client hint", clientID: []string{"bad id"}, wantPrefix: "req_"},
		{name: "short client hint", clientID: []string{"short"}, wantPrefix: "req_"},
		{name: "duplicate client hint", clientID: []string{"first-request", "second-request"}, wantPrefix: "req_"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3")
			request.Header.Del("X-Latchway-Request-ID")
			for _, value := range test.clientID {
				request.Header.Add("X-Latchway-Request-ID", value)
			}
			if test.contextID != "" {
				request = request.WithContext(context.WithValue(request.Context(), middleware.RequestIDKey, test.contextID))
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			actual := response.Header().Get("X-Latchway-Request-ID")
			if test.want != "" && actual != test.want {
				t.Fatalf("request ID = %q, want %q", actual, test.want)
			}
			if test.wantPrefix != "" && !strings.HasPrefix(actual, test.wantPrefix) {
				t.Fatalf("request ID = %q, want prefix %q", actual, test.wantPrefix)
			}
			if len(coordinator.challengeInputs) != 1 {
				t.Fatalf("challenge inputs = %#v", coordinator.challengeInputs)
			}
			logicalRequestID := coordinator.challengeInputs[0].Metadata.RequestID
			if err := id.Validate(logicalRequestID, id.LogicalRequest); err != nil {
				t.Fatalf("metadata logical request ID is not canonical: %v", err)
			}
			if len(test.clientID) == 1 && logicalRequestID == test.clientID[0] {
				t.Fatalf("client request hint became logical request ID: %q", logicalRequestID)
			}
		})
	}
}

func TestProtocolUpgradeProblemAdvertisesOnlySupportedVersion(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3")
	request.Header.Set("X-Latchway-Protocol-Version", "99")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, "protocol_version_unsupported", http.StatusUpgradeRequired)
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	versions, ok := document["supported_protocol_versions"].([]any)
	if !ok || len(versions) != 1 || versions[0] != float64(1) {
		t.Fatalf("supported versions = %#v", document["supported_protocol_versions"])
	}
}

func assertProblemErrorsMatchContract(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	raw, exists := document["errors"]
	if !exists {
		return
	}
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("problem errors = %#v", raw)
	}
	for _, item := range items {
		field, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("field error = %#v", item)
		}
		assertExactKeys(t, field, "path", "message")
	}
}
