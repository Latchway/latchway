package clientapi

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

const (
	validChallengeID   = "chl_01K3NQ7M8P9RSTVWXYZABCDE12"
	validInstallation  = "ins_01K3NQ7M8P9RSTVWXYZABCDE12"
	validProof         = "header.payload.signature"
	validRequestIDText = "client-request-123"
	logicalLookingHint = "req_01K3NQ7M8P9RSTVWXYZABCDE12"
)

var testInstant = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

type fakeCoordinator struct {
	challengeResult ChallengeResult
	challengeErr    error
	exchangeResult  GrantResult
	exchangeErr     error
	refreshResult   GrantResult
	refreshErr      error
	revokeErr       error
	challengeInputs []ChallengeInput
	exchangeInputs  []ExchangeInput
	refreshInputs   []RefreshInput
	revokeInputs    []RevokeInstallationInput
}

func (fake *fakeCoordinator) CreateChallenge(_ context.Context, input ChallengeInput) (ChallengeResult, error) {
	fake.challengeInputs = append(fake.challengeInputs, input)
	return fake.challengeResult, fake.challengeErr
}

func (fake *fakeCoordinator) ExchangeSession(_ context.Context, input ExchangeInput) (GrantResult, error) {
	fake.exchangeInputs = append(fake.exchangeInputs, input)
	return fake.exchangeResult, fake.exchangeErr
}

func (fake *fakeCoordinator) RefreshSession(_ context.Context, input RefreshInput) (GrantResult, error) {
	fake.refreshInputs = append(fake.refreshInputs, input)
	return fake.refreshResult, fake.refreshErr
}

func (fake *fakeCoordinator) RevokeCurrentInstallation(_ context.Context, input RevokeInstallationInput) error {
	fake.revokeInputs = append(fake.revokeInputs, input)
	return fake.revokeErr
}

type fakeJWKSProvider struct {
	result JWKS
	err    error
	calls  int
}

func (fake *fakeJWKSProvider) PublicJWKS(context.Context) (JWKS, error) {
	fake.calls++
	return fake.result, fake.err
}

type fakeFeatureQuotaProvider struct {
	result FeatureQuotaResult
	err    error
	inputs []FeatureQuotaInput
}

func (fake *fakeFeatureQuotaProvider) FeatureQuota(_ context.Context, input FeatureQuotaInput) (FeatureQuotaResult, error) {
	fake.inputs = append(fake.inputs, input)
	return fake.result, fake.err
}

func TestNewValidatesDependenciesAndCanonicalPublicOrigin(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{}
	quotas := &fakeFeatureQuotaProvider{}
	keys := &fakeJWKSProvider{}
	var nilCoordinator *fakeCoordinator
	var nilQuotas *fakeFeatureQuotaProvider
	var nilKeys *fakeJWKSProvider
	tests := []struct {
		name   string
		config Config
	}{
		{name: "missing coordinator", config: Config{FeatureQuotas: quotas, JWKS: keys, PublicOrigin: "https://gateway.example.test"}},
		{name: "typed nil coordinator", config: Config{Coordinator: nilCoordinator, FeatureQuotas: quotas, JWKS: keys, PublicOrigin: "https://gateway.example.test"}},
		{name: "missing feature quotas", config: Config{Coordinator: coordinator, JWKS: keys, PublicOrigin: "https://gateway.example.test"}},
		{name: "typed nil feature quotas", config: Config{Coordinator: coordinator, FeatureQuotas: nilQuotas, JWKS: keys, PublicOrigin: "https://gateway.example.test"}},
		{name: "missing jwks", config: Config{Coordinator: coordinator, FeatureQuotas: quotas, PublicOrigin: "https://gateway.example.test"}},
		{name: "typed nil jwks", config: Config{Coordinator: coordinator, FeatureQuotas: quotas, JWKS: nilKeys, PublicOrigin: "https://gateway.example.test"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(test.config); err == nil {
				t.Fatal("New() accepted a nil dependency")
			}
		})
	}

	invalidOrigins := []string{
		"", " gateway.example.test", "gateway.example.test", "ftp://gateway.example.test",
		"http://gateway.example.test", "https://user@gateway.example.test", "https://gateway.example.test/path",
		"https://gateway.example.test?query=1", "https://gateway.example.test#fragment", "https://gateway.example.test/?",
	}
	for _, origin := range invalidOrigins {
		origin := origin
		t.Run("invalid origin "+origin, func(t *testing.T) {
			t.Parallel()
			if _, err := New(Config{Coordinator: coordinator, FeatureQuotas: quotas, JWKS: keys, PublicOrigin: origin}); err == nil {
				t.Fatalf("New() accepted public origin %q", origin)
			}
		})
	}
	for _, origin := range []string{"https://Gateway.Example.Test/", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		origin := origin
		t.Run("valid origin "+origin, func(t *testing.T) {
			t.Parallel()
			if _, err := New(Config{Coordinator: coordinator, FeatureQuotas: quotas, JWKS: keys, PublicOrigin: origin}); err != nil {
				t.Fatalf("New() error = %v", err)
			}
		})
	}
}

func TestHandlerRejectsClientHintWithoutServerLogicalIdentity(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
	api, err := New(Config{
		Coordinator:   coordinator,
		FeatureQuotas: &fakeFeatureQuotaProvider{},
		JWKS:          &fakeJWKSProvider{result: validJWKS()},
		PublicOrigin:  "https://gateway.example.test",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3")
	request.Header.Set("X-Latchway-Request-ID", logicalLookingHint)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)

	assertProblem(t, response, "server_not_ready", http.StatusServiceUnavailable)
	if got := response.Header().Get("X-Latchway-Request-ID"); got != logicalLookingHint {
		t.Fatalf("correlation hint = %q, want %q", got, logicalLookingHint)
	}
	if len(coordinator.challengeInputs) != 0 {
		t.Fatalf("coordinator ran without server logical identity: %#v", coordinator.challengeInputs)
	}
}

func TestCreateChallengeUsesCanonicalOriginAndExactWireShape(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://Gateway.Example.Test/")
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3")
	request.Host = "attacker.invalid"
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Request-ID", validRequestIDText)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertSuccessHeaders(t, response, "no-store")
	if response.Header().Get("X-Latchway-Request-ID") != validRequestIDText {
		t.Fatalf("request ID = %q", response.Header().Get("X-Latchway-Request-ID"))
	}
	if len(coordinator.challengeInputs) != 1 {
		t.Fatalf("challenge calls = %d", len(coordinator.challengeInputs))
	}
	input := coordinator.challengeInputs[0]
	if input.ApplicationID != "app_public" || input.Environment != "production" || input.IdentityProvider != "firebase" || input.IdentityToken.Reveal() != "identity-token-123" || input.Platform != "ios" {
		t.Fatalf("unexpected challenge input: %#v", input)
	}
	if err := id.Validate(input.Metadata.RequestID, id.LogicalRequest); err != nil {
		t.Fatalf("metadata logical request ID is not canonical: %v", err)
	}
	if input.Metadata.RequestID == validRequestIDText || input.Metadata.SDK != "ios" || input.Metadata.SDKVersion != "1.2.3" || input.Metadata.HTTPMethod != http.MethodPost || input.Metadata.DPoPProof.Reveal() != validProof {
		t.Fatalf("unexpected request metadata: %#v", input.Metadata)
	}
	if target := input.Metadata.TargetURL.String(); target != "https://gateway.example.test"+challengePath {
		t.Fatalf("target URL = %q", target)
	}
	if strings.Contains(response.Body.String(), "identity-token-123") || strings.Contains(response.Body.String(), "attacker.invalid") {
		t.Fatalf("response leaked request data: %s", response.Body.String())
	}
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document, "challenge_id", "challenge_nonce", "binding_version", "issued_at", "expires_at", "attestation")
	attestation, ok := document["attestation"].(map[string]any)
	if !ok {
		t.Fatalf("attestation document = %#v", document["attestation"])
	}
	assertExactKeys(t, attestation, "provider", "mode", "client_data_hash", "provider_options")
	if attestation["provider"] != "debug" || attestation["mode"] != "required" {
		t.Fatalf("attestation document = %#v", attestation)
	}
}

func TestBrowserOriginIsCanonicalPropagatedAndCORSIsCredentialless(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{challengeResult: validChallengeResult()}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("web"), "javascript", "1.2.3")
	request.Header.Set("Origin", "https://app.example.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || len(coordinator.challengeInputs) != 1 {
		t.Fatalf("web challenge status=%d body=%s calls=%d", response.Code, response.Body.String(), len(coordinator.challengeInputs))
	}
	if coordinator.challengeInputs[0].Metadata.Origin != "https://app.example.test" {
		t.Fatalf("origin metadata = %q", coordinator.challengeInputs[0].Metadata.Origin)
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "https://app.example.test" ||
		response.Header().Get("Access-Control-Allow-Credentials") != "" ||
		!strings.Contains(response.Header().Get("Access-Control-Expose-Headers"), "DPoP-Nonce") {
		t.Fatalf("CORS response headers = %#v", response.Header())
	}

	for _, test := range []struct {
		name     string
		platform string
		sdk      string
		origin   string
	}{
		{name: "web missing origin", platform: "web", sdk: "javascript"},
		{name: "web noncanonical origin", platform: "web", sdk: "javascript", origin: "https://App.example.test"},
		{name: "native origin", platform: "ios", sdk: "ios", origin: "https://app.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolated := &fakeCoordinator{challengeResult: validChallengeResult()}
			request := validClientRequest(http.MethodPost, challengePath, validChallengeBody(test.platform), test.sdk, "1.2.3")
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			newTestHandler(t, isolated, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test").ServeHTTP(response, request)
			assertProblem(t, response, "request_invalid", http.StatusBadRequest)
			if len(isolated.challengeInputs) != 0 {
				t.Fatal("invalid Origin reached the coordinator")
			}
		})
	}
}

func TestClientCORSPreflightIsBoundedAndDoesNotAuthorize(t *testing.T) {
	t.Parallel()
	coordinator := &fakeCoordinator{}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	request := httptest.NewRequest(http.MethodOptions, challengePath, nil)
	request.Header.Set("Origin", "https://app.example.test")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "content-type, dpop, x-latchway-sdk")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Access-Control-Allow-Origin") != "https://app.example.test" ||
		response.Header().Get("Access-Control-Allow-Methods") != http.MethodPost ||
		response.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("preflight status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if len(coordinator.challengeInputs) != 0 {
		t.Fatal("preflight invoked the coordinator")
	}

	unsafe := httptest.NewRequest(http.MethodOptions, challengePath, nil)
	unsafe.Header.Set("Origin", "https://app.example.test")
	unsafe.Header.Set("Access-Control-Request-Method", http.MethodPost)
	unsafe.Header.Set("Access-Control-Request-Headers", "cookie")
	unsafeResponse := httptest.NewRecorder()
	handler.ServeHTTP(unsafeResponse, unsafe)
	assertProblem(t, unsafeResponse, "request_invalid", http.StatusBadRequest)
}

func TestExchangeAndRefreshUseExactRequestAndResponseShapes(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{exchangeResult: validGrantResult("ios"), refreshResult: validGrantResult("ios")}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	exchangeRequest := validClientRequest(http.MethodPost, exchangePath, `{
		"challenge_id":"`+validChallengeID+`",
		"attestation":{"provider":"debug","evidence":{"key_id":"safe-public-id","signature":"opaque-sensitive-evidence"}},
		"installation":{"app_version":"42.1","os_version":"27.0","device_model":"Phone"}
	}`, "ios", "1.2.3")
	exchangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(exchangeResponse, exchangeRequest)

	if exchangeResponse.Code != http.StatusCreated {
		t.Fatalf("exchange status = %d, body = %s", exchangeResponse.Code, exchangeResponse.Body.String())
	}
	assertSuccessHeaders(t, exchangeResponse, "no-store")
	if len(coordinator.exchangeInputs) != 1 {
		t.Fatalf("exchange calls = %d", len(coordinator.exchangeInputs))
	}
	exchangeInput := coordinator.exchangeInputs[0]
	if exchangeInput.Metadata.TargetURL.String() != "https://gateway.example.test"+exchangePath || exchangeInput.ChallengeID != validChallengeID || exchangeInput.Attestation.Provider != "debug" || exchangeInput.Installation.AppVersion != "42.1" || exchangeInput.Installation.OSVersion != "27.0" || exchangeInput.Installation.DeviceModel != "Phone" {
		t.Fatalf("unexpected exchange input: %#v", exchangeInput)
	}
	evidence, err := exchangeInput.Attestation.Payload.Object()
	if err != nil || evidence["key_id"] != "safe-public-id" || evidence["signature"] != "opaque-sensitive-evidence" {
		t.Fatalf("evidence = %#v, err = %v", evidence, err)
	}
	assertGrantDocument(t, exchangeResponse)

	refreshRequest := validClientRequest(http.MethodPost, refreshPath, `{
		"refresh_token":"`+strings.Repeat("r", 48)+`",
		"identity_token":"fresh-identity-token-123",
		"attestation":{"provider":"debug","evidence":{"assertion":"opaque-refresh-evidence"}}
	}`, "ios", "1.2.3")
	refreshResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshResponse, refreshRequest)

	if refreshResponse.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", refreshResponse.Code, refreshResponse.Body.String())
	}
	assertSuccessHeaders(t, refreshResponse, "no-store")
	if len(coordinator.refreshInputs) != 1 {
		t.Fatalf("refresh calls = %d", len(coordinator.refreshInputs))
	}
	refreshInput := coordinator.refreshInputs[0]
	if refreshInput.Metadata.TargetURL.String() != "https://gateway.example.test"+refreshPath || refreshInput.RefreshToken.Reveal() != strings.Repeat("r", 48) || !refreshInput.HasIdentityToken || refreshInput.IdentityToken.Reveal() != "fresh-identity-token-123" || refreshInput.Attestation == nil || refreshInput.Attestation.Provider != "debug" {
		t.Fatalf("unexpected refresh input: %#v", refreshInput)
	}
	assertGrantDocument(t, refreshResponse)
}

func TestOptionalRefreshFeatureIsRejectedByCoordinatorWithoutFakeSuccess(t *testing.T) {
	t.Parallel()

	coordinator := &fakeCoordinator{
		refreshResult: validGrantResult("ios"),
		refreshErr:    &DependencyError{Code: "attestation_unsupported"},
	}
	handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	request := validClientRequest(http.MethodPost, refreshPath, `{
		"refresh_token":"`+strings.Repeat("sensitive-refresh-", 3)+`",
		"attestation":{"provider":"app_attest","evidence":{"secret":"must-not-leak"}}
	}`, "ios", "1.2.3")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertProblem(t, response, "attestation_unsupported", http.StatusBadRequest)
	if strings.Contains(response.Body.String(), "must-not-leak") || strings.Contains(response.Body.String(), "sensitive-refresh") || strings.Contains(response.Body.String(), "access-token") {
		t.Fatalf("failure response leaked or faked credentials: %s", response.Body.String())
	}
}

func TestPublicJWKSIsPublicCacheableAndBodyless(t *testing.T) {
	t.Parallel()

	keys := &fakeJWKSProvider{result: validJWKS()}
	handler := newTestHandler(t, &fakeCoordinator{}, keys, "https://gateway.example.test")
	request := httptest.NewRequest(http.MethodGet, jwksPath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertSuccessHeaders(t, response, "public, max-age=300")
	if keys.calls != 1 {
		t.Fatalf("JWKS calls = %d", keys.calls)
	}
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document, "keys")
	items, ok := document["keys"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("keys = %#v", document["keys"])
	}
	key, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("key = %#v", items[0])
	}
	assertExactKeys(t, key, "kty", "crv", "x", "y", "kid", "use", "alg")
	for _, forbidden := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "jku", "x5u"} {
		if _, exists := key[forbidden]; exists {
			t.Fatalf("JWKS exposed forbidden member %q", forbidden)
		}
	}

	bodyRequest := httptest.NewRequest(http.MethodGet, jwksPath, strings.NewReader(`{}`))
	bodyResponse := httptest.NewRecorder()
	handler.ServeHTTP(bodyResponse, bodyRequest)
	assertProblem(t, bodyResponse, "request_invalid", http.StatusBadRequest)
	if keys.calls != 1 {
		t.Fatal("JWKS provider was called for a request with a body")
	}

	headRequest := httptest.NewRequest(http.MethodHead, jwksPath, nil)
	headResponse := httptest.NewRecorder()
	handler.ServeHTTP(headResponse, headRequest)
	assertProblem(t, headResponse, "request_invalid", http.StatusBadRequest)
}

func TestPublicDiscoveryUsesLockedWireShape(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, &fakeCoordinator{}, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, discoveryPath, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertSuccessHeaders(t, response, "public, max-age=300")
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document,
		"server_version", "contract_version", "supported_protocol_versions",
		"session_endpoint", "dpop_algorithms", "maximum_clock_skew_seconds",
	)
	if document["contract_version"] != "0.5.0" || document["session_endpoint"] != exchangePath || document["maximum_clock_skew_seconds"] != float64(300) {
		t.Fatalf("discovery document = %#v", document)
	}
	versions, ok := document["supported_protocol_versions"].([]any)
	if !ok || len(versions) != 1 || versions[0] != float64(1) {
		t.Fatalf("supported versions = %#v", document["supported_protocol_versions"])
	}
	algorithms, ok := document["dpop_algorithms"].([]any)
	if !ok || len(algorithms) != 1 || algorithms[0] != "ES256" {
		t.Fatalf("DPoP algorithms = %#v", document["dpop_algorithms"])
	}

	bodyResponse := httptest.NewRecorder()
	handler.ServeHTTP(bodyResponse, httptest.NewRequest(http.MethodGet, discoveryPath, strings.NewReader(`{}`)))
	assertProblem(t, bodyResponse, "request_invalid", http.StatusBadRequest)
}

type failingResponseWriter struct {
	header      http.Header
	statuses    []int
	writeCalls  int
	writeResult int
	writeErr    error
}

func (writer *failingResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *failingResponseWriter) WriteHeader(status int) {
	writer.statuses = append(writer.statuses, status)
}

func (writer *failingResponseWriter) Write([]byte) (int, error) {
	writer.writeCalls++
	return writer.writeResult, writer.writeErr
}

func TestCommittedSuccessWriteFailureDoesNotAppendProblem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		request     func() *http.Request
		coordinator *fakeCoordinator
		wantStatus  int
		wantCache   string
	}{
		{
			name: "challenge",
			request: func() *http.Request {
				return validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3")
			},
			coordinator: &fakeCoordinator{challengeResult: validChallengeResult()},
			wantStatus:  http.StatusCreated,
			wantCache:   "no-store",
		},
		{
			name: "JWKS",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, jwksPath, nil)
			},
			coordinator: &fakeCoordinator{},
			wantStatus:  http.StatusOK,
			wantCache:   "public, max-age=300",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, test.coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			writer := &failingResponseWriter{writeErr: io.ErrClosedPipe}
			handler.ServeHTTP(writer, test.request())
			if len(writer.statuses) != 1 || writer.statuses[0] != test.wantStatus {
				t.Fatalf("written statuses = %v, want only %d", writer.statuses, test.wantStatus)
			}
			if writer.writeCalls != 1 {
				t.Fatalf("write calls = %d, want 1", writer.writeCalls)
			}
			if got := writer.Header().Get("Cache-Control"); got != test.wantCache {
				t.Fatalf("Cache-Control = %q, want %q", got, test.wantCache)
			}
		})
	}
}

func TestJWKSFailuresAreRedactedAndFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		keys   *fakeJWKSProvider
		status int
		code   string
	}{
		{name: "provider unavailable", keys: &fakeJWKSProvider{err: errors.New("database secret signing material")}, status: http.StatusServiceUnavailable, code: "server_not_ready"},
		{name: "empty key set", keys: &fakeJWKSProvider{result: JWKS{}}, status: http.StatusInternalServerError, code: "internal_error"},
		{name: "invalid key", keys: &fakeJWKSProvider{result: JWKS{Keys: []PublicJWK{{Kty: "oct", Kid: "private-secret", Use: "sig", Alg: "HS256"}}}}, status: http.StatusInternalServerError, code: "internal_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, &fakeCoordinator{}, test.keys, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, jwksPath, nil))
			assertProblem(t, response, test.code, test.status)
			if strings.Contains(response.Body.String(), "database secret") || strings.Contains(response.Body.String(), "private-secret") {
				t.Fatalf("response leaked provider failure: %s", response.Body.String())
			}
		})
	}
}

func TestDependencyProblemMappingIsStableAndRedacted(t *testing.T) {
	t.Parallel()

	codes := []string{
		"request_invalid", "identity_token_missing", "identity_token_invalid", "identity_token_expired", "identity_reauthentication_required",
		"attestation_required", "attestation_unsupported", "attestation_invalid", "attestation_stale", "attestation_step_up_required",
		"dpop_missing", "dpop_invalid", "dpop_replayed", "session_expired", "session_revoked", "refresh_token_reused",
		"installation_revoked", "server_not_ready", "protocol_version_unsupported", "conflict", "internal_error",
	}
	for _, code := range codes {
		code := code
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			retryAfter := 0
			if code == "session_expired" || code == "server_not_ready" {
				retryAfter = 7
			}
			coordinator := &fakeCoordinator{challengeErr: fmt.Errorf("raw-secret-token: %w", &DependencyError{Code: code, RetryAfterSeconds: retryAfter})}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3"))
			definition := problemDefinition(t, code)
			assertProblem(t, response, code, definition)
			wantRetryAfter := ""
			if retryAfter > 0 {
				wantRetryAfter = "7"
			}
			if response.Header().Get("Retry-After") != wantRetryAfter {
				t.Fatalf("Retry-After = %q, want %q", response.Header().Get("Retry-After"), wantRetryAfter)
			}
			if strings.Contains(response.Body.String(), "raw-secret-token") {
				t.Fatalf("response leaked wrapped dependency error: %s", response.Body.String())
			}
		})
	}

	t.Run("nonce challenge", func(t *testing.T) {
		t.Parallel()
		nonce := strings.Repeat("n", 24)
		coordinator := &fakeCoordinator{challengeErr: &DependencyError{Code: "dpop_nonce_required", DPoPNonce: nonce}}
		handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3"))
		assertProblem(t, response, "dpop_nonce_required", http.StatusUnauthorized)
		if response.Header().Get("DPoP-Nonce") != nonce {
			t.Fatalf("DPoP-Nonce = %q", response.Header().Get("DPoP-Nonce"))
		}
		var document map[string]any
		decodeJSONResponse(t, response, &document)
		if document["detail"] != "A fresh server DPoP nonce is required." {
			t.Fatalf("DPoP nonce detail = %#v", document["detail"])
		}
	})

	invalidFailures := []error{
		errors.New("raw database error containing super-secret"),
		&DependencyError{Code: "feature_not_found"},
		&DependencyError{Code: "dpop_nonce_required"},
		&DependencyError{Code: "dpop_nonce_required", DPoPNonce: "short"},
		&DependencyError{Code: "dpop_invalid", DPoPNonce: strings.Repeat("n", 24)},
		&DependencyError{Code: "identity_token_invalid", RetryAfterSeconds: 1},
		&DependencyError{Code: "server_not_ready", RetryAfterSeconds: 86401},
	}
	for index, failure := range invalidFailures {
		failure := failure
		t.Run(fmt.Sprintf("invalid dependency failure %d", index), func(t *testing.T) {
			t.Parallel()
			coordinator := &fakeCoordinator{challengeErr: failure}
			handler := newTestHandler(t, coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "ios", "1.2.3"))
			assertProblem(t, response, "internal_error", http.StatusInternalServerError)
			if strings.Contains(response.Body.String(), "super-secret") || strings.Contains(response.Body.String(), "feature_not_found") {
				t.Fatalf("response leaked invalid dependency error: %s", response.Body.String())
			}
		})
	}
}

func TestInvalidDependencyResultsNeverProduceSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		coordinator *fakeCoordinator
		path        string
		body        string
	}{
		{name: "empty challenge", coordinator: &fakeCoordinator{}, path: challengePath, body: validChallengeBody("ios")},
		{name: "unencodable provider options", coordinator: &fakeCoordinator{challengeResult: func() ChallengeResult {
			result := validChallengeResult()
			result.Attestation.ProviderOptions = map[string]any{"unsafe": func() {}}
			return result
		}()}, path: challengePath, body: validChallengeBody("ios")},
		{name: "short access token", coordinator: &fakeCoordinator{exchangeResult: func() GrantResult {
			result := validGrantResult("ios")
			result.AccessToken = NewSensitiveString("short")
			return result
		}()}, path: exchangePath, body: validExchangeBody()},
		{name: "SDK platform mismatch", coordinator: &fakeCoordinator{exchangeResult: validGrantResult("android")}, path: exchangePath, body: validExchangeBody()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, test.coordinator, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validClientRequest(http.MethodPost, test.path, test.body, "ios", "1.2.3"))
			assertProblem(t, response, "internal_error", http.StatusInternalServerError)
			if strings.Contains(response.Body.String(), "access-token") || strings.Contains(response.Body.String(), "refresh-token") {
				t.Fatalf("invalid result produced credentials: %s", response.Body.String())
			}
		})
	}
}

func TestSensitiveValuesAndEvidenceAreOpaqueAndDefensivelyCopied(t *testing.T) {
	t.Parallel()

	secret := "credential-that-must-never-format"
	value := NewSensitiveString(secret)
	assertOpaqueFormatting(t, secret, value, &value)

	payload, err := newEvidencePayload(map[string]any{"secret": secret, "nested": map[string]any{"value": "original"}})
	if err != nil {
		t.Fatalf("newEvidencePayload() error = %v", err)
	}
	assertOpaqueFormatting(t, secret, payload, &payload)
	first, err := payload.Object()
	if err != nil {
		t.Fatalf("Object() error = %v", err)
	}
	first["secret"] = "mutated"
	nested := first["nested"].(map[string]any)
	nested["value"] = "mutated"
	second, err := payload.Object()
	if err != nil {
		t.Fatalf("Object() second error = %v", err)
	}
	if second["secret"] != secret || second["nested"].(map[string]any)["value"] != "original" {
		t.Fatalf("evidence defensive copy was mutated: %#v", second)
	}
}

func newTestHandler(t *testing.T, coordinator Coordinator, keys JWKSProvider, origin string) http.Handler {
	return newTestHandlerWithFeatureQuotas(t, coordinator, &fakeFeatureQuotaProvider{}, keys, origin)
}

func newTestHandlerWithFeatureQuotas(t *testing.T, coordinator Coordinator, quotas FeatureQuotaProvider, keys JWKSProvider, origin string) http.Handler {
	t.Helper()
	api, err := New(Config{Coordinator: coordinator, FeatureQuotas: quotas, JWKS: keys, PublicOrigin: origin})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := requestidentity.NewContext(r.Context())
		if err != nil {
			t.Errorf("requestidentity.NewContext() error = %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		api.Handler().ServeHTTP(w, r.WithContext(ctx))
	})
}

func validClientRequest(method, path, body, sdk, version string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", sdk)
	request.Header.Set("X-Latchway-SDK-Version", version)
	request.Header.Set("DPoP", validProof)
	return request
}

func validChallengeBody(platform string) string {
	return `{"application_id":"app_public","environment":"production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"` + platform + `","sdk_version":"1.2.3"}`
}

func validExchangeBody() string {
	return `{"challenge_id":"` + validChallengeID + `","attestation":{"provider":"debug","evidence":{}},"installation":{"app_version":"1.0"}}`
}

func validChallengeResult() ChallengeResult {
	digest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	return ChallengeResult{
		ChallengeID: validChallengeID, ChallengeNonce: digest, BindingVersion: 1,
		IssuedAt: testInstant.Unix(), ExpiresAt: testInstant.Add(5 * time.Minute),
		Attestation: AttestationRequirement{
			Provider: "debug", Mode: "required", ClientDataHash: digest,
			ProviderOptions: map[string]any{"key_id": "public-debug-key"},
		},
	}
}

func validGrantResult(platform string) GrantResult {
	digest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	return GrantResult{
		AccessToken: NewSensitiveString(strings.Repeat("access-token-", 8)), ExpiresIn: 600,
		RefreshToken: NewSensitiveString(strings.Repeat("refresh-token-", 3)), RefreshExpiresIn: 86400,
		Installation: InstallationSummary{ID: validInstallation, Platform: platform, DPoPJKT: digest, Status: "active"},
		Trust:        TrustSummary{Provider: "debug", Level: "debug", VerifiedAt: testInstant, ExpiresAt: testInstant.Add(time.Hour)},
	}
}

func validJWKS() JWKS {
	curve := elliptic.P256()
	return JWKS{Keys: []PublicJWK{{
		Kty: "EC", Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(curve.Params().Gx.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(curve.Params().Gy.FillBytes(make([]byte, 32))),
		Kid: "gsk_public_test_key", Use: "sig", Alg: "ES256",
	}}}
}

func assertSuccessHeaders(t *testing.T, response *httptest.ResponseRecorder, cacheControl string) {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
	if response.Header().Get("Cache-Control") != cacheControl {
		t.Fatalf("Cache-Control = %q, want %q", response.Header().Get("Cache-Control"), cacheControl)
	}
	if response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatal("response omitted X-Latchway-Request-ID")
	}
	if response.Header().Get("Content-Length") != fmt.Sprintf("%d", response.Body.Len()) {
		t.Fatalf("Content-Length = %q, body bytes = %d", response.Header().Get("Content-Length"), response.Body.Len())
	}
}

func assertGrantDocument(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document, "access_token", "token_type", "expires_in", "refresh_token", "refresh_expires_in", "installation", "trust")
	if document["token_type"] != "DPoP" {
		t.Fatalf("token_type = %#v", document["token_type"])
	}
	installation := document["installation"].(map[string]any)
	assertExactKeys(t, installation, "id", "platform", "dpop_jkt", "status")
	trust := document["trust"].(map[string]any)
	assertExactKeys(t, trust, "provider", "level", "verified_at", "expires_at")
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, code string, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, status, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("problem headers = %#v", response.Header())
	}
	if response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatal("problem omitted request ID header")
	}
	var document map[string]any
	decodeJSONResponse(t, response, &document)
	if document["code"] != code || int(document["status"].(float64)) != status || document["request_id"] != response.Header().Get("X-Latchway-Request-ID") {
		t.Fatalf("problem document = %#v", document)
	}
	if strings.Contains(response.Body.String(), `"code":""`) {
		t.Fatalf("client field error emitted an undeclared code member: %s", response.Body.String())
	}
}

func problemDefinition(t *testing.T, code string) int {
	t.Helper()
	statuses := map[string]int{
		"request_invalid": http.StatusBadRequest, "identity_token_missing": http.StatusUnauthorized,
		"identity_token_invalid": http.StatusUnauthorized, "identity_token_expired": http.StatusUnauthorized,
		"identity_reauthentication_required": http.StatusUnauthorized, "attestation_required": http.StatusUnauthorized,
		"attestation_unsupported": http.StatusBadRequest, "attestation_invalid": http.StatusUnauthorized,
		"attestation_stale": http.StatusUnauthorized, "attestation_step_up_required": http.StatusUnauthorized,
		"dpop_missing": http.StatusUnauthorized, "dpop_invalid": http.StatusUnauthorized, "dpop_replayed": http.StatusUnauthorized,
		"session_expired": http.StatusUnauthorized, "session_revoked": http.StatusUnauthorized,
		"refresh_token_reused": http.StatusUnauthorized, "installation_revoked": http.StatusForbidden,
		"server_not_ready": http.StatusServiceUnavailable, "protocol_version_unsupported": http.StatusUpgradeRequired,
		"conflict": http.StatusConflict, "internal_error": http.StatusInternalServerError,
	}
	status, exists := statuses[code]
	if !exists {
		t.Fatalf("test status missing for code %q", code)
	}
	return status
}

func decodeJSONResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(response.Body.String()))
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode response error = %v, body = %s", err, response.Body.String())
	}
}

func assertExactKeys(t *testing.T, object map[string]any, expected ...string) {
	t.Helper()
	if len(object) != len(expected) {
		t.Fatalf("object keys = %#v, want %v", object, expected)
	}
	for _, key := range expected {
		if _, exists := object[key]; !exists {
			t.Fatalf("object omitted %q: %#v", key, object)
		}
	}
}

func assertOpaqueFormatting(t *testing.T, secret string, values ...any) {
	t.Helper()
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%p"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, secret) {
				t.Fatalf("format %q leaked secret: %s", format, formatted)
			}
		}
	}
}
