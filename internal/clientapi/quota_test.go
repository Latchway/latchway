package clientapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

const validQuotaAccessToken = "quota.headerheaderheaderheader.payloadpayloadpayloadpayload.signaturesignaturesignature"

func TestFeatureQuotaUsesCanonicalAuthenticatedInputAndExactSafeWireShape(t *testing.T) {
	t.Parallel()

	maximum := int64(100)
	used := int64(25)
	reserved := int64(5)
	remaining := int64(70)
	unsafe := maximumSafeJSONInteger + 1
	reset := testInstant.Add(12 * time.Hour)
	provider := &fakeFeatureQuotaProvider{result: FeatureQuotaResult{
		Feature: "assistant", ObservedAt: testInstant,
		Limits: []FeatureQuotaLimit{
			{
				Metric: "logical_requests", Maximum: &maximum, Used: &used,
				Reserved: &reserved, Remaining: &remaining, ResetsAt: &reset, Hard: true,
			},
			{
				Metric: "output_tokens", Maximum: &unsafe, Used: &unsafe,
				Reserved: &unsafe, Remaining: &unsafe, Hard: true,
			},
			{Metric: "concurrent_streams", Hard: true},
		},
	}}
	handler := newTestHandlerWithFeatureQuotas(
		t, &fakeCoordinator{}, provider, &fakeJWKSProvider{result: validJWKS()}, "https://Gateway.Example.Test/",
	)
	request := validFeatureQuotaRequest("assistant")
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
	if len(provider.inputs) != 1 {
		t.Fatalf("feature quota calls = %d", len(provider.inputs))
	}
	input := provider.inputs[0]
	if err := id.Validate(input.LogicalRequestID.String(), id.LogicalRequest); err != nil {
		t.Fatalf("opaque logical request ID is not canonical: %v", err)
	}
	if input.LogicalRequestID.String() != input.Metadata.RequestID || input.LogicalRequestID.String() == logicalLookingHint ||
		input.Feature != "assistant" || input.AccessToken.Reveal() != validQuotaAccessToken ||
		input.Metadata.SDK != "ios" || input.Metadata.SDKVersion != "1.2.3" || input.Metadata.HTTPMethod != http.MethodGet ||
		input.Metadata.DPoPProof.Reveal() != validProof || input.Metadata.TargetURL.String() != "https://gateway.example.test/client/v1/features/assistant/quota" {
		t.Fatalf("unexpected feature quota input: %#v", input)
	}
	formatted := fmt.Sprintf("%#v", input)
	if strings.Contains(formatted, validQuotaAccessToken) || strings.Contains(formatted, validProof) {
		t.Fatalf("feature quota input formatting exposed credentials: %s", formatted)
	}

	var document map[string]any
	decodeJSONResponse(t, response, &document)
	assertExactKeys(t, document, "feature", "observed_at", "limits")
	if document["feature"] != "assistant" || document["observed_at"] != testInstant.Format(time.RFC3339) {
		t.Fatalf("quota snapshot identity = %#v", document)
	}
	limits, ok := document["limits"].([]any)
	if !ok || len(limits) != 3 {
		t.Fatalf("limits = %#v", document["limits"])
	}
	first := limits[0].(map[string]any)
	assertExactKeys(t, first, "metric", "maximum", "used", "reserved", "remaining", "resets_at", "hard")
	if first["metric"] != "logical_requests" || first["maximum"] != float64(100) || first["used"] != float64(25) ||
		first["reserved"] != float64(5) || first["remaining"] != float64(70) || first["resets_at"] != reset.Format(time.RFC3339) || first["hard"] != true {
		t.Fatalf("safe quota limit = %#v", first)
	}
	unsafeLimit := limits[1].(map[string]any)
	assertExactKeys(t, unsafeLimit, "metric", "hard")
	if unsafeLimit["metric"] != "output_tokens" || unsafeLimit["hard"] != true {
		t.Fatalf("unsafe quota projection = %#v", unsafeLimit)
	}
	nilLimit := limits[2].(map[string]any)
	assertExactKeys(t, nilLimit, "metric", "hard")
	if strings.Contains(response.Body.String(), validQuotaAccessToken) || strings.Contains(response.Body.String(), validProof) || strings.Contains(response.Body.String(), "attacker.invalid") {
		t.Fatalf("quota response leaked transport input: %s", response.Body.String())
	}
}

func TestFeatureQuotaPathIsExactAndCanonical(t *testing.T) {
	t.Parallel()

	maximumFeature := "a" + strings.Repeat("b", 62)
	valid := []string{"a", "assistant", "assistant_v2-beta", maximumFeature}
	for _, feature := range valid {
		path := featureQuotaPrefix + feature + featureQuotaSuffix
		got, ok := featureFromQuotaPath(path)
		if !ok || got != feature {
			t.Fatalf("featureFromQuotaPath(%q) = %q, %t", path, got, ok)
		}
	}
	invalid := []string{
		"", featureQuotaPrefix + featureQuotaSuffix, featureQuotaPrefix + "Assistant" + featureQuotaSuffix,
		featureQuotaPrefix + "1assistant" + featureQuotaSuffix, featureQuotaPrefix + "assistant/v2" + featureQuotaSuffix,
		featureQuotaPrefix + "assistant" + featureQuotaSuffix + "/", featureQuotaPrefix + "assistant",
		featureQuotaPrefix + "a" + strings.Repeat("b", 63) + featureQuotaSuffix,
		featureQuotaPrefix + "assistánt" + featureQuotaSuffix,
	}
	for _, path := range invalid {
		if feature, ok := featureFromQuotaPath(path); ok {
			t.Fatalf("featureFromQuotaPath(%q) accepted %q", path, feature)
		}
	}
}

func TestFeatureQuotaRejectsCorrelationHintWithoutServerLogicalIdentity(t *testing.T) {
	t.Parallel()

	provider := &fakeFeatureQuotaProvider{result: validFeatureQuotaResult("assistant")}
	api, err := New(Config{
		Coordinator: &fakeCoordinator{}, FeatureQuotas: provider,
		JWKS: &fakeJWKSProvider{result: validJWKS()}, PublicOrigin: "https://gateway.example.test",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validFeatureQuotaRequest("assistant")
	request.Header.Set("X-Latchway-Request-ID", logicalLookingHint)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)

	assertProblem(t, response, "server_not_ready", http.StatusServiceUnavailable)
	if response.Header().Get("X-Latchway-Request-ID") != logicalLookingHint {
		t.Fatalf("correlation hint = %q", response.Header().Get("X-Latchway-Request-ID"))
	}
	if len(provider.inputs) != 0 {
		t.Fatalf("provider ran without logical identity: %#v", provider.inputs)
	}
}

func TestFeatureQuotaRejectsInvalidRouteQueryMethodAndTransportBeforeProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
		wantPath   string
	}{
		{name: "wrong method", mutate: func(r *http.Request) { r.Method = http.MethodPost }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "empty feature", mutate: func(r *http.Request) { r.URL.Path = featureQuotaPrefix + featureQuotaSuffix }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "uppercase feature", mutate: func(r *http.Request) { r.URL.Path = featureQuotaPrefix + "Assistant" + featureQuotaSuffix }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "nested feature", mutate: func(r *http.Request) { r.URL.Path = featureQuotaPrefix + "assistant/v2" + featureQuotaSuffix }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "trailing slash", mutate: func(r *http.Request) { r.URL.Path += "/" }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "encoded path", mutate: func(r *http.Request) { r.URL.RawPath = featureQuotaPrefix + "%61ssistant" + featureQuotaSuffix }, wantCode: "resource_not_found", wantStatus: http.StatusNotFound},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "token=must-not-echo" }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "query"},
		{name: "empty query marker", mutate: func(r *http.Request) { r.URL.ForceQuery = true }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "query"},
		{name: "missing protocol", mutate: func(r *http.Request) { r.Header.Del("X-Latchway-Protocol-Version") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "duplicate protocol", mutate: func(r *http.Request) { r.Header.Add("X-Latchway-Protocol-Version", "1") }, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "invalid SDK", mutate: func(r *http.Request) { r.Header.Set("X-Latchway-SDK", "swift") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.X-Latchway-SDK"},
		{name: "invalid SDK version", mutate: func(r *http.Request) { r.Header.Set("X-Latchway-SDK-Version", "latest") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.X-Latchway-SDK-Version"},
		{name: "missing authorization", mutate: func(r *http.Request) { r.Header.Del("Authorization") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "duplicate authorization", mutate: func(r *http.Request) { r.Header.Add("Authorization", "DPoP "+validQuotaAccessToken) }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "wrong authorization scheme", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+validQuotaAccessToken) }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "short access token", mutate: func(r *http.Request) { r.Header.Set("Authorization", "DPoP short") }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "header.Authorization"},
		{name: "missing proof", mutate: func(r *http.Request) { r.Header.Del("DPoP") }, wantCode: "dpop_missing", wantStatus: http.StatusUnauthorized},
		{name: "duplicate proof", mutate: func(r *http.Request) { r.Header.Add("DPoP", validProof) }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "malformed proof", mutate: func(r *http.Request) { r.Header.Set("DPoP", "not-a-compact-proof") }, wantCode: "dpop_invalid", wantStatus: http.StatusUnauthorized},
		{name: "body", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"secret":"must-not-echo"}`))
			r.ContentLength = int64(len(`{"secret":"must-not-echo"}`))
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "body"},
		{name: "declared body", mutate: func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "body"},
		{name: "chunked body", mutate: func(r *http.Request) { r.Body = http.NoBody; r.TransferEncoding = []string{"chunked"} }, wantCode: "request_invalid", wantStatus: http.StatusBadRequest, wantPath: "body"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provider := &fakeFeatureQuotaProvider{result: validFeatureQuotaResult("assistant")}
			handler := newTestHandlerWithFeatureQuotas(
				t, &fakeCoordinator{}, provider, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test",
			)
			request := validFeatureQuotaRequest("assistant")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assertProblem(t, response, test.wantCode, test.wantStatus)
			if len(provider.inputs) != 0 {
				t.Fatalf("provider called for rejected request: %#v", provider.inputs)
			}
			if strings.Contains(response.Body.String(), validQuotaAccessToken) || strings.Contains(response.Body.String(), validProof) || strings.Contains(response.Body.String(), "must-not-echo") {
				t.Fatalf("problem leaked rejected transport input: %s", response.Body.String())
			}
			assertProblemErrorsMatchContract(t, response)
			if test.wantPath != "" {
				assertSingleProblemPath(t, response, test.wantPath)
			}
		})
	}
}

func TestFeatureQuotaValidationOrderIsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
	}{
		{name: "method before declarations", mutate: func(r *http.Request) {
			r.Method = http.MethodPost
			r.Header.Del("X-Latchway-Protocol-Version")
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "declarations before authorization", mutate: func(r *http.Request) {
			r.Header.Del("X-Latchway-Protocol-Version")
			r.Header.Del("Authorization")
		}, wantCode: "protocol_version_unsupported", wantStatus: http.StatusUpgradeRequired},
		{name: "authorization before proof", mutate: func(r *http.Request) {
			r.Header.Del("Authorization")
			r.Header.Del("DPoP")
		}, wantCode: "request_invalid", wantStatus: http.StatusBadRequest},
		{name: "proof before body", mutate: func(r *http.Request) {
			r.Header.Del("DPoP")
			r.Body = io.NopCloser(strings.NewReader("secret"))
			r.ContentLength = 6
		}, wantCode: "dpop_missing", wantStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provider := &fakeFeatureQuotaProvider{result: validFeatureQuotaResult("assistant")}
			handler := newTestHandlerWithFeatureQuotas(
				t, &fakeCoordinator{}, provider, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test",
			)
			request := validFeatureQuotaRequest("assistant")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertProblem(t, response, test.wantCode, test.wantStatus)
			if len(provider.inputs) != 0 {
				t.Fatal("provider ran before transport validation completed")
			}
		})
	}
}

func TestFeatureQuotaRejectsInvalidProviderResults(t *testing.T) {
	t.Parallel()

	nonUTC := time.FixedZone("not-utc", 0)
	tests := []struct {
		name   string
		mutate func(*FeatureQuotaResult)
	}{
		{name: "feature mismatch", mutate: func(result *FeatureQuotaResult) { result.Feature = "other" }},
		{name: "zero observed time", mutate: func(result *FeatureQuotaResult) { result.ObservedAt = time.Time{} }},
		{name: "non UTC observed time", mutate: func(result *FeatureQuotaResult) { result.ObservedAt = result.ObservedAt.In(nonUTC) }},
		{name: "too many limits", mutate: func(result *FeatureQuotaResult) {
			result.Limits = make([]FeatureQuotaLimit, maximumFeatureQuotaLimits+1)
			for index := range result.Limits {
				result.Limits[index] = FeatureQuotaLimit{Metric: "logical_requests", Hard: true}
			}
		}},
		{name: "unsupported metric", mutate: func(result *FeatureQuotaResult) { result.Limits[0].Metric = "cost_nano_usd" }},
		{name: "soft limit", mutate: func(result *FeatureQuotaResult) { result.Limits[0].Hard = false }},
		{name: "negative maximum", mutate: func(result *FeatureQuotaResult) { result.Limits[0].Maximum = int64Pointer(-1) }},
		{name: "negative used", mutate: func(result *FeatureQuotaResult) { result.Limits[0].Used = int64Pointer(-1) }},
		{name: "negative reserved", mutate: func(result *FeatureQuotaResult) { result.Limits[0].Reserved = int64Pointer(-1) }},
		{name: "negative remaining", mutate: func(result *FeatureQuotaResult) { result.Limits[0].Remaining = int64Pointer(-1) }},
		{name: "zero reset", mutate: func(result *FeatureQuotaResult) { result.Limits[0].ResetsAt = timePointer(time.Time{}) }},
		{name: "non UTC reset", mutate: func(result *FeatureQuotaResult) {
			result.Limits[0].ResetsAt = timePointer(testInstant.Add(time.Hour).In(nonUTC))
		}},
		{name: "reset equals observed", mutate: func(result *FeatureQuotaResult) { result.Limits[0].ResetsAt = timePointer(testInstant) }},
		{name: "reset before observed", mutate: func(result *FeatureQuotaResult) {
			result.Limits[0].ResetsAt = timePointer(testInstant.Add(-time.Second))
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := validFeatureQuotaResult("assistant")
			test.mutate(&result)
			provider := &fakeFeatureQuotaProvider{result: result}
			handler := newTestHandlerWithFeatureQuotas(
				t, &fakeCoordinator{}, provider, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test",
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validFeatureQuotaRequest("assistant"))

			assertProblem(t, response, "internal_error", http.StatusInternalServerError)
			if len(provider.inputs) != 1 {
				t.Fatalf("provider calls = %d", len(provider.inputs))
			}
			if strings.Contains(response.Body.String(), "cost_nano_usd") || strings.Contains(response.Body.String(), "other") {
				t.Fatalf("invalid provider result leaked: %s", response.Body.String())
			}
		})
	}
}

func TestFeatureQuotaResultProjectionDefensivelyCopiesAndAcceptsBoundaries(t *testing.T) {
	t.Parallel()

	maximum := maximumSafeJSONInteger
	reset := testInstant.Add(time.Hour)
	result := FeatureQuotaResult{
		Feature: "assistant", ObservedAt: testInstant,
		Limits: []FeatureQuotaLimit{{Metric: "logical_requests", Maximum: &maximum, ResetsAt: &reset, Hard: true}},
	}
	document, err := featureQuotaDocumentFor(result, "assistant")
	if err != nil {
		t.Fatalf("featureQuotaDocumentFor() error = %v", err)
	}
	if document.Limits[0].Maximum == result.Limits[0].Maximum || document.Limits[0].ResetsAt == result.Limits[0].ResetsAt {
		t.Fatal("feature quota projection retained provider pointers")
	}
	*document.Limits[0].Maximum = 0
	*document.Limits[0].ResetsAt = testInstant.Add(2 * time.Hour)
	document.Limits[0].Metric = "mutated"
	if *result.Limits[0].Maximum != maximumSafeJSONInteger || !result.Limits[0].ResetsAt.Equal(reset) || result.Limits[0].Metric != "logical_requests" {
		t.Fatalf("provider result was mutated through document: %#v", result)
	}

	boundary := validFeatureQuotaResult("assistant")
	boundary.Limits = make([]FeatureQuotaLimit, maximumFeatureQuotaLimits)
	for index := range boundary.Limits {
		boundary.Limits[index] = FeatureQuotaLimit{Metric: "concurrent_requests", Hard: true}
	}
	if projected, err := featureQuotaDocumentFor(boundary, "assistant"); err != nil || len(projected.Limits) != maximumFeatureQuotaLimits {
		t.Fatalf("128-limit boundary = (%d, %v)", len(projected.Limits), err)
	}
	empty := FeatureQuotaResult{Feature: "assistant", ObservedAt: testInstant, Limits: []FeatureQuotaLimit{}}
	if projected, err := featureQuotaDocumentFor(empty, "assistant"); err != nil || projected.Limits == nil || len(projected.Limits) != 0 {
		t.Fatalf("empty contract-valid limits = (%#v, %v)", projected.Limits, err)
	}
}

func TestFeatureQuotaDependencyFailuresAreFeatureSafeAndRedacted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code        string
		status      int
		retryAfter  int
		nonce       string
		wantFeature bool
	}{
		{code: "feature_not_found", status: http.StatusNotFound, wantFeature: true},
		{code: "feature_not_allowed", status: http.StatusForbidden, wantFeature: true},
		{code: "route_not_found", status: http.StatusServiceUnavailable, retryAfter: 7, wantFeature: true},
		{code: "configuration_invalid", status: http.StatusUnprocessableEntity},
		{code: "session_expired", status: http.StatusUnauthorized, retryAfter: 7},
		{code: "dpop_nonce_required", status: http.StatusUnauthorized, nonce: strings.Repeat("n", 24)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.code, func(t *testing.T) {
			t.Parallel()
			failure := &DependencyError{Code: test.code, RetryAfterSeconds: test.retryAfter, DPoPNonce: test.nonce}
			provider := &fakeFeatureQuotaProvider{
				result: validFeatureQuotaResult("assistant"),
				err:    fmt.Errorf("database-secret %s: %w", validQuotaAccessToken, failure),
			}
			handler := newTestHandlerWithFeatureQuotas(
				t, &fakeCoordinator{}, provider, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test",
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validFeatureQuotaRequest("assistant"))

			assertProblem(t, response, test.code, test.status)
			var document map[string]any
			decodeJSONResponse(t, response, &document)
			if test.wantFeature {
				if document["feature"] != "assistant" {
					t.Fatalf("problem feature = %#v", document["feature"])
				}
			} else if _, exists := document["feature"]; exists {
				t.Fatalf("non-feature problem exposed feature: %#v", document)
			}
			wantRetry := ""
			if test.retryAfter > 0 {
				wantRetry = fmt.Sprintf("%d", test.retryAfter)
			}
			if response.Header().Get("Retry-After") != wantRetry {
				t.Fatalf("Retry-After = %q, want %q", response.Header().Get("Retry-After"), wantRetry)
			}
			if response.Header().Get("DPoP-Nonce") != test.nonce {
				t.Fatalf("DPoP-Nonce = %q, want %q", response.Header().Get("DPoP-Nonce"), test.nonce)
			}
			if strings.Contains(response.Body.String(), "database-secret") || strings.Contains(response.Body.String(), validQuotaAccessToken) {
				t.Fatalf("dependency problem leaked wrapped context: %s", response.Body.String())
			}
		})
	}

	invalid := []error{
		errors.New("raw provider failure containing raw-secret"),
		&DependencyError{Code: "quota_exceeded"},
		&DependencyError{Code: "feature_not_found", RetryAfterSeconds: 1},
		&DependencyError{Code: "route_not_found", RetryAfterSeconds: 86401},
	}
	for index, failure := range invalid {
		failure := failure
		t.Run(fmt.Sprintf("invalid failure %d", index), func(t *testing.T) {
			t.Parallel()
			provider := &fakeFeatureQuotaProvider{err: failure}
			handler := newTestHandlerWithFeatureQuotas(
				t, &fakeCoordinator{}, provider, &fakeJWKSProvider{result: validJWKS()}, "https://gateway.example.test",
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, validFeatureQuotaRequest("assistant"))
			assertProblem(t, response, "internal_error", http.StatusInternalServerError)
			if strings.Contains(response.Body.String(), "raw-secret") || strings.Contains(response.Body.String(), "quota_exceeded") {
				t.Fatalf("invalid failure leaked: %s", response.Body.String())
			}
		})
	}
}

func validFeatureQuotaRequest(feature string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, featureQuotaPrefix+feature+featureQuotaSuffix, nil)
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "ios")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("Authorization", "DPoP "+validQuotaAccessToken)
	request.Header.Set("DPoP", validProof)
	return request
}

func validFeatureQuotaResult(feature string) FeatureQuotaResult {
	maximum := int64(100)
	used := int64(25)
	reserved := int64(5)
	remaining := int64(70)
	reset := testInstant.Add(time.Hour)
	return FeatureQuotaResult{
		Feature: feature, ObservedAt: testInstant,
		Limits: []FeatureQuotaLimit{{
			Metric: "logical_requests", Maximum: &maximum, Used: &used,
			Reserved: &reserved, Remaining: &remaining, ResetsAt: &reset, Hard: true,
		}},
	}
}

func int64Pointer(value int64) *int64        { return &value }
func timePointer(value time.Time) *time.Time { return &value }
