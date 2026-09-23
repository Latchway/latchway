package clientapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/requestidentity"
)

func TestClientProblemLogCapturesClosedFailureContextWithoutSecrets(t *testing.T) {
	t.Parallel()

	const dependencySecret = "database-secret-must-not-be-logged"
	var logs bytes.Buffer
	coordinator := &fakeCoordinator{
		challengeErr: errors.Join(errors.New(dependencySecret), &DependencyError{Code: "session_expired"}),
	}
	api, err := New(Config{
		Coordinator: coordinator, FeatureQuotas: &fakeFeatureQuotaProvider{},
		JWKS: &fakeJWKSProvider{result: validJWKS()}, PublicOrigin: "https://gateway.example.test",
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("android"), "android", "1.2.3")
	request.Header.Set("X-Latchway-Request-ID", "android:observability-test")
	ctx, err := requestidentity.NewContext(request.Context())
	if err != nil {
		t.Fatalf("requestidentity.NewContext() error = %v", err)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request.WithContext(ctx))

	assertProblem(t, response, "session_expired", http.StatusUnauthorized)
	record := decodeSingleLogRecord(t, logs.Bytes())
	for key, want := range map[string]any{
		"msg":           "Client API problem",
		"request_id":    "android:observability-test",
		"endpoint":      "session_challenge",
		"method":        "POST",
		"sdk":           "android",
		"caller":        "standalone",
		"failure_stage": "dependency",
		"error_code":    "session_expired",
		"status":        float64(http.StatusUnauthorized),
		"retryable":     true,
	} {
		if got := record[key]; got != want {
			t.Errorf("log %s = %#v, want %#v", key, got, want)
		}
	}
	if logical, _ := record["logical_request_id"].(string); !strings.HasPrefix(logical, "req_") {
		t.Errorf("logical_request_id = %#v", record["logical_request_id"])
	}
	encoded := logs.String()
	for _, forbidden := range []string{dependencySecret, "identity-token-123", validProof, "body", "headers"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("client problem log leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestClientProblemLogClassifiesInternalDependencyContractFailure(t *testing.T) {
	t.Parallel()

	const secret = "raw-postgres-message"
	var logs bytes.Buffer
	coordinator := &fakeCoordinator{challengeErr: errors.New(secret)}
	api, err := New(Config{
		Coordinator: coordinator, FeatureQuotas: &fakeFeatureQuotaProvider{},
		JWKS: &fakeJWKSProvider{result: validJWKS()}, PublicOrigin: "https://gateway.example.test",
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "native", "1.2.3")
	request.Header.Set("X-Latchway-Protocol-Version", "3")
	request.Header.Set("X-Latchway-Caller", "react-native")
	ctx, err := requestidentity.NewContext(request.Context())
	if err != nil {
		t.Fatalf("requestidentity.NewContext() error = %v", err)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request.WithContext(ctx))

	assertProblem(t, response, "internal_error", http.StatusInternalServerError)
	record := decodeSingleLogRecord(t, logs.Bytes())
	if record["sdk"] != "native" || record["caller"] != "react-native" ||
		record["failure_stage"] != "dependency_contract" || record["error_code"] != "internal_error" {
		t.Fatalf("unexpected failure record: %#v", record)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("internal failure log leaked dependency detail: %s", logs.String())
	}
}

func TestClientEndpointCategoryNeverReturnsRawDynamicPath(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		challengePath: "session_challenge",
		featureQuotaPrefix + "habi-assistant" + featureQuotaSuffix:                          "feature_quota",
		revokeComponentPrefix + "cmp_01K3NQ7M8P9RSTVWXYZABCDE12":                            "component_revoke",
		revokeComponentPrefix + "cmp_01K3NQ7M8P9RSTVWXYZABCDE12" + componentChallengeSuffix: "component_attestation_challenge",
		"/client/v1/private-value-that-must-not-be-logged":                                  "unknown",
	}
	for path, want := range tests {
		if got := clientEndpointCategory(path); got != want {
			t.Errorf("clientEndpointCategory(%q) = %q, want %q", path, got, want)
		}
	}
}

func decodeSingleLogRecord(t *testing.T, encoded []byte) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(encoded), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("log records = %d, want 1: %s", len(lines), encoded)
	}
	var record map[string]any
	if err := json.Unmarshal(lines[0], &record); err != nil {
		t.Fatalf("decode log record: %v: %s", err, lines[0])
	}
	return record
}
