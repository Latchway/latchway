package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerRedactsSensitiveAttributesAndNestedGroups(t *testing.T) {
	t.Parallel()

	const secret = "super-private-provider-value"
	var output bytes.Buffer
	logger := NewLogger(&output, "debug").With(
		"authorization", "Bearer "+secret,
		"safe", "retained",
	)
	logger.Info("request",
		"input_tokens", 42,
		"identity_token", secret,
		slog.Group("provider", "credential", secret, "outcome", "failed"),
		slog.Group("outer", slog.Group("inner", "private_key", secret)),
	)
	logger.WithGroup("request_headers").Info("headers", "benign_name", secret)

	logged := output.String()
	if strings.Contains(logged, secret) {
		t.Fatalf("structured log disclosed private material: %s", logged)
	}
	for _, fragment := range []string{`"authorization":"[REDACTED]"`, `"identity_token":"[REDACTED]"`,
		`"credential":"[REDACTED]"`, `"private_key":"[REDACTED]"`, `"safe":"retained"`, `"input_tokens":42`} {
		if !strings.Contains(logged, fragment) {
			t.Fatalf("structured log missing %s: %s", fragment, logged)
		}
	}
}

func TestSensitiveTelemetryKeyDoesNotHideAggregateTokenCounts(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"input_tokens", "output_tokens", "total_tokens", "token_count", "error_code"} {
		if sensitiveTelemetryKey(key) {
			t.Fatalf("safe aggregate key %q was classified as sensitive", key)
		}
	}
	for _, key := range []string{"refresh-token", "DPoP", "attestation.evidence", "service_account", "headers", "provider_key", "api-key"} {
		if !sensitiveTelemetryKey(key) {
			t.Fatalf("private key %q was not classified as sensitive", key)
		}
	}
}
