package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/requestidentity"
)

type unprintableAttestationError struct{}

func (unprintableAttestationError) Error() string {
	panic("operator logging must never format an error")
}

func TestAttestationFailureLogCorrelatesWithoutFormattingPrivateErrors(t *testing.T) {
	for _, provider := range []string{"play_integrity", "app_attest"} {
		t.Run(provider, func(t *testing.T) {
			var output bytes.Buffer
			coordinator := &clientCoordinator{logger: slog.New(slog.NewJSONHandler(&output, nil))}
			ctx, err := requestidentity.NewContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx = context.WithValue(ctx, middleware.RequestIDKey, "android:operator-log-request")
			logical, _ := requestidentity.FromContext(ctx)
			coordinator.logMobileAttestationFailure(ctx, clientEnvironment{
				ApplicationID: "app_00000000000000000000000000", EnvironmentID: "env_00000000000000000000000000",
				Slug: "private-configuration-not-for-logs",
			}, "rev_00000000000000000000000000", provider, "android", "verification", unprintableAttestationError{})
			var row map[string]any
			if err := json.Unmarshal(output.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{
				"msg": "Attestation verification failed", "level": "WARN", "provider": provider,
				"request_id": "android:operator-log-request", "logical_request_id": logical.String(),
				"stage": "verification", "reason": "verification_failed", "error_code": "attestation_invalid",
				"application_id": "app_00000000000000000000000000", "environment_id": "env_00000000000000000000000000",
				"config_revision_id": "rev_00000000000000000000000000",
			} {
				if row[key] != want {
					t.Fatalf("%s = %v; want %s", key, row[key], want)
				}
			}
			if strings.Contains(output.String(), "private-configuration") {
				t.Fatal("configuration leaked")
			}
		})
	}
}

func TestAttestationFailureLogRedactsMalformedLabelsAndWrappedErrors(t *testing.T) {
	var output bytes.Buffer
	coordinator := &clientCoordinator{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	secret := "sensitive-body\ncredential"
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, secret)
	coordinator.logMobileAttestationFailure(ctx, clientEnvironment{ApplicationID: secret, EnvironmentID: secret},
		secret, "play_integrity", secret, secret, fmt.Errorf("%s: %w", secret, attestation.ErrPlayIntegrityService))
	var row map[string]any
	if err := json.Unmarshal(output.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row["platform"] != "unknown" || row["stage"] != "unknown" || row["error_code"] != "server_not_ready" {
		t.Fatalf("unsafe log: %v", row)
	}
	for _, key := range []string{"request_id", "logical_request_id", "application_id", "environment_id", "config_revision_id", "error", "payload", "evidence", "provider_http_status"} {
		if _, ok := row[key]; ok {
			t.Fatalf("unexpected %s in diagnostic", key)
		}
	}
	if strings.Contains(output.String(), "sensitive-body") || strings.Contains(output.String(), "credential") {
		t.Fatal("private error leaked")
	}
}

func TestAttestationFailureLogOnlyRecordsRequestedProvidersAndFailures(t *testing.T) {
	var output bytes.Buffer
	coordinator := &clientCoordinator{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	for _, provider := range []string{"debug", "firebase_app_check", "turnstile", "private-provider"} {
		coordinator.logMobileAttestationFailure(context.Background(), clientEnvironment{}, "", provider, "web", "verification", errors.New("private"))
	}
	coordinator.logMobileAttestationFailure(context.Background(), clientEnvironment{}, "", "app_attest", "ios", "verification", nil)
	(&clientCoordinator{}).logMobileAttestationFailure(context.Background(), clientEnvironment{}, "", "app_attest", "ios", "verification", attestation.ErrInvalid)
	if output.Len() != 0 {
		t.Fatal("unexpected failure log")
	}
}

func TestAttestationCorrelationUsesCanonicalBoundedGrammar(t *testing.T) {
	for _, value := range []string{"android:441b5762-6f03-4093-901d-663fd3d4b043", "request_123", strings.Repeat("a", 128)} {
		if !safeAttestationCorrelation(value) {
			t.Fatalf("valid correlation rejected: %q", value)
		}
	}
	for _, value := range []string{"", "short", "_request123", "request\n123", "request 123", "request,123", "requesté123", strings.Repeat("a", 129)} {
		if safeAttestationCorrelation(value) {
			t.Fatalf("invalid correlation accepted: %q", value)
		}
	}
}
