package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/requestidentity"
)

func TestAttestationLoggingPathsPlayHTTPFailures(t *testing.T) {
	for _, platform := range []string{"android", "react_native_android"} {
		for _, test := range []struct {
			status  int
			reason  string
			code    string
			outcome string
			cause   error
		}{
			{http.StatusBadRequest, "play_integrity_token_rejected", "attestation_invalid", "rejected", attestation.ErrInvalid},
			{http.StatusForbidden, "play_integrity_decode_permission_denied", "server_not_ready", "unavailable", attestation.ErrPlayIntegrityService},
		} {
			t.Run(fmt.Sprintf("%s/%d", platform, test.status), func(t *testing.T) {
				now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
				environment, snapshot := attestationLoggingTestScope()
				const accessToken = "private-metadata-access-token"
				const integrityToken = "private-integrity-token-1234"
				const providerBody = `{"error":{"message":"private-google-body-with-credential"}}`
				var output bytes.Buffer
				metadataCalls, decodeCalls := 0, 0
				transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
					switch request.URL.Host {
					case "metadata.google.internal":
						metadataCalls++
						if request.Method != http.MethodGet || request.Header.Get("Metadata-Flavor") != "Google" {
							t.Fatal("unexpected Google metadata request")
						}
						response := jsonHTTPResponse(http.StatusOK, `{"access_token":"`+accessToken+`","expires_in":3600,"token_type":"Bearer"}`)
						response.Header.Set("Metadata-Flavor", "Google")
						return response, nil
					case "playintegrity.googleapis.com":
						decodeCalls++
						if request.Method != http.MethodPost || request.URL.Path != "/v1/com.example.habits:decodeIntegrityToken" ||
							request.Header.Get("Authorization") != "Bearer "+accessToken {
							t.Fatal("unexpected Google decode request")
						}
						return jsonHTTPResponse(test.status, providerBody), nil
					default:
						t.Fatal("unexpected destination: the test must not use a live provider")
						return nil, errors.New("unexpected destination")
					}
				})
				coordinator := &clientCoordinator{
					now: nowClock(now), attestationTransport: transport,
					logger:           slog.New(slog.NewJSONHandler(&output, nil)),
					attestationCache: make(map[attestationVerifierCacheKey]*preparedAttestationVerifier),
				}
				binding := attestation.Binding{
					Version: 1, ChallengeID: "chl_01J00000000000000000000000",
					ChallengeNonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
					ApplicationID:  environment.ApplicationID, Environment: environment.Slug,
					PrincipalID: "usr_01J00000000000000000000000",
					DPoPJKT:     "bX0yCl562RPdpf8cJHVLBeUXu6PWExYJ0w-Bydre3q8", Platform: platform, IssuedAt: now.Unix(),
				}
				evidence, err := attestation.NewEvidence("play_integrity", map[string]any{"integrity_token": integrityToken})
				if err != nil {
					t.Fatal(err)
				}
				ctx, logicalID := attestationLoggingTestContext(t)
				_, err = coordinator.verifyAttestationEvidence(ctx, environment, snapshot,
					configuration.AttestationPolicy{ID: "native", MaxAge: 10 * time.Minute},
					validPlayIntegritySelection("metadata"), evidence, binding)
				if !errors.Is(err, test.cause) || mapAttestationError(err) != test.code {
					t.Fatalf("public failure semantics changed: cause matches=%t code=%s", errors.Is(err, test.cause), mapAttestationError(err))
				}
				if metadataCalls != 1 || decodeCalls != 1 {
					t.Fatalf("Google path not exercised exactly once: metadata=%d decode=%d", metadataCalls, decodeCalls)
				}
				row := attestationLoggingTestRow(t, &output)
				attestationLoggingAssertFields(t, row, map[string]any{
					"provider": "play_integrity", "platform": platform, "stage": "verification",
					"reason": test.reason, "error_code": test.code, "outcome": test.outcome,
					"phase": "google_decode", "provider_http_status": float64(test.status),
					"request_id": "rn:attestation-log-path", "logical_request_id": logicalID,
					"application_id": environment.ApplicationID, "environment_id": environment.EnvironmentID,
					"config_revision_id": snapshot.RevisionID,
				})
				attestationLoggingAssertPrivateAbsent(t, &output, accessToken, integrityToken,
					"private-google-body-with-credential", binding.ChallengeID, binding.ChallengeNonce,
					binding.PrincipalID, binding.DPoPJKT)
			})
		}
	}
}

func TestAttestationLoggingPathsPreflightAndConfigurationFailures(t *testing.T) {
	for _, path := range []string{"preflight", "preflight_configuration", "verification_configuration"} {
		t.Run(path, func(t *testing.T) {
			const privateMaterial = "private-malformed-service-account-credential"
			var output bytes.Buffer
			environment, snapshot := attestationLoggingTestScope()
			selection := validPlayIntegritySelection("service_account")
			selection.SecretRef = "secret/private-service-account"
			store := &ephemeralSecretStore{material: []byte(privateMaterial)}
			coordinator := &clientCoordinator{
				now:              nowClock(time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)),
				logger:           slog.New(slog.NewJSONHandler(&output, nil)),
				attestationCache: make(map[attestationVerifierCacheKey]*preparedAttestationVerifier),
				attestationTransport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("configuration failure must not contact Google")
					return nil, errors.New("unexpected transport call")
				}),
			}
			stage := "verifier_configuration"
			if path == "preflight" {
				coordinator.secrets = store
				stage = "preflight"
			}
			ctx, logicalID := attestationLoggingTestContext(t)
			policy := configuration.AttestationPolicy{ID: "native", MaxAge: 10 * time.Minute}
			var err error
			if path == "verification_configuration" {
				_, err = coordinator.verifyAttestationEvidence(ctx, environment, snapshot, policy, selection,
					attestation.Evidence{}, attestation.Binding{Platform: "react_native_android"})
			} else {
				err = coordinator.preflightAttestationVerifier(ctx, environment, snapshot, policy, selection, "react_native_android")
			}
			if !errors.Is(err, attestation.ErrConfiguration) || mapAttestationError(err) != "server_not_ready" {
				t.Fatal("configuration failure did not retain the existing public error")
			}
			if path == "preflight" && (store.calls.Load() != 1 || !store.lastCallbackBufferCleared()) {
				t.Fatal("credential preflight was not exercised or its temporary material was not cleared")
			}
			row := attestationLoggingTestRow(t, &output)
			attestationLoggingAssertFields(t, row, map[string]any{
				"provider": "play_integrity", "platform": "react_native_android", "stage": stage,
				"reason": "configuration_invalid", "error_code": "server_not_ready", "outcome": "unavailable",
				"request_id": "rn:attestation-log-path", "logical_request_id": logicalID,
				"application_id": environment.ApplicationID, "environment_id": environment.EnvironmentID,
				"config_revision_id": snapshot.RevisionID,
			})
			if _, ok := row["provider_http_status"]; ok {
				t.Fatal("configuration failure invented a Google HTTP status")
			}
			attestationLoggingAssertPrivateAbsent(t, &output, privateMaterial, selection.SecretRef)
		})
	}
}

func TestAttestationLoggingPathsComponentCorrelation(t *testing.T) {
	var output bytes.Buffer
	coordinator := &clientCoordinator{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	environment, snapshot := attestationLoggingTestScope()
	ctx, logicalID := attestationLoggingTestContext(t)
	challenge := ComponentAttestationChallenge{
		EnvironmentID: environment.EnvironmentID, ConfigurationRevisionID: snapshot.RevisionID,
		Attestation: ChallengeAttestationPolicy{Provider: "app_attest"},
		Binding: attestation.Binding{
			ApplicationID: environment.ApplicationID, Platform: "react_native_ios",
			PrincipalID: "private-principal", ClientComponentID: "private-component",
			InstallationFamilyID: "private-family", ComponentDefinitionID: "private-definition",
			DPoPJKT: "private-thumbprint", ChallengeNonce: "private-challenge-nonce",
		},
	}
	coordinator.logComponentAttestationFailure(ctx, challenge, "component_binding", attestation.ErrInvalid)
	row := attestationLoggingTestRow(t, &output)
	attestationLoggingAssertFields(t, row, map[string]any{
		"provider": "app_attest", "platform": "react_native_ios", "stage": "component_binding",
		"reason": "evidence_invalid", "error_code": "attestation_invalid", "outcome": "rejected",
		"request_id": "rn:attestation-log-path", "logical_request_id": logicalID,
		"application_id": environment.ApplicationID, "environment_id": environment.EnvironmentID,
		"config_revision_id": snapshot.RevisionID,
	})
	attestationLoggingAssertPrivateAbsent(t, &output, "private-principal", "private-component", "private-family",
		"private-definition", "private-thumbprint", "private-challenge-nonce")
}

func attestationLoggingTestScope() (clientEnvironment, configuration.ActiveSnapshot) {
	return clientEnvironment{
		OrganizationID: "org_00000000000000000000000000", ApplicationID: "app_00000000000000000000000000",
		EnvironmentID: "env_00000000000000000000000000", Slug: "development", Kind: "development",
	}, configuration.ActiveSnapshot{RevisionID: "rev_00000000000000000000000000"}
}

func attestationLoggingTestContext(t *testing.T) (context.Context, string) {
	t.Helper()
	ctx, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	logical, ok := requestidentity.FromContext(ctx)
	if !ok {
		t.Fatal("server-generated request identity is missing")
	}
	return context.WithValue(ctx, middleware.RequestIDKey, "rn:attestation-log-path"), logical.String()
}

func attestationLoggingTestRow(t *testing.T, output *bytes.Buffer) map[string]any {
	t.Helper()
	var row map[string]any
	if err := json.Unmarshal(output.Bytes(), &row); err != nil {
		t.Fatalf("expected exactly one JSON failure diagnostic: %v", err)
	}
	for _, key := range []string{"error", "payload", "evidence", "claims", "binding", "configuration"} {
		if _, ok := row[key]; ok {
			t.Fatalf("forbidden diagnostic field %s", key)
		}
	}
	return row
}

func attestationLoggingAssertFields(t *testing.T, row, want map[string]any) {
	t.Helper()
	for key, value := range want {
		if row[key] != value {
			t.Fatalf("diagnostic field %s = %v; want %v", key, row[key], value)
		}
	}
}

func attestationLoggingAssertPrivateAbsent(t *testing.T, output *bytes.Buffer, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(output.String(), value) {
			t.Fatal("private material leaked into an operator diagnostic")
		}
	}
}
