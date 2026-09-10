package session

import (
	"context"
	"log/slog"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

func (coordinator *clientCoordinator) logChallengeAttestationFailure(ctx context.Context, challenge Challenge, stage string, err error) {
	coordinator.logMobileAttestationFailure(ctx, clientEnvironment{
		ApplicationID: challenge.Binding.ApplicationID, EnvironmentID: challenge.EnvironmentID,
	}, challenge.ConfigurationRevisionID, challenge.Attestation.Provider, challenge.Binding.Platform, stage, err)
}

func (coordinator *clientCoordinator) logComponentAttestationFailure(ctx context.Context, challenge ComponentAttestationChallenge, stage string, err error) {
	coordinator.logMobileAttestationFailure(ctx, clientEnvironment{
		ApplicationID: challenge.Binding.ApplicationID, EnvironmentID: challenge.EnvironmentID,
	}, challenge.ConfigurationRevisionID, challenge.Attestation.Provider, challenge.Binding.Platform, stage, err)
}

// Only closed diagnostics and bounded correlation identifiers cross this
// boundary. Never pass err, evidence, binding, decoded signals or configuration
// as a slog value: provider errors and those objects can contain credentials.
func (coordinator *clientCoordinator) logMobileAttestationFailure(
	ctx context.Context, environment clientEnvironment, revision, provider, platform, stage string, err error,
) {
	if coordinator == nil || coordinator.logger == nil || err == nil ||
		(provider != "app_attest" && provider != "play_integrity") {
		return
	}
	switch platform {
	case "ios", "react_native_ios", "watchos", "android", "react_native_android":
	default:
		platform = "unknown"
	}
	switch stage {
	case "verifier_configuration", "preflight", "verification", "provider_binding", "origin_binding", "payload", "component_binding":
	default:
		stage = "unknown"
	}
	diagnostic := attestation.FailureDiagnosticOf(err)
	attributes := []slog.Attr{
		slog.String("provider", provider), slog.String("platform", platform),
		slog.String("stage", stage), slog.String("reason", diagnostic.Reason),
		slog.String("outcome", attestationTelemetryOutcome(err)),
		slog.String("error_code", mapAttestationError(err)),
	}
	for _, field := range []struct {
		name, value string
		kind        id.Prefix
	}{
		{"application_id", environment.ApplicationID, id.Application},
		{"environment_id", environment.EnvironmentID, id.Environment},
		{"config_revision_id", revision, id.ConfigRevision},
	} {
		if id.Validate(field.value, field.kind) == nil {
			attributes = append(attributes, slog.String(field.name, field.value))
		}
	}
	if logicalID, ok := requestidentity.FromContext(ctx); ok {
		attributes = append(attributes, slog.String("logical_request_id", logicalID.String()))
	}
	if correlation := middleware.GetReqID(ctx); safeAttestationCorrelation(correlation) {
		attributes = append(attributes, slog.String("request_id", correlation))
	}
	if diagnostic.Phase != "" {
		attributes = append(attributes, slog.String("phase", diagnostic.Phase))
	}
	if diagnostic.HTTPStatus != 0 {
		attributes = append(attributes, slog.Int("provider_http_status", diagnostic.HTTPStatus))
	}
	coordinator.logger.LogAttrs(ctx, slog.LevelWarn, "Attestation verification failed", attributes...)
}

func safeAttestationCorrelation(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for index, char := range []byte(value) {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			continue
		}
		if index > 0 && (char == '.' || char == '_' || char == ':' || char == '-') {
			continue
		}
		return false
	}
	return true
}
