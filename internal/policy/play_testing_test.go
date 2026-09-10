package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/session"
)

func TestResolverPlayTestingIsDevelopmentOnlyAndKeepsDebugLevel(t *testing.T) {
	t.Parallel()
	for _, platform := range []string{"android", "react_native_android"} {
		for _, kind := range []string{"development", "staging", "production"} {
			for _, enabled := range []bool{false, true} {
				snapshot := policySnapshot()
				policy := snapshot.attestations["native"]
				policy.Platforms = map[string]configuration.PlatformAttestation{platform: {
					Provider: "play_integrity", Mode: "required", MinimumTrustLevel: "device_verified",
					PlayIntegrity: &configuration.PlayIntegrityConfiguration{MinimumDeviceIntegrity: "device", AllowTestingResponses: enabled},
				}}
				snapshot.attestations["native"] = policy
				input := policyInput("premium")
				input.environment.Kind = kind
				input.authorization.environmentKind = kind
				input.authorization.installationPlatform = platform
				input.authorization.attestationProvider = "play_integrity"
				input.authorization.trustLevel = "debug"
				resolver, err := newResolver(func() time.Time { return policyTestNow })
				if err != nil {
					t.Fatal(err)
				}
				_, err = resolver.Resolve(context.Background(), snapshot, "assistant", input)
				if kind == "development" && enabled {
					if err != nil {
						t.Fatalf("%s opted-in Development rejected: %v", platform, err)
					}
					feature := snapshot.features["assistant"]
					feature.AccessExpression += ` && installation.trust_level == 'device_verified'`
					snapshot.features["assistant"] = feature
					_, err = resolver.Resolve(context.Background(), snapshot, "assistant", input)
					if !errors.Is(err, ErrFeatureNotAllowed) {
						t.Fatalf("debug evidence promoted: %v", err)
					}
				} else if !errors.Is(err, session.ErrAttestationStepUpRequired) {
					t.Fatalf("platform=%s kind=%s enabled=%t error=%v", platform, kind, enabled, err)
				}
			}
		}
	}
}
