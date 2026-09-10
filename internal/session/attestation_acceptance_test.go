package session

import (
	"testing"
	"time"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
)

func TestPlayTestingSelectionDoesNotPromoteDebugTrust(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"development", "staging", "production", ""} {
		for _, enabled := range []bool{false, true} {
			selection := configuration.PlatformAttestation{
				Provider: "play_integrity", Mode: "required", MinimumTrustLevel: "device_verified",
				PlayIntegrity: &configuration.PlayIntegrityConfiguration{
					MinimumDeviceIntegrity: "device", AllowTestingResponses: enabled,
				},
			}
			want := kind == "development" && enabled
			if got := TrustSatisfiesSelection(kind, selection, "play_integrity", "debug"); got != want {
				t.Errorf("kind=%q enabled=%t got=%t want=%t", kind, enabled, got, want)
			}
			if !TrustSatisfiesSelection(kind, selection, "play_integrity", "device_verified") {
				t.Fatal("real evidence should still satisfy the selection")
			}
			if TrustSatisfiesSelection(kind, selection, "debug", "debug") {
				t.Fatal("a different debug provider bypassed Play verification")
			}
			selection.MinimumTrustLevel = "strong_device_verified"
			if TrustSatisfiesSelection(kind, selection, "play_integrity", "debug") {
				t.Fatal("inconsistent strong policy accepted")
			}
		}
	}
	if TrustSatisfies("debug", "device_verified") || TrustSatisfies("debug", "none") {
		t.Fatal("global debug trust ordering changed")
	}
}

func TestChallengeTestingRequiresVerifiedMarkerAndFreshScope(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	policy := ChallengeAttestationPolicy{Provider: "play_integrity", Mode: "required", MinimumTrustLevel: "device_verified", MaximumAge: time.Minute}
	selection := configuration.PlatformAttestation{
		Provider: "play_integrity", Mode: "required", MinimumTrustLevel: "device_verified",
		PlayIntegrity: &configuration.PlayIntegrityConfiguration{MinimumDeviceIntegrity: "device", AllowTestingResponses: true},
	}
	result := attestation.Result{Provider: "play_integrity", TrustLevel: "debug", VerifiedAt: now, ExpiresAt: now.Add(time.Minute)}
	for _, marker := range []any{nil, false, "true", true} {
		result.NormalizedSignals = map[string]any{"testing_response": marker}
		want := marker == true
		if got := challengeAttestationAllowsSelection(policy, result, now, "development", selection); got != want {
			t.Errorf("marker=%v got=%t want=%t", marker, got, want)
		}
	}
	if challengeAttestationAllowsSelection(policy, result, now.Add(time.Minute), "development", selection) ||
		challengeAttestationAllowsSelection(policy, result, now, "production", selection) {
		t.Fatal("testing opt-in bypassed age or environment scope")
	}
}

func TestChallengeAppleAnyUsesActualEnvironment(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	policy := ChallengeAttestationPolicy{Provider: "app_attest", Mode: "required", MinimumTrustLevel: "app_verified", MaximumAge: time.Minute}
	for _, accepted := range []string{"development", "production", "any"} {
		selection := configuration.PlatformAttestation{Provider: "app_attest", Mode: "required", MinimumTrustLevel: "app_verified",
			AppAttest: &configuration.AppAttestConfiguration{Environment: accepted}}
		for _, actual := range []string{"development", "production", "any", "", "unknown"} {
			result := attestation.Result{Provider: "app_attest", TrustLevel: "app_verified", VerifiedAt: now,
				NormalizedSignals: map[string]any{"app_attest_environment": actual}}
			want := (actual == "development" || actual == "production") && (accepted == "any" || accepted == actual)
			if got := challengeAttestationAllowsSelection(policy, result, now, "development", selection); got != want {
				t.Errorf("accepted=%s actual=%s got=%t want=%t", accepted, actual, got, want)
			}
		}
	}
}
