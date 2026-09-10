package session

import (
	"time"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
)

// TrustSatisfiesSelection evaluates server-owned policy against verified or
// durably sealed session trust. It must never be called with client claims.
// Google's authenticated testing responses remain debug, outside the normal
// assurance order. Only the explicit Development Play policy can accept them.
func TrustSatisfiesSelection(kind string, selection configuration.PlatformAttestation, provider, actual string) bool {
	if provider != selection.Provider {
		return false
	}
	if provider == "play_integrity" && actual == "debug" {
		return kind == "development" && selection.PlayIntegrity != nil &&
			selection.PlayIntegrity.AllowTestingResponses &&
			((selection.PlayIntegrity.MinimumDeviceIntegrity == "device" && selection.MinimumTrustLevel == "device_verified") ||
				(selection.PlayIntegrity.MinimumDeviceIntegrity == "strong" && selection.MinimumTrustLevel == "strong_device_verified"))
	}
	return trustSatisfies(actual, selection.MinimumTrustLevel)
}

func challengeAttestationAllowsSelection(policy ChallengeAttestationPolicy, result attestation.Result, now time.Time, kind string, selection configuration.PlatformAttestation) bool {
	if policy.Provider != selection.Provider || policy.Mode != selection.Mode ||
		policy.MinimumTrustLevel != selection.MinimumTrustLevel ||
		!validAttestationProvider(policy.Provider) || policy.Mode != "required" ||
		policy.MaximumAge < time.Minute || policy.MaximumAge > 30*24*time.Hour ||
		now.IsZero() || !result.VerifiedAt.Add(policy.MaximumAge).After(now) ||
		!TrustSatisfiesSelection(kind, selection, result.Provider, result.TrustLevel) {
		return false
	}
	if result.Provider == "play_integrity" && result.TrustLevel == "debug" {
		testing, ok := result.NormalizedSignals["testing_response"].(bool)
		return ok && testing
	}
	if result.Provider == "app_attest" {
		actual, _ := result.NormalizedSignals["app_attest_environment"].(string)
		return selection.AppAttest != nil &&
			attestation.AppAttestEnvironment(selection.AppAttest.Environment).Allows(attestation.AppAttestEnvironment(actual))
	}
	return true
}
