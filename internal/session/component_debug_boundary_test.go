package session

import "testing"

func TestDirectDelegatedStepUpExcludesAndroidPlayPlatforms(t *testing.T) {
	// Direct delegated step-up is an App Attest-only surface. Play testing
	// support for Android roots and shared RN sessions must not accidentally
	// expand it to Android or the reserved Wear OS platform.
	for _, platform := range []string{"android", "react_native_android", "wearos"} {
		for _, kind := range []string{"android_app", "wear_app", "main_app", "action_extension", "sso_extension", "watch_extension"} {
			if componentDirectStepUpSupported(platform, kind) {
				t.Errorf("unsupported direct step-up accepted for %s/%s", platform, kind)
			}
		}
	}
	for _, platform := range []string{"ios", "react_native_ios", "watchos"} {
		for _, kind := range []string{"action_extension", "sso_extension", "watch_extension"} {
			if !componentDirectStepUpSupported(platform, kind) {
				t.Errorf("supported Apple direct step-up rejected for %s/%s", platform, kind)
			}
		}
	}
}

func TestDirectDelegatedStepUpDoesNotPromoteSimulatedParentTrust(t *testing.T) {
	// An explicitly cross-platform delegated Apple component could inherit
	// debug trust from a Development Play-testing parent. Even genuine App
	// Attest evidence for that child must not promote the parent's assurance.
	for _, trust := range []string{"none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug"} {
		for _, pair := range [][2]string{{"debug", trust}, {trust, "debug"}} {
			if effective, ok := minimumTrustLevel(pair[0], pair[1]); ok || effective != "" {
				t.Errorf("debug parent/child trust was promoted: %q + %q -> %q", pair[0], pair[1], effective)
			}
		}
	}
	if effective, ok := minimumTrustLevel("app_verified", "app_verified"); !ok || effective != "app_verified" {
		t.Fatal("genuine Apple development or production attestation lost normal step-up support")
	}
}
