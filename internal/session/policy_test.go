package session

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/attestation"
)

func TestTrustSatisfiesFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		actual  string
		minimum string
		want    bool
	}{
		{actual: "none", minimum: "none", want: true},
		{actual: "identity_only", minimum: "none", want: true},
		{actual: "web_risk_verified", minimum: "identity_only", want: true},
		{actual: "web_risk_verified", minimum: "app_verified", want: false},
		{actual: "app_verified", minimum: "web_risk_verified", want: true},
		{actual: "device_verified", minimum: "app_verified", want: true},
		{actual: "app_verified", minimum: "device_verified", want: false},
		{actual: "strong_device_verified", minimum: "device_verified", want: true},
		{actual: "debug", minimum: "debug", want: true},
		{actual: "debug", minimum: "none", want: false},
		{actual: "strong_device_verified", minimum: "debug", want: false},
		{actual: "unknown", minimum: "none", want: false},
		{actual: "strong_device_verified", minimum: "unknown", want: false},
	}
	for _, test := range tests {
		if got := trustSatisfies(test.actual, test.minimum); got != test.want {
			t.Errorf("trustSatisfies(%q, %q)=%t want=%t", test.actual, test.minimum, got, test.want)
		}
	}
}

func TestChallengeAttestationPolicyEnforcement(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	policy := ChallengeAttestationPolicy{
		ID: "native", Provider: "app_attest", Mode: "required",
		MinimumTrustLevel: "app_verified", MaximumAge: 5 * time.Minute,
	}
	result := attestation.Result{
		Provider: "app_attest", TrustLevel: "device_verified",
		VerifiedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	if !challengeAttestationAllows(policy, result, now) {
		t.Fatal("fresh provider-matched stronger attestation was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*ChallengeAttestationPolicy, *attestation.Result, *time.Time)
	}{
		{name: "provider mismatch", mutate: func(_ *ChallengeAttestationPolicy, result *attestation.Result, _ *time.Time) {
			result.Provider = "debug"
		}},
		{name: "preferred mode", mutate: func(policy *ChallengeAttestationPolicy, _ *attestation.Result, _ *time.Time) {
			policy.Mode = "preferred"
		}},
		{name: "insufficient trust", mutate: func(_ *ChallengeAttestationPolicy, result *attestation.Result, _ *time.Time) {
			result.TrustLevel = "web_risk_verified"
		}},
		{name: "debug bypass", mutate: func(policy *ChallengeAttestationPolicy, result *attestation.Result, _ *time.Time) {
			policy.Provider = "debug"
			policy.MinimumTrustLevel = "none"
			result.Provider = "debug"
			result.TrustLevel = "debug"
		}},
		{name: "maximum age exceeded", mutate: func(_ *ChallengeAttestationPolicy, _ *attestation.Result, now *time.Time) {
			*now = now.Add(5 * time.Minute)
		}},
		{name: "invalid maximum age", mutate: func(policy *ChallengeAttestationPolicy, _ *attestation.Result, _ *time.Time) { policy.MaximumAge = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidatePolicy := policy
			candidateResult := result
			candidateNow := now
			test.mutate(&candidatePolicy, &candidateResult, &candidateNow)
			if challengeAttestationAllows(candidatePolicy, candidateResult, candidateNow) {
				t.Fatal("policy mismatch was accepted")
			}
		})
	}
}

func TestExchangeInputApplicationVersionMatchesContract(t *testing.T) {
	t.Parallel()

	requestURI, err := url.Parse("https://gateway.example.test/client/v1/sessions")
	if err != nil {
		t.Fatal(err)
	}
	base := ExchangeInput{
		ChallengeID: "chl_00000000000000000000000001",
		DPoPProof:   DPoPProof{value: "proof"},
		HTTPMethod:  "POST",
		RequestURI:  requestURI,
		KeyStorage:  "unknown",
		AppVersion:  strings.Repeat("v", 128),
	}
	if err := base.validate(); err != nil {
		t.Fatalf("128-character application version was rejected: %v", err)
	}
	base.AppVersion = strings.Repeat("界", 128)
	if err := base.validate(); err != nil {
		t.Fatalf("128-character multibyte application version was rejected: %v", err)
	}
	base.AppVersion += "v"
	if err := base.validate(); err == nil {
		t.Fatal("129-character application version was accepted")
	}
}
