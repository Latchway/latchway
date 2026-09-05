package attestation

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
)

func TestAppAttestAnyBuildPolicyRetainsIdentityAndCategoryChecks(t *testing.T) {
	for _, test := range []struct {
		name        string
		version     string
		category    uint32
		bundleID    string
		wantAllowed bool
	}{
		{name: "first build", version: "100", category: 4, wantAllowed: true},
		{name: "future build", version: "99999.12", category: 4, wantAllowed: true},
		{name: "wrong signing category", version: "100", category: 3},
		{name: "wrong app identity", version: "100", category: 4, bundleID: "com.example.other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := appAttestTestBinding(1)
			fixture := mustAppAttestFixture(t, binding, appAttestFixtureOptions{
				environment: AppAttestProduction, bundleVersion: test.version, validationCategory: test.category,
			})
			config := appAttestTestConfig(newMemoryAppAttestKeyStore(), AppAttestProduction, []uint32{4}, []string{"*"})
			if test.bundleID != "" {
				config.BundleID = test.bundleID
			}
			roots := x509.NewCertPool()
			roots.AddCert(fixture.root)
			verifier, err := newAppAttestVerifier(config, roots)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(context.Background(), mustAppAttestEvidence(t, fixture.keyID, "attestation_object", fixture.attestation, binding), binding)
			if (err == nil) != test.wantAllowed {
				t.Fatalf("allowed = %v, want %v: %v", err == nil, test.wantAllowed, err)
			}
		})
	}
}

func TestAppAttestAnyBuildPolicyRejectsAmbiguousAndMalformedVersions(t *testing.T) {
	config := appAttestTestConfig(newMemoryAppAttestKeyStore(), AppAttestProduction, []uint32{4}, []string{"*", "100"})
	if _, err := NewAppAttestVerifier(config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("mixed wildcard accepted: %v", err)
	}
	verifier := &AppAttestVerifier{allowedCategories: map[uint32]struct{}{4: {}}, allowedBundleVersions: map[string]struct{}{"*": {}}}
	for _, version := range []string{"", "*", "1/../../2"} {
		if verifier.extensionsAllowed(appAttestExtensions{present: true, validationCategory: 4, bundleVersion: version}) {
			t.Fatalf("malformed evidence version %q accepted", version)
		}
	}
}
