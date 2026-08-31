package localverify

import (
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
)

func TestVerificationConfigurationValidates(t *testing.T) {
	t.Parallel()

	fixture := &fixture{oidc: &mockOIDC{
		issuer:  "https://issuer.local-verify.example.test",
		jwksURL: "https://issuer.local-verify.example.test/jwks",
	}}
	document, err := fixture.configurationDocument()
	if err != nil {
		t.Fatal(err)
	}
	validator, err := configuration.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, configuration.EnvironmentDescriptor{
		OrganizationSlug: "local-verify",
		ApplicationSlug:  "mobile-app",
		EnvironmentSlug:  "development",
		EnvironmentKind:  "development",
		SecretNames: map[string]struct{}{
			"debug-attestation-public-keys": {},
			"provider-credential":           {},
		},
	}, time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("local verification configuration is invalid: %+v", report.Issues)
	}
}

func TestDevelopmentConfigurationValidatesAllClientPlatforms(t *testing.T) {
	t.Parallel()
	fixture := &fixture{
		browserOrigin: "http://localhost:5173",
		oidc: &mockOIDC{
			issuer:  "https://issuer.local-verify.example.test",
			jwksURL: "https://issuer.local-verify.example.test/jwks",
		},
	}
	document, err := fixture.developmentConfigurationDocument()
	if err != nil {
		t.Fatal(err)
	}
	validator, err := configuration.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, configuration.EnvironmentDescriptor{
		OrganizationSlug: "local-verify",
		ApplicationSlug:  "mobile-app",
		EnvironmentSlug:  "development",
		EnvironmentKind:  "development",
		SecretNames: map[string]struct{}{
			"debug-attestation-public-keys": {},
			"provider-credential":           {},
		},
	}, time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("local development configuration is invalid: %+v", report.Issues)
	}
}
