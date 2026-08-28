package configuration

import (
	"encoding/json"
	"testing"
	"time"
)

func TestValidatorMobileAttestationProviderConfiguration(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		platform   string
		mutate     func(map[string]any)
		issue      string
		schemaOnly bool
	}{
		{
			name: "Apple development trust in production", platform: "ios",
			mutate: func(selection map[string]any) {
				objectValue(selection, "appAttest")["environment"] = "development"
			},
			issue: "app_attest_environment_forbidden",
		},
		{
			name: "App Attest cannot promise device trust", platform: "ios",
			mutate: func(selection map[string]any) {
				selection["minimumTrustLevel"] = "device_verified"
			},
			issue: "attestation_trust_unreachable",
		},
		{
			name: "Play testing response without production acknowledgement", platform: "android",
			mutate: func(selection map[string]any) {
				objectValue(selection, "playIntegrity")["allowTestingResponses"] = true
			},
			issue: "play_integrity_testing_forbidden",
		},
		{
			name: "Play service account missing secret", platform: "android",
			mutate: func(selection map[string]any) {
				objectValue(selection, "playIntegrity")["credentialSource"] = "service_account"
			},
			issue: "schema_allof", schemaOnly: true,
		},
		{
			name: "Play metadata forbids secret", platform: "android",
			mutate: func(selection map[string]any) {
				selection["secretRef"] = "secret/present"
			},
			issue: "schema_allof", schemaOnly: true,
		},
		{
			name: "provider-specific configurations cannot coexist", platform: "ios",
			mutate: func(selection map[string]any) {
				selection["playIntegrity"] = deepClone(map[string]any{
					"packageName": "com.example.habits", "cloudProjectNumber": json.Number("123456789"),
					"certificateSha256Digests": []any{"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
					"minimumDeviceIntegrity":   "device", "requireLicensed": true,
					"allowTestingResponses": false, "minimumVersionCode": json.Number("1"),
					"maximumVersionCode": json.Number("0"), "credentialSource": "metadata",
				})
			},
			issue: "schema_allof", schemaOnly: true,
		},
		{
			name: "canonical duplicate Play certificate", platform: "android",
			mutate: func(selection map[string]any) {
				objectValue(selection, "playIntegrity")["certificateSha256Digests"] = []any{
					"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
					"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
				}
			},
			issue: "attestation_provider_configuration_invalid",
		},
		{
			name: "inverted Play version bounds", platform: "android",
			mutate: func(selection map[string]any) {
				configuration := objectValue(selection, "playIntegrity")
				configuration["minimumVersionCode"] = json.Number("100")
				configuration["maximumVersionCode"] = json.Number("99")
			},
			issue: "attestation_provider_configuration_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			selection := objectValue(
				objectValue(objectArray(objectValue(document, "spec"), "attestationPolicies")[0], "platforms"),
				test.platform,
			)
			test.mutate(selection)
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if test.schemaOnly {
				issues := validator.SchemaIssues(encoded)
				if !hasIssue(issues, test.issue) {
					t.Fatalf("missing %s in %+v", test.issue, issues)
				}
				return
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.issue) {
				t.Fatalf("invalid mobile attestation compiled: %+v", report.Issues)
			}
		})
	}
}

func TestSnapshotMobileAttestationConfigurationIsImmutable(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := validConfigurationDocument(t)
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("configuration rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000", "env_00000000000000000000000000", document, compiled,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, appSelection, ok := snapshot.RequiredAttestationForPlatform("ios")
	if !ok || appSelection.AppAttest == nil {
		t.Fatal("App Attest selection missing")
	}
	appSelection.AppAttest.AllowedBundleVersions[0] = "changed"
	_, appAgain, _ := snapshot.RequiredAttestationForPlatform("ios")
	if appAgain.AppAttest.AllowedBundleVersions[0] != "1.0" {
		t.Fatal("App Attest nested configuration was mutable")
	}
	_, playSelection, ok := snapshot.RequiredAttestationForPlatform("android")
	if !ok || playSelection.PlayIntegrity == nil {
		t.Fatal("Play Integrity selection missing")
	}
	playSelection.PlayIntegrity.CertificateSHA256Digests[0] = "changed"
	_, playAgain, _ := snapshot.RequiredAttestationForPlatform("android")
	if playAgain.PlayIntegrity.CertificateSHA256Digests[0] != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" {
		t.Fatal("Play Integrity nested configuration was mutable")
	}
}
