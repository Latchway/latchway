package configuration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	configuredFirebaseProject = "123456789012"
	configuredFirebaseAppID   = "1:123456789012:web:0123456789abcdef"
)

func TestValidatorAcceptsTypedFirebaseAppCheckAndTurnstileSelections(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		platform  string
		selection map[string]any
		trust     string
	}{
		{name: "Firebase iOS", platform: "ios", selection: validFirebaseAppCheckSelection("ios"), trust: "app_verified"},
		{name: "Firebase Android", platform: "android", selection: validFirebaseAppCheckSelection("android"), trust: "app_verified"},
		{name: "Firebase React Native iOS", platform: "react_native_ios", selection: validFirebaseAppCheckSelection("react_native_ios"), trust: "app_verified"},
		{name: "Firebase React Native Android", platform: "react_native_android", selection: validFirebaseAppCheckSelection("react_native_android"), trust: "app_verified"},
		{name: "Firebase web", platform: "web", selection: validFirebaseAppCheckSelection("web"), trust: "web_risk_verified"},
		{name: "Turnstile web", platform: "web", selection: validTurnstileSelection(), trust: "web_risk_verified"},
		{
			name: "debug web", platform: "web", trust: "debug",
			selection: map[string]any{
				"provider": "debug", "mode": "required", "secretRef": "secret/present",
				"dangerousAllowInProduction": true,
				"allowedOrigins":             []any{"https://debug.example.test"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			documentObject := configurationWithAttestationSelection(t, test.platform, test.selection)
			document, marshalErr := json.Marshal(documentObject)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(document, testEnvironment(), time.Now())
			if !report.Valid || len(compiled) == 0 {
				t.Fatalf("valid %s configuration rejected: %+v", test.name, report.Issues)
			}
			snapshot, snapshotErr := newActiveSnapshot(
				"rev_00000000000000000000000000", "env_00000000000000000000000000", document, compiled,
			)
			if snapshotErr != nil {
				t.Fatal(snapshotErr)
			}
			selection, ok := snapshot.SelectAttestation("native", test.platform)
			if !ok || selection.MinimumTrustLevel != test.trust {
				t.Fatalf("compiled selection = %#v, found=%t", selection, ok)
			}
			if selection.FirebaseAppCheck != nil {
				selection.FirebaseAppCheck.AllowedAppIDs[0] = "changed"
			}
			if selection.Turnstile != nil {
				selection.Turnstile.AllowedHostnames[0] = "changed.example.test"
			}
			if len(selection.AllowedOrigins) != 0 {
				selection.AllowedOrigins[0] = "https://changed.example.test"
			}
			again, _ := snapshot.SelectAttestation("native", test.platform)
			if again.FirebaseAppCheck != nil && again.FirebaseAppCheck.AllowedAppIDs[0] != configuredFirebaseAppID {
				t.Fatal("Firebase App Check app IDs were mutable through snapshot lookup")
			}
			if again.Turnstile != nil && again.Turnstile.AllowedHostnames[0] != "app.example.test" {
				t.Fatal("Turnstile hostnames were mutable through snapshot lookup")
			}
			if len(again.AllowedOrigins) != 0 && again.AllowedOrigins[0] == "https://changed.example.test" {
				t.Fatal("allowed origins were mutable through snapshot lookup")
			}
		})
	}
}

func TestValidatorRejectsUnsafeFirebaseAppCheckAndTurnstileSelections(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		platform     string
		selection    map[string]any
		mutate       func(map[string]any)
		issue        string
		schemaReject bool
	}{
		{
			name: "Firebase configuration missing", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) { delete(selection, "firebaseAppCheck") }, schemaReject: true,
		},
		{
			name: "Firebase secret forbidden", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) { selection["secretRef"] = "secret/present" }, schemaReject: true,
		},
		{
			name: "Firebase provider configurations coexist", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				selection["turnstile"] = validTurnstileConfigurationObject()
			}, schemaReject: true,
		},
		{
			name: "Firebase project number is numeric", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["projectNumber"] = json.Number(configuredFirebaseProject)
			}, schemaReject: true,
		},
		{
			name: "Firebase project number has leading zero", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["projectNumber"] = "0123456789"
			}, schemaReject: true,
		},
		{
			name: "Firebase project number exceeds uint64", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["projectNumber"] = "18446744073709551616"
			}, issue: "attestation_provider_configuration_invalid",
		},
		{
			name: "Firebase app ID list empty", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["allowedAppIds"] = []any{}
			}, schemaReject: true,
		},
		{
			name: "Firebase app ID duplicate", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["allowedAppIds"] = []any{configuredFirebaseAppID, configuredFirebaseAppID}
			}, schemaReject: true,
		},
		{
			name: "Firebase app ID not printable", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["allowedAppIds"] = []any{"app\nidentity"}
			}, schemaReject: true,
		},
		{
			name: "Firebase native trust overstated", platform: "android", selection: validFirebaseAppCheckSelection("android"),
			mutate: func(selection map[string]any) { selection["minimumTrustLevel"] = "device_verified" },
			issue:  "attestation_trust_unreachable",
		},
		{
			name: "Firebase web trust promoted", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["minimumTrustLevel"] = "app_verified" },
			issue:  "attestation_trust_unreachable",
		},
		{
			name: "Firebase native origin forbidden", platform: "ios", selection: validFirebaseAppCheckSelection("ios"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://app.example.test"}
			}, issue: "attestation_allowed_origins_forbidden",
		},
		{
			name: "Firebase web origin required", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { delete(selection, "allowedOrigins") },
			issue:  "attestation_allowed_origins_required",
		},
		{
			name: "web origin trailing slash", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://app.example.test/"}
			}, issue: "attestation_allowed_origin_invalid",
		},
		{
			name: "web origin uppercase host", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://App.Example.test"}
			}, issue: "attestation_allowed_origin_invalid",
		},
		{
			name: "web origin default port", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://app.example.test:443"}
			}, issue: "attestation_allowed_origin_invalid",
		},
		{
			name: "web origin user info", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://user@app.example.test"}
			}, issue: "attestation_allowed_origin_invalid",
		},
		{
			name: "web origin hostname underscore", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://app_name.example.test"}
			}, issue: "attestation_allowed_origin_invalid",
		},
		{
			name: "web origin invalid DNS label", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://-app.example.test"}
			}, issue: "attestation_allowed_origin_invalid",
		},
		{
			name: "generic application identifiers remain unsupported", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["applicationIdentifiers"] = []any{"generic-app-id"}
			}, issue: "attestation_application_identifiers_unsupported",
		},
		{
			name: "Firebase unsupported on Node", platform: "node", selection: validFirebaseAppCheckSelection("node"),
			mutate: func(map[string]any) {}, issue: "attestation_provider_platform_mismatch",
		},
		{
			name: "Turnstile configuration missing", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { delete(selection, "turnstile") }, schemaReject: true,
		},
		{
			name: "Turnstile secret missing", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { delete(selection, "secretRef") }, schemaReject: true,
		},
		{
			name: "disabled Turnstile secret forbidden", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { selection["mode"] = "disabled" }, schemaReject: true,
		},
		{
			name: "Turnstile hostname has empty label", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				objectValue(selection, "turnstile")["allowedHostnames"] = []any{"app..example.test"}
			}, issue: "attestation_provider_configuration_invalid",
		},
		{
			name: "Turnstile hostname label too long", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				objectValue(selection, "turnstile")["allowedHostnames"] = []any{strings.Repeat("a", 64) + ".example.test"}
			}, issue: "attestation_provider_configuration_invalid",
		},
		{
			name: "Turnstile hostname duplicate", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				objectValue(selection, "turnstile")["allowedHostnames"] = []any{"app.example.test", "app.example.test"}
			}, schemaReject: true,
		},
		{
			name: "Turnstile action invalid", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				objectValue(selection, "turnstile")["expectedAction"] = "session action"
			}, schemaReject: true,
		},
		{
			name: "Turnstile trust promoted", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { selection["minimumTrustLevel"] = "app_verified" },
			issue:  "attestation_trust_unreachable",
		},
		{
			name: "Turnstile only supports web", platform: "ios", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { delete(selection, "allowedOrigins") },
			issue:  "attestation_provider_platform_mismatch",
		},
		{
			name: "debug trust overstated", platform: "node", selection: validDebugSelection(),
			mutate: func(selection map[string]any) { selection["minimumTrustLevel"] = "app_verified" },
			issue:  "attestation_trust_unreachable",
		},
		{
			name: "disabled web origins forbidden", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				selection["mode"] = "disabled"
				delete(selection, "secretRef")
			}, issue: "attestation_allowed_origins_forbidden",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection := deepClone(test.selection).(map[string]any)
			test.mutate(selection)
			documentObject := configurationWithAttestationSelection(t, test.platform, selection)
			document, marshalErr := json.Marshal(documentObject)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if test.schemaReject {
				if issues := validator.SchemaIssues(document); len(issues) == 0 {
					t.Fatal("unsafe selection satisfied the canonical schema")
				}
				return
			}
			report, compiled := validator.Validate(document, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.issue) {
				t.Fatalf("missing %s in %+v", test.issue, report.Issues)
			}
		})
	}
}

func TestActiveSnapshotRejectsCorruptWebAttestationConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		platform  string
		selection map[string]any
		mutate    func(map[string]any)
	}{
		{
			name: "unknown selection member", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["futureProviderConfiguration"] = true },
		},
		{
			name: "unknown Firebase member", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { objectValue(selection, "firebaseAppCheck")["future"] = true },
		},
		{
			name: "Firebase project overflow", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["projectNumber"] = "18446744073709551616"
			},
		},
		{
			name: "Firebase app IDs wrong type", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				objectValue(selection, "firebaseAppCheck")["allowedAppIds"] = configuredFirebaseAppID
			},
		},
		{
			name: "Firebase secret injected", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["secretRef"] = "secret/present" },
		},
		{
			name: "Firebase web trust promoted", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["minimumTrustLevel"] = "app_verified" },
		},
		{
			name: "Firebase origin removed", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { delete(selection, "allowedOrigins") },
		},
		{
			name: "Firebase origin noncanonical", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://app.example.test/"}
			},
		},
		{
			name: "Firebase null mismatched configuration", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["turnstile"] = nil },
		},
		{
			name: "Firebase null optional field", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["applicationIdentifiers"] = nil },
		},
		{
			name: "provider configurations coexist", platform: "web", selection: validFirebaseAppCheckSelection("web"),
			mutate: func(selection map[string]any) { selection["turnstile"] = validTurnstileConfigurationObject() },
		},
		{
			name: "unknown Turnstile member", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { objectValue(selection, "turnstile")["future"] = true },
		},
		{
			name: "Turnstile secret removed", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) { delete(selection, "secretRef") },
		},
		{
			name: "Turnstile hostname corrupt", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				objectValue(selection, "turnstile")["allowedHostnames"] = []any{"app..example.test"}
			},
		},
		{
			name: "Turnstile origin duplicate", platform: "web", selection: validTurnstileSelection(),
			mutate: func(selection map[string]any) {
				selection["allowedOrigins"] = []any{"https://app.example.test", "https://app.example.test"}
			},
		},
		{
			name: "debug trust unreachable", platform: "node", selection: validDebugSelection(),
			mutate: func(selection map[string]any) { selection["minimumTrustLevel"] = "app_verified" },
		},
	}
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			documentObject := configurationWithAttestationSelection(t, test.platform, test.selection)
			document, marshalErr := json.Marshal(documentObject)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(document, testEnvironment(), time.Now())
			if !report.Valid {
				t.Fatalf("valid base configuration rejected: %+v", report.Issues)
			}
			decoded, decodeErr := jsonsafe.Decode(compiled)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			compiledSpec := objectValue(decoded.(map[string]any), "spec")
			selection := objectValue(
				objectValue(objectArray(compiledSpec, "attestationPolicies")[0], "platforms"), test.platform,
			)
			test.mutate(selection)
			corrupt, corruptErr := json.Marshal(decoded)
			if corruptErr != nil {
				t.Fatal(corruptErr)
			}
			if _, snapshotErr := newActiveSnapshot(
				"rev_00000000000000000000000000", "env_00000000000000000000000000", document, corrupt,
			); snapshotErr == nil {
				t.Fatal("corrupt web attestation snapshot was accepted")
			}
		})
	}
}

func TestCanonicalBrowserHTTPSOrigin(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"https://app.example.test",
		"https://app.example.test:8443",
		"https://127.0.0.1",
		"https://[2001:db8::1]",
	} {
		if !canonicalBrowserHTTPSOrigin(origin) {
			t.Errorf("canonical origin %q was rejected", origin)
		}
	}
	for _, origin := range []string{
		"http://app.example.test",
		"HTTPS://app.example.test",
		"https://App.example.test",
		"https://app.example.test/",
		"https://app.example.test/path",
		"https://app.example.test?query=1",
		"https://app.example.test#fragment",
		"https://user@app.example.test",
		"https://app.example.test:443",
		"https://app.example.test:08443",
		"https://app.example.test.",
		"https://app_name.example.test",
		"https://-app.example.test",
		"https://app-.example.test",
		"https://app..example.test",
		"https://[2001:0db8::1]",
		"https://äpp.example.test",
	} {
		if canonicalBrowserHTTPSOrigin(origin) {
			t.Errorf("noncanonical origin %q was accepted", origin)
		}
	}
}

func configurationWithAttestationSelection(
	t *testing.T,
	platform string,
	selection map[string]any,
) map[string]any {
	t.Helper()
	document := configurationObject(t)
	policy := objectArray(objectValue(document, "spec"), "attestationPolicies")[0]
	policy["platforms"] = map[string]any{platform: deepClone(selection)}
	return document
}

func validFirebaseAppCheckSelection(platform string) map[string]any {
	selection := map[string]any{
		"provider": "firebase_app_check",
		"mode":     "required",
		"firebaseAppCheck": map[string]any{
			"projectNumber": configuredFirebaseProject,
			"allowedAppIds": []any{configuredFirebaseAppID},
		},
	}
	if platform == "web" {
		selection["allowedOrigins"] = []any{"https://app.example.test"}
	}
	return selection
}

func validTurnstileSelection() map[string]any {
	return map[string]any{
		"provider": "turnstile", "mode": "required", "secretRef": "secret/present",
		"allowedOrigins": []any{"https://app.example.test"},
		"turnstile":      validTurnstileConfigurationObject(),
	}
}

func validDebugSelection() map[string]any {
	return map[string]any{
		"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
		"secretRef": "secret/present", "dangerousAllowInProduction": true,
	}
}

func validTurnstileConfigurationObject() map[string]any {
	return map[string]any{
		"allowedHostnames": []any{"app.example.test"},
		"expectedAction":   "latchway_session",
	}
}
