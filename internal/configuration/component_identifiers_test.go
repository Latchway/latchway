package configuration

import (
	"encoding/json"
	"testing"
	"time"
)

func sharedIOSRootDocument(t *testing.T) map[string]any {
	t.Helper()
	document := configurationObject(t)
	spec := objectValue(document, "spec")
	definitions := validComponentDefinitions()
	rn := deepClone(definitions[0]).(map[string]any)
	rn["id"], rn["platform"] = "rn-main", "react_native_ios"
	spec["componentDefinitions"] = append(definitions, rn)
	for _, policy := range objectArray(spec, "attestationPolicies") {
		platforms := objectValue(policy, "platforms")
		if ios, ok := platforms["ios"]; ok {
			platforms["react_native_ios"] = deepClone(ios)
		}
	}
	return document
}

func TestNativeReactNativeSharedBundleResolvesExactPlatform(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(sharedIOSRootDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("shared root pair rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("rev", "env", encoded, compiled)
	if err != nil {
		t.Fatal(err)
	}
	for platform, id := range map[string]string{"ios": "ios-main", "react_native_ios": "rn-main"} {
		root, ok := snapshot.RootComponentDefinition(platform, "app_attest", "")
		if !ok || root.ID != id || root.Platform != platform {
			t.Fatalf("%s selected %+v, ok=%t", platform, root, ok)
		}
		if _, ok := snapshot.RootComponentDefinition(platform, "debug", ""); ok {
			t.Fatal("wrong provider selected root")
		}
	}
	if _, ok := snapshot.RootComponentDefinition("watchos", "app_attest", ""); ok {
		t.Fatal("unconfigured platform selected root")
	}
}

func TestSharedRootBundleStillRejectsAmbiguityAndDelegatedOverlap(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"third root", "delegated overlap", "watch root", "wrong provider", "mismatched attested bundle"} {
		t.Run(name, func(t *testing.T) {
			document := sharedIOSRootDocument(t)
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(baseline, testEnvironment(), time.Now())
			if !report.Valid {
				t.Fatalf("invalid baseline: %+v", report.Issues)
			}
			if _, err := newActiveSnapshot("rev", "env", baseline, compiled); err != nil {
				t.Fatal(err)
			}
			var runtimeDocument map[string]any
			if err := json.Unmarshal(compiled, &runtimeDocument); err != nil {
				t.Fatal(err)
			}
			mutate := func(document map[string]any) {
				spec := objectValue(document, "spec")
				definitions := objectArray(spec, "componentDefinitions")
				switch name {
				case "third root":
					third := deepClone(definitions[0]).(map[string]any)
					third["id"] = "third-main"
					spec["componentDefinitions"] = append(spec["componentDefinitions"].([]any), third)
				case "delegated overlap":
					objectValue(definitions[1], "identifiers")["bundleIdentifiers"] = []any{"com.example.habits"}
				case "watch root":
					definitions[2]["platform"] = "watchos"
				case "wrong provider":
					objectValue(definitions[2], "attestation")["provider"] = "debug"
				case "mismatched attested bundle":
					for _, policy := range objectArray(spec, "attestationPolicies") {
						platforms := objectValue(policy, "platforms")
						if raw, ok := platforms["react_native_ios"].(map[string]any); ok {
							objectValue(raw, "appAttest")["bundleId"] = "com.example.other"
						}
					}
				}
			}
			mutate(document)
			mutate(runtimeDocument)
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, _ = validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid {
				t.Fatal("unsafe overlap accepted by validator")
			}
			// Exercise runtime revalidation independently, bypassing compilation.
			corrupt, err := json.Marshal(runtimeDocument)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newActiveSnapshot("rev", "env", encoded, corrupt); err == nil {
				t.Fatal("unsafe overlap accepted by runtime")
			}
		})
	}
}
