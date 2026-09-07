package configuration

import (
	"encoding/json"
	"testing"
	"time"
)

func sharedAndroidRootDocument(t *testing.T) map[string]any {
	t.Helper()
	document := sharedIOSRootDocument(t)
	spec := objectValue(document, "spec")
	for _, policy := range objectArray(spec, "attestationPolicies") {
		platforms := objectValue(policy, "platforms")
		if android, ok := platforms["android"].(map[string]any); ok {
			objectValue(android, "playIntegrity")["packageName"] = "com.example.habits.android"
			platforms["react_native_android"] = deepClone(android)
		}
	}
	for _, platform := range []string{"android", "react_native_android"} {
		spec["componentDefinitions"] = append(spec["componentDefinitions"].([]any), map[string]any{
			"id": platform + "-root", "platform": platform, "kind": "android_app", "familyRole": "root",
			"identifiers":     map[string]any{"packageNames": []any{"com.example.habits.android"}},
			"attestation":     map[string]any{"strategy": "direct", "provider": "play_integrity"},
			"allowedFeatures": []any{"assistant"},
		})
	}
	return document
}

func TestNativeReactNativeSharedAndroidPackageResolvesExactPlatform(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(sharedAndroidRootDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("shared Android package rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("rev", "env", encoded, compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"ios", "react_native_ios", "android", "react_native_android"} {
		provider, want := "play_integrity", platform+"-root"
		if platform == "ios" {
			provider, want = "app_attest", "ios-main"
		}
		if platform == "react_native_ios" {
			provider, want = "app_attest", "rn-main"
		}
		root, ok := snapshot.RootComponentDefinition(platform, provider, "")
		if !ok || root.ID != want || root.Platform != platform {
			t.Fatalf("%s resolved %+v, ok=%t", platform, root, ok)
		}
		if _, ok := snapshot.RootComponentDefinition(platform, "debug", ""); ok {
			t.Fatal("wrong provider selected root")
		}
	}
}

func TestSharedAndroidPackageRejectsUnsafeOverlapsInValidatorAndRuntime(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"third root", "same platform", "delegated overlap", "wear root", "wrong provider", "wrong package", "identity only", "wrong kind"} {
		t.Run(name, func(t *testing.T) {
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			document := sharedAndroidRootDocument(t)
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
			mutate := func(target map[string]any) {
				spec := objectValue(target, "spec")
				var rn map[string]any
				for _, def := range objectArray(spec, "componentDefinitions") {
					if def["id"] == "react_native_android-root" {
						rn = def
					}
				}
				if rn == nil {
					t.Fatal("missing fixture root")
				}
				switch name {
				case "third root":
					third := deepClone(rn).(map[string]any)
					third["id"] = "third-android"
					spec["componentDefinitions"] = append(spec["componentDefinitions"].([]any), third)
				case "same platform":
					rn["platform"] = "android"
				case "delegated overlap":
					rn["familyRole"] = "delegated"
					rn["attestation"] = map[string]any{"strategy": "delegated"}
					rn["delegation"] = map[string]any{"allowedParents": []any{"android-root"}, "maximumLifetime": "1h"}
				case "wear root":
					rn["platform"] = "wearos"
				case "wrong provider":
					objectValue(rn, "attestation")["provider"] = "debug"
				case "wrong package":
					objectValue(rn, "identifiers")["packageNames"] = []any{"com.example.other"}
				case "identity only":
					rn["attestation"] = map[string]any{"strategy": "identity_only"}
				case "wrong kind":
					rn["kind"] = "wear_app"
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
				t.Fatal("unsafe Android overlap accepted by validator")
			}
			corrupt, err := json.Marshal(runtimeDocument)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newActiveSnapshot("rev", "env", encoded, corrupt); err == nil {
				t.Fatal("unsafe Android overlap accepted by runtime")
			}
		})
	}
}
