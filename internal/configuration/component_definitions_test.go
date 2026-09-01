package configuration

import (
	"encoding/json"
	"testing"
	"time"
)

func TestComponentDefinitionsCompileIntoImmutableRuntimeSnapshot(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	spec := objectValue(document, "spec")
	spec["componentDefinitions"] = validComponentDefinitions()
	objectArray(spec, "features")[0]["access"] = map[string]any{
		"expression": "principal.authenticated && client.component.kind in ['main_app', 'widget'] && client.family.status == 'active'",
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("component configuration rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("rev", "env", encoded, compiled)
	if err != nil {
		t.Fatal(err)
	}
	widget, ok := snapshot.ComponentDefinition("ios-widget")
	if !ok || widget.FamilyRole != "delegated" || widget.Delegation == nil ||
		widget.Delegation.MaximumLifetime != 7*24*time.Hour ||
		len(widget.AllowedFeatures) != 1 || widget.AllowedFeatures[0] != "assistant" {
		t.Fatalf("compiled widget definition = %+v ok=%t", widget, ok)
	}
	widget.AllowedFeatures[0] = "mutated"
	again, _ := snapshot.ComponentDefinition("ios-widget")
	if again.AllowedFeatures[0] != "assistant" {
		t.Fatal("component definition escaped snapshot immutability")
	}
	root, ok := snapshot.RootComponentDefinition("ios", "app_attest", "")
	if !ok || root.ID != "ios-main" {
		t.Fatalf("authoritative App Attest root = %+v ok=%t", root, ok)
	}
	if _, ok := snapshot.RootComponentDefinition("ios", "debug", ""); ok {
		t.Fatal("mismatched attestation provider selected an iOS root")
	}
}

func TestComponentDefinitionSemanticFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code string
		edit func([]any)
	}{
		{
			name: "unknown parent", code: "component_parent_not_found",
			edit: func(definitions []any) {
				objectValue(definitions[1].(map[string]any), "delegation")["allowedParents"] = []any{"missing"}
			},
		},
		{
			name: "unknown feature", code: "component_feature_not_found",
			edit: func(definitions []any) { definitions[1].(map[string]any)["allowedFeatures"] = []any{"missing"} },
		},
		{
			name: "duplicate bundle", code: "component_identifier_duplicate",
			edit: func(definitions []any) {
				objectValue(definitions[1].(map[string]any), "identifiers")["bundleIdentifiers"] = []any{"com.example.habits"}
			},
		},
		{
			name: "unbounded delegation", code: "component_delegation_lifetime_unbounded",
			edit: func(definitions []any) {
				objectValue(definitions[1].(map[string]any), "delegation")["maximumLifetime"] = "31d"
			},
		},
		{
			name: "unsupported direct widget", code: "component_attestation_unsupported",
			edit: func(definitions []any) {
				widget := definitions[1].(map[string]any)
				widget["familyRole"] = "root"
				delete(widget, "delegation")
				widget["attestation"] = map[string]any{"strategy": "direct", "provider": "app_attest"}
			},
		},
		{
			name: "root provider does not match required selection", code: "component_root_attestation_provider_mismatch",
			edit: func(definitions []any) {
				definitions[0].(map[string]any)["attestation"] = map[string]any{
					"strategy": "direct", "provider": "debug",
				}
			},
		},
		{
			name: "root bundle does not match required App Attest selection", code: "component_root_identifier_mismatch",
			edit: func(definitions []any) {
				objectValue(definitions[0].(map[string]any), "identifiers")["bundleIdentifiers"] = []any{
					"com.example.other",
				}
			},
		},
		{
			name: "identity-only root is reserved but unsupported", code: "component_root_identity_only_unsupported",
			edit: func(definitions []any) {
				definitions[0].(map[string]any)["attestation"] = map[string]any{"strategy": "identity_only"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			document := configurationObject(t)
			definitions := validComponentDefinitions()
			test.edit(definitions)
			objectValue(document, "spec")["componentDefinitions"] = definitions
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, _ := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || !hasIssue(report.Issues, test.code) {
				t.Fatalf("issues = %+v, want %s", report.Issues, test.code)
			}
		})
	}
}

func TestComponentDefinitionsRejectAmbiguousNativeRoots(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	definitions := validComponentDefinitions()
	definitions = append(definitions, map[string]any{
		"id": "ios-secondary", "platform": "ios", "kind": "main_app",
		"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.secondary"}},
		"familyRole":      "root",
		"attestation":     map[string]any{"strategy": "direct", "provider": "app_attest"},
		"allowedFeatures": []any{"assistant"},
	})
	objectValue(document, "spec")["componentDefinitions"] = definitions
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "component_root_ambiguous") {
		t.Fatalf("ambiguous native roots compiled: %+v", report.Issues)
	}
}

func TestMultipleWebRootDefinitionsResolveOnlyByExactConfiguredOrigin(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := validWebRootPartitionConfiguration(t)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("exact web root partition rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled,
	)
	if err != nil {
		t.Fatal(err)
	}
	for origin, expectedID := range map[string]string{
		"https://app.example.test":        "web-app",
		"https://admin.example.test:8443": "web-admin",
	} {
		definition, ok := snapshot.RootComponentDefinition("web", "turnstile", origin)
		if !ok || definition.ID != expectedID {
			t.Fatalf("origin %q resolved definition=%+v ok=%t, want %s", origin, definition, ok, expectedID)
		}
	}
	for _, input := range []struct{ provider, origin string }{
		{provider: "debug", origin: "https://app.example.test"},
		{provider: "turnstile", origin: "https://unknown.example.test"},
	} {
		if definition, ok := snapshot.RootComponentDefinition("web", input.provider, input.origin); ok {
			t.Fatalf("untrusted selector %+v resolved root %+v", input, definition)
		}
	}
}

func TestWebRootDefinitionsRejectOverlappingAndUnmappedAllowedOrigins(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		code string
		edit func(map[string]any)
	}{
		{
			name: "overlapping root origin", code: "component_root_origin_ambiguous",
			edit: func(document map[string]any) {
				definitions := objectArray(objectValue(document, "spec"), "componentDefinitions")
				objectValue(definitions[0], "identifiers")["origins"] = []any{
					"https://app.example.test", "https://admin.example.test:8443",
				}
			},
		},
		{
			name: "allowed origin without root", code: "component_root_origin_unmapped",
			edit: func(document map[string]any) {
				spec := objectValue(document, "spec")
				policy := objectArray(spec, "attestationPolicies")[0]
				selection := objectValue(objectValue(policy, "platforms"), "web")
				selection["allowedOrigins"] = []any{
					"https://app.example.test", "https://admin.example.test:8443",
					"https://support.example.test",
				}
				objectValue(selection, "turnstile")["allowedHostnames"] = []any{
					"app.example.test", "admin.example.test", "support.example.test",
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			document := validWebRootPartitionConfiguration(t)
			test.edit(document)
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("web root partition issues=%+v want=%s", report.Issues, test.code)
			}
		})
	}
}

func TestRuntimeSnapshotRejectsOverlappingWebRootOrigins(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := validWebRootPartitionConfiguration(t)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("valid web root partition rejected: %+v", report.Issues)
	}
	var forged map[string]any
	if err := json.Unmarshal(compiled, &forged); err != nil {
		t.Fatal(err)
	}
	definitions := objectArray(objectValue(forged, "spec"), "componentDefinitions")
	objectValue(definitions[0], "identifiers")["origins"] = []any{
		"https://app.example.test", "https://admin.example.test:8443",
	}
	forgedCompiled, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newActiveSnapshot(
		"rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, forgedCompiled,
	); err == nil {
		t.Fatal("compiled snapshot accepted overlapping web root origins")
	}
}

func validWebRootPartitionConfiguration(t *testing.T) map[string]any {
	t.Helper()
	selection := validTurnstileSelection()
	selection["allowedOrigins"] = []any{
		"https://app.example.test", "https://admin.example.test:8443",
	}
	objectValue(selection, "turnstile")["allowedHostnames"] = []any{
		"app.example.test", "admin.example.test",
	}
	document := configurationWithAttestationSelection(t, "web", selection)
	objectValue(document, "spec")["componentDefinitions"] = []any{
		map[string]any{
			"id": "web-app", "platform": "web", "kind": "browser",
			"identifiers":     map[string]any{"origins": []any{"https://app.example.test"}},
			"familyRole":      "root",
			"attestation":     map[string]any{"strategy": "direct", "provider": "turnstile"},
			"allowedFeatures": []any{"assistant"},
		},
		map[string]any{
			"id": "web-admin", "platform": "web", "kind": "browser",
			"identifiers":     map[string]any{"origins": []any{"https://admin.example.test:8443"}},
			"familyRole":      "root",
			"attestation":     map[string]any{"strategy": "direct", "provider": "turnstile"},
			"allowedFeatures": []any{"assistant"},
		},
	}
	return document
}

func TestComponentDefinitionDelegationCycleFails(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	definitions := []any{
		map[string]any{
			"id": "component-a", "platform": "ios", "kind": "widget",
			"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.a"}},
			"familyRole":      "delegated",
			"delegation":      map[string]any{"allowedParents": []any{"component-b"}, "maximumLifetime": "1h", "allowChildDelegation": true},
			"attestation":     map[string]any{"strategy": "delegated"},
			"allowedFeatures": []any{"assistant"},
		},
		map[string]any{
			"id": "component-b", "platform": "ios", "kind": "share_extension",
			"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.b"}},
			"familyRole":      "delegated",
			"delegation":      map[string]any{"allowedParents": []any{"component-a"}, "maximumLifetime": "1h", "allowChildDelegation": true},
			"attestation":     map[string]any{"strategy": "delegated"},
			"allowedFeatures": []any{"assistant"},
		},
	}
	objectValue(document, "spec")["componentDefinitions"] = definitions
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || !hasIssue(report.Issues, "component_delegation_cycle") {
		t.Fatalf("issues = %+v, want delegation cycle", report.Issues)
	}
}

func TestNestedComponentDelegationFailsClosedForV1(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	definitions := validComponentDefinitions()
	delegatedParent := definitions[1].(map[string]any)
	delegatedParent["delegation"].(map[string]any)["allowChildDelegation"] = true
	definitions = append(definitions, map[string]any{
		"id": "ios-share", "platform": "ios", "kind": "share_extension",
		"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.habits.share"}},
		"familyRole":      "delegated",
		"delegation":      map[string]any{"allowedParents": []any{"ios-widget"}, "maximumLifetime": "1h"},
		"attestation":     map[string]any{"strategy": "delegated"},
		"allowedFeatures": []any{"assistant"},
	})
	objectValue(document, "spec")["componentDefinitions"] = definitions
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || !hasIssue(report.Issues, "component_child_delegation_unsupported") ||
		!hasIssue(report.Issues, "component_parent_delegation_forbidden") {
		t.Fatalf("issues = %+v, want unsupported nested delegation errors", report.Issues)
	}
}

func validComponentDefinitions() []any {
	return []any{
		map[string]any{
			"id": "ios-main", "platform": "ios", "kind": "main_app",
			"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.habits"}},
			"familyRole":      "root",
			"attestation":     map[string]any{"strategy": "direct", "provider": "app_attest"},
			"allowedFeatures": []any{"assistant"},
		},
		map[string]any{
			"id": "ios-widget", "platform": "ios", "kind": "widget",
			"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.habits.widget"}},
			"familyRole":      "delegated",
			"delegation":      map[string]any{"allowedParents": []any{"ios-main"}, "maximumLifetime": "7d"},
			"attestation":     map[string]any{"strategy": "delegated"},
			"allowedFeatures": []any{"assistant"},
		},
	}
}
