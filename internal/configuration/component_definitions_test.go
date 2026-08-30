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
