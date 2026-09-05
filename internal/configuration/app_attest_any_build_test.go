package configuration

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAppAttestAnyBuildConfiguration(t *testing.T) {
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		versions []any
		valid    bool
	}{
		{name: "explicit any", versions: []any{"*"}, valid: true},
		{name: "exact allowlist", versions: []any{"100", "101"}, valid: true},
		{name: "mixed wildcard", versions: []any{"*", "100"}},
		{name: "empty", versions: []any{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := configurationObject(t)
			selection := objectValue(objectValue(objectArray(objectValue(root, "spec"), "attestationPolicies")[0], "platforms"), "ios")
			objectValue(selection, "appAttest")["allowedBundleVersions"] = test.versions
			encoded, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid != test.valid {
				t.Fatalf("valid = %v, want %v: %+v", report.Valid, test.valid, report.Issues)
			}
			if test.valid {
				if _, err := newActiveSnapshot("rev_any_build", testEnvironment().EnvironmentID, encoded, compiled); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
