package configuration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetupWizardNativeTemplateIsActivatable(t *testing.T) {
	t.Parallel()

	document, err := os.ReadFile(filepath.Join(
		"..", "..", "web", "console", "src", "pages", "native-template.fixture.json",
	))
	if err != nil {
		t.Fatalf("read setup-wizard fixture: %v", err)
	}
	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	if issues := validator.SchemaIssues(document); len(issues) != 0 {
		t.Fatalf("setup-wizard fixture is not schema-valid: %+v", issues)
	}
	environment := testEnvironment()
	environment.ApplicationSlug = "mobile-app"
	report, compiled := validator.Validate(document, environment, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC))
	if !report.Valid {
		t.Fatalf("setup-wizard fixture cannot activate: %+v", report.Issues)
	}
	if _, err := newActiveSnapshot("rev_setup_wizard", environment.EnvironmentID, document, compiled); err != nil {
		t.Fatalf("setup-wizard fixture cannot load as an active snapshot: %v", err)
	}
}
