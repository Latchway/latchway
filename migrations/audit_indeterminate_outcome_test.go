package migrations

import (
	"strings"
	"testing"
)

func TestAuditIndeterminateOutcomeMigration(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000011_audit_indeterminate_outcome.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"DROP CONSTRAINT audit_events_outcome_check",
		"'succeeded', 'denied', 'failed', 'indeterminate'",
		"COMMENT ON CONSTRAINT audit_events_outcome_check",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("audit-outcome migration is missing %q", required)
		}
	}
}
