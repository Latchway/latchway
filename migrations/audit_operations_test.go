package migrations

import (
	"strings"
	"testing"
)

func TestAuditOperationsMigrationKeepsMetadataBoundedAndValueFree(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000027_audit_operations.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"source IN ('console', 'cli', 'api', 'system')",
		"char_length(reason) BETWEEN 1 AND 100",
		"replace(reason, '.', '_')",
		"normalize_system_audit_source",
		"audit_events_normalize_system_source",
		"BEFORE INSERT ON audit_events",
		"audit_events_system_source_check",
		"CHECK ((source = 'system') = (actor_kind = 'system'))",
		"audit_events_external_source_check",
		"audit_events_environment_time_idx",
		"audit_events_browse_idx",
		"audit_events_actor_time_idx",
		"audit_events_resource_time_idx",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("audit-operations migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{"before_value", "after_value", "request_body", "response_body"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("audit-operations migration introduced unsafe value storage %q", forbidden)
		}
	}
}
