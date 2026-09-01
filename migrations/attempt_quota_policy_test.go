package migrations

import (
	"strings"
	"testing"
)

func TestAttemptQuotaPolicyMigrationOwnsDurableRetryTreatmentAndAttemptMetric(t *testing.T) {
	contents, err := Files.ReadFile("000028_attempt_quota_policy.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	source := strings.ToLower(string(contents))
	for _, required := range []string{
		"cost_retry_treatment",
		"actual_attempts",
		"initial_attempt_only",
		"upstream_attempts",
		"upstream_attempt_quota_entries_metric_check",
		"create or replace function latchway_schema12_attempt_terminal_compat()",
		"entry.origin_attempt_number = 1",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("migration does not contain %q", required)
		}
	}
	compatibilityFunction := source[strings.Index(source, "create or replace function latchway_schema12_attempt_terminal_compat()"):]
	if !strings.Contains(compatibilityFunction, "bucket.metric in (\n          'upstream_attempts'") {
		t.Fatal("schema-12 terminal compatibility expected topology omits upstream_attempts")
	}
}
