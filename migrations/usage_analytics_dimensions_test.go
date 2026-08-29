package migrations

import (
	"strings"
	"testing"
)

func TestUsageAnalyticsDimensionsMigrationPersistsSelectedPlanWithoutInference(t *testing.T) {
	contents, err := Files.ReadFile("000017_usage_analytics_dimensions.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, required := range []string{
		"selected_limit_plan_key text NOT NULL DEFAULT 'legacy_unknown'",
		"logical_requests_usage_analytics_idx",
		"upstream_attempts_usage_analytics_idx",
		"attestation_events_usage_analytics_idx",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("usage analytics migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{"UPDATE logical_requests", "DROP COLUMN", "DELETE FROM"} {
		if strings.Contains(strings.ToUpper(sql), strings.ToUpper(forbidden)) {
			t.Errorf("usage analytics migration contains unsafe historical rewrite %q", forbidden)
		}
	}
}
