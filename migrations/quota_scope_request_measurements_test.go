package migrations

import (
	"strings"
	"testing"
)

func TestQuotaScopeRequestMeasurementMigrationIsForwardOnlyAndCanonical(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000018_quota_scope_request_measurements.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"cardinality(scope_dimensions) between 1 and 11",
		"(organization\\n)?(application\\n)?(environment\\n)?(user\\n)?",
		"(model\\n)?(platform\\n)?(normalized_claim:",
		"scope_type = 'normalized_claim'",
		"request_measurement_binding_version smallint not null default 0",
		"request_measurement_sha256 bytea",
		"measured_request_bytes bigint",
		"measured_image_units bigint",
		"measured_tool_calls bigint",
		"measured_request_bytes between 0 and 104857600",
		"measured_image_units is null or measured_image_units between 0 and 1000000",
		"measured_tool_calls is null or measured_tool_calls between 0 and 1000000",
		"attempt_decision_binding_version in (1, 2)",
		"attempt_decision_binding_version = 2 and request_measurement_binding_version = 1",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema-18 migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"update quota_buckets",
		"delete from quota_buckets",
		"truncate quota_buckets",
		"select dimension from unnest(scope_dimensions)",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("schema-18 migration contains forbidden state rewrite/subquery %q", forbidden)
		}
	}
	if strings.Index(sql, "(organization\\n)?") > strings.Index(sql, "(platform\\n)?") ||
		strings.Index(sql, "(platform\\n)?") > strings.Index(sql, "(normalized_claim:") {
		t.Fatal("database scope constraint does not preserve canonical dimension order")
	}
}
