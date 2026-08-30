package migrations

import (
	"strings"
	"testing"
)

func TestQuotaComponentScopesMigrationIsForwardOnlyAndCanonical(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000022_quota_component_scopes.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"cardinality(scope_dimensions) between 1 and 16",
		"cardinality(scope_dimensions) between 2 and 16",
		"(installation\\n)?(installation_family\\n)?(client_component\\n)?",
		"(component_definition\\n)?(component_kind\\n)?(trust_source\\n)?(feature\\n)?",
		"'installation_family', 'client_component'",
		"'component_definition', 'component_kind', 'trust_source'",
		"logical_requests_component_attribution_check",
		"logical_requests_framework_attribution_check",
		"'swift-openai', 'vercel-ai-sdk'",
		"trust_source is not null",
		"framework is not null",
		"framework_version is not null",
		"char_length(framework_version) between 5 and 128",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema-22 migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"update quota_buckets",
		"delete from quota_buckets",
		"truncate quota_buckets",
		"select dimension from unnest(scope_dimensions)",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("schema-22 migration contains forbidden state rewrite/subquery %q", forbidden)
		}
	}
	ordered := []string{
		"(installation\\n)?",
		"(installation_family\\n)?",
		"(client_component\\n)?",
		"(component_definition\\n)?",
		"(component_kind\\n)?",
		"(trust_source\\n)?",
		"(feature\\n)?",
	}
	for index := 1; index < len(ordered); index++ {
		if strings.Index(sql, ordered[index-1]) >= strings.Index(sql, ordered[index]) {
			t.Fatalf("database scope constraint does not preserve canonical order at %q then %q",
				ordered[index-1], ordered[index])
		}
	}
}
