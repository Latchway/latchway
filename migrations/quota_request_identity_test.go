package migrations

import (
	"strings"
	"testing"
)

func TestQuotaRequestIdentityMigrationLocksTrustedIdentities(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000008_quota_request_identity.sql")
	if err != nil {
		t.Fatalf("read quota request identity migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	required := []string{
		"drop index logical_requests_client_request_idx",
		"create index logical_requests_client_request_idx",
		"where client_request_id is not null",
		"drop constraint logical_requests_feature_key_check",
		"logical_requests_feature_key_identifier_check",
		"feature_key = lower(feature_key)",
		"feature_key ~ '^[a-z][a-z0-9_-]{0,62}$'",
		"quota_reservations_logical_request_key",
		"unique (environment_id, logical_request_id)",
		"if exists (select 1 from quota_buckets limit 1)",
		"using errcode = '23514'",
		"add column limit_plan_key text not null",
		"add column rule_key text not null",
		"add column scope_dimensions text[] not null",
		"quota_buckets_limit_plan_key_identifier_check",
		"^[a-z][a-z0-9_-]{0,62}$",
		"quota_buckets_rule_key_hash_check",
		"quota_buckets_scope_dimensions_check",
		"array_ndims(scope_dimensions) = 1",
		"array_lower(scope_dimensions, 1) = 1",
		"cardinality(scope_dimensions) between 1 and 9",
		"array_position(scope_dimensions, null) is null",
		"quota_buckets_scope_type_dimensions_check",
		"scope_type = 'composite'",
		"scope_dimensions[1] = scope_type",
		"quota_buckets_scope_key_hash_check",
		"^[a-za-z0-9_-]{43}$",
		"drop constraint quota_buckets_environment_id_metric_scope_type_scope_key_al_key",
		"quota_buckets_identity_key",
		"drop index quota_buckets_scope_idx",
		"create index quota_buckets_tenant_scope_idx",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Errorf("quota request identity migration is missing %q", fragment)
		}
	}

	if strings.Contains(sql, "create unique index logical_requests_client_request_idx") {
		t.Error("client request identifier remains an idempotency constraint")
	}
	if strings.Index(sql, "if exists (select 1 from quota_buckets limit 1)") >
		strings.Index(sql, "alter table quota_buckets") {
		t.Error("persisted quota buckets must be rejected before their identity is changed")
	}
	for _, forbidden := range []string{
		"update quota_buckets",
		"delete from quota_buckets",
		"truncate quota_buckets",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("quota identity migration mutates persisted bucket state via %q", forbidden)
		}
	}
}

func TestQuotaBucketIdentityExcludesMutableMaximum(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000008_quota_request_identity.sql")
	if err != nil {
		t.Fatalf("read quota request identity migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	constraintStart := strings.Index(sql, "add constraint quota_buckets_identity_key")
	if constraintStart < 0 {
		t.Fatal("quota bucket identity constraint is missing")
	}
	constraintEnd := strings.Index(sql[constraintStart:], ");")
	if constraintEnd < 0 {
		t.Fatal("quota bucket identity constraint is unterminated")
	}
	identity := sql[constraintStart : constraintStart+constraintEnd]
	for _, required := range []string{
		"environment_id",
		"limit_plan_key",
		"rule_key",
		"metric",
		"algorithm",
		"window_key",
		"scope_key",
	} {
		if !strings.Contains(identity, required) {
			t.Errorf("quota bucket identity is missing %q", required)
		}
	}
	for _, mutable := range []string{
		"hard_maximum",
		"available_units",
		"refill_numerator",
		"refill_denominator",
		"used_units",
		"reserved_units",
	} {
		if strings.Contains(identity, mutable) {
			t.Errorf("quota bucket identity includes mutable state %q", mutable)
		}
	}
}

func TestQuotaScopeDimensionsCoverConfigurationSchema(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000008_quota_request_identity.sql")
	if err != nil {
		t.Fatalf("read quota request identity migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, dimension := range []string{
		"organization",
		"application",
		"environment",
		"user",
		"installation",
		"feature",
		"route",
		"upstream",
		"model",
	} {
		if !strings.Contains(sql, "array_positions(scope_dimensions, '"+dimension+"')") {
			t.Errorf("scope dimension %q is not uniqueness-checked", dimension)
		}
	}
}
