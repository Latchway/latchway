package migrations

import (
	"strings"
	"testing"
)

func TestDomainFoundationMigrationDeclaresRequiredTables(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000002_domain_foundation.sql")
	if err != nil {
		t.Fatalf("read domain migration: %v", err)
	}
	sql := string(contents)
	required := []string{
		"organizations",
		"applications",
		"environments",
		"admin_users",
		"admin_password_credentials",
		"admin_sessions",
		"admin_memberships",
		"admin_api_tokens",
		"config_revisions",
		"active_config_revisions",
		"secret_records",
		"gateway_signing_keys",
		"identity_provider_states",
		"application_users",
		"external_identities",
		"user_overrides",
		"installations",
		"attestation_keys",
		"attestation_events",
		"session_challenges",
		"session_grants",
		"refresh_tokens",
		"dpop_replay_entries",
		"quota_buckets",
		"quota_reservations",
		"quota_reservation_entries",
		"concurrency_leases",
		"logical_requests",
		"upstream_attempts",
		"usage_records",
		"usage_rollups_hourly",
		"usage_rollups_daily",
		"jobs",
		"audit_events",
	}
	for _, table := range required {
		if !strings.Contains(sql, "CREATE TABLE "+table+" ") {
			t.Errorf("migration does not create required table %s", table)
		}
	}
}

func TestDomainFoundationMigrationAvoidsForbiddenPrimitives(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000002_domain_foundation.sql")
	if err != nil {
		t.Fatalf("read domain migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, forbidden := range []string{
		"create extension",
		"drop table",
		"double precision",
		" real ",
		"money",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("migration contains forbidden primitive %q", forbidden)
		}
	}
	if !strings.Contains(sql, "cost_nano_usd bigint") {
		t.Error("migration does not represent costs as bigint nano-USD")
	}
}

func TestDomainFoundationMigrationUsesContractIDPrefixes(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000002_domain_foundation.sql")
	if err != nil {
		t.Fatalf("read domain migration: %v", err)
	}
	sql := string(contents)
	for _, prefix := range []string{"^adm_", "^tok_", "^rev_", "^chl_"} {
		if !strings.Contains(sql, prefix) {
			t.Errorf("migration does not enforce contract prefix %q", prefix)
		}
	}
	for _, obsolete := range []string{"^adu_", "^aap_", "^cfg_", "^sch_"} {
		if strings.Contains(sql, obsolete) {
			t.Errorf("migration still contains obsolete prefix %q", obsolete)
		}
	}
}
