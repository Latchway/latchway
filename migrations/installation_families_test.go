package migrations

import (
	"strings"
	"testing"
)

func TestInstallationFamilyMigrationHasIndependentTrustAndRefreshBoundaries(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000021_installation_families.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"create table installation_families",
		"create table component_definitions",
		"create table client_components",
		"create table component_keys",
		"create table component_delegations",
		"create table component_session_families",
		"create table component_refresh_tokens",
		"create table refresh_rotation_results",
		"unique (root_installation_id)",
		"delegated_from_attested_root",
		"old_refresh_token_hash bytea not null unique",
		"rotation_response_ciphertext bytea not null",
		"expires_at <= created_at + interval '5 minutes'",
		"create unique index component_refresh_tokens_one_active_family_idx",
		"add column installation_family_id text",
		"add column client_component_id text",
		"add column framework_version text",
		"from installations as i",
		"insert into component_refresh_tokens",
		"latest_active.refresh_token_id",
		"update attestation_events as event",
		"update logical_requests as request",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema-21 migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"private_key",
		"provider_credential",
		"delete from installations",
		"update installations",
		"delete from refresh_tokens",
		"update session_grants",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("schema-21 migration contains forbidden material or legacy rewrite %q", forbidden)
		}
	}
}
