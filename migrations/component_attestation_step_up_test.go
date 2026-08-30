package migrations

import (
	"strings"
	"testing"
)

func TestComponentAttestationStepUpMigrationKeepsRootAndComponentScopesDistinct(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000023_component_attestation_step_up.sql")
	if err != nil {
		t.Fatalf("read component attestation migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"create table component_attestation_challenges",
		"component_attestation_challenge_id text primary key",
		"component_key_id text not null",
		"binding_hash bytea not null",
		"attestation_provider text not null check (attestation_provider = 'app_attest')",
		"attestation_mode text not null check (attestation_mode = 'required')",
		"foreign key (client_component_id, component_key_id)",
		"add column installation_family_id text",
		"add column client_component_id text",
		"add column component_key_id text",
		"attestation_keys_component_scope_fkey",
		"attestation_keys_component_key_scope_fkey",
		"installation_id is not null",
		"installation_id is null",
		"old.linked_at is not null",
		"delegated_direct_attested",
		"session_grants_trust_source_check",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema-23 migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"drop table attestation_keys",
		"drop table client_components",
		"delete from attestation_keys",
		"delete from client_components",
		"truncate ",
		"drop column installation_id",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("schema-23 migration contains destructive operation %q", forbidden)
		}
	}
}
