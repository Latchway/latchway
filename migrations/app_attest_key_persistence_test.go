package migrations

import (
	"strings"
	"testing"
)

func TestAppAttestKeyPersistenceMigrationKeepsPreSessionScopeClosed(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000013_app_attest_key_persistence.sql")
	if err != nil {
		t.Fatalf("read App Attest key migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"alter column installation_id drop not null",
		"add column application_user_id text",
		"add column binding_environment text",
		"add column platform text",
		"add column dpop_jkt text",
		"add column provider_key_hash bytea",
		"add column app_id_hash bytea",
		"add column last_assertion_hash bytea",
		"add column extensions_present boolean",
		"add column validation_category bigint",
		"add column bundle_version text",
		"add column attested_at_unix_seconds bigint",
		"add column attested_at_nanosecond integer",
		"attestation_keys_environment_scope_fkey",
		"attestation_keys_principal_scope_fkey",
		"attestation_keys_binding_environment_fkey",
		"attestation_keys_installation_scope_fkey",
		"attestation_keys_pre_session_provider_check",
		"attestation_keys_app_attest_retry_hash_provider_check",
		"attestation_keys_link_state_check",
		"attestation_keys_app_attest_state_check",
		"provider_key_hash <> decode(repeat('00', 32), 'hex')",
		"app_id_hash <> decode(repeat('00', 32), 'hex')",
		"sign_count between 0 and 4294967295",
		"sign_count = 0",
		"last_assertion_hash is null",
		"octet_length(last_assertion_hash) = 32",
		"last_assertion_hash <> decode(repeat('00', 32), 'hex')",
		"attested_at_unix_seconds is not null",
		"attested_at_nanosecond is not null",
		"validation_category is not null",
		"create unique index attestation_keys_app_attest_provider_key_hash_idx",
		"where provider = 'app_attest' and provider_key_hash is not null",
		"create index attestation_keys_unlinked_app_attest_cleanup_idx",
		"create table app_attest_key_commit_receipts",
		"octet_length(commit_token) = 32",
		"commit_token <> decode(repeat('00', 32), 'hex')",
		"app_attest_key_commit_receipts_key_scope_fkey",
		"references attestation_keys",
		") on delete cascade",
		"check (expires_at > committed_at)",
		"create index app_attest_key_commit_receipts_expiry_idx",
		"create index app_attest_key_commit_receipts_key_scope_idx",
		"create function enforce_attestation_key_lifecycle()",
		"attestation_keys_immutable_scope_check",
		"attestation_keys_immutable_link_check",
		"attestation_keys_terminal_status_check",
		"attestation_keys_app_attest_counter_monotonic_check",
		"attestation_keys_app_attest_same_counter_state_check",
		"attestation_keys_app_attest_counter_hash_check",
		"create trigger attestation_keys_lifecycle_guard",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("App Attest key migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"drop table attestation_keys",
		"delete from attestation_keys",
		"truncate attestation_keys",
		"drop column installation_id",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("App Attest key migration contains destructive operation %q", forbidden)
		}
	}
}
