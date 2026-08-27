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

func TestSessionBindingMigrationSeparatesAuditAndEphemeralRetention(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000005_session_challenge_binding.sql")
	if err != nil {
		t.Fatalf("read session binding migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"add column challenge_nonce",
		"add column identity_provider_key",
		"add column identity_expires_at",
		"add column attestation_expires_at",
		"set status = 'revoked'",
		"revoke_reason = coalesce(revoke_reason, 'schema_upgrade_v5')",
		"attested_at = null",
		"add column installation_id",
		"set installation_id = session_grant.installation_id",
		"alter column installation_id set not null",
		"dpop_replay_entries_installation_fkey",
		"drop constraint dpop_replay_entries_session_grant_id_proof_jti_hash_key",
		"unique (installation_id, proof_jti_hash)",
		"constraint_entry.confrelid = 'session_challenges'::regclass",
		"alter table attestation_events drop constraint",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("session binding migration is missing %q", required)
		}
	}
}

func TestSessionChallengePolicyMigrationFailsClosed(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000006_session_challenge_policy.sql")
	if err != nil {
		t.Fatalf("read challenge policy migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"delete from session_challenge_consumptions",
		"delete from session_challenges",
		"add column config_revision_id",
		"add column attestation_policy_id",
		"add column attestation_provider",
		"add column attestation_mode",
		"add column attestation_minimum_trust_level",
		"add column attestation_maximum_age_milliseconds",
		"add column challenge_dpop_proof_jti_hash",
		"add column challenge_dpop_http_uri_hash",
		"session_challenges_config_revision_fkey",
		"session_challenges_dpop_proof_unique",
		"unique (\n            environment_id,\n            dpop_jkt,\n            challenge_dpop_proof_jti_hash",
		"installations_app_version_length_check",
		"char_length(app_version) between 1 and 128",
		"installations_key_storage_check",
		"'unknown'",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("challenge policy migration is missing %q", required)
		}
	}
	if strings.Index(sql, "delete from session_challenge_consumptions") > strings.Index(sql, "delete from session_challenges") {
		t.Error("challenge consumptions must be invalidated before their parent challenges")
	}
	for _, forbidden := range []string{
		"add column challenge_dpop_proof_jti text",
		"add column challenge_dpop_http_uri text",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("challenge policy migration persists raw DPoP material via %q", forbidden)
		}
	}
}

func TestIdentityProviderIdentifierMigrationLocksPersistedBounds(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000007_identity_provider_identifier_bounds.sql")
	if err != nil {
		t.Fatalf("read identity-provider identifier migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"from identity_provider_states",
		"from external_identities",
		"from session_challenges",
		"from session_grants",
		"using errcode = '23514'",
		"drop constraint identity_provider_states_provider_key_check",
		"drop constraint external_identities_provider_key_check",
		"drop constraint session_challenges_identity_provider_key_check",
		"drop constraint session_grants_identity_provider_key_check",
		"identity_provider_states_provider_key_identifier_check",
		"external_identities_provider_key_identifier_check",
		"session_challenges_identity_provider_key_identifier_check",
		"session_grants_identity_provider_key_identifier_check",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("identity-provider identifier migration is missing %q", required)
		}
	}
	if strings.Count(sql, "^[a-z][a-z0-9_-]{0,62}$") != 8 {
		t.Errorf("identity-provider identifier migration must apply the locked expression to four preflight checks and four constraints")
	}
	if strings.Index(sql, "raise exception") > strings.Index(sql, "drop constraint") {
		t.Error("invalid persisted identifiers must be detected before replacing constraints")
	}
}
