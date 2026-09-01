package migrations

import (
	"strings"
	"testing"
)

func TestLogicalRequestDecisionLifecycleMigrationIsDurableBoundedAndAppendOnly(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000026_logical_request_decision_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"'authenticated'",
		"create table logical_request_decision_stages",
		"stage_number between 1 and 256",
		"'identity_verified'",
		"'client_trust_verified'",
		"'policy_evaluated'",
		"'quota_rule_evaluated'",
		"'lifecycle_recovered'",
		"config_revision_id text not null",
		"limit_rule_key text",
		"selected_route_key text",
		"logical_requests_decision_revision_key",
		"logical_requests_authenticated_recovery_idx",
		"drop constraint jobs_job_type_check",
		"'recover_stale_authenticated_requests'",
		"on delete cascade",
		"pg_trigger_depth() > 1",
		"before update or delete on logical_request_decision_stages",
		"logical request decision stages are append-only",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"request_body text", "response_body text", "prompt text", "credential text", "attestation_evidence text",
		"delete from", "truncate", "drop table", "create index concurrently",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("migration contains forbidden persistence surface %q", forbidden)
		}
	}
}
