package migrations

import (
	"strings"
	"testing"
)

func TestUpstreamAttemptAccountingMigrationIsBoundedAndRelationallyClosed(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000012_upstream_attempt_accounting.sql")
	if err != nil {
		t.Fatalf("read upstream-attempt accounting migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"add column initial_reserved_units bigint",
		"set initial_reserved_units = reserved_units",
		"add column origin_attempt_number integer not null default 1",
		"attempt_number between 1 and 32",
		"add column model_key text",
		"attempt_decision_binding_version smallint not null default 0",
		"add column per_request_output_token_bound bigint",
		"upstream_attempts_decision_binding_check",
		"octet_length(attempt_decision_sha256) = 32",
		"input_accounting_binding_version smallint not null default 0",
		"upstream_attempts_input_accounting_binding_check",
		"create table upstream_attempt_quota_entries",
		"upstream_attempt_quota_entries_attempt_fkey",
		"upstream_attempt_quota_entries_request_reservation_fkey",
		"upstream_attempt_quota_entries_reservation_entry_fkey",
		"quota_reservations_attempt_binding_key",
		"quota_reservation_entries_attempt_binding_key",
		"usage_records_request_attempt_fkey",
		"having count(*) > 1",
		"where attempt_number <> 1",
		"using errcode = '23514'",
		"entry.initial_reserved_units",
		"where bucket.metric in ('input_tokens', 'output_tokens', 'total_tokens', 'cost_nano_usd')",
		"quota_reservation_entries_schema11_insert_compat",
		"upstream_attempts_schema11_insert_compat",
		"upstream_attempts_schema11_terminal_compat",
		"deferrable initially deferred",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("upstream-attempt accounting migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"update usage_records",
		"delete from usage_records",
		"truncate usage_records",
		"delete from upstream_attempts",
		"truncate upstream_attempts",
		"alter column attempt_decision_binding_version set default 1",
		"alter column input_accounting_binding_version set default 1",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("upstream-attempt accounting migration contains unsafe rewrite %q", forbidden)
		}
	}
}
