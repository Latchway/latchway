package migrations

import (
	"strings"
	"testing"
)

func TestAttemptTerminalValidationMigrationPreservesChecksAndRepair(t *testing.T) {
	oldBytes, err := Files.ReadFile("000028_attempt_quota_policy.sql")
	if err != nil {
		t.Fatal(err)
	}
	newBytes, err := Files.ReadFile("000029_attempt_terminal_validation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old, candidate := string(oldBytes), string(newBytes)
	start := "CREATE OR REPLACE FUNCTION latchway_schema12_attempt_terminal_compat()"
	if strings.Count(candidate, start) != 1 {
		t.Fatal("candidate must replace only the existing function")
	}
	for _, forbidden := range []string{"ALTER TABLE", "CREATE TABLE", "CREATE TRIGGER", "DROP ", "CREATE INDEX", "SET CONSTRAINTS", "FOR UPDATE", "SECURITY DEFINER"} {
		if strings.Contains(candidate, forbidden) {
			t.Fatalf("candidate changes schema/locking boundary: %s", forbidden)
		}
	}
	previous := -1
	for _, message := range []string{
		"legacy terminal attempt ledger is incomplete",
		"legacy terminal attempt ledger has invalid allocation binding",
		"settled legacy attempt has incoherent aggregate lifecycle",
		"legacy terminal attempt ledger disagrees with reservation",
		"legacy terminal attempt requires coherent terminal reservation",
		"legacy terminal attempt ledger update is incomplete",
	} {
		position := strings.Index(candidate, "RAISE EXCEPTION '"+message+"'")
		if position <= previous || strings.Count(candidate, "RAISE EXCEPTION '"+message+"'") != 1 || !strings.Contains(old, message) {
			t.Fatalf("changed exception precedence: %s", message)
		}
		previous = position
	}
	if strings.Count(candidate, "USING ERRCODE = '23514'") != 6 {
		t.Fatal("changed fixed constraint-error mapping")
	}
	repair := "    UPDATE upstream_attempt_quota_entries AS quota\n"
	oldRepair := old[strings.LastIndex(old, repair):]
	oldRepair = oldRepair[:strings.Index(oldRepair, "$$;")+3]
	newRepair := candidate[strings.LastIndex(candidate, repair):]
	newRepair = newRepair[:strings.Index(newRepair, "$$;")+3]
	if oldRepair != newRepair {
		t.Fatal("legacy repair and actual ROW_COUNT check must remain byte-identical")
	}
	for _, required := range []string{
		"ledger_count integer;", "expected_count integer;", "settled_count integer;",
		"scoped_reservation AS MATERIALIZED", "scoped_ledger AS MATERIALIZED",
		"FROM scoped_ledger\n    )", "LEFT JOIN aggregate_state ON true",
		"bucket.quota_bucket_id IS NOT NULL AND (", "quota.metric <> bucket.metric",
		"quota.allocated_units <> entry.initial_reserved_units", "entry.origin_attempt_number <> 1",
		"quota.charged_units <> entry.settled_units", "quota.released_units <> entry.released_units",
		"quota.settled_at IS DISTINCT FROM NEW.completed_at", "COALESCE(bool_or(",
		"IF settled_count = ledger_count THEN", "entry.origin_attempt_number = 1",
		"'upstream_attempts'", "'input_tokens'", "'output_tokens'", "'total_tokens'", "'cost_nano_usd'",
	} {
		if !strings.Contains(candidate, required) {
			t.Fatalf("missing invariant expression: %s", required)
		}
	}
}
