package migrations

import (
	"strings"
	"testing"
)

func TestLogicalRequestFingerprintMigrationIsBoundedAndLegacyNullable(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000009_logical_request_fingerprint.sql")
	if err != nil {
		t.Fatalf("read logical request fingerprint migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"alter table logical_requests",
		"add column trusted_decision_fingerprint text",
		"logical_requests_trusted_decision_fingerprint_check",
		"trusted_decision_fingerprint is null",
		"trusted_decision_fingerprint ~ '^[a-za-z0-9_-]{43}$'",
		") not valid",
		"comment on column logical_requests.trusted_decision_fingerprint",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("logical request fingerprint migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"trusted_decision_fingerprint text not null",
		"update logical_requests",
		"delete from logical_requests",
		"validate constraint logical_requests_trusted_decision_fingerprint_check",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("logical request fingerprint migration contains unsafe legacy rewrite %q", forbidden)
		}
	}
}
