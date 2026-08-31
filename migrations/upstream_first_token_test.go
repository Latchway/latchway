package migrations

import (
	"strings"
	"testing"
)

func TestUpstreamFirstTokenMigrationPreservesFirstByteAndFailsClosed(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000024_upstream_first_token.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, required := range []string{
		"ADD COLUMN first_token_at timestamptz",
		"first_token_at IS NULL",
		"first_byte_at IS NOT NULL",
		"first_token_at >= first_byte_at",
		"first_token_at <= completed_at",
		"upstream_attempts_first_token_analytics_idx",
		"WHERE first_token_at IS NOT NULL",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration omitted %q", required)
		}
	}
	if strings.Contains(sql, "UPDATE upstream_attempts") || strings.Contains(sql, "DROP COLUMN first_byte_at") {
		t.Fatal("migration inferred historical tokens or removed the first-byte accounting boundary")
	}
}
