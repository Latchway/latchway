package migrations

import (
	"strings"
	"testing"
)

func TestClientDiagnosticsRefreshIndexMigrationIsAdditiveAndBounded(t *testing.T) {
	t.Parallel()

	contents, err := Files.ReadFile("000020_client_diagnostics_refresh_index.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"create index refresh_tokens_client_diagnostics_idx",
		"on refresh_tokens (session_grant_id, expires_at)",
		"where status = 'active'",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("client diagnostics refresh migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"create index concurrently", "drop table", "drop index", "delete from", "truncate", "alter table",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("client diagnostics refresh migration contains forbidden operation %q", forbidden)
		}
	}
}
