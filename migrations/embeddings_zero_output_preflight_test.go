package migrations

import (
	"strings"
	"testing"
)

func TestEmbeddingsZeroOutputPreflightMigrationIsNarrowAndTransactional(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000016_embeddings_zero_output_preflight.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"drop constraint upstream_attempts_input_accounting_binding_check",
		"add constraint upstream_attempts_input_accounting_binding_check",
		"input_accounting_binding_version = 0",
		"input_accounting_binding_version = 1",
		"input_accounting_method = 'utf8_byte_bpe_declared_framing_v1'",
		"input_token_bound > 0",
		"output_token_bound >= 0",
		"total_token_bound = input_token_bound + output_token_bound",
		"total_token_bound >= input_token_bound",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"output_token_bound > 0", "drop table", "truncate", "delete from",
		"create index concurrently", "alter column input_accounting_binding_version set default 1",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("migration contains forbidden %q", forbidden)
		}
	}
}
