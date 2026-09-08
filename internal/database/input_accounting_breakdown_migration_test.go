package database

import (
	"strings"
	"testing"

	"github.com/latchway/latchway/migrations"
)

func TestMigratorPostgreSQLInputAccountingBreakdownPreservesHistoricalAttempts(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	if _, err := pool.Exec(ctx, `CREATE TABLE upstream_attempts (
		input_accounting_method text, input_token_bound bigint
	); INSERT INTO upstream_attempts VALUES ('utf8_byte_bpe_declared_framing_v1',400),(NULL,NULL)`); err != nil {
		t.Fatal(err)
	}
	migration, err := migrations.Files.ReadFile("000032_input_accounting_breakdown.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	var historical int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM upstream_attempts WHERE input_accounting_breakdown IS NULL`).Scan(&historical); err != nil || historical != 2 {
		t.Fatalf("historical diagnostics changed: %d %v", historical, err)
	}
	base := `{"version":1,"rewritten_request_bytes":100,"framing_unit_count":2,"maximum_framing_tokens_per_request":16,"maximum_framing_tokens_per_unit":8,"expanded_schema_bytes":268}`
	if _, err := pool.Exec(ctx, `INSERT INTO upstream_attempts(input_accounting_method,input_token_bound,input_accounting_breakdown) VALUES ('utf8_byte_bpe_declared_framing_v1',400,$1)`, base); err != nil {
		t.Fatalf("valid aggregate proof rejected: %v", err)
	}
	for _, raw := range []string{
		`null`, `[]`, `{}`,
		strings.Replace(base, `"version":1`, `"version":2`, 1),
		strings.Replace(base, `"expanded_schema_bytes":268`, `"expanded_schema_bytes":267`, 1),
		strings.Replace(base, `"expanded_schema_bytes":268`, `"expanded_schema_bytes":-1`, 1),
		strings.Replace(base, `"maximum_framing_tokens_per_unit":8`, `"maximum_framing_tokens_per_unit":null`, 1),
		strings.Replace(base, `"maximum_framing_tokens_per_unit":8`, `"maximum_framing_tokens_per_unit":9223372036854775808`, 1),
		strings.Replace(base, `"version":1`, `"version":1,"prompt":"must never persist"`, 1),
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO upstream_attempts(input_accounting_method,input_token_bound,input_accounting_breakdown) VALUES ('utf8_byte_bpe_declared_framing_v1',400,$1)`, raw); err == nil {
			t.Fatalf("malformed diagnostic record accepted: %s", raw)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO upstream_attempts(input_accounting_breakdown) VALUES ($1)`, base); err == nil {
		t.Fatal("diagnostics without a trusted bound were accepted")
	}
}
