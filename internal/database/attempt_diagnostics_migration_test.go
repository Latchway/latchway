package database

import (
	"testing"

	"github.com/latchway/latchway/migrations"
)

func TestMigratorPostgreSQLDiagnosticUpgradeAndRollback(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 20)
	entries, err := migrationEntries()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.version > 20 && entry.version <= 31 {
			if err := NewMigrator(pool).apply(ctx, conn.Conn(), entry); err != nil {
				conn.Release()
				t.Fatal(err)
			}
		}
	}
	conn.Release()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, name := range []string{"000032_input_accounting_breakdown.sql", "000033_attempt_diagnostics.sql"} {
		sql, err := migrations.Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var tableExists, columnExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema()||'.upstream_attempt_diagnostics') IS NOT NULL,
	 EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='upstream_attempts' AND column_name='input_accounting_breakdown')`).Scan(&tableExists, &columnExists); err != nil || tableExists || columnExists {
		t.Fatalf("rolled back diagnostics table=%v column=%v err=%v", tableExists, columnExists, err)
	}
	migrator := NewMigrator(pool)
	current, _, err := migrator.Status(ctx)
	if err != nil || current != 31 {
		t.Fatalf("rollback schema=%d err=%v", current, err)
	}
	for range 2 {
		if err := migrator.Up(ctx); err != nil {
			t.Fatal(err)
		}
	}
	current, available, err := migrator.Status(ctx)
	if err != nil || current != 33 || available != 33 {
		t.Fatalf("upgrade schema=%d/%d err=%v", current, available, err)
	}
}
