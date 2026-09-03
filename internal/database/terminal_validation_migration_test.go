package database

import (
	"testing"
)

func TestMigratorPostgreSQLTerminalValidationBodyOnly(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	// The historical helper intentionally enumerates only migrations 1–20.
	// Advance this owned fixture explicitly; do not silently compare 20→29.
	applyMigrationsThrough(t, ctx, pool, 20)
	entries, err := migrationEntries()
	if err != nil {
		t.Fatal("list terminal validation baseline migrations")
	}
	func() {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("acquire terminal validation baseline connection")
		}
		defer conn.Release()
		for _, entry := range entries {
			if entry.version > 20 && entry.version <= 28 {
				if err := NewMigrator(pool).apply(ctx, conn.Conn(), entry); err != nil {
					t.Fatal("apply terminal validation baseline migration")
				}
			}
		}
	}()
	assertLedger := func(want int64) {
		t.Helper()
		var count, minimum, maximum int64
		if err := pool.QueryRow(ctx, `SELECT count(*),min(version),max(version) FROM schema_migrations`).Scan(&count, &minimum, &maximum); err != nil {
			t.Fatal("read terminal validation migration ledger")
		}
		// version is a bigint primary key: exactly want distinct rows spanning
		// [1,want] proves there are neither missing nor unexpected versions.
		if count != want || minimum != 1 || maximum != want {
			t.Fatal("terminal validation migration ledger is not the exact expected baseline")
		}
	}
	assertLedger(28)
	// Compare real schema catalogs around the new migration, not the synthetic
	// semantic fixture: no table constraint, index, or trigger may change.
	const catalog = `
		SELECT jsonb_build_object(
			'constraints', COALESCE((
				SELECT jsonb_agg(jsonb_build_array(c.oid,c.conname,pg_get_constraintdef(c.oid),c.convalidated) ORDER BY c.oid)
				FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
				WHERE n.nspname=current_schema()
			), '[]'::jsonb),
			'indexes', COALESCE((
				SELECT jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid)) ORDER BY i.indexrelid)
				FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
				WHERE n.nspname=current_schema()
			), '[]'::jsonb),
			'triggers', COALESCE((
				SELECT jsonb_agg(jsonb_build_array(t.oid,pg_get_triggerdef(t.oid),t.tgenabled,t.tgdeferrable,t.tginitdeferred) ORDER BY t.oid)
				FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
				WHERE n.nspname=current_schema()
			), '[]'::jsonb)
		)::text
	`
	var before, after string
	if err := pool.QueryRow(ctx, catalog).Scan(&before); err != nil {
		t.Fatal("read original migration catalog")
	}
	const function = `SELECT p.oid::bigint,p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() AND p.proname='latchway_schema12_attempt_terminal_compat' AND p.pronargs=0`
	var originalOID, candidateOID int64
	var originalBody, candidateBody string
	if err := pool.QueryRow(ctx, function).Scan(&originalOID, &originalBody); err != nil {
		t.Fatal("read original terminal function")
	}
	if err := NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply terminal validation migration: %v", err)
	}
	assertLedger(29)
	if err := pool.QueryRow(ctx, catalog).Scan(&after); err != nil || before != after {
		t.Fatal("terminal validation migration changed constraints, indexes, or triggers")
	}
	if err := pool.QueryRow(ctx, function).Scan(&candidateOID, &candidateBody); err != nil || originalOID != candidateOID || originalBody == candidateBody {
		t.Fatal("terminal validation must change only the body of the same function")
	}
	if err := NewMigrator(pool).Up(ctx); err != nil {
		t.Fatal("terminal validation migration is not idempotent")
	}
}
