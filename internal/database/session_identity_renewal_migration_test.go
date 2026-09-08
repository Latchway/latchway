package database

import (
	"testing"

	"github.com/latchway/latchway/migrations"
)

func TestMigratorPostgreSQLIdentityRenewalUpgradeAndRollback(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 20)
	entries, err := migrationEntries()
	if err != nil {
		t.Fatal(err)
	}
	func() {
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		for _, entry := range entries {
			if entry.version > 20 && entry.version <= 30 {
				if err := NewMigrator(pool).apply(ctx, conn.Conn(), entry); err != nil {
					t.Fatal(err)
				}
			}
		}
	}()
	const catalog = `SELECT jsonb_build_object(
		'constraints', (SELECT jsonb_agg(jsonb_build_array(c.oid,c.conname,pg_get_constraintdef(c.oid),c.convalidated) ORDER BY c.oid)
			FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname=current_schema()
			AND NOT (c.conrelid='session_grants'::regclass AND (pg_get_constraintdef(c.oid)='CHECK ((identity_verified_at <= issued_at))'
			OR c.conname='session_grants_identity_freshness_valid'))),
		'indexes', (SELECT jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid)) ORDER BY i.indexrelid)
			FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema()),
		'triggers', (SELECT jsonb_agg(jsonb_build_array(t.oid,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY t.oid)
			FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema())
	)::text`
	var before, after string
	if err := pool.QueryRow(ctx, catalog).Scan(&before); err != nil {
		t.Fatal(err)
	}
	contents, err := migrations.Files.ReadFile("000031_session_identity_renewal.sql")
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL DDL remains transactional. An interrupted migration must not
	// leave the old binary with a half-changed constraint or an advanced ledger.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(contents)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertChecks := func(old, replacement int) {
		t.Helper()
		var gotOld, gotReplacement int
		if err := pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE pg_get_constraintdef(oid)='CHECK ((identity_verified_at <= issued_at))'),
			count(*) FILTER (WHERE conname='session_grants_identity_freshness_valid' AND convalidated)
			FROM pg_constraint WHERE conrelid='session_grants'::regclass`).Scan(&gotOld, &gotReplacement); err != nil {
			t.Fatal(err)
		}
		if gotOld != old || gotReplacement != replacement {
			t.Fatalf("identity constraints old=%d new=%d; want %d/%d", gotOld, gotReplacement, old, replacement)
		}
	}
	assertChecks(1, 0)
	migrator := NewMigrator(pool)
	current, available, err := migrator.Status(ctx)
	if err != nil || current != 30 || available != latestTestSchemaVersion {
		t.Fatalf("rolled-back status current=%d available=%d err=%v", current, available, err)
	}
	// Verify migration 31's catalog boundary independently of later additive
	// migrations; the full upgrade is exercised after this comparison.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.version == 31 {
			if err := migrator.apply(ctx, conn.Conn(), entry); err != nil {
				conn.Release()
				t.Fatal(err)
			}
		}
	}
	conn.Release()
	assertChecks(0, 1)
	if err := pool.QueryRow(ctx, catalog).Scan(&after); err != nil || after != before {
		t.Fatalf("renewal migration changed unrelated constraints, indexes or triggers: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}
	current, available, err = migrator.Status(ctx)
	if err != nil || current != latestTestSchemaVersion || available != latestTestSchemaVersion {
		t.Fatalf("upgraded status current=%d available=%d err=%v", current, available, err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("migration ledger must make repeat Up idempotent: %v", err)
	}
}

func TestMigratorPostgreSQLIdentityRenewalPreservesLegacyAndExpiryBounds(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	// A focused table exercises the unchanged timestamp semantics without
	// depending on unrelated identity/installation fixture inserts.
	if _, err := pool.Exec(ctx, `CREATE TABLE session_grants (
		issued_at timestamptz NOT NULL, identity_verified_at timestamptz NOT NULL,
		identity_expires_at timestamptz, expires_at timestamptz NOT NULL,
		attested_at timestamptz,
		CHECK (identity_verified_at <= issued_at), CHECK (expires_at > issued_at),
		CHECK (attested_at IS NULL OR attested_at <= issued_at),
		CHECK (identity_expires_at IS NULL OR identity_expires_at > identity_verified_at)
	)`); err != nil {
		t.Fatal(err)
	}
	contents, err := migrations.Files.ReadFile("000031_session_identity_renewal.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(contents)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, verified, expiry, accessExpiry, attested string
		valid                                          bool
	}{
		{"renewed", "00:00:02", "00:30:00", "00:10:00", "00:00:00", true},
		{"renew after access expires", "00:11:00", "00:30:00", "00:10:00", "00:00:00", true},
		{"identity expires at verification", "00:00:02", "00:00:02", "00:10:00", "00:00:00", false},
		{"identity-less legacy", "00:00:00", "", "00:10:00", "00:00:00", true},
		{"identity-less later timestamp", "00:00:02", "", "00:10:00", "00:00:00", false},
		{"access expiry unchanged", "00:00:02", "00:30:00", "00:00:00", "00:00:00", false},
		{"attestation issuance bound unchanged", "00:00:02", "00:30:00", "00:10:00", "00:00:02", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var expiry any
			if test.expiry != "" {
				expiry = "2026-09-08T" + test.expiry + "Z"
			}
			_, err := pool.Exec(ctx, `INSERT INTO session_grants (issued_at,identity_verified_at,identity_expires_at,expires_at,attested_at)
				VALUES ('2026-09-08T00:00:00Z',$1::text::timestamptz,$2::text::timestamptz,$3::text::timestamptz,$4::text::timestamptz)`,
				"2026-09-08T"+test.verified+"Z", expiry, "2026-09-08T"+test.accessExpiry+"Z", "2026-09-08T"+test.attested+"Z")
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}
