package database

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigratorPostgreSQLIdentityJWKSCacheFreshAndUpgrade(t *testing.T) {
	for _, test := range []struct {
		name    string
		upgrade bool
	}{
		{name: "fresh"},
		{name: "upgrade from 14", upgrade: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, pool := newPostgreSQLIntegrationPool(t)
			if test.upgrade {
				// The upgrade path must use this subtest's isolated pool.
				applyMigrationsThrough(t, ctx, pool, 14)
			}
			migrator := NewMigrator(pool)
			if err := migrator.Up(ctx); err != nil {
				t.Fatal(err)
			}
			current, available, err := migrator.Status(ctx)
			if err != nil || current != latestTestSchemaVersion || available != latestTestSchemaVersion {
				t.Fatalf("schema current=%d available=%d err=%v", current, available, err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			issuer, source := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
			document := []byte(`{"keys":[{"kty":"RSA","kid":"public"}]}`)
			documentHash := bytes.Repeat([]byte{0x33}, 32)
			if _, err := pool.Exec(ctx, `
				INSERT INTO identity_jwks_cache (
					issuer_sha256, source_sha256, source_format, document, document_sha256,
					etag, last_modified, fetched_at, fresh_until, stale_until, created_at, updated_at
				) VALUES ($1,$2,'jwks',$3,$4,'"public-v1"',$5,$5,$6,$7,$5,$5)
			`, issuer, source, document, documentHash, now, now.Add(time.Minute), now.Add(time.Hour)); err != nil {
				t.Fatalf("insert bounded public cache record: %v", err)
			}
			_, err = pool.Exec(ctx, `
				INSERT INTO identity_jwks_cache (issuer_sha256, source_sha256, source_format)
				VALUES ($1,$2,'jwks')
			`, make([]byte, 32), bytes.Repeat([]byte{0x44}, 32))
			var constraint *pgconn.PgError
			if err == nil || !asPostgreSQLConstraint(err, &constraint) {
				t.Fatalf("zero digest constraint error=%v", err)
			}
		})
	}
}

// asPostgreSQLConstraint keeps the assertion independent of a generated
// constraint name while still proving the database, rather than Go code,
// rejects an invalid digest.
func asPostgreSQLConstraint(err error, target **pgconn.PgError) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	ok := errors.As(err, &pgErr)
	if ok {
		*target = pgErr
	}
	return ok && pgErr.Code == "23514"
}
