package migrations

import (
	"strings"
	"testing"
)

func TestIdentityJWKSCacheMigrationIsPublicOnlyBoundedAndAdditive(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000015_identity_jwks_cache.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"create table identity_jwks_cache", "issuer_sha256 bytea", "source_sha256 bytea",
		"source_format text", "document bytea", "document_sha256 bytea", "etag text",
		"last_modified timestamptz", "fetched_at timestamptz", "fresh_until timestamptz",
		"stale_until timestamptz", "refresh_lease_token bytea", "refresh_lease_until timestamptz",
		"octet_length(document) between 2 and 1048576", "stale_until <= fresh_until + interval '24 hours'",
		"fresh_until <= fetched_at + interval '24 hours'",
		"create index identity_jwks_cache_refresh_idx", "create index identity_jwks_cache_stale_idx",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"identity_token", "refresh_token", "secret", "credential", "private_key",
		"drop table", "truncate", "delete from", "create index concurrently",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("migration contains forbidden %q", forbidden)
		}
	}
}
