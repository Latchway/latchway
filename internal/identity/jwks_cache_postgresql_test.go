package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
)

func TestPostgreSQLRemoteKeyCacheWorkerAndAPIReplicaSharing(t *testing.T) {
	pool, ctx := isolatedIdentityKeyCachePool(t)
	cache, err := NewPostgreSQLRemoteKeyCache(pool)
	if err != nil {
		t.Fatal(err)
	}
	key := mustRSAKey(t)
	jwk := rsaJWK("shared-key", "RS256", &key.PublicKey)
	jwk["d"] = "provider-private-member-must-not-persist"
	issuer := "https://issuer.example.test/tenant"
	endpoint := "https://keys.example.test/.well-known/jwks.json"
	initial := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	now := initial
	lastModified := initial.Add(-time.Hour).Format(http.TimeFormat)

	var phase atomic.Int32
	var calls atomic.Int32
	var conditionalETag atomic.Bool
	var conditionalModified atomic.Bool
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if phase.Load() == 0 {
			return jsonResponse(http.StatusOK, jwksJSON(t, jwk), map[string]string{
				"Cache-Control": "public, max-age=60", "ETag": `"shared-v1"`, "Last-Modified": lastModified,
			}), nil
		}
		conditionalETag.Store(request.Header.Get("If-None-Match") == `"shared-v1"`)
		conditionalModified.Store(request.Header.Get("If-Modified-Since") == lastModified)
		startedOnce.Do(func() { close(started) })
		<-release
		return jsonResponse(http.StatusNotModified, "", map[string]string{"Cache-Control": "max-age=300"}), nil
	})
	workerSource := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: endpoint, Issuer: issuer, Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: transport}, SharedCache: cache, Now: func() time.Time { return now },
	})
	if err := workerSource.Refresh(ctx); err != nil {
		t.Fatalf("worker refresh: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("worker HTTP calls = %d, want 1", calls.Load())
	}

	var document, documentHash, issuerDigest, sourceDigest []byte
	var etag string
	var storedLastModified time.Time
	if err := pool.QueryRow(ctx, `
		SELECT document, document_sha256, issuer_sha256, source_sha256, etag, last_modified
		FROM identity_jwks_cache
	`).Scan(&document, &documentHash, &issuerDigest, &sourceDigest, &etag, &storedLastModified); err != nil {
		t.Fatal(err)
	}
	calculated := sha256.Sum256(document)
	if !bytes.Equal(documentHash, calculated[:]) || len(issuerDigest) != sha256.Size || len(sourceDigest) != sha256.Size || etag != `"shared-v1"` {
		t.Fatal("shared public-key cache metadata is invalid")
	}
	for _, forbidden := range []string{issuer, endpoint, "provider-private-member-must-not-persist", `"d"`} {
		if bytes.Contains(document, []byte(forbidden)) || bytes.Contains(issuerDigest, []byte(forbidden)) || bytes.Contains(sourceDigest, []byte(forbidden)) {
			t.Fatalf("shared cache persisted forbidden value %q", forbidden)
		}
	}
	wantModified, _ := http.ParseTime(lastModified)
	if !storedLastModified.Equal(wantModified) {
		t.Fatalf("last-modified = %s, want %s", storedLastModified, wantModified)
	}

	var apiNetworkCalls atomic.Int32
	apiSource := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: endpoint, Issuer: issuer, Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			apiNetworkCalls.Add(1)
			return nil, errors.New("API-only replica has no network in this test")
		})}, SharedCache: cache, Now: func() time.Time { return now },
	})
	resolved, err := apiSource.Key(ctx, "shared-key", "RS256")
	if err != nil || resolved == nil || apiNetworkCalls.Load() != 0 {
		t.Fatalf("API-only shared resolution key=%T calls=%d err=%v", resolved, apiNetworkCalls.Load(), err)
	}

	// Expire freshness while preserving the bounded LKG window, then prove two
	// worker replicas converge on one conditional fetch through the DB lease.
	now = initial.Add(2 * time.Minute)
	if _, err := pool.Exec(ctx, `
		UPDATE identity_jwks_cache
		SET fresh_until = $1, stale_until = $2, updated_at = statement_timestamp()
	`, now.Add(-time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	phase.Store(1)
	calls.Store(0)
	first := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: endpoint, Issuer: issuer, Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: transport}, SharedCache: cache, Now: func() time.Time { return now },
	})
	second := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: endpoint, Issuer: issuer, Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: transport}, SharedCache: cache, Now: func() time.Time { return now },
	})
	results := make(chan error, 2)
	go func() { results <- first.Refresh(ctx) }()
	go func() { results <- second.Refresh(ctx) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("conditional refresh did not start")
	}
	var early error
	select {
	case early = <-results:
	case <-time.After(3 * time.Second):
		t.Fatal("second replica did not observe the shared refresh lease")
	}
	close(release)
	late := <-results
	if early == nil || late != nil {
		t.Fatalf("multi-replica outcomes early=%v late=%v", early, late)
	}
	if calls.Load() != 1 || !conditionalETag.Load() || !conditionalModified.Load() {
		t.Fatalf("conditional fetch calls=%d etag=%t modified=%t", calls.Load(), conditionalETag.Load(), conditionalModified.Load())
	}

	// A hash mismatch is treated as untrusted state. The next request repairs it
	// only with a newly fetched, revalidated, public-only document.
	if _, err := pool.Exec(ctx, `UPDATE identity_jwks_cache SET document = '{}'::text::bytea`); err != nil {
		t.Fatal(err)
	}
	repairCalls := 0
	repair := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: endpoint, Issuer: issuer, Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			repairCalls++
			return jsonResponse(http.StatusOK, jwksJSON(t, jwk), map[string]string{"Cache-Control": "max-age=60"}), nil
		})}, SharedCache: cache, Now: func() time.Time { return now },
	})
	if _, err := repair.Key(ctx, "shared-key", "RS256"); err != nil || repairCalls != 1 {
		t.Fatalf("request-time cache repair calls=%d err=%v", repairCalls, err)
	}
	var leaseCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_jwks_cache WHERE refresh_lease_token IS NOT NULL`).Scan(&leaseCount); err != nil || leaseCount != 0 {
		t.Fatalf("refresh leases after repair=%d err=%v", leaseCount, err)
	}
}

func isolatedIdentityKeyCachePool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_identity_test_%d", time.Now().UnixNano())
	if !identityIntegrationSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsed.String(), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func TestRemoteKeyCacheErrorsRemainRedactionSafe(t *testing.T) {
	identity := newRemoteKeyIdentity("https://issuer.example.test/private-tenant", "https://keys.example.test/jwks", RemoteKeyFormatJWKS)
	for _, value := range []string{
		fmt.Sprintf("%v", identity), fmt.Sprintf("%#v", identity),
		errors.New("shared identity key cache is invalid").Error(),
	} {
		for _, forbidden := range []string{"private-tenant", "keys.example.test", "identity-token-value"} {
			if strings.Contains(value, forbidden) {
				t.Fatalf("cache error/identity formatting leaked %q: %s", forbidden, value)
			}
		}
	}
}
