package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

var signingIntegrationSchemaPattern = regexp.MustCompile(`^latchway_signing_test_[0-9]+$`)

func TestSigningKeysAndAccessTokensPostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	envelope, err := secrets.NewEnvironmentMasterKey(masterKey)
	if err != nil {
		t.Fatalf("construct envelope provider: %v", err)
	}
	manager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct signing-key manager: %v", err)
	}

	const workers = 12
	keyIDs := make(chan string, workers)
	failures := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			key, activeErr := manager.Active(ctx)
			keyIDs <- key.KeyID()
			failures <- activeErr
		}()
	}
	wait.Wait()
	close(keyIDs)
	close(failures)
	for activeErr := range failures {
		if activeErr != nil {
			t.Fatalf("concurrent active key: %v", activeErr)
		}
	}
	var firstKeyID string
	for keyID := range keyIDs {
		if firstKeyID == "" {
			firstKeyID = keyID
		}
		if keyID != firstKeyID {
			t.Fatalf("concurrent initialization created multiple active keys: %q, %q", firstKeyID, keyID)
		}
	}
	if id.Validate(firstKeyID, id.GatewaySigningKey) != nil {
		t.Fatalf("invalid signing key ID: %q", firstKeyID)
	}
	var activeCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM gateway_signing_keys WHERE status = 'active'").Scan(&activeCount); err != nil || activeCount != 1 {
		t.Fatalf("active signing-key count=%d err=%v", activeCount, err)
	}

	jwks, err := manager.PublicJWKS(ctx)
	if err != nil || len(jwks.Keys) != 1 || jwks.Keys[0].Kid != firstKeyID {
		t.Fatalf("initial public JWKS=%#v err=%v", jwks, err)
	}
	encodedJWKS := fmt.Sprintf("%#v", jwks)
	if strings.Contains(encodedJWKS, "private") || strings.Contains(encodedJWKS, "encrypted") {
		t.Fatal("public JWKS representation exposed private-key fields")
	}

	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: manager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Lifetime: 10 * time.Minute, Now: func() time.Time { return now },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 1024)),
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: manager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token verifier: %v", err)
	}
	input := AccessIssueInput{
		OrganizationID: mustSessionID(t, id.Organization), ApplicationID: mustSessionID(t, id.Application),
		EnvironmentID: mustSessionID(t, id.Environment), ApplicationUserID: mustSessionID(t, id.ApplicationUser),
		InstallationID: mustSessionID(t, id.Installation), SessionGrantID: mustSessionID(t, id.SessionGrant),
		IdentityProvider: "firebase", TrustLevel: "app_verified", PolicyRevisionID: mustSessionID(t, id.ConfigRevision),
		DPoPJKT: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
	}
	issued, err := issuer.Issue(ctx, input)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	if strings.Contains(fmt.Sprint(issued.Token), issued.Token.Reveal()) || strings.Contains(fmt.Sprintf("%#v", issued.Token), issued.Token.Reveal()) {
		t.Fatal("access-token formatting disclosed plaintext")
	}
	principal, err := verifier.Verify(ctx, issued.Token)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if principal.OrganizationID != input.OrganizationID || principal.ApplicationUserID != input.ApplicationUserID || principal.DPoPJKT != input.DPoPJKT || principal.JTIHash != issued.JTIHash || !principal.ExpiresAt.Equal(issued.ExpiresAt) {
		t.Fatalf("unexpected access principal: %#v", principal)
	}

	wrongAudience, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: manager, Issuer: "https://gateway.example.test", Audience: "other-audience", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct wrong-audience verifier: %v", err)
	}
	if _, err := wrongAudience.Verify(ctx, issued.Token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong audience should fail: %v", err)
	}
	tamperedRaw := issued.Token.Reveal()
	last := byte('A')
	if tamperedRaw[len(tamperedRaw)-1] == 'A' {
		last = 'B'
	}
	tampered, err := NewAccessToken(tamperedRaw[:len(tamperedRaw)-1] + string(last))
	if err != nil {
		t.Fatalf("construct tampered token: %v", err)
	}
	if _, err := verifier.Verify(ctx, tampered); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("tampered token should fail: %v", err)
	}
	now = issued.ExpiresAt.Add(2 * time.Minute)
	if _, err := verifier.Verify(ctx, issued.Token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token should fail: %v", err)
	}

	now = time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)
	rotated, err := manager.Active(ctx)
	if err != nil {
		t.Fatalf("rotate signing key: %v", err)
	}
	if rotated.KeyID() == firstKeyID {
		t.Fatal("key inside rotation lead was not rotated")
	}
	jwks, err = manager.PublicJWKS(ctx)
	if err != nil || len(jwks.Keys) != 2 {
		t.Fatalf("rotation JWKS should publish active and retiring keys: %#v err=%v", jwks, err)
	}
	var active, retiring int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'active'), count(*) FILTER (WHERE status = 'retiring') FROM gateway_signing_keys`).Scan(&active, &retiring); err != nil || active != 1 || retiring != 1 {
		t.Fatalf("rotation states active=%d retiring=%d err=%v", active, retiring, err)
	}

	wrongEnvelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32)))
	if err != nil {
		t.Fatalf("construct wrong envelope: %v", err)
	}
	wrongManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: wrongEnvelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct wrong manager: %v", err)
	}
	if _, err := wrongManager.Active(ctx); !errors.Is(err, ErrSigningKeyUnavailable) {
		t.Fatalf("wrong master key should fail closed: %v", err)
	}
}

func isolatedSessionPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	return isolatedSessionPoolWithMaxConnections(t, 12)
}

func isolatedSessionPoolWithMaxConnections(t *testing.T, maxConnections int32) (*pgxpool.Pool, context.Context) {
	t.Helper()
	if maxConnections < 1 {
		t.Fatal("session test pool must have at least one connection")
	}
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_signing_test_%d", time.Now().UnixNano())
	if !signingIntegrationSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create session test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsedURL.String(), maxConnections)
	if err != nil {
		t.Fatalf("open isolated session database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, ctx
}

func mustSessionID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
