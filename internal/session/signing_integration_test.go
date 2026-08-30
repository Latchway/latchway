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

	now = time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)
	if _, err := wrongManager.Active(ctx); !errors.Is(err, ErrSigningKeyUnavailable) {
		t.Fatalf("wrong master key rotated a near-expiry signing key: %v", err)
	}
	var unchangedActiveID, unchangedMasterKeyID string
	var unchangedTotal int
	if err := pool.QueryRow(ctx, `
		SELECT gateway_signing_key_id, master_key_identifier,
		       (SELECT count(*) FROM gateway_signing_keys)
		FROM gateway_signing_keys
		WHERE status = 'active'
	`).Scan(&unchangedActiveID, &unchangedMasterKeyID, &unchangedTotal); err != nil {
		t.Fatalf("read signing-key state after rejected rotation: %v", err)
	}
	if unchangedActiveID != firstKeyID || unchangedMasterKeyID != envelope.KeyID() || unchangedTotal != 1 {
		t.Fatal("rejected wrong-key rotation changed persisted signing-key state")
	}

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

	if _, err := wrongManager.Active(ctx); !errors.Is(err, ErrSigningKeyUnavailable) {
		t.Fatalf("wrong master key should fail closed: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE gateway_signing_keys
		SET master_key_identifier = $1
		WHERE status = 'retiring'
	`, wrongEnvelope.KeyID()); err != nil {
		t.Fatalf("create historical signing-key mismatch fixture: %v", err)
	}
	if _, err := manager.Active(ctx); !errors.Is(err, ErrSigningKeyUnavailable) {
		t.Fatalf("historical signing-key master-key mismatch was accepted: %v", err)
	}
}

func TestSigningKeyConcurrentFreshStartChoosesOneMasterKeyPostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	providers := make([]*secrets.EnvironmentMasterKey, 2)
	managers := make([]*SigningKeyManager, 2)
	for index, fill := range []byte{0x71, 0x72} {
		provider, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)))
		if err != nil {
			t.Fatalf("construct envelope provider %d: %v", index, err)
		}
		manager, err := NewSigningKeyManager(SigningKeyManagerConfig{
			Pool: pool, Envelope: provider, Now: func() time.Time { return now },
			KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("construct signing-key manager %d: %v", index, err)
		}
		providers[index] = provider
		managers[index] = manager
	}

	type activeResult struct {
		index int
		key   signingKey
		err   error
	}
	start := make(chan struct{})
	results := make(chan activeResult, len(managers))
	for index, manager := range managers {
		go func() {
			<-start
			key, err := manager.Active(ctx)
			results <- activeResult{index: index, key: key, err: err}
		}()
	}
	close(start)

	winner := -1
	for range managers {
		result := <-results
		switch {
		case result.err == nil && result.key.KeyID() != "":
			if winner != -1 {
				t.Fatal("different master keys both initialized a fresh signing-key table")
			}
			winner = result.index
		case errors.Is(result.err, ErrSigningKeyUnavailable) && result.key.KeyID() == "":
		default:
			t.Fatalf("unexpected concurrent initialization result: key=%q err=%v", result.key.KeyID(), result.err)
		}
	}
	if winner == -1 {
		t.Fatal("neither master key initialized the fresh signing-key table")
	}

	var storedMasterKeyID string
	var signingKeyCount int
	if err := pool.QueryRow(ctx, `
		SELECT master_key_identifier, (SELECT count(*) FROM gateway_signing_keys)
		FROM gateway_signing_keys
		WHERE status = 'active'
	`).Scan(&storedMasterKeyID, &signingKeyCount); err != nil {
		t.Fatalf("read initialized signing-key state: %v", err)
	}
	if storedMasterKeyID != providers[winner].KeyID() || signingKeyCount != 1 {
		t.Fatal("fresh signing-key initialization did not persist exactly the winning master-key marker")
	}
	loser := 1 - winner
	if _, err := managers[loser].Active(ctx); !errors.Is(err, ErrSigningKeyUnavailable) {
		t.Fatalf("losing master key did not remain rejected: %v", err)
	}
}

func TestSigningKeyMaintenancePreservesSessionsIssuedBeforeRotationPostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	start := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	now := start
	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 24 * time.Hour, RotationLead: 2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := manager.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}

	now = start.Add(21*time.Hour + 30*time.Minute)
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: manager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Lifetime: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: manager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	input := AccessIssueInput{
		OrganizationID: mustSessionID(t, id.Organization), ApplicationID: mustSessionID(t, id.Application),
		EnvironmentID: mustSessionID(t, id.Environment), ApplicationUserID: mustSessionID(t, id.ApplicationUser),
		InstallationID: mustSessionID(t, id.Installation), SessionGrantID: mustSessionID(t, id.SessionGrant),
		IdentityProvider: "firebase", TrustLevel: "device_verified",
		PolicyRevisionID: mustSessionID(t, id.ConfigRevision),
		DPoPJKT:          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)),
	}
	issued, err := issuer.Issue(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	preRotation, err := manager.Active(ctx)
	if err != nil || preRotation.KeyID() != initial.KeyID() {
		t.Fatalf("session was not issued before rotation: key=%q err=%v", preRotation.KeyID(), err)
	}

	now = start.Add(22*time.Hour + 5*time.Minute)
	changed, err := manager.MaintainSigningKeys(ctx)
	if err != nil || changed != 1 {
		t.Fatalf("maintenance changed=%d err=%v", changed, err)
	}
	active, err := manager.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if active.KeyID() == initial.KeyID() {
		t.Fatal("near-expiry key was not rotated")
	}
	if _, err := verifier.Verify(ctx, issued.Token); err != nil {
		t.Fatalf("pre-rotation active session stopped verifying: %v", err)
	}
	var oldStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM gateway_signing_keys WHERE key_id = $1`, initial.KeyID()).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "retiring" {
		t.Fatalf("old key status=%q want retiring", oldStatus)
	}

	now = start.Add(24*time.Hour + time.Minute)
	changed, err = manager.MaintainSigningKeys(ctx)
	if err != nil || changed != 1 {
		t.Fatalf("retirement changed=%d err=%v", changed, err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM gateway_signing_keys WHERE key_id = $1`, initial.KeyID()).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "retired" {
		t.Fatalf("expired old key status=%q want retired", oldStatus)
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
