package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

type accessRevocationFixture struct {
	pool       *pgxpool.Pool
	ctx        context.Context
	now        time.Time
	store      *Store
	issuer     *AccessTokenIssuer
	verifier   *AccessTokenVerifier
	key        *ecdsa.PrivateKey
	issued     IssuedSession
	principal  AccessPrincipal
	refreshURI *url.URL
	revokeURI  *url.URL
}

func TestAccessAuthorizationAndRevocationPostgreSQL(t *testing.T) {
	fixture := newAccessRevocationFixture(t)

	// Give the installation two grants and a refresh family with rotated
	// history so revocation must invalidate every live descendant without
	// rewriting the historical rotated status.
	rotated, err := fixture.store.Rotate(fixture.ctx, RotateInput{
		RefreshToken: fixture.issued.Refresh,
		DPoPProof: signedSessionDPoP(t, fixture.key, "POST", fixture.refreshURI,
			fixture.now, "access-revocation-pre-rotation"),
		HTTPMethod: "POST", RequestURI: fixture.refreshURI,
	})
	if err != nil {
		t.Fatalf("prepare rotated revocation family: %v", err)
	}

	baselineReplays := countAccessRevocationRows(t, fixture.ctx, fixture.pool, "dpop_replay_entries", "TRUE")
	assertInstallationActive := func() {
		t.Helper()
		var status string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status FROM installations WHERE installation_id = $1
		`, fixture.issued.Installation.ID).Scan(&status); err != nil || status != "active" {
			t.Fatalf("installation status=%q err=%v, want active", status, err)
		}
	}

	validInput := func(label string) AccessRequestInput {
		return AccessRequestInput{
			AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
			DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", fixture.revokeURI,
				fixture.now, fixture.issued.Access.Token.Reveal(), label),
			HTTPMethod: "DELETE", RequestURI: fixture.revokeURI,
		}
	}

	t.Run("rejects every mismatched binding without consuming replay state", func(t *testing.T) {
		wrongKey, _, _ := newChallengeKey(t)
		wrongURI := mustSessionURL(t, "https://gateway.example.test/client/v1/diagnostics")
		mixedToken, err := fixture.issuer.Issue(fixture.ctx, AccessIssueInput{
			OrganizationID: fixture.principal.OrganizationID, ApplicationID: fixture.principal.ApplicationID,
			EnvironmentID: fixture.principal.EnvironmentID, ApplicationUserID: fixture.principal.ApplicationUserID,
			InstallationID: fixture.principal.InstallationID, SessionGrantID: fixture.principal.SessionGrantID,
			IdentityProvider: fixture.principal.IdentityProvider, TrustLevel: fixture.principal.TrustLevel,
			PolicyRevisionID: fixture.principal.PolicyRevisionID, DPoPJKT: fixture.principal.DPoPJKT,
		})
		if err != nil {
			t.Fatalf("issue independently signed mixed token: %v", err)
		}
		tamperedPrincipal := fixture.principal
		tamperedPrincipal.InstallationID = rotated.Installation.ID + "x"

		tests := []struct {
			name  string
			input AccessRequestInput
			check func(error) bool
		}{
			{
				name: "method",
				input: AccessRequestInput{AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
					DPoPProof: signedSessionAccessDPoP(t, fixture.key, "POST", fixture.revokeURI,
						fixture.now, fixture.issued.Access.Token.Reveal(), "access-wrong-method"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return dpop.IsCode(err, "dpop_invalid") },
			},
			{
				name: "URI",
				input: AccessRequestInput{AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
					DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", wrongURI,
						fixture.now, fixture.issued.Access.Token.Reveal(), "access-wrong-uri"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return dpop.IsCode(err, "dpop_invalid") },
			},
			{
				name: "access token hash",
				input: AccessRequestInput{AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
					DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", fixture.revokeURI,
						fixture.now, "different-access-token", "access-wrong-ath"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return dpop.IsCode(err, "dpop_invalid") },
			},
			{
				name: "DPoP key",
				input: AccessRequestInput{AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
					DPoPProof: signedSessionAccessDPoP(t, wrongKey, "DELETE", fixture.revokeURI,
						fixture.now, fixture.issued.Access.Token.Reveal(), "access-wrong-key"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return dpop.IsCode(err, "dpop_invalid") },
			},
			{
				name: "replay-unsafe proof identifier",
				input: AccessRequestInput{AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
					DPoPProof: signedSessionAccessDPoPWithJTI(t, fixture.key, "DELETE", fixture.revokeURI,
						fixture.now, fixture.issued.Access.Token.Reveal(), "control\njti"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return dpop.IsCode(err, "dpop_invalid") },
			},
			{
				name: "mixed verified principal and raw token",
				input: AccessRequestInput{AccessToken: mixedToken.Token, Principal: fixture.principal,
					DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", fixture.revokeURI,
						fixture.now, mixedToken.Token.Reveal(), "access-mixed-token"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return errors.Is(err, ErrTokenInvalid) },
			},
			{
				name: "principal changed after verification",
				input: AccessRequestInput{AccessToken: fixture.issued.Access.Token, Principal: tamperedPrincipal,
					DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", fixture.revokeURI,
						fixture.now, fixture.issued.Access.Token.Reveal(), "access-tampered-principal"),
					HTTPMethod: "DELETE", RequestURI: fixture.revokeURI},
				check: func(err error) bool { return errors.Is(err, ErrSessionInvalid) },
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if err := fixture.store.RevokeCurrentInstallation(fixture.ctx, test.input); !test.check(err) {
					t.Fatalf("mismatched request error=%v", err)
				}
				assertInstallationActive()
				if got := countAccessRevocationRows(t, fixture.ctx, fixture.pool, "dpop_replay_entries", "TRUE"); got != baselineReplays {
					t.Fatalf("rejected request consumed replay state: got=%d want=%d", got, baselineReplays)
				}
			})
		}
	})

	authorizedInput := validInput("access-authorize-once")
	authorized, err := fixture.store.AuthorizeAccess(fixture.ctx, authorizedInput)
	if err != nil || authorized.SessionGrantID != fixture.issued.GrantID || authorized.InstallationID != fixture.issued.Installation.ID {
		t.Fatalf("authorize proof-bound access=%#v err=%v", authorized, err)
	}
	if err := fixture.store.RevokeCurrentInstallation(fixture.ctx, authorizedInput); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("accepted proof replay error=%v, want dpop replay", err)
	}
	assertInstallationActive()

	firstRevoke := validInput("access-revoke-first")
	if err := fixture.store.RevokeCurrentInstallation(fixture.ctx, firstRevoke); err != nil {
		t.Fatalf("revoke current installation: %v", err)
	}
	assertRevokedInstallationTerminalState(t, fixture, 2, 1, 1)

	var firstRevokedAt time.Time
	var firstReason string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT revoked_at, revoke_reason FROM installations WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&firstRevokedAt, &firstReason); err != nil {
		t.Fatalf("read initial installation revocation: %v", err)
	}
	if firstReason != clientInstallationRevocationReason {
		t.Fatalf("installation reason=%q", firstReason)
	}

	// Normal protected authorization rejects the revoked installation without
	// consuming the proof; the idempotent revoke path may then accept that same
	// fresh proof and repair any hypothetical live descendants.
	idempotentInput := validInput("access-revoke-idempotent")
	if _, err := fixture.store.AuthorizeAccess(fixture.ctx, idempotentInput); !errors.Is(err, ErrInstallationRevoked) {
		t.Fatalf("ordinary authorization of revoked installation error=%v", err)
	}
	if err := fixture.store.RevokeCurrentInstallation(fixture.ctx, idempotentInput); err != nil {
		t.Fatalf("idempotent installation revocation: %v", err)
	}
	assertRevokedInstallationTerminalState(t, fixture, 2, 1, 1)
	var repeatedRevokedAt time.Time
	var repeatedReason string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT revoked_at, revoke_reason FROM installations WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&repeatedRevokedAt, &repeatedReason); err != nil {
		t.Fatalf("read repeated installation revocation: %v", err)
	}
	if !repeatedRevokedAt.Equal(firstRevokedAt) || repeatedReason != firstReason {
		t.Fatalf("idempotent revocation rewrote audit metadata: first=%s/%q repeated=%s/%q",
			firstRevokedAt, firstReason, repeatedRevokedAt, repeatedReason)
	}
	if err := fixture.store.RevokeCurrentInstallation(fixture.ctx, idempotentInput); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("idempotent proof replay error=%v, want dpop replay", err)
	}
}

func TestInstallationRevocationSurvivesClockRegressionPostgreSQL(t *testing.T) {
	fixture := newAccessRevocationFixture(t)
	future := fixture.now.Add(2 * time.Minute)
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE installations SET updated_at = $2, last_seen_at = $2 WHERE installation_id = $1
	`, fixture.issued.Installation.ID, future); err != nil {
		t.Fatalf("advance installation timestamps: %v", err)
	}
	input := AccessRequestInput{
		AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
		DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", fixture.revokeURI,
			fixture.now, fixture.issued.Access.Token.Reveal(), "access-clock-regression"),
		HTTPMethod: "DELETE", RequestURI: fixture.revokeURI,
	}
	if err := fixture.store.RevokeCurrentInstallation(fixture.ctx, input); err != nil {
		t.Fatalf("revoke under regressed clock: %v", err)
	}
	var revokedAt, updatedAt, lastSeenAt time.Time
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT revoked_at, updated_at, last_seen_at
		FROM installations WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&revokedAt, &updatedAt, &lastSeenAt); err != nil {
		t.Fatalf("read clock-safe revocation timestamps: %v", err)
	}
	if !revokedAt.Equal(future) || !updatedAt.Equal(future) || !lastSeenAt.Equal(future) {
		t.Fatalf("clock-safe timestamps revoked=%s updated=%s last_seen=%s want=%s",
			revokedAt, updatedAt, lastSeenAt, future)
	}
}

func TestInstallationRevocationAndRefreshRotationRacePostgreSQL(t *testing.T) {
	fixture := newAccessRevocationFixture(t)
	revokeInput := AccessRequestInput{
		AccessToken: fixture.issued.Access.Token, Principal: fixture.principal,
		DPoPProof: signedSessionAccessDPoP(t, fixture.key, "DELETE", fixture.revokeURI,
			fixture.now, fixture.issued.Access.Token.Reveal(), "access-race-revoke"),
		HTTPMethod: "DELETE", RequestURI: fixture.revokeURI,
	}
	rotateInput := RotateInput{
		RefreshToken: fixture.issued.Refresh,
		DPoPProof: signedSessionDPoP(t, fixture.key, "POST", fixture.refreshURI,
			fixture.now, "access-race-refresh"),
		HTTPMethod: "POST", RequestURI: fixture.refreshURI,
	}

	start := make(chan struct{})
	results := make(chan struct {
		operation string
		err       error
	}, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		results <- struct {
			operation string
			err       error
		}{operation: "revoke", err: fixture.store.RevokeCurrentInstallation(fixture.ctx, revokeInput)}
	}()
	go func() {
		defer wait.Done()
		<-start
		_, err := fixture.store.Rotate(fixture.ctx, rotateInput)
		results <- struct {
			operation string
			err       error
		}{operation: "refresh", err: err}
	}()
	close(start)
	wait.Wait()
	close(results)
	for result := range results {
		switch result.operation {
		case "revoke":
			if result.err != nil {
				t.Fatalf("concurrent revoke returned opaque failure: %v", result.err)
			}
		case "refresh":
			if result.err != nil && !errors.Is(result.err, ErrInstallationRevoked) && !errors.Is(result.err, ErrSessionRevoked) {
				t.Fatalf("concurrent refresh returned opaque failure: %v", result.err)
			}
		default:
			t.Fatalf("unknown concurrent operation %q", result.operation)
		}
	}
	assertRevokedInstallationTerminalState(t, fixture, -1, -1, -1)
}

func newAccessRevocationFixture(t *testing.T) accessRevocationFixture {
	t.Helper()
	pool, ctx := isolatedSessionPool(t)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	domain := createChallengeFixture(t, ctx, pool)
	revisionID := activateChallengeTestRevision(t, ctx, pool, domain, now)
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct revocation configuration store: %v", err)
	}
	challengeStore, err := newChallengeStore(ChallengeStoreConfig{
		Pool: pool, Configuration: configurationStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct revocation challenge store: %v", err)
	}
	key, jwk, jkt := newChallengeKey(t)
	challengeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
	exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
	challenge, err := challengeStore.Create(ctx, withChallengeProof(ChallengeInput{
		OrganizationID: domain.organizationID, ApplicationID: domain.applicationID,
		EnvironmentID: domain.environmentID, ConfigurationRevisionID: revisionID,
		EnvironmentSlug: "development", ApplicationUserID: domain.applicationUserID,
		IdentityProvider: "firebase", IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
		Platform: "ios", DPoPJKT: jkt, DPoPPublicJWK: jwk,
	}, challengeURI, now, "access-revocation-challenge"))
	if err != nil {
		t.Fatalf("create revocation challenge: %v", err)
	}
	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32)))
	if err != nil {
		t.Fatalf("construct revocation signing envelope: %v", err)
	}
	keyManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct revocation signing-key manager: %v", err)
	}
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct revocation access issuer: %v", err)
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct revocation access verifier: %v", err)
	}
	store, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: issuer, Configuration: configurationStore,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct revocation session store: %v", err)
	}
	issued, err := store.Exchange(ctx, ExchangeInput{
		ChallengeID: challenge.ID,
		Attestation: verifiedDebugAttestation(t, challenge.Binding, now, "access-revocation-exchange"),
		DPoPProof:   signedSessionDPoP(t, key, "POST", exchangeURI, now, "access-revocation-exchange"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "unknown", AppVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("exchange revocation session: %v", err)
	}
	principal, err := verifier.Verify(ctx, issued.Access.Token)
	if err != nil {
		t.Fatalf("verify revocation access token: %v", err)
	}
	attestationKeyID := mustSessionID(t, id.AttestationKey)
	if _, err := pool.Exec(ctx, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			installation_id, provider, environment, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, 'debug', 'development', 'active', $6, $6)
	`, attestationKeyID, principal.OrganizationID, principal.ApplicationID,
		principal.EnvironmentID, principal.InstallationID, now); err != nil {
		t.Fatalf("create active revocation attestation key: %v", err)
	}
	return accessRevocationFixture{
		pool: pool, ctx: ctx, now: now, store: store, issuer: issuer, verifier: verifier,
		key: key, issued: issued, principal: principal,
		refreshURI: mustSessionURL(t, "https://gateway.example.test/client/v1/sessions/refresh"),
		revokeURI:  mustSessionURL(t, "https://gateway.example.test/client/v1/installations/current"),
	}
}

func assertRevokedInstallationTerminalState(t *testing.T, fixture accessRevocationFixture, grants, rotatedTokens, revokedTokens int) {
	t.Helper()
	var status string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT status FROM installations WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&status); err != nil || status != "revoked" {
		t.Fatalf("terminal installation status=%q err=%v", status, err)
	}
	var liveGrants, totalGrants int
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*)
		FROM session_grants WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&liveGrants, &totalGrants); err != nil {
		t.Fatalf("read terminal grants: %v", err)
	}
	if liveGrants != 0 || (grants >= 0 && totalGrants != grants) {
		t.Fatalf("terminal grants live=%d total=%d want_total=%d", liveGrants, totalGrants, grants)
	}
	var liveRefresh, rotatedRefresh, revokedRefresh int
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*) FILTER (WHERE status IN ('staged', 'active')),
		       count(*) FILTER (WHERE status = 'rotated'),
		       count(*) FILTER (WHERE status = 'revoked')
		FROM refresh_tokens WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&liveRefresh, &rotatedRefresh, &revokedRefresh); err != nil {
		t.Fatalf("read terminal refresh family: %v", err)
	}
	if liveRefresh != 0 || (rotatedTokens >= 0 && rotatedRefresh != rotatedTokens) || (revokedTokens >= 0 && revokedRefresh != revokedTokens) {
		t.Fatalf("terminal refresh live=%d rotated=%d revoked=%d wants=%d/%d",
			liveRefresh, rotatedRefresh, revokedRefresh, rotatedTokens, revokedTokens)
	}
	var liveAttestationKeys, revokedAttestationKeys int
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*) FILTER (WHERE status <> 'revoked'),
		       count(*) FILTER (WHERE status = 'revoked')
		FROM attestation_keys WHERE installation_id = $1
	`, fixture.issued.Installation.ID).Scan(&liveAttestationKeys, &revokedAttestationKeys); err != nil {
		t.Fatalf("read terminal attestation keys: %v", err)
	}
	if liveAttestationKeys != 0 || revokedAttestationKeys != 1 {
		t.Fatalf("terminal attestation keys live=%d revoked=%d", liveAttestationKeys, revokedAttestationKeys)
	}
}

func countAccessRevocationRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, predicate string) int {
	t.Helper()
	allowed := map[string]bool{"dpop_replay_entries": true}
	if !allowed[table] || predicate != "TRUE" {
		t.Fatal("invalid test count query")
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE "+predicate).Scan(&count); err != nil {
		t.Fatalf("count %s rows: %v", table, err)
	}
	return count
}

func signedSessionAccessDPoP(t *testing.T, privateKey *ecdsa.PrivateKey, method string, target *url.URL, now time.Time, accessToken, label string) DPoPProof {
	t.Helper()
	return signedSessionAccessDPoPWithJTI(t, privateKey, method, target, now, accessToken, sessionProofJTI(label, now))
}

func signedSessionAccessDPoPWithJTI(t *testing.T, privateKey *ecdsa.PrivateKey, method string, target *url.URL, now time.Time, accessToken, proofJTI string) DPoPProof {
	t.Helper()
	if privateKey == nil {
		t.Fatal("DPoP private key is nil")
	}
	htu, err := dpop.NormalizeHTU(target)
	if err != nil {
		t.Fatalf("normalize access DPoP target: %v", err)
	}
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(privateKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(privateKey.Y.FillBytes(make([]byte, 32))),
	}
	header, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk})
	if err != nil {
		t.Fatalf("encode access DPoP header: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"jti": proofJTI, "htm": method, "htu": htu,
		"iat": now.UTC().Unix(), "ath": dpop.AccessTokenHash(accessToken),
	})
	if err != nil {
		t.Fatalf("encode access DPoP claims: %v", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimsSegment := base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimsSegment))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign access DPoP proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	proof, err := NewDPoPProof(headerSegment + "." + claimsSegment + "." + base64.RawURLEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatalf("construct access DPoP proof: %v", err)
	}
	return proof
}
