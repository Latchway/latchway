package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/secrets"
)

func TestAppAttestKeyLinksInSessionTransactionAndRevokesPostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	fixture := createChallengeFixture(t, ctx, pool)
	revisionID := activateChallengeTestRevisionWithPolicy(
		t, ctx, pool, fixture, now, "app_attest", "required", "app_verified", "10m",
	)
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	challengeStore, err := newChallengeStore(ChallengeStoreConfig{
		Pool: pool, Configuration: configurationStore, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, jwk, jkt := newChallengeKey(t)
	challengeTarget := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
	exchangeTarget := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
	challenge, err := challengeStore.Create(ctx, withChallengeProof(ChallengeInput{
		OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, ConfigurationRevisionID: revisionID,
		EnvironmentSlug: "development", ApplicationUserID: fixture.applicationUserID,
		IdentityProvider: "firebase", IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
		Platform: "ios", DPoPJKT: jkt, DPoPPublicJWK: jwk,
	}, challengeTarget, now, "app-attest-link-challenge"))
	if err != nil {
		t.Fatalf("create App Attest challenge: %v", err)
	}

	appPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := appPrivateKey.PublicKey.Bytes()
	if err != nil || len(publicKey) != 65 || publicKey[0] != 4 {
		t.Fatalf("encode App Attest lifecycle key: bytes=%d err=%v", len(publicKey), err)
	}
	keyID := sha256.Sum256(publicKey)
	appIDHash := sha256.Sum256([]byte("TEAM1234.com.example.challenge"))
	keyStore, err := attestation.NewPostgreSQLAppAttestKeyStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	initialState := attestation.AppAttestStoredKey{
		PublicKeyX963: publicKey, AppIDHash: appIDHash,
		AttestationEnvironment: attestation.AppAttestDevelopment,
		ApplicationID:          challenge.Binding.ApplicationID, EnvironmentID: challenge.Binding.Environment,
		Platform: challenge.Binding.Platform, PrincipalID: challenge.Binding.PrincipalID,
		DPoPJKT: challenge.Binding.DPoPJKT, AttestedAt: now,
	}
	if err := keyStore.TransactAppAttestKey(ctx, keyID, func(
		_ attestation.AppAttestStoredKey,
		exists bool,
	) (attestation.AppAttestStoredKey, error) {
		if exists {
			return attestation.AppAttestStoredKey{}, errors.New("unexpected existing App Attest key")
		}
		return initialState, nil
	}); err != nil {
		t.Fatalf("persist pre-session App Attest key: %v", err)
	}
	assertionPayload := appAttestAssertionPayload(
		t, appPrivateKey, keyID, challenge.Binding, 1,
	)
	boundedPayload, err := clientapi.NewEvidencePayload(assertionPayload)
	if err != nil {
		t.Fatalf("construct bounded App Attest payload: %v", err)
	}

	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x79}, 32))
	envelope, err := secrets.NewEnvironmentMasterKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	keyManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: nowClock(now),
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A failure after the link statement must roll the installation and link
	// back together, leaving the pre-session key reusable for a safe retry.
	failingStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: lateFailingAccessIssuer{}, Configuration: configurationStore,
		Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	exchangeProof := signedSessionDPoP(t, dpopKey, "POST", exchangeTarget, now, "app-attest-link-exchange")
	exchangeInput := clientapi.ExchangeInput{
		ChallengeID: challenge.ID,
		Metadata: clientapi.RequestMetadata{
			HTTPMethod: "POST", TargetURL: *exchangeTarget,
			DPoPProof: clientapi.NewSensitiveString(exchangeProof.value),
		},
		Attestation:  clientapi.AttestationEvidence{Provider: "app_attest", Payload: boundedPayload},
		Installation: clientapi.InstallationMetadata{AppVersion: "1.0.0"},
	}
	coordinator := &clientCoordinator{
		pool: pool, configuration: configurationStore, sessions: failingStore,
		challenges: challengeStore, appAttestKeys: keyStore, now: nowClock(now),
		attestationCache: make(map[attestationVerifierCacheKey]*preparedAttestationVerifier),
	}
	if _, err := coordinator.ExchangeSession(ctx, exchangeInput); err == nil {
		t.Fatal("late coordinator exchange unexpectedly succeeded")
	} else {
		var failure *clientapi.DependencyError
		if !errors.As(err, &failure) || failure.Code != "internal_error" {
			t.Fatalf("late coordinator exchange failure = %v", err)
		}
	}
	assertAppAttestKeyLink(t, ctx, pool, keyID, "", "active", false, 1, true)
	var installations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM installations`).Scan(&installations); err != nil || installations != 0 {
		t.Fatalf("rolled-back installation count=%d err=%v", installations, err)
	}
	if _, err := challengeStore.Get(ctx, challenge.ID); err != nil {
		t.Fatalf("late failure consumed challenge: %v", err)
	}

	// Equal counter is not broadly retryable. A new valid ECDSA signature over
	// the same authenticator data changes the exact evidence digest and must be
	// rejected before the session store, while preserving the original retry.
	differentAssertionPayload := appAttestAssertionPayload(
		t, appPrivateKey, keyID, challenge.Binding, 1,
	)
	if differentAssertionPayload["assertion_object"] == assertionPayload["assertion_object"] {
		t.Fatal("fresh equal-counter assertion unexpectedly reused exact evidence bytes")
	}
	differentBoundedPayload, err := clientapi.NewEvidencePayload(differentAssertionPayload)
	if err != nil {
		t.Fatal(err)
	}
	differentExchangeInput := exchangeInput
	differentExchangeInput.Attestation.Payload = differentBoundedPayload
	if _, err := coordinator.ExchangeSession(ctx, differentExchangeInput); err == nil {
		t.Fatal("different equal-counter assertion unexpectedly succeeded")
	} else {
		var failure *clientapi.DependencyError
		if !errors.As(err, &failure) || failure.Code != "attestation_invalid" {
			t.Fatalf("different equal-counter assertion failure = %v", err)
		}
	}
	assertAppAttestKeyLink(t, ctx, pool, keyID, "", "active", false, 1, true)
	if _, err := challengeStore.Get(ctx, challenge.ID); err != nil {
		t.Fatalf("different assertion consumed recoverable challenge: %v", err)
	}

	sessionStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: issuer, Configuration: configurationStore, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Assertion verification committed before the session transaction failed.
	// Reuse the exact request: the digest-bound same-counter verifier path must
	// be a no-op, while the still-live challenge remains the one-session gate.
	coordinator.sessions = sessionStore
	issued, err := coordinator.ExchangeSession(ctx, exchangeInput)
	if err != nil {
		t.Fatalf("retry App Attest exchange: %v", err)
	}
	assertAppAttestKeyLink(t, ctx, pool, keyID, issued.Installation.ID, "active", true, 1, true)
	var normalizedJSON []byte
	if err := pool.QueryRow(ctx, `
		SELECT normalized_signals::text FROM attestation_events WHERE installation_id = $1
	`, issued.Installation.ID).Scan(&normalizedJSON); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(normalizedJSON, []byte(base64.RawURLEncoding.EncodeToString(keyID[:]))) ||
		bytes.Contains(normalizedJSON, []byte(base64.StdEncoding.EncodeToString(keyID[:]))) {
		t.Fatalf("attestation event leaked provider key identifier: %s", normalizedJSON)
	}

	accessVerifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := NewAccessToken(issued.AccessToken.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	principal, err := accessVerifier.Verify(ctx, accessToken)
	if err != nil {
		t.Fatal(err)
	}
	revokeTarget := mustSessionURL(t, "https://gateway.example.test/client/v1/installations/current")
	if err := sessionStore.RevokeCurrentInstallation(ctx, AccessRequestInput{
		AccessToken: accessToken, Principal: principal,
		DPoPProof: signedSessionAccessDPoP(
			t, dpopKey, "DELETE", revokeTarget, now, issued.AccessToken.Reveal(), "app-attest-link-revoke",
		),
		HTTPMethod: "DELETE", RequestURI: revokeTarget,
	}); err != nil {
		t.Fatalf("revoke App Attest installation: %v", err)
	}
	assertAppAttestKeyLink(t, ctx, pool, keyID, issued.Installation.ID, "revoked", true, 1, true)
}

func appAttestAssertionPayload(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	keyID [sha256.Size]byte,
	binding attestation.Binding,
	counter uint32,
) map[string]any {
	t.Helper()
	return appAttestAssertionPayloadForAppID(
		t, privateKey, keyID, binding, counter, "TEAM1234.com.example.challenge",
	)
}

func appAttestAssertionPayloadForAppID(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	keyID [sha256.Size]byte,
	binding attestation.Binding,
	counter uint32,
	appID string,
) map[string]any {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(appID))
	authenticatorData := make([]byte, 37)
	copy(authenticatorData, rpIDHash[:])
	binary.BigEndian.PutUint32(authenticatorData[33:37], counter)
	bindingHash, err := binding.Hash()
	if err != nil {
		t.Fatal(err)
	}
	nonceInput := append(append([]byte(nil), authenticatorData...), bindingHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, nonce[:])
	if err != nil {
		t.Fatal(err)
	}
	object, err := cbor.Marshal(map[string]any{
		"signature": signature, "authenticatorData": authenticatorData,
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"key_id":           base64.StdEncoding.EncodeToString(keyID[:]),
		"client_data_hash": base64.RawURLEncoding.EncodeToString(bindingHash[:]),
		"assertion_object": base64.RawURLEncoding.EncodeToString(object),
	}
}

func assertAppAttestKeyLink(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	keyID [sha256.Size]byte,
	wantInstallation string,
	wantStatus string,
	wantLinked bool,
	wantCounter int64,
	wantAssertionHash bool,
) {
	t.Helper()
	var installationID *string
	var status string
	var createdAt time.Time
	var linkedAt *time.Time
	var counter int64
	var lastAssertionHash []byte
	if err := pool.QueryRow(ctx, `
		SELECT installation_id, status, created_at, linked_at,
		       sign_count, last_assertion_hash
		FROM attestation_keys
		WHERE provider = 'app_attest' AND provider_key_hash = $1
	`, keyID[:]).Scan(
		&installationID, &status, &createdAt, &linkedAt,
		&counter, &lastAssertionHash,
	); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || (installationID != nil) != wantLinked || (linkedAt != nil) != wantLinked ||
		counter != wantCounter || (len(lastAssertionHash) == sha256.Size) != wantAssertionHash {
		t.Fatalf("App Attest link installation=%v status=%q linked_at=%v counter=%d assertion_hash=%d",
			installationID, status, linkedAt, counter, len(lastAssertionHash))
	}
	if wantLinked {
		if *installationID != wantInstallation || linkedAt.Before(createdAt) {
			t.Fatalf("App Attest link installation=%q linked_at=%v created_at=%v", *installationID, linkedAt, createdAt)
		}
	}
}

var errLateAccessIssue = errors.New("late access issue failure")

type lateFailingAccessIssuer struct{}

func (lateFailingAccessIssuer) Prepare(context.Context) (PreparedAccessIssuer, error) {
	return lateFailingPreparedAccessIssuer{}, nil
}

type lateFailingPreparedAccessIssuer struct{}

func (lateFailingPreparedAccessIssuer) preparedAccessIssuer() {}

func (lateFailingPreparedAccessIssuer) IssueFor(AccessIssueInput, time.Duration) (IssuedAccess, error) {
	return IssuedAccess{}, errLateAccessIssue
}
