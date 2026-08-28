package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

func TestChallengeStorePostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	fixture := createChallengeFixture(t, ctx, pool)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	policyRevisionID := activateChallengeTestRevision(t, ctx, pool, fixture, now)
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct configuration store: %v", err)
	}
	store, err := newChallengeStore(ChallengeStoreConfig{
		Pool: pool, Configuration: configurationStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct challenge store: %v", err)
	}
	_, jwk, jkt := newChallengeKey(t)
	challengeRequestURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
	input := withChallengeProof(ChallengeInput{
		OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, ConfigurationRevisionID: policyRevisionID, EnvironmentSlug: "development",
		ApplicationUserID: fixture.applicationUserID, IdentityProvider: "firebase",
		IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
		Platform: "ios", DPoPJKT: jkt, DPoPPublicJWK: jwk,
	}, challengeRequestURI, now, "challenge-store-initial")

	challenge, err := store.Create(ctx, input)
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	if id.Validate(challenge.ID, id.SessionChallenge) != nil || challenge.Nonce == "" || challenge.Binding.DPoPJKT != jkt || !challenge.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
	loaded, err := store.Get(ctx, challenge.ID)
	if err != nil {
		t.Fatalf("load challenge: %v", err)
	}
	if loaded.ID != challenge.ID || loaded.Nonce != challenge.Nonce || loaded.Binding != challenge.Binding || loaded.BindingHash != challenge.BindingHash || loaded.DPoPPublicJWK != jwk {
		t.Fatalf("loaded challenge differs: got=%#v want=%#v", loaded, challenge)
	}
	if loaded.ConfigurationRevisionID != challenge.ConfigurationRevisionID || loaded.Attestation != challenge.Attestation || loaded.Attestation.Provider != "debug" || loaded.Attestation.MinimumTrustLevel != "debug" {
		t.Fatalf("loaded immutable challenge policy differs: got=%#v want=%#v", loaded.Attestation, challenge.Attestation)
	}

	var storedNonce string
	var nonceHash, proofJTIHash, proofURIHash []byte
	if err := pool.QueryRow(ctx, `
		SELECT challenge_nonce, nonce_hash, challenge_dpop_proof_jti_hash,
		       challenge_dpop_http_uri_hash
		FROM session_challenges
		WHERE session_challenge_id = $1
	`, challenge.ID).Scan(&storedNonce, &nonceHash, &proofJTIHash, &proofURIHash); err != nil {
		t.Fatalf("read persisted nonce binding: %v", err)
	}
	expectedNonceHash := sha256.Sum256(mustDecodeChallengeNonce(t, challenge.Nonce))
	if storedNonce != challenge.Nonce || len(nonceHash) != sha256.Size || string(nonceHash) != string(expectedNonceHash[:]) || string(nonceHash) == challenge.Nonce {
		t.Fatal("challenge nonce persistence did not preserve both public binding and digest")
	}
	expectedProofJTIHash := sha256.Sum256([]byte(input.DPoPProofJTI))
	normalizedChallengeURI, err := dpop.NormalizeHTU(challengeRequestURI)
	if err != nil {
		t.Fatalf("normalize challenge request URI: %v", err)
	}
	expectedProofURIHash := sha256.Sum256([]byte(normalizedChallengeURI))
	if string(proofJTIHash) != string(expectedProofJTIHash[:]) || string(proofURIHash) != string(expectedProofURIHash[:]) || strings.Contains(string(proofJTIHash), input.DPoPProofJTI) || strings.Contains(string(proofURIHash), normalizedChallengeURI) {
		t.Fatal("challenge DPoP request binding was not persisted exclusively as digests")
	}
	if _, err := store.Create(ctx, input); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("challenge DPoP proof replay should fail across challenge IDs: %v", err)
	}

	missingUser := input
	missingUser.ApplicationUserID = mustSessionID(t, id.ApplicationUser)
	if _, err := store.Create(ctx, missingUser); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("unknown user should fail closed: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE session_challenges SET binding_hash = $2 WHERE session_challenge_id = $1
	`, challenge.ID, make([]byte, sha256.Size)); err != nil {
		t.Fatalf("tamper challenge binding hash: %v", err)
	}
	if _, err := store.Get(ctx, challenge.ID); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("tampered binding should fail: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE session_challenges
		SET binding_hash = $2, dpop_public_jwk = dpop_public_jwk || '{"kid":"untrusted"}'::jsonb
		WHERE session_challenge_id = $1
	`, challenge.ID, challenge.BindingHash[:]); err != nil {
		t.Fatalf("tamper challenge JWK: %v", err)
	}
	if _, err := store.Get(ctx, challenge.ID); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("JWK with extra member should fail: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE session_challenges SET dpop_public_jwk = dpop_public_jwk - 'kid' WHERE session_challenge_id = $1
	`, challenge.ID); err != nil {
		t.Fatalf("restore challenge JWK: %v", err)
	}
	if _, err := store.Get(ctx, challenge.ID); err != nil {
		t.Fatalf("restored challenge should load: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE session_challenges
		SET attestation_provider = 'app_attest'
		WHERE session_challenge_id = $1
	`, challenge.ID); err != nil {
		t.Fatalf("tamper persisted attestation provider: %v", err)
	}
	if _, err := store.Get(ctx, challenge.ID); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("tampered challenge policy should fail: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE session_challenges
		SET attestation_provider = 'debug'
		WHERE session_challenge_id = $1
	`, challenge.ID); err != nil {
		t.Fatalf("restore persisted attestation provider: %v", err)
	}

	assertSingleChallengeConsumption(t, ctx, pool, challenge, now.Add(time.Minute))
	if _, err := store.Get(ctx, challenge.ID); !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("consumed challenge should fail: %v", err)
	}

	input = withChallengeProof(input, challengeRequestURI, now, "challenge-store-expiring")
	expiring, err := store.Create(ctx, input)
	if err != nil {
		t.Fatalf("create expiring challenge: %v", err)
	}
	now = expiring.ExpiresAt.Add(time.Second)
	if _, err := store.Get(ctx, expiring.ID); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired challenge should fail: %v", err)
	}
	deleted, err := store.DeleteExpired(ctx, now, 100)
	if err != nil {
		t.Fatalf("delete expired challenges: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("challenge replay digests were removed before the replay window: deleted=%d", deleted)
	}
	if _, err := store.Create(ctx, input); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("expired challenge proof became reusable during replay retention: %v", err)
	}
	now = time.Unix(challenge.Binding.IssuedAt, 0).UTC().Add(defaultReplayLifetime + time.Second)
	deleted, err = store.DeleteExpired(ctx, now, 100)
	if err != nil {
		t.Fatalf("delete replay-safe expired challenges: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted challenge count=%d want=2", deleted)
	}
	var remaining int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM session_challenges").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining challenge count=%d err=%v", remaining, err)
	}
}

func TestSessionExchangePostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	fixture := createChallengeFixture(t, ctx, pool)
	policyRevisionID := activateChallengeTestRevision(t, ctx, pool, fixture, now)
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct configuration store: %v", err)
	}
	challengeStore, err := newChallengeStore(ChallengeStoreConfig{
		Pool: pool, Configuration: configurationStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct challenge store: %v", err)
	}
	dpopKey, jwk, jkt := newChallengeKey(t)
	challengeRequestURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
	exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
	refreshURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions/refresh")
	challengeInput := withChallengeProof(ChallengeInput{
		OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, ConfigurationRevisionID: policyRevisionID, EnvironmentSlug: "development",
		ApplicationUserID: fixture.applicationUserID, IdentityProvider: "firebase",
		IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
		Platform: "ios", DPoPJKT: jkt, DPoPPublicJWK: jwk,
	}, challengeRequestURI, now, "initial-exchange-challenge")
	challenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create exchange challenge: %v", err)
	}

	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	envelope, err := secrets.NewEnvironmentMasterKey(masterKey)
	if err != nil {
		t.Fatalf("construct signing envelope: %v", err)
	}
	keyManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct signing-key manager: %v", err)
	}
	accessIssuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	sessionStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: accessIssuer, Configuration: configurationStore,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct session store: %v", err)
	}
	attestationResult := verifiedDebugAttestation(t, challenge.Binding, now, "initial-exchange")
	exchangeInput := ExchangeInput{
		ChallengeID: challenge.ID, Attestation: attestationResult,
		DPoPProof:  signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "initial-exchange"),
		HTTPMethod: "POST", RequestURI: exchangeURI, KeyStorage: "unknown", AppVersion: strings.Repeat("界", 128),
	}
	issued, err := sessionStore.Exchange(ctx, exchangeInput)
	if err != nil {
		t.Fatalf("exchange session challenge: %v", err)
	}
	if id.Validate(issued.Installation.ID, id.Installation) != nil || id.Validate(issued.GrantID, id.SessionGrant) != nil || id.Validate(issued.RefreshID, id.RefreshToken) != nil || id.Validate(issued.RefreshFamilyID, id.RefreshTokenFamily) != nil || issued.Installation.DPoPJKT != jkt || issued.Trust.Level != "debug" {
		t.Fatalf("unexpected issued session: %#v", issued)
	}
	if strings.Contains(fmt.Sprint(issued.Refresh), issued.Refresh.Reveal()) || strings.Contains(fmt.Sprintf("%#v", issued.Refresh), issued.Refresh.Reveal()) {
		t.Fatal("refresh-token formatting disclosed plaintext")
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token verifier: %v", err)
	}
	principal, err := verifier.Verify(ctx, issued.Access.Token)
	if err != nil {
		t.Fatalf("verify exchanged access token: %v", err)
	}
	if principal.InstallationID != issued.Installation.ID || principal.SessionGrantID != issued.GrantID || principal.ApplicationUserID != fixture.applicationUserID || principal.PolicyRevisionID != policyRevisionID {
		t.Fatalf("unexpected exchanged principal: %#v", principal)
	}
	if !issued.Access.ExpiresAt.Equal(now.Add(10*time.Minute)) || !issued.RefreshExpiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("default active policy was not authoritative: access=%s refresh=%s", issued.Access.ExpiresAt, issued.RefreshExpiresAt)
	}
	authorized, err := sessionStore.Authorize(ctx, principal)
	if err != nil || authorized.SessionGrantID != issued.GrantID || authorized.AttestationProvider != "debug" {
		t.Fatalf("authorize exchanged session=%#v err=%v", authorized, err)
	}
	tamperedPrincipal := principal
	tamperedPrincipal.IssuedAt = tamperedPrincipal.IssuedAt.Add(time.Second)
	if _, err := sessionStore.Authorize(ctx, tamperedPrincipal); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("principal mutated after token verification should fail integrity validation: %v", err)
	}
	assertSessionExchangePersistence(t, ctx, pool, issued)
	assertExchangeProofRecorded(t, ctx, pool, issued, "initial-exchange", now, "POST", exchangeURI)

	replayInput := exchangeInput
	replayInput.DPoPProof = signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "challenge-replay")
	if _, err := sessionStore.Exchange(ctx, replayInput); !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("replayed exchange should fail: %v", err)
	}
	assertTableCount(t, ctx, pool, "installations", 1)
	assertTableCount(t, ctx, pool, "session_grants", 1)
	assertTableCount(t, ctx, pool, "refresh_tokens", 1)

	binding, err := sessionStore.InspectRefresh(ctx, issued.Refresh)
	if err != nil {
		t.Fatalf("inspect initial refresh binding: %v", err)
	}
	if binding.DPoPJKT != jkt || binding.SessionGrantID != issued.GrantID || binding.Status != "active" || binding.IdentityProvider != "firebase" || binding.DPoPPublicJWK != jwk {
		t.Fatalf("unexpected initial refresh binding: %#v", binding)
	}
	operationNow := challenge.ExpiresAt.Add(time.Second)
	now = time.Unix(challenge.Binding.IssuedAt, 0).UTC().Add(defaultReplayLifetime + time.Second)
	deleted, err := challengeStore.DeleteExpired(ctx, now, 10)
	if err != nil || deleted != 1 {
		t.Fatalf("prune exchanged challenge: deleted=%d err=%v", deleted, err)
	}
	var retainedAttestationEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM attestation_events WHERE session_challenge_id = $1`, challenge.ID).Scan(&retainedAttestationEvents); err != nil || retainedAttestationEvents != 1 {
		t.Fatalf("attestation audit event should survive challenge cleanup: count=%d err=%v", retainedAttestationEvents, err)
	}
	now = operationNow

	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "invalid-attestation-challenge")
	invalidChallenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create invalid-attestation challenge: %v", err)
	}
	invalidInput := ExchangeInput{
		ChallengeID: invalidChallenge.ID,
		Attestation: attestation.Result{
			Provider: "debug", TrustLevel: "debug", VerifiedAt: now, ExpiresAt: now.Add(10 * time.Minute),
			NormalizedSignals: map[string]any{"deterministic_test_evidence": true},
			EvidenceHash:      sha256.Sum256([]byte("caller-forged-result")),
		},
		DPoPProof:  signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "unsealed-attestation"),
		HTTPMethod: "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	if _, err := sessionStore.Exchange(ctx, invalidInput); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("caller-forged unsealed attestation should fail: %v", err)
	}
	invalidInput.Attestation = verifiedDebugAttestation(t, challenge.Binding, now, "wrong-binding")
	invalidInput.DPoPProof = signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "wrong-binding")
	if _, err := sessionStore.Exchange(ctx, invalidInput); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("attestation sealed for a different challenge should fail: %v", err)
	}
	invalidInput.Attestation = verifiedDebugAttestation(t, invalidChallenge.Binding, now, "mutated-result")
	invalidInput.Attestation.NormalizedSignals["deterministic_test_evidence"] = false
	invalidInput.DPoPProof = signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "mutated-result")
	if _, err := sessionStore.Exchange(ctx, invalidInput); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("attestation mutated after verification should fail: %v", err)
	}
	wrongDPoPKey, _, _ := newChallengeKey(t)
	invalidInput.Attestation = verifiedDebugAttestation(t, invalidChallenge.Binding, now, "wrong-dpop-key")
	invalidInput.DPoPProof = signedSessionDPoP(t, wrongDPoPKey, "POST", exchangeURI, now, "wrong-dpop-key")
	if _, err := sessionStore.Exchange(ctx, invalidInput); err == nil {
		t.Fatal("DPoP proof from a key outside the challenge binding was accepted")
	}
	if _, err := challengeStore.Get(ctx, invalidChallenge.ID); err != nil {
		t.Fatalf("rejected attestation or DPoP proof should not consume challenge: %v", err)
	}

	rotateInput := RotateInput{
		RefreshToken: issued.Refresh,
		DPoPProof:    signedSessionDPoP(t, dpopKey, "POST", refreshURI, now, "initial-rotation"),
		HTTPMethod:   "POST", RequestURI: refreshURI,
	}
	rotated, err := sessionStore.Rotate(ctx, rotateInput)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if rotated.Refresh.Reveal() == issued.Refresh.Reveal() || rotated.RefreshFamilyID != issued.RefreshFamilyID || rotated.GrantID == issued.GrantID || rotated.Installation.ID != issued.Installation.ID {
		t.Fatalf("unexpected rotated session: %#v", rotated)
	}
	rotatedPrincipal, err := verifier.Verify(ctx, rotated.Access.Token)
	if err != nil || rotatedPrincipal.SessionGrantID != rotated.GrantID || rotatedPrincipal.DPoPJKT != jkt {
		t.Fatalf("verify rotated access token principal=%#v err=%v", rotatedPrincipal, err)
	}
	oldBinding, err := sessionStore.InspectRefresh(ctx, issued.Refresh)
	if err != nil || oldBinding.Status != "rotated" {
		t.Fatalf("old refresh-token status=%q err=%v", oldBinding.Status, err)
	}
	newBinding, err := sessionStore.InspectRefresh(ctx, rotated.Refresh)
	if err != nil || newBinding.Status != "active" {
		t.Fatalf("new refresh-token status=%q err=%v", newBinding.Status, err)
	}
	replayedRefreshProof := rotateInput
	replayedRefreshProof.RefreshToken = rotated.Refresh
	if _, err := sessionStore.Rotate(ctx, replayedRefreshProof); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("successful refresh proof replayed through the new grant should fail: %v", err)
	}
	newBinding, err = sessionStore.InspectRefresh(ctx, rotated.Refresh)
	if err != nil || newBinding.Status != "active" || newBinding.SessionGrantID != rotated.GrantID {
		t.Fatalf("replayed proof consumed or revoked the newly issued refresh token: binding=%#v err=%v", newBinding, err)
	}
	if _, err := sessionStore.Authorize(ctx, rotatedPrincipal); err != nil {
		t.Fatalf("replayed proof revoked the newly issued access grant: %v", err)
	}
	reuseInput := rotateInput
	reuseInput.DPoPProof = signedSessionDPoP(t, dpopKey, "POST", refreshURI, now, "family-reuse")
	if _, err := sessionStore.Rotate(ctx, reuseInput); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("rotated refresh-token reuse should revoke family: %v", err)
	}
	var reusedCount, revokedCount, revokedGrantCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status = 'reused'),
			count(*) FILTER (WHERE status = 'revoked')
		FROM refresh_tokens WHERE family_id = $1
	`, issued.RefreshFamilyID).Scan(&reusedCount, &revokedCount); err != nil {
		t.Fatalf("count reused refresh family: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM session_grants
		WHERE session_grant_id IN (
			SELECT session_grant_id FROM refresh_tokens WHERE family_id = $1
		) AND revoked_at IS NOT NULL AND revoke_reason = 'refresh_token_reuse'
	`, issued.RefreshFamilyID).Scan(&revokedGrantCount); err != nil {
		t.Fatalf("count reuse-revoked grants: %v", err)
	}
	if reusedCount != 1 || revokedCount != 1 || revokedGrantCount != 2 {
		t.Fatalf("reuse revocation reused=%d revoked=%d grants=%d", reusedCount, revokedCount, revokedGrantCount)
	}
	if _, err := sessionStore.Authorize(ctx, rotatedPrincipal); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("reuse-revoked access grant should fail authorization: %v", err)
	}

	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "old-policy-challenge")
	policyChallenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create policy-snapshot challenge: %v", err)
	}
	nextPolicyRevisionID := activateNextChallengeTestRevision(t, ctx, pool, fixture, policyRevisionID, now)
	policyExchange := ExchangeInput{
		ChallengeID: policyChallenge.ID,
		Attestation: verifiedDebugAttestation(t, policyChallenge.Binding, now, "active-policy"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "active-policy"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	if _, err := sessionStore.Exchange(ctx, policyExchange); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("challenge from superseded configuration revision should fail closed: %v", err)
	}
	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "active-policy-challenge")
	challengeInput.ConfigurationRevisionID = nextPolicyRevisionID
	policyChallenge, err = challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create challenge against new active policy: %v", err)
	}
	policyExchange.ChallengeID = policyChallenge.ID
	policyExchange.Attestation = verifiedDebugAttestation(t, policyChallenge.Binding, now, "active-policy")
	policySession, err := sessionStore.Exchange(ctx, policyExchange)
	if err != nil {
		t.Fatalf("exchange challenge from new active policy: %v", err)
	}
	policyPrincipal, err := verifier.Verify(ctx, policySession.Access.Token)
	if err != nil {
		t.Fatalf("verify active-policy access token: %v", err)
	}
	if policyPrincipal.PolicyRevisionID != nextPolicyRevisionID || !policySession.Access.ExpiresAt.Equal(now.Add(7*time.Minute)) || !policySession.RefreshExpiresAt.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("exchange did not use authoritative active snapshot: principal=%#v session=%#v", policyPrincipal, policySession)
	}
	assertExchangeProofRecorded(t, ctx, pool, policySession, "active-policy", now, "POST", exchangeURI)

	futureInput := challengeInput
	futureInput.IdentityVerifiedAt = now.Add(20 * time.Second)
	futureInput.IdentityExpiresAt = now.Add(time.Hour)
	futureInput = withChallengeProof(futureInput, challengeRequestURI, now, "future-within-skew-challenge")
	futureChallenge, err := challengeStore.Create(ctx, futureInput)
	if err != nil {
		t.Fatalf("create future-within-skew challenge: %v", err)
	}
	futureExchange := ExchangeInput{
		ChallengeID: futureChallenge.ID,
		Attestation: verifiedDebugAttestation(t, futureChallenge.Binding, now.Add(20*time.Second), "future-within-skew"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "future-within-skew"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	futureSession, err := sessionStore.Exchange(ctx, futureExchange)
	if err != nil {
		t.Fatalf("exchange future-within-skew proofs: %v", err)
	}
	futurePrincipal, err := verifier.Verify(ctx, futureSession.Access.Token)
	if err != nil {
		t.Fatalf("verify future-within-skew access token: %v", err)
	}
	var persistedIdentityVerifiedAt, persistedAttestedAt, persistedIssuedAt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT identity_verified_at, attested_at, issued_at
		FROM session_grants
		WHERE session_grant_id = $1
	`, futureSession.GrantID).Scan(&persistedIdentityVerifiedAt, &persistedAttestedAt, &persistedIssuedAt); err != nil {
		t.Fatalf("read clamped proof timestamps: %v", err)
	}
	if persistedIdentityVerifiedAt.After(persistedIssuedAt) || persistedAttestedAt.After(persistedIssuedAt) ||
		!persistedIdentityVerifiedAt.Equal(persistedIssuedAt) || !persistedAttestedAt.Equal(persistedIssuedAt) {
		t.Fatalf("future proof timestamps were not clamped to issuance: identity=%s attested=%s issued=%s", persistedIdentityVerifiedAt, persistedAttestedAt, persistedIssuedAt)
	}
	if _, err := sessionStore.Authorize(ctx, futurePrincipal); err != nil {
		t.Fatalf("clamped future-within-skew grant was not immediately usable: %v", err)
	}
	assertExchangeProofRecorded(t, ctx, pool, futureSession, "future-within-skew", now, "POST", exchangeURI)

	command, err := pool.Exec(ctx, `
		UPDATE installations
		SET trust_level = 'app_verified', updated_at = $2
		WHERE installation_id = $1
	`, issued.Installation.ID, now)
	if err != nil {
		t.Fatalf("alter current installation trust for transition test: %v", err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("altered installation trust rows=%d want=1", command.RowsAffected())
	}
	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "trust-transition-challenge")
	trustChallenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create trust-transition challenge: %v", err)
	}
	trustExchange := ExchangeInput{
		ChallengeID: trustChallenge.ID,
		Attestation: verifiedDebugAttestation(t, trustChallenge.Binding, now, "trust-transition"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "trust-transition"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.4",
	}
	trustSession, err := sessionStore.Exchange(ctx, trustExchange)
	if err != nil {
		t.Fatalf("exchange after installation trust transition: %v", err)
	}
	if trustSession.Installation.ID != issued.Installation.ID || trustSession.Trust.Level != "debug" {
		t.Fatalf("trust transition did not preserve installation and issue debug session: %#v", trustSession)
	}
	trustPrincipal, err := verifier.Verify(ctx, trustSession.Access.Token)
	if err != nil {
		t.Fatalf("verify trust-transition access token: %v", err)
	}
	var transitionedGrantCount, transitionedRefreshCount, priorLiveGrantCount, priorLiveRefreshCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM session_grants
		WHERE session_grant_id IN ($1, $2)
		  AND revoked_at IS NOT NULL
		  AND revoke_reason = 'attestation_trust_changed'
	`, policySession.GrantID, futureSession.GrantID).Scan(&transitionedGrantCount); err != nil {
		t.Fatalf("count trust-transition grants: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM refresh_tokens
		WHERE refresh_token_id IN ($1, $2) AND status = 'revoked'
	`, policySession.RefreshID, futureSession.RefreshID).Scan(&transitionedRefreshCount); err != nil {
		t.Fatalf("count trust-transition refresh credentials: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM session_grants
		WHERE installation_id = $1 AND session_grant_id <> $2 AND revoked_at IS NULL
	`, trustSession.Installation.ID, trustSession.GrantID).Scan(&priorLiveGrantCount); err != nil {
		t.Fatalf("count live grants after trust transition: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM refresh_tokens
		WHERE installation_id = $1 AND refresh_token_id <> $2 AND status IN ('staged', 'active')
	`, trustSession.Installation.ID, trustSession.RefreshID).Scan(&priorLiveRefreshCount); err != nil {
		t.Fatalf("count live refresh credentials after trust transition: %v", err)
	}
	if transitionedGrantCount != 2 || transitionedRefreshCount != 2 || priorLiveGrantCount != 0 || priorLiveRefreshCount != 0 {
		t.Fatalf("trust transition was not atomic: grants=%d refresh=%d prior_live_grants=%d prior_live_refresh=%d", transitionedGrantCount, transitionedRefreshCount, priorLiveGrantCount, priorLiveRefreshCount)
	}
	if _, err := sessionStore.Authorize(ctx, policyPrincipal); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("old policy grant remained authorized after trust transition: %v", err)
	}
	if _, err := sessionStore.Authorize(ctx, futurePrincipal); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("future-within-skew grant remained authorized after trust transition: %v", err)
	}
	if _, err := sessionStore.Authorize(ctx, trustPrincipal); err != nil {
		t.Fatalf("new trust-transition grant was not authorized: %v", err)
	}
	trustRefreshBinding, err := sessionStore.InspectRefresh(ctx, trustSession.Refresh)
	if err != nil || trustRefreshBinding.Status != "active" || trustRefreshBinding.SessionGrantID != trustSession.GrantID {
		t.Fatalf("new trust-transition refresh credential was not active: binding=%#v err=%v", trustRefreshBinding, err)
	}
	assertExchangeProofRecorded(t, ctx, pool, trustSession, "trust-transition", now, "POST", exchangeURI)

	expiredIdentityInput := challengeInput
	expiredIdentityInput.IdentityExpiresAt = now.Add(time.Second)
	expiredIdentityInput = withChallengeProof(expiredIdentityInput, challengeRequestURI, now, "expired-identity-challenge")
	expiredIdentityChallenge, err := challengeStore.Create(ctx, expiredIdentityInput)
	if err != nil {
		t.Fatalf("create identity-expiry exchange challenge: %v", err)
	}
	now = now.Add(2 * time.Second)
	expiredIdentityExchange := ExchangeInput{
		ChallengeID: expiredIdentityChallenge.ID,
		Attestation: verifiedDebugAttestation(t, expiredIdentityChallenge.Binding, now, "expired-identity-exchange"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "expired-identity-exchange"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	if _, err := sessionStore.Exchange(ctx, expiredIdentityExchange); !errors.Is(err, ErrIdentityRefreshRequired) {
		t.Fatalf("identity expiring between challenge and exchange should require reauthentication: %v", err)
	}
	if _, err := challengeStore.Get(ctx, expiredIdentityChallenge.ID); err != nil {
		t.Fatalf("identity-expired exchange should not consume challenge: %v", err)
	}

	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "refresh-freshness-challenge")
	freshnessChallenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create refresh-freshness challenge: %v", err)
	}
	freshnessExchange := ExchangeInput{
		ChallengeID: freshnessChallenge.ID,
		Attestation: verifiedDebugAttestation(t, freshnessChallenge.Binding, now, "refresh-freshness"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "refresh-freshness"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	freshnessSession, err := sessionStore.Exchange(ctx, freshnessExchange)
	if err != nil {
		t.Fatalf("exchange refresh-freshness session: %v", err)
	}
	assertExchangeProofRecorded(t, ctx, pool, freshnessSession, "refresh-freshness", now, "POST", exchangeURI)
	freshnessRotate := RotateInput{RefreshToken: freshnessSession.Refresh, HTTPMethod: "POST", RequestURI: refreshURI}
	now = time.Date(2026, 8, 27, 12, 16, 0, 0, time.UTC)
	freshnessRotate.DPoPProof = signedSessionDPoP(t, dpopKey, "POST", refreshURI, now, "expired-attestation")
	if _, err := sessionStore.Rotate(ctx, freshnessRotate); !errors.Is(err, ErrAttestationRefreshNeeded) {
		t.Fatalf("expired attestation should require fresh evidence: %v", err)
	}
	now = time.Date(2026, 8, 27, 13, 0, 0, 0, time.UTC)
	freshnessRotate.DPoPProof = signedSessionDPoP(t, dpopKey, "POST", refreshURI, now, "expired-identity")
	if _, err := sessionStore.Rotate(ctx, freshnessRotate); !errors.Is(err, ErrIdentityRefreshRequired) {
		t.Fatalf("expired identity should require reauthentication: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET status = 'revoked', revoked_at = GREATEST(issued_at, $2)
		WHERE refresh_token_id = $1
	`, freshnessSession.RefreshID, now); err != nil {
		t.Fatalf("simulate migrated legacy refresh revocation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE session_grants
		SET revoked_at = GREATEST(issued_at, $2), revoke_reason = 'schema_upgrade_v5',
		    identity_provider_key = NULL, identity_expires_at = NULL,
		    attested_at = NULL, attestation_provider = NULL, attestation_expires_at = NULL
		WHERE session_grant_id = $1
	`, freshnessSession.GrantID, now); err != nil {
		t.Fatalf("simulate migrated legacy grant metadata: %v", err)
	}
	if _, err := sessionStore.InspectRefresh(ctx, freshnessSession.Refresh); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("migrated nullable legacy refresh metadata should fail with a safe revocation sentinel: %v", err)
	}

	challengeInput.IdentityVerifiedAt = now
	challengeInput.IdentityExpiresAt = now.Add(time.Hour)
	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "installation-revocation-challenge")
	revocationChallenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create installation-revocation session challenge: %v", err)
	}
	revocationExchange := ExchangeInput{
		ChallengeID: revocationChallenge.ID,
		Attestation: verifiedDebugAttestation(t, revocationChallenge.Binding, now, "installation-revocation"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "installation-revocation"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	revocationSession, err := sessionStore.Exchange(ctx, revocationExchange)
	if err != nil {
		t.Fatalf("exchange installation-revocation session: %v", err)
	}
	assertExchangeProofRecorded(t, ctx, pool, revocationSession, "installation-revocation", now, "POST", exchangeURI)
	revocationPrincipal, err := verifier.Verify(ctx, revocationSession.Access.Token)
	if err != nil {
		t.Fatalf("verify installation-revocation access token: %v", err)
	}
	revocationURI := mustSessionURL(t, "https://gateway.example.test/client/v1/installations/current")
	if err := sessionStore.RevokeCurrentInstallation(ctx, AccessRequestInput{
		AccessToken: revocationSession.Access.Token, Principal: revocationPrincipal,
		DPoPProof: signedSessionAccessDPoP(t, dpopKey, "DELETE", revocationURI, now,
			revocationSession.Access.Token.Reveal(), "installation-revocation-request"),
		HTTPMethod: "DELETE", RequestURI: revocationURI,
	}); err != nil {
		t.Fatalf("revoke current installation: %v", err)
	}
	if _, err := sessionStore.Authorize(ctx, revocationPrincipal); !errors.Is(err, ErrInstallationRevoked) {
		t.Fatalf("revoked installation should fail authorization: %v", err)
	}
	challengeInput = withChallengeProof(challengeInput, challengeRequestURI, now, "revoked-installation-challenge")
	revokedChallenge, err := challengeStore.Create(ctx, challengeInput)
	if err != nil {
		t.Fatalf("create revoked-installation challenge: %v", err)
	}
	revokedInput := ExchangeInput{
		ChallengeID: revokedChallenge.ID,
		Attestation: verifiedDebugAttestation(t, revokedChallenge.Binding, now, "revoked-installation"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "revoked-installation"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	}
	if _, err := sessionStore.Exchange(ctx, revokedInput); !errors.Is(err, ErrInstallationRevoked) {
		t.Fatalf("revoked installation should fail: %v", err)
	}
	if _, err := challengeStore.Get(ctx, revokedChallenge.ID); err != nil {
		t.Fatalf("revoked exchange should roll back challenge consumption: %v", err)
	}
}

func TestSessionExchangeAttestationPolicyPostgreSQL(t *testing.T) {
	tests := []struct {
		name             string
		provider         string
		mode             string
		minimumTrust     string
		maximumAge       string
		exchangeAdvance  time.Duration
		challengeFailure bool
	}{
		{name: "provider mismatch", provider: "app_attest", mode: "required", minimumTrust: "app_verified", maximumAge: "10m"},
		{name: "insufficient trust", provider: "debug", mode: "required", minimumTrust: "strong_device_verified", maximumAge: "10m"},
		{name: "maximum age exceeded", provider: "debug", mode: "required", minimumTrust: "debug", maximumAge: "1m", exchangeAdvance: 2 * time.Minute},
		{name: "preferred is ineligible", provider: "debug", mode: "preferred", minimumTrust: "debug", maximumAge: "10m", challengeFailure: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool, ctx := isolatedSessionPool(t)
			now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
			fixture := createChallengeFixture(t, ctx, pool)
			policyRevisionID := activateChallengeTestRevisionWithPolicy(
				t, ctx, pool, fixture, now,
				test.provider, test.mode, test.minimumTrust, test.maximumAge,
			)
			configurationStore, err := configuration.NewStore(pool)
			if err != nil {
				t.Fatalf("construct policy-test configuration store: %v", err)
			}
			challengeStore, err := newChallengeStore(ChallengeStoreConfig{
				Pool: pool, Configuration: configurationStore, Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatalf("construct policy-test challenge store: %v", err)
			}
			dpopKey, jwk, jkt := newChallengeKey(t)
			challengeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
			challengeInput := withChallengeProof(ChallengeInput{
				OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
				EnvironmentID: fixture.environmentID, ConfigurationRevisionID: policyRevisionID, EnvironmentSlug: "development",
				ApplicationUserID: fixture.applicationUserID, IdentityProvider: "firebase",
				IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
				Platform: "ios", DPoPJKT: jkt, DPoPPublicJWK: jwk,
			}, challengeURI, now, "policy-test-challenge-"+test.name)
			challenge, err := challengeStore.Create(ctx, challengeInput)
			if test.challengeFailure {
				if !errors.Is(err, ErrSessionScope) {
					t.Fatalf("ineligible challenge policy error=%v want=%v", err, ErrSessionScope)
				}
				return
			}
			if err != nil {
				t.Fatalf("create policy-test challenge: %v", err)
			}
			result := verifiedDebugAttestation(t, challenge.Binding, now, "policy-test-"+test.name)
			now = now.Add(test.exchangeAdvance)
			sessionStore, err := NewStore(StoreConfig{
				Pool: pool, AccessTokens: unusedAccessIssuer{}, Configuration: configurationStore,
				Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatalf("construct policy-test session store: %v", err)
			}
			exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
			_, err = sessionStore.Exchange(ctx, ExchangeInput{
				ChallengeID: challenge.ID, Attestation: result,
				DPoPProof:  signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "policy-test-exchange-"+test.name),
				HTTPMethod: "POST", RequestURI: exchangeURI, KeyStorage: "software", AppVersion: "1.0.0",
			})
			if !errors.Is(err, ErrSessionInvalid) {
				t.Fatalf("policy mismatch exchange error=%v want=%v", err, ErrSessionInvalid)
			}
			if _, err := challengeStore.Get(ctx, challenge.ID); err != nil {
				t.Fatalf("rejected policy exchange consumed challenge: %v", err)
			}
		})
	}
}

type unusedAccessIssuer struct{}

func (unusedAccessIssuer) Prepare(context.Context) (PreparedAccessIssuer, error) {
	return nil, errors.New("access issuer must not be reached for rejected attestation policy")
}

func TestSessionExchangeAndRotateWithSingleDatabaseConnection(t *testing.T) {
	pool, ctx := isolatedSessionPoolWithMaxConnections(t, 1)
	now := time.Date(2026, 8, 27, 12, 0, 0, 987654321, time.UTC)
	fixture := createChallengeFixture(t, ctx, pool)
	policyRevisionID := activateChallengeTestRevision(t, ctx, pool, fixture, now)
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct single-connection configuration store: %v", err)
	}
	challengeStore, err := newChallengeStore(ChallengeStoreConfig{
		Pool: pool, Configuration: configurationStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct single-connection challenge store: %v", err)
	}
	dpopKey, jwk, jkt := newChallengeKey(t)
	challengeRequestURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
	challenge, err := challengeStore.Create(ctx, ChallengeInput{
		OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, ConfigurationRevisionID: policyRevisionID, EnvironmentSlug: "development",
		ApplicationUserID: fixture.applicationUserID, IdentityProvider: "firebase",
		IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
		Platform: "ios", DPoPJKT: jkt, DPoPPublicJWK: jwk,
		DPoPProofJTI:   sessionProofJTI("single-connection-challenge", now),
		DPoPHTTPMethod: "POST", DPoPRequestURI: challengeRequestURI,
	})
	if err != nil {
		t.Fatalf("create single-connection challenge: %v", err)
	}
	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 32)))
	if err != nil {
		t.Fatalf("construct single-connection signing envelope: %v", err)
	}
	keyManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct single-connection key manager: %v", err)
	}
	accessIssuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct single-connection access issuer: %v", err)
	}
	sessionStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: accessIssuer, Configuration: configurationStore,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct single-connection session store: %v", err)
	}
	exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
	operationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	issued, err := sessionStore.Exchange(operationCtx, ExchangeInput{
		ChallengeID: challenge.ID,
		Attestation: verifiedDebugAttestation(t, challenge.Binding, now, "single-connection-exchange"),
		DPoPProof:   signedSessionDPoP(t, dpopKey, "POST", exchangeURI, now, "single-connection-exchange"),
		HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "secure_enclave", AppVersion: "1.2.3",
	})
	if err != nil {
		t.Fatalf("exchange must not require a nested pool connection: %v", err)
	}
	if issued.Access.ExpiresAt.Sub(issued.Access.IssuedAt) != 10*time.Minute || issued.RefreshExpiresAt.Sub(issued.Access.IssuedAt) != 30*24*time.Hour {
		t.Fatalf("fractional exchange clock changed exact TTLs: access=%s refresh=%s", issued.Access.ExpiresAt.Sub(issued.Access.IssuedAt), issued.RefreshExpiresAt.Sub(issued.Access.IssuedAt))
	}
	refreshURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions/refresh")
	rotated, err := sessionStore.Rotate(operationCtx, RotateInput{
		RefreshToken: issued.Refresh,
		DPoPProof:    signedSessionDPoP(t, dpopKey, "POST", refreshURI, now, "single-connection-refresh"),
		HTTPMethod:   "POST", RequestURI: refreshURI,
	})
	if err != nil {
		t.Fatalf("refresh must not require a nested pool connection: %v", err)
	}
	if rotated.Access.ExpiresAt.Sub(rotated.Access.IssuedAt) != 10*time.Minute || rotated.RefreshExpiresAt.Sub(rotated.Access.IssuedAt) != 30*24*time.Hour {
		t.Fatalf("fractional refresh clock changed exact TTLs: access=%s refresh=%s", rotated.Access.ExpiresAt.Sub(rotated.Access.IssuedAt), rotated.RefreshExpiresAt.Sub(rotated.Access.IssuedAt))
	}
}

type challengeFixture struct {
	organizationID    string
	applicationID     string
	environmentID     string
	applicationUserID string
}

func activateChallengeTestRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fixture challengeFixture, now time.Time) string {
	return activateChallengeTestRevisionWithPolicy(t, ctx, pool, fixture, now, "debug", "required", "debug", "10m")
}

func activateChallengeTestRevisionWithPolicy(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fixture challengeFixture, now time.Time, provider, mode, minimumTrust, maximumAge string) string {
	t.Helper()
	adminUserID := mustSessionID(t, id.AdminUser)
	adminMembershipID := mustSessionID(t, id.AdminMembership)
	revisionID := mustSessionID(t, id.ConfigRevision)
	selection := map[string]any{
		"provider": provider, "mode": mode, "minimumTrustLevel": minimumTrust,
	}
	if provider == "debug" {
		selection["secretRef"] = "secret/debug-attestation-public-keys"
	}
	compiledDocument, err := json.Marshal(map[string]any{"spec": sessionTestCompiledSpec(
		[]any{map[string]any{"id": "firebase", "type": "firebase"}},
		[]any{map[string]any{
			"id": "native", "maxAge": maximumAge,
			"platforms": map[string]any{"ios": selection},
		}},
	)})
	if err != nil {
		t.Fatalf("encode active session test revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name)
		VALUES ($1, 'session-owner@example.test', 'session-owner@example.test', 'Session Owner')
	`, adminUserID); err != nil {
		t.Fatalf("create session test admin: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role)
		VALUES ($1, $2, $3, 'owner')
	`, adminMembershipID, fixture.organizationID, adminUserID); err != nil {
		t.Fatalf("create session test membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_report, created_by_admin_user_id, validated_at, activated_at
		) VALUES (
		    $1, $2, $3, $4, 1, 'session-test-etag-0001', 'valid', '{}'::jsonb,
		    $7::jsonb,
		          '{"valid":true,"checked_at":"2026-08-27T12:00:00Z","issues":[]}'::jsonb, $5, $6, $6)
	`, revisionID, fixture.organizationID, fixture.applicationID, fixture.environmentID, adminUserID, now, compiledDocument); err != nil {
		t.Fatalf("create active session test revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO active_config_revisions (
			organization_id, application_id, environment_id, config_revision_id,
			revision_status, activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, 'valid', $5, $6)
	`, fixture.organizationID, fixture.applicationID, fixture.environmentID, revisionID, adminUserID, now); err != nil {
		t.Fatalf("activate session test revision: %v", err)
	}
	return revisionID
}

func activateNextChallengeTestRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fixture challengeFixture, currentRevisionID string, now time.Time) string {
	t.Helper()
	var adminUserID string
	if err := pool.QueryRow(ctx, `
		SELECT created_by_admin_user_id
		FROM config_revisions
		WHERE config_revision_id = $1
	`, currentRevisionID).Scan(&adminUserID); err != nil {
		t.Fatalf("resolve active policy owner: %v", err)
	}
	revisionID := mustSessionID(t, id.ConfigRevision)
	compiledSpec := sessionTestCompiledSpec(
		[]any{map[string]any{"id": "firebase", "type": "firebase"}},
		[]any{map[string]any{
			"id": "native", "maxAge": "10m", "platforms": map[string]any{
				"ios": map[string]any{
					"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
					"secretRef": "secret/debug-attestation-public-keys",
				},
			},
		}},
	)
	compiledSpec["session"] = map[string]any{
		"accessTokenTtl": "7m", "challengeTtl": "4m", "refreshTokenTtl": "48h", "maximumClockSkewSeconds": 30,
	}
	compiledDocument, err := json.Marshal(map[string]any{"spec": compiledSpec})
	if err != nil {
		t.Fatalf("encode next active session test revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_report, created_by_admin_user_id, validated_at, activated_at
			) VALUES (
				$1, $2, $3, $4, 2, 'session-test-etag-0002', 'valid', '{}'::jsonb,
				$7::jsonb,
				'{"valid":true,"checked_at":"2026-08-27T12:05:01Z","issues":[]}'::jsonb,
				$5, $6, $6
			)
		`, revisionID, fixture.organizationID, fixture.applicationID, fixture.environmentID, adminUserID, now, compiledDocument); err != nil {
		t.Fatalf("create next active session test revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE active_config_revisions
		SET config_revision_id = $1, activated_by_admin_user_id = $2, activated_at = $3
		WHERE organization_id = $4 AND application_id = $5 AND environment_id = $6
	`, revisionID, adminUserID, now, fixture.organizationID, fixture.applicationID, fixture.environmentID); err != nil {
		t.Fatalf("activate next session test revision: %v", err)
	}
	return revisionID
}

func sessionTestCompiledSpec(identityProviders, attestationPolicies []any) map[string]any {
	if len(attestationPolicies) == 0 {
		// Canonical configuration requires at least one policy. A disabled policy
		// represents the refresh test's intentional removal of every required
		// policy while keeping the active snapshot structurally loadable.
		attestationPolicies = []any{map[string]any{
			"id": "disabled", "maxAge": "10m", "platforms": map[string]any{
				"ios": map[string]any{
					"provider": "debug", "mode": "disabled", "minimumTrustLevel": "debug",
				},
			},
		}}
	}
	policyID, _ := attestationPolicies[0].(map[string]any)["id"].(string)
	return map[string]any{
		"identityProviders":   identityProviders,
		"attestationPolicies": attestationPolicies,
		"upstreams": []any{map[string]any{
			"id": "primary", "type": "openai_compatible", "baseUrl": "https://api.example.test/v1",
			"authentication": map[string]any{"type": "none"},
			"timeouts": map[string]any{
				"connect": "5s", "firstByte": "30s", "idle": "1m", "total": "2m",
			},
			"destinationPolicy": map[string]any{
				"allowedPorts": []any{443}, "allowRedirects": false, "allowPrivateNetworks": false, "dnsPinning": true,
			},
		}},
		"models": []any{map[string]any{
			"id": "fast", "upstream": "primary", "upstreamModel": "configured-fast-model",
			"capabilities": []any{"openai_chat"},
		}},
		"limitPlans": []any{map[string]any{
			"id": "free", "limits": []any{map[string]any{
				"metric": "logical_requests", "algorithm": "calendar", "window": "1d", "maximum": 5, "hard": true,
				"scope": []any{"user", "feature"},
			}},
		}},
		"features": []any{map[string]any{
			"id": "assistant", "protocol": "openai_chat", "attestationPolicy": policyID,
			"access":    map[string]any{"expression": "principal.authenticated"},
			"limitPlan": map[string]any{"expression": "'free'"},
			"output":    map[string]any{"defaultMaximumTokens": 800, "absoluteMaximumTokens": 1500},
			"routes": []any{map[string]any{
				"id": "primary", "when": "true", "model": "fast", "priority": 10,
				"weight": 1, "stickyBy": "none", "fallbackOn": []any{},
			}},
		}},
	}
}

func assertSessionExchangePersistence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, issued IssuedSession) {
	t.Helper()
	for table, want := range map[string]int{"installations": 1, "attestation_events": 1, "session_grants": 1, "refresh_tokens": 1, "session_challenge_consumptions": 1} {
		assertTableCount(t, ctx, pool, table, want)
	}
	var tokenHash []byte
	if err := pool.QueryRow(ctx, `
		SELECT token_hash FROM refresh_tokens WHERE refresh_token_id = $1
	`, issued.RefreshID).Scan(&tokenHash); err != nil {
		t.Fatalf("read refresh token hash: %v", err)
	}
	expectedHash := sha256.Sum256([]byte(issued.Refresh.Reveal()))
	if len(tokenHash) != sha256.Size || string(tokenHash) != string(expectedHash[:]) || strings.Contains(string(tokenHash), issued.Refresh.Reveal()) {
		t.Fatal("refresh credential was not persisted exclusively as a digest")
	}
}

func assertTableCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, want int) {
	t.Helper()
	allowed := map[string]bool{
		"installations": true, "attestation_events": true, "session_grants": true,
		"refresh_tokens": true, "session_challenge_consumptions": true,
	}
	if !allowed[table] {
		t.Fatalf("unsafe test table %q", table)
	}
	var got int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s count=%d want=%d", table, got, want)
	}
}

func createChallengeFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) challengeFixture {
	t.Helper()
	fixture := challengeFixture{
		organizationID: mustSessionID(t, id.Organization), applicationID: mustSessionID(t, id.Application),
		environmentID: mustSessionID(t, id.Environment), applicationUserID: mustSessionID(t, id.ApplicationUser),
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name)
		VALUES ($1, 'challenge-test', 'Challenge Test')
	`, fixture.organizationID); err != nil {
		t.Fatalf("create challenge organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name)
		VALUES ($2, $1, 'challenge-app', 'Challenge App')
	`, fixture.organizationID, fixture.applicationID); err != nil {
		t.Fatalf("create challenge application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind)
		VALUES ($3, $1, $2, 'development', 'Development', 'development')
	`, fixture.organizationID, fixture.applicationID, fixture.environmentID); err != nil {
		t.Fatalf("create challenge environment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (application_user_id, organization_id, application_id)
		VALUES ($3, $1, $2)
	`, fixture.organizationID, fixture.applicationID, fixture.applicationUserID); err != nil {
		t.Fatalf("create challenge application user: %v", err)
	}
	return fixture
}

func newChallengeKey(t *testing.T) (*ecdsa.PrivateKey, dpop.PublicJWK, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	jwk := dpop.PublicJWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(privateKey.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(privateKey.Y.FillBytes(make([]byte, 32))),
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("compute DPoP thumbprint: %v", err)
	}
	return privateKey, jwk, jkt
}

func sessionProofJTI(label string, now time.Time) string {
	digest := sha256.Sum256([]byte(label + "\x00" + now.UTC().Format(time.RFC3339Nano)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func withChallengeProof(input ChallengeInput, target *url.URL, now time.Time, label string) ChallengeInput {
	input.DPoPProofJTI = sessionProofJTI(label, now)
	input.DPoPHTTPMethod = "POST"
	input.DPoPRequestURI = target
	return input
}

func signedSessionDPoP(t *testing.T, privateKey *ecdsa.PrivateKey, method string, target *url.URL, now time.Time, label string) DPoPProof {
	t.Helper()
	if privateKey == nil {
		t.Fatal("DPoP private key is nil")
	}
	htu, err := dpop.NormalizeHTU(target)
	if err != nil {
		t.Fatalf("normalize DPoP target: %v", err)
	}
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(privateKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(privateKey.Y.FillBytes(make([]byte, 32))),
	}
	header, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk})
	if err != nil {
		t.Fatalf("encode DPoP header: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"jti": sessionProofJTI(label, now),
		"htm": method, "htu": htu, "iat": now.UTC().Unix(),
	})
	if err != nil {
		t.Fatalf("encode DPoP claims: %v", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimsSegment := base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimsSegment))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	proof, err := NewDPoPProof(headerSegment + "." + claimsSegment + "." + base64.RawURLEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatalf("construct DPoP proof: %v", err)
	}
	return proof
}

func assertExchangeProofRecorded(t *testing.T, ctx context.Context, pool *pgxpool.Pool, issued IssuedSession, label string, now time.Time, method string, target *url.URL) {
	t.Helper()
	proofJTIHash := sha256.Sum256([]byte(sessionProofJTI(label, now)))
	normalizedURI, err := dpop.NormalizeHTU(target)
	if err != nil {
		t.Fatalf("normalize recorded exchange URI: %v", err)
	}
	expectedURIHash := sha256.Sum256([]byte(normalizedURI))
	var storedGrantID, storedMethod string
	var storedURIHash []byte
	if err := pool.QueryRow(ctx, `
		SELECT session_grant_id, http_method, http_uri_hash
		FROM dpop_replay_entries
		WHERE installation_id = $1 AND proof_jti_hash = $2
	`, issued.Installation.ID, proofJTIHash[:]).Scan(&storedGrantID, &storedMethod, &storedURIHash); err != nil {
		t.Fatalf("read recorded exchange proof: %v", err)
	}
	if storedGrantID != issued.GrantID || storedMethod != method || !bytes.Equal(storedURIHash, expectedURIHash[:]) {
		t.Fatalf("recorded exchange proof binding mismatch: grant=%q method=%q uri_hash=%x", storedGrantID, storedMethod, storedURIHash)
	}
}

func verifiedDebugAttestation(t *testing.T, binding attestation.Binding, now time.Time, label string) attestation.Result {
	t.Helper()
	seed := sha256.Sum256([]byte("latchway/session/debug-attestation/" + label))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	keyID := "fixture-" + base64.RawURLEncoding.EncodeToString(seed[:8])
	verifier, err := attestation.NewDebugVerifier(attestation.DebugConfig{
		Enabled: true, EnvironmentKind: "development",
		PublicKeys: map[string]ed25519.PublicKey{keyID: privateKey.Public().(ed25519.PublicKey)},
		Now:        func() time.Time { return now }, MaximumEvidenceLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("construct deterministic debug verifier: %v", err)
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		t.Fatalf("hash debug attestation binding: %v", err)
	}
	expiresAt := now.UTC().Add(10 * time.Minute).Truncate(time.Second)
	signature := ed25519.Sign(privateKey, attestation.DebugSigningMessage(bindingHash, expiresAt.Unix()))
	evidence, err := attestation.NewEvidence("debug", map[string]any{
		"key_id":       keyID,
		"binding_hash": base64.RawURLEncoding.EncodeToString(bindingHash[:]),
		"expires_at":   expiresAt.Unix(),
		"signature":    base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("construct deterministic debug evidence: %v", err)
	}
	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("verify deterministic debug evidence: %v", err)
	}
	return result
}

func mustSessionURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse session URL: %v", err)
	}
	return parsed
}

func mustDecodeChallengeNonce(t *testing.T, nonce string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil {
		t.Fatalf("decode challenge nonce: %v", err)
	}
	return decoded
}

func assertSingleChallengeConsumption(t *testing.T, ctx context.Context, pool *pgxpool.Pool, challenge Challenge, now time.Time) {
	t.Helper()
	const workers = 12
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
			if err != nil {
				results <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := consumeChallenge(ctx, tx, challenge, now); err != nil {
				results <- err
				return
			}
			results <- tx.Commit(ctx)
		}()
	}
	wait.Wait()
	close(results)
	var accepted, consumed int
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrChallengeConsumed):
			consumed++
		default:
			t.Fatalf("unexpected challenge consumption result: %v", err)
		}
	}
	if accepted != 1 || consumed != workers-1 {
		t.Fatalf("challenge consumption accepted=%d consumed=%d", accepted, consumed)
	}
}
