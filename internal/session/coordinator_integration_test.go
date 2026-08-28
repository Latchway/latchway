package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
)

const (
	clientHTTPOrigin           = "https://gateway.example.test"
	clientHTTPAudience         = "latchway-data-plane"
	clientHTTPIdentityIssuer   = "https://identity.example.test"
	clientHTTPIdentityAudience = "latchway-client"
)

func TestClientHTTPVerticalSlicePostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	fixture := createChallengeFixture(t, ctx, pool)

	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x76}, 32))
	envelope, err := secrets.NewEnvironmentMasterKey(masterKey)
	if err != nil {
		t.Fatalf("construct test envelope provider: %v", err)
	}
	adminUserID := insertClientHTTPAdministrator(t, ctx, pool, fixture.organizationID, now)

	identityPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate identity signing key: %v", err)
	}
	identityPublicDER, err := x509.MarshalPKIXPublicKey(&identityPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode identity public key: %v", err)
	}
	identityPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: identityPublicDER})

	debugSeed := sha256.Sum256([]byte("latchway/client-http/debug-key/v1"))
	debugPrivateKey := ed25519.NewKeyFromSeed(debugSeed[:])
	debugKeyID := "client-http-debug-key-01"
	debugPublicKeyDocument, err := json.Marshal(map[string]any{
		"version": 1,
		"keys": []any{map[string]any{
			"key_id":     debugKeyID,
			"public_key": base64.RawURLEncoding.EncodeToString(debugPrivateKey.Public().(ed25519.PublicKey)),
		}},
	})
	if err != nil {
		t.Fatalf("encode debug public-key document: %v", err)
	}

	insertClientHTTPEncryptedSecret(t, ctx, pool, envelope, fixture, adminUserID,
		"identity-public-key", identityPublicPEM, now.Add(-time.Minute))
	insertClientHTTPEncryptedSecret(t, ctx, pool, envelope, fixture, adminUserID,
		"debug-attestation-public-keys", debugPublicKeyDocument, now.Add(-time.Minute))
	revisionID := activateClientHTTPConfiguration(t, ctx, pool, fixture, adminUserID, now)

	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
	if err != nil {
		t.Fatalf("construct encrypted secret store: %v", err)
	}
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct configuration store: %v", err)
	}
	var subjectProtector *identity.SubjectProtector
	if err := envelope.UseIdentitySubjectHMACKey(func(key []byte) error {
		var protectorErr error
		subjectProtector, protectorErr = identity.NewSubjectProtector(key)
		return protectorErr
	}); err != nil {
		t.Fatalf("construct identity subject protector: %v", err)
	}
	userStore, err := identity.NewUserStore(pool, subjectProtector)
	if err != nil {
		t.Fatalf("construct identity user store: %v", err)
	}
	keyManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct signing-key manager: %v", err)
	}
	if _, err := keyManager.Active(ctx); err != nil {
		t.Fatalf("initialize signing key: %v", err)
	}
	accessIssuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: clientHTTPOrigin, Audience: clientHTTPAudience,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	accessVerifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: clientHTTPOrigin, Audience: clientHTTPAudience,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token verifier: %v", err)
	}
	sessionStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: accessIssuer, Configuration: configurationStore,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct session store: %v", err)
	}
	coordinator, err := NewClientCoordinator(ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore,
		Sessions: sessionStore, AccessTokens: accessVerifier,
		Secrets: secretStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct client coordinator: %v", err)
	}
	publicKeys, err := NewClientJWKSProvider(keyManager)
	if err != nil {
		t.Fatalf("construct client JWKS provider: %v", err)
	}
	api, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, FeatureQuotas: clientHTTPUnusedFeatureQuotas{},
		JWKS: publicKeys, PublicOrigin: clientHTTPOrigin,
	})
	if err != nil {
		t.Fatalf("construct client HTTP API: %v", err)
	}
	clientHandler := api.Handler()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestContext, contextErr := requestidentity.NewContext(request.Context())
		if contextErr != nil {
			t.Errorf("generate logical request identity: %v", contextErr)
			http.Error(writer, "request identity unavailable", http.StatusInternalServerError)
			return
		}
		clientHandler.ServeHTTP(writer, request.WithContext(requestContext))
	})

	identityClaims := jwt.MapClaims{
		"iss": clientHTTPIdentityIssuer, "aud": clientHTTPIdentityAudience,
		"sub": "external-user-001", "iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	identityToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, identityClaims).SignedString(identityPrivateKey)
	if err != nil {
		t.Fatalf("sign identity credential: %v", err)
	}
	dpopPrivateKey, _, dpopJKT := newChallengeKey(t)

	challengeTarget := clientHTTPURL(t, "/client/v1/session-challenges")
	challengeProof := signedSessionDPoP(t, dpopPrivateKey, http.MethodPost, challengeTarget, now, "client-http-challenge")
	t.Run("attestation secret preflight precedes user persistence", func(t *testing.T) {
		var initialUserCount int
		if err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM application_users
			WHERE organization_id = $1 AND application_id = $2
		`, fixture.organizationID, fixture.applicationID).Scan(&initialUserCount); err != nil {
			t.Fatalf("count initial application users: %v", err)
		}
		var secretRecordID string
		var originalCiphertext []byte
		if err := pool.QueryRow(ctx, `
			SELECT secret_record_id, ciphertext
			FROM secret_records
			WHERE organization_id = $1
			  AND application_id = $2
			  AND environment_id = $3
			  AND name = 'debug-attestation-public-keys'
			  AND rotated_at IS NULL
			  AND destroyed_at IS NULL
		`, fixture.organizationID, fixture.applicationID, fixture.environmentID).Scan(&secretRecordID, &originalCiphertext); err != nil {
			t.Fatalf("load debug attestation ciphertext: %v", err)
		}
		corruptedCiphertext := append([]byte(nil), originalCiphertext...)
		corruptedCiphertext[len(corruptedCiphertext)-1] ^= 0xff
		if _, err := pool.Exec(ctx, `UPDATE secret_records SET ciphertext = $2 WHERE secret_record_id = $1`, secretRecordID, corruptedCiphertext); err != nil {
			t.Fatalf("corrupt debug attestation ciphertext: %v", err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(ctx, `UPDATE secret_records SET ciphertext = $2 WHERE secret_record_id = $1`, secretRecordID, originalCiphertext); err != nil {
				t.Errorf("restore debug attestation ciphertext: %v", err)
			}
		})

		_, err := coordinator.CreateChallenge(ctx, clientapi.ChallengeInput{
			Metadata: clientapi.RequestMetadata{
				HTTPMethod: http.MethodPost, TargetURL: *challengeTarget,
				DPoPProof: clientapi.NewSensitiveString(challengeProof.value),
			},
			ApplicationID: fixture.applicationID, Environment: "development",
			IdentityProvider: "custom", IdentityToken: clientapi.NewSensitiveString(identityToken),
			Platform: "ios",
		})
		var failure *clientapi.DependencyError
		if !errors.As(err, &failure) || failure.Code != "server_not_ready" {
			t.Fatalf("challenge with unusable attestation secret error = %v", err)
		}
		var userCount int
		if err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM application_users
			WHERE organization_id = $1 AND application_id = $2
		`, fixture.organizationID, fixture.applicationID).Scan(&userCount); err != nil {
			t.Fatalf("count application users: %v", err)
		}
		if userCount != initialUserCount {
			t.Fatalf("unusable attestation secret changed application-user count from %d to %d", initialUserCount, userCount)
		}
	})
	var challenge clientHTTPChallengeDocument
	clientHTTPPostJSON(t, handler, "/client/v1/session-challenges", challengeProof, map[string]any{
		"application_id": fixture.applicationID, "environment": "development",
		"identity_provider": "custom", "identity_token": identityToken,
		"platform": "ios", "sdk_version": "1.2.3",
	}, http.StatusCreated, &challenge)
	if id.Validate(challenge.ChallengeID, id.SessionChallenge) != nil || challenge.BindingVersion != 1 ||
		challenge.IssuedAt != now.Unix() || !challenge.ExpiresAt.Equal(now.Add(5*time.Minute)) ||
		challenge.Attestation.Provider != "debug" || challenge.Attestation.Mode != "required" {
		t.Fatal("challenge response did not preserve the active identity and attestation policy")
	}
	bindingHashBytes, err := base64.RawURLEncoding.Strict().DecodeString(challenge.Attestation.ClientDataHash)
	if err != nil || len(bindingHashBytes) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(bindingHashBytes) != challenge.Attestation.ClientDataHash {
		t.Fatal("challenge response contained an invalid client-data hash")
	}
	var bindingHash [sha256.Size]byte
	copy(bindingHash[:], bindingHashBytes)
	attestationExpiresAt := now.Add(10 * time.Minute).Unix()
	debugSignature := ed25519.Sign(debugPrivateKey, attestation.DebugSigningMessage(bindingHash, attestationExpiresAt))

	exchangeTarget := clientHTTPURL(t, "/client/v1/sessions")
	exchangeProof := signedSessionDPoP(t, dpopPrivateKey, http.MethodPost, exchangeTarget, now, "client-http-exchange")
	var exchanged clientHTTPGrantDocument
	clientHTTPPostJSON(t, handler, "/client/v1/sessions", exchangeProof, map[string]any{
		"challenge_id": challenge.ChallengeID,
		"attestation": map[string]any{
			"provider": "debug",
			"evidence": map[string]any{
				"key_id": debugKeyID, "binding_hash": challenge.Attestation.ClientDataHash,
				"expires_at": attestationExpiresAt,
				"signature":  base64.RawURLEncoding.EncodeToString(debugSignature),
			},
		},
		"installation": map[string]any{"app_version": "1.0.0"},
	}, http.StatusCreated, &exchanged)
	assertClientHTTPGrant(t, exchanged, dpopJKT)
	assertClientHTTPAccessToken(t, ctx, keyManager, exchanged.AccessToken, fixture, revisionID, dpopJKT, now)

	refreshTarget := clientHTTPURL(t, "/client/v1/sessions/refresh")
	refreshProof := signedSessionDPoP(t, dpopPrivateKey, http.MethodPost, refreshTarget, now, "client-http-refresh")
	var refreshed clientHTTPGrantDocument
	clientHTTPPostJSON(t, handler, "/client/v1/sessions/refresh", refreshProof, map[string]any{
		"refresh_token": exchanged.RefreshToken,
	}, http.StatusOK, &refreshed)
	assertClientHTTPGrant(t, refreshed, dpopJKT)
	if refreshed.Installation.ID != exchanged.Installation.ID ||
		refreshed.AccessToken == exchanged.AccessToken || refreshed.RefreshToken == exchanged.RefreshToken {
		t.Fatal("refresh response did not rotate credentials for the same installation")
	}
	assertClientHTTPAccessToken(t, ctx, keyManager, refreshed.AccessToken, fixture, revisionID, dpopJKT, now)

	revokeTarget := clientHTTPURL(t, "/client/v1/installations/current")
	unknownKeyToken := clientHTTPAccessTokenWithKeyID(t, refreshed.AccessToken, dpopPrivateKey,
		"gsk_unknown-attacker-selected-key")
	unknownKeyProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodDelete, revokeTarget,
		now, unknownKeyToken, "client-http-revoke-unknown-access-kid")
	unknownKeyResponse := clientHTTPDeleteInstallation(t, handler, unknownKeyToken, unknownKeyProof)
	assertClientHTTPProblem(t, unknownKeyResponse, http.StatusUnauthorized, "session_expired")
	assertClientHTTPInstallationLive(t, ctx, pool, refreshed.Installation.ID, 2, 1)

	wrongRevokeKey, _, _ := newChallengeKey(t)
	wrongKeyProof := signedSessionAccessDPoP(t, wrongRevokeKey, http.MethodDelete, revokeTarget,
		now, refreshed.AccessToken, "client-http-revoke-wrong-key")
	wrongKeyResponse := clientHTTPDeleteInstallation(t, handler, refreshed.AccessToken, wrongKeyProof)
	assertClientHTTPProblem(t, wrongKeyResponse, http.StatusUnauthorized, "dpop_invalid")
	assertClientHTTPInstallationLive(t, ctx, pool, refreshed.Installation.ID, 2, 1)

	wrongAccessHashProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodDelete, revokeTarget,
		now, exchanged.AccessToken, "client-http-revoke-wrong-ath")
	wrongAccessHashResponse := clientHTTPDeleteInstallation(t, handler, refreshed.AccessToken, wrongAccessHashProof)
	assertClientHTTPProblem(t, wrongAccessHashResponse, http.StatusUnauthorized, "dpop_invalid")
	assertClientHTTPInstallationLive(t, ctx, pool, refreshed.Installation.ID, 2, 1)

	revokeProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodDelete, revokeTarget,
		now, refreshed.AccessToken, "client-http-revoke")
	revokeResponse := clientHTTPDeleteInstallation(t, handler, refreshed.AccessToken, revokeProof)
	assertClientHTTPNoContent(t, revokeResponse)

	replayResponse := clientHTTPDeleteInstallation(t, handler, refreshed.AccessToken, revokeProof)
	assertClientHTTPProblem(t, replayResponse, http.StatusUnauthorized, "dpop_replayed")

	idempotentProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodDelete, revokeTarget,
		now, refreshed.AccessToken, "client-http-revoke-idempotent")
	idempotentResponse := clientHTTPDeleteInstallation(t, handler, refreshed.AccessToken, idempotentProof)
	assertClientHTTPNoContent(t, idempotentResponse)

	postRevocationRefreshProof := signedSessionDPoP(t, dpopPrivateKey, http.MethodPost, refreshTarget,
		now, "client-http-refresh-after-revoke")
	postRevocationRefreshResponse := clientHTTPPostJSONResponse(t, handler, "/client/v1/sessions/refresh",
		postRevocationRefreshProof, map[string]any{"refresh_token": refreshed.RefreshToken})
	assertClientHTTPProblem(t, postRevocationRefreshResponse, http.StatusUnauthorized, "session_revoked")

	request := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	request.Host = "untrusted-inbound.example.test"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("public JWKS status = %d", response.Code)
	}
	if response.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("public JWKS Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	var jwks clientapi.JWKS
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode public JWKS response: %v", err)
	}
	wantKeyID := clientHTTPAccessTokenKeyID(t, refreshed.AccessToken)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != wantKeyID || jwks.Keys[0].Kty != "EC" ||
		jwks.Keys[0].Crv != "P-256" || jwks.Keys[0].Use != "sig" || jwks.Keys[0].Alg != "ES256" {
		t.Fatal("public JWKS did not contain the access-token verification key")
	}

	var activeRefresh, rotatedRefresh, revokedRefresh, grantCount, revokedGrants int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'active'),
		       count(*) FILTER (WHERE status = 'rotated'),
		       count(*) FILTER (WHERE status = 'revoked')
		FROM refresh_tokens
	`).Scan(&activeRefresh, &rotatedRefresh, &revokedRefresh); err != nil {
		t.Fatalf("inspect refresh rotation state: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM session_grants
	`).Scan(&grantCount, &revokedGrants); err != nil {
		t.Fatalf("inspect session grants: %v", err)
	}
	if activeRefresh != 0 || rotatedRefresh != 1 || revokedRefresh != 1 || grantCount != 2 || revokedGrants != 2 {
		t.Fatalf("persisted revoked session state = active:%d rotated:%d revoked:%d grants:%d revoked_grants:%d",
			activeRefresh, rotatedRefresh, revokedRefresh, grantCount, revokedGrants)
	}
}

func TestClientCoordinatorAppAttestChallengePostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	fixture := createChallengeFixture(t, ctx, pool)
	masterKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x67}, 32))
	envelope, err := secrets.NewEnvironmentMasterKey(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	adminUserID := insertClientHTTPAdministrator(t, ctx, pool, fixture.organizationID, now)
	identityPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	identityPublicDER, err := x509.MarshalPKIXPublicKey(&identityPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	insertClientHTTPEncryptedSecret(
		t, ctx, pool, envelope, fixture, adminUserID, "identity-public-key",
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: identityPublicDER}), now.Add(-time.Minute),
	)
	activateClientHTTPConfigurationWithAttestation(
		t, ctx, pool, fixture, adminUserID, now,
		map[string]any{
			"provider": "app_attest", "mode": "required", "minimumTrustLevel": "app_verified",
			"appAttest": map[string]any{
				"appIdPrefix": "TEAM1234", "bundleId": "com.example.challenge",
				"environment": "development", "allowedValidationCategories": []any{1},
				"allowedBundleVersions": []any{"1.0"},
			},
		},
		map[string]struct{}{"identity-public-key": {}},
	)
	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
	if err != nil {
		t.Fatal(err)
	}
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	var protector *identity.SubjectProtector
	if err := envelope.UseIdentitySubjectHMACKey(func(key []byte) error {
		protector, err = identity.NewSubjectProtector(key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	userStore, err := identity.NewUserStore(pool, protector)
	if err != nil {
		t.Fatal(err)
	}
	sessionStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: unusedAccessIssuer{}, Configuration: configurationStore, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{
		"iss": clientHTTPIdentityIssuer, "aud": clientHTTPIdentityAudience,
		"sub": "external-app-attest-user", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	identityToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(identityPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, _, _ := newChallengeKey(t)
	target := clientHTTPURL(t, "/client/v1/session-challenges")
	challengeInput := func(label string) clientapi.ChallengeInput {
		proof := signedSessionDPoP(t, dpopKey, http.MethodPost, target, now, label)
		return clientapi.ChallengeInput{
			Metadata: clientapi.RequestMetadata{
				HTTPMethod: http.MethodPost, TargetURL: *target,
				DPoPProof: clientapi.NewSensitiveString(proof.value),
			},
			ApplicationID: fixture.applicationID, Environment: "development",
			IdentityProvider: "custom", IdentityToken: clientapi.NewSensitiveString(identityToken), Platform: "ios",
		}
	}
	var typedNilKeys *attestation.PostgreSQLAppAttestKeyStore
	broken, err := NewClientCoordinator(ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore, Sessions: sessionStore,
		AccessTokens: &AccessTokenVerifier{}, Secrets: secretStore, AppAttestKeys: typedNilKeys, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = broken.CreateChallenge(ctx, challengeInput("app-attest-preflight-failure"))
	var failure *clientapi.DependencyError
	if !errors.As(err, &failure) || failure.Code != "server_not_ready" {
		t.Fatalf("typed nil App Attest preflight error = %v", err)
	}
	var users int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM application_users`).Scan(&users); err != nil || users != 1 {
		// createChallengeFixture owns the one pre-existing user; identity.Resolve
		// must not add the external subject before verifier preflight succeeds.
		t.Fatalf("preflight failure application-user count=%d err=%v", users, err)
	}
	appAttestKeys, err := attestation.NewPostgreSQLAppAttestKeyStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewClientCoordinator(ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore, Sessions: sessionStore,
		AccessTokens: &AccessTokenVerifier{}, Secrets: secretStore, AppAttestKeys: appAttestKeys, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := coordinator.CreateChallenge(ctx, challengeInput("app-attest-preflight-success"))
	if err != nil {
		t.Fatalf("create non-debug App Attest challenge: %v", err)
	}
	if challenge.Attestation.Provider != "app_attest" || challenge.Attestation.Mode != "required" ||
		challenge.Attestation.ProviderOptions != nil {
		t.Fatalf("App Attest challenge = %#v", challenge.Attestation)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM application_users`).Scan(&users); err != nil || users != 2 {
		t.Fatalf("successful App Attest challenge user count=%d err=%v", users, err)
	}
	_, err = coordinator.ExchangeSession(ctx, clientapi.ExchangeInput{
		ChallengeID: challenge.ChallengeID,
		Attestation: clientapi.AttestationEvidence{Provider: "play_integrity"},
	})
	if !errors.As(err, &failure) || failure.Code != "attestation_invalid" {
		t.Fatalf("provider-mismatched exchange error = %v", err)
	}
}

// This integration test owns only the session lifecycle. The feature-quota
// dependency is required by the complete client transport but must remain
// unreachable in this fixture.
type clientHTTPUnusedFeatureQuotas struct{}

func (clientHTTPUnusedFeatureQuotas) FeatureQuota(
	context.Context,
	clientapi.FeatureQuotaInput,
) (clientapi.FeatureQuotaResult, error) {
	return clientapi.FeatureQuotaResult{}, &clientapi.DependencyError{Code: "server_not_ready"}
}

type clientHTTPChallengeDocument struct {
	ChallengeID    string    `json:"challenge_id"`
	ChallengeNonce string    `json:"challenge_nonce"`
	BindingVersion int       `json:"binding_version"`
	IssuedAt       int64     `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Attestation    struct {
		Provider       string `json:"provider"`
		Mode           string `json:"mode"`
		ClientDataHash string `json:"client_data_hash"`
	} `json:"attestation"`
}

type clientHTTPGrantDocument struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Installation     struct {
		ID       string `json:"id"`
		Platform string `json:"platform"`
		DPoPJKT  string `json:"dpop_jkt"`
		Status   string `json:"status"`
	} `json:"installation"`
	Trust struct {
		Provider   string    `json:"provider"`
		Level      string    `json:"level"`
		VerifiedAt time.Time `json:"verified_at"`
		ExpiresAt  time.Time `json:"expires_at"`
	} `json:"trust"`
}

func insertClientHTTPAdministrator(t *testing.T, ctx context.Context, pool *pgxpool.Pool, organizationID string, now time.Time) string {
	t.Helper()
	adminUserID := mustSessionID(t, id.AdminUser)
	membershipID := mustSessionID(t, id.AdminMembership)
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name, created_at, updated_at
		) VALUES ($1, 'client-http@example.test', 'client-http@example.test', 'Client HTTP Test', $2, $2)
	`, adminUserID, now.Add(-time.Minute)); err != nil {
		t.Fatalf("insert client HTTP administrator: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, created_at, updated_at
		) VALUES ($1, $2, $3, 'owner', $4, $4)
	`, membershipID, organizationID, adminUserID, now.Add(-time.Minute)); err != nil {
		t.Fatalf("insert client HTTP administrator membership: %v", err)
	}
	return adminUserID
}

func insertClientHTTPEncryptedSecret(t *testing.T, ctx context.Context, pool *pgxpool.Pool, provider secrets.Provider, fixture challengeFixture, adminUserID, name string, plaintext []byte, createdAt time.Time) {
	t.Helper()
	recordID := mustSessionID(t, id.SecretRecord)
	encrypted, err := provider.Encrypt(plaintext, secrets.AssociatedData{
		OrganizationID: fixture.organizationID, EnvironmentID: fixture.environmentID,
		SecretID: recordID, SecretVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		t.Fatalf("encrypt client HTTP secret fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO secret_records (
			secret_record_id, organization_id, application_id, environment_id,
			name, version, encryption_format_version, algorithm,
			master_key_identifier, ciphertext, nonce, created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, 1, $6, 'aes-256-gcm', $7, $8, $9, $10, $11)
	`, recordID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
		name, int16(encrypted.FormatVersion), encrypted.KeyID, encrypted.Ciphertext,
		encrypted.Nonce, adminUserID, createdAt); err != nil {
		t.Fatalf("insert encrypted client HTTP secret fixture: %v", err)
	}
}

func activateClientHTTPConfiguration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fixture challengeFixture, adminUserID string, now time.Time) string {
	return activateClientHTTPConfigurationWithAttestation(t, ctx, pool, fixture, adminUserID, now, map[string]any{
		"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
		"secretRef": "secret/debug-attestation-public-keys",
	}, map[string]struct{}{
		"identity-public-key": {}, "debug-attestation-public-keys": {},
	})
}

func activateClientHTTPConfigurationWithAttestation(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture challengeFixture,
	adminUserID string,
	now time.Time,
	selection map[string]any,
	secretNames map[string]struct{},
) string {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"apiVersion": "latchway.dev/v1alpha1",
		"kind":       "EnvironmentConfig",
		"metadata": map[string]any{
			"organization": "challenge-test", "application": "challenge-app", "environment": "development",
		},
		"spec": map[string]any{
			"identityProviders": []any{map[string]any{
				"id": "custom", "type": "custom_jwt", "issuer": clientHTTPIdentityIssuer,
				"audiences": []any{clientHTTPIdentityAudience}, "allowedAlgorithms": []any{"RS256"},
				"staticPublicKeySecretRef": "secret/identity-public-key",
				"subjectClaim":             "sub", "clockSkewSeconds": 0,
			}},
			"attestationPolicies": []any{map[string]any{
				"id": "native", "maxAge": "10m",
				"platforms": map[string]any{"ios": selection},
			}},
			"upstreams": []any{map[string]any{
				"id": "primary", "type": "openai_compatible", "baseUrl": "https://api.example.test/v1",
				"authentication": map[string]any{"type": "none"},
			}},
			"models": []any{map[string]any{
				"id": "fast", "upstream": "primary", "upstreamModel": "configured-fast-model",
			}},
			"limitPlans": []any{map[string]any{
				"id": "free", "limits": []any{map[string]any{
					"metric": "logical_requests", "window": "1d", "maximum": 5,
					"scope": []any{"user", "feature"},
				}},
			}},
			"features": []any{map[string]any{
				"id": "assistant", "protocol": "openai_chat", "attestationPolicy": "native",
				"access":    map[string]any{"expression": "principal.authenticated"},
				"limitPlan": map[string]any{"expression": "'free'"},
				"output": map[string]any{
					"defaultMaximumTokens": 800, "absoluteMaximumTokens": 1500,
				},
				"routes": []any{map[string]any{
					"id": "primary", "when": "true", "model": "fast", "priority": 10,
				}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("encode client HTTP configuration: %v", err)
	}
	validator, err := configuration.NewValidator()
	if err != nil {
		t.Fatalf("construct configuration validator: %v", err)
	}
	report, compiled := validator.Validate(document, configuration.EnvironmentDescriptor{
		TenantScope: configuration.TenantScope{
			OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
			EnvironmentID: fixture.environmentID,
		},
		OrganizationSlug: "challenge-test", ApplicationSlug: "challenge-app",
		EnvironmentSlug: "development", EnvironmentKind: "development",
		SecretNames: secretNames,
	}, now)
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("client HTTP configuration did not compile: %+v", report.Issues)
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode client HTTP validation report: %v", err)
	}
	revisionID := mustSessionID(t, id.ConfigRevision)
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_errors, validation_report, created_by_admin_user_id,
			validated_at, activated_at
		) VALUES (
			$1, $2, $3, $4, 1, 'client-http-etag-0001', 'valid', $5::jsonb, $6::jsonb,
			'[]'::jsonb, $7::jsonb, $8, $9, $9
		)
	`, revisionID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
		document, compiled, reportJSON, adminUserID, now); err != nil {
		t.Fatalf("insert client HTTP configuration revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO active_config_revisions (
			organization_id, application_id, environment_id, config_revision_id,
			revision_status, activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, 'valid', $5, $6)
	`, fixture.organizationID, fixture.applicationID, fixture.environmentID,
		revisionID, adminUserID, now); err != nil {
		t.Fatalf("activate client HTTP configuration revision: %v", err)
	}
	return revisionID
}

func clientHTTPPostJSON(t *testing.T, handler http.Handler, path string, proof DPoPProof, body any, wantStatus int, output any) {
	t.Helper()
	response := clientHTTPPostJSONResponse(t, handler, path, proof, body)
	if response.Code != wantStatus {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &failure)
		t.Fatalf("client HTTP %s status = %d, problem code = %q", path, response.Code, failure.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("client HTTP %s Cache-Control = %q", path, response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("client HTTP %s omitted required success headers", path)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatalf("decode client HTTP %s response: %v", path, err)
	}
}

func clientHTTPPostJSONResponse(t *testing.T, handler http.Handler, path string, proof DPoPProof, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode client HTTP request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	setClientHTTPProtectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func clientHTTPDeleteInstallation(t *testing.T, handler http.Handler, accessToken string, proof DPoPProof) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodDelete, "/client/v1/installations/current", nil)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	setClientHTTPProtectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func setClientHTTPProtectedHeaders(request *http.Request, proof DPoPProof) {
	request.Host = "untrusted-inbound.example.test"
	request.Header.Set("Forwarded", "host=untrusted-forwarded.example.test;proto=http")
	request.Header.Set("X-Forwarded-Host", "untrusted-forwarded.example.test")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "ios")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("DPoP", proof.value)
}

func assertClientHTTPNoContent(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Content-Type") != "" || response.Header().Get("Content-Length") != "" ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("client HTTP DELETE response status=%d headers=%#v body=%q",
			response.Code, response.Header(), response.Body.String())
	}
}

func assertClientHTTPProblem(t *testing.T, response *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	var failure struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(response.Body).Decode(&failure); err != nil {
		t.Fatalf("decode client HTTP problem: %v", err)
	}
	if response.Code != wantStatus || failure.Code != wantCode || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "application/problem+json" || response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("client HTTP problem status=%d code=%q headers=%#v want=%d/%q",
			response.Code, failure.Code, response.Header(), wantStatus, wantCode)
	}
}

func assertClientHTTPInstallationLive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, installationID string, wantLiveGrants, wantActiveRefresh int) {
	t.Helper()
	var status string
	var liveGrants, activeRefresh int
	if err := pool.QueryRow(ctx, `
		SELECT status,
		       (SELECT count(*) FROM session_grants WHERE installation_id = $1 AND revoked_at IS NULL),
		       (SELECT count(*) FROM refresh_tokens WHERE installation_id = $1 AND status = 'active')
		FROM installations WHERE installation_id = $1
	`, installationID).Scan(&status, &liveGrants, &activeRefresh); err != nil {
		t.Fatalf("inspect live client HTTP installation: %v", err)
	}
	if status != "active" || liveGrants != wantLiveGrants || activeRefresh != wantActiveRefresh {
		t.Fatalf("client HTTP installation status=%q live_grants=%d active_refresh=%d wants=active/%d/%d",
			status, liveGrants, activeRefresh, wantLiveGrants, wantActiveRefresh)
	}
}

func clientHTTPURL(t *testing.T, path string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(clientHTTPOrigin + path)
	if err != nil {
		t.Fatalf("parse trusted client HTTP target: %v", err)
	}
	return parsed
}

func assertClientHTTPGrant(t *testing.T, grant clientHTTPGrantDocument, dpopJKT string) {
	t.Helper()
	if grant.TokenType != "DPoP" || grant.ExpiresIn != 600 || grant.RefreshExpiresIn != 30*24*60*60 ||
		len(grant.AccessToken) < 64 || len(grant.RefreshToken) < 32 ||
		id.Validate(grant.Installation.ID, id.Installation) != nil || grant.Installation.Platform != "ios" ||
		grant.Installation.DPoPJKT != dpopJKT || grant.Installation.Status != "active" ||
		grant.Trust.Provider != "debug" || grant.Trust.Level != "debug" ||
		grant.Trust.VerifiedAt.IsZero() || !grant.Trust.ExpiresAt.After(grant.Trust.VerifiedAt) {
		t.Fatal("client HTTP grant response violated the session contract")
	}
}

func assertClientHTTPAccessToken(t *testing.T, ctx context.Context, keyManager *SigningKeyManager, raw string, fixture challengeFixture, revisionID, dpopJKT string, now time.Time) {
	t.Helper()
	token, err := NewAccessToken(raw)
	if err != nil {
		t.Fatal("client HTTP response contained a malformed access token")
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: clientHTTPOrigin, Audience: clientHTTPAudience,
		Now: func() time.Time { return now }, ClockSkewSet: true,
	})
	if err != nil {
		t.Fatalf("construct client HTTP access-token verifier: %v", err)
	}
	principal, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("verify client HTTP access token: %v", err)
	}
	if principal.OrganizationID != fixture.organizationID || principal.ApplicationID != fixture.applicationID ||
		principal.EnvironmentID != fixture.environmentID || id.Validate(principal.ApplicationUserID, id.ApplicationUser) != nil ||
		id.Validate(principal.InstallationID, id.Installation) != nil || id.Validate(principal.SessionGrantID, id.SessionGrant) != nil ||
		principal.IdentityProvider != "custom" || principal.TrustLevel != "debug" ||
		principal.PolicyRevisionID != revisionID || principal.DPoPJKT != dpopJKT {
		t.Fatal("client HTTP access token did not preserve the verified session scope")
	}
}

func clientHTTPAccessTokenKeyID(t *testing.T, raw string) string {
	t.Helper()
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		t.Fatal("client HTTP access token was not compact JWT syntax")
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(segments[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(headerBytes) != segments[0] {
		t.Fatal("client HTTP access token had a noncanonical protected header")
	}
	var header struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || id.Validate(header.KeyID, id.GatewaySigningKey) != nil {
		t.Fatal("client HTTP access token omitted its signing-key identifier")
	}
	return header.KeyID
}

func clientHTTPAccessTokenWithKeyID(t *testing.T, raw string, signingKey *ecdsa.PrivateKey, keyID string) string {
	t.Helper()
	segments := strings.Split(raw, ".")
	if len(segments) != 3 || signingKey == nil {
		t.Fatal("cannot rewrite malformed client HTTP access token")
	}
	header, err := json.Marshal(map[string]any{"alg": "ES256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		t.Fatalf("encode rewritten access-token header: %v", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	digest := sha256.Sum256([]byte(headerSegment + "." + segments[1]))
	r, s, err := ecdsa.Sign(rand.Reader, signingKey, digest[:])
	if err != nil {
		t.Fatalf("sign rewritten access token: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + segments[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
}
