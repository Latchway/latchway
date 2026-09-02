package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/telemetry"
)

const (
	clientHTTPOrigin           = "https://gateway.example.test"
	clientHTTPAudience         = "latchway-data-plane"
	clientHTTPIdentityIssuer   = "https://identity.example.test"
	clientHTTPIdentityAudience = "latchway-client"
)

type componentRefreshRaceAccessIssuer struct {
	delegate    AccessIssuer
	armed       atomic.Bool
	blockOnce   sync.Once
	releaseOnce sync.Once
	entered     chan struct{}
	release     chan struct{}
}

func newComponentRefreshRaceAccessIssuer(delegate AccessIssuer) *componentRefreshRaceAccessIssuer {
	return &componentRefreshRaceAccessIssuer{
		delegate: delegate,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (issuer *componentRefreshRaceAccessIssuer) Prepare(ctx context.Context) (PreparedAccessIssuer, error) {
	prepared, err := issuer.delegate.Prepare(ctx)
	if err != nil {
		return nil, err
	}
	return &componentRefreshRacePreparedIssuer{delegate: prepared, owner: issuer}, nil
}

func (issuer *componentRefreshRaceAccessIssuer) arm() {
	issuer.armed.Store(true)
}

func (issuer *componentRefreshRaceAccessIssuer) unblock() {
	issuer.releaseOnce.Do(func() { close(issuer.release) })
}

type componentRefreshRacePreparedIssuer struct {
	delegate PreparedAccessIssuer
	owner    *componentRefreshRaceAccessIssuer
}

func (*componentRefreshRacePreparedIssuer) preparedAccessIssuer() {}

func (issuer *componentRefreshRacePreparedIssuer) IssueFor(input AccessIssueInput, lifetime time.Duration) (IssuedAccess, error) {
	if issuer.owner.armed.Load() {
		issuer.owner.blockOnce.Do(func() {
			close(issuer.owner.entered)
			<-issuer.owner.release
		})
	}
	return issuer.delegate.IssueFor(input, lifetime)
}

func TestClientHTTPVerticalSlicePostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	now := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
	fixture := createChallengeFixture(t, ctx, pool)
	metrics, err := telemetry.NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })

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
	raceAccessIssuer := newComponentRefreshRaceAccessIssuer(accessIssuer)
	t.Cleanup(raceAccessIssuer.unblock)
	sessionStore, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: raceAccessIssuer, Configuration: configurationStore,
		Now: func() time.Time { return now }, RotationProtector: envelope,
	})
	if err != nil {
		t.Fatalf("construct session store: %v", err)
	}
	appAttestKeys, err := attestation.NewPostgreSQLAppAttestKeyStore(pool)
	if err != nil {
		t.Fatalf("construct App Attest key store: %v", err)
	}
	coordinator, err := NewClientCoordinator(ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore,
		Sessions: sessionStore, AccessTokens: accessVerifier,
		Secrets: secretStore, AppAttestKeys: appAttestKeys,
		Telemetry: metrics, Now: func() time.Time { return now },
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
	invalidExchangeProof := signedSessionDPoP(t, dpopPrivateKey, http.MethodPost, exchangeTarget, now, "client-http-exchange-invalid-attestation")
	invalidExchange := clientHTTPPostJSONResponse(t, handler, "/client/v1/sessions", invalidExchangeProof, map[string]any{
		"challenge_id": challenge.ChallengeID,
		"attestation": map[string]any{
			"provider": "debug",
			"evidence": map[string]any{
				"key_id": debugKeyID, "binding_hash": challenge.Attestation.ClientDataHash,
				"expires_at": attestationExpiresAt,
				"signature":  base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
			},
		},
		"installation": map[string]any{"app_version": "1.0.0"},
	})
	assertClientHTTPProblem(t, invalidExchange, http.StatusUnauthorized, "attestation_invalid")

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

	childPrivateKey, childPublicJWK, childJKT := newChallengeKey(t)
	provisionComponentTarget := clientHTTPURL(t, "/client/v1/installation-families/current/components")
	provisionComponentProof := signedSessionAccessDPoP(
		t, dpopPrivateKey, http.MethodPost, provisionComponentTarget, now,
		refreshed.AccessToken, "client-http-provision-widget",
	)
	var provisionedComponent clientHTTPProvisionComponentDocument
	clientHTTPPostJSONAuthorized(
		t, handler, "/client/v1/installation-families/current/components",
		refreshed.AccessToken, provisionComponentProof,
		map[string]any{
			"component_definition_id": "ios-widget",
			"public_jwk":              childPublicJWK,
			"requested_features":      []any{"assistant"},
			"client_metadata": map[string]any{
				"app_version": "1.0.0", "sdk_version": "1.2.3",
			},
		},
		http.StatusCreated,
		&provisionedComponent,
	)
	if id.Validate(provisionedComponent.ComponentID, id.ClientComponent) != nil ||
		refreshed.InstallationFamily == nil ||
		provisionedComponent.InstallationFamilyID != refreshed.InstallationFamily.ID ||
		provisionedComponent.Trust.Source != "delegated_identity_only" ||
		!provisionedComponent.Trust.ExpiresAt.Equal(now.Add(10*time.Minute)) ||
		!provisionedComponent.RefreshGrantExpiresAt.Equal(provisionedComponent.Trust.ExpiresAt) ||
		len(provisionedComponent.RefreshGrant) < 32 ||
		len(provisionedComponent.GrantedFeatures) != 1 ||
		provisionedComponent.GrantedFeatures[0] != "assistant" {
		t.Fatalf("component provisioning response violated the delegated contract: component=%q family=%q source=%q trust_expiry=%s grant_expiry=%s features=%v",
			provisionedComponent.ComponentID, provisionedComponent.InstallationFamilyID,
			provisionedComponent.Trust.Source, provisionedComponent.Trust.ExpiresAt,
			provisionedComponent.RefreshGrantExpiresAt, provisionedComponent.GrantedFeatures)
	}

	componentSessionTarget := clientHTTPURL(t, "/client/v1/component-sessions")
	componentSessionProof := signedSessionDPoP(
		t, childPrivateKey, http.MethodPost, componentSessionTarget, now,
		"client-http-create-widget-session",
	)
	var componentSession clientHTTPComponentSessionDocument
	clientHTTPPostJSON(
		t, handler, "/client/v1/component-sessions", componentSessionProof,
		map[string]any{
			"component_id":  provisionedComponent.ComponentID,
			"refresh_grant": provisionedComponent.RefreshGrant,
		},
		http.StatusCreated,
		&componentSession,
	)
	if componentSession.ExpiresIn != 600 || len(componentSession.AccessToken) < 64 ||
		len(componentSession.RefreshToken) < 32 ||
		!componentSession.RefreshExpiresAt.Equal(provisionedComponent.RefreshGrantExpiresAt) {
		t.Fatalf("component session response violated the independent-session contract: expires_in=%d refresh_expiry=%s access_present=%t refresh_present=%t",
			componentSession.ExpiresIn, componentSession.RefreshExpiresAt,
			componentSession.AccessToken != "", componentSession.RefreshToken != "")
	}
	componentAccessToken, err := NewAccessToken(componentSession.AccessToken)
	if err != nil {
		t.Fatalf("parse component access token: %v", err)
	}
	componentPrincipal, err := accessVerifier.Verify(ctx, componentAccessToken)
	if err != nil {
		t.Fatalf("verify component access token: %v", err)
	}
	if componentPrincipal.InstallationFamilyID != provisionedComponent.InstallationFamilyID ||
		componentPrincipal.ComponentID != provisionedComponent.ComponentID ||
		componentPrincipal.ComponentDefinitionID != "ios-widget" ||
		componentPrincipal.ComponentKind != "widget" || componentPrincipal.ComponentIsRoot ||
		componentPrincipal.DPoPJKT != childJKT ||
		componentPrincipal.TrustSource != "delegated_identity_only" ||
		refreshed.Component == nil || componentPrincipal.ParentComponentID != refreshed.Component.ID ||
		componentPrincipal.ParentAttestationProvider != "debug" ||
		id.Validate(componentPrincipal.DelegationID, id.ComponentDelegation) != nil ||
		len(componentPrincipal.Features) != 1 || componentPrincipal.Features[0] != "assistant" {
		t.Fatalf("component access token omitted the delegated principal boundary: %#v", componentPrincipal)
	}

	componentRefreshToken, err := NewRefreshToken(componentSession.RefreshToken)
	if err != nil {
		t.Fatalf("parse component refresh token: %v", err)
	}
	raceProofs := []DPoPProof{
		signedSessionDPoP(t, childPrivateKey, http.MethodPost, refreshTarget, now,
			"client-http-refresh-widget-race-a"),
		signedSessionDPoP(t, childPrivateKey, http.MethodPost, refreshTarget, now,
			"client-http-refresh-widget-race-b"),
	}
	type componentRaceResult struct {
		issued IssuedSession
		err    error
	}
	raceAccessIssuer.arm()
	startRace := make(chan struct{})
	raceResults := make(chan componentRaceResult, len(raceProofs))
	for _, proof := range raceProofs {
		go func(proof DPoPProof) {
			<-startRace
			issued, rotateErr := sessionStore.Rotate(ctx, RotateInput{
				RefreshToken: componentRefreshToken,
				DPoPProof:    proof, HTTPMethod: http.MethodPost, RequestURI: refreshTarget,
			})
			raceResults <- componentRaceResult{issued: issued, err: rotateErr}
		}(proof)
	}
	close(startRace)
	select {
	case <-raceAccessIssuer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first component refresh did not reach the in-transaction issuance barrier")
	}
	waitForComponentRefreshLock(t, ctx, pool)
	raceAccessIssuer.unblock()
	firstRace := <-raceResults
	secondRace := <-raceResults
	if firstRace.err != nil || secondRace.err != nil {
		t.Fatalf("simultaneous component refresh errors = %v / %v", firstRace.err, secondRace.err)
	}
	if firstRace.issued.Access.Token.Reveal() != secondRace.issued.Access.Token.Reveal() ||
		firstRace.issued.Refresh.Reveal() != secondRace.issued.Refresh.Reveal() ||
		firstRace.issued.RefreshID != secondRace.issued.RefreshID ||
		firstRace.issued.GrantID != secondRace.issued.GrantID ||
		!firstRace.issued.RefreshExpiresAt.Equal(secondRace.issued.RefreshExpiresAt) {
		t.Fatal("simultaneous component refreshes did not recover the exact committed rotation")
	}

	componentRefreshRetryProof := signedSessionDPoP(
		t, childPrivateKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-widget-idempotent-retry",
	)
	var refreshedComponent clientHTTPGrantDocument
	clientHTTPPostJSON(
		t, handler, "/client/v1/sessions/refresh", componentRefreshRetryProof,
		map[string]any{"refresh_token": componentSession.RefreshToken},
		http.StatusOK,
		&refreshedComponent,
	)
	if refreshedComponent.TokenType != "DPoP" || refreshedComponent.ExpiresIn != 600 ||
		refreshedComponent.RefreshExpiresIn != 600 ||
		refreshedComponent.AccessToken == componentSession.AccessToken ||
		refreshedComponent.RefreshToken == componentSession.RefreshToken ||
		refreshedComponent.Installation.DPoPJKT != childJKT ||
		refreshedComponent.InstallationFamily == nil ||
		refreshedComponent.InstallationFamily.ID != provisionedComponent.InstallationFamilyID ||
		refreshedComponent.Component == nil ||
		refreshedComponent.Component.ID != provisionedComponent.ComponentID ||
		refreshedComponent.Component.IsRoot ||
		refreshedComponent.Trust.Source != "delegated_identity_only" ||
		refreshedComponent.Trust.ParentComponentID != refreshed.Component.ID {
		t.Fatalf("component refresh response violated the independent rotation contract: expires_in=%d refresh_expires_in=%d family=%v component=%v source=%q parent=%q",
			refreshedComponent.ExpiresIn, refreshedComponent.RefreshExpiresIn,
			refreshedComponent.InstallationFamily, refreshedComponent.Component,
			refreshedComponent.Trust.Source, refreshedComponent.Trust.ParentComponentID)
	}
	if refreshedComponent.AccessToken != firstRace.issued.Access.Token.Reveal() ||
		refreshedComponent.RefreshToken != firstRace.issued.Refresh.Reveal() ||
		!refreshedComponent.Trust.ExpiresAt.Equal(firstRace.issued.Trust.ExpiresAt) {
		t.Fatal("HTTP component refresh retry did not recover the exact concurrent rotation")
	}
	assertEncryptedComponentRotationResult(
		t, ctx, pool, envelope, componentSession.RefreshToken,
		provisionedComponent.ComponentID, firstRace.issued, now,
	)
	wrongComponentKey, _, _ := newChallengeKey(t)
	wrongComponentRefreshProof := signedSessionDPoP(
		t, wrongComponentKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-widget-wrong-key",
	)
	wrongComponentRefreshResponse := clientHTTPPostJSONResponse(
		t, handler, "/client/v1/sessions/refresh", wrongComponentRefreshProof,
		map[string]any{"refresh_token": componentSession.RefreshToken},
	)
	assertClientHTTPProblem(t, wrongComponentRefreshResponse, http.StatusUnauthorized, "dpop_invalid")

	componentDiagnosticsTarget := clientHTTPURL(t, "/client/v1/diagnostics")
	componentDiagnosticsProof := signedSessionAccessDPoP(
		t, childPrivateKey, http.MethodGet, componentDiagnosticsTarget, now,
		refreshedComponent.AccessToken, "client-http-widget-diagnostics",
	)
	componentDiagnosticsResponse := clientHTTPGetDiagnostics(
		t, handler, refreshedComponent.AccessToken, componentDiagnosticsProof, "ios",
	)
	if componentDiagnosticsResponse.Code != http.StatusOK {
		rawComponentAccess, parseErr := NewAccessToken(refreshedComponent.AccessToken)
		if parseErr != nil {
			t.Fatalf("parse refreshed component access token after diagnostics failure: %v", parseErr)
		}
		failedPrincipal, verifyErr := accessVerifier.Verify(ctx, rawComponentAccess)
		if verifyErr != nil {
			t.Fatalf("verify refreshed component access token after diagnostics failure: %v", verifyErr)
		}
		failedState, stateErr := loadAuthorizationState(ctx, pool, failedPrincipal, "")
		if stateErr != nil {
			t.Fatalf("component diagnostics status=%d body=%s state_load=%v",
				componentDiagnosticsResponse.Code, componentDiagnosticsResponse.Body.String(), stateErr)
		}
		t.Fatalf("component diagnostics status=%d body=%s state_error=%v family=%q component=%q key=%q component_session=%q installation=%q grant_revoked=%t installation_trust=%q grant_trust=%q access_expiry=%s identity_expiry=%s attestation_expiry=%s",
			componentDiagnosticsResponse.Code, componentDiagnosticsResponse.Body.String(),
			authorizationStateError(failedState, now, false), failedState.familyStatus,
			failedState.componentStatus, failedState.componentKeyStatus,
			failedState.componentSessionStatus, failedState.installationStatus,
			failedState.grantRevoked, failedState.installationTrust, failedState.TrustLevel,
			failedState.AccessExpiresAt, failedState.IdentityExpiresAt, failedState.AttestationExpiresAt)
	}
	var componentDiagnostics clientHTTPDiagnosticsDocument
	if err := json.NewDecoder(componentDiagnosticsResponse.Body).Decode(&componentDiagnostics); err != nil {
		t.Fatalf("decode component diagnostics: %v", err)
	}
	if componentDiagnostics.Installation.DPoPJKT != childJKT ||
		!componentDiagnostics.Session.RefreshAvailable ||
		componentDiagnostics.Trust.Source != "delegated_identity_only" ||
		componentDiagnostics.Trust.ParentComponentID != refreshed.Component.ID {
		t.Fatalf("component diagnostics crossed the principal boundary: %#v", componentDiagnostics)
	}

	// A directly attestable Action extension begins as an independently
	// delegated component, then rotates only its own component-session family
	// after proving App Attest evidence for its exact bundle and DPoP key.
	actionPrivateKey, actionPublicJWK, actionJKT := newChallengeKey(t)
	actionProvisionProof := signedSessionAccessDPoP(
		t, dpopPrivateKey, http.MethodPost, provisionComponentTarget, now,
		refreshed.AccessToken, "client-http-provision-action",
	)
	var provisionedAction clientHTTPProvisionComponentDocument
	clientHTTPPostJSONAuthorized(
		t, handler, "/client/v1/installation-families/current/components",
		refreshed.AccessToken, actionProvisionProof,
		map[string]any{
			"component_definition_id": "ios-action",
			"public_jwk":              actionPublicJWK,
			"requested_features":      []any{"assistant"},
			"client_metadata": map[string]any{
				"app_version": "1.0.0", "sdk_version": "1.2.3",
			},
		},
		http.StatusCreated,
		&provisionedAction,
	)
	if provisionedAction.Trust.Source != "delegated_identity_only" ||
		provisionedAction.InstallationFamilyID != provisionedComponent.InstallationFamilyID {
		t.Fatalf("Action provisioning crossed the delegated family boundary: %#v", provisionedAction)
	}
	actionSessionProof := signedSessionDPoP(
		t, actionPrivateKey, http.MethodPost, componentSessionTarget, now,
		"client-http-create-action-session",
	)
	var actionSession clientHTTPComponentSessionDocument
	clientHTTPPostJSON(
		t, handler, "/client/v1/component-sessions", actionSessionProof,
		map[string]any{
			"component_id":  provisionedAction.ComponentID,
			"refresh_grant": provisionedAction.RefreshGrant,
		},
		http.StatusCreated,
		&actionSession,
	)
	actionAccess, err := NewAccessToken(actionSession.AccessToken)
	if err != nil {
		t.Fatalf("parse delegated Action access token: %v", err)
	}
	actionPrincipal, err := accessVerifier.Verify(ctx, actionAccess)
	if err != nil {
		t.Fatalf("verify delegated Action access token: %v", err)
	}
	if actionPrincipal.ComponentID != provisionedAction.ComponentID ||
		actionPrincipal.ComponentDefinitionID != "ios-action" ||
		actionPrincipal.ComponentKind != "action_extension" || actionPrincipal.ComponentIsRoot ||
		actionPrincipal.DPoPJKT != actionJKT ||
		actionPrincipal.TrustSource != "delegated_identity_only" {
		t.Fatalf("delegated Action token omitted its component boundary: %#v", actionPrincipal)
	}

	// The root fixture intentionally uses debug evidence. Elevate this one
	// delegated grant to the direct policy's minimum solely to exercise the
	// production component step-up transaction without weakening its runtime
	// trust floor.
	elevatedActionAccess, err := accessIssuer.IssueFor(ctx, AccessIssueInput{
		OrganizationID: actionPrincipal.OrganizationID, ApplicationID: actionPrincipal.ApplicationID,
		EnvironmentID: actionPrincipal.EnvironmentID, ApplicationUserID: actionPrincipal.ApplicationUserID,
		InstallationID: refreshed.Installation.ID, InstallationFamilyID: actionPrincipal.InstallationFamilyID,
		ComponentID: actionPrincipal.ComponentID, ComponentDefinitionID: actionPrincipal.ComponentDefinitionID,
		ComponentKind: actionPrincipal.ComponentKind, ComponentIsRoot: false,
		TrustSource: "delegated_identity_only", AttestationProvider: "app_attest",
		ParentComponentID:         actionPrincipal.ParentComponentID,
		ParentAttestationProvider: actionPrincipal.ParentAttestationProvider,
		DelegationID:              actionPrincipal.DelegationID,
		Features:                  append([]string(nil), actionPrincipal.Features...),
		SessionGrantID:            actionPrincipal.SessionGrantID, IdentityProvider: actionPrincipal.IdentityProvider,
		TrustLevel: "app_verified", PolicyRevisionID: actionPrincipal.PolicyRevisionID,
		DPoPJKT: actionPrincipal.DPoPJKT,
	}, 10*time.Minute)
	if err != nil {
		t.Fatalf("issue elevated Action fixture access: %v", err)
	}
	elevatedActionToken := elevatedActionAccess.Token.Reveal()
	if command, err := pool.Exec(ctx, `
		UPDATE session_grants
		SET access_token_jti_hash = $2, trust_level = 'app_verified',
		    attestation_provider = 'app_attest', attested_at = $3,
		    attestation_expires_at = $4, expires_at = $5
		WHERE session_grant_id = $1 AND revoked_at IS NULL
	`, actionPrincipal.SessionGrantID, elevatedActionAccess.JTIHash[:], now,
		now.Add(10*time.Minute), elevatedActionAccess.ExpiresAt); err != nil {
		t.Fatalf("elevate Action fixture grant: %v", err)
	} else if command.RowsAffected() != 1 {
		t.Fatalf("elevate Action fixture grant rows = %d", command.RowsAffected())
	}

	actionChallengePath := "/client/v1/installation-families/current/components/" +
		provisionedAction.ComponentID + "/attestation-challenges"
	actionChallengeTarget := clientHTTPURL(t, actionChallengePath)
	actionChallengeProof := signedSessionAccessDPoP(
		t, actionPrivateKey, http.MethodPost, actionChallengeTarget, now,
		elevatedActionToken, "client-http-action-attestation-challenge",
	)
	var actionChallengeDocument clientHTTPChallengeDocument
	clientHTTPPostBodylessAuthorized(
		t, handler, actionChallengePath, elevatedActionToken, actionChallengeProof,
		http.StatusCreated, &actionChallengeDocument,
	)
	if actionChallengeDocument.BindingVersion != 2 ||
		actionChallengeDocument.Attestation.Provider != "app_attest" ||
		actionChallengeDocument.Attestation.Mode != "required" {
		t.Fatalf("Action challenge did not select binding v2 App Attest: %#v", actionChallengeDocument)
	}
	actionChallenge, err := sessionStore.GetComponentAttestationChallenge(ctx, actionChallengeDocument.ChallengeID)
	if err != nil {
		t.Fatalf("load authoritative Action challenge: %v", err)
	}
	if actionChallenge.Binding.ClientComponentID != provisionedAction.ComponentID ||
		actionChallenge.Binding.ComponentDefinitionID != "ios-action" ||
		actionChallenge.Binding.DPoPJKT != actionJKT ||
		actionChallenge.Binding.Platform != "ios" {
		t.Fatalf("Action challenge crossed its signed scope: %#v", actionChallenge.Binding)
	}

	actionAppAttestPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate Action App Attest fixture key: %v", err)
	}
	actionAppAttestPublicKey, err := actionAppAttestPrivateKey.PublicKey.Bytes()
	if err != nil || len(actionAppAttestPublicKey) != 65 || actionAppAttestPublicKey[0] != 4 {
		t.Fatalf("encode Action App Attest fixture key: bytes=%d err=%v", len(actionAppAttestPublicKey), err)
	}
	actionAppAttestKeyID := sha256.Sum256(actionAppAttestPublicKey)
	actionAppIDHash := sha256.Sum256([]byte("TEAM1234.com.example.latchway.action"))
	if err := appAttestKeys.TransactAppAttestKey(ctx, actionAppAttestKeyID, func(
		_ attestation.AppAttestStoredKey,
		exists bool,
	) (attestation.AppAttestStoredKey, error) {
		if exists {
			return attestation.AppAttestStoredKey{}, errors.New("unexpected existing Action App Attest key")
		}
		return attestation.AppAttestStoredKey{
			PublicKeyX963: actionAppAttestPublicKey, AppIDHash: actionAppIDHash,
			AttestationEnvironment: attestation.AppAttestDevelopment,
			ApplicationID:          actionChallenge.Binding.ApplicationID,
			EnvironmentID:          actionChallenge.Binding.Environment,
			Platform:               actionChallenge.Binding.Platform,
			PrincipalID:            actionChallenge.Binding.PrincipalID,
			DPoPJKT:                actionChallenge.Binding.DPoPJKT,
			AttestedAt:             now,
		}, nil
	}); err != nil {
		t.Fatalf("persist unlinked Action App Attest key: %v", err)
	}
	actionAssertionPayload := appAttestAssertionPayloadForAppID(
		t, actionAppAttestPrivateKey, actionAppAttestKeyID,
		actionChallenge.Binding, 1, "TEAM1234.com.example.latchway.action",
	)
	actionExchangeBody := map[string]any{
		"challenge_id": actionChallenge.ID,
		"attestation": map[string]any{
			"provider": "app_attest", "evidence": actionAssertionPayload,
		},
	}
	actionExchangePath := "/client/v1/installation-families/current/components/" +
		provisionedAction.ComponentID + "/attestation-exchanges"
	actionExchangeTarget := clientHTTPURL(t, actionExchangePath)
	wrongActionKey, _, _ := newChallengeKey(t)
	wrongActionProof := signedSessionAccessDPoP(
		t, wrongActionKey, http.MethodPost, actionExchangeTarget, now,
		elevatedActionToken, "client-http-action-attestation-wrong-dpop",
	)
	wrongActionResponse := clientHTTPPostJSONAuthorizedResponse(
		t, handler, actionExchangePath, elevatedActionToken, wrongActionProof, actionExchangeBody,
	)
	assertClientHTTPProblem(t, wrongActionResponse, http.StatusUnauthorized, "dpop_invalid")
	assertAppAttestKeyLink(t, ctx, pool, actionAppAttestKeyID, "", "active", false, 0, false)

	var parentTrustSource string
	var parentTrustVerifiedAt, parentTrustExpiresAt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT trust_source, trust_verified_at, trust_expires_at
		FROM client_components
		WHERE client_component_id = $1
	`, actionPrincipal.ParentComponentID).Scan(
		&parentTrustSource, &parentTrustVerifiedAt, &parentTrustExpiresAt,
	); err != nil {
		t.Fatalf("load Action parent trust expiry: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE client_components
		SET trust_source = 'direct_attested',
		    trust_verified_at = $2, trust_expires_at = $3
		WHERE client_component_id = $1
	`, actionPrincipal.ParentComponentID, now.Add(-time.Second), now); err != nil {
		t.Fatalf("expire Action parent trust fixture: %v", err)
	}
	expiredParentProof := signedSessionAccessDPoP(
		t, actionPrivateKey, http.MethodPost, actionExchangeTarget, now,
		elevatedActionToken, "client-http-action-attestation-expired-parent",
	)
	expiredParentResponse := clientHTTPPostJSONAuthorizedResponse(
		t, handler, actionExchangePath, elevatedActionToken, expiredParentProof, actionExchangeBody,
	)
	assertClientHTTPProblem(
		t, expiredParentResponse, http.StatusUnauthorized, "component_parent_trust_expired",
	)
	assertAppAttestKeyLink(t, ctx, pool, actionAppAttestKeyID, "", "active", false, 1, true)
	if _, err := sessionStore.GetComponentAttestationChallenge(ctx, actionChallenge.ID); err != nil {
		t.Fatalf("parent-trust rollback consumed Action challenge: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE client_components
		SET trust_verified_at = $2, trust_expires_at = $3
		WHERE client_component_id = $1
	`, actionPrincipal.ParentComponentID, parentTrustVerifiedAt, parentTrustExpiresAt); err != nil {
		t.Fatalf("restore Action parent trust fixture: %v", err)
	}

	retryActionProof := signedSessionAccessDPoP(
		t, actionPrivateKey, http.MethodPost, actionExchangeTarget, now,
		elevatedActionToken, "client-http-action-attestation-exact-retry",
	)
	var directActionGrant clientHTTPGrantDocument
	clientHTTPPostJSONAuthorized(
		t, handler, actionExchangePath, elevatedActionToken, retryActionProof,
		actionExchangeBody, http.StatusCreated, &directActionGrant,
	)
	// The direct Action may refresh only while its parent retains the exact
	// attested trust used by the exchange. Rotate once inside that boundary so
	// component revocation can later prove deletion of a still-live cache.
	actionRefreshProof := signedSessionDPoP(
		t, actionPrivateKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-action-before-revoke",
	)
	var refreshedAction clientHTTPGrantDocument
	clientHTTPPostJSON(
		t, handler, "/client/v1/sessions/refresh", actionRefreshProof,
		map[string]any{"refresh_token": directActionGrant.RefreshToken},
		http.StatusOK,
		&refreshedAction,
	)
	if refreshedAction.Component == nil ||
		refreshedAction.Component.ID != provisionedAction.ComponentID ||
		refreshedAction.RefreshToken == directActionGrant.RefreshToken {
		t.Fatal("Action refresh did not create an independent rotated result")
	}
	actionOldRefreshDigest := sha256.Sum256([]byte(directActionGrant.RefreshToken))
	var actionRotationResults int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM refresh_rotation_results
		WHERE old_refresh_token_hash = $1 AND client_component_id = $2
	`, actionOldRefreshDigest[:], provisionedAction.ComponentID).Scan(&actionRotationResults); err != nil {
		t.Fatalf("inspect live Action rotation cache: %v", err)
	}
	if actionRotationResults != 1 {
		t.Fatalf("live Action rotation cache rows = %d, want 1", actionRotationResults)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE client_components
		SET trust_source = $2
		WHERE client_component_id = $1
	`, actionPrincipal.ParentComponentID, parentTrustSource); err != nil {
		t.Fatalf("restore Action parent trust source fixture: %v", err)
	}
	if directActionGrant.Component == nil ||
		directActionGrant.Component.ID != provisionedAction.ComponentID ||
		directActionGrant.Component.DefinitionID != "ios-action" ||
		directActionGrant.Component.DPoPJKT != actionJKT ||
		directActionGrant.Trust.Source != "delegated_direct_attested" ||
		directActionGrant.Trust.Provider != "app_attest" ||
		directActionGrant.Trust.Level != "app_verified" ||
		directActionGrant.Trust.ParentComponentID != actionPrincipal.ParentComponentID ||
		directActionGrant.Trust.ParentAttestationProvider != actionPrincipal.ParentAttestationProvider ||
		directActionGrant.Trust.DelegationID != actionPrincipal.DelegationID {
		t.Fatalf("direct Action exchange omitted composite trust provenance: %#v", directActionGrant)
	}
	directActionAccess, err := NewAccessToken(directActionGrant.AccessToken)
	if err != nil {
		t.Fatalf("parse direct Action access token: %v", err)
	}
	directActionPrincipal, err := accessVerifier.Verify(ctx, directActionAccess)
	if err != nil {
		t.Fatalf("verify direct Action access token: %v", err)
	}
	if directActionPrincipal.TrustSource != "delegated_direct_attested" ||
		directActionPrincipal.AttestationProvider != "app_attest" ||
		directActionPrincipal.ParentComponentID != actionPrincipal.ParentComponentID ||
		directActionPrincipal.DelegationID != actionPrincipal.DelegationID {
		t.Fatalf("direct Action token lost composite provenance: %#v", directActionPrincipal)
	}
	var directActionComponentKeyID string
	if err := pool.QueryRow(ctx, `
		SELECT current_component_key_id
		FROM client_components
		WHERE client_component_id = $1
	`, provisionedAction.ComponentID).Scan(&directActionComponentKeyID); err != nil {
		t.Fatalf("load directly attested Action component key: %v", err)
	}
	assertAppAttestComponentKeyLink(
		t, ctx, pool, actionAppAttestKeyID, provisionedAction.InstallationFamilyID,
		provisionedAction.ComponentID, directActionComponentKeyID, "active", 1,
	)

	oldActionDiagnosticsProof := signedSessionAccessDPoP(
		t, actionPrivateKey, http.MethodGet, componentDiagnosticsTarget, now,
		elevatedActionToken, "client-http-action-old-session-after-step-up",
	)
	oldActionDiagnosticsResponse := clientHTTPGetDiagnostics(
		t, handler, elevatedActionToken, oldActionDiagnosticsProof, "ios",
	)
	assertClientHTTPProblem(t, oldActionDiagnosticsResponse, http.StatusUnauthorized, "session_revoked")
	replayActionProof := signedSessionAccessDPoP(
		t, actionPrivateKey, http.MethodPost, actionExchangeTarget, now,
		directActionGrant.AccessToken, "client-http-action-attestation-replay",
	)
	replayActionResponse := clientHTTPPostJSONAuthorizedResponse(
		t, handler, actionExchangePath, directActionGrant.AccessToken,
		replayActionProof, actionExchangeBody,
	)
	assertClientHTTPProblem(t, replayActionResponse, http.StatusConflict, "conflict")
	assertAppAttestComponentKeyLink(
		t, ctx, pool, actionAppAttestKeyID, provisionedAction.InstallationFamilyID,
		provisionedAction.ComponentID, directActionComponentKeyID, "active", 1,
	)

	siblingDiagnosticsProof := signedSessionAccessDPoP(
		t, childPrivateKey, http.MethodGet, componentDiagnosticsTarget, now,
		refreshedComponent.AccessToken, "client-http-widget-after-action-step-up",
	)
	siblingDiagnosticsResponse := clientHTTPGetDiagnostics(
		t, handler, refreshedComponent.AccessToken, siblingDiagnosticsProof, "ios",
	)
	if siblingDiagnosticsResponse.Code != http.StatusOK {
		t.Fatalf("Action step-up affected widget sibling: status=%d body=%s",
			siblingDiagnosticsResponse.Code, siblingDiagnosticsResponse.Body.String())
	}

	// Revoke the directly attested Action while its exact-retry cache is still
	// live. The cache must be deleted transactionally, the old credential must
	// not recover it, and the widget sibling must remain usable.
	actionRevokePath := "/client/v1/installation-families/current/components/" + provisionedAction.ComponentID
	actionRevokeTarget := clientHTTPURL(t, actionRevokePath)
	actionRevokeProof := signedSessionAccessDPoP(
		t, dpopPrivateKey, http.MethodDelete, actionRevokeTarget, now,
		refreshed.AccessToken, "client-http-revoke-action-with-cache",
	)
	actionRevokeResponse := clientHTTPDeleteAuthorized(
		t, handler, actionRevokePath, refreshed.AccessToken, actionRevokeProof,
	)
	assertClientHTTPNoContent(t, actionRevokeResponse)
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM refresh_rotation_results
		WHERE client_component_id = $1
	`, provisionedAction.ComponentID).Scan(&actionRotationResults); err != nil {
		t.Fatalf("inspect revoked Action rotation cache: %v", err)
	}
	if actionRotationResults != 0 {
		t.Fatalf("revoked Action retained %d encrypted rotation caches", actionRotationResults)
	}
	postActionRevokeRefreshProof := signedSessionDPoP(
		t, actionPrivateKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-action-after-component-revoke",
	)
	postActionRevokeRefreshResponse := clientHTTPPostJSONResponse(
		t, handler, "/client/v1/sessions/refresh", postActionRevokeRefreshProof,
		map[string]any{"refresh_token": directActionGrant.RefreshToken},
	)
	assertClientHTTPProblem(
		t, postActionRevokeRefreshResponse, http.StatusForbidden, "component_revoked",
	)
	widgetAfterActionRevokeProof := signedSessionAccessDPoP(
		t, childPrivateKey, http.MethodGet, componentDiagnosticsTarget, now,
		refreshedComponent.AccessToken, "client-http-widget-after-action-revoke",
	)
	widgetAfterActionRevokeResponse := clientHTTPGetDiagnostics(
		t, handler, refreshedComponent.AccessToken, widgetAfterActionRevokeProof, "ios",
	)
	if widgetAfterActionRevokeResponse.Code != http.StatusOK {
		t.Fatalf("Action revocation affected widget sibling: status=%d body=%s",
			widgetAfterActionRevokeResponse.Code, widgetAfterActionRevokeResponse.Body.String())
	}

	// Once the bounded exact-retry window closes, reusing the old credential
	// revokes only this component-session family and deletes its encrypted cache.
	now = now.Add(componentRefreshIdempotencyGrace + time.Second)
	expiredRetryProof := signedSessionDPoP(
		t, childPrivateKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-widget-after-grace",
	)
	expiredRetryResponse := clientHTTPPostJSONResponse(
		t, handler, "/client/v1/sessions/refresh", expiredRetryProof,
		map[string]any{"refresh_token": componentSession.RefreshToken},
	)
	assertClientHTTPProblem(t, expiredRetryResponse, http.StatusUnauthorized, "refresh_token_reused")
	oldRefreshDigest := sha256.Sum256([]byte(componentSession.RefreshToken))
	newRefreshDigest := sha256.Sum256([]byte(refreshedComponent.RefreshToken))
	var oldRefreshStatus, newRefreshStatus, componentSessionStatus string
	var retainedRotationResults int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT status FROM component_refresh_tokens WHERE token_hash = $1),
			(SELECT status FROM component_refresh_tokens WHERE token_hash = $2),
			(SELECT status FROM component_session_families
			 WHERE component_session_family_id = $3),
			(SELECT count(*) FROM refresh_rotation_results
			 WHERE old_refresh_token_hash IN ($1, $2))
	`, oldRefreshDigest[:], newRefreshDigest[:], firstRace.issued.RefreshFamilyID).Scan(
		&oldRefreshStatus, &newRefreshStatus, &componentSessionStatus,
		&retainedRotationResults,
	); err != nil {
		t.Fatalf("inspect after-grace component refresh reuse: %v", err)
	}
	if oldRefreshStatus != "reused" || newRefreshStatus != "revoked" ||
		componentSessionStatus != "revoked" || retainedRotationResults != 0 {
		t.Fatalf("after-grace reuse state old=%q new=%q family=%q cached=%d",
			oldRefreshStatus, newRefreshStatus, componentSessionStatus, retainedRotationResults)
	}
	var reuseAuditAction, reuseAuditReason string
	var reuseAuditChanges, sensitiveReuseChanges int
	if err := pool.QueryRow(ctx, `
		SELECT event.action, COALESCE(event.reason, ''), count(*)::int,
		       count(*) FILTER (WHERE change.classification = 'sensitive')::int
		FROM audit_events AS event
		JOIN audit_event_changes AS change ON change.audit_event_id = event.audit_event_id
		WHERE event.resource_type = 'client_component' AND event.resource_id = $1
		  AND event.action = 'client.component.refresh_reuse_detected'
		GROUP BY event.audit_event_id, event.action, event.reason
	`, provisionedComponent.ComponentID).Scan(
		&reuseAuditAction, &reuseAuditReason, &reuseAuditChanges, &sensitiveReuseChanges,
	); err != nil {
		t.Fatalf("inspect component refresh-reuse audit event: %v", err)
	}
	if reuseAuditAction != "client.component.refresh_reuse_detected" ||
		reuseAuditReason != "refresh_reuse_detected" || reuseAuditChanges != 3 || sensitiveReuseChanges != 2 {
		t.Fatalf("component refresh-reuse audit action=%q reason=%q changes=%d sensitive=%d",
			reuseAuditAction, reuseAuditReason, reuseAuditChanges, sensitiveReuseChanges)
	}
	revokedFamilyRefreshProof := signedSessionDPoP(
		t, childPrivateKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-widget-revoked-family",
	)
	revokedFamilyRefreshResponse := clientHTTPPostJSONResponse(
		t, handler, "/client/v1/sessions/refresh", revokedFamilyRefreshProof,
		map[string]any{"refresh_token": refreshedComponent.RefreshToken},
	)
	assertClientHTTPProblem(t, revokedFamilyRefreshResponse, http.StatusUnauthorized, "session_revoked")

	componentRevokePath := "/client/v1/installation-families/current/components/" + provisionedComponent.ComponentID
	componentRevokeTarget := clientHTTPURL(t, componentRevokePath)
	componentRevokeProof := signedSessionAccessDPoP(
		t, dpopPrivateKey, http.MethodDelete, componentRevokeTarget, now,
		refreshed.AccessToken, "client-http-revoke-widget",
	)
	componentRevokeResponse := clientHTTPDeleteAuthorized(
		t, handler, componentRevokePath, refreshed.AccessToken, componentRevokeProof,
	)
	assertClientHTTPNoContent(t, componentRevokeResponse)
	componentRevokeRetryProof := signedSessionAccessDPoP(
		t, dpopPrivateKey, http.MethodDelete, componentRevokeTarget, now,
		refreshed.AccessToken, "client-http-revoke-widget-idempotent",
	)
	componentRevokeRetryResponse := clientHTTPDeleteAuthorized(
		t, handler, componentRevokePath, refreshed.AccessToken, componentRevokeRetryProof,
	)
	assertClientHTTPNoContent(t, componentRevokeRetryResponse)
	postComponentRevokeProof := signedSessionAccessDPoP(
		t, childPrivateKey, http.MethodGet, componentDiagnosticsTarget, now,
		refreshedComponent.AccessToken, "client-http-widget-diagnostics-after-revoke",
	)
	postComponentRevokeResponse := clientHTTPGetDiagnostics(
		t, handler, refreshedComponent.AccessToken, postComponentRevokeProof, "ios",
	)
	assertClientHTTPProblem(t, postComponentRevokeResponse, http.StatusForbidden, "component_revoked")
	postComponentRevokeRefreshProof := signedSessionDPoP(
		t, childPrivateKey, http.MethodPost, refreshTarget, now,
		"client-http-refresh-widget-after-component-revoke",
	)
	postComponentRevokeRefreshResponse := clientHTTPPostJSONResponse(
		t, handler, "/client/v1/sessions/refresh", postComponentRevokeRefreshProof,
		map[string]any{"refresh_token": componentSession.RefreshToken},
	)
	assertClientHTTPProblem(t, postComponentRevokeRefreshResponse, http.StatusForbidden, "component_revoked")

	diagnosticsTarget := clientHTTPURL(t, "/client/v1/diagnostics")
	mismatchedSDKProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodGet, diagnosticsTarget,
		now, refreshed.AccessToken, "client-http-diagnostics-mismatched-sdk")
	mismatchedSDKResponse := clientHTTPGetDiagnostics(t, handler, refreshed.AccessToken, mismatchedSDKProof, "android")
	assertClientHTTPProblem(t, mismatchedSDKResponse, http.StatusBadRequest, "request_invalid")

	oldDiagnosticsProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodGet, diagnosticsTarget,
		now, exchanged.AccessToken, "client-http-diagnostics-rotated-refresh")
	oldDiagnosticsResponse := clientHTTPGetDiagnostics(t, handler, exchanged.AccessToken, oldDiagnosticsProof, "ios")
	if oldDiagnosticsResponse.Code != http.StatusOK {
		t.Fatalf("old client diagnostics status=%d body=%s", oldDiagnosticsResponse.Code, oldDiagnosticsResponse.Body.String())
	}
	var oldDiagnostics clientHTTPDiagnosticsDocument
	if err := json.NewDecoder(oldDiagnosticsResponse.Body).Decode(&oldDiagnostics); err != nil {
		t.Fatalf("decode old client diagnostics: %v", err)
	}
	if oldDiagnostics.Session.RefreshAvailable {
		t.Fatal("diagnostics reported a rotated refresh token as available")
	}

	diagnosticsProof := signedSessionAccessDPoP(t, dpopPrivateKey, http.MethodGet, diagnosticsTarget,
		now, refreshed.AccessToken, "client-http-diagnostics")
	diagnosticsResponse := clientHTTPGetDiagnostics(t, handler, refreshed.AccessToken, diagnosticsProof, "ios")
	if diagnosticsResponse.Code != http.StatusOK || diagnosticsResponse.Header().Get("Cache-Control") != "no-store" ||
		diagnosticsResponse.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("client diagnostics status=%d headers=%#v body=%s",
			diagnosticsResponse.Code, diagnosticsResponse.Header(), diagnosticsResponse.Body.String())
	}
	var diagnostics clientHTTPDiagnosticsDocument
	if err := json.NewDecoder(diagnosticsResponse.Body).Decode(&diagnostics); err != nil {
		t.Fatalf("decode client diagnostics: %v", err)
	}
	if diagnostics.RequestID == "" || diagnostics.RequestID != diagnosticsResponse.Header().Get("X-Latchway-Request-ID") ||
		diagnostics.ServerVersion != buildinfo.Version || diagnostics.ContractVersion != buildinfo.ContractVersion ||
		diagnostics.ProtocolVersion != buildinfo.CurrentProtocolVersion || diagnostics.Installation != refreshed.Installation ||
		!diagnostics.Session.ExpiresAt.Equal(refreshed.Trust.ExpiresAt) || !diagnostics.Session.RefreshAvailable ||
		diagnostics.Trust != refreshed.Trust {
		t.Fatalf("client diagnostics violated the redacted session contract: %#v", diagnostics)
	}
	if strings.Contains(diagnosticsResponse.Body.String(), refreshed.AccessToken) ||
		strings.Contains(diagnosticsResponse.Body.String(), refreshed.RefreshToken) ||
		strings.Contains(diagnosticsResponse.Body.String(), fixture.organizationID) ||
		strings.Contains(diagnosticsResponse.Body.String(), "external-user-001") {
		t.Fatalf("client diagnostics exposed private session material: %s", diagnosticsResponse.Body.String())
	}
	diagnosticsReplay := clientHTTPGetDiagnostics(t, handler, refreshed.AccessToken, diagnosticsProof, "ios")
	assertClientHTTPProblem(t, diagnosticsReplay, http.StatusUnauthorized, "dpop_replayed")

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

	familyRevokePath := "/client/v1/installation-families/current"
	familyRevokeTarget := clientHTTPURL(t, familyRevokePath)
	familyRevokeProof := signedSessionAccessDPoP(
		t, dpopPrivateKey, http.MethodDelete, familyRevokeTarget, now,
		refreshed.AccessToken, "client-http-revoke-family",
	)
	familyRevokeResponse := clientHTTPDeleteAuthorized(
		t, handler, familyRevokePath, refreshed.AccessToken, familyRevokeProof,
	)
	assertClientHTTPNoContent(t, familyRevokeResponse)
	var retainedFamilyRotationResults int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM refresh_rotation_results AS result
		JOIN client_components AS component
		  ON component.client_component_id = result.client_component_id
		WHERE component.installation_family_id = $1
	`, provisionedComponent.InstallationFamilyID).Scan(&retainedFamilyRotationResults); err != nil {
		t.Fatalf("inspect revoked-family rotation caches: %v", err)
	}
	if retainedFamilyRotationResults != 0 {
		t.Fatalf("revoked family retained %d encrypted rotation caches", retainedFamilyRotationResults)
	}
	assertAppAttestComponentKeyLink(
		t, ctx, pool, actionAppAttestKeyID, provisionedAction.InstallationFamilyID,
		provisionedAction.ComponentID, directActionComponentKeyID, "revoked", 1,
	)

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
	assertClientHTTPProblem(t, postRevocationRefreshResponse, http.StatusForbidden, "installation_family_revoked")

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
	var activeComponentRefresh, rotatedComponentRefresh, revokedComponentRefresh, reusedComponentRefresh int
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
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'active'),
		       count(*) FILTER (WHERE status = 'rotated'),
		       count(*) FILTER (WHERE status = 'revoked'),
		       count(*) FILTER (WHERE status = 'reused')
		FROM component_refresh_tokens
	`).Scan(&activeComponentRefresh, &rotatedComponentRefresh, &revokedComponentRefresh,
		&reusedComponentRefresh); err != nil {
		t.Fatalf("inspect component refresh rotation state: %v", err)
	}
	if activeRefresh != 0 || rotatedRefresh != 0 || revokedRefresh != 0 ||
		activeComponentRefresh != 0 || rotatedComponentRefresh != 4 || revokedComponentRefresh != 4 ||
		reusedComponentRefresh != 1 ||
		grantCount != 7 || revokedGrants != 7 {
		t.Fatalf("persisted revoked session state = legacy(active:%d rotated:%d revoked:%d) component(active:%d rotated:%d revoked:%d reused:%d) grants:%d revoked_grants:%d",
			activeRefresh, rotatedRefresh, revokedRefresh,
			activeComponentRefresh, rotatedComponentRefresh, revokedComponentRefresh, reusedComponentRefresh,
			grantCount, revokedGrants)
	}
	metricResponse := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metricResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metricText := metricResponse.Body.String()
	for _, series := range []string{
		`latchway_attestation_results_total{application="` + fixture.applicationID + `",attestation_level="none",environment="` + fixture.environmentID + `",outcome="rejected",platform="ios"} 1`,
		`latchway_attestation_results_total{application="` + fixture.applicationID + `",attestation_level="debug",environment="` + fixture.environmentID + `",outcome="succeeded",platform="ios"} 1`,
	} {
		if !strings.Contains(metricText, series) {
			t.Fatalf("attestation metrics missing %q:\n%s", series, metricText)
		}
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
				"appIdPrefix": "TEAM1234", "bundleId": "com.example.latchway",
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
	InstallationFamily *clientapi.InstallationFamilySummary `json:"installation_family,omitempty"`
	Component          *clientapi.ClientComponentSummary    `json:"component,omitempty"`
	Trust              clientapi.TrustSummary               `json:"trust"`
}

type clientHTTPProvisionComponentDocument struct {
	ComponentID          string `json:"component_id"`
	InstallationFamilyID string `json:"installation_family_id"`
	Trust                struct {
		Source    string    `json:"source"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"trust"`
	GrantedFeatures       []string  `json:"granted_features"`
	RefreshGrant          string    `json:"refresh_grant"`
	RefreshGrantExpiresAt time.Time `json:"refresh_grant_expires_at"`
}

type clientHTTPComponentSessionDocument struct {
	AccessToken      string    `json:"access_token"`
	ExpiresIn        int       `json:"expires_in"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type clientHTTPDiagnosticsDocument struct {
	RequestID       string                        `json:"request_id"`
	ServerVersion   string                        `json:"server_version"`
	ContractVersion string                        `json:"contract_version"`
	ProtocolVersion int                           `json:"protocol_version"`
	Installation    clientapi.InstallationSummary `json:"installation"`
	Session         struct {
		ExpiresAt        time.Time `json:"expires_at"`
		RefreshAvailable bool      `json:"refresh_available"`
	} `json:"session"`
	Trust clientapi.TrustSummary `json:"trust"`
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
			"attestationPolicies": []any{
				map[string]any{
					"id": "native", "maxAge": "10m",
					"platforms": map[string]any{"ios": selection},
				},
				map[string]any{
					"id": "ios-action-direct", "maxAge": "10m",
					"platforms": map[string]any{"ios": map[string]any{
						"provider": "app_attest", "mode": "preferred", "minimumTrustLevel": "app_verified",
						"appAttest": map[string]any{
							"appIdPrefix": "TEAM1234", "bundleId": "com.example.latchway.action",
							"environment": "development", "allowedValidationCategories": []any{1},
							"allowedBundleVersions": []any{"1.0"},
						},
					}},
				},
			},
			"componentDefinitions": []any{
				map[string]any{
					"id": "ios-main", "platform": "ios", "kind": "main_app",
					"identifiers":     map[string]any{"bundleIdentifiers": []any{"com.example.latchway"}},
					"familyRole":      "root",
					"attestation":     map[string]any{"strategy": "direct", "provider": selection["provider"]},
					"allowedFeatures": []any{"assistant"},
				},
				map[string]any{
					"id": "ios-widget", "platform": "ios", "kind": "widget",
					"identifiers": map[string]any{"bundleIdentifiers": []any{"com.example.latchway.widget"}},
					"familyRole":  "delegated",
					"delegation": map[string]any{
						"allowedParents": []any{"ios-main"}, "maximumLifetime": "7d",
					},
					"attestation":     map[string]any{"strategy": "delegated"},
					"allowedFeatures": []any{"assistant"},
				},
				map[string]any{
					"id": "ios-action", "platform": "ios", "kind": "action_extension",
					"identifiers": map[string]any{"bundleIdentifiers": []any{"com.example.latchway.action"}},
					"familyRole":  "delegated",
					"delegation": map[string]any{
						"allowedParents": []any{"ios-main"}, "maximumLifetime": "7d",
					},
					"attestation": map[string]any{
						"strategy": "delegated", "directStepUp": true,
						"directAttestationPolicy": "ios-action-direct",
					},
					"allowedFeatures": []any{"assistant"},
				},
			},
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

func clientHTTPPostJSONAuthorized(
	t *testing.T,
	handler http.Handler,
	path string,
	accessToken string,
	proof DPoPProof,
	body any,
	wantStatus int,
	output any,
) {
	t.Helper()
	response := clientHTTPPostJSONAuthorizedResponse(t, handler, path, accessToken, proof, body)
	if response.Code != wantStatus {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &failure)
		t.Fatalf("authorized client HTTP %s status = %d, problem code = %q, body=%s",
			path, response.Code, failure.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("authorized client HTTP %s omitted required success headers", path)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatalf("decode authorized client HTTP %s response: %v", path, err)
	}
}

func clientHTTPPostJSONAuthorizedResponse(
	t *testing.T,
	handler http.Handler,
	path string,
	accessToken string,
	proof DPoPProof,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode authorized client HTTP request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "DPoP "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	setClientHTTPProtectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func clientHTTPPostBodylessAuthorized(
	t *testing.T,
	handler http.Handler,
	path string,
	accessToken string,
	proof DPoPProof,
	wantStatus int,
	output any,
) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	setClientHTTPProtectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &failure)
		t.Fatalf("bodyless authorized client HTTP %s status = %d, problem code = %q, body=%s",
			path, response.Code, failure.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("bodyless authorized client HTTP %s omitted required success headers", path)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatalf("decode bodyless authorized client HTTP %s response: %v", path, err)
	}
}

func clientHTTPDeleteAuthorized(t *testing.T, handler http.Handler, path, accessToken string, proof DPoPProof) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodDelete, path, nil)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	setClientHTTPProtectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func clientHTTPDeleteInstallation(t *testing.T, handler http.Handler, accessToken string, proof DPoPProof) *httptest.ResponseRecorder {
	t.Helper()
	return clientHTTPDeleteAuthorized(t, handler, "/client/v1/installations/current", accessToken, proof)
}

func clientHTTPGetDiagnostics(t *testing.T, handler http.Handler, accessToken string, proof DPoPProof, sdk string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/client/v1/diagnostics", nil)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	setClientHTTPProtectedHeaders(request, proof)
	request.Header.Set("X-Latchway-SDK", sdk)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func setClientHTTPProtectedHeaders(request *http.Request, proof DPoPProof) {
	request.Host = "untrusted-inbound.example.test"
	request.Header.Set("Forwarded", "host=untrusted-forwarded.example.test;proto=http")
	request.Header.Set("X-Forwarded-Host", "untrusted-forwarded.example.test")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Protocol-Version", buildinfo.ProtocolVersion)
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
		       (SELECT count(*) FROM refresh_tokens WHERE installation_id = $1 AND status = 'active') +
		       (SELECT count(*)
		          FROM component_refresh_tokens AS component_refresh
		          JOIN component_session_families AS component_session
		            ON component_session.component_session_family_id = component_refresh.component_session_family_id
		          JOIN installation_families AS family
		            ON family.installation_family_id = component_session.installation_family_id
		         WHERE family.root_installation_id = $1
		           AND component_refresh.status = 'active'
		           AND component_refresh.grant_kind = 'session')
		FROM installations WHERE installation_id = $1
	`, installationID).Scan(&status, &liveGrants, &activeRefresh); err != nil {
		t.Fatalf("inspect live client HTTP installation: %v", err)
	}
	if status != "active" || liveGrants != wantLiveGrants || activeRefresh != wantActiveRefresh {
		t.Fatalf("client HTTP installation status=%q live_grants=%d active_refresh=%d wants=active/%d/%d",
			status, liveGrants, activeRefresh, wantLiveGrants, wantActiveRefresh)
	}
}

func assertAppAttestComponentKeyLink(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	keyID [sha256.Size]byte,
	wantFamilyID string,
	wantComponentID string,
	wantComponentKeyID string,
	wantStatus string,
	wantCounter int64,
) {
	t.Helper()
	var installationID *string
	var familyID, componentID, componentKeyID *string
	var status string
	var linkedAt *time.Time
	var counter int64
	if err := pool.QueryRow(ctx, `
		SELECT installation_id, installation_family_id, client_component_id,
		       component_key_id, status, linked_at, sign_count
		FROM attestation_keys
		WHERE provider = 'app_attest' AND provider_key_hash = $1
	`, keyID[:]).Scan(
		&installationID, &familyID, &componentID, &componentKeyID,
		&status, &linkedAt, &counter,
	); err != nil {
		t.Fatalf("load component App Attest key link: %v", err)
	}
	if installationID != nil || familyID == nil || componentID == nil || componentKeyID == nil ||
		*familyID != wantFamilyID || *componentID != wantComponentID ||
		*componentKeyID != wantComponentKeyID || status != wantStatus || linkedAt == nil ||
		counter != wantCounter {
		t.Fatalf("component App Attest link installation=%v family=%v component=%v key=%v status=%q linked_at=%v counter=%d",
			installationID, familyID, componentID, componentKeyID, status, linkedAt, counter)
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

func waitForComponentRefreshLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND pid <> pg_backend_pid()
			  AND wait_event_type = 'Lock'
			  AND query ILIKE '%component_refresh%'
		`).Scan(&waiting); err != nil {
			t.Fatalf("inspect concurrent component refresh lock: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("second component refresh did not overlap on the PostgreSQL rotation lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertEncryptedComponentRotationResult(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	protector secrets.Provider,
	oldRefreshToken string,
	componentID string,
	issued IssuedSession,
	now time.Time,
) {
	t.Helper()
	oldDigest := sha256.Sum256([]byte(oldRefreshToken))
	var resultID, algorithm, keyID string
	var ciphertext, nonce []byte
	var formatVersion int
	var createdAt, expiresAt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT refresh_rotation_result_id, rotation_response_ciphertext,
		       rotation_response_nonce, encryption_format_version,
		       encryption_algorithm, master_key_identifier, created_at, expires_at
		FROM refresh_rotation_results
		WHERE old_refresh_token_hash = $1 AND client_component_id = $2
	`, oldDigest[:], componentID).Scan(
		&resultID, &ciphertext, &nonce, &formatVersion,
		&algorithm, &keyID, &createdAt, &expiresAt,
	); err != nil {
		t.Fatalf("load encrypted component refresh rotation result: %v", err)
	}
	if formatVersion != 1 || algorithm != "AES-256-GCM" || keyID == "" ||
		len(ciphertext) == 0 || len(nonce) == 0 || !createdAt.Equal(now) ||
		!expiresAt.Equal(now.Add(componentRefreshIdempotencyGrace)) {
		t.Fatalf("component rotation cache envelope metadata is invalid: format=%d algorithm=%q created=%s expires=%s",
			formatVersion, algorithm, createdAt, expiresAt)
	}
	for label, plaintext := range map[string]string{
		"old refresh": oldRefreshToken,
		"new refresh": issued.Refresh.Reveal(),
		"access":      issued.Access.Token.Reveal(),
	} {
		if bytes.Contains(ciphertext, []byte(plaintext)) {
			t.Fatalf("component rotation cache disclosed the %s credential at rest", label)
		}
	}
	// The production decrypt path binds organization, environment, result ID,
	// version, and format. Query the non-secret scope only after proving the
	// row carries no plaintext credential bytes.
	var organizationID, environmentID string
	if err := pool.QueryRow(ctx, `
		SELECT component.organization_id, component.environment_id
		FROM client_components AS component
		WHERE component.client_component_id = $1
	`, componentID).Scan(&organizationID, &environmentID); err != nil {
		t.Fatalf("load component rotation cache scope: %v", err)
	}
	plaintext, err := protector.Decrypt(secrets.Envelope{
		FormatVersion: formatVersion,
		Algorithm:     algorithm,
		KeyID:         keyID,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
	}, secrets.AssociatedData{
		OrganizationID: organizationID,
		EnvironmentID:  environmentID,
		SecretID:       resultID,
		SecretVersion:  1,
		FormatVersion:  1,
	})
	if err != nil {
		t.Fatalf("decrypt component rotation cache with exact associated data: %v", err)
	}
	defer clear(plaintext)
	var cached cachedComponentRotation
	if err := json.Unmarshal(plaintext, &cached); err != nil {
		t.Fatalf("decode decrypted component rotation cache: %v", err)
	}
	if cached.AccessToken != issued.Access.Token.Reveal() ||
		cached.RefreshToken != issued.Refresh.Reveal() ||
		cached.RefreshTokenID != issued.RefreshID ||
		cached.SessionGrantID != issued.GrantID ||
		cached.SessionFamilyID != issued.RefreshFamilyID {
		t.Fatal("decrypted component rotation cache did not bind the exact committed result")
	}
}

func assertClientHTTPGrant(t *testing.T, grant clientHTTPGrantDocument, dpopJKT string) {
	t.Helper()
	if grant.TokenType != "DPoP" || grant.ExpiresIn != 600 || grant.RefreshExpiresIn != 30*24*60*60 ||
		len(grant.AccessToken) < 64 || len(grant.RefreshToken) < 32 ||
		id.Validate(grant.Installation.ID, id.Installation) != nil || grant.Installation.Platform != "ios" ||
		grant.Installation.DPoPJKT != dpopJKT || grant.Installation.Status != "active" ||
		grant.InstallationFamily == nil || id.Validate(grant.InstallationFamily.ID, id.InstallationFamily) != nil ||
		grant.InstallationFamily.Status != "active" || grant.Component == nil ||
		id.Validate(grant.Component.ID, id.ClientComponent) != nil || grant.Component.DefinitionID != "ios-main" ||
		grant.Component.Kind != "main_app" || grant.Component.Platform != "ios" || !grant.Component.IsRoot ||
		grant.Component.Status != "active" || grant.Component.DPoPJKT != dpopJKT ||
		len(grant.Component.GrantedFeatures) != 1 || grant.Component.GrantedFeatures[0] != "assistant" ||
		grant.Trust.Provider != "debug" || grant.Trust.Level != "debug" ||
		grant.Trust.Source != "debug" || grant.Trust.ParentComponentID != "" ||
		grant.Trust.ParentAttestationProvider != "" || grant.Trust.DelegationID != "" ||
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
		principal.InstallationID != "" || id.Validate(principal.InstallationFamilyID, id.InstallationFamily) != nil ||
		id.Validate(principal.ComponentID, id.ClientComponent) != nil || !principal.ComponentIsRoot ||
		id.Validate(principal.SessionGrantID, id.SessionGrant) != nil ||
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
