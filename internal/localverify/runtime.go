package localverify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/latchway/latchway/conformance/mockupstream"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/session"
)

type challengeDocument struct {
	ChallengeID string `json:"challenge_id"`
	Attestation struct {
		Provider       string `json:"provider"`
		Mode           string `json:"mode"`
		ClientDataHash string `json:"client_data_hash"`
	} `json:"attestation"`
}

type grantDocument struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Installation struct {
		ID       string `json:"id"`
		Platform string `json:"platform"`
		DPoPJKT  string `json:"dpop_jkt"`
	} `json:"installation"`
	Trust struct {
		Provider string `json:"provider"`
		Level    string `json:"level"`
	} `json:"trust"`
}

func (f *fixture) startMockServices() error {
	oidc, err := newMockOIDC()
	if err != nil {
		return err
	}
	f.oidc = oidc
	defaultMock, err := mockupstream.New(mockupstream.DefaultConfig())
	if err != nil {
		return err
	}
	failureConfig := mockupstream.DefaultConfig()
	failureConfig.Scenario = mockupstream.ScenarioHTTP500
	failureMock, err := mockupstream.New(failureConfig)
	if err != nil {
		return err
	}
	fallbackMock, err := mockupstream.New(mockupstream.DefaultConfig())
	if err != nil {
		return err
	}
	f.providerCapture = &captureHandler{
		next: defaultMock, blockMarker: blockedPrompt,
		blockStarted: make(chan struct{}), blockRelease: make(chan struct{}),
	}
	f.failureCapture = &captureHandler{next: failureMock}
	f.fallbackCapture = &captureHandler{next: fallbackMock}
	if f.providerServer, err = startPrivateServer(f.providerCapture); err != nil {
		return err
	}
	if f.failureServer, err = startPrivateServer(f.failureCapture); err != nil {
		return err
	}
	if f.fallbackServer, err = startPrivateServer(f.fallbackCapture); err != nil {
		return err
	}
	return nil
}

func (f *fixture) seedVerificationSecrets(ctx context.Context) error {
	debugDocument, err := debugKeyDocument(f.debugKey)
	if err != nil {
		return err
	}
	if err := f.insertSecret(ctx, "debug-attestation-public-keys", debugDocument); err != nil {
		return err
	}
	return f.insertSecret(ctx, "provider-credential", f.providerCredential)
}

func (f *fixture) composeRuntime(ctx context.Context) error {
	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: f.pool, Provider: f.envelope})
	if err != nil {
		return err
	}
	var subjectProtector *identity.SubjectProtector
	if err := f.envelope.UseIdentitySubjectHMACKey(func(key []byte) error {
		var protectorErr error
		subjectProtector, protectorErr = identity.NewSubjectProtector(key)
		return protectorErr
	}); err != nil {
		return err
	}
	userStore, err := identity.NewUserStore(f.pool, subjectProtector)
	if err != nil {
		return err
	}
	keyManager, err := session.NewSigningKeyManager(session.SigningKeyManagerConfig{
		Pool: f.pool, Envelope: f.envelope, Now: func() time.Time { return f.now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	if _, err := keyManager.Active(ctx); err != nil {
		return err
	}
	accessIssuer, err := session.NewAccessTokenIssuer(session.AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: publicOrigin, Audience: accessAudience,
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		return err
	}
	accessVerifier, err := session.NewAccessTokenVerifier(session.AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: publicOrigin, Audience: accessAudience,
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		return err
	}
	sessionStore, err := session.NewStore(session.StoreConfig{
		Pool: f.pool, AccessTokens: accessIssuer, Configuration: f.configurationStore,
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		return err
	}
	identityCache, err := identity.NewPostgreSQLRemoteKeyCache(f.pool)
	if err != nil {
		return err
	}
	coordinator, err := session.NewClientCoordinator(session.ClientCoordinatorConfig{
		Pool: f.pool, Configuration: f.configurationStore, Users: userStore,
		Sessions: sessionStore, AccessTokens: accessVerifier, Secrets: secretStore,
		IdentityHTTPClient: f.oidc.server.Client(), IdentityKeyCache: identityCache,
		Now: func() time.Time { return f.now },
	})
	if err != nil {
		return err
	}
	publicKeys, err := session.NewClientJWKSProvider(keyManager)
	if err != nil {
		return err
	}
	resolver, err := policy.NewResolver()
	if err != nil {
		return err
	}
	policyEngine, err := dataplane.NewPolicyEngine(resolver)
	if err != nil {
		return err
	}
	quotaStore, err := quota.NewStore(quota.StoreConfig{Pool: f.pool})
	if err != nil {
		return err
	}
	f.quotaStore = quotaStore
	featureQuotas, err := dataplane.NewFeatureQuotaProvider(dataplane.FeatureQuotaConfig{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: f.configurationStore, Policies: resolver,
		Quotas: quotaStore, PublicOrigin: publicOrigin,
	})
	if err != nil {
		return err
	}
	clientAPI, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, FeatureQuotas: featureQuotas,
		JWKS: publicKeys, PublicOrigin: publicOrigin,
	})
	if err != nil {
		return err
	}
	targets, err := dataplane.NewIsolatedVerificationTargetFactory(map[string]string{
		configuredPrimary:  f.providerServer.baseURL + "/v1",
		configuredFailure:  f.failureServer.baseURL + "/v1",
		configuredFallback: f.fallbackServer.baseURL + "/v1",
	})
	if err != nil {
		return err
	}
	dataPlane, err := dataplane.New(dataplane.Config{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: f.configurationStore, Policies: policyEngine,
		Quotas: quotaStore, Secrets: secretStore, Targets: targets,
		PublicOrigin: publicOrigin, Now: func() time.Time { return f.now },
	})
	if err != nil {
		return err
	}
	f.dataPlane = dataPlane
	f.clientHandler = withRequestIdentity(clientAPI.Handler())
	f.dataHandler = withRequestIdentity(dataPlane.Handler())
	return nil
}

func (f *fixture) exchangeSession(ctx context.Context) error {
	discoveryRequest, err := http.NewRequestWithContext(
		ctx, http.MethodGet, f.oidc.issuer+"/.well-known/openid-configuration", nil,
	)
	if err != nil {
		return err
	}
	discoveryResponse, err := f.oidc.server.Client().Do(discoveryRequest)
	if err != nil {
		return err
	}
	if err := discoveryResponse.Body.Close(); err != nil {
		return errors.New("close mock OIDC discovery response")
	}
	if discoveryResponse.StatusCode != http.StatusOK {
		return errors.New("mock OIDC discovery failed")
	}
	identityToken, err := f.oidc.token(f.now)
	if err != nil {
		return err
	}
	challengeTarget, err := parseURL(publicOrigin + "/client/v1/session-challenges")
	if err != nil {
		return err
	}
	challengeProof, err := signDPoP(f.dpopKey, http.MethodPost, challengeTarget, f.now, "challenge", "")
	if err != nil {
		return err
	}
	challengeResponse, err := postJSON(f.clientHandler, "/client/v1/session-challenges", challengeProof, map[string]any{
		"application_id": f.tenant.applicationID, "environment": "development",
		"identity_provider": "mock_oidc", "identity_token": identityToken,
		"platform": "react_native_ios", "sdk_version": "1.0.0",
	})
	if err != nil {
		return err
	}
	if err := requireStatus(challengeResponse, http.StatusCreated); err != nil {
		return fmt.Errorf("challenge: %w: %s", err, strings.TrimSpace(challengeResponse.Body.String()))
	}
	var challenge challengeDocument
	if err := decodeJSON(challengeResponse, &challenge); err != nil {
		return err
	}
	if challenge.ChallengeID == "" || challenge.Attestation.Provider != "debug" ||
		challenge.Attestation.Mode != "required" || challenge.Attestation.ClientDataHash == "" {
		return errors.New("session challenge did not bind OIDC and debug attestation")
	}
	bindingBytes, err := base64.RawURLEncoding.Strict().DecodeString(challenge.Attestation.ClientDataHash)
	if err != nil || len(bindingBytes) != sha256.Size {
		return errors.New("session challenge returned an invalid attestation binding")
	}
	var bindingHash [sha256.Size]byte
	copy(bindingHash[:], bindingBytes)
	expiresAt := f.now.Add(10 * time.Minute).Unix()
	debugSignature := ed25519.Sign(f.debugKey, attestation.DebugSigningMessage(bindingHash, expiresAt))
	exchangeTarget, err := parseURL(publicOrigin + "/client/v1/sessions")
	if err != nil {
		return err
	}
	exchangeProof, err := signDPoP(f.dpopKey, http.MethodPost, exchangeTarget, f.now, "exchange", "")
	if err != nil {
		return err
	}
	exchangeResponse, err := postJSON(f.clientHandler, "/client/v1/sessions", exchangeProof, map[string]any{
		"challenge_id": challenge.ChallengeID,
		"attestation": map[string]any{
			"provider": "debug", "evidence": map[string]any{
				"key_id": debugKeyID, "binding_hash": challenge.Attestation.ClientDataHash,
				"expires_at": expiresAt,
				"signature":  base64.RawURLEncoding.EncodeToString(debugSignature),
			},
		},
		"installation": map[string]any{"app_version": "1.0.0"},
	})
	if err != nil {
		return err
	}
	if err := requireStatus(exchangeResponse, http.StatusCreated); err != nil {
		return fmt.Errorf("exchange: %w: %s", err, strings.TrimSpace(exchangeResponse.Body.String()))
	}
	var grant grantDocument
	if err := decodeJSON(exchangeResponse, &grant); err != nil {
		return err
	}
	if grant.TokenType != "DPoP" || grant.Installation.ID == "" ||
		grant.Installation.DPoPJKT != f.dpopJKT || grant.Installation.Platform != "react_native_ios" ||
		grant.Trust.Provider != "debug" || grant.Trust.Level != "debug" || len(grant.AccessToken) < 64 {
		return errors.New("session grant is not P-256 DPoP and debug-attestation bound")
	}
	f.accessToken = grant.AccessToken
	f.installationID = grant.Installation.ID
	if err := f.pool.QueryRow(ctx, `
		SELECT g.session_grant_id, i.application_user_id
		FROM session_grants AS g
		JOIN installations AS i USING (installation_id)
		WHERE g.installation_id = $1 AND g.revoked_at IS NULL
	`, f.installationID).Scan(&f.sessionGrantID, &f.applicationUserID); err != nil {
		return err
	}
	if f.oidc.requestCount() < 2 {
		return errors.New("mock OIDC discovery and JWKS endpoints were not both used")
	}
	return nil
}

func decodeUsageBody(response *httptest.ResponseRecorder) error {
	var document struct {
		Usage struct {
			PromptTokens int64 `json:"prompt_tokens"`
			OutputTokens int64 `json:"completion_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := decodeJSON(response, &document); err != nil {
		return err
	}
	if document.Usage.PromptTokens != 11 || document.Usage.OutputTokens != 7 || document.Usage.TotalTokens != 18 {
		return errors.New("mock provider usage was not relayed exactly")
	}
	return nil
}

func containsFinalSSEUsage(response *httptest.ResponseRecorder) bool {
	body := response.Body.String()
	return response.Header().Get("Content-Type") == "text/event-stream" &&
		strings.Contains(body, "\ndata: [DONE]\n\n") && strings.Contains(body, `"usage"`) &&
		strings.Contains(body, `"prompt_tokens":11`) && strings.Contains(body, `"completion_tokens":7`)
}
