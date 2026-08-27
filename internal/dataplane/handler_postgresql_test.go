package dataplane

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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/conformance/mockupstream"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	dataPlaneE2EOrigin              = "https://gateway.example.test"
	dataPlaneE2EAudience            = "latchway-data-plane"
	dataPlaneE2EIdentityIssuer      = "https://identity.example.test"
	dataPlaneE2EIdentityAudience    = "latchway-client"
	dataPlaneE2EConfiguredUpstream  = "https://api.example.test/v1"
	dataPlaneE2EProviderSecret      = "fixture-provider-credential-value-01"
	dataPlaneE2EPromptMarker        = "prompt-marker-dataplane-e2e-01"
	dataPlaneE2EStreamPromptMarker  = "prompt-marker-dataplane-e2e-stream-01"
	dataPlaneE2EProviderModel       = "configured-chat-model"
	dataPlaneE2EPricingCatalog      = "configured_flat_rate"
	dataPlaneE2ECalculatedCost      = int64(65_236)
	dataPlaneE2EClientRequestID     = "client-request-dataplane-e2e-01"
	dataPlaneE2EStreamRequestID     = "client-request-dataplane-e2e-stream-01"
	dataPlaneE2EDeniedRequestID     = "client-request-dataplane-e2e-denied-01"
	dataPlaneE2EDebugAttestationKey = "dataplane-debug-key-01"
	dataPlaneE2EUntrustedHost       = "untrusted-inbound.example.test"
)

var dataPlaneE2ESchemaPattern = regexp.MustCompile(`^latchway_dataplane_e2e_test_[0-9]+$`)

// TestAuthenticatedChatCompletionsPostgreSQL exercises the first complete
// authenticated data-plane vertical against isolated migrated PostgreSQL.
// The only private-network exception is the test-owned TargetFactory below;
// the durable configuration remains valid production-shaped state.
func TestAuthenticatedChatCompletionsPostgreSQL(t *testing.T) {
	pool, ctx := isolatedDataPlaneE2EPool(t)
	requireDataPlaneE2EStableUTCWindow(t, ctx, pool)
	now := time.Now().UTC().Truncate(time.Second)
	tenant, principal := seedDataPlaneE2ETenant(t, ctx, pool, now)

	mock, err := mockupstream.New(mockupstream.DefaultConfig())
	if err != nil {
		t.Fatalf("construct mock upstream: %v", err)
	}
	capture := &dataPlaneE2EProviderCapture{next: mock}
	privateBaseURL := startDataPlaneE2EPrivateServer(t, capture) + "/v1"
	privateTargetAuthority := mustDataPlaneE2EURL(t, privateBaseURL).Host

	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6d}, 32)))
	if err != nil {
		t.Fatalf("construct test envelope: %v", err)
	}
	identityPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate identity signing key: %v", err)
	}
	identityPublicDER, err := x509.MarshalPKIXPublicKey(&identityPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal identity public key: %v", err)
	}
	identityPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: identityPublicDER})
	debugPublicKey, debugPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate debug-attestation key: %v", err)
	}
	debugKeyDocument, err := json.Marshal(map[string]any{
		"version": 1,
		"keys": []any{map[string]any{
			"key_id":     dataPlaneE2EDebugAttestationKey,
			"public_key": base64.RawURLEncoding.EncodeToString(debugPublicKey),
		}},
	})
	if err != nil {
		t.Fatalf("encode debug-attestation keys: %v", err)
	}
	insertDataPlaneE2ESecret(t, ctx, pool, envelope, tenant, principal.AdminUserID,
		"identity-public-key", identityPublicPEM, now.Add(-time.Minute))
	insertDataPlaneE2ESecret(t, ctx, pool, envelope, tenant, principal.AdminUserID,
		"debug-attestation-public-keys", debugKeyDocument, now.Add(-time.Minute))
	insertDataPlaneE2ESecret(t, ctx, pool, envelope, tenant, principal.AdminUserID,
		"provider-credential", []byte(dataPlaneE2EProviderSecret), now.Add(-time.Minute))

	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct configuration store: %v", err)
	}
	revisionID := activateDataPlaneE2EConfiguration(t, ctx, configurationStore, principal, tenant)
	snapshot, err := configurationStore.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: tenant.organizationID,
		ApplicationID:  tenant.applicationID,
		EnvironmentID:  tenant.environmentID,
	})
	if err != nil {
		t.Fatalf("load active immutable snapshot: %v", err)
	}
	if snapshot.PolicyRevision() != revisionID || snapshot.PolicyEnvironment() != tenant.environmentID {
		t.Fatalf("active snapshot identity = %q/%q, want %q/%q",
			snapshot.PolicyRevision(), snapshot.PolicyEnvironment(), revisionID, tenant.environmentID)
	}
	limitPlan, ok := snapshot.LimitPlan("free")
	wantLimitPlan := configuration.LimitPlan{
		ID: "free",
		Limits: []configuration.Limit{
			{
				Metric: quota.LogicalRequestsMetric, Algorithm: quota.CalendarAlgorithm,
				Scope: []string{"user", "feature"}, Window: "1d", Maximum: 2, Hard: true,
			},
			{
				Metric: quota.LogicalRequestsMetric, Algorithm: quota.CalendarAlgorithm,
				Scope: []string{"environment"}, Window: "1mo", Maximum: 3, Hard: true,
			},
			{
				Metric: quota.OutputTokensMetric, Algorithm: quota.CalendarAlgorithm,
				Scope: []string{"user", "model"}, Window: "1d", Maximum: 256, Hard: true,
			},
			{
				Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
				Scope: []string{"user", "model"}, PerRequestMaximum: 64, Hard: true,
			},
		},
	}
	if !ok || !reflect.DeepEqual(limitPlan, wantLimitPlan) {
		t.Fatalf("active multi-rule limit plan = %+v ok=%t", limitPlan, ok)
	}
	pricingCatalog, ok := snapshot.PricingCatalog(dataPlaneE2EPricingCatalog)
	pricingEntry, entryOK := snapshot.PricingEntry(dataPlaneE2EPricingCatalog, "fast")
	if !ok || !entryOK || pricingCatalog.ID != dataPlaneE2EPricingCatalog ||
		pricingCatalog.Currency != quota.USDCurrency || pricingCatalog.EffectiveAt == nil ||
		!pricingCatalog.EffectiveAt.Before(now) || pricingEntry != (configuration.PricingEntry{
		ModelID: "fast", InputNanoUSDPerMillion: 2_000_000_001,
		OutputNanoUSDPerMillion: 6_000_000_001, RequestNanoUSD: 1_234,
	}) {
		t.Fatalf("active configured pricing = catalog:%+v entry:%+v ok=%t/%t",
			pricingCatalog, pricingEntry, ok, entryOK)
	}

	secretStore, err := secrets.NewStore(secrets.StoreConfig{
		Pool: pool, Provider: envelope, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct encrypted secret store: %v", err)
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
	keyManager, err := session.NewSigningKeyManager(session.SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct signing-key manager: %v", err)
	}
	if _, err := keyManager.Active(ctx); err != nil {
		t.Fatalf("initialize signing key: %v", err)
	}
	accessIssuer, err := session.NewAccessTokenIssuer(session.AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: dataPlaneE2EOrigin, Audience: dataPlaneE2EAudience,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	accessVerifier, err := session.NewAccessTokenVerifier(session.AccessTokenVerifierConfig{
		Keys: keyManager, Issuer: dataPlaneE2EOrigin, Audience: dataPlaneE2EAudience,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token verifier: %v", err)
	}
	sessionStore, err := session.NewStore(session.StoreConfig{
		Pool: pool, AccessTokens: accessIssuer, Configuration: configurationStore,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct session store: %v", err)
	}
	coordinator, err := session.NewClientCoordinator(session.ClientCoordinatorConfig{
		Pool: pool, Configuration: configurationStore, Users: userStore,
		Sessions: sessionStore, AccessTokens: accessVerifier,
		Secrets: secretStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct client coordinator: %v", err)
	}
	publicKeys, err := session.NewClientJWKSProvider(keyManager)
	if err != nil {
		t.Fatalf("construct client JWKS provider: %v", err)
	}
	clientAPI, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, JWKS: publicKeys, PublicOrigin: dataPlaneE2EOrigin,
	})
	if err != nil {
		t.Fatalf("construct client HTTP API: %v", err)
	}
	clientHandler := withDataPlaneE2ERequestIdentity(t, clientAPI.Handler())

	identityToken := signDataPlaneE2EIdentityToken(t, identityPrivateKey, now)
	dpopPrivateKey, dpopJKT := newDataPlaneE2EDPoPKey(t)
	challengeTarget := mustDataPlaneE2EURL(t, dataPlaneE2EOrigin+"/client/v1/session-challenges")
	challengeProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, challengeTarget,
		now, "dataplane-e2e-challenge", "")
	var challenge dataPlaneE2EChallengeDocument
	postDataPlaneE2EJSON(t, clientHandler, "/client/v1/session-challenges", challengeProof, map[string]any{
		"application_id": tenant.applicationID, "environment": "development",
		"identity_provider": "custom", "identity_token": identityToken,
		"platform": "ios", "sdk_version": "1.2.3",
	}, http.StatusCreated, &challenge)
	if id.Validate(challenge.ChallengeID, id.SessionChallenge) != nil ||
		challenge.Attestation.Provider != "debug" || challenge.Attestation.Mode != "required" {
		t.Fatal("client challenge did not preserve custom identity and debug-attestation policy")
	}
	bindingBytes, err := base64.RawURLEncoding.Strict().DecodeString(challenge.Attestation.ClientDataHash)
	if err != nil || len(bindingBytes) != sha256.Size {
		t.Fatal("challenge returned a malformed attestation binding")
	}
	var bindingHash [sha256.Size]byte
	copy(bindingHash[:], bindingBytes)
	attestationExpiresAt := now.Add(10 * time.Minute).Unix()
	debugSignature := ed25519.Sign(debugPrivateKey,
		attestation.DebugSigningMessage(bindingHash, attestationExpiresAt))
	exchangeTarget := mustDataPlaneE2EURL(t, dataPlaneE2EOrigin+"/client/v1/sessions")
	exchangeProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, exchangeTarget,
		now, "dataplane-e2e-exchange", "")
	var grant dataPlaneE2EGrantDocument
	postDataPlaneE2EJSON(t, clientHandler, "/client/v1/sessions", exchangeProof, map[string]any{
		"challenge_id": challenge.ChallengeID,
		"attestation": map[string]any{
			"provider": "debug",
			"evidence": map[string]any{
				"key_id":       dataPlaneE2EDebugAttestationKey,
				"binding_hash": challenge.Attestation.ClientDataHash,
				"expires_at":   attestationExpiresAt,
				"signature":    base64.RawURLEncoding.EncodeToString(debugSignature),
			},
		},
		"installation": map[string]any{"app_version": "1.0.0"},
	}, http.StatusCreated, &grant)
	if grant.TokenType != "DPoP" || grant.Installation.DPoPJKT != dpopJKT ||
		grant.Installation.Platform != "ios" || grant.Trust.Provider != "debug" ||
		grant.Trust.Level != "debug" || len(grant.AccessToken) < 64 {
		t.Fatal("debug-attested session grant violated the client contract")
	}

	resolver, err := policy.NewResolver()
	if err != nil {
		t.Fatalf("construct policy resolver: %v", err)
	}
	policyEngine, err := NewPolicyEngine(resolver)
	if err != nil {
		t.Fatalf("construct data-plane policy engine: %v", err)
	}
	quotaStore, err := quota.NewStore(quota.StoreConfig{Pool: pool})
	if err != nil {
		t.Fatalf("construct quota store: %v", err)
	}
	replayingQuotaStore := &dataPlaneE2EReplayingQuotaStore{Store: quotaStore}
	targets := &dataPlaneE2EPrivateTargetFactory{
		configuredBaseURL: dataPlaneE2EConfiguredUpstream,
		privateBaseURL:    privateBaseURL,
	}
	dataPlaneHandler, err := New(Config{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: configurationStore, Policies: policyEngine,
		Quotas: replayingQuotaStore, Secrets: secretStore, Targets: targets,
		PublicOrigin: dataPlaneE2EOrigin,
	})
	if err != nil {
		t.Fatalf("construct data-plane handler: %v", err)
	}
	t.Cleanup(func() { _ = dataPlaneHandler.Close() })
	protectedHandler := withDataPlaneE2ERequestIdentity(t, dataPlaneHandler.Handler())
	dataTarget := mustDataPlaneE2EURL(t, dataPlaneE2EOrigin+chatCompletionsPath)
	accessProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-chat", grant.AccessToken)

	chatBody := map[string]any{
		"model":                 "untrusted-client-model",
		"messages":              []any{map[string]any{"role": "user", "content": dataPlaneE2EPromptMarker}},
		"max_completion_tokens": 9999,
	}
	chatResponse := postDataPlaneE2EChat(t, protectedHandler, grant.AccessToken, accessProof,
		dataPlaneE2EClientRequestID, chatBody)
	if chatResponse.Code != http.StatusOK {
		providerRequests, captureErr := capture.snapshot()
		var logicalStatus, attemptStatus, failureCode string
		_ = pool.QueryRow(ctx, `
			SELECT request.status, COALESCE(attempt.status, ''), COALESCE(attempt.failure_code, '')
			FROM logical_requests AS request
			LEFT JOIN upstream_attempts AS attempt USING (logical_request_id)
			WHERE request.client_request_id = $1
		`, dataPlaneE2EClientRequestID).Scan(&logicalStatus, &attemptStatus, &failureCode)
		t.Logf("safe failure state: target acquisitions/releases=%d/%d provider requests=%d capture_error=%v mock_observations=%+v logical/attempt/failure=%s/%s/%s",
			targets.acquisitions.Load(), targets.releases.Load(), len(providerRequests), captureErr,
			mock.Observations(), logicalStatus, attemptStatus, failureCode)
		t.Fatalf("authenticated chat status = %d, body = %s", chatResponse.Code, chatResponse.Body.String())
	}
	var chatDocument struct {
		ID      string `json:"id"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Index        int    `json:"index"`
			Message      struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(chatResponse.Body).Decode(&chatDocument); err != nil {
		t.Fatalf("decode chat response: %v", err)
	}
	if chatDocument.ID != "chatcmpl_mock_0001" || chatDocument.Usage.PromptTokens != 11 ||
		chatDocument.Usage.CompletionTokens != 7 || chatDocument.Usage.TotalTokens != 18 {
		t.Fatalf("unexpected deterministic chat response: %+v", chatDocument)
	}
	if len(chatDocument.Choices) != 1 || chatDocument.Choices[0].Index != 0 ||
		chatDocument.Choices[0].FinishReason != "stop" || chatDocument.Choices[0].Message.Role != "assistant" ||
		chatDocument.Choices[0].Message.Content != "Deterministic mock response." {
		t.Fatalf("relayed assistant choice did not preserve the deterministic provider response: %+v", chatDocument.Choices)
	}

	providerRequests, captureErr := capture.snapshot()
	if captureErr != nil {
		t.Fatalf("capture provider request: %v", captureErr)
	}
	if len(providerRequests) != 1 {
		t.Fatalf("provider dispatches = %d, want 1", len(providerRequests))
	}
	if replayingQuotaStore.successfulReplays.Load() != 1 {
		t.Fatalf("exact durable reservation replays = %d, want 1",
			replayingQuotaStore.successfulReplays.Load())
	}
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[0], privateTargetAuthority,
		dataPlaneE2EPromptMarker, false)

	observations := mock.Observations()
	if len(observations) != 1 || observations[0].Method != http.MethodPost ||
		observations[0].Path != "/v1/chat/completions" || observations[0].StatusCode != http.StatusOK ||
		observations[0].RequestBytes == 0 || !observations[0].ResponseStarted {
		t.Fatalf("mock-upstream observations = %+v", observations)
	}
	firstLogicalID := assertDataPlaneE2EPersistence(
		t, ctx, pool, dataPlaneE2EClientRequestID, 1, revisionID,
	)
	firstQuotaState := readDataPlaneE2EQuotaBuckets(t, ctx, pool)
	assertDataPlaneE2EQuotaBuckets(t, firstQuotaState, 1)
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 1, reservations: 1, reservationEntries: 3,
		buckets: 3, attempts: 1, usageRecords: 5,
	})
	assertDataPlaneE2EMarkersNotPersisted(t, ctx, pool,
		dataPlaneE2EProviderSecret, dataPlaneE2EPromptMarker, "Deterministic mock response.")

	// This HTTP replay deliberately reuses the DPoP proof and must fail during
	// session authorization. Exact quota-store replay is exercised separately by
	// replayingQuotaStore during the first accepted request above.
	replayResponse := postDataPlaneE2EChat(t, protectedHandler, grant.AccessToken, accessProof,
		dataPlaneE2EClientRequestID, chatBody)
	assertDataPlaneE2EProblem(t, replayResponse, http.StatusUnauthorized, "dpop_replayed")
	if targets.acquisitions.Load() != 1 || targets.releases.Load() != 1 || len(mock.Observations()) != 1 {
		t.Fatalf("replayed DPoP proof reached dispatch: acquisitions=%d releases=%d observations=%d",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EPersistence(t, ctx, pool, dataPlaneE2EClientRequestID, 1, revisionID)
	if replayQuotaState := readDataPlaneE2EQuotaBuckets(t, ctx, pool); !reflect.DeepEqual(replayQuotaState, firstQuotaState) {
		t.Fatalf("replayed DPoP proof changed quota state: before=%+v after=%+v",
			firstQuotaState, replayQuotaState)
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 1, reservations: 1, reservationEntries: 3,
		buckets: 3, attempts: 1, usageRecords: 5,
	})

	streamProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-chat-stream", grant.AccessToken)
	streamBody := map[string]any{
		"model":                 "untrusted-client-stream-model",
		"messages":              []any{map[string]any{"role": "user", "content": dataPlaneE2EStreamPromptMarker}},
		"max_completion_tokens": 9999,
		"stream":                true,
	}
	streamResponse := postDataPlaneE2EChat(t, protectedHandler, grant.AccessToken, streamProof,
		dataPlaneE2EStreamRequestID, streamBody)
	assertDataPlaneE2EChatStream(t, streamResponse)

	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil {
		t.Fatalf("capture streaming provider request: %v", captureErr)
	}
	if len(providerRequests) != 2 {
		t.Fatalf("provider dispatches after stream = %d, want 2", len(providerRequests))
	}
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[1], privateTargetAuthority,
		dataPlaneE2EStreamPromptMarker, true)
	if targets.acquisitions.Load() != 2 || targets.releases.Load() != 2 {
		t.Fatalf("streaming target acquisitions/releases = %d/%d, want 2/2",
			targets.acquisitions.Load(), targets.releases.Load())
	}
	observations = mock.Observations()
	if len(observations) != 2 || observations[1].Method != http.MethodPost ||
		observations[1].Path != "/v1/chat/completions" || observations[1].StatusCode != http.StatusOK ||
		observations[1].RequestBytes == 0 || !observations[1].ResponseStarted || observations[1].Canceled {
		t.Fatalf("streaming mock-upstream observations = %+v", observations)
	}
	secondLogicalID := assertDataPlaneE2EPersistence(
		t, ctx, pool, dataPlaneE2EStreamRequestID, 2, revisionID,
	)
	if firstLogicalID == secondLogicalID {
		t.Fatalf("streaming request reused non-streaming logical request identity %q", firstLogicalID)
	}
	assertDataPlaneE2EPersistence(t, ctx, pool, dataPlaneE2EClientRequestID, 2, revisionID)
	quotaStateBeforeDenial := readDataPlaneE2EQuotaBuckets(t, ctx, pool)
	assertDataPlaneE2EQuotaBuckets(t, quotaStateBeforeDenial, 2)
	assertDataPlaneE2EOnlyDailyRequestLimitExhausted(t, quotaStateBeforeDenial)
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 2, reservations: 2, reservationEntries: 6,
		buckets: 3, attempts: 2, usageRecords: 10,
	})

	deniedProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-chat-denied", grant.AccessToken)
	deniedResponse := postDataPlaneE2EChat(t, protectedHandler, grant.AccessToken, deniedProof,
		dataPlaneE2EDeniedRequestID, chatBody)
	assertDataPlaneE2EProblem(t, deniedResponse, http.StatusTooManyRequests, "quota_exceeded")
	if retryAfter, err := strconv.Atoi(deniedResponse.Header().Get("Retry-After")); err != nil || retryAfter < 1 {
		t.Fatalf("quota denial Retry-After = %q, want positive seconds", deniedResponse.Header().Get("Retry-After"))
	}
	if targets.acquisitions.Load() != 2 || targets.releases.Load() != 2 || len(mock.Observations()) != 2 {
		t.Fatalf("atomically denied request reached dispatch: acquisitions=%d releases=%d observations=%d",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 2 {
		t.Fatalf("provider capture after atomic denial = requests:%d err:%v, want two prior dispatches",
			len(providerRequests), captureErr)
	}
	quotaStateAfterDenial := readDataPlaneE2EQuotaBuckets(t, ctx, pool)
	if !reflect.DeepEqual(quotaStateAfterDenial, quotaStateBeforeDenial) {
		t.Fatalf("denied multi-rule reservation partially consumed quota: before=%+v after=%+v",
			quotaStateBeforeDenial, quotaStateAfterDenial)
	}
	assertDataPlaneE2EQuotaBuckets(t, quotaStateAfterDenial, 2)
	assertDataPlaneE2EDenialPersistence(t, ctx, pool, dataPlaneE2EDeniedRequestID)
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 3, reservations: 2, reservationEntries: 6,
		buckets: 3, attempts: 2, usageRecords: 10, deniedRequests: 1,
	})
	assertDataPlaneE2EMarkersNotPersisted(t, ctx, pool,
		dataPlaneE2EProviderSecret,
		dataPlaneE2EPromptMarker,
		dataPlaneE2EStreamPromptMarker,
		"Deterministic mock response.",
		"Deterministic ",
		"mock response.",
	)
}

type dataPlaneE2ETenant struct {
	organizationID string
	applicationID  string
	environmentID  string
}

func isolatedDataPlaneE2EPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_dataplane_e2e_test_%d", time.Now().UnixNano())
	if !dataPlaneE2ESchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create data-plane test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop isolated data-plane test schema: %v", err)
		}
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsedURL.String(), 12)
	if err != nil {
		t.Fatalf("open isolated data-plane database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, ctx
}

func requireDataPlaneE2EStableUTCWindow(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var databaseNow time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		t.Fatalf("read PostgreSQL clock for calendar-window guard: %v", err)
	}
	databaseNow = databaseNow.UTC()
	nextMidnight := time.Date(
		databaseNow.Year(), databaseNow.Month(), databaseNow.Day()+1,
		0, 0, 0, 0, time.UTC,
	)
	if remaining := nextMidnight.Sub(databaseNow); remaining <= 5*time.Minute {
		t.Skipf("authenticated quota vertical needs one stable UTC day; next boundary is in %s", remaining)
	}
}

func seedDataPlaneE2ETenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, now time.Time) (dataPlaneE2ETenant, adminauth.Principal) {
	t.Helper()
	tenant := dataPlaneE2ETenant{
		organizationID: mustDataPlaneE2EID(t, id.Organization),
		applicationID:  mustDataPlaneE2EID(t, id.Application),
		environmentID:  mustDataPlaneE2EID(t, id.Environment),
	}
	adminUserID := mustDataPlaneE2EID(t, id.AdminUser)
	membershipID := mustDataPlaneE2EID(t, id.AdminMembership)
	createdAt := now.Add(-2 * time.Minute)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations (organization_id, slug, display_name, status, created_at, updated_at) VALUES ($1, 'dataplane-test', 'Data Plane Test', 'active', $2, $2)`, []any{tenant.organizationID, createdAt}},
		{`INSERT INTO applications (application_id, organization_id, slug, display_name, status, created_at, updated_at) VALUES ($1, $2, 'chat-app', 'Chat App', 'active', $3, $3)`, []any{tenant.applicationID, tenant.organizationID, createdAt}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, status, created_at, updated_at) VALUES ($1, $2, $3, 'development', 'Development', 'development', 'active', $4, $4)`, []any{tenant.environmentID, tenant.organizationID, tenant.applicationID, createdAt}},
		{`INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name, status, created_at, updated_at) VALUES ($1, 'dataplane@example.test', 'dataplane@example.test', 'Data Plane Test', 'active', $2, $2)`, []any{adminUserID, createdAt}},
		{`INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role, status, created_by_admin_user_id, created_at, updated_at) VALUES ($1, $2, $3, 'owner', 'active', $3, $4, $4)`, []any{membershipID, tenant.organizationID, adminUserID, createdAt}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed data-plane tenant: %v", err)
		}
	}
	return tenant, adminauth.Principal{
		OrganizationID: tenant.organizationID, AdminUserID: adminUserID,
		Role: adminauth.RoleOwner, Method: adminauth.AuthenticationSession,
	}
}

func insertDataPlaneE2ESecret(t *testing.T, ctx context.Context, pool *pgxpool.Pool, provider secrets.Provider, tenant dataPlaneE2ETenant, adminUserID, name string, plaintext []byte, createdAt time.Time) {
	t.Helper()
	recordID := mustDataPlaneE2EID(t, id.SecretRecord)
	encrypted, err := provider.Encrypt(plaintext, secrets.AssociatedData{
		OrganizationID: tenant.organizationID, EnvironmentID: tenant.environmentID,
		SecretID: recordID, SecretVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		t.Fatalf("encrypt %s fixture: %v", name, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO secret_records (
			secret_record_id, organization_id, application_id, environment_id,
			name, version, encryption_format_version, algorithm,
			master_key_identifier, ciphertext, nonce, created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, 1, $6, 'aes-256-gcm', $7, $8, $9, $10, $11)
	`, recordID, tenant.organizationID, tenant.applicationID, tenant.environmentID,
		name, int16(encrypted.FormatVersion), encrypted.KeyID, encrypted.Ciphertext,
		encrypted.Nonce, adminUserID, createdAt); err != nil {
		t.Fatalf("insert encrypted %s fixture: %v", name, err)
	}
}

func activateDataPlaneE2EConfiguration(t *testing.T, ctx context.Context, store *configuration.Store, principal adminauth.Principal, tenant dataPlaneE2ETenant) string {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"apiVersion": "latchway.dev/v1alpha1",
		"kind":       "EnvironmentConfig",
		"metadata": map[string]any{
			"organization": "dataplane-test", "application": "chat-app", "environment": "development",
		},
		"spec": map[string]any{
			"identityProviders": []any{map[string]any{
				"id": "custom", "type": "custom_jwt", "issuer": dataPlaneE2EIdentityIssuer,
				"audiences": []any{dataPlaneE2EIdentityAudience}, "allowedAlgorithms": []any{"RS256"},
				"staticPublicKeySecretRef": "secret/identity-public-key",
				"subjectClaim":             "sub", "clockSkewSeconds": 0,
				"claimMappings": map[string]any{"tier": "claims.tier"},
			}},
			"attestationPolicies": []any{map[string]any{
				"id": "native", "maxAge": "10m",
				"platforms": map[string]any{"ios": map[string]any{
					"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
					"secretRef": "secret/debug-attestation-public-keys",
				}},
			}},
			"upstreams": []any{map[string]any{
				"id": "primary", "type": "openai_compatible", "baseUrl": dataPlaneE2EConfiguredUpstream,
				"authentication": map[string]any{"type": "bearer", "secretRef": "secret/provider-credential"},
				"staticHeaders":  map[string]any{"X-Provider-Tenant": "tenant-e2e"},
				"timeouts":       map[string]any{"connect": "2s", "firstByte": "2s", "idle": "2s", "total": "10s"},
			}},
			"models": []any{map[string]any{
				"id": "fast", "upstream": "primary", "upstreamModel": dataPlaneE2EProviderModel,
				"pricingRef": dataPlaneE2EPricingCatalog, "capabilities": []any{"openai_chat"},
			}},
			"pricingCatalogs": []any{map[string]any{
				"id": dataPlaneE2EPricingCatalog, "currency": quota.USDCurrency,
				"effectiveAt": "2020-01-01T00:00:00Z",
				"entries": []any{map[string]any{
					"model": "fast", "inputNanoUsdPerMillion": int64(2_000_000_001),
					"outputNanoUsdPerMillion": int64(6_000_000_001), "requestNanoUsd": int64(1_234),
				}},
			}},
			"limitPlans": []any{map[string]any{
				"id": "free", "limits": []any{
					map[string]any{
						"metric": "logical_requests", "algorithm": "calendar",
						"scope": []any{"feature", "user"}, "window": "1d", "maximum": 2, "hard": true,
					},
					map[string]any{
						"metric": "logical_requests", "algorithm": "calendar",
						"scope": []any{"environment"}, "window": "1mo", "maximum": 3, "hard": true,
					},
					map[string]any{
						"metric": "output_tokens", "algorithm": "calendar",
						"scope": []any{"model", "user"}, "window": "1d", "maximum": 256, "hard": true,
					},
					map[string]any{
						"metric": "output_tokens", "algorithm": "per_request",
						"scope": []any{"model", "user"}, "perRequestMaximum": 64, "hard": true,
					},
				},
			}},
			"features": []any{map[string]any{
				"id": "assistant", "protocol": "openai_chat", "attestationPolicy": "native",
				"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
				"limitPlan": map[string]any{"expression": "'free'"},
				"output":    map[string]any{"defaultMaximumTokens": 32, "absoluteMaximumTokens": 64},
				"routes": []any{map[string]any{
					"id": "primary", "when": "true", "model": "fast", "priority": 10,
				}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("encode data-plane configuration: %v", err)
	}
	revision, err := store.CreateRevision(ctx, principal, configuration.CreateInput{
		EnvironmentID: tenant.environmentID, Document: document, Description: "data-plane end-to-end",
	})
	if err != nil {
		t.Fatalf("create data-plane revision: %v", err)
	}
	report, err := store.ValidateRevision(ctx, principal, revision.ID)
	if err != nil || !report.Valid {
		t.Fatalf("validate data-plane revision: valid=%t issues=%+v err=%v", report.Valid, report.Issues, err)
	}
	activated, err := store.ActivateRevision(ctx, principal, revision.ID, revision.ETag)
	if err != nil {
		t.Fatalf("activate data-plane revision: %v", err)
	}
	if activated.State != configuration.StateActive || activated.ID != revision.ID {
		t.Fatalf("activated revision = %+v", activated)
	}
	return activated.ID
}

func signDataPlaneE2EIdentityToken(t *testing.T, privateKey *rsa.PrivateKey, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": dataPlaneE2EIdentityIssuer, "aud": dataPlaneE2EIdentityAudience,
		"sub": "external-user-dataplane-01", "tier": "pro",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign custom identity token: %v", err)
	}
	return token
}

func newDataPlaneE2EDPoPKey(t *testing.T) (*ecdsa.PrivateKey, string) {
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
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("compute DPoP thumbprint: %v", err)
	}
	return privateKey, thumbprint
}

func signDataPlaneE2EDPoP(t *testing.T, privateKey *ecdsa.PrivateKey, method string, target *url.URL, now time.Time, label, accessToken string) string {
	t.Helper()
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
	jtiDigest := sha256.Sum256([]byte(label + "\x00" + now.Format(time.RFC3339Nano)))
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jtiDigest[:]),
		"htm": method, "htu": htu, "iat": now.Unix(),
	}
	if accessToken != "" {
		claims["ath"] = dpop.AccessTokenHash(accessToken)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode DPoP claims: %v", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimsSegment := base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimsSegment))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + claimsSegment + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type dataPlaneE2EChallengeDocument struct {
	ChallengeID string `json:"challenge_id"`
	Attestation struct {
		Provider       string `json:"provider"`
		Mode           string `json:"mode"`
		ClientDataHash string `json:"client_data_hash"`
	} `json:"attestation"`
}

type dataPlaneE2EGrantDocument struct {
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

func postDataPlaneE2EJSON(t *testing.T, handler http.Handler, path, proof string, body any, wantStatus int, output any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode client request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	setDataPlaneE2EProtectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("client %s status = %d, want %d, body = %s", path, response.Code, wantStatus, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("client %s omitted protected response headers", path)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatalf("decode client %s response: %v", path, err)
	}
}

func setDataPlaneE2EProtectedHeaders(request *http.Request, proof string) {
	request.Host = dataPlaneE2EUntrustedHost
	request.Header.Set("Forwarded", "host=untrusted-forwarded.example.test;proto=http")
	request.Header.Set("X-Forwarded-Host", "untrusted-forwarded.example.test")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "ios")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("DPoP", proof)
}

func postDataPlaneE2EChat(t *testing.T, handler http.Handler, accessToken, proof, clientRequestID string, body any) *dataPlaneE2EResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode chat request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, chatCompletionsPath, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	setDataPlaneE2EProtectedHeaders(request, proof)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	request.Header.Set("X-Latchway-Feature", "assistant")
	request.Header.Set("X-Latchway-Request-ID", clientRequestID)
	request.Header.Set("Cookie", "client-cookie=must-not-cross")
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	request.Header.Set(mockupstream.ScenarioHeader, string(mockupstream.ScenarioHTTP500))
	request.Header.Set("X-Untrusted-Provider-Header", "must-not-cross")
	response := &dataPlaneE2EResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(response, request)
	return response
}

func assertDataPlaneE2EProviderChatRequest(
	t *testing.T,
	request dataPlaneE2EProviderRequest,
	targetAuthority, prompt string,
	wantStream bool,
) {
	t.Helper()
	if request.method != http.MethodPost || request.path != "/v1/chat/completions" ||
		request.host != targetAuthority || request.host == dataPlaneE2EUntrustedHost {
		t.Fatalf("provider route authority was not target-bound: method=%s path=%s host_matches_target=%t retained_untrusted_host=%t",
			request.method, request.path, request.host == targetAuthority, request.host == dataPlaneE2EUntrustedHost)
	}
	if request.authorization != "Bearer "+dataPlaneE2EProviderSecret || request.staticTenant != "tenant-e2e" {
		t.Fatal("server-held provider credential or static header was not applied")
	}
	for _, forbidden := range []string{
		"DPoP", "Cookie", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
		"X-Forwarded-Proto", "X-Latchway-Feature", "X-Latchway-Protocol-Version",
		"X-Latchway-Request-ID", "X-Latchway-SDK", "X-Latchway-SDK-Version",
		mockupstream.ScenarioHeader, "X-Untrusted-Provider-Header",
	} {
		if values := request.headers.Values(forbidden); len(values) != 0 {
			t.Fatalf("provider request retained forbidden client header %q", forbidden)
		}
	}

	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(request.body))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		t.Fatalf("decode rewritten provider request: %v", err)
	}
	if err := requireDataPlaneE2EJSONEOF(decoder); err != nil {
		t.Fatalf("rewritten provider request was not one exact JSON value: %v", err)
	}
	if body["model"] != dataPlaneE2EProviderModel {
		t.Fatalf("physical model = %#v, want %q", body["model"], dataPlaneE2EProviderModel)
	}
	limit, ok := body["max_completion_tokens"].(json.Number)
	if !ok || limit.String() != "64" {
		t.Fatalf("provider output clamp = %#v, want 64", body["max_completion_tokens"])
	}
	if _, exists := body["max_tokens"]; exists {
		t.Fatal("provider request retained an ambiguous legacy output limit")
	}
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) != 1 {
		t.Fatalf("provider messages = %#v, want exactly one message", body["messages"])
	}
	message, ok := messages[0].(map[string]any)
	if !ok || len(message) != 2 || message["role"] != "user" || message["content"] != prompt {
		t.Fatalf("provider message did not preserve the exact client prompt: %#v", messages[0])
	}
	stream, hasStream := body["stream"]
	options, hasOptions := body["stream_options"]
	if !wantStream {
		if hasStream || hasOptions || len(body) != 3 {
			t.Fatalf("non-streaming provider request retained streaming fields: stream=%#v options=%#v fields=%d",
				stream, options, len(body))
		}
		return
	}
	if !hasStream || stream != true || !hasOptions || len(body) != 5 {
		t.Fatalf("streaming provider request fields = stream:%#v options:%#v count:%d", stream, options, len(body))
	}
	streamOptions, ok := options.(map[string]any)
	if !ok || len(streamOptions) != 1 || streamOptions["include_usage"] != true {
		t.Fatalf("streaming provider request did not require final usage: %#v", options)
	}
}

func assertDataPlaneE2EChatStream(t *testing.T, response *dataPlaneE2EResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("streaming response status/content-type/cache = %d/%q/%q",
			response.Code, response.Header().Get("Content-Type"), response.Header().Get("Cache-Control"))
	}
	frames := strings.Split(response.Body.String(), "\n\n")
	if len(frames) != 6 || frames[len(frames)-1] != "" {
		t.Fatalf("streaming response frames = %d, want exactly five complete SSE events", len(frames)-1)
	}
	if frames[4] != "data: [DONE]" {
		t.Fatalf("final streaming event = %q, want exact [DONE] sentinel", frames[4])
	}

	base := func(delta map[string]any, finishReason any) map[string]any {
		return map[string]any{
			"choices": []any{map[string]any{
				"delta": delta, "finish_reason": finishReason, "index": json.Number("0"),
			}},
			"created": json.Number("1787820000"),
			"id":      "chatcmpl_mock_0001",
			"model":   "latchway-mock-model",
			"object":  "chat.completion.chunk",
		}
	}
	expected := []map[string]any{
		base(map[string]any{"role": "assistant"}, nil),
		base(map[string]any{"content": "Deterministic "}, nil),
		base(map[string]any{"content": "mock response."}, nil),
		base(map[string]any{}, "stop"),
	}
	expected[3]["usage"] = map[string]any{
		"completion_tokens":        json.Number("7"),
		"prompt_tokens":            json.Number("11"),
		"total_tokens":             json.Number("18"),
		"x_latchway_cost_nano_usd": json.Number("123456"),
	}
	for index, want := range expected {
		if !strings.HasPrefix(frames[index], "data: ") || strings.Contains(frames[index], "\n") {
			t.Fatalf("streaming event %d has invalid SSE framing: %q", index, frames[index])
		}
		var got map[string]any
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(frames[index], "data: ")))
		decoder.UseNumber()
		if err := decoder.Decode(&got); err != nil {
			t.Fatalf("decode streaming event %d: %v", index, err)
		}
		if err := requireDataPlaneE2EJSONEOF(decoder); err != nil {
			t.Fatalf("streaming event %d was not one exact JSON value: %v", index, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("streaming event %d = %#v, want %#v", index, got, want)
		}
	}
}

func requireDataPlaneE2EJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

// RelayResponse applies real net/http write deadlines. ResponseRecorder does
// not expose that optional interface, so this wrapper supplies the same
// successful deadline contract as a live HTTP connection.
type dataPlaneE2EResponseRecorder struct {
	*httptest.ResponseRecorder
}

func (*dataPlaneE2EResponseRecorder) SetWriteDeadline(time.Time) error { return nil }

// dataPlaneE2EReplayingQuotaStore proves that the exact multi-rule reservation
// produced by the handler is idempotent in the real PostgreSQL store. It
// replays only the first accepted reservation; later requests use the delegate
// normally so the test can exercise settlement and atomic denial as well.
type dataPlaneE2EReplayingQuotaStore struct {
	*quota.Store
	replayAttempted   atomic.Bool
	successfulReplays atomic.Int64
}

func (store *dataPlaneE2EReplayingQuotaStore) Reserve(
	ctx context.Context,
	input quota.ReserveInput,
) (quota.Reservation, error) {
	reservation, err := store.Store.Reserve(ctx, input)
	if err != nil || !store.replayAttempted.CompareAndSwap(false, true) {
		return reservation, err
	}
	replayed, err := store.Store.Reserve(ctx, input)
	if err != nil {
		return quota.Reservation{}, fmt.Errorf("replay exact durable reservation: %w", err)
	}
	if replayed.ID() != reservation.ID() ||
		replayed.LogicalRequestID() != reservation.LogicalRequestID() ||
		!replayed.ResetAt().Equal(reservation.ResetAt()) ||
		!replayed.ExpiresAt().Equal(reservation.ExpiresAt()) {
		return quota.Reservation{}, errors.New("exact durable reservation replay returned a different handle")
	}
	store.successfulReplays.Add(1)
	return replayed, nil
}

func withDataPlaneE2ERequestIdentity(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, err := requestidentity.NewContext(request.Context())
		if err != nil {
			t.Errorf("install logical request identity: %v", err)
			http.Error(writer, "request identity unavailable", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

type dataPlaneE2EProviderRequest struct {
	method        string
	path          string
	host          string
	headers       http.Header
	body          []byte
	authorization string
	staticTenant  string
}

type dataPlaneE2EProviderCapture struct {
	next     http.Handler
	mu       sync.Mutex
	requests []dataPlaneE2EProviderRequest
	err      error
}

func (capture *dataPlaneE2EProviderCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		capture.mu.Lock()
		capture.err = err
		capture.mu.Unlock()
		http.Error(writer, "capture failed", http.StatusInternalServerError)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	capture.mu.Lock()
	capture.requests = append(capture.requests, dataPlaneE2EProviderRequest{
		method: request.Method, path: request.URL.Path, host: request.Host, headers: request.Header.Clone(),
		body: append([]byte(nil), body...), authorization: request.Header.Get("Authorization"),
		staticTenant: request.Header.Get("X-Provider-Tenant"),
	})
	capture.mu.Unlock()
	capture.next.ServeHTTP(writer, request)
}

func (capture *dataPlaneE2EProviderCapture) snapshot() ([]dataPlaneE2EProviderRequest, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	result := make([]dataPlaneE2EProviderRequest, len(capture.requests))
	copy(result, capture.requests)
	return result, capture.err
}

func startDataPlaneE2EPrivateServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	privateIP := dataPlaneE2EPrivateIPv4(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(privateIP, "0"))
	if err != nil {
		t.Fatalf("listen for private mock upstream: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case serveErr := <-serveErrors:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("private mock upstream shutdown: %v", serveErr)
			}
		case <-time.After(time.Second):
			t.Error("private mock upstream did not stop")
		}
	})
	return "http://" + net.JoinHostPort(privateIP, strconv.Itoa(port))
}

func dataPlaneE2EPrivateIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("enumerate private interfaces: %v", err)
	}
	for _, candidate := range addresses {
		host, _, splitErr := net.ParseCIDR(candidate.String())
		if splitErr != nil || host == nil || host.To4() == nil || host.IsLoopback() || !host.IsPrivate() {
			continue
		}
		return host.String()
	}
	t.Skip("no non-loopback private IPv4 address is available for the protected-target conformance test")
	return ""
}

type dataPlaneE2EPrivateTargetFactory struct {
	configuredBaseURL string
	privateBaseURL    string
	acquisitions      atomic.Int64
	releases          atomic.Int64
}

func (factory *dataPlaneE2EPrivateTargetFactory) Acquire(config configuration.Upstream) (TargetLease, error) {
	if factory == nil || config.ID != "primary" || config.Type != "openai_compatible" ||
		config.BaseURL != factory.configuredBaseURL || config.Authentication.Type != "bearer" ||
		config.Authentication.SecretRef != "secret/provider-credential" || factory.privateBaseURL == "" {
		return nil, errTargetConfiguration
	}
	target, err := upstream.NewTarget(factory.privateBaseURL, upstream.DestinationPolicy{AllowPrivate: true}, upstream.Timeouts{
		Connect: config.Timeouts.Connect, TLSHandshake: config.Timeouts.Connect,
		ResponseHeader: config.Timeouts.FirstByte, IdleConnection: config.Timeouts.Idle,
	}, nil)
	if err != nil {
		return nil, err
	}
	factory.acquisitions.Add(1)
	return &dataPlaneE2EPrivateTargetLease{
		protectedDispatchTarget: &protectedDispatchTarget{target: target},
		onRelease:               func() { factory.releases.Add(1) },
	}, nil
}

type dataPlaneE2EPrivateTargetLease struct {
	*protectedDispatchTarget
	released  atomic.Bool
	onRelease func()
}

func (lease *dataPlaneE2EPrivateTargetLease) Release() {
	if lease == nil || !lease.released.CompareAndSwap(false, true) {
		return
	}
	lease.CloseIdleConnections()
	if lease.onRelease != nil {
		lease.onRelease()
	}
}

func assertDataPlaneE2EPersistence(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID string,
	expectedSuccessfulRequests int64,
	priceRevision string,
) string {
	t.Helper()
	var logicalID, logicalStatus, reservationStatus, attemptID, attemptStatus, physicalModel string
	var currency, persistedPriceRevision, pricingSource, costConfidence string
	var billedCost int64
	var httpStatus int
	var firstByte bool
	var reservations, attempts, usageRecords int64
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, reservation.status,
		       attempt.upstream_attempt_id, attempt.status,
		       attempt.http_status, attempt.physical_model,
		       attempt.billed_cost_nano_usd, attempt.currency,
		       attempt.price_revision, attempt.pricing_source, attempt.cost_confidence,
		       attempt.first_byte_at IS NOT NULL,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &logicalStatus, &reservationStatus, &attemptID,
		&attemptStatus, &httpStatus, &physicalModel,
		&billedCost, &currency, &persistedPriceRevision, &pricingSource, &costConfidence, &firstByte,
		&reservations, &attempts, &usageRecords,
	)
	if err != nil {
		t.Fatalf("read persisted data-plane lifecycle: %v", err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil || id.Validate(attemptID, id.UpstreamAttempt) != nil ||
		logicalStatus != "succeeded" ||
		reservationStatus != "settled" || attemptStatus != quota.AttemptSucceeded ||
		httpStatus != http.StatusOK || physicalModel != dataPlaneE2EProviderModel || !firstByte ||
		billedCost != dataPlaneE2ECalculatedCost || currency != quota.USDCurrency ||
		persistedPriceRevision != priceRevision || pricingSource != dataPlaneE2EPricingCatalog ||
		costConfidence != quota.CalculatedCostConfidence ||
		reservations != 1 || attempts != 1 || usageRecords != 5 {
		t.Fatalf("persisted lifecycle request=%q/%s reservation=%s/count=%d attempt=%q/%s/%d/%s/count=%d price=%d/%s/%s/%s/%s first_byte=%t usage_count=%d",
			logicalID, logicalStatus, reservationStatus, reservations,
			attemptID, attemptStatus, httpStatus, physicalModel, attempts,
			billedCost, currency, persistedPriceRevision, pricingSource, costConfidence,
			firstByte, usageRecords)
	}
	assertDataPlaneE2EUsage(t, ctx, pool, logicalID, attemptID, priceRevision)

	rows, err := pool.Query(ctx, `
		SELECT entry.quota_reservation_entry_id, bucket.quota_bucket_id,
		       bucket.limit_plan_key, bucket.metric, bucket.scope_type,
		       bucket.scope_dimensions, bucket.algorithm, bucket.window_key,
		       bucket.hard_maximum, bucket.used_units, bucket.reserved_units,
		       entry.reserved_units, entry.settled_units, entry.released_units
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE request.client_request_id = $1
		ORDER BY bucket.quota_bucket_id COLLATE "C"
	`, clientRequestID)
	if err != nil {
		t.Fatalf("read persisted data-plane quota entries: %v", err)
	}
	defer rows.Close()
	seenBuckets := make(map[string]struct{}, 2)
	entryCount := 0
	for rows.Next() {
		var entryID, bucketID, limitPlanKey, bucketMetric, scopeType, algorithm, windowKey string
		var scopeDimensions []string
		var hardMaximum, used, reserved, entryReserved, settled, released int64
		if err := rows.Scan(
			&entryID, &bucketID, &limitPlanKey, &bucketMetric, &scopeType,
			&scopeDimensions, &algorithm, &windowKey,
			&hardMaximum, &used, &reserved, &entryReserved, &settled, &released,
		); err != nil {
			t.Fatalf("scan persisted data-plane quota entry: %v", err)
		}
		expected, ok := dataPlaneE2EExpectedLimit(bucketMetric, scopeDimensions, expectedSuccessfulRequests)
		if id.Validate(entryID, id.QuotaEntry) != nil || id.Validate(bucketID, id.QuotaBucket) != nil ||
			limitPlanKey != "free" || algorithm != quota.CalendarAlgorithm || !ok ||
			scopeType != expected.scopeType ||
			!strings.HasPrefix(windowKey, "utc:v1:"+expected.window+":") ||
			hardMaximum != expected.maximum || used != expected.used || reserved != 0 ||
			entryReserved != expected.entryReserved || settled != expected.entrySettled ||
			released != expected.entryReleased {
			t.Fatalf("persisted quota entry=%q bucket=%q plan=%q metric=%q scope=%q/%v algorithm=%q window=%q maximum=%d occupancy=%d/%d entry=%d/%d/%d",
				entryID, bucketID, limitPlanKey, bucketMetric, scopeType, scopeDimensions,
				algorithm, windowKey, hardMaximum, used, reserved, entryReserved, settled, released)
		}
		if _, duplicate := seenBuckets[bucketID]; duplicate {
			t.Fatalf("successful request linked duplicate quota bucket %q", bucketID)
		}
		seenBuckets[bucketID] = struct{}{}
		entryCount++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate persisted data-plane quota entries: %v", err)
	}
	if entryCount != 3 {
		t.Fatalf("persisted quota entries = %d, want two logical calendars plus one output calendar", entryCount)
	}
	return logicalID
}

func assertDataPlaneE2EUsage(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logicalID, attemptID string,
	priceRevision string,
) {
	t.Helper()
	type expectedUsage struct {
		units         int64
		confidence    string
		provenance    string
		attemptScoped bool
		costed        bool
	}
	expected := map[string]expectedUsage{
		quota.LogicalRequestsMetric: {
			units: 1, confidence: "calculated",
			provenance: "logical-request:" + logicalID,
		},
		"input_tokens": {
			units: 11, confidence: "reported",
			provenance:    quota.ProviderReportedProvenance + ":" + attemptID + ":input_tokens",
			attemptScoped: true,
		},
		quota.OutputTokensMetric: {
			units: 7, confidence: "reported",
			provenance:    quota.ProviderReportedProvenance + ":" + attemptID + ":" + quota.OutputTokensMetric,
			attemptScoped: true,
		},
		"total_tokens": {
			units: 18, confidence: "reported",
			provenance:    quota.ProviderReportedProvenance + ":" + attemptID + ":total_tokens",
			attemptScoped: true,
		},
		quota.CostNanoUSDMetric: {
			units: dataPlaneE2ECalculatedCost, confidence: quota.CalculatedCostConfidence,
			provenance:    "configured_flat_rate:" + attemptID,
			attemptScoped: true,
			costed:        true,
		},
	}
	rows, err := pool.Query(ctx, `
		SELECT usage_record_id, upstream_attempt_id, metric, units,
		       cost_nano_usd, currency, price_revision, pricing_source,
		       confidence, provenance_key
		FROM usage_records
		WHERE logical_request_id = $1
		ORDER BY provenance_key COLLATE "C"
	`, logicalID)
	if err != nil {
		t.Fatalf("read persisted data-plane usage: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var usageID, metric, confidence, provenance string
		var usageAttemptID *string
		var costNanoUSD *int64
		var currency, persistedPriceRevision, pricingSource *string
		var units int64
		if err := rows.Scan(
			&usageID, &usageAttemptID, &metric, &units,
			&costNanoUSD, &currency, &persistedPriceRevision, &pricingSource,
			&confidence, &provenance,
		); err != nil {
			t.Fatalf("scan persisted data-plane usage: %v", err)
		}
		want, ok := expected[metric]
		attemptMatches := (!want.attemptScoped && usageAttemptID == nil) ||
			(want.attemptScoped && usageAttemptID != nil && *usageAttemptID == attemptID)
		costMatches := !want.costed && costNanoUSD == nil && currency == nil &&
			persistedPriceRevision == nil && pricingSource == nil
		if want.costed {
			costMatches = costNanoUSD != nil && *costNanoUSD == dataPlaneE2ECalculatedCost &&
				currency != nil && *currency == quota.USDCurrency &&
				persistedPriceRevision != nil && *persistedPriceRevision == priceRevision &&
				pricingSource != nil && *pricingSource == dataPlaneE2EPricingCatalog
		}
		if id.Validate(usageID, id.UsageRecord) != nil || !ok || !attemptMatches ||
			!costMatches || units != want.units || confidence != want.confidence || provenance != want.provenance {
			t.Fatalf("persisted usage id=%q attempt=%v metric=%q units=%d cost=%v/%v/%v/%v confidence=%q provenance=%q",
				usageID, usageAttemptID, metric, units, costNanoUSD, currency,
				persistedPriceRevision, pricingSource, confidence, provenance)
		}
		if _, duplicate := seen[metric]; duplicate {
			t.Fatalf("persisted usage repeated metric %q", metric)
		}
		seen[metric] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate persisted data-plane usage: %v", err)
	}
	if len(seen) != len(expected) {
		t.Fatalf("persisted usage metrics = %v, want logical/input/output/total/configured-cost", seen)
	}
}

type dataPlaneE2EExpectedQuotaState struct {
	window        string
	maximum       int64
	scopeType     string
	used          int64
	entryReserved int64
	entrySettled  int64
	entryReleased int64
}

type dataPlaneE2EQuotaBucketState struct {
	bucketID        string
	limitPlanKey    string
	metric          string
	scopeType       string
	scopeDimensions []string
	algorithm       string
	windowKey       string
	hardMaximum     int64
	used            int64
	reserved        int64
	version         int64
}

func readDataPlaneE2EQuotaBuckets(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []dataPlaneE2EQuotaBucketState {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT quota_bucket_id, limit_plan_key, metric, scope_type,
		       scope_dimensions, algorithm, window_key, hard_maximum,
		       used_units, reserved_units, version
		FROM quota_buckets
		ORDER BY quota_bucket_id COLLATE "C"
	`)
	if err != nil {
		t.Fatalf("read durable quota buckets: %v", err)
	}
	defer rows.Close()
	result := make([]dataPlaneE2EQuotaBucketState, 0, 3)
	for rows.Next() {
		var state dataPlaneE2EQuotaBucketState
		if err := rows.Scan(
			&state.bucketID, &state.limitPlanKey, &state.metric, &state.scopeType,
			&state.scopeDimensions, &state.algorithm, &state.windowKey, &state.hardMaximum,
			&state.used, &state.reserved, &state.version,
		); err != nil {
			t.Fatalf("scan durable quota bucket: %v", err)
		}
		state.scopeDimensions = append([]string(nil), state.scopeDimensions...)
		result = append(result, state)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate durable quota buckets: %v", err)
	}
	return result
}

func assertDataPlaneE2EQuotaBuckets(t *testing.T, states []dataPlaneE2EQuotaBucketState, expectedSuccessfulRequests int64) {
	t.Helper()
	if len(states) != 3 {
		t.Fatalf("durable quota buckets = %d, want two logical calendars plus one output calendar: %+v", len(states), states)
	}
	seenRules := make(map[string]struct{}, 3)
	for _, state := range states {
		expected, ok := dataPlaneE2EExpectedLimit(state.metric, state.scopeDimensions, expectedSuccessfulRequests)
		if id.Validate(state.bucketID, id.QuotaBucket) != nil || state.limitPlanKey != "free" ||
			state.algorithm != quota.CalendarAlgorithm || !ok || state.scopeType != expected.scopeType ||
			!strings.HasPrefix(state.windowKey, "utc:v1:"+expected.window+":") ||
			state.hardMaximum != expected.maximum || state.used != expected.used || state.reserved != 0 ||
			state.version != expectedSuccessfulRequests*2 {
			t.Fatalf("durable quota bucket violated multi-rule state: %+v", state)
		}
		ruleKey := state.metric + "\x00" + strings.Join(state.scopeDimensions, "\x00")
		if _, duplicate := seenRules[ruleKey]; duplicate {
			t.Fatalf("durable quota buckets repeated rule %q/%v", state.metric, state.scopeDimensions)
		}
		seenRules[ruleKey] = struct{}{}
	}
}

func dataPlaneE2EExpectedLimit(
	metric string,
	scope []string,
	expectedSuccessfulRequests int64,
) (dataPlaneE2EExpectedQuotaState, bool) {
	switch {
	case metric == quota.LogicalRequestsMetric && reflect.DeepEqual(scope, []string{"user", "feature"}):
		return dataPlaneE2EExpectedQuotaState{
			window: "1d", maximum: 2, scopeType: "composite", used: expectedSuccessfulRequests,
			entryReserved: 1, entrySettled: 1,
		}, true
	case metric == quota.LogicalRequestsMetric && reflect.DeepEqual(scope, []string{"environment"}):
		return dataPlaneE2EExpectedQuotaState{
			window: "1mo", maximum: 3, scopeType: "environment", used: expectedSuccessfulRequests,
			entryReserved: 1, entrySettled: 1,
		}, true
	case metric == quota.OutputTokensMetric && reflect.DeepEqual(scope, []string{"user", "model"}):
		return dataPlaneE2EExpectedQuotaState{
			window: "1d", maximum: 256, scopeType: "composite", used: expectedSuccessfulRequests * 7,
			entryReserved: 64, entrySettled: 7, entryReleased: 57,
		}, true
	default:
		return dataPlaneE2EExpectedQuotaState{}, false
	}
}

func assertDataPlaneE2EOnlyDailyRequestLimitExhausted(t *testing.T, states []dataPlaneE2EQuotaBucketState) {
	t.Helper()
	dailyExhausted := false
	for _, state := range states {
		requestedUnits := int64(1)
		if state.metric == quota.OutputTokensMetric {
			requestedUnits = 64
		}
		wouldExceed := state.hardMaximum-state.used-state.reserved < requestedUnits
		isDailyRequestLimit := state.metric == quota.LogicalRequestsMetric &&
			reflect.DeepEqual(state.scopeDimensions, []string{"user", "feature"})
		if wouldExceed != isDailyRequestLimit {
			t.Fatalf("next reservation eligibility for metric=%q scope=%v occupancy=%d/%d requested=%d would_exceed=%t",
				state.metric, state.scopeDimensions, state.used+state.reserved,
				state.hardMaximum, requestedUnits, wouldExceed)
		}
		dailyExhausted = dailyExhausted || isDailyRequestLimit
	}
	if !dailyExhausted {
		t.Fatal("daily logical-request limit was not present before atomic denial")
	}
}

type dataPlaneE2EDurableCounts struct {
	logicalRequests    int64
	reservations       int64
	reservationEntries int64
	buckets            int64
	attempts           int64
	usageRecords       int64
	deniedRequests     int64
}

func assertDataPlaneE2EDurableCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want dataPlaneE2EDurableCounts) {
	t.Helper()
	var got dataPlaneE2EDurableCounts
	err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM logical_requests),
			(SELECT count(*) FROM quota_reservations),
			(SELECT count(*) FROM quota_reservation_entries),
			(SELECT count(*) FROM quota_buckets),
			(SELECT count(*) FROM upstream_attempts),
			(SELECT count(*) FROM usage_records),
			(SELECT count(*) FROM logical_requests WHERE status = 'denied')
	`).Scan(
		&got.logicalRequests, &got.reservations, &got.reservationEntries,
		&got.buckets, &got.attempts, &got.usageRecords, &got.deniedRequests,
	)
	if err != nil {
		t.Fatalf("count durable data-plane state: %v", err)
	}
	if got != want {
		t.Fatalf("durable data-plane counts = %+v, want %+v", got, want)
	}
}

func assertDataPlaneE2EDenialPersistence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, clientRequestID string) {
	t.Helper()
	var logicalID, status, failureCode string
	var reservations, attempts, usageRecords int64
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, request.failure_code,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(&logicalID, &status, &failureCode, &reservations, &attempts, &usageRecords)
	if err != nil {
		t.Fatalf("read denied data-plane request: %v", err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil || status != "denied" ||
		failureCode != "quota_exceeded" || reservations != 0 || attempts != 0 || usageRecords != 0 {
		t.Fatalf("denied data-plane lifecycle = request:%q status:%q failure:%q reservations:%d attempts:%d usage:%d",
			logicalID, status, failureCode, reservations, attempts, usageRecords)
	}
}

func assertDataPlaneE2EMarkersNotPersisted(t *testing.T, ctx context.Context, pool *pgxpool.Pool, markers ...string) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`)
	if err != nil {
		t.Fatalf("list persisted tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			t.Fatalf("scan persisted table: %v", err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("iterate persisted tables: %v", err)
	}
	rows.Close()
	for _, table := range tables {
		identifier := pgx.Identifier{table}.Sanitize()
		for _, marker := range markers {
			for _, representation := range dataPlaneE2EMarkerRepresentations(marker) {
				var found bool
				query := `SELECT EXISTS (SELECT 1 FROM ` + identifier + ` AS persisted WHERE strpos(to_jsonb(persisted)::text, $1) > 0)`
				if err := pool.QueryRow(ctx, query, representation).Scan(&found); err != nil {
					t.Fatalf("scan %s for protected marker: %v", table, err)
				}
				if found {
					t.Fatalf("protected provider credential or body marker was persisted in %s", table)
				}
			}
		}
	}
}

func dataPlaneE2EMarkerRepresentations(marker string) []string {
	candidates := []string{
		marker,
		hex.EncodeToString([]byte(marker)),
		base64.StdEncoding.EncodeToString([]byte(marker)),
		base64.RawStdEncoding.EncodeToString([]byte(marker)),
		base64.URLEncoding.EncodeToString([]byte(marker)),
		base64.RawURLEncoding.EncodeToString([]byte(marker)),
	}
	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func assertDataPlaneE2EProblem(t *testing.T, response *dataPlaneE2EResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	var document struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode data-plane problem: %v", err)
	}
	if response.Code != wantStatus || document.Code != wantCode {
		t.Fatalf("data-plane problem status/code = %d/%q, want %d/%q",
			response.Code, document.Code, wantStatus, wantCode)
	}
}

func mustDataPlaneE2EID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}

func mustDataPlaneE2EURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse trusted URL: %v", err)
	}
	return parsed
}
