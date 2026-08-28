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
	"slices"
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
	dataPlaneE2EOrigin                                 = "https://gateway.example.test"
	dataPlaneE2EAudience                               = "latchway-data-plane"
	dataPlaneE2EIdentityIssuer                         = "https://identity.example.test"
	dataPlaneE2EIdentityAudience                       = "latchway-client"
	dataPlaneE2EConfiguredUpstream                     = "https://api.example.test/v1"
	dataPlaneE2EProviderSecret                         = "fixture-provider-credential-value-01"
	dataPlaneE2EPromptMarker                           = "prompt-marker-dataplane-e2e-01"
	dataPlaneE2EStreamPromptMarker                     = "prompt-marker-dataplane-e2e-stream-01"
	dataPlaneE2EConcurrencyFeature                     = "stream_guard"
	dataPlaneE2EConcurrencyPlan                        = "stream_guard"
	dataPlaneE2EConcurrencyHold                        = "prompt-marker-dataplane-e2e-concurrency-hold-01"
	dataPlaneE2EConcurrencyDenied                      = "prompt-marker-dataplane-e2e-concurrency-denied-01"
	dataPlaneE2EConcurrencyNonStream                   = "prompt-marker-dataplane-e2e-concurrency-nonstream-01"
	dataPlaneE2EConcurrencyReuse                       = "prompt-marker-dataplane-e2e-concurrency-reuse-01"
	dataPlaneE2EConcurrencyHoldRequestID               = "client-request-dataplane-e2e-concurrency-hold-01"
	dataPlaneE2EConcurrencyDeniedRequestID             = "client-request-dataplane-e2e-concurrency-denied-01"
	dataPlaneE2EConcurrencyNonStreamRequestID          = "client-request-dataplane-e2e-concurrency-nonstream-01"
	dataPlaneE2EConcurrencyReuseRequestID              = "client-request-dataplane-e2e-concurrency-reuse-01"
	dataPlaneE2ETokenBucketFeature                     = "request_pacer"
	dataPlaneE2ETokenBucketPlan                        = "request_pacer"
	dataPlaneE2ETokenBucketFirst                       = "prompt-marker-dataplane-e2e-token-first-01"
	dataPlaneE2ETokenBucketDenied                      = "prompt-marker-dataplane-e2e-token-denied-01"
	dataPlaneE2ETokenBucketThird                       = "prompt-marker-dataplane-e2e-token-third-01"
	dataPlaneE2ETokenBucketFirstRequestID              = "client-request-dataplane-e2e-token-first-01"
	dataPlaneE2ETokenBucketDeniedRequestID             = "client-request-dataplane-e2e-token-denied-01"
	dataPlaneE2ETokenBucketThirdRequestID              = "client-request-dataplane-e2e-token-third-01"
	dataPlaneE2EOutputTokenBucketFeature               = "output_pacer"
	dataPlaneE2EOutputTokenBucketPlan                  = "output_pacer"
	dataPlaneE2EOutputTokenBucketFirst                 = "prompt-marker-dataplane-e2e-output-token-first-01"
	dataPlaneE2EOutputTokenBucketDenied                = "prompt-marker-dataplane-e2e-output-token-denied-01"
	dataPlaneE2EOutputTokenBucketThird                 = "prompt-marker-dataplane-e2e-output-token-third-01"
	dataPlaneE2EOutputTokenBucketFirstRequestID        = "client-request-dataplane-e2e-output-token-first-01"
	dataPlaneE2EOutputTokenBucketDeniedRequestID       = "client-request-dataplane-e2e-output-token-denied-01"
	dataPlaneE2EOutputTokenBucketThirdRequestID        = "client-request-dataplane-e2e-output-token-third-01"
	dataPlaneE2ECostFeature                            = "cost_guard"
	dataPlaneE2ECostPlan                               = "cost_guard"
	dataPlaneE2ECostModel                              = "cost_fast"
	dataPlaneE2ECostPricingCatalog                     = "cost_guard_price"
	dataPlaneE2ECostPrompt                             = "prompt-marker-dataplane-e2e-cost-first-01"
	dataPlaneE2ECostDeniedPrompt                       = "prompt-marker-dataplane-e2e-cost-denied-01"
	dataPlaneE2ECostRequestID                          = "client-request-dataplane-e2e-cost-first-01"
	dataPlaneE2ECostDeniedRequestID                    = "client-request-dataplane-e2e-cost-denied-01"
	dataPlaneE2ECostMaximum                      int64 = 17
	dataPlaneE2ECostReservation                  int64 = 10
	dataPlaneE2EActualCost                       int64 = 9
	dataPlaneE2ETokenBalanceScale                int64 = 1_000_000_000_000
	dataPlaneE2ETokenRefillInterval                    = 100 * time.Second
	dataPlaneE2EOutputTokenRefillInterval              = 700 * time.Second
	dataPlaneE2EProviderModel                          = "configured-chat-model"
	dataPlaneE2EPricingCatalog                         = "configured_flat_rate"
	dataPlaneE2ECalculatedCost                         = int64(43_235)
	dataPlaneE2EClientRequestID                        = "client-request-dataplane-e2e-01"
	dataPlaneE2EStreamRequestID                        = "client-request-dataplane-e2e-stream-01"
	dataPlaneE2EDeniedRequestID                        = "client-request-dataplane-e2e-denied-01"
	dataPlaneE2EDebugAttestationKey                    = "dataplane-debug-key-01"
	dataPlaneE2EUntrustedHost                          = "untrusted-inbound.example.test"
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
	capture := &dataPlaneE2EProviderCapture{
		next: mock, blockPrompt: dataPlaneE2EConcurrencyHold,
		blockStarted: make(chan struct{}), blockRelease: make(chan struct{}),
	}
	privateBaseURL := startDataPlaneE2EPrivateServer(t, capture) + "/v1"
	t.Cleanup(capture.releaseBlock)
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
	concurrencyPlan, ok := snapshot.LimitPlan(dataPlaneE2EConcurrencyPlan)
	wantConcurrencyPlan := configuration.LimitPlan{
		ID: dataPlaneE2EConcurrencyPlan,
		Limits: []configuration.Limit{{
			Metric: quota.ConcurrentStreamsMetric, Algorithm: quota.ConcurrencyAlgorithm,
			Scope: []string{"environment", "feature"}, Maximum: 1, Hard: true,
		}},
	}
	if !ok || !reflect.DeepEqual(concurrencyPlan, wantConcurrencyPlan) {
		t.Fatalf("active concurrency limit plan = %+v ok=%t", concurrencyPlan, ok)
	}
	tokenBucketPlan, ok := snapshot.LimitPlan(dataPlaneE2ETokenBucketPlan)
	wantTokenBucketPlan := configuration.LimitPlan{
		ID: dataPlaneE2ETokenBucketPlan,
		Limits: []configuration.Limit{{
			Metric: quota.LogicalRequestsMetric, Algorithm: quota.TokenBucketAlgorithm,
			Scope: []string{"user", "feature"}, Capacity: 1,
			RefillPerSecond: configuration.RefillRate{Numerator: 1, Denominator: 100}, Hard: true,
		}},
	}
	if !ok || !reflect.DeepEqual(tokenBucketPlan, wantTokenBucketPlan) {
		t.Fatalf("active token-bucket limit plan = %+v ok=%t", tokenBucketPlan, ok)
	}
	outputTokenBucketPlan, ok := snapshot.LimitPlan(dataPlaneE2EOutputTokenBucketPlan)
	wantOutputTokenBucketPlan := configuration.LimitPlan{
		ID: dataPlaneE2EOutputTokenBucketPlan,
		Limits: []configuration.Limit{{
			Metric: quota.OutputTokensMetric, Algorithm: quota.TokenBucketAlgorithm,
			Scope: []string{"user", "feature"}, Capacity: 8,
			RefillPerSecond: configuration.RefillRate{Numerator: 1, Denominator: 100}, Hard: true,
		}},
	}
	if !ok || !reflect.DeepEqual(outputTokenBucketPlan, wantOutputTokenBucketPlan) {
		t.Fatalf("active output-token bucket limit plan = %+v ok=%t", outputTokenBucketPlan, ok)
	}
	costPlan, ok := snapshot.LimitPlan(dataPlaneE2ECostPlan)
	wantCostPlan := configuration.LimitPlan{
		ID: dataPlaneE2ECostPlan,
		Limits: []configuration.Limit{{
			Metric: quota.CostNanoUSDMetric, Algorithm: quota.CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1mo",
			Maximum: dataPlaneE2ECostMaximum, Hard: true,
		}},
	}
	if !ok || !reflect.DeepEqual(costPlan, wantCostPlan) {
		t.Fatalf("active hard-cost limit plan = %+v ok=%t", costPlan, ok)
	}
	pricingCatalog, ok := snapshot.PricingCatalog(dataPlaneE2EPricingCatalog)
	pricingEntry, entryOK := snapshot.PricingEntry(dataPlaneE2EPricingCatalog, "fast")
	if !ok || !entryOK || pricingCatalog.ID != dataPlaneE2EPricingCatalog ||
		pricingCatalog.Currency != quota.USDCurrency || pricingCatalog.EffectiveAt == nil ||
		!pricingCatalog.EffectiveAt.Before(now) || pricingEntry != (configuration.PricingEntry{
		ModelID: "fast", InputNanoUSDPerMillion: 0,
		OutputNanoUSDPerMillion: 6_000_000_001, RequestNanoUSD: 1_234,
	}) {
		t.Fatalf("active configured pricing = catalog:%+v entry:%+v ok=%t/%t",
			pricingCatalog, pricingEntry, ok, entryOK)
	}
	costCatalog, ok := snapshot.PricingCatalog(dataPlaneE2ECostPricingCatalog)
	costEntry, costEntryOK := snapshot.PricingEntry(dataPlaneE2ECostPricingCatalog, dataPlaneE2ECostModel)
	if !ok || !costEntryOK || costCatalog.ID != dataPlaneE2ECostPricingCatalog ||
		costCatalog.Currency != quota.USDCurrency || costCatalog.EffectiveAt == nil ||
		!costCatalog.EffectiveAt.Before(now) || costEntry != (configuration.PricingEntry{
		ModelID: dataPlaneE2ECostModel, InputNanoUSDPerMillion: 0,
		OutputNanoUSDPerMillion: 1_000_000, RequestNanoUSD: 2,
	}) {
		t.Fatalf("active hard-cost pricing = catalog:%+v entry:%+v ok=%t/%t",
			costCatalog, costEntry, ok, costEntryOK)
	}

	secretStore, err := secrets.NewStore(secrets.StoreConfig{Pool: pool, Provider: envelope})
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
	featureQuotas, err := NewFeatureQuotaProvider(FeatureQuotaConfig{
		AccessTokens: accessVerifier, Sessions: sessionStore,
		Configuration: configurationStore, Policies: resolver,
		Quotas: quotaStore, PublicOrigin: dataPlaneE2EOrigin,
	})
	if err != nil {
		t.Fatalf("construct feature quota provider: %v", err)
	}
	clientAPI, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, FeatureQuotas: featureQuotas,
		JWKS: publicKeys, PublicOrigin: dataPlaneE2EOrigin,
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

	concurrencyBody := func(prompt string, streaming bool) map[string]any {
		body := map[string]any{
			"model":                 "untrusted-client-concurrency-model",
			"messages":              []any{map[string]any{"role": "user", "content": prompt}},
			"max_completion_tokens": 9999,
		}
		if streaming {
			body["stream"] = true
		}
		return body
	}
	holdProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-concurrency-hold", grant.AccessToken)
	holdRequest, holdResponse := newDataPlaneE2EChatRequest(
		t, grant.AccessToken, holdProof, dataPlaneE2EConcurrencyFeature,
		dataPlaneE2EConcurrencyHoldRequestID, concurrencyBody(dataPlaneE2EConcurrencyHold, true),
	)
	holdDone := make(chan struct{})
	go func() {
		protectedHandler.ServeHTTP(holdResponse, holdRequest)
		close(holdDone)
	}()
	select {
	case <-capture.blockStarted:
	case <-holdDone:
		t.Fatalf("held streaming dispatch completed before provider release: status=%d body=%s",
			holdResponse.Code, holdResponse.Body.String())
	case <-time.After(10 * time.Second):
		t.Fatal("held streaming dispatch did not reach the provider")
	}
	if targets.acquisitions.Load() != 3 || targets.releases.Load() != 2 ||
		len(mock.Observations()) != 2 {
		t.Fatalf("held stream dispatch state acquisitions/releases/observations=%d/%d/%d, want 3/2/2",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EConcurrencyState(t, ctx, pool, 1, 1, 0)

	concurrencyDeniedProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-concurrency-denied", grant.AccessToken)
	concurrencyDeniedResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, concurrencyDeniedProof,
		dataPlaneE2EConcurrencyFeature, dataPlaneE2EConcurrencyDeniedRequestID,
		concurrencyBody(dataPlaneE2EConcurrencyDenied, true),
	)
	assertDataPlaneE2EConcurrencyProblem(t, concurrencyDeniedResponse, dataPlaneE2EConcurrencyFeature)
	if replayingQuotaStore.concurrencyDenialReplays.Load() != 1 {
		t.Fatalf("exact durable concurrency-denial replays = %d, want 1",
			replayingQuotaStore.concurrencyDenialReplays.Load())
	}
	if targets.acquisitions.Load() != 3 || targets.releases.Load() != 2 ||
		len(mock.Observations()) != 2 {
		t.Fatalf("concurrency denial reached dispatch acquisitions/releases/observations=%d/%d/%d",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EConcurrencyDenialPersistence(
		t, ctx, pool, dataPlaneE2EConcurrencyDeniedRequestID,
	)
	assertDataPlaneE2EConcurrencyState(t, ctx, pool, 1, 1, 0)

	nonStreamProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-concurrency-nonstream", grant.AccessToken)
	nonStreamResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, nonStreamProof,
		dataPlaneE2EConcurrencyFeature, dataPlaneE2EConcurrencyNonStreamRequestID,
		concurrencyBody(dataPlaneE2EConcurrencyNonStream, false),
	)
	if nonStreamResponse.Code != http.StatusOK {
		t.Fatalf("non-stream request under an occupied stream limit = %d, body=%s",
			nonStreamResponse.Code, nonStreamResponse.Body.String())
	}
	if targets.acquisitions.Load() != 4 || targets.releases.Load() != 3 ||
		len(mock.Observations()) != 3 {
		t.Fatalf("non-stream bypass acquisitions/releases/observations=%d/%d/%d, want 4/3/3",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EConcurrencyState(t, ctx, pool, 1, 1, 0)
	assertDataPlaneE2EEntrylessReservation(
		t, ctx, pool, dataPlaneE2EConcurrencyNonStreamRequestID, revisionID,
	)

	capture.releaseBlock()
	select {
	case <-holdDone:
	case <-time.After(10 * time.Second):
		t.Fatal("held streaming dispatch did not complete after provider release")
	}
	assertDataPlaneE2EChatStream(t, holdResponse)
	assertDataPlaneE2EConcurrencyState(t, ctx, pool, 0, 1, 1)

	reuseProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-concurrency-reuse", grant.AccessToken)
	reuseResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, reuseProof,
		dataPlaneE2EConcurrencyFeature, dataPlaneE2EConcurrencyReuseRequestID,
		concurrencyBody(dataPlaneE2EConcurrencyReuse, true),
	)
	assertDataPlaneE2EChatStream(t, reuseResponse)
	if targets.acquisitions.Load() != 5 || targets.releases.Load() != 5 ||
		len(mock.Observations()) != 5 {
		t.Fatalf("immediate concurrency reuse acquisitions/releases/observations=%d/%d/%d, want 5/5/5",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EConcurrencyState(t, ctx, pool, 0, 2, 2)
	assertDataPlaneE2EConcurrencyTerminalLifecycle(t, ctx, pool, revisionID)
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 7, reservations: 5, reservationEntries: 8,
		buckets: 4, attempts: 5, usageRecords: 25, deniedRequests: 2,
	})
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 5 {
		t.Fatalf("provider capture after concurrency proof = requests:%d err:%v, want five dispatches",
			len(providerRequests), captureErr)
	}
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[2], privateTargetAuthority,
		dataPlaneE2EConcurrencyHold, true)
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[3], privateTargetAuthority,
		dataPlaneE2EConcurrencyNonStream, false)
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[4], privateTargetAuthority,
		dataPlaneE2EConcurrencyReuse, true)
	assertDataPlaneE2EMarkersNotPersisted(t, ctx, pool,
		dataPlaneE2EConcurrencyHold,
		dataPlaneE2EConcurrencyDenied,
		dataPlaneE2EConcurrencyNonStream,
		dataPlaneE2EConcurrencyReuse,
	)

	tokenFirstProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-token-first", grant.AccessToken)
	tokenDeniedProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-token-denied", grant.AccessToken)
	tokenThirdProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-token-third", grant.AccessToken)
	tokenFirstResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, tokenFirstProof,
		dataPlaneE2ETokenBucketFeature, dataPlaneE2ETokenBucketFirstRequestID,
		concurrencyBody(dataPlaneE2ETokenBucketFirst, false),
	)
	if tokenFirstResponse.Code != http.StatusOK {
		t.Fatalf("first token-bucket request = %d, body=%s",
			tokenFirstResponse.Code, tokenFirstResponse.Body.String())
	}
	// Keep the denial immediately adjacent to the first settlement. The real
	// PostgreSQL clock remains authoritative, and a 0.01/s bucket needs one
	// hundred full seconds before another whole logical-request token exists.
	tokenDeniedResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, tokenDeniedProof,
		dataPlaneE2ETokenBucketFeature, dataPlaneE2ETokenBucketDeniedRequestID,
		concurrencyBody(dataPlaneE2ETokenBucketDenied, false),
	)
	assertDataPlaneE2EProblem(t, tokenDeniedResponse, http.StatusTooManyRequests, "quota_exceeded")
	if retryAfter, err := strconv.Atoi(tokenDeniedResponse.Header().Get("Retry-After")); err != nil || retryAfter < 1 {
		t.Fatalf("token-bucket Retry-After = %q, want positive seconds",
			tokenDeniedResponse.Header().Get("Retry-After"))
	}
	if replayingQuotaStore.tokenDenialReplays.Load() != 1 {
		t.Fatalf("exact durable token-bucket denial replays = %d, want 1",
			replayingQuotaStore.tokenDenialReplays.Load())
	}
	if targets.acquisitions.Load() != 6 || targets.releases.Load() != 6 ||
		len(mock.Observations()) != 6 {
		t.Fatalf("token-bucket denial reached dispatch acquisitions/releases/observations=%d/%d/%d, want 6/6/6",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 6 {
		t.Fatalf("provider capture after token-bucket denial = requests:%d err:%v, want six dispatches",
			len(providerRequests), captureErr)
	}
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[5], privateTargetAuthority,
		dataPlaneE2ETokenBucketFirst, false)
	assertDataPlaneE2ETokenBucketSuccess(
		t, ctx, pool, dataPlaneE2ETokenBucketFirstRequestID, revisionID,
	)
	assertDataPlaneE2EDenialPersistence(t, ctx, pool, dataPlaneE2ETokenBucketDeniedRequestID)
	tokenStateAfterDenial := readDataPlaneE2ETokenBucketState(t, ctx, pool)
	assertDataPlaneE2ETokenBucketMetadata(t, tokenStateAfterDenial)
	if tokenStateAfterDenial.available < 0 ||
		tokenStateAfterDenial.available >= dataPlaneE2ETokenBalanceScale ||
		tokenStateAfterDenial.version != 2 {
		t.Fatalf("depleted token-bucket state after denial = %+v", tokenStateAfterDenial)
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 9, reservations: 6, reservationEntries: 9,
		buckets: 5, attempts: 6, usageRecords: 30, deniedRequests: 3,
	})

	backdatedTokenState := backdateDataPlaneE2ETokenBucket(t, ctx, pool, tokenStateAfterDenial)
	if !backdatedTokenState.refilledAt.Equal(tokenStateAfterDenial.refilledAt.Add(-dataPlaneE2ETokenRefillInterval)) {
		t.Fatalf("token-bucket refill cursor = %s, want exactly 100 seconds before %s",
			backdatedTokenState.refilledAt, tokenStateAfterDenial.refilledAt)
	}
	tokenThirdResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, tokenThirdProof,
		dataPlaneE2ETokenBucketFeature, dataPlaneE2ETokenBucketThirdRequestID,
		concurrencyBody(dataPlaneE2ETokenBucketThird, false),
	)
	if tokenThirdResponse.Code != http.StatusOK {
		t.Fatalf("refilled token-bucket request = %d, body=%s",
			tokenThirdResponse.Code, tokenThirdResponse.Body.String())
	}
	if targets.acquisitions.Load() != 7 || targets.releases.Load() != 7 ||
		len(mock.Observations()) != 7 {
		t.Fatalf("refilled token-bucket dispatch acquisitions/releases/observations=%d/%d/%d, want 7/7/7",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2ETokenBucketSuccess(
		t, ctx, pool, dataPlaneE2ETokenBucketThirdRequestID, revisionID,
	)
	finalTokenState := readDataPlaneE2ETokenBucketState(t, ctx, pool)
	assertDataPlaneE2ETokenBucketMetadata(t, finalTokenState)
	if finalTokenState.available != 0 || finalTokenState.version != 3 ||
		finalTokenState.refilledAt.Before(tokenStateAfterDenial.refilledAt) {
		t.Fatalf("token-bucket final balance/version/cursor = %d/%d/%s, want 0/3/not before %s",
			finalTokenState.available, finalTokenState.version, finalTokenState.refilledAt,
			tokenStateAfterDenial.refilledAt)
	}
	if replayingQuotaStore.tokenResetChecks.Load() != 2 {
		t.Fatalf("token-only zero-reset reservations = %d, want 2",
			replayingQuotaStore.tokenResetChecks.Load())
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 10, reservations: 7, reservationEntries: 10,
		buckets: 5, attempts: 7, usageRecords: 35, deniedRequests: 3,
	})
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 7 {
		t.Fatalf("provider capture after token-bucket refill = requests:%d err:%v, want seven dispatches",
			len(providerRequests), captureErr)
	}
	assertDataPlaneE2EProviderChatRequest(t, providerRequests[6], privateTargetAuthority,
		dataPlaneE2ETokenBucketThird, false)
	assertDataPlaneE2EMarkersNotPersisted(t, ctx, pool,
		dataPlaneE2ETokenBucketFirst,
		dataPlaneE2ETokenBucketDenied,
		dataPlaneE2ETokenBucketThird,
	)

	outputTokenFirstProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-output-token-first", grant.AccessToken)
	outputTokenDeniedProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-output-token-denied", grant.AccessToken)
	outputTokenThirdProof := signDataPlaneE2EDPoP(t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-output-token-third", grant.AccessToken)
	outputTokenFirstResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, outputTokenFirstProof,
		dataPlaneE2EOutputTokenBucketFeature, dataPlaneE2EOutputTokenBucketFirstRequestID,
		concurrencyBody(dataPlaneE2EOutputTokenBucketFirst, false),
	)
	if outputTokenFirstResponse.Code != http.StatusOK {
		t.Fatalf("first output-token bucket request = %d, body=%s",
			outputTokenFirstResponse.Code, outputTokenFirstResponse.Body.String())
	}
	if targets.acquisitions.Load() != 8 || targets.releases.Load() != 8 ||
		len(mock.Observations()) != 8 {
		t.Fatalf("first output-token dispatch acquisitions/releases/observations=%d/%d/%d, want 8/8/8",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 8 {
		t.Fatalf("provider capture after first output-token request = requests:%d err:%v, want eight dispatches",
			len(providerRequests), captureErr)
	}
	assertDataPlaneE2EProviderChatRequestWithOutputCap(
		t, providerRequests[7], privateTargetAuthority, dataPlaneE2EOutputTokenBucketFirst, false, 8,
	)
	assertDataPlaneE2EOutputTokenBucketSuccess(
		t, ctx, pool, dataPlaneE2EOutputTokenBucketFirstRequestID, revisionID,
	)
	outputStateAfterFirst := readDataPlaneE2EOutputTokenBucketState(t, ctx, pool)
	assertDataPlaneE2EOutputTokenBucketMetadata(t, outputStateAfterFirst)
	if outputStateAfterFirst.available != dataPlaneE2ETokenBalanceScale ||
		outputStateAfterFirst.version != 2 {
		t.Fatalf("settled output-token balance/version = %d/%d, want %d/2",
			outputStateAfterFirst.available, outputStateAfterFirst.version, dataPlaneE2ETokenBalanceScale)
	}

	outputTokenDeniedResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, outputTokenDeniedProof,
		dataPlaneE2EOutputTokenBucketFeature, dataPlaneE2EOutputTokenBucketDeniedRequestID,
		concurrencyBody(dataPlaneE2EOutputTokenBucketDenied, false),
	)
	assertDataPlaneE2EProblem(t, outputTokenDeniedResponse, http.StatusTooManyRequests, "quota_exceeded")
	if retryAfter, err := strconv.Atoi(outputTokenDeniedResponse.Header().Get("Retry-After")); err != nil || retryAfter < 1 {
		t.Fatalf("output-token bucket Retry-After = %q, want positive seconds",
			outputTokenDeniedResponse.Header().Get("Retry-After"))
	}
	if replayingQuotaStore.outputTokenDenialReplays.Load() != 1 {
		t.Fatalf("exact durable output-token denial replays = %d, want 1",
			replayingQuotaStore.outputTokenDenialReplays.Load())
	}
	if targets.acquisitions.Load() != 8 || targets.releases.Load() != 8 ||
		len(mock.Observations()) != 8 {
		t.Fatalf("output-token denial reached dispatch acquisitions/releases/observations=%d/%d/%d, want 8/8/8",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EDenialPersistence(t, ctx, pool, dataPlaneE2EOutputTokenBucketDeniedRequestID)
	outputStateAfterDenial := readDataPlaneE2EOutputTokenBucketState(t, ctx, pool)
	assertDataPlaneE2EOutputTokenBucketMetadata(t, outputStateAfterDenial)
	if outputStateAfterDenial.available < dataPlaneE2ETokenBalanceScale ||
		outputStateAfterDenial.available >= 2*dataPlaneE2ETokenBalanceScale ||
		outputStateAfterDenial.version != 3 {
		t.Fatalf("depleted output-token state after denial = %+v", outputStateAfterDenial)
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 12, reservations: 8, reservationEntries: 11,
		buckets: 6, attempts: 8, usageRecords: 40, deniedRequests: 4,
	})

	backdatedOutputState := backdateDataPlaneE2EOutputTokenBucket(t, ctx, pool, outputStateAfterDenial)
	if !backdatedOutputState.refilledAt.Equal(
		outputStateAfterDenial.refilledAt.Add(-dataPlaneE2EOutputTokenRefillInterval),
	) {
		t.Fatalf("output-token refill cursor = %s, want exactly 700 seconds before %s",
			backdatedOutputState.refilledAt, outputStateAfterDenial.refilledAt)
	}
	outputTokenThirdResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, outputTokenThirdProof,
		dataPlaneE2EOutputTokenBucketFeature, dataPlaneE2EOutputTokenBucketThirdRequestID,
		concurrencyBody(dataPlaneE2EOutputTokenBucketThird, false),
	)
	if outputTokenThirdResponse.Code != http.StatusOK {
		t.Fatalf("refilled output-token bucket request = %d, body=%s",
			outputTokenThirdResponse.Code, outputTokenThirdResponse.Body.String())
	}
	if targets.acquisitions.Load() != 9 || targets.releases.Load() != 9 ||
		len(mock.Observations()) != 9 {
		t.Fatalf("refilled output-token dispatch acquisitions/releases/observations=%d/%d/%d, want 9/9/9",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EOutputTokenBucketSuccess(
		t, ctx, pool, dataPlaneE2EOutputTokenBucketThirdRequestID, revisionID,
	)
	finalOutputState := readDataPlaneE2EOutputTokenBucketState(t, ctx, pool)
	assertDataPlaneE2EOutputTokenBucketMetadata(t, finalOutputState)
	if finalOutputState.available != dataPlaneE2ETokenBalanceScale || finalOutputState.version != 5 ||
		finalOutputState.refilledAt.Before(outputStateAfterDenial.refilledAt) {
		t.Fatalf("output-token final balance/version/cursor = %d/%d/%s, want %d/5/not before %s",
			finalOutputState.available, finalOutputState.version, finalOutputState.refilledAt,
			dataPlaneE2ETokenBalanceScale, outputStateAfterDenial.refilledAt)
	}
	if replayingQuotaStore.outputTokenResetChecks.Load() != 2 {
		t.Fatalf("output-token-only zero-reset reservations = %d, want 2",
			replayingQuotaStore.outputTokenResetChecks.Load())
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 13, reservations: 9, reservationEntries: 12,
		buckets: 6, attempts: 9, usageRecords: 45, deniedRequests: 4,
	})
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 9 {
		t.Fatalf("provider capture after output-token refill = requests:%d err:%v, want nine dispatches",
			len(providerRequests), captureErr)
	}
	assertDataPlaneE2EProviderChatRequestWithOutputCap(
		t, providerRequests[8], privateTargetAuthority, dataPlaneE2EOutputTokenBucketThird, false, 8,
	)
	assertDataPlaneE2EMarkersNotPersisted(t, ctx, pool,
		dataPlaneE2EOutputTokenBucketFirst,
		dataPlaneE2EOutputTokenBucketDenied,
		dataPlaneE2EOutputTokenBucketThird,
	)

	quotaPath := "/client/v1/features/" + dataPlaneE2EOutputTokenBucketFeature + "/quota"
	quotaTarget := mustDataPlaneE2EURL(t, dataPlaneE2EOrigin+quotaPath)
	quotaProof := signDataPlaneE2EDPoP(
		t, dpopPrivateKey, http.MethodGet, quotaTarget,
		now, "dataplane-e2e-output-token-quota", grant.AccessToken,
	)
	baselineReplays := countDataPlaneE2EDPoPReplays(t, ctx, pool)
	invalidQuotaResponse := getDataPlaneE2EFeatureQuota(
		t, clientHandler, grant.AccessToken, quotaProof, quotaPath+"?untrusted=1",
	)
	assertDataPlaneE2EClientProblem(
		t, invalidQuotaResponse, http.StatusBadRequest, "request_invalid",
	)
	if got := countDataPlaneE2EDPoPReplays(t, ctx, pool); got != baselineReplays {
		t.Fatalf("query rejection consumed DPoP proof: replay rows=%d, want %d", got, baselineReplays)
	}

	quotaStateBeforeRead := readDataPlaneE2EOutputTokenBucketState(t, ctx, pool)
	quotaResponse := getDataPlaneE2EFeatureQuota(
		t, clientHandler, grant.AccessToken, quotaProof, quotaPath,
	)
	if quotaResponse.Code != http.StatusOK ||
		quotaResponse.Header().Get("Content-Type") != "application/json" ||
		quotaResponse.Header().Get("Cache-Control") != "no-store" ||
		quotaResponse.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("feature quota response status=%d headers=%#v body=%s",
			quotaResponse.Code, quotaResponse.Header(), quotaResponse.Body.String())
	}
	var quotaDocument dataPlaneE2EQuotaDocument
	if err := json.NewDecoder(quotaResponse.Body).Decode(&quotaDocument); err != nil {
		t.Fatalf("decode feature quota response: %v", err)
	}
	if quotaDocument.Feature != dataPlaneE2EOutputTokenBucketFeature ||
		quotaDocument.ObservedAt.IsZero() || quotaDocument.ObservedAt.Location() != time.UTC ||
		len(quotaDocument.Limits) != 1 {
		t.Fatalf("feature quota envelope = %+v", quotaDocument)
	}
	limit := quotaDocument.Limits[0]
	if limit.Metric != quota.OutputTokensMetric || !limit.Hard ||
		limit.Maximum == nil || *limit.Maximum != 8 ||
		limit.Used == nil || *limit.Used != 7 ||
		limit.Reserved == nil || *limit.Reserved != 0 ||
		limit.Remaining == nil || *limit.Remaining != 1 || limit.ResetsAt != nil {
		t.Fatalf("feature quota token limit = %+v", limit)
	}
	quotaStateAfterRead := readDataPlaneE2EOutputTokenBucketState(t, ctx, pool)
	if !reflect.DeepEqual(quotaStateAfterRead, quotaStateBeforeRead) {
		t.Fatalf("feature quota read mutated bucket\nbefore=%+v\nafter=%+v",
			quotaStateBeforeRead, quotaStateAfterRead)
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 13, reservations: 9, reservationEntries: 12,
		buckets: 6, attempts: 9, usageRecords: 45, deniedRequests: 4,
	})
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 9 {
		t.Fatalf("feature quota read reached provider: requests=%d err=%v", len(providerRequests), captureErr)
	}
	if got := countDataPlaneE2EDPoPReplays(t, ctx, pool); got != baselineReplays+1 {
		t.Fatalf("authorized quota replay rows=%d, want %d", got, baselineReplays+1)
	}

	replayedQuotaResponse := getDataPlaneE2EFeatureQuota(
		t, clientHandler, grant.AccessToken, quotaProof, quotaPath,
	)
	assertDataPlaneE2EClientProblem(
		t, replayedQuotaResponse, http.StatusUnauthorized, "dpop_replayed",
	)
	if got := countDataPlaneE2EDPoPReplays(t, ctx, pool); got != baselineReplays+1 {
		t.Fatalf("replayed quota proof changed replay rows=%d, want %d", got, baselineReplays+1)
	}

	costFirstProof := signDataPlaneE2EDPoP(
		t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-cost-first", grant.AccessToken,
	)
	costFirstResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, costFirstProof,
		dataPlaneE2ECostFeature, dataPlaneE2ECostRequestID,
		concurrencyBody(dataPlaneE2ECostPrompt, false),
	)
	if costFirstResponse.Code != http.StatusOK {
		t.Fatalf("first hard-cost request = %d, body=%s",
			costFirstResponse.Code, costFirstResponse.Body.String())
	}
	if targets.acquisitions.Load() != 10 || targets.releases.Load() != 10 ||
		len(mock.Observations()) != 10 {
		t.Fatalf("hard-cost success acquisitions/releases/observations=%d/%d/%d, want 10/10/10",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EHardCostSuccess(t, ctx, pool, dataPlaneE2ECostRequestID, revisionID)
	costStateAfterSuccess := readDataPlaneE2ECostBucketState(t, ctx, pool)
	assertDataPlaneE2ECostBucketState(t, costStateAfterSuccess)
	providerRequests, captureErr = capture.snapshot()
	if captureErr != nil || len(providerRequests) != 10 {
		t.Fatalf("hard-cost provider capture = requests:%d err:%v, want ten dispatches",
			len(providerRequests), captureErr)
	}
	assertDataPlaneE2EProviderChatRequestWithOutputCap(
		t, providerRequests[9], privateTargetAuthority, dataPlaneE2ECostPrompt, false, 8,
	)

	costDeniedProof := signDataPlaneE2EDPoP(
		t, dpopPrivateKey, http.MethodPost, dataTarget,
		now, "dataplane-e2e-cost-denied", grant.AccessToken,
	)
	costDeniedResponse := postDataPlaneE2EFeatureChat(
		t, protectedHandler, grant.AccessToken, costDeniedProof,
		dataPlaneE2ECostFeature, dataPlaneE2ECostDeniedRequestID,
		concurrencyBody(dataPlaneE2ECostDeniedPrompt, false),
	)
	assertDataPlaneE2EProblem(t, costDeniedResponse, http.StatusTooManyRequests, "quota_exceeded")
	if targets.acquisitions.Load() != 10 || targets.releases.Load() != 10 ||
		len(mock.Observations()) != 10 {
		t.Fatalf("hard-cost denial reached target/provider: acquisitions=%d releases=%d observations=%d",
			targets.acquisitions.Load(), targets.releases.Load(), len(mock.Observations()))
	}
	assertDataPlaneE2EHardCostDenial(t, ctx, pool, dataPlaneE2ECostDeniedRequestID)
	if costStateAfterDenial := readDataPlaneE2ECostBucketState(t, ctx, pool); !reflect.DeepEqual(
		costStateAfterDenial, costStateAfterSuccess,
	) {
		t.Fatalf("hard-cost denial mutated the accepted bucket\nbefore=%+v\nafter=%+v",
			costStateAfterSuccess, costStateAfterDenial)
	}

	costQuotaPath := "/client/v1/features/" + dataPlaneE2ECostFeature + "/quota"
	costQuotaTarget := mustDataPlaneE2EURL(t, dataPlaneE2EOrigin+costQuotaPath)
	costQuotaProof := signDataPlaneE2EDPoP(
		t, dpopPrivateKey, http.MethodGet, costQuotaTarget,
		now, "dataplane-e2e-cost-quota", grant.AccessToken,
	)
	costQuotaBaselineReplays := countDataPlaneE2EDPoPReplays(t, ctx, pool)
	costQuotaResponse := getDataPlaneE2EFeatureQuota(
		t, clientHandler, grant.AccessToken, costQuotaProof, costQuotaPath,
	)
	if costQuotaResponse.Code != http.StatusOK ||
		costQuotaResponse.Header().Get("Content-Type") != "application/json" ||
		costQuotaResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("hard-cost quota response status=%d headers=%#v body=%s",
			costQuotaResponse.Code, costQuotaResponse.Header(), costQuotaResponse.Body.String())
	}
	var costQuotaDocument dataPlaneE2EQuotaDocument
	if err := json.NewDecoder(costQuotaResponse.Body).Decode(&costQuotaDocument); err != nil {
		t.Fatalf("decode hard-cost quota response: %v", err)
	}
	if costQuotaDocument.Feature != dataPlaneE2ECostFeature ||
		costQuotaDocument.ObservedAt.IsZero() || costQuotaDocument.ObservedAt.Location() != time.UTC ||
		len(costQuotaDocument.Limits) != 1 {
		t.Fatalf("hard-cost quota envelope = %+v", costQuotaDocument)
	}
	costLimit := costQuotaDocument.Limits[0]
	if costLimit.Metric != quota.CostNanoUSDMetric || !costLimit.Hard ||
		costLimit.Maximum == nil || *costLimit.Maximum != dataPlaneE2ECostMaximum ||
		costLimit.Used == nil || *costLimit.Used != dataPlaneE2EActualCost ||
		costLimit.Reserved == nil || *costLimit.Reserved != 0 ||
		costLimit.Remaining == nil || *costLimit.Remaining != dataPlaneE2ECostMaximum-dataPlaneE2EActualCost ||
		costLimit.ResetsAt == nil || !costLimit.ResetsAt.After(costQuotaDocument.ObservedAt) ||
		costLimit.ResetsAt.Location() != time.UTC {
		t.Fatalf("hard-cost quota limit = %+v", costLimit)
	}
	if costStateAfterSnapshot := readDataPlaneE2ECostBucketState(t, ctx, pool); !reflect.DeepEqual(
		costStateAfterSnapshot, costStateAfterSuccess,
	) {
		t.Fatalf("hard-cost quota snapshot mutated the bucket\nbefore=%+v\nafter=%+v",
			costStateAfterSuccess, costStateAfterSnapshot)
	}
	if got := countDataPlaneE2EDPoPReplays(t, ctx, pool); got != costQuotaBaselineReplays+1 {
		t.Fatalf("hard-cost quota replay rows=%d, want %d", got, costQuotaBaselineReplays+1)
	}
	assertDataPlaneE2EDurableCounts(t, ctx, pool, dataPlaneE2EDurableCounts{
		logicalRequests: 15, reservations: 10, reservationEntries: 13,
		buckets: 7, attempts: 10, usageRecords: 50, deniedRequests: 5,
	})
	assertDataPlaneE2EMarkersNotPersisted(t, ctx, pool,
		dataPlaneE2ECostPrompt, dataPlaneE2ECostDeniedPrompt)
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
				"timeouts":       map[string]any{"connect": "2s", "firstByte": "30s", "idle": "2s", "total": "45s"},
			}},
			"models": []any{
				map[string]any{
					"id": "fast", "upstream": "primary", "upstreamModel": dataPlaneE2EProviderModel,
					"pricingRef": dataPlaneE2EPricingCatalog, "capabilities": []any{"openai_chat"},
				},
				map[string]any{
					"id": dataPlaneE2ECostModel, "upstream": "primary", "upstreamModel": dataPlaneE2EProviderModel,
					"pricingRef": dataPlaneE2ECostPricingCatalog, "capabilities": []any{"openai_chat"},
				},
			},
			"pricingCatalogs": []any{
				map[string]any{
					"id": dataPlaneE2EPricingCatalog, "currency": quota.USDCurrency,
					"effectiveAt": "2020-01-01T00:00:00Z",
					// A user override can select the hard-cost plan for any feature
					// in this environment. Every routed OpenAI Chat model must
					// therefore have a conservatively preflightable zero input rate.
					"entries": []any{map[string]any{
						"model": "fast", "inputNanoUsdPerMillion": int64(0),
						"outputNanoUsdPerMillion": int64(6_000_000_001), "requestNanoUsd": int64(1_234),
					}},
				},
				map[string]any{
					"id": dataPlaneE2ECostPricingCatalog, "currency": quota.USDCurrency,
					"effectiveAt": "2020-01-01T00:00:00Z",
					"entries": []any{map[string]any{
						"model": dataPlaneE2ECostModel, "inputNanoUsdPerMillion": int64(0),
						"outputNanoUsdPerMillion": int64(1_000_000), "requestNanoUsd": int64(2),
					}},
				},
			},
			"limitPlans": []any{
				map[string]any{
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
				},
				map[string]any{
					"id": dataPlaneE2EConcurrencyPlan, "limits": []any{map[string]any{
						"metric": quota.ConcurrentStreamsMetric, "algorithm": quota.ConcurrencyAlgorithm,
						"scope": []any{"feature", "environment"}, "maximum": 1, "hard": true,
					}},
				},
				map[string]any{
					"id": dataPlaneE2ETokenBucketPlan, "limits": []any{map[string]any{
						"metric": quota.LogicalRequestsMetric, "algorithm": quota.TokenBucketAlgorithm,
						"scope": []any{"feature", "user"}, "capacity": 1,
						"refillPerSecond": json.Number("0.01"), "hard": true,
					}},
				},
				map[string]any{
					"id": dataPlaneE2EOutputTokenBucketPlan, "limits": []any{map[string]any{
						"metric": quota.OutputTokensMetric, "algorithm": quota.TokenBucketAlgorithm,
						"scope": []any{"feature", "user"}, "capacity": 8,
						"refillPerSecond": json.Number("0.01"), "hard": true,
					}},
				},
				map[string]any{
					"id": dataPlaneE2ECostPlan, "limits": []any{map[string]any{
						"metric": quota.CostNanoUSDMetric, "algorithm": quota.CalendarAlgorithm,
						"scope": []any{"feature", "user"}, "window": "1mo",
						"maximum": dataPlaneE2ECostMaximum, "hard": true,
					}},
				},
			},
			"features": []any{
				map[string]any{
					"id": "assistant", "protocol": "openai_chat", "attestationPolicy": "native",
					"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
					"limitPlan": map[string]any{"expression": "'free'"},
					"output":    map[string]any{"defaultMaximumTokens": 32, "absoluteMaximumTokens": 64},
					"routes": []any{map[string]any{
						"id": "primary", "when": "true", "model": "fast", "priority": 10,
					}},
				},
				map[string]any{
					"id": dataPlaneE2EConcurrencyFeature, "protocol": "openai_chat", "attestationPolicy": "native",
					"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
					"limitPlan": map[string]any{"expression": "'" + dataPlaneE2EConcurrencyPlan + "'"},
					"output":    map[string]any{"defaultMaximumTokens": 32, "absoluteMaximumTokens": 64},
					"routes": []any{map[string]any{
						"id": "primary", "when": "true", "model": "fast", "priority": 10,
					}},
				},
				map[string]any{
					"id": dataPlaneE2ETokenBucketFeature, "protocol": "openai_chat", "attestationPolicy": "native",
					"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
					"limitPlan": map[string]any{"expression": "'" + dataPlaneE2ETokenBucketPlan + "'"},
					"output":    map[string]any{"defaultMaximumTokens": 32, "absoluteMaximumTokens": 64},
					"routes": []any{map[string]any{
						"id": "primary", "when": "true", "model": "fast", "priority": 10,
					}},
				},
				map[string]any{
					"id": dataPlaneE2EOutputTokenBucketFeature, "protocol": "openai_chat", "attestationPolicy": "native",
					"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
					"limitPlan": map[string]any{"expression": "'" + dataPlaneE2EOutputTokenBucketPlan + "'"},
					"output":    map[string]any{"defaultMaximumTokens": 32, "absoluteMaximumTokens": 64},
					"routes": []any{map[string]any{
						"id": "primary", "when": "true", "model": "fast", "priority": 10,
					}},
				},
				map[string]any{
					"id": dataPlaneE2ECostFeature, "protocol": "openai_chat", "attestationPolicy": "native",
					"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
					"limitPlan": map[string]any{"expression": "'" + dataPlaneE2ECostPlan + "'"},
					"output":    map[string]any{"defaultMaximumTokens": 8, "absoluteMaximumTokens": 8},
					"routes": []any{map[string]any{
						"id": "cost_primary", "when": "true", "model": dataPlaneE2ECostModel, "priority": 10,
					}},
				},
			},
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

type dataPlaneE2EQuotaDocument struct {
	Feature    string    `json:"feature"`
	ObservedAt time.Time `json:"observed_at"`
	Limits     []struct {
		Metric    string     `json:"metric"`
		Maximum   *int64     `json:"maximum"`
		Used      *int64     `json:"used"`
		Reserved  *int64     `json:"reserved"`
		Remaining *int64     `json:"remaining"`
		ResetsAt  *time.Time `json:"resets_at"`
		Hard      bool       `json:"hard"`
	} `json:"limits"`
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

func getDataPlaneE2EFeatureQuota(
	t *testing.T,
	handler http.Handler,
	accessToken, proof, path string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	setDataPlaneE2EProtectedHeaders(request, proof)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertDataPlaneE2EClientProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	var document struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode client problem: %v", err)
	}
	if response.Code != wantStatus || document.Code != wantCode ||
		response.Header().Get("Content-Type") != "application/problem+json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Latchway-Request-ID") == "" {
		t.Fatalf("client problem status/code=%d/%q headers=%#v, want %d/%q",
			response.Code, document.Code, response.Header(), wantStatus, wantCode)
	}
}

func countDataPlaneE2EDPoPReplays(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dpop_replay_entries`).Scan(&count); err != nil {
		t.Fatalf("count DPoP replay entries: %v", err)
	}
	return count
}

func postDataPlaneE2EChat(t *testing.T, handler http.Handler, accessToken, proof, clientRequestID string, body any) *dataPlaneE2EResponseRecorder {
	t.Helper()
	request, response := newDataPlaneE2EChatRequest(
		t, accessToken, proof, "assistant", clientRequestID, body,
	)
	handler.ServeHTTP(response, request)
	return response
}

func postDataPlaneE2EFeatureChat(t *testing.T, handler http.Handler, accessToken, proof, feature, clientRequestID string, body any) *dataPlaneE2EResponseRecorder {
	t.Helper()
	request, response := newDataPlaneE2EChatRequest(
		t, accessToken, proof, feature, clientRequestID, body,
	)
	handler.ServeHTTP(response, request)
	return response
}

func newDataPlaneE2EChatRequest(t *testing.T, accessToken, proof, feature, clientRequestID string, body any) (*http.Request, *dataPlaneE2EResponseRecorder) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode chat request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, chatCompletionsPath, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	setDataPlaneE2EProtectedHeaders(request, proof)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	request.Header.Set("X-Latchway-Feature", feature)
	request.Header.Set("X-Latchway-Request-ID", clientRequestID)
	request.Header.Set("Cookie", "client-cookie=must-not-cross")
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	request.Header.Set(mockupstream.ScenarioHeader, string(mockupstream.ScenarioHTTP500))
	request.Header.Set("X-Untrusted-Provider-Header", "must-not-cross")
	response := &dataPlaneE2EResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	return request, response
}

func assertDataPlaneE2EProviderChatRequest(
	t *testing.T,
	request dataPlaneE2EProviderRequest,
	targetAuthority, prompt string,
	wantStream bool,
) {
	t.Helper()
	assertDataPlaneE2EProviderChatRequestWithOutputCap(
		t, request, targetAuthority, prompt, wantStream, 64,
	)
}

func assertDataPlaneE2EProviderChatRequestWithOutputCap(
	t *testing.T,
	request dataPlaneE2EProviderRequest,
	targetAuthority, prompt string,
	wantStream bool,
	wantOutputCap int64,
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
	if !ok || limit.String() != strconv.FormatInt(wantOutputCap, 10) {
		t.Fatalf("provider output clamp = %#v, want %d", body["max_completion_tokens"], wantOutputCap)
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

// dataPlaneE2EReplayingQuotaStore proves that exact accepted and denied
// decisions produced by the handler are idempotent in the real PostgreSQL
// store. Replay gates keep each proof isolated while later requests exercise
// settlement, atomic denial, and token refill normally.
type dataPlaneE2EReplayingQuotaStore struct {
	*quota.Store
	replayAttempted            atomic.Bool
	successfulReplays          atomic.Int64
	concurrencyReplayAttempted atomic.Bool
	concurrencyDenialReplays   atomic.Int64
	tokenDenialReplayAttempted atomic.Bool
	tokenDenialReplays         atomic.Int64
	tokenResetChecks           atomic.Int64
	outputTokenDenialAttempted atomic.Bool
	outputTokenDenialReplays   atomic.Int64
	outputTokenResetChecks     atomic.Int64
}

func (store *dataPlaneE2EReplayingQuotaStore) Reserve(
	ctx context.Context,
	input quota.ReserveInput,
) (quota.Reservation, error) {
	reservation, err := store.Store.Reserve(ctx, input)
	if err != nil {
		if errors.Is(err, quota.ErrExceeded) &&
			input.FeatureKey == dataPlaneE2EOutputTokenBucketFeature &&
			store.outputTokenDenialAttempted.CompareAndSwap(false, true) {
			var denial *quota.ExceededError
			if !errors.As(err, &denial) {
				return quota.Reservation{}, fmt.Errorf("output-token bucket denial type: %w", err)
			}
			_, replayErr := store.Store.Reserve(ctx, input)
			var replayDenial *quota.ExceededError
			if !errors.Is(replayErr, quota.ErrExceeded) || !errors.As(replayErr, &replayDenial) ||
				replayDenial.LogicalRequestID() != denial.LogicalRequestID() ||
				replayDenial.Maximum() != 8 || replayDenial.Reserved() != 0 {
				return quota.Reservation{}, fmt.Errorf(
					"replay exact durable output-token bucket denial: got %v, want matching %w",
					replayErr, quota.ErrExceeded,
				)
			}
			store.outputTokenDenialReplays.Add(1)
			return reservation, err
		}
		if errors.Is(err, quota.ErrExceeded) &&
			input.FeatureKey == dataPlaneE2ETokenBucketFeature &&
			store.tokenDenialReplayAttempted.CompareAndSwap(false, true) {
			var denial *quota.ExceededError
			if !errors.As(err, &denial) {
				return quota.Reservation{}, fmt.Errorf("token-bucket denial type: %w", err)
			}
			_, replayErr := store.Store.Reserve(ctx, input)
			var replayDenial *quota.ExceededError
			if !errors.Is(replayErr, quota.ErrExceeded) || !errors.As(replayErr, &replayDenial) ||
				replayDenial.LogicalRequestID() != denial.LogicalRequestID() ||
				replayDenial.Maximum() != 1 || replayDenial.Reserved() != 0 {
				return quota.Reservation{}, fmt.Errorf(
					"replay exact durable token-bucket denial: got %v, want matching %w",
					replayErr, quota.ErrExceeded,
				)
			}
			store.tokenDenialReplays.Add(1)
			return reservation, err
		}
		if !errors.Is(err, quota.ErrConcurrencyExceeded) ||
			!store.concurrencyReplayAttempted.CompareAndSwap(false, true) {
			return reservation, err
		}
		_, replayErr := store.Store.Reserve(ctx, input)
		if !errors.Is(replayErr, quota.ErrConcurrencyExceeded) {
			return quota.Reservation{}, fmt.Errorf(
				"replay exact durable concurrency denial: got %v, want %w",
				replayErr, quota.ErrConcurrencyExceeded,
			)
		}
		store.concurrencyDenialReplays.Add(1)
		return reservation, err
	}
	if input.FeatureKey == dataPlaneE2EOutputTokenBucketFeature {
		if !reservation.ResetAt().IsZero() {
			return quota.Reservation{}, fmt.Errorf(
				"output-token-only reservation reset = %s, want zero", reservation.ResetAt(),
			)
		}
		store.outputTokenResetChecks.Add(1)
		return reservation, nil
	}
	if input.FeatureKey == dataPlaneE2ETokenBucketFeature {
		if !reservation.ResetAt().IsZero() {
			return quota.Reservation{}, fmt.Errorf(
				"token-only reservation reset = %s, want zero", reservation.ResetAt(),
			)
		}
		store.tokenResetChecks.Add(1)
		return reservation, nil
	}
	if !store.replayAttempted.CompareAndSwap(false, true) {
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
	next         http.Handler
	blockPrompt  string
	blockStarted chan struct{}
	blockRelease chan struct{}
	blockOnce    sync.Once
	releaseOnce  sync.Once
	mu           sync.Mutex
	requests     []dataPlaneE2EProviderRequest
	err          error
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
	if capture.blockPrompt != "" && bytes.Contains(body, []byte(capture.blockPrompt)) {
		capture.blockOnce.Do(func() {
			close(capture.blockStarted)
			<-capture.blockRelease
		})
	}
	capture.next.ServeHTTP(writer, request)
}

func (capture *dataPlaneE2EProviderCapture) releaseBlock() {
	if capture == nil || capture.blockRelease == nil {
		return
	}
	capture.releaseOnce.Do(func() { close(capture.blockRelease) })
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

func assertDataPlaneE2ETokenBucketSuccess(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID, priceRevision string,
) {
	t.Helper()
	var logicalID, logicalStatus, featureKey, configRevision string
	var reservationStatus, attemptID, attemptStatus, physicalModel string
	var currency, persistedPriceRevision, pricingSource, costConfidence string
	var billedCost, reservations, entries, attempts, usageRecords int64
	var httpStatus int
	var firstByte bool
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, request.feature_key,
		       request.config_revision_id, reservation.status,
		       attempt.upstream_attempt_id, attempt.status, attempt.http_status,
		       attempt.physical_model, attempt.billed_cost_nano_usd,
		       attempt.currency, attempt.price_revision, attempt.pricing_source,
		       attempt.cost_confidence, attempt.first_byte_at IS NOT NULL,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM quota_reservation_entries AS counted
		        WHERE counted.quota_reservation_id = reservation.quota_reservation_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &logicalStatus, &featureKey, &configRevision,
		&reservationStatus, &attemptID, &attemptStatus, &httpStatus,
		&physicalModel, &billedCost, &currency, &persistedPriceRevision,
		&pricingSource, &costConfidence, &firstByte,
		&reservations, &entries, &attempts, &usageRecords,
	)
	if err != nil {
		t.Fatalf("read token-bucket success %q: %v", clientRequestID, err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil ||
		id.Validate(attemptID, id.UpstreamAttempt) != nil ||
		logicalStatus != "succeeded" || featureKey != dataPlaneE2ETokenBucketFeature ||
		configRevision != priceRevision || reservationStatus != "settled" ||
		attemptStatus != quota.AttemptSucceeded || httpStatus != http.StatusOK ||
		physicalModel != dataPlaneE2EProviderModel || billedCost != dataPlaneE2ECalculatedCost ||
		currency != quota.USDCurrency || persistedPriceRevision != priceRevision ||
		pricingSource != dataPlaneE2EPricingCatalog || costConfidence != quota.CalculatedCostConfidence ||
		!firstByte || reservations != 1 || entries != 1 || attempts != 1 || usageRecords != 5 {
		t.Fatalf("token-bucket success %q = logical:%q/%s feature/revision:%s/%s reservation:%s/count:%d entries:%d attempt:%q/%s/%d/%s/count:%d price:%d/%s/%s/%s/%s first_byte:%t usage:%d",
			clientRequestID, logicalID, logicalStatus, featureKey, configRevision,
			reservationStatus, reservations, entries, attemptID, attemptStatus,
			httpStatus, physicalModel, attempts, billedCost, currency,
			persistedPriceRevision, pricingSource, costConfidence, firstByte, usageRecords)
	}
	assertDataPlaneE2EUsage(t, ctx, pool, logicalID, attemptID, priceRevision)

	var entryID, bucketID, planKey, metric, algorithm, windowKey string
	var entryReserved, entrySettled, entryReleased int64
	if err := pool.QueryRow(ctx, `
		SELECT entry.quota_reservation_entry_id, bucket.quota_bucket_id,
		       bucket.limit_plan_key, bucket.metric, bucket.algorithm,
		       bucket.window_key, entry.reserved_units,
		       entry.settled_units, entry.released_units
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&entryID, &bucketID, &planKey, &metric, &algorithm, &windowKey,
		&entryReserved, &entrySettled, &entryReleased,
	); err != nil {
		t.Fatalf("read token-bucket entry %q: %v", clientRequestID, err)
	}
	if id.Validate(entryID, id.QuotaEntry) != nil || id.Validate(bucketID, id.QuotaBucket) != nil ||
		planKey != dataPlaneE2ETokenBucketPlan || metric != quota.LogicalRequestsMetric ||
		algorithm != quota.TokenBucketAlgorithm || windowKey != "rolling" ||
		entryReserved != 1 || entrySettled != 1 || entryReleased != 0 {
		t.Fatalf("token-bucket entry %q = entry:%q bucket:%q plan:%q metric:%q algorithm:%q window:%q units:%d/%d/%d",
			clientRequestID, entryID, bucketID, planKey, metric, algorithm,
			windowKey, entryReserved, entrySettled, entryReleased)
	}
}

func assertDataPlaneE2EOutputTokenBucketSuccess(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID, priceRevision string,
) {
	t.Helper()
	var logicalID, logicalStatus, featureKey, configRevision string
	var reservationStatus, attemptID, attemptStatus, physicalModel string
	var currency, persistedPriceRevision, pricingSource, costConfidence string
	var entryID, bucketID, planKey, metric, algorithm, windowKey string
	var billedCost, reservations, entries, attempts, usageRecords int64
	var entryReserved, entrySettled, entryReleased int64
	var httpStatus int
	var firstByte bool
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, request.feature_key,
		       request.config_revision_id, reservation.status,
		       attempt.upstream_attempt_id, attempt.status, attempt.http_status,
		       attempt.physical_model, attempt.billed_cost_nano_usd,
		       attempt.currency, attempt.price_revision, attempt.pricing_source,
		       attempt.cost_confidence, attempt.first_byte_at IS NOT NULL,
		       entry.quota_reservation_entry_id, bucket.quota_bucket_id,
		       bucket.limit_plan_key, bucket.metric, bucket.algorithm,
		       bucket.window_key, entry.reserved_units,
		       entry.settled_units, entry.released_units,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM quota_reservation_entries AS counted
		        WHERE counted.quota_reservation_id = reservation.quota_reservation_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &logicalStatus, &featureKey, &configRevision,
		&reservationStatus, &attemptID, &attemptStatus, &httpStatus,
		&physicalModel, &billedCost, &currency, &persistedPriceRevision,
		&pricingSource, &costConfidence, &firstByte,
		&entryID, &bucketID, &planKey, &metric, &algorithm, &windowKey,
		&entryReserved, &entrySettled, &entryReleased,
		&reservations, &entries, &attempts, &usageRecords,
	)
	if err != nil {
		t.Fatalf("read output-token bucket success %q: %v", clientRequestID, err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil ||
		id.Validate(attemptID, id.UpstreamAttempt) != nil || id.Validate(entryID, id.QuotaEntry) != nil ||
		id.Validate(bucketID, id.QuotaBucket) != nil || logicalStatus != "succeeded" ||
		featureKey != dataPlaneE2EOutputTokenBucketFeature || configRevision != priceRevision ||
		reservationStatus != "settled" || attemptStatus != quota.AttemptSucceeded ||
		httpStatus != http.StatusOK || physicalModel != dataPlaneE2EProviderModel ||
		billedCost != dataPlaneE2ECalculatedCost || currency != quota.USDCurrency ||
		persistedPriceRevision != priceRevision || pricingSource != dataPlaneE2EPricingCatalog ||
		costConfidence != quota.CalculatedCostConfidence || !firstByte ||
		planKey != dataPlaneE2EOutputTokenBucketPlan || metric != quota.OutputTokensMetric ||
		algorithm != quota.TokenBucketAlgorithm || windowKey != "rolling" ||
		entryReserved != 8 || entrySettled != 7 || entryReleased != 1 ||
		reservations != 1 || entries != 1 || attempts != 1 || usageRecords != 5 {
		t.Fatalf("output-token bucket success %q = logical:%q/%s feature/revision:%s/%s reservation:%s/count:%d entries:%d attempt:%q/%s/%d/%s/count:%d price:%d/%s/%s/%s/%s first_byte:%t entry:%q bucket:%q plan/metric/algorithm/window:%s/%s/%s/%s units:%d/%d/%d usage:%d",
			clientRequestID, logicalID, logicalStatus, featureKey, configRevision,
			reservationStatus, reservations, entries, attemptID, attemptStatus,
			httpStatus, physicalModel, attempts, billedCost, currency,
			persistedPriceRevision, pricingSource, costConfidence, firstByte,
			entryID, bucketID, planKey, metric, algorithm, windowKey,
			entryReserved, entrySettled, entryReleased, usageRecords)
	}
	assertDataPlaneE2EUsage(t, ctx, pool, logicalID, attemptID, priceRevision)
}

func assertDataPlaneE2EHardCostSuccess(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID, priceRevision string,
) {
	t.Helper()
	var logicalID, logicalStatus, featureKey, configRevision string
	var reservationStatus, attemptID, attemptStatus, physicalModel string
	var currency, persistedPriceRevision, pricingSource, costConfidence string
	var entryID, bucketID, planKey, metric, algorithm, windowKey string
	var billedCost, reservations, entries, attempts, usageRecords int64
	var entryReserved, entrySettled, entryReleased int64
	var httpStatus int
	var firstByte bool
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, request.feature_key,
		       request.config_revision_id, reservation.status,
		       attempt.upstream_attempt_id, attempt.status, attempt.http_status,
		       attempt.physical_model, attempt.billed_cost_nano_usd,
		       attempt.currency, attempt.price_revision, attempt.pricing_source,
		       attempt.cost_confidence, attempt.first_byte_at IS NOT NULL,
		       entry.quota_reservation_entry_id, bucket.quota_bucket_id,
		       bucket.limit_plan_key, bucket.metric, bucket.algorithm,
		       bucket.window_key, entry.reserved_units,
		       entry.settled_units, entry.released_units,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM quota_reservation_entries AS counted
		        WHERE counted.quota_reservation_id = reservation.quota_reservation_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &logicalStatus, &featureKey, &configRevision,
		&reservationStatus, &attemptID, &attemptStatus, &httpStatus,
		&physicalModel, &billedCost, &currency, &persistedPriceRevision,
		&pricingSource, &costConfidence, &firstByte,
		&entryID, &bucketID, &planKey, &metric, &algorithm, &windowKey,
		&entryReserved, &entrySettled, &entryReleased,
		&reservations, &entries, &attempts, &usageRecords,
	)
	if err != nil {
		t.Fatalf("read hard-cost success %q: %v", clientRequestID, err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil ||
		id.Validate(attemptID, id.UpstreamAttempt) != nil || id.Validate(entryID, id.QuotaEntry) != nil ||
		id.Validate(bucketID, id.QuotaBucket) != nil || logicalStatus != "succeeded" ||
		featureKey != dataPlaneE2ECostFeature || configRevision != priceRevision ||
		reservationStatus != "settled" || attemptStatus != quota.AttemptSucceeded ||
		httpStatus != http.StatusOK || physicalModel != dataPlaneE2EProviderModel ||
		billedCost != dataPlaneE2EActualCost || currency != quota.USDCurrency ||
		persistedPriceRevision != priceRevision || pricingSource != dataPlaneE2ECostPricingCatalog ||
		costConfidence != quota.CalculatedCostConfidence || !firstByte ||
		planKey != dataPlaneE2ECostPlan || metric != quota.CostNanoUSDMetric ||
		algorithm != quota.CalendarAlgorithm || !strings.HasPrefix(windowKey, "utc:v1:1mo:") ||
		entryReserved != dataPlaneE2ECostReservation || entrySettled != dataPlaneE2EActualCost ||
		entryReleased != dataPlaneE2ECostReservation-dataPlaneE2EActualCost ||
		reservations != 1 || entries != 1 || attempts != 1 || usageRecords != 5 {
		t.Fatalf("hard-cost success %q = logical:%q/%s feature/revision:%s/%s reservation:%s/count:%d entries:%d attempt:%q/%s/%d/%s/count:%d price:%d/%s/%s/%s/%s first_byte:%t entry:%q bucket:%q plan/metric/algorithm/window:%s/%s/%s/%s units:%d/%d/%d usage:%d",
			clientRequestID, logicalID, logicalStatus, featureKey, configRevision,
			reservationStatus, reservations, entries, attemptID, attemptStatus,
			httpStatus, physicalModel, attempts, billedCost, currency,
			persistedPriceRevision, pricingSource, costConfidence, firstByte,
			entryID, bucketID, planKey, metric, algorithm, windowKey,
			entryReserved, entrySettled, entryReleased, usageRecords)
	}
	assertDataPlaneE2EPricedUsage(
		t, ctx, pool, logicalID, attemptID, priceRevision,
		dataPlaneE2EActualCost, dataPlaneE2ECostPricingCatalog,
	)
}

func assertDataPlaneE2EHardCostDenial(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID string,
) {
	t.Helper()
	var logicalID, featureKey, status, failureCode string
	var reservations, attempts, usageRecords int64
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.feature_key,
		       request.status, request.failure_code,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &featureKey, &status, &failureCode,
		&reservations, &attempts, &usageRecords,
	)
	if err != nil {
		t.Fatalf("read hard-cost denial %q: %v", clientRequestID, err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil ||
		featureKey != dataPlaneE2ECostFeature || status != "denied" ||
		failureCode != "quota_exceeded" || reservations != 0 || attempts != 0 || usageRecords != 0 {
		t.Fatalf("hard-cost denial %q = request:%q feature:%q status:%q failure:%q reservations:%d attempts:%d usage:%d",
			clientRequestID, logicalID, featureKey, status, failureCode,
			reservations, attempts, usageRecords)
	}
}

func assertDataPlaneE2EUsage(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logicalID, attemptID string,
	priceRevision string,
) {
	t.Helper()
	assertDataPlaneE2EPricedUsage(
		t, ctx, pool, logicalID, attemptID, priceRevision,
		dataPlaneE2ECalculatedCost, dataPlaneE2EPricingCatalog,
	)
}

func assertDataPlaneE2EPricedUsage(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logicalID, attemptID string,
	priceRevision string,
	expectedCost int64,
	expectedPricingSource string,
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
			units: expectedCost, confidence: quota.CalculatedCostConfidence,
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
			costMatches = costNanoUSD != nil && *costNanoUSD == expectedCost &&
				currency != nil && *currency == quota.USDCurrency &&
				persistedPriceRevision != nil && *persistedPriceRevision == priceRevision &&
				pricingSource != nil && *pricingSource == expectedPricingSource
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

type dataPlaneE2ETokenBucketState struct {
	bucketID          string
	limitPlanKey      string
	metric            string
	scopeType         string
	scopeDimensions   []string
	algorithm         string
	windowKey         string
	hardMaximum       int64
	used              int64
	reserved          int64
	available         int64
	refillNumerator   int64
	refillDenominator int64
	refilledAt        time.Time
	version           int64
	createdAt         time.Time
	updatedAt         time.Time
	bucketCount       int64
}

func readDataPlaneE2ETokenBucketState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) dataPlaneE2ETokenBucketState {
	t.Helper()
	return readDataPlaneE2ETokenBucketStateFor(
		t, ctx, pool, dataPlaneE2ETokenBucketPlan, quota.LogicalRequestsMetric,
	)
}

func readDataPlaneE2EOutputTokenBucketState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) dataPlaneE2ETokenBucketState {
	t.Helper()
	return readDataPlaneE2ETokenBucketStateFor(
		t, ctx, pool, dataPlaneE2EOutputTokenBucketPlan, quota.OutputTokensMetric,
	)
}

func readDataPlaneE2ETokenBucketStateFor(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	planKey, metric string,
) dataPlaneE2ETokenBucketState {
	t.Helper()
	var state dataPlaneE2ETokenBucketState
	err := pool.QueryRow(ctx, `
		SELECT quota_bucket_id, limit_plan_key, metric, scope_type,
		       scope_dimensions, algorithm, window_key, hard_maximum,
		       used_units, reserved_units, available_units,
		       refill_numerator, refill_denominator, refilled_at,
		       version, created_at, updated_at, count(*) OVER ()
		FROM quota_buckets
		WHERE limit_plan_key = $1 AND metric = $2 AND algorithm = $3
		  AND window_key = 'rolling'
	`, planKey, metric,
		quota.TokenBucketAlgorithm).Scan(
		&state.bucketID, &state.limitPlanKey, &state.metric, &state.scopeType,
		&state.scopeDimensions, &state.algorithm, &state.windowKey, &state.hardMaximum,
		&state.used, &state.reserved, &state.available,
		&state.refillNumerator, &state.refillDenominator, &state.refilledAt,
		&state.version, &state.createdAt, &state.updatedAt, &state.bucketCount,
	)
	if err != nil {
		t.Fatalf("read token-bucket state: %v", err)
	}
	state.scopeDimensions = append([]string(nil), state.scopeDimensions...)
	return state
}

func assertDataPlaneE2ETokenBucketMetadata(t *testing.T, state dataPlaneE2ETokenBucketState) {
	t.Helper()
	if state.bucketCount != 1 || id.Validate(state.bucketID, id.QuotaBucket) != nil ||
		state.limitPlanKey != dataPlaneE2ETokenBucketPlan ||
		state.metric != quota.LogicalRequestsMetric || state.scopeType != "composite" ||
		!reflect.DeepEqual(state.scopeDimensions, []string{"user", "feature"}) ||
		state.algorithm != quota.TokenBucketAlgorithm || state.windowKey != "rolling" ||
		state.hardMaximum != 1 || state.used != 0 || state.reserved != 0 ||
		state.available < 0 || state.available > dataPlaneE2ETokenBalanceScale ||
		state.refillNumerator != 1 || state.refillDenominator != 100 ||
		state.refilledAt.IsZero() || state.version < 1 || state.createdAt.IsZero() ||
		state.updatedAt.IsZero() || state.updatedAt.Before(state.createdAt) {
		t.Fatalf("token-bucket metadata violated exact rolling state: %+v", state)
	}
}

func assertDataPlaneE2EOutputTokenBucketMetadata(t *testing.T, state dataPlaneE2ETokenBucketState) {
	t.Helper()
	if state.bucketCount != 1 || id.Validate(state.bucketID, id.QuotaBucket) != nil ||
		state.limitPlanKey != dataPlaneE2EOutputTokenBucketPlan ||
		state.metric != quota.OutputTokensMetric || state.scopeType != "composite" ||
		!reflect.DeepEqual(state.scopeDimensions, []string{"user", "feature"}) ||
		state.algorithm != quota.TokenBucketAlgorithm || state.windowKey != "rolling" ||
		state.hardMaximum != 8 || state.used != 0 || state.reserved != 0 ||
		state.available < 0 || state.available > 8*dataPlaneE2ETokenBalanceScale ||
		state.refillNumerator != 1 || state.refillDenominator != 100 ||
		state.refilledAt.IsZero() || state.version < 1 || state.createdAt.IsZero() ||
		state.updatedAt.IsZero() || state.updatedAt.Before(state.createdAt) {
		t.Fatalf("output-token bucket metadata violated exact rolling state: %+v", state)
	}
}

func backdateDataPlaneE2ETokenBucket(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	before dataPlaneE2ETokenBucketState,
) dataPlaneE2ETokenBucketState {
	t.Helper()
	assertDataPlaneE2ETokenBucketMetadata(t, before)
	command, err := pool.Exec(ctx, `
		UPDATE quota_buckets
		SET refilled_at = refilled_at - INTERVAL '100 seconds'
		WHERE limit_plan_key = $1 AND metric = $2 AND algorithm = $3
		  AND window_key = 'rolling'
	`, dataPlaneE2ETokenBucketPlan, quota.LogicalRequestsMetric,
		quota.TokenBucketAlgorithm)
	if err != nil {
		t.Fatalf("backdate token-bucket refill cursor: %v", err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("backdated token buckets = %d, want 1", command.RowsAffected())
	}
	after := readDataPlaneE2ETokenBucketState(t, ctx, pool)
	want := before
	want.refilledAt = before.refilledAt.Add(-dataPlaneE2ETokenRefillInterval)
	if !reflect.DeepEqual(after, want) {
		t.Fatalf("backdating changed more than the exact refill cursor: before=%+v after=%+v want=%+v",
			before, after, want)
	}
	return after
}

func backdateDataPlaneE2EOutputTokenBucket(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	before dataPlaneE2ETokenBucketState,
) dataPlaneE2ETokenBucketState {
	t.Helper()
	assertDataPlaneE2EOutputTokenBucketMetadata(t, before)
	command, err := pool.Exec(ctx, `
		UPDATE quota_buckets
		SET refilled_at = refilled_at - INTERVAL '700 seconds'
		WHERE limit_plan_key = $1 AND metric = $2 AND algorithm = $3
		  AND window_key = 'rolling'
	`, dataPlaneE2EOutputTokenBucketPlan, quota.OutputTokensMetric,
		quota.TokenBucketAlgorithm)
	if err != nil {
		t.Fatalf("backdate output-token bucket refill cursor: %v", err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("backdated output-token buckets = %d, want 1", command.RowsAffected())
	}
	after := readDataPlaneE2EOutputTokenBucketState(t, ctx, pool)
	want := before
	want.refilledAt = before.refilledAt.Add(-dataPlaneE2EOutputTokenRefillInterval)
	if !reflect.DeepEqual(after, want) {
		t.Fatalf("backdating changed more than the exact output-token refill cursor: before=%+v after=%+v want=%+v",
			before, after, want)
	}
	return after
}

func readDataPlaneE2ECostBucketState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) dataPlaneE2EQuotaBucketState {
	t.Helper()
	var state dataPlaneE2EQuotaBucketState
	var bucketCount int64
	err := pool.QueryRow(ctx, `
		SELECT quota_bucket_id, limit_plan_key, metric, scope_type,
		       scope_dimensions, algorithm, window_key, hard_maximum,
		       used_units, reserved_units, version, count(*) OVER ()
		FROM quota_buckets
		WHERE limit_plan_key = $1 AND metric = $2 AND algorithm = $3
	`, dataPlaneE2ECostPlan, quota.CostNanoUSDMetric, quota.CalendarAlgorithm).Scan(
		&state.bucketID, &state.limitPlanKey, &state.metric, &state.scopeType,
		&state.scopeDimensions, &state.algorithm, &state.windowKey, &state.hardMaximum,
		&state.used, &state.reserved, &state.version, &bucketCount,
	)
	if err != nil {
		t.Fatalf("read hard-cost bucket state: %v", err)
	}
	if bucketCount != 1 {
		t.Fatalf("hard-cost buckets = %d, want 1", bucketCount)
	}
	state.scopeDimensions = append([]string(nil), state.scopeDimensions...)
	return state
}

func assertDataPlaneE2ECostBucketState(t *testing.T, state dataPlaneE2EQuotaBucketState) {
	t.Helper()
	if id.Validate(state.bucketID, id.QuotaBucket) != nil ||
		state.limitPlanKey != dataPlaneE2ECostPlan || state.metric != quota.CostNanoUSDMetric ||
		state.scopeType != "composite" ||
		!reflect.DeepEqual(state.scopeDimensions, []string{"user", "feature"}) ||
		state.algorithm != quota.CalendarAlgorithm ||
		!strings.HasPrefix(state.windowKey, "utc:v1:1mo:") ||
		state.hardMaximum != dataPlaneE2ECostMaximum ||
		state.used != dataPlaneE2EActualCost || state.reserved != 0 || state.version != 2 {
		t.Fatalf("hard-cost bucket violated exact calendar state: %+v", state)
	}
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

func assertDataPlaneE2EConcurrencyProblem(t *testing.T, response *dataPlaneE2EResponseRecorder, feature string) {
	t.Helper()
	var document struct {
		Code       string  `json:"code"`
		Detail     string  `json:"detail"`
		Feature    string  `json:"feature"`
		Retryable  bool    `json:"retryable"`
		RetryAfter *string `json:"retry_after"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode concurrency problem: %v", err)
	}
	if response.Code != http.StatusTooManyRequests || document.Code != "concurrency_exceeded" ||
		document.Detail != "The configured concurrency limit has been reached." ||
		document.Feature != feature || !document.Retryable || document.RetryAfter != nil ||
		response.Header().Get("Retry-After") != "" {
		t.Fatalf("concurrency problem status/header/document = %d/%q/%+v",
			response.Code, response.Header().Get("Retry-After"), document)
	}
}

func assertDataPlaneE2EConcurrencyDenialPersistence(t *testing.T, ctx context.Context, pool *pgxpool.Pool, clientRequestID string) {
	t.Helper()
	var logicalID, status, failureCode string
	var reservations, attempts, usageRecords, leases int64
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, request.failure_code,
		       (SELECT count(*) FROM quota_reservations AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM upstream_attempts AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM concurrency_leases AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &status, &failureCode, &reservations, &attempts, &usageRecords, &leases,
	)
	if err != nil {
		t.Fatalf("read concurrency-denied request: %v", err)
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil || status != "denied" ||
		failureCode != "concurrency_exceeded" || reservations != 0 || attempts != 0 ||
		usageRecords != 0 || leases != 0 {
		t.Fatalf("concurrency-denied lifecycle = request:%q status:%q failure:%q reservations:%d attempts:%d usage:%d leases:%d",
			logicalID, status, failureCode, reservations, attempts, usageRecords, leases)
	}
}

func assertDataPlaneE2EConcurrencyState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	wantActive, wantLeases, wantReleased int64,
) {
	t.Helper()
	var bucketCount int64
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM quota_buckets WHERE metric = $1
	`, quota.ConcurrentStreamsMetric).Scan(&bucketCount); err != nil {
		t.Fatalf("count concurrency buckets: %v", err)
	}
	if bucketCount != 1 {
		t.Fatalf("concurrency buckets = %d, want 1", bucketCount)
	}
	var bucketID, plan, metric, scopeType, algorithm, windowKey string
	var scope []string
	var maximum, used, reserved, version int64
	if err := pool.QueryRow(ctx, `
		SELECT quota_bucket_id, limit_plan_key, metric, scope_type, scope_dimensions,
		       algorithm, window_key, hard_maximum, used_units, reserved_units, version
		FROM quota_buckets
		WHERE metric = $1
	`, quota.ConcurrentStreamsMetric).Scan(
		&bucketID, &plan, &metric, &scopeType, &scope,
		&algorithm, &windowKey, &maximum, &used, &reserved, &version,
	); err != nil {
		t.Fatalf("read concurrency bucket: %v", err)
	}
	if id.Validate(bucketID, id.QuotaBucket) != nil || plan != dataPlaneE2EConcurrencyPlan ||
		metric != quota.ConcurrentStreamsMetric || scopeType != "composite" ||
		!reflect.DeepEqual(scope, []string{"environment", "feature"}) ||
		algorithm != quota.ConcurrencyAlgorithm || windowKey != "active" || maximum != 1 ||
		used != 0 || reserved != wantActive || used+reserved > maximum ||
		version != wantLeases+wantReleased {
		t.Fatalf("concurrency bucket = id:%q plan:%q metric:%q scope:%q/%v algorithm:%q window:%q maximum:%d occupancy:%d/%d version:%d",
			bucketID, plan, metric, scopeType, scope, algorithm, windowKey,
			maximum, used, reserved, version)
	}
	var leases, active, released int64
	var validTimes bool
	if err := pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE lease.released_at IS NULL),
		       count(*) FILTER (WHERE lease.released_at IS NOT NULL),
		       bool_and(lease.expires_at > lease.acquired_at AND
		                (lease.released_at IS NULL OR lease.released_at >= lease.acquired_at))
		FROM concurrency_leases AS lease
		WHERE lease.quota_bucket_id = $1
	`, bucketID).Scan(&leases, &active, &released, &validTimes); err != nil {
		t.Fatalf("read concurrency leases: %v", err)
	}
	if leases != wantLeases || active != wantActive || released != wantReleased || !validTimes {
		t.Fatalf("concurrency leases total/active/released/valid=%d/%d/%d/%t, want %d/%d/%d/true",
			leases, active, released, validTimes, wantLeases, wantActive, wantReleased)
	}
	var concurrencyUsage int64
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM usage_records WHERE metric IN ($1, $2)
	`, quota.ConcurrentRequestsMetric, quota.ConcurrentStreamsMetric).Scan(&concurrencyUsage); err != nil {
		t.Fatalf("count concurrency usage records: %v", err)
	}
	if concurrencyUsage != 0 {
		t.Fatalf("concurrency usage records = %d, want 0", concurrencyUsage)
	}
}

func assertDataPlaneE2EEntrylessReservation(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID, priceRevision string,
) {
	t.Helper()
	assertDataPlaneE2EConcurrencySuccess(
		t, ctx, pool, clientRequestID, priceRevision, false,
	)
}

func assertDataPlaneE2EConcurrencyTerminalLifecycle(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	priceRevision string,
) {
	t.Helper()
	for _, clientRequestID := range []string{
		dataPlaneE2EConcurrencyHoldRequestID,
		dataPlaneE2EConcurrencyReuseRequestID,
	} {
		assertDataPlaneE2EConcurrencySuccess(
			t, ctx, pool, clientRequestID, priceRevision, true,
		)
	}
	rows, err := pool.Query(ctx, `
		SELECT request.client_request_id
		FROM concurrency_leases AS lease
		JOIN logical_requests AS request USING (logical_request_id)
		ORDER BY request.client_request_id COLLATE "C"
	`)
	if err != nil {
		t.Fatalf("read concurrency lease request identities: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var clientRequestID string
		if err := rows.Scan(&clientRequestID); err != nil {
			t.Fatalf("scan concurrency lease request identity: %v", err)
		}
		got = append(got, clientRequestID)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate concurrency lease request identities: %v", err)
	}
	want := []string{
		dataPlaneE2EConcurrencyHoldRequestID,
		dataPlaneE2EConcurrencyReuseRequestID,
	}
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("concurrency lease requests = %v, want %v", got, want)
	}
}

func assertDataPlaneE2EConcurrencySuccess(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	clientRequestID, priceRevision string,
	wantConcurrencyEntry bool,
) {
	t.Helper()
	var logicalID, logicalStatus, reservationStatus, attemptStatus, physicalModel string
	var currency, persistedPriceRevision, pricingSource, costConfidence string
	var httpStatus int
	var billedCost, entries, leases, releasedLeases, usageRecords int64
	var firstByte bool
	err := pool.QueryRow(ctx, `
		SELECT request.logical_request_id, request.status, reservation.status,
		       attempt.status, attempt.http_status, attempt.physical_model,
		       attempt.billed_cost_nano_usd, attempt.currency,
		       attempt.price_revision, attempt.pricing_source, attempt.cost_confidence,
		       attempt.first_byte_at IS NOT NULL,
		       (SELECT count(*) FROM quota_reservation_entries AS counted
		        WHERE counted.quota_reservation_id = reservation.quota_reservation_id),
		       (SELECT count(*) FROM concurrency_leases AS counted
		        WHERE counted.logical_request_id = request.logical_request_id),
		       (SELECT count(*) FROM concurrency_leases AS counted
		        WHERE counted.logical_request_id = request.logical_request_id
		          AND counted.released_at IS NOT NULL),
		       (SELECT count(*) FROM usage_records AS counted
		        WHERE counted.logical_request_id = request.logical_request_id)
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&logicalID, &logicalStatus, &reservationStatus,
		&attemptStatus, &httpStatus, &physicalModel,
		&billedCost, &currency, &persistedPriceRevision, &pricingSource, &costConfidence,
		&firstByte, &entries, &leases, &releasedLeases, &usageRecords,
	)
	if err != nil {
		t.Fatalf("read concurrency success %q: %v", clientRequestID, err)
	}
	wantEntries := int64(0)
	if wantConcurrencyEntry {
		wantEntries = 1
	}
	if id.Validate(logicalID, id.LogicalRequest) != nil || logicalStatus != "succeeded" ||
		reservationStatus != "settled" || attemptStatus != quota.AttemptSucceeded ||
		httpStatus != http.StatusOK || physicalModel != dataPlaneE2EProviderModel ||
		billedCost != dataPlaneE2ECalculatedCost || currency != quota.USDCurrency ||
		persistedPriceRevision != priceRevision || pricingSource != dataPlaneE2EPricingCatalog ||
		costConfidence != quota.CalculatedCostConfidence || !firstByte ||
		entries != wantEntries || leases != wantEntries || releasedLeases != wantEntries ||
		usageRecords != 5 {
		t.Fatalf("concurrency success %q = logical:%q/%s reservation:%s attempt:%s/%d/%s price:%d/%s/%s/%s/%s first_byte:%t entries/leases/released:%d/%d/%d usage:%d",
			clientRequestID, logicalID, logicalStatus, reservationStatus,
			attemptStatus, httpStatus, physicalModel, billedCost, currency,
			persistedPriceRevision, pricingSource, costConfidence, firstByte,
			entries, leases, releasedLeases, usageRecords)
	}
	if !wantConcurrencyEntry {
		return
	}
	var metric, algorithm, windowKey string
	var entryReserved, entrySettled, entryReleased, bucketUsed, bucketReserved int64
	var leaseReleased bool
	if err := pool.QueryRow(ctx, `
		SELECT bucket.metric, bucket.algorithm, bucket.window_key,
		       entry.reserved_units, entry.settled_units, entry.released_units,
		       bucket.used_units, bucket.reserved_units,
		       lease.released_at IS NOT NULL
		FROM logical_requests AS request
		JOIN quota_reservations AS reservation USING (logical_request_id)
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		JOIN concurrency_leases AS lease
		  ON lease.logical_request_id = request.logical_request_id
		 AND lease.quota_bucket_id = bucket.quota_bucket_id
		WHERE request.client_request_id = $1
	`, clientRequestID).Scan(
		&metric, &algorithm, &windowKey,
		&entryReserved, &entrySettled, &entryReleased,
		&bucketUsed, &bucketReserved, &leaseReleased,
	); err != nil {
		t.Fatalf("read terminal concurrency entry %q: %v", clientRequestID, err)
	}
	if metric != quota.ConcurrentStreamsMetric || algorithm != quota.ConcurrencyAlgorithm ||
		windowKey != "active" || entryReserved != 1 || entrySettled != 0 || entryReleased != 1 ||
		bucketUsed != 0 || bucketReserved != 0 || !leaseReleased {
		t.Fatalf("terminal concurrency entry %q = metric:%q algorithm:%q window:%q entry:%d/%d/%d bucket:%d/%d released:%t",
			clientRequestID, metric, algorithm, windowKey,
			entryReserved, entrySettled, entryReleased,
			bucketUsed, bucketReserved, leaseReleased)
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
