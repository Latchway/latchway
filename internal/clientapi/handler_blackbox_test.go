package clientapi_test

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/requestidentity"
)

type blackBoxCoordinator struct {
	challenge clientapi.ChallengeInput
	exchange  clientapi.ExchangeInput
	refresh   clientapi.RefreshInput
	revoke    clientapi.RevokeInstallationInput
}

func (fake *blackBoxCoordinator) CreateChallenge(_ context.Context, input clientapi.ChallengeInput) (clientapi.ChallengeResult, error) {
	fake.challenge = input
	digest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	issuedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return clientapi.ChallengeResult{
		ChallengeID: "chl_01K3NQ7M8P9RSTVWXYZABCDE12", ChallengeNonce: digest,
		BindingVersion: 1, IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(5 * time.Minute),
		Attestation: clientapi.AttestationRequirement{Provider: "debug", Mode: "required", ClientDataHash: digest},
	}, nil
}

func (fake *blackBoxCoordinator) ExchangeSession(_ context.Context, input clientapi.ExchangeInput) (clientapi.GrantResult, error) {
	fake.exchange = input
	return blackBoxGrant(), nil
}

func (fake *blackBoxCoordinator) RefreshSession(_ context.Context, input clientapi.RefreshInput) (clientapi.GrantResult, error) {
	fake.refresh = input
	return blackBoxGrant(), nil
}

func (fake *blackBoxCoordinator) ProvisionComponent(_ context.Context, _ clientapi.ProvisionComponentInput) (clientapi.ProvisionComponentResult, error) {
	return clientapi.ProvisionComponentResult{}, nil
}

func (fake *blackBoxCoordinator) CreateComponentSession(_ context.Context, _ clientapi.CreateComponentSessionInput) (clientapi.GrantResult, error) {
	return blackBoxGrant(), nil
}

func (fake *blackBoxCoordinator) RevokeComponent(_ context.Context, _ clientapi.RevokeComponentInput) error {
	return nil
}

func (fake *blackBoxCoordinator) RevokeCurrentFamily(_ context.Context, _ clientapi.RevokeFamilyInput) error {
	return nil
}

func (fake *blackBoxCoordinator) Diagnostics(_ context.Context, input clientapi.DiagnosticsInput) (clientapi.DiagnosticsResult, error) {
	return clientapi.DiagnosticsResult{}, nil
}

func (fake *blackBoxCoordinator) RevokeCurrentInstallation(_ context.Context, input clientapi.RevokeInstallationInput) error {
	fake.revoke = input
	return nil
}

type blackBoxKeys struct{}

func (blackBoxKeys) PublicJWKS(context.Context) (clientapi.JWKS, error) {
	curve := elliptic.P256()
	return clientapi.JWKS{Keys: []clientapi.PublicJWK{{
		Kty: "EC", Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(curve.Params().Gx.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(curve.Params().Gy.FillBytes(make([]byte, 32))),
		Kid: "gsk_black_box_key", Use: "sig", Alg: "ES256",
	}}}, nil
}

type blackBoxFeatureQuotas struct {
	input clientapi.FeatureQuotaInput
}

func (fake *blackBoxFeatureQuotas) FeatureQuota(_ context.Context, input clientapi.FeatureQuotaInput) (clientapi.FeatureQuotaResult, error) {
	fake.input = input
	maximum := int64(100)
	used := int64(25)
	remaining := int64(75)
	reset := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	return clientapi.FeatureQuotaResult{
		Feature: "assistant", ObservedAt: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		Limits: []clientapi.FeatureQuotaLimit{{
			Metric: "logical_requests", Maximum: &maximum, Used: &used,
			Remaining: &remaining, ResetsAt: &reset, Hard: true,
		}},
	}, nil
}

func TestExportedHandlerBlackBox(t *testing.T) {
	t.Parallel()

	coordinator := &blackBoxCoordinator{}
	quotas := &blackBoxFeatureQuotas{}
	api, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, FeatureQuotas: quotas, JWKS: blackBoxKeys{}, PublicOrigin: "https://public.example.test",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, contextErr := requestidentity.NewContext(r.Context())
		if contextErr != nil {
			t.Errorf("requestidentity.NewContext() error = %v", contextErr)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		api.Handler().ServeHTTP(w, r.WithContext(ctx))
	})

	challenge := blackBoxRequest("/client/v1/session-challenges", `{"application_id":"app_public","environment":"production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"web","sdk_version":"1.2.3"}`)
	challenge.Header.Set("X-Latchway-SDK", "javascript")
	challenge.Header.Set("Origin", "https://app.example.test")
	challenge.Host = "untrusted.invalid"
	challenge.Header.Set("Forwarded", "host=untrusted.invalid;proto=http")
	challengeResponse := httptest.NewRecorder()
	handler.ServeHTTP(challengeResponse, challenge)
	assertBlackBoxStatus(t, challengeResponse, http.StatusCreated)
	if coordinator.challenge.Metadata.TargetURL.String() != "https://public.example.test/client/v1/session-challenges" || coordinator.challenge.Metadata.SDK != "javascript" || coordinator.challenge.Metadata.Origin != "https://app.example.test" {
		t.Fatalf("challenge metadata = %#v", coordinator.challenge.Metadata)
	}

	exchange := blackBoxRequest("/client/v1/sessions", `{"challenge_id":"chl_01K3NQ7M8P9RSTVWXYZABCDE12","attestation":{"provider":"debug","evidence":{"proof":"opaque"}},"installation":{"app_version":"1.0"}}`)
	exchange.Header.Set("X-Latchway-SDK", "javascript")
	exchange.Header.Set("Origin", "https://app.example.test")
	exchangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(exchangeResponse, exchange)
	assertBlackBoxStatus(t, exchangeResponse, http.StatusCreated)
	if coordinator.exchange.Metadata.TargetURL.String() != "https://public.example.test/client/v1/sessions" || coordinator.exchange.Metadata.Origin != "https://app.example.test" {
		t.Fatalf("exchange metadata = %#v", coordinator.exchange.Metadata)
	}

	refresh := blackBoxRequest("/client/v1/sessions/refresh", `{"refresh_token":"`+strings.Repeat("r", 48)+`"}`)
	refresh.Header.Set("X-Latchway-SDK", "javascript")
	refresh.Header.Set("Origin", "https://app.example.test")
	refreshResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshResponse, refresh)
	assertBlackBoxStatus(t, refreshResponse, http.StatusOK)
	if coordinator.refresh.Metadata.TargetURL.String() != "https://public.example.test/client/v1/sessions/refresh" || coordinator.refresh.Metadata.Origin != "https://app.example.test" {
		t.Fatalf("refresh metadata = %#v", coordinator.refresh.Metadata)
	}

	revoke := httptest.NewRequest(http.MethodDelete, "/client/v1/installations/current", nil)
	revoke.Header.Set("X-Latchway-Protocol-Version", "1")
	revoke.Header.Set("X-Latchway-SDK", "javascript")
	revoke.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	revoke.Header.Set("Authorization", "DPoP "+strings.Repeat("access-", 12))
	revoke.Header.Set("DPoP", "header.payload.signature")
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusNoContent || revokeResponse.Body.Len() != 0 {
		t.Fatalf("revoke status = %d, body = %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	if coordinator.revoke.Metadata.TargetURL.String() != "https://public.example.test/client/v1/installations/current" || coordinator.revoke.AccessToken.Reveal() != strings.Repeat("access-", 12) {
		t.Fatalf("revoke input = %#v", coordinator.revoke)
	}

	quota := httptest.NewRequest(http.MethodGet, "/client/v1/features/assistant/quota", nil)
	quota.Header.Set("X-Latchway-Protocol-Version", "1")
	quota.Header.Set("X-Latchway-SDK", "javascript")
	quota.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	quota.Header.Set("X-Latchway-Request-ID", "client-correlation-hint")
	quota.Header.Set("Authorization", "DPoP "+strings.Repeat("quota-access-", 8))
	quota.Header.Set("DPoP", "quota.header.signature")
	quota.Host = "untrusted.invalid"
	quota.Header.Set("Forwarded", "host=untrusted.invalid;proto=http")
	quotaResponse := httptest.NewRecorder()
	handler.ServeHTTP(quotaResponse, quota)
	assertBlackBoxStatus(t, quotaResponse, http.StatusOK)
	if quotas.input.Feature != "assistant" || quotas.input.AccessToken.Reveal() != strings.Repeat("quota-access-", 8) ||
		quotas.input.Metadata.DPoPProof.Reveal() != "quota.header.signature" || quotas.input.Metadata.TargetURL.String() != "https://public.example.test/client/v1/features/assistant/quota" ||
		quotas.input.LogicalRequestID.String() == "" || quotas.input.LogicalRequestID.String() != quotas.input.Metadata.RequestID || quotas.input.LogicalRequestID.String() == "client-correlation-hint" {
		t.Fatalf("quota input = %#v", quotas.input)
	}
	if quotaResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("quota Cache-Control = %q", quotaResponse.Header().Get("Cache-Control"))
	}
	var quotaDocument map[string]any
	if err := json.Unmarshal(quotaResponse.Body.Bytes(), &quotaDocument); err != nil {
		t.Fatalf("invalid quota JSON response: %v", err)
	}
	if quotaDocument["feature"] != "assistant" || len(quotaDocument["limits"].([]any)) != 1 {
		t.Fatalf("quota document = %#v", quotaDocument)
	}

	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	assertBlackBoxStatus(t, jwksResponse, http.StatusOK)
	if jwksResponse.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("JWKS Cache-Control = %q", jwksResponse.Header().Get("Cache-Control"))
	}
}

func blackBoxGrant() clientapi.GrantResult {
	digest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return clientapi.GrantResult{
		AccessToken: clientapi.NewSensitiveString(strings.Repeat("access-", 12)), ExpiresIn: 600,
		RefreshToken: clientapi.NewSensitiveString(strings.Repeat("refresh-", 5)), RefreshExpiresIn: 86400,
		Installation: clientapi.InstallationSummary{ID: "ins_01K3NQ7M8P9RSTVWXYZABCDE12", Platform: "web", DPoPJKT: digest, Status: "active"},
		Trust:        clientapi.TrustSummary{Provider: "debug", Level: "debug", VerifiedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
}

func blackBoxRequest(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "javascript")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("DPoP", "header.payload.signature")
	return request
}

func assertBlackBoxStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, want, response.Body.String())
	}
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
}
