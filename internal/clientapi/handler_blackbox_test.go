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

func TestExportedHandlerBlackBox(t *testing.T) {
	t.Parallel()

	coordinator := &blackBoxCoordinator{}
	api, err := clientapi.New(clientapi.Config{
		Coordinator: coordinator, JWKS: blackBoxKeys{}, PublicOrigin: "https://public.example.test",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handler := api.Handler()

	challenge := blackBoxRequest("/client/v1/session-challenges", `{"application_id":"app_public","environment":"production","identity_provider":"firebase","identity_token":"identity-token-123","platform":"web","sdk_version":"1.2.3"}`)
	challenge.Header.Set("X-Latchway-SDK", "javascript")
	challenge.Host = "untrusted.invalid"
	challenge.Header.Set("Forwarded", "host=untrusted.invalid;proto=http")
	challengeResponse := httptest.NewRecorder()
	handler.ServeHTTP(challengeResponse, challenge)
	assertBlackBoxStatus(t, challengeResponse, http.StatusCreated)
	if coordinator.challenge.Metadata.TargetURL.String() != "https://public.example.test/client/v1/session-challenges" || coordinator.challenge.Metadata.SDK != "javascript" {
		t.Fatalf("challenge metadata = %#v", coordinator.challenge.Metadata)
	}

	exchange := blackBoxRequest("/client/v1/sessions", `{"challenge_id":"chl_01K3NQ7M8P9RSTVWXYZABCDE12","attestation":{"provider":"debug","evidence":{"proof":"opaque"}},"installation":{"app_version":"1.0"}}`)
	exchange.Header.Set("X-Latchway-SDK", "javascript")
	exchangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(exchangeResponse, exchange)
	assertBlackBoxStatus(t, exchangeResponse, http.StatusCreated)
	if coordinator.exchange.Metadata.TargetURL.String() != "https://public.example.test/client/v1/sessions" {
		t.Fatalf("exchange target = %q", coordinator.exchange.Metadata.TargetURL.String())
	}

	refresh := blackBoxRequest("/client/v1/sessions/refresh", `{"refresh_token":"`+strings.Repeat("r", 48)+`"}`)
	refresh.Header.Set("X-Latchway-SDK", "javascript")
	refreshResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshResponse, refresh)
	assertBlackBoxStatus(t, refreshResponse, http.StatusOK)
	if coordinator.refresh.Metadata.TargetURL.String() != "https://public.example.test/client/v1/sessions/refresh" {
		t.Fatalf("refresh target = %q", coordinator.refresh.Metadata.TargetURL.String())
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
