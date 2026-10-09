package oidc_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchway/latchway/internal/oidc"
	"github.com/latchway/latchway/internal/oidc/oidctest"
)

const (
	issuer      = "https://idp.example.test"
	clientID    = "latchway-console"
	secret      = "test-only-client-secret"
	redirectURI = "https://console.example.test/admin/v1/auth/sso/callback"
)

func newProvider(t *testing.T) (*oidctest.Provider, *oidc.Client) {
	t.Helper()
	provider, err := oidctest.New(issuer, clientID, secret)
	if err != nil {
		t.Fatal(err)
	}
	return provider, &oidc.Client{HTTP: provider.Client()}
}

// signIn runs discovery, the redirect, the provider's approval and the code exchange.
func signIn(t *testing.T, provider *oidctest.Provider, client *oidc.Client, claims map[string]any) (oidc.Provider, string, string, error) {
	t.Helper()
	discovered, err := client.Discover(context.Background(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	state, nonce, verifier, err := oidc.NewLogin()
	if err != nil {
		t.Fatal(err)
	}
	code, returnedState, err := provider.Authorize(oidc.AuthorizationURL(discovered, clientID, redirectURI, state, nonce, verifier), claims)
	if err != nil || returnedState != state {
		t.Fatalf("authorize state=%q err=%v", returnedState, err)
	}
	idToken, err := client.Exchange(context.Background(), discovered, clientID, secret, redirectURI, code, verifier)
	return discovered, idToken, nonce, err
}

func TestSignInVerifiesTheIDToken(t *testing.T) {
	provider, client := newProvider(t)
	discovered, idToken, nonce, err := signIn(t, provider, client, map[string]any{"sub": "user-1", "email": "ada@example.test", "email_verified": true, "name": "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	if discovered.TokenEndpoint != issuer+"/token" || discovered.JWKSURI != issuer+"/jwks" {
		t.Fatalf("discovered=%+v", discovered)
	}
	claims, err := client.VerifyIDToken(context.Background(), discovered, clientID, idToken, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if claims != (oidc.Claims{Subject: "user-1", Email: "ada@example.test", EmailVerified: true, Name: "Ada"}) {
		t.Fatalf("claims=%+v", claims)
	}
	if _, err := client.VerifyIDToken(context.Background(), discovered, clientID, idToken, "another-nonce"); !errors.Is(err, oidc.ErrIDToken) {
		t.Fatalf("nonce mismatch err=%v", err)
	}
	if _, err := client.VerifyIDToken(context.Background(), discovered, "another-client", idToken, nonce); !errors.Is(err, oidc.ErrIDToken) {
		t.Fatalf("audience mismatch err=%v", err)
	}
}

func TestExchangeNeedsTheVerifierAndWorksOnce(t *testing.T) {
	provider, client := newProvider(t)
	discovered, err := client.Discover(context.Background(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	state, nonce, verifier, err := oidc.NewLogin()
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := provider.Authorize(oidc.AuthorizationURL(discovered, clientID, redirectURI, state, nonce, verifier), map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(context.Background(), discovered, clientID, secret, redirectURI, code, verifier+"x"); !errors.Is(err, oidc.ErrExchange) {
		t.Fatalf("wrong verifier err=%v", err)
	}
	if _, err := client.Exchange(context.Background(), discovered, clientID, secret, redirectURI, code, verifier); !errors.Is(err, oidc.ErrExchange) {
		t.Fatalf("reused code err=%v", err)
	}
}

func TestIDTokenFailures(t *testing.T) {
	for name, adjust := range map[string]func(*oidctest.Provider){
		"expired":        func(provider *oidctest.Provider) { provider.Lifetime = -2 * time.Minute },
		"other audience": func(provider *oidctest.Provider) { provider.Audience = "someone-else" },
		"replayed nonce": func(provider *oidctest.Provider) { provider.Nonce = "from-another-sign-in" },
	} {
		t.Run(name, func(t *testing.T) {
			provider, client := newProvider(t)
			adjust(provider)
			discovered, idToken, nonce, err := signIn(t, provider, client, map[string]any{"sub": "user-1"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.VerifyIDToken(context.Background(), discovered, clientID, idToken, nonce); !errors.Is(err, oidc.ErrIDToken) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestUnsignedTokensAreRefused(t *testing.T) {
	provider, client := newProvider(t)
	discovered, _, nonce, err := signIn(t, provider, client, map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": issuer, "aud": clientID, "sub": "attacker", "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyIDToken(context.Background(), discovered, clientID, unsigned, nonce); !errors.Is(err, oidc.ErrIDToken) {
		t.Fatalf("alg none err=%v", err)
	}
}

func TestDiscoveryChecks(t *testing.T) {
	_, client := newProvider(t)
	for _, bad := range []string{"http://idp.example.test", "https://idp.example.test?x=1", "https://idp.example.test#f", "https://user@idp.example.test"} {
		if _, err := client.Discover(context.Background(), bad); !errors.Is(err, oidc.ErrDiscovery) {
			t.Fatalf("issuer %q err=%v", bad, err)
		}
	}
	// A document naming another issuer is refused.
	mismatched := &oidc.Client{HTTP: &http.Client{Transport: roundTrip(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(`{"issuer":"https://evil.example.test","authorization_endpoint":"https://idp.example.test/a","token_endpoint":"https://idp.example.test/t","jwks_uri":"https://idp.example.test/k"}`), nil
	})}}
	if _, err := mismatched.Discover(context.Background(), issuer); err == nil || !strings.Contains(err.Error(), "different issuer") {
		t.Fatalf("issuer mismatch err=%v", err)
	}
	insecure := &oidc.Client{HTTP: &http.Client{Transport: roundTrip(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(`{"issuer":"https://idp.example.test","authorization_endpoint":"http://idp.example.test/a","token_endpoint":"https://idp.example.test/t","jwks_uri":"https://idp.example.test/k"}`), nil
	})}}
	if _, err := insecure.Discover(context.Background(), issuer); err == nil || !strings.Contains(err.Error(), "authorization endpoint") {
		t.Fatalf("insecure endpoint err=%v", err)
	}
}

func TestAuthorizationURLCarriesPKCE(t *testing.T) {
	built := oidc.AuthorizationURL(oidc.Provider{AuthorizationEndpoint: issuer + "/authorize"}, clientID, redirectURI, "state-value", "nonce-value", "verifier-value")
	parsed, err := url.Parse(built)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("code_challenge") == "verifier-value" ||
		query.Get("state") != "state-value" || query.Get("nonce") != "nonce-value" || query.Get("scope") != "openid email profile" {
		t.Fatalf("authorization URL=%s", built)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (fn roundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}
