// Package oidctest is an in-memory OpenID provider for tests. It serves
// discovery, a JWKS and a token endpoint through an http.RoundTripper, checks
// client credentials, redirect URI and PKCE, and signs ES256 ID tokens.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Provider is one fake issuer with one registered client.
type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// Audience overrides the ID token audience when set.
	Audience string
	// Nonce overrides the ID token nonce when set.
	Nonce string
	// Lifetime overrides the ID token lifetime when non-zero.
	Lifetime time.Duration

	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	codes map[string]grant
	// Exchanges counts token requests, successful or not.
	Exchanges int
}

type grant struct {
	claims      map[string]any
	nonce       string
	challenge   string
	redirectURI string
}

// New creates a provider at issuer (an https URL) for one client.
func New(issuer, clientID, clientSecret string) (*Provider, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Provider{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, key: key, codes: map[string]grant{}}, nil
}

// Client returns an HTTP client whose every request this provider answers.
func (provider *Provider) Client() *http.Client {
	return &http.Client{Transport: provider}
}

// Authorize plays the user approving the sign-in at the provider: it reads
// the authorization URL the relying party built and returns the code and
// state the provider would send to the callback, for an account with claims.
func (provider *Provider) Authorize(authorizationURL string, claims map[string]any) (code, state string, err error) {
	parsed, err := url.Parse(authorizationURL)
	if err != nil || !strings.HasPrefix(authorizationURL, provider.Issuer+"/authorize?") {
		return "", "", errors.New("not this provider's authorization endpoint")
	}
	query := parsed.Query()
	if query.Get("client_id") != provider.ClientID || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" ||
		!strings.Contains(query.Get("scope"), "openid") {
		return "", "", errors.New("authorization request is invalid")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	code = base64.RawURLEncoding.EncodeToString(raw)
	provider.mu.Lock()
	provider.codes[code] = grant{claims: claims, nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), redirectURI: query.Get("redirect_uri")}
	provider.mu.Unlock()
	return code, query.Get("state"), nil
}

func respond(status int, body any) *http.Response {
	encoded, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(string(encoded))), ContentLength: int64(len(encoded)),
	}
}

// RoundTrip serves discovery, the JWKS and the token endpoint.
func (provider *Provider) RoundTrip(request *http.Request) (*http.Response, error) {
	switch {
	case request.Method == http.MethodGet && request.URL.String() == provider.Issuer+"/.well-known/openid-configuration":
		return respond(http.StatusOK, map[string]any{
			"issuer": provider.Issuer, "authorization_endpoint": provider.Issuer + "/authorize",
			"token_endpoint": provider.Issuer + "/token", "jwks_uri": provider.Issuer + "/jwks",
			"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"ES256"}, "subject_types_supported": []string{"public"},
		}), nil
	case request.Method == http.MethodGet && request.URL.String() == provider.Issuer+"/jwks":
		encoded, _ := provider.key.PublicKey.Bytes()
		return respond(http.StatusOK, map[string]any{"keys": []map[string]any{{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "test-key",
			"x": base64.RawURLEncoding.EncodeToString(encoded[1:33]), "y": base64.RawURLEncoding.EncodeToString(encoded[33:65]),
		}}}), nil
	case request.Method == http.MethodPost && request.URL.String() == provider.Issuer+"/token":
		return provider.token(request)
	default:
		return respond(http.StatusNotFound, map[string]any{"error": "not_found"}), nil
	}
}

func (provider *Provider) token(request *http.Request) (*http.Response, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.Exchanges++
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return respond(http.StatusBadRequest, map[string]any{"error": "invalid_request"}), nil
	}
	if form.Get("client_id") != provider.ClientID || form.Get("client_secret") != provider.ClientSecret {
		return respond(http.StatusUnauthorized, map[string]any{"error": "invalid_client"}), nil
	}
	granted, ok := provider.codes[form.Get("code")]
	delete(provider.codes, form.Get("code"))
	verifier := sha256.Sum256([]byte(form.Get("code_verifier")))
	if !ok || form.Get("grant_type") != "authorization_code" || form.Get("redirect_uri") != granted.redirectURI ||
		base64.RawURLEncoding.EncodeToString(verifier[:]) != granted.challenge {
		return respond(http.StatusBadRequest, map[string]any{"error": "invalid_grant"}), nil
	}
	now := time.Now()
	lifetime := provider.Lifetime
	if lifetime == 0 {
		lifetime = 5 * time.Minute
	}
	audience := provider.Audience
	if audience == "" {
		audience = provider.ClientID
	}
	nonce := provider.Nonce
	if nonce == "" {
		nonce = granted.nonce
	}
	claims := jwt.MapClaims{"iss": provider.Issuer, "aud": audience, "iat": now.Unix(), "exp": now.Add(lifetime).Unix(), "nonce": nonce}
	for name, value := range granted.claims {
		claims[name] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(provider.key)
	if err != nil {
		return nil, err
	}
	return respond(http.StatusOK, map[string]any{"access_token": "test-access-token", "token_type": "Bearer", "id_token": signed, "expires_in": 300}), nil
}
