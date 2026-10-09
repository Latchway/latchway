// Package oidc is the relying-party side of OpenID Connect that administrator
// single sign-on needs: discovery, the authorization-code flow with PKCE, and
// ID token verification. Every request goes to an HTTPS endpoint the issuer's
// own discovery document named, through the same DNS-rebinding-resistant,
// redirect-free, public-destination transport used for AI upstreams.
package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	maxDocumentBytes = 64 << 10
	maxIDTokenBytes  = 16 << 10
	clockSkew        = time.Minute
)

var (
	// ErrDiscovery means the issuer's discovery document is unreachable,
	// malformed or unsuitable.
	ErrDiscovery = errors.New("openid provider discovery failed")
	// ErrExchange means the token endpoint refused or failed the code exchange.
	ErrExchange = errors.New("openid authorization code exchange failed")
	// ErrIDToken means the ID token failed verification.
	ErrIDToken = errors.New("openid id token is invalid")
)

// signingAlgorithms are the ID token algorithms accepted; "none" and HMAC are
// never accepted.
var signingAlgorithms = []string{"RS256", "ES256"}

// Provider is the part of an issuer's discovery document a relying party uses.
type Provider struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
}

// Claims are the verified ID token claims single sign-on uses.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Client performs the network side of OpenID Connect.
type Client struct {
	// HTTP replaces the protected public-internet transport when set; tests use
	// it with an in-memory RoundTripper.
	HTTP *http.Client
	// Now overrides the clock for ID token validation.
	Now func() time.Time
}

func (client *Client) now() time.Time {
	if client.Now != nil {
		return client.Now()
	}
	return time.Now()
}

// CanonicalIssuer validates an issuer identifier: an HTTPS URL with no query,
// fragment or credentials, compared exactly as the provider spells it.
func CanonicalIssuer(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || len(raw) > 2048 || parsed.String() != raw {
		return "", fmt.Errorf("%w: the issuer must be an https URL without a query or fragment", ErrDiscovery)
	}
	return raw, nil
}

func endpoint(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	return raw, err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil &&
		parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && len(raw) <= 2048 && parsed.String() == raw
}

// do sends one request and returns the status and a bounded body.
func (client *Client) do(request *http.Request, forwarded []string) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	if client.HTTP != nil {
		httpClient := *client.HTTP
		httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := httpClient.Do(request)
		if err != nil {
			return 0, nil, nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentBytes+1))
		if err != nil || len(body) > maxDocumentBytes {
			return 0, nil, nil, errors.New("response is too large or unreadable")
		}
		return response.StatusCode, response.Header, body, nil
	}
	target, err := upstream.NewTarget(request.URL.String(), upstream.DestinationPolicy{}, upstream.Timeouts{
		Connect: 5 * time.Second, TLSHandshake: 5 * time.Second, ResponseHeader: 10 * time.Second,
	}, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	defer target.CloseIdleConnections()
	prepared, err := upstream.PrepareBaseRequest(request, target, forwarded, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	dispatched, err := target.Dispatch(ctx, prepared)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = dispatched.Close() }()
	body, err := io.ReadAll(io.LimitReader(dispatched.Body, maxDocumentBytes+1))
	if err != nil || len(body) > maxDocumentBytes {
		return 0, nil, nil, errors.New("response is too large or unreadable")
	}
	return dispatched.StatusCode, dispatched.Header, body, nil
}

func jsonDocument(header http.Header, body []byte) (map[string]any, error) {
	if media := header.Get("Content-Type"); media != "" {
		parsed, _, err := mime.ParseMediaType(media)
		if err != nil || parsed != "application/json" {
			return nil, errors.New("response is not JSON")
		}
	}
	value, err := jsonsafe.DecodeReader(bytes.NewReader(body), maxDocumentBytes)
	if err != nil {
		return nil, err
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("response is not a JSON object")
	}
	return document, nil
}

func stringField(document map[string]any, name string) string {
	value, _ := document[name].(string)
	return value
}

// Discover reads issuer/.well-known/openid-configuration and checks that it
// names the same issuer, HTTPS endpoints, the code flow, PKCE S256 and an
// accepted signing algorithm.
func (client *Client) Discover(ctx context.Context, issuer string) (Provider, error) {
	if _, err := CanonicalIssuer(issuer); err != nil {
		return Provider{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return Provider{}, ErrDiscovery
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway-gateway/sso")
	status, header, body, err := client.do(request, []string{"Accept", "User-Agent"})
	if err != nil {
		return Provider{}, fmt.Errorf("%w: the discovery document couldn't be fetched", ErrDiscovery)
	}
	if status != http.StatusOK {
		return Provider{}, fmt.Errorf("%w: the discovery document returned HTTP %d", ErrDiscovery, status)
	}
	document, err := jsonDocument(header, body)
	if err != nil {
		return Provider{}, fmt.Errorf("%w: the discovery document isn't valid JSON", ErrDiscovery)
	}
	if stringField(document, "issuer") != issuer {
		return Provider{}, fmt.Errorf("%w: the discovery document names a different issuer", ErrDiscovery)
	}
	provider := Provider{Issuer: issuer}
	var ok bool
	if provider.AuthorizationEndpoint, ok = endpoint(stringField(document, "authorization_endpoint")); !ok {
		return Provider{}, fmt.Errorf("%w: the authorization endpoint must be https without a query", ErrDiscovery)
	}
	if provider.TokenEndpoint, ok = endpoint(stringField(document, "token_endpoint")); !ok {
		return Provider{}, fmt.Errorf("%w: the token endpoint must be https without a query", ErrDiscovery)
	}
	if provider.JWKSURI, ok = endpoint(stringField(document, "jwks_uri")); !ok {
		return Provider{}, fmt.Errorf("%w: the JWKS URI must be https without a query", ErrDiscovery)
	}
	if !listed(document, "response_types_supported", "code", true) {
		return Provider{}, fmt.Errorf("%w: the provider doesn't offer the authorization code flow", ErrDiscovery)
	}
	if !listed(document, "code_challenge_methods_supported", "S256", true) {
		return Provider{}, fmt.Errorf("%w: the provider doesn't support PKCE with S256", ErrDiscovery)
	}
	if !slices.ContainsFunc(signingAlgorithms, func(algorithm string) bool {
		return listed(document, "id_token_signing_alg_values_supported", algorithm, false)
	}) {
		return Provider{}, fmt.Errorf("%w: the provider doesn't sign ID tokens with RS256 or ES256", ErrDiscovery)
	}
	return provider, nil
}

// listed reports whether a discovery array contains value; a missing array
// counts as present when absentMeansYes, as some providers omit optional ones.
func listed(document map[string]any, field, value string, absentMeansYes bool) bool {
	raw, present := document[field]
	if !present {
		return absentMeansYes
	}
	values, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func randomToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// NewLogin returns the random state, nonce and PKCE verifier for one sign-in.
func NewLogin() (state, nonce, verifier string, err error) {
	if state, err = randomToken(32); err != nil {
		return "", "", "", err
	}
	if nonce, err = randomToken(32); err != nil {
		return "", "", "", err
	}
	if verifier, err = randomToken(32); err != nil {
		return "", "", "", err
	}
	return state, nonce, verifier, nil
}

// AuthorizationURL builds the redirect to the provider's authorization endpoint.
func AuthorizationURL(provider Provider, clientID, redirectURI, state, nonce, verifier string) string {
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {clientID},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"nonce":                 {nonce},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
	}
	return provider.AuthorizationEndpoint + "?" + query.Encode()
}

// Exchange redeems an authorization code and returns the raw ID token. The
// client authenticates with client_secret_post.
func (client *Client) Exchange(ctx context.Context, provider Provider, clientID, clientSecret, redirectURI, code, verifier string) (string, error) {
	if code == "" || len(code) > 2048 {
		return "", ErrExchange
	}
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrExchange
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "latchway-gateway/sso")
	status, header, body, err := client.do(request, []string{"Accept", "Content-Type", "User-Agent"})
	if err != nil {
		return "", fmt.Errorf("%w: the token endpoint couldn't be reached", ErrExchange)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%w: the token endpoint returned HTTP %d", ErrExchange, status)
	}
	document, err := jsonDocument(header, body)
	if err != nil {
		return "", fmt.Errorf("%w: the token response isn't valid JSON", ErrExchange)
	}
	idToken := stringField(document, "id_token")
	if idToken == "" || len(idToken) > maxIDTokenBytes {
		return "", fmt.Errorf("%w: the token response has no ID token", ErrExchange)
	}
	return idToken, nil
}

// VerifyIDToken checks the ID token's signature against the provider's JWKS
// and its issuer, audience, authorized party, expiry, issue time and nonce.
func (client *Client) VerifyIDToken(ctx context.Context, provider Provider, clientID, raw, nonce string) (Claims, error) {
	keys, err := identity.NewRemoteKeySource(identity.RemoteKeySourceConfig{
		URL: provider.JWKSURI, Issuer: provider.Issuer, Format: identity.RemoteKeyFormatJWKS, Client: client.HTTP, Now: client.now,
	})
	if err != nil {
		return Claims{}, fmt.Errorf("%w: the JWKS URI is unusable", ErrIDToken)
	}
	claims := jwt.MapClaims{}
	_, err = jwt.NewParser(
		jwt.WithValidMethods(signingAlgorithms),
		jwt.WithIssuer(provider.Issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(client.now),
	).ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		algorithm, _ := token.Header["alg"].(string)
		return keys.Key(ctx, kid, algorithm)
	})
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %s", ErrIDToken, verificationReason(err))
	}
	if value, _ := claims["nonce"].(string); value == "" || value != nonce {
		return Claims{}, fmt.Errorf("%w: the nonce doesn't match this sign-in", ErrIDToken)
	}
	// With several audiences the authorized party must be this client.
	if audiences, _ := claims.GetAudience(); len(audiences) > 1 {
		if azp, _ := claims["azp"].(string); azp != clientID {
			return Claims{}, fmt.Errorf("%w: the token was issued to another client", ErrIDToken)
		}
	}
	subject, _ := claims["sub"].(string)
	if subject == "" || len(subject) > 255 {
		return Claims{}, fmt.Errorf("%w: the subject is missing", ErrIDToken)
	}
	verified := Claims{Subject: subject}
	verified.Email, _ = claims["email"].(string)
	verified.Name, _ = claims["name"].(string)
	switch value := claims["email_verified"].(type) {
	case bool:
		verified.EmailVerified = value
	case string:
		// Some providers send the JSON string "true".
		verified.EmailVerified = value == "true"
	}
	if len(verified.Email) > 320 {
		verified.Email = ""
		verified.EmailVerified = false
	}
	if len(verified.Name) > 200 {
		verified.Name = verified.Name[:200]
	}
	return verified, nil
}

func verificationReason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "the token expired"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "the issuer doesn't match"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "the audience doesn't match"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenUnverifiable):
		return "the signature doesn't verify"
	default:
		return "the token is malformed or not yet valid"
	}
}

// AuthorizationError explains an error the provider sent back to the
// callback; only registered OAuth error codes are echoed.
func AuthorizationError(code string) string {
	switch code {
	case "access_denied":
		return "the sign-in was cancelled or refused at the identity provider"
	case "login_required", "interaction_required", "consent_required", "account_selection_required":
		return "the identity provider needs you to sign in there first"
	default:
		return "the identity provider reported an error"
	}
}
