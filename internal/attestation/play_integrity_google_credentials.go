package attestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	googleOAuthTokenEndpoint         = "https://oauth2.googleapis.com/token"
	googleServiceAccountGrantType    = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultGoogleTokenRequestTimeout = 10 * time.Second
	maximumGoogleTokenRequestTimeout = 30 * time.Second
	maximumServiceAccountJSONBytes   = 64 << 10
	maximumGoogleTokenResponseBytes  = 32 << 10
	googleServiceAccountAssertionTTL = time.Hour
	googleAccessTokenRefreshMargin   = time.Minute
)

var (
	googleServiceAccountEmailPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._+-]{0,190}@[A-Za-z0-9.-]{1,120}\.gserviceaccount\.com$`,
	)
	googlePrivateKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

type GoogleServiceAccountTokenSourceOptions struct {
	Transport http.RoundTripper
	Timeout   time.Duration
	Now       func() time.Time
}

type GoogleServiceAccountTokenSource struct {
	client       *http.Client
	clientEmail  string
	privateKeyID string
	privateKey   *rsa.PrivateKey
	tokenURI     *url.URL
	timeout      time.Duration
	now          func() time.Time
	gate         chan struct{}
	cached       PlayIntegrityAccessToken
}

// NewGoogleServiceAccountTokenSource parses a bounded Google service-account
// JSON credential entirely in memory. The private key and OAuth assertions are
// never exposed through formatting or errors. Only Google's fixed HTTPS token
// endpoint and the Play Integrity OAuth scope are accepted.
func NewGoogleServiceAccountTokenSource(
	credentialsJSON []byte,
	options GoogleServiceAccountTokenSourceOptions,
) (*GoogleServiceAccountTokenSource, error) {
	endpoint, err := url.Parse(googleOAuthTokenEndpoint)
	if err != nil {
		return nil, ErrConfiguration
	}
	return newGoogleServiceAccountTokenSource(credentialsJSON, options, endpoint)
}

func newGoogleServiceAccountTokenSource(
	credentialsJSON []byte,
	options GoogleServiceAccountTokenSourceOptions,
	endpoint *url.URL,
) (*GoogleServiceAccountTokenSource, error) {
	if len(credentialsJSON) == 0 || len(credentialsJSON) > maximumServiceAccountJSONBytes ||
		(options.Transport != nil && nilPlayIntegrityDependency(options.Transport)) ||
		endpoint == nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, ErrConfiguration
	}
	value, err := jsonsafe.Decode(credentialsJSON)
	if err != nil {
		return nil, ErrConfiguration
	}
	credentials, ok := value.(map[string]any)
	if !ok || len(credentials) > 32 {
		return nil, ErrConfiguration
	}
	credentialType, typeOK := stringMember(credentials, "type", 1, 64)
	clientEmail, emailOK := stringMember(credentials, "client_email", 3, 320)
	privateKeyID, keyIDOK := stringMember(credentials, "private_key_id", 16, 128)
	privateKeyPEM, keyOK := credentials["private_key"].(string)
	keyOK = keyOK && len(privateKeyPEM) >= 64 && len(privateKeyPEM) <= 32<<10
	tokenURI, tokenURIOK := stringMember(credentials, "token_uri", 1, 2048)
	if !typeOK || credentialType != "service_account" || !emailOK ||
		!googleServiceAccountEmailPattern.MatchString(clientEmail) || !keyIDOK ||
		!googlePrivateKeyIDPattern.MatchString(privateKeyID) || !keyOK || !tokenURIOK ||
		tokenURI != endpoint.String() {
		return nil, ErrConfiguration
	}
	privateKey, err := parseGoogleServiceAccountPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, ErrConfiguration
	}
	if options.Timeout == 0 {
		options.Timeout = defaultGoogleTokenRequestTimeout
	}
	if options.Timeout < time.Second || options.Timeout > maximumGoogleTokenRequestTimeout {
		return nil, ErrConfiguration
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	transport := options.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ownedEndpoint := *endpoint
	return &GoogleServiceAccountTokenSource{
		client: client, clientEmail: clientEmail, privateKeyID: privateKeyID,
		privateKey: privateKey, tokenURI: &ownedEndpoint, timeout: options.Timeout,
		now: options.Now, gate: make(chan struct{}, 1),
	}, nil
}

func (source *GoogleServiceAccountTokenSource) AccessToken(
	ctx context.Context,
) (PlayIntegrityAccessToken, error) {
	if source == nil || ctx == nil || source.client == nil || source.privateKey == nil ||
		source.tokenURI == nil || source.now == nil || source.gate == nil || source.timeout <= 0 {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	if err := ctx.Err(); err != nil {
		return PlayIntegrityAccessToken{}, err
	}
	select {
	case source.gate <- struct{}{}:
		defer func() { <-source.gate }()
	case <-ctx.Done():
		return PlayIntegrityAccessToken{}, ctx.Err()
	}
	now := source.now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	if validPlayIntegrityAccessToken(source.cached, now.Add(googleAccessTokenRefreshMargin)) {
		return source.cached, nil
	}
	assertion, err := source.signedAssertion(now)
	if err != nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	form := url.Values{
		"grant_type": []string{googleServiceAccountGrantType},
		"assertion":  []string{assertion},
	}
	requestContext, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, source.tokenURI.String(),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway/google-service-account-v1")
	response, err := source.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if contextErr := requestContext.Err(); contextErr != nil {
			return PlayIntegrityAccessToken{}, contextErr
		}
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	if response == nil || response.Body == nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	defer response.Body.Close()
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, maximumGoogleTokenResponseBytes+1))
	if readErr != nil || len(encoded) > maximumGoogleTokenResponseBytes || response.StatusCode != http.StatusOK {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	mediaType, _, contentTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if contentTypeErr != nil || mediaType != "application/json" {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	token, err := parseGoogleAccessTokenResponse(encoded, now)
	if err != nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	if err := requestContext.Err(); err != nil {
		return PlayIntegrityAccessToken{}, err
	}
	source.cached = token
	return token, nil
}

func (source *GoogleServiceAccountTokenSource) signedAssertion(now time.Time) (string, error) {
	if source == nil || source.privateKey == nil || now.IsZero() {
		return "", ErrConfiguration
	}
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}{Algorithm: "RS256", KeyID: source.privateKeyID, Type: "JWT"})
	if err != nil {
		return "", ErrConfiguration
	}
	issuedAt := now.Unix()
	claims, err := json.Marshal(struct {
		Audience  string `json:"aud"`
		ExpiresAt int64  `json:"exp"`
		IssuedAt  int64  `json:"iat"`
		Issuer    string `json:"iss"`
		Scope     string `json:"scope"`
	}{
		Audience: source.tokenURI.String(), ExpiresAt: issuedAt + int64(googleServiceAccountAssertionTTL/time.Second),
		IssuedAt: issuedAt, Issuer: source.clientEmail, Scope: googlePlayIntegrityScope,
	})
	if err != nil {
		return "", ErrConfiguration
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, source.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", ErrPlayIntegrityService
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseGoogleServiceAccountPrivateKey(encoded []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 ||
		len(block.Bytes) == 0 || len(block.Bytes) > 16<<10 {
		return nil, ErrInvalid
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalid
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok || privateKey.N == nil || privateKey.N.BitLen() < 2048 || privateKey.N.BitLen() > 8192 ||
		privateKey.E != 65537 || privateKey.Validate() != nil {
		return nil, ErrInvalid
	}
	return privateKey, nil
}

func parseGoogleAccessTokenResponse(encoded []byte, now time.Time) (PlayIntegrityAccessToken, error) {
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return PlayIntegrityAccessToken{}, ErrInvalid
	}
	response, ok := value.(map[string]any)
	if !ok || len(response) == 0 || len(response) > 8 {
		return PlayIntegrityAccessToken{}, ErrInvalid
	}
	accessToken, tokenOK := stringMember(response, "access_token", 16, maxPlayIntegrityAccessTokenBytes)
	tokenType, typeOK := stringMember(response, "token_type", 1, 32)
	expiresNumber, expiresOK := response["expires_in"].(json.Number)
	if !tokenOK || !typeOK || tokenType != "Bearer" || !expiresOK {
		return PlayIntegrityAccessToken{}, ErrInvalid
	}
	expiresIn, err := strconv.ParseInt(string(expiresNumber), 10, 64)
	if err != nil || expiresIn < 60 || expiresIn > 24*60*60 {
		return PlayIntegrityAccessToken{}, ErrInvalid
	}
	token := PlayIntegrityAccessToken{
		Value: accessToken, ExpiresAt: now.Add(time.Duration(expiresIn) * time.Second).UTC(),
	}
	if !validPlayIntegrityAccessToken(token, now) {
		return PlayIntegrityAccessToken{}, ErrInvalid
	}
	return token, nil
}

func (GoogleServiceAccountTokenSource) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "GoogleServiceAccountTokenSource{[REDACTED]}")
}

func (GoogleServiceAccountTokenSource) LogValue() slog.Value {
	return slog.StringValue("GoogleServiceAccountTokenSource{[REDACTED]}")
}

var _ PlayIntegrityAccessTokenSource = (*GoogleServiceAccountTokenSource)(nil)
