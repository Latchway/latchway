package attestation

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"cloud.google.com/go/auth"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	googleOAuthTokenEndpoint         = "https://oauth2.googleapis.com/token"
	googleServiceAccountGrantType    = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultGoogleTokenRequestTimeout = 10 * time.Second
	maximumGoogleTokenRequestTimeout = 30 * time.Second
	maximumServiceAccountJSONBytes   = 64 << 10
	maximumGoogleTokenResponseBytes  = 32 << 10
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
	*googleTokenSource
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
	_, err = parseGoogleServiceAccountPrivateKey([]byte(privateKeyPEM))
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
		Transport: &googleTokenTransport{base: transport, endpoint: *endpoint},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// Use the explicit 2LO provider, not ambient credential discovery. The typed
	// JSON loader also installs a cache whose clock/cancellation/refresh behavior
	// differs from this boundary. Only the validated service-account fields are
	// passed to Google; credential JSON cannot enable delegation or other flows.
	provider, err := auth.New2LOTokenProvider(&auth.Options2LO{
		Email: clientEmail, PrivateKeyID: privateKeyID, PrivateKey: []byte(privateKeyPEM),
		TokenURL: endpoint.String(), Scopes: []string{googlePlayIntegrityScope},
		Client: client, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, ErrConfiguration
	}
	return &GoogleServiceAccountTokenSource{googleTokenSource: newGoogleTokenSource(
		options.Timeout, options.Now,
		func(ctx context.Context, now time.Time) (PlayIntegrityAccessToken, error) {
			token, err := provider.Token(ctx)
			if err != nil || token == nil {
				return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
			}
			// The bounded transport normalizes expires_in to an integer in [60,
			// 86400]. Keep expiry anchored to the start of the request, including
			// the injectable policy clock, rather than extending it by HTTP latency.
			seconds, ok := token.Metadata["expires_in"].(float64)
			if !ok || seconds < 60 || seconds > 86400 || seconds != float64(int64(seconds)) {
				return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
			}
			return PlayIntegrityAccessToken{
				Value: token.Value, ExpiresAt: now.Add(time.Duration(seconds) * time.Second),
			}, nil
		},
	)}, nil
}

func (source *GoogleServiceAccountTokenSource) AccessToken(
	ctx context.Context,
) (PlayIntegrityAccessToken, error) {
	if source == nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	return source.googleTokenSource.AccessToken(ctx)
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
