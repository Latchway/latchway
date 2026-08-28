package attestation

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	googleMetadataTokenPath           = "/computeMetadata/v1/instance/service-accounts/default/token"
	googleMetadataTokenQuery          = "enforce_scopes=true&scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fplayintegrity"
	googleMetadataTokenEndpoint       = "http://metadata.google.internal" + googleMetadataTokenPath + "?" + googleMetadataTokenQuery
	defaultGoogleMetadataTimeout      = 2 * time.Second
	maximumGoogleMetadataTimeout      = 10 * time.Second
	googleMetadataFlavorHeader        = "Metadata-Flavor"
	googleMetadataFlavorExpectedValue = "Google"
)

type GoogleMetadataTokenSourceOptions struct {
	Transport http.RoundTripper
	Timeout   time.Duration
	Now       func() time.Time
}

// GoogleMetadataTokenSource obtains short-lived OAuth credentials from the
// fixed Google Cloud metadata endpoint. It is suitable for Cloud Run and other
// Google Cloud workloads with an attached service identity, avoiding a stored
// service-account private key.
type GoogleMetadataTokenSource struct {
	client   *http.Client
	endpoint *url.URL
	timeout  time.Duration
	now      func() time.Time
	gate     chan struct{}
	cached   PlayIntegrityAccessToken
}

func NewGoogleMetadataTokenSource(
	options GoogleMetadataTokenSourceOptions,
) (*GoogleMetadataTokenSource, error) {
	endpoint, err := url.Parse(googleMetadataTokenEndpoint)
	if err != nil {
		return nil, ErrConfiguration
	}
	return newGoogleMetadataTokenSource(options, endpoint)
}

func newGoogleMetadataTokenSource(
	options GoogleMetadataTokenSourceOptions,
	endpoint *url.URL,
) (*GoogleMetadataTokenSource, error) {
	if endpoint == nil || endpoint.Scheme != "http" || endpoint.Host != "metadata.google.internal" ||
		endpoint.User != nil || endpoint.Path != googleMetadataTokenPath || endpoint.RawPath != "" ||
		endpoint.RawQuery != googleMetadataTokenQuery || endpoint.Fragment != "" ||
		(options.Transport != nil && nilPlayIntegrityDependency(options.Transport)) {
		return nil, ErrConfiguration
	}
	if options.Timeout == 0 {
		options.Timeout = defaultGoogleMetadataTimeout
	}
	if options.Timeout < 250*time.Millisecond || options.Timeout > maximumGoogleMetadataTimeout {
		return nil, ErrConfiguration
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	transport := options.Transport
	if transport == nil {
		// The metadata endpoint is intentionally plaintext and link-local. Never
		// honor HTTP_PROXY/ProxyFromEnvironment for its bearer-token response.
		dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
		transport = &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext,
			MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ownedEndpoint := *endpoint
	return &GoogleMetadataTokenSource{
		client: client, endpoint: &ownedEndpoint, timeout: options.Timeout,
		now: options.Now, gate: make(chan struct{}, 1),
	}, nil
}

func (source *GoogleMetadataTokenSource) AccessToken(
	ctx context.Context,
) (PlayIntegrityAccessToken, error) {
	if source == nil || ctx == nil || source.client == nil || source.endpoint == nil ||
		source.now == nil || source.gate == nil || source.timeout <= 0 {
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
	requestContext, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodGet, source.endpoint.String(), nil,
	)
	if err != nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	request.Header.Set(googleMetadataFlavorHeader, googleMetadataFlavorExpectedValue)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway/google-metadata-v1")
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
	if readErr != nil || len(encoded) > maximumGoogleTokenResponseBytes ||
		response.StatusCode != http.StatusOK ||
		response.Header.Get(googleMetadataFlavorHeader) != googleMetadataFlavorExpectedValue {
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

func (GoogleMetadataTokenSource) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "GoogleMetadataTokenSource{[REDACTED]}")
}

func (GoogleMetadataTokenSource) LogValue() slog.Value {
	return slog.StringValue("GoogleMetadataTokenSource{[REDACTED]}")
}

var _ PlayIntegrityAccessTokenSource = (*GoogleMetadataTokenSource)(nil)
