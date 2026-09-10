package attestation

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"cloud.google.com/go/compute/metadata"
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
	*googleTokenSource
	client *http.Client
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
		Transport: &googleTokenTransport{base: transport, endpoint: *endpoint, metadata: true},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	metadataClient := metadata.NewWithOptions(&metadata.Options{
		Client: client, Logger: slog.New(slog.DiscardHandler),
	})
	return &GoogleMetadataTokenSource{
		client: client,
		googleTokenSource: newGoogleTokenSource(options.Timeout, options.Now,
			func(ctx context.Context, now time.Time) (PlayIntegrityAccessToken, error) {
				encoded, err := metadataClient.GetWithContext(ctx,
					"instance/service-accounts/default/token?"+googleMetadataTokenQuery)
				if err != nil {
					return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
				}
				return parseGoogleAccessTokenResponse([]byte(encoded), now)
			}),
	}, nil
}

func (source *GoogleMetadataTokenSource) AccessToken(
	ctx context.Context,
) (PlayIntegrityAccessToken, error) {
	if source == nil {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	return source.googleTokenSource.AccessToken(ctx)
}

func (GoogleMetadataTokenSource) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "GoogleMetadataTokenSource{[REDACTED]}")
}

func (GoogleMetadataTokenSource) LogValue() slog.Value {
	return slog.StringValue("GoogleMetadataTokenSource{[REDACTED]}")
}

var _ PlayIntegrityAccessTokenSource = (*GoogleMetadataTokenSource)(nil)
