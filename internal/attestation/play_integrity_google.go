package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	googlePlayIntegrityEndpoint       = "https://playintegrity.googleapis.com"
	googlePlayIntegrityScope          = "https://www.googleapis.com/auth/playintegrity"
	defaultPlayIntegrityDecodeTimeout = 10 * time.Second
	maximumPlayIntegrityDecodeTimeout = 30 * time.Second
	maxPlayIntegrityAccessTokenBytes  = 16 << 10
)

var ErrPlayIntegrityTokenRejected = errors.New("play integrity token was rejected")

// PlayIntegrityAccessToken is redacted across formatting, JSON, text, and
// structured logging boundaries. An expiry is mandatory so a decoder never
// knowingly dispatches an expired bearer credential.
type PlayIntegrityAccessToken struct {
	Value     string
	ExpiresAt time.Time
}

func (PlayIntegrityAccessToken) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func (PlayIntegrityAccessToken) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

func (PlayIntegrityAccessToken) MarshalText() ([]byte, error) {
	return []byte("[REDACTED]"), nil
}

func (PlayIntegrityAccessToken) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

type PlayIntegrityAccessTokenSource interface {
	AccessToken(context.Context) (PlayIntegrityAccessToken, error)
}

type GooglePlayIntegrityDecoderConfig struct {
	CloudProjectNumber int64
	TokenSource        PlayIntegrityAccessTokenSource
	Transport          http.RoundTripper
	Timeout            time.Duration
	Now                func() time.Time
}

// GooglePlayIntegrityDecoder calls only Google's fixed v1 decode endpoint,
// uses an Authorization header (never a query credential), rejects redirects,
// and bounds both request time and response bytes.
type GooglePlayIntegrityDecoder struct {
	cloudProjectNumber int64
	tokenSource        PlayIntegrityAccessTokenSource
	client             *http.Client
	endpoint           *url.URL
	timeout            time.Duration
	now                func() time.Time
}

func NewGooglePlayIntegrityDecoder(
	config GooglePlayIntegrityDecoderConfig,
) (*GooglePlayIntegrityDecoder, error) {
	endpoint, err := url.Parse(googlePlayIntegrityEndpoint)
	if err != nil {
		return nil, ErrConfiguration
	}
	return newGooglePlayIntegrityDecoder(config, endpoint)
}

func newGooglePlayIntegrityDecoder(
	config GooglePlayIntegrityDecoderConfig,
	endpoint *url.URL,
) (*GooglePlayIntegrityDecoder, error) {
	if config.CloudProjectNumber <= 0 || nilPlayIntegrityDependency(config.TokenSource) ||
		(config.Transport != nil && nilPlayIntegrityDependency(config.Transport)) || endpoint == nil ||
		(endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.Host == "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return nil, ErrConfiguration
	}
	if config.Timeout == 0 {
		config.Timeout = defaultPlayIntegrityDecodeTimeout
	}
	if config.Timeout < time.Second || config.Timeout > maximumPlayIntegrityDecodeTimeout {
		return nil, ErrConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	transport := config.Transport
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
	ownedEndpoint.Path = strings.TrimSuffix(endpoint.Path, "/")
	ownedEndpoint.RawPath = ""
	return &GooglePlayIntegrityDecoder{
		cloudProjectNumber: config.CloudProjectNumber, tokenSource: config.TokenSource,
		client: client, endpoint: &ownedEndpoint, timeout: config.Timeout, now: config.Now,
	}, nil
}

func (decoder *GooglePlayIntegrityDecoder) CloudProjectNumber() int64 {
	if decoder == nil {
		return 0
	}
	return decoder.cloudProjectNumber
}

func (decoder *GooglePlayIntegrityDecoder) DecodeIntegrityToken(
	ctx context.Context,
	packageName string,
	integrityToken string,
) ([]byte, error) {
	if decoder == nil || ctx == nil || !validPlayIntegrityPackage(packageName) ||
		len(integrityToken) < 16 || len(integrityToken) > maxPlayIntegrityTokenBytes ||
		!playIntegrityTokenPattern.MatchString(integrityToken) {
		return nil, ErrPlayIntegrityService
	}
	if decoder.client == nil || decoder.endpoint == nil || decoder.now == nil ||
		nilPlayIntegrityDependency(decoder.tokenSource) || decoder.timeout <= 0 {
		return nil, ErrPlayIntegrityService
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	access, err := decoder.tokenSource.AccessToken(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrPlayIntegrityService
	}
	now := decoder.now().UTC()
	if !validPlayIntegrityAccessToken(access, now) {
		return nil, ErrPlayIntegrityService
	}
	body, err := json.Marshal(map[string]string{"integrityToken": integrityToken})
	if err != nil {
		return nil, ErrPlayIntegrityService
	}
	requestContext, cancel := context.WithTimeout(ctx, decoder.timeout)
	defer cancel()
	endpoint := *decoder.endpoint
	basePath := strings.TrimSuffix(endpoint.Path, "/")
	endpoint.Path = basePath + "/v1/" + url.PathEscape(packageName) + ":decodeIntegrityToken"
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, endpoint.String(), bytes.NewReader(body),
	)
	if err != nil {
		return nil, ErrPlayIntegrityService
	}
	request.Header.Set("Authorization", "Bearer "+access.Value)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway/play-integrity-v1")
	response, err := decoder.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if contextErr := requestContext.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, ErrPlayIntegrityService
	}
	if response == nil || response.Body == nil {
		return nil, ErrPlayIntegrityService
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, maxPlayIntegrityDecodedBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(encoded) > maxPlayIntegrityDecodedBytes {
		return nil, ErrPlayIntegrityService
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusBadRequest {
			return nil, ErrPlayIntegrityTokenRejected
		}
		return nil, ErrPlayIntegrityService
	}
	mediaType, _, contentTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if contentTypeErr != nil || mediaType != "application/json" {
		return nil, ErrPlayIntegrityService
	}
	if _, err := jsonsafe.Decode(encoded); err != nil {
		return nil, ErrPlayIntegrityService
	}
	if err := requestContext.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), encoded...), nil
}

func validPlayIntegrityAccessToken(token PlayIntegrityAccessToken, now time.Time) bool {
	if now.IsZero() || len(token.Value) < 16 || len(token.Value) > maxPlayIntegrityAccessTokenBytes ||
		token.ExpiresAt.IsZero() || !token.ExpiresAt.After(now.Add(5*time.Second)) {
		return false
	}
	for _, character := range token.Value {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func (GooglePlayIntegrityDecoder) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "GooglePlayIntegrityDecoder{[REDACTED]}")
}

func (GooglePlayIntegrityDecoder) LogValue() slog.Value {
	return slog.StringValue("GooglePlayIntegrityDecoder{[REDACTED]}")
}

var _ PlayIntegrityTokenDecoder = (*GooglePlayIntegrityDecoder)(nil)
