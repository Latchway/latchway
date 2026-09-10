package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

// googleTokenSource retains only Latchway's cancellation and lifetime policy.
// Google's blocking cache uses a non-cancellable mutex and a fixed early-expiry
// check; using it would change the public token source's existing guarantees.
type googleTokenSource struct {
	load    func(context.Context, time.Time) (PlayIntegrityAccessToken, error)
	timeout time.Duration
	now     func() time.Time
	gate    chan struct{}
	cached  PlayIntegrityAccessToken
}

func newGoogleTokenSource(timeout time.Duration, now func() time.Time,
	load func(context.Context, time.Time) (PlayIntegrityAccessToken, error),
) *googleTokenSource {
	return &googleTokenSource{load: load, timeout: timeout, now: now, gate: make(chan struct{}, 1)}
}

func (source *googleTokenSource) AccessToken(ctx context.Context) (PlayIntegrityAccessToken, error) {
	if source == nil || ctx == nil || source.load == nil || source.now == nil || source.gate == nil || source.timeout <= 0 {
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
	if err := ctx.Err(); err != nil {
		return PlayIntegrityAccessToken{}, err
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
	token, err := source.load(requestContext, now)
	if contextErr := requestContext.Err(); contextErr != nil {
		return PlayIntegrityAccessToken{}, contextErr
	}
	if err != nil || !validPlayIntegrityAccessToken(token, now) {
		return PlayIntegrityAccessToken{}, ErrPlayIntegrityService
	}
	source.cached = token
	return token, nil
}

// googleTokenTransport constrains the otherwise general-purpose Google clients
// to the existing endpoint, response bounds, and access-token-only semantics.
// Its errors never contain request credentials or provider response bodies.
type googleTokenTransport struct {
	base     http.RoundTripper
	endpoint url.URL
	metadata bool
}

func (transport *googleTokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	request = request.Clone(request.Context())
	if transport.metadata {
		// The metadata library supports GCE_METADATA_HOST for emulation. This
		// deployment boundary deliberately does not: pin the complete request
		// before dispatch, including scope, host, and credentials-free headers.
		if request.Method != http.MethodGet {
			return nil, ErrPlayIntegrityService
		}
		endpoint := transport.endpoint
		request.URL, request.Host = &endpoint, ""
		request.Header.Del("Authorization")
	} else if request.URL.String() != transport.endpoint.String() || request.Method != http.MethodPost {
		return nil, ErrPlayIntegrityService
	}
	request.Header.Set("Accept", "application/json")
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrPlayIntegrityService
	}
	if response == nil || response.Body == nil {
		return nil, ErrPlayIntegrityService
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, maximumGoogleTokenResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(encoded) > maximumGoogleTokenResponseBytes ||
		response.StatusCode != http.StatusOK ||
		(transport.metadata && response.Header.Get(googleMetadataFlavorHeader) != googleMetadataFlavorExpectedValue) {
		return nil, ErrPlayIntegrityService
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, ErrPlayIntegrityService
	}
	epoch := time.Unix(0, 0).UTC()
	token, err := parseGoogleAccessTokenResponse(encoded, epoch)
	if err != nil {
		return nil, ErrPlayIntegrityService
	}
	// Do not let optional id_token or future Google response fields switch
	// the library into ID-token processing or override the access-token expiry.
	encoded, err = json.Marshal(struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}{token.Value, int64(token.ExpiresAt.Sub(epoch) / time.Second), "Bearer"})
	if err != nil {
		return nil, ErrPlayIntegrityService
	}
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(encoded))
	response.ContentLength = int64(len(encoded))
	response.Header.Del("Content-Length")
	return response, nil
}
