package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// DispatchedResponse owns the response body and dedicated cancellation
// capability for exactly one upstream RoundTrip. RelayResponse consumes this
// type so a handler-wide or total-request cancel function cannot accidentally
// be used for transport cleanup after a successful relay.
type DispatchedResponse struct {
	*http.Response
	body   *onceReadCloser
	cancel context.CancelFunc
}

// Close aborts the exact RoundTrip and closes its original response body.
// Callers use this when protocol validation fails before RelayResponse takes
// ownership. Both operations are idempotent.
func (response *DispatchedResponse) Close() error {
	if response == nil {
		return nil
	}
	if response.cancel != nil {
		response.cancel()
	}
	if response.body == nil {
		return nil
	}
	return response.body.Close()
}

// Dispatch sends a prepared request without authentication. The caller owns
// the returned response and must close it.
func (target *Target) Dispatch(ctx context.Context, prepared PreparedRequest) (*DispatchedResponse, error) {
	outbound, cancelRoundTrip, err := target.outboundRequest(ctx, prepared)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			cancelRoundTrip()
		}
	}()

	dispatched, err := target.roundTrip(outbound, outbound.Clone(outbound.Context()), cancelRoundTrip)
	if err != nil {
		return nil, err
	}
	owned = true
	return dispatched, nil
}

// WithBearerDispatch sends a prepared request with a scoped Authorization
// credential. The consumer must inspect and relay the response synchronously.
// The exact response body is closed before the credential is removed, which is
// required because a RoundTripper may retain request fields until Body.Close.
func (target *Target) WithBearerDispatch(
	ctx context.Context,
	prepared PreparedRequest,
	credential []byte,
	consume func(*DispatchedResponse) error,
) error {
	return target.withCredentialDispatch(ctx, prepared, consume, func(headers http.Header, operation func() error) error {
		return withBearerCredential(headers, credential, operation)
	})
}

// WithHeaderDispatch is the fixed-header equivalent of WithBearerDispatch.
func (target *Target) WithHeaderDispatch(
	ctx context.Context,
	prepared PreparedRequest,
	name string,
	credential []byte,
	consume func(*DispatchedResponse) error,
) error {
	return target.withCredentialDispatch(ctx, prepared, consume, func(headers http.Header, operation func() error) error {
		return withHeaderCredential(headers, name, credential, operation)
	})
}

type credentialScope func(http.Header, func() error) error

func (target *Target) withCredentialDispatch(
	ctx context.Context,
	prepared PreparedRequest,
	consume func(*DispatchedResponse) error,
	credential credentialScope,
) error {
	if consume == nil || credential == nil {
		return errors.New("invalid scoped upstream dispatch")
	}
	outbound, cancelRoundTrip, err := target.outboundRequest(ctx, prepared)
	if err != nil {
		return err
	}
	defer cancelRoundTrip()
	responseRequest := outbound.Clone(outbound.Context())

	return credential(outbound.Header, func() (resultErr error) {
		dispatched, err := target.roundTrip(outbound, responseRequest, cancelRoundTrip)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := dispatched.Close(); resultErr == nil && closeErr != nil {
				resultErr = fmt.Errorf("close upstream response: %w", closeErr)
			}
		}()
		return consume(dispatched)
	})
}

func (target *Target) outboundRequest(
	ctx context.Context,
	prepared PreparedRequest,
) (*http.Request, context.CancelFunc, error) {
	if nilInterface(ctx) {
		return nil, nil, errors.New("invalid upstream dispatch context")
	}
	if err := target.claimPreparedRequest(prepared); err != nil {
		return nil, nil, err
	}

	roundTripContext, cancelRoundTrip := context.WithCancel(ctx)
	cancelOnce := sync.OnceFunc(cancelRoundTrip)
	outbound := prepared.request.Clone(roundTripContext)
	if err := target.validatePreparedRequest(PreparedRequest{target: target, request: outbound, state: prepared.state}); err != nil {
		cancelOnce()
		return nil, nil, err
	}
	return outbound, cancelOnce, nil
}

func (target *Target) roundTrip(
	outbound *http.Request,
	responseRequest *http.Request,
	cancelRoundTrip context.CancelFunc,
) (*DispatchedResponse, error) {
	response, err := target.client.Do(outbound)
	if err != nil {
		cancelRoundTrip()
		if response != nil && !nilInterface(response.Body) {
			_ = response.Body.Close()
		}
		return nil, err
	}
	if response == nil || nilInterface(response.Body) {
		cancelRoundTrip()
		return nil, errors.New("upstream transport returned an invalid response")
	}
	body := &onceReadCloser{ReadCloser: response.Body}
	response.Body = body
	response.Request = responseRequest
	return &DispatchedResponse{Response: response, body: body, cancel: cancelRoundTrip}, nil
}

func withBearerCredential(headers http.Header, credential []byte, operation func() error) error {
	if headers == nil || operation == nil || len(headerValues(headers, "Authorization")) != 0 || !validBearerCredential(credential) {
		return errors.New("invalid bearer credential scope")
	}
	headers.Set("Authorization", "Bearer "+string(credential))
	defer headers.Del("Authorization")
	return operation()
}

func requestContainsCredential(headers http.Header) bool {
	for _, name := range credentialHeaderNames {
		if len(headerValues(headers, name)) != 0 {
			return true
		}
	}
	return false
}

var credentialHeaderNames = [...]string{
	"Authorization", "Proxy-Authorization", "Dpop", "Dpop-Nonce", "Cookie",
	"X-Api-Key", "Api-Key", "Openai-Api-Key", "Openai-Organization",
	"Anthropic-Api-Key", "X-Goog-Api-Key", "X-Auth-Token",
}

func withHeaderCredential(headers http.Header, name string, credential []byte, operation func() error) error {
	canonical := http.CanonicalHeaderKey(name)
	if headers == nil || operation == nil || strings.TrimSpace(name) != name || !validHeaderName(name) ||
		isForbiddenCredentialHeader(canonical) || len(headerValues(headers, canonical)) != 0 || !validHeaderCredential(credential) {
		return errors.New("invalid header credential scope")
	}
	headers.Set(canonical, string(credential))
	defer headers.Del(canonical)
	return operation()
}
