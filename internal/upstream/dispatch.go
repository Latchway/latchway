package upstream

import (
	"context"
	"encoding/base64"
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
	return target.dispatch(ctx, prepared, nil)
}

// DispatchWithBeforeRoundTrip sends a prepared request without authentication
// after beforeRoundTrip succeeds. The callback runs exactly once after the
// prepared request is claimed and revalidated, immediately before
// http.Client.Do. The caller owns the returned response and must close it.
func (target *Target) DispatchWithBeforeRoundTrip(
	ctx context.Context,
	prepared PreparedRequest,
	beforeRoundTrip func() error,
) (*DispatchedResponse, error) {
	if beforeRoundTrip == nil {
		return nil, errors.New("invalid before-round-trip callback")
	}
	return target.dispatch(ctx, prepared, beforeRoundTrip)
}

func (target *Target) dispatch(
	ctx context.Context,
	prepared PreparedRequest,
	beforeRoundTrip func() error,
) (*DispatchedResponse, error) {
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

	dispatched, err := target.roundTrip(outbound, outbound.Clone(outbound.Context()), cancelRoundTrip, beforeRoundTrip)
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
	return target.withCredentialDispatch(ctx, prepared, nil, consume, func(headers http.Header, operation func() error) error {
		return withBearerCredential(headers, credential, operation)
	})
}

// WithBearerDispatchWithBeforeRoundTrip is WithBearerDispatch with an
// additional callback that runs exactly once after the bearer credential is
// validated and injected, immediately before http.Client.Do. A callback error
// prevents the RoundTrip and the credential is still removed.
func (target *Target) WithBearerDispatchWithBeforeRoundTrip(
	ctx context.Context,
	prepared PreparedRequest,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*DispatchedResponse) error,
) error {
	if beforeRoundTrip == nil {
		return errors.New("invalid before-round-trip callback")
	}
	return target.withCredentialDispatch(ctx, prepared, beforeRoundTrip, consume, func(headers http.Header, operation func() error) error {
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
	return target.withCredentialDispatch(ctx, prepared, nil, consume, func(headers http.Header, operation func() error) error {
		return withHeaderCredential(headers, name, credential, operation)
	})
}

// WithHeaderDispatchWithBeforeRoundTrip is WithHeaderDispatch with an
// additional callback that runs exactly once after the fixed-header credential
// is validated and injected, immediately before http.Client.Do. A callback
// error prevents the RoundTrip and the credential is still removed.
func (target *Target) WithHeaderDispatchWithBeforeRoundTrip(
	ctx context.Context,
	prepared PreparedRequest,
	name string,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*DispatchedResponse) error,
) error {
	if beforeRoundTrip == nil {
		return errors.New("invalid before-round-trip callback")
	}
	return target.withCredentialDispatch(ctx, prepared, beforeRoundTrip, consume, func(headers http.Header, operation func() error) error {
		return withHeaderCredential(headers, name, credential, operation)
	})
}

// WithBasicDispatch sends a prepared request with one scoped HTTP Basic
// credential. The consumer must inspect and relay the response synchronously.
func (target *Target) WithBasicDispatch(
	ctx context.Context,
	prepared PreparedRequest,
	username string,
	password []byte,
	consume func(*DispatchedResponse) error,
) error {
	return target.withCredentialDispatch(ctx, prepared, nil, consume, func(headers http.Header, operation func() error) error {
		return withBasicCredential(headers, username, password, operation)
	})
}

// WithBasicDispatchWithBeforeRoundTrip sends a prepared request with one
// scoped HTTP Basic credential. The password remains inside the caller's
// secret-use callback, and the derived Authorization value is removed only
// after the response body has been closed.
func (target *Target) WithBasicDispatchWithBeforeRoundTrip(
	ctx context.Context,
	prepared PreparedRequest,
	username string,
	password []byte,
	beforeRoundTrip func() error,
	consume func(*DispatchedResponse) error,
) error {
	if beforeRoundTrip == nil {
		return errors.New("invalid before-round-trip callback")
	}
	return target.withCredentialDispatch(ctx, prepared, beforeRoundTrip, consume, func(headers http.Header, operation func() error) error {
		return withBasicCredential(headers, username, password, operation)
	})
}

// HeaderCredential is one fixed header and its scoped secret value. Callers
// must not retain values after WithHeadersDispatchWithBeforeRoundTrip returns.
type HeaderCredential struct {
	Name  string
	Value []byte
}

// WithHeadersDispatch sends a prepared request with between one and eight
// independently configured credential headers. The consumer must inspect and
// relay the response synchronously.
func (target *Target) WithHeadersDispatch(
	ctx context.Context,
	prepared PreparedRequest,
	credentials []HeaderCredential,
	consume func(*DispatchedResponse) error,
) error {
	return target.withCredentialDispatch(ctx, prepared, nil, consume, func(headers http.Header, operation func() error) error {
		return withHeaderCredentials(headers, credentials, operation)
	})
}

// WithHeadersDispatchWithBeforeRoundTrip applies between one and eight
// independently configured credential headers for exactly one synchronous
// dispatch/consume operation.
func (target *Target) WithHeadersDispatchWithBeforeRoundTrip(
	ctx context.Context,
	prepared PreparedRequest,
	credentials []HeaderCredential,
	beforeRoundTrip func() error,
	consume func(*DispatchedResponse) error,
) error {
	if beforeRoundTrip == nil {
		return errors.New("invalid before-round-trip callback")
	}
	return target.withCredentialDispatch(ctx, prepared, beforeRoundTrip, consume, func(headers http.Header, operation func() error) error {
		return withHeaderCredentials(headers, credentials, operation)
	})
}

type credentialScope func(http.Header, func() error) error

func (target *Target) withCredentialDispatch(
	ctx context.Context,
	prepared PreparedRequest,
	beforeRoundTrip func() error,
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
		dispatched, err := target.roundTrip(outbound, responseRequest, cancelRoundTrip, beforeRoundTrip)
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
	beforeRoundTrip func() error,
) (*DispatchedResponse, error) {
	clientOwnsRequestBody := false
	defer func() {
		if !clientOwnsRequestBody && !nilInterface(outbound.Body) {
			_ = outbound.Body.Close()
		}
	}()
	if err := outbound.Context().Err(); err != nil {
		cancelRoundTrip()
		return nil, fmt.Errorf("upstream dispatch context: %w", err)
	}
	if beforeRoundTrip != nil {
		if err := beforeRoundTrip(); err != nil {
			cancelRoundTrip()
			return nil, fmt.Errorf("before upstream round trip: %w", err)
		}
	}
	clientOwnsRequestBody = true
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

func withBasicCredential(headers http.Header, username string, password []byte, operation func() error) error {
	if headers == nil || operation == nil || len(headerValues(headers, "Authorization")) != 0 ||
		!validBasicUsername(username) || len(password) == 0 || len(password) > maximumForwardedHeaderBytes {
		return errors.New("invalid basic credential scope")
	}
	plainLength := len(username) + 1 + len(password)
	if base64.StdEncoding.EncodedLen(plainLength) > maximumForwardedHeaderBytes-len("Basic ") {
		return errors.New("invalid basic credential scope")
	}
	plain := make([]byte, 0, plainLength)
	plain = append(plain, username...)
	plain = append(plain, ':')
	plain = append(plain, password...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plain)))
	base64.StdEncoding.Encode(encoded, plain)
	for index := range plain {
		plain[index] = 0
	}
	headers.Set("Authorization", "Basic "+string(encoded))
	defer func() {
		headers.Del("Authorization")
		for index := range encoded {
			encoded[index] = 0
		}
	}()
	return operation()
}

func withHeaderCredentials(headers http.Header, credentials []HeaderCredential, operation func() error) error {
	if headers == nil || operation == nil || len(credentials) < 1 || len(credentials) > 8 {
		return errors.New("invalid header credential scope")
	}
	canonicalNames := make([]string, len(credentials))
	seen := make(map[string]struct{}, len(credentials))
	totalBytes := 0
	for index, credential := range credentials {
		canonical := http.CanonicalHeaderKey(credential.Name)
		totalBytes += len(canonical) + len(credential.Value)
		if strings.TrimSpace(credential.Name) != credential.Name || !validHeaderName(credential.Name) ||
			isForbiddenCredentialHeader(canonical) || len(headerValues(headers, canonical)) != 0 ||
			!validHeaderCredential(credential.Value) || totalBytes > maximumForwardedHeaderBytes {
			return errors.New("invalid header credential scope")
		}
		if _, duplicate := seen[canonical]; duplicate {
			return errors.New("invalid header credential scope")
		}
		seen[canonical] = struct{}{}
		canonicalNames[index] = canonical
	}
	for index, credential := range credentials {
		headers.Set(canonicalNames[index], string(credential.Value))
	}
	defer func() {
		for _, name := range canonicalNames {
			headers.Del(name)
		}
	}()
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
