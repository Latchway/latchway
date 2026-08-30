package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/latchway/latchway/internal/protocol"
)

const (
	relayBufferBytes         = 32 << 10
	maximumResponseHeaders   = 128
	maximumResponseHeadBytes = 64 << 10
	maximumProvenanceBytes   = 64
)

var (
	// ErrInvalidResponseRelay indicates that relay inputs or upstream response
	// metadata cannot be used safely.
	ErrInvalidResponseRelay = errors.New("invalid upstream response relay")
	// ErrResponseIdleTimeout indicates that no upstream body progress occurred
	// before the configured stream idle deadline.
	ErrResponseIdleTimeout = errors.New("upstream response idle timeout")
	// ErrResponseFirstByteTimeout indicates that response headers arrived but
	// the upstream did not produce its first body byte before the configured
	// deadline. It is distinct from both response-header and stream-idle waits.
	ErrResponseFirstByteTimeout = errors.New("upstream response first byte timeout")
	// ErrResponseBodyTooLarge indicates that the upstream body exceeded the
	// administrator-owned response limit. A streaming response may already have
	// started when an unknown-length body crosses the limit.
	ErrResponseBodyTooLarge = errors.New("upstream response body exceeds limit")
	// ErrUpstreamNonSuccess indicates that an upstream returned a non-2xx
	// response. Provider-controlled error bodies are never relayed; the caller
	// must map this error to a canonical Latchway problem response.
	ErrUpstreamNonSuccess = errors.New("upstream returned a non-success response")
)

// ResponseRelayConfig controls one response stream. Every limit is required.
// The exact RoundTrip cancellation capability is carried by DispatchedResponse
// and cannot be substituted with a handler-wide context cancel function.
// OnFirstByte, when set, runs exactly once immediately before the response is
// committed for a non-empty body.
type ResponseRelayConfig struct {
	FirstByteTimeout   time.Duration
	IdleTimeout        time.Duration
	ClientWriteTimeout time.Duration
	MaxBodyBytes       int64
	OnFirstByte        func(context.Context) error
}

// RelayOutcome describes bytes accepted by the client writer and normalized
// protocol usage. BodyBytes never includes bytes rejected by the client.
type RelayOutcome struct {
	StatusCode    int
	BodyBytes     int64
	ClientStarted bool
	Usage         protocol.Usage
}

// NormalizeResponseStatus applies the production provider-status boundary
// without reading a provider-controlled response body. Non-2xx responses are
// classified as ErrUpstreamNonSuccess; invalid HTTP response statuses are
// classified as ErrInvalidResponseRelay.
func NormalizeResponseStatus(statusCode int) error {
	if statusCode < http.StatusOK || statusCode > 599 {
		return ErrInvalidResponseRelay
	}
	if statusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: status %d", ErrUpstreamNonSuccess, statusCode)
	}
	return nil
}

// RelayResponse streams one upstream response to a client. It deliberately
// owns no retry, fallback, routing, or quota policy. The caller decides how to
// handle an error based on ClientStarted.
func RelayResponse(
	ctx context.Context,
	destination http.ResponseWriter,
	dispatched *DispatchedResponse,
	observer protocol.ResponseObserver,
	config ResponseRelayConfig,
) (outcome RelayOutcome, relayErr error) {
	var response *http.Response
	var body *onceReadCloser
	if dispatched != nil {
		response = dispatched.Response
		body = dispatched.body
	}
	if response != nil {
		outcome.StatusCode = response.StatusCode
	}

	if body != nil {
		defer func() {
			if err := body.Close(); relayErr == nil && err != nil {
				relayErr = fmt.Errorf("close upstream response body: %w", err)
			}
		}()
	}
	var cancelUpstream context.CancelFunc
	if dispatched != nil && dispatched.cancel != nil {
		cancelUpstream = dispatched.cancel
		defer cancelUpstream()
	}

	if nilInterface(ctx) || nilInterface(destination) || response == nil || body == nil ||
		response.StatusCode < http.StatusOK || response.StatusCode > 599 ||
		nilInterface(observer) || config.FirstByteTimeout < 0 || config.IdleTimeout <= 0 || config.ClientWriteTimeout <= 0 ||
		config.MaxBodyBytes <= 0 || cancelUpstream == nil {
		return outcome, ErrInvalidResponseRelay
	}
	abortUpstream := func() {
		cancelUpstream()
		_ = body.Close()
	}

	if err := NormalizeResponseStatus(response.StatusCode); err != nil {
		return outcome, err
	}
	if response.ContentLength > config.MaxBodyBytes {
		return outcome, ErrResponseBodyTooLarge
	}

	headers, eventStream, err := responseHeaders(response.Header)
	if err != nil {
		return outcome, err
	}

	buffer := make([]byte, relayBufferBytes)
	firstBytePending := true

	for {
		readTimeout := config.IdleTimeout
		timeoutError := ErrResponseIdleTimeout
		if firstBytePending {
			// A zero value preserves the bounded pre-v1 caller behavior while
			// active configuration migrates from one combined first-byte/idle
			// setting. Production route wiring supplies this explicitly.
			if config.FirstByteTimeout > 0 {
				readTimeout = config.FirstByteTimeout
			}
			timeoutError = ErrResponseFirstByteTimeout
		}
		count, readErr, waitErr := readResponseChunk(ctx, body, buffer, readTimeout, timeoutError, abortUpstream)
		if waitErr != nil {
			return outcome, waitErr
		}
		if count < 0 || count > len(buffer) || (count == 0 && readErr == nil) {
			return outcome, fmt.Errorf("%w: response body violated the reader contract", ErrInvalidResponseRelay)
		}

		if count > 0 {
			if int64(count) > config.MaxBodyBytes-outcome.BodyBytes {
				return outcome, ErrResponseBodyTooLarge
			}
			if firstBytePending {
				firstBytePending = false
				if config.OnFirstByte != nil {
					if err := config.OnFirstByte(ctx); err != nil {
						return outcome, fmt.Errorf("run upstream first-byte hook: %w", err)
					}
				}
				if err := ctx.Err(); err != nil {
					_ = body.Close()
					return outcome, err
				}
				if err := withClientWriteDeadline(ctx, destination, config.ClientWriteTimeout, func() error {
					startClientResponse(destination, headers, response.StatusCode)
					outcome.ClientStarted = true
					return nil
				}); err != nil {
					return outcome, err
				}
			}
			if err := ctx.Err(); err != nil {
				_ = body.Close()
				return outcome, err
			}

			written := 0
			writeErr := withClientWriteDeadline(ctx, destination, config.ClientWriteTimeout, func() error {
				var err error
				written, err = destination.Write(buffer[:count])
				return err
			})
			if written < 0 || written > count {
				return outcome, fmt.Errorf("%w: client writer returned an invalid byte count", ErrInvalidResponseRelay)
			}
			if written > 0 {
				outcome.BodyBytes += int64(written)
				if err := observer.Observe(buffer[:written]); err != nil {
					return outcome, fmt.Errorf("observe relayed response body: %w", err)
				}
			}
			if writeErr != nil {
				return outcome, fmt.Errorf("write relayed response body: %w", writeErr)
			}
			if written != count {
				return outcome, fmt.Errorf("write relayed response body: %w", io.ErrShortWrite)
			}
			if eventStream {
				if err := withClientWriteDeadline(ctx, destination, config.ClientWriteTimeout, func() error {
					if err := http.NewResponseController(destination).Flush(); err != nil {
						return fmt.Errorf("flush relayed event stream: %w", err)
					}
					return nil
				}); err != nil {
					return outcome, err
				}
			}
		}

		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return outcome, fmt.Errorf("read upstream response body: %w", readErr)
		}
		if errors.Is(readErr, io.EOF) {
			usage, err := observer.Finalize()
			if err != nil {
				return outcome, fmt.Errorf("finalize relayed response observation: %w", err)
			}
			usage, err = normalizedUsage(usage)
			if err != nil {
				return outcome, err
			}
			outcome.Usage = usage
			if !outcome.ClientStarted {
				if err := withClientWriteDeadline(ctx, destination, config.ClientWriteTimeout, func() error {
					startClientResponse(destination, headers, response.StatusCode)
					outcome.ClientStarted = true
					return nil
				}); err != nil {
					return outcome, err
				}
			}
			return outcome, nil
		}
	}
}

func readResponseChunk(
	ctx context.Context,
	body *onceReadCloser,
	buffer []byte,
	readTimeout time.Duration,
	timeoutError error,
	abort func(),
) (int, error, error) {
	if err := ctx.Err(); err != nil {
		abort()
		return 0, nil, err
	}

	idleExpired := false
	timerDone := make(chan struct{})
	timer := time.AfterFunc(readTimeout, func() {
		idleExpired = true
		abort()
		close(timerDone)
	})
	contextAbortDone := make(chan struct{})
	stopContextAbort := context.AfterFunc(ctx, func() {
		abort()
		close(contextAbortDone)
	})
	count, readErr := body.Read(buffer)
	if !timer.Stop() {
		<-timerDone
	}
	if !stopContextAbort() {
		<-contextAbortDone
	}
	if idleExpired {
		return 0, nil, timeoutError
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	return count, readErr, nil
}

type onceReadCloser struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (body *onceReadCloser) Close() error {
	body.once.Do(func() {
		body.err = body.ReadCloser.Close()
	})
	return body.err
}

func responseHeaders(source http.Header) (http.Header, bool, error) {
	connectionTokens := make(map[string]struct{})
	totalBytes := 0
	headerCount := 0
	for name, values := range source {
		if !validResponseHeaderName(name) {
			return nil, false, fmt.Errorf("%w: upstream response has an invalid header name", ErrInvalidResponseRelay)
		}
		headerCount++
		if headerCount > maximumResponseHeaders {
			return nil, false, fmt.Errorf("%w: upstream response has too many headers", ErrInvalidResponseRelay)
		}
		canonical := http.CanonicalHeaderKey(name)
		for _, value := range values {
			totalBytes += len(canonical) + len(value)
			if totalBytes > maximumResponseHeadBytes {
				return nil, false, fmt.Errorf("%w: upstream response headers exceed the size limit", ErrInvalidResponseRelay)
			}
			if !validResponseHeaderValue(value) {
				return nil, false, fmt.Errorf("%w: upstream response has an invalid header value", ErrInvalidResponseRelay)
			}
		}
		if canonical == "Connection" {
			for _, value := range values {
				for _, token := range strings.Split(value, ",") {
					token = strings.TrimSpace(token)
					if token == "" {
						continue
					}
					if !validResponseHeaderName(token) {
						return nil, false, fmt.Errorf("%w: upstream response has an invalid Connection token", ErrInvalidResponseRelay)
					}
					connectionTokens[http.CanonicalHeaderKey(token)] = struct{}{}
				}
			}
		}
	}

	filtered := make(http.Header)
	singletons := make(map[string]bool, 3)
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(name)
		if _, connected := connectionTokens[canonical]; connected {
			continue
		}
		switch canonical {
		case "Content-Type", "Content-Encoding", "Retry-After":
		default:
			continue
		}
		if singletons[canonical] || len(values) != 1 {
			return nil, false, fmt.Errorf("%w: upstream response has an ambiguous %s header", ErrInvalidResponseRelay, canonical)
		}
		singletons[canonical] = true
		if canonical == "Content-Encoding" {
			encoding := strings.TrimSpace(values[0])
			if encoding == "" {
				continue
			}
			if !strings.EqualFold(encoding, "identity") {
				return nil, false, fmt.Errorf("%w: upstream response body is unexpectedly encoded", ErrInvalidResponseRelay)
			}
			values = []string{"identity"}
		}
		for _, value := range values {
			filtered.Add(canonical, value)
		}
	}
	filtered.Set("Cache-Control", "no-store")

	eventStream := false
	if contentType := filtered.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil, false, fmt.Errorf("%w: upstream response has an invalid Content-Type", ErrInvalidResponseRelay)
		}
		eventStream = strings.EqualFold(mediaType, "text/event-stream")
	}
	return filtered, eventStream, nil
}

func validResponseHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			return false
		}
	}
	return true
}

func validResponseHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		if (value[index] < 0x20 && value[index] != '\t') || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func startClientResponse(destination http.ResponseWriter, headers http.Header, statusCode int) {
	target := destination.Header()
	for _, name := range []string{
		"Content-Length", "Trailer", "Location", "Refresh",
		"Content-Encoding", "Content-Type", "Retry-After",
	} {
		target.Del(name)
	}
	for name, values := range headers {
		target.Del(name)
		for _, value := range values {
			target.Add(name, value)
		}
	}
	target.Set("Cache-Control", "no-store")
	target.Set("X-Content-Type-Options", "nosniff")
	target.Set("X-Frame-Options", "DENY")
	target.Set("Referrer-Policy", "no-referrer")
	destination.WriteHeader(statusCode)
}

func withClientWriteDeadline(
	ctx context.Context,
	destination http.ResponseWriter,
	timeout time.Duration,
	operation func() error,
) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	controller := http.NewResponseController(destination)
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set client response write deadline: %w", err)
	}
	defer func() {
		if err := controller.SetWriteDeadline(time.Time{}); err != nil && result == nil {
			result = fmt.Errorf("clear client response write deadline: %w", err)
		}
	}()
	return operation()
}

func normalizedUsage(usage protocol.Usage) (protocol.Usage, error) {
	if !validProviderReportedCost(usage.ReportedCost) {
		return protocol.Usage{}, fmt.Errorf("%w: observer returned invalid provider cost state", ErrInvalidResponseRelay)
	}
	if !usage.Known {
		if usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.TotalTokens != 0 {
			return protocol.Usage{}, fmt.Errorf("%w: observer returned counts for unknown usage", ErrInvalidResponseRelay)
		}
		return protocol.Usage{
			Known: false, Provenance: "unknown", ReportedCost: usage.ReportedCost,
		}, nil
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens < 0 ||
		usage.InputTokens > math.MaxInt64-usage.OutputTokens ||
		usage.TotalTokens != usage.InputTokens+usage.OutputTokens ||
		!validUsageProvenance(usage.Provenance) || usage.Provenance == "unknown" {
		return protocol.Usage{}, fmt.Errorf("%w: observer returned invalid normalized usage", ErrInvalidResponseRelay)
	}
	return usage, nil
}

func validProviderReportedCost(cost protocol.ProviderReportedCost) bool {
	if !cost.Present {
		return !cost.Known && cost.NanoUSD == 0
	}
	if !cost.Known {
		return cost.NanoUSD == 0
	}
	return cost.NanoUSD >= 0
}

func validUsageProvenance(value string) bool {
	if len(value) == 0 || len(value) > maximumProvenanceBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if index == 0 {
			if character < 'a' || character > 'z' {
				return false
			}
			continue
		}
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
