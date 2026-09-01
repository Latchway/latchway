package upstream

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const maximumPreparedHeaderBytes = 64 << 10

// PreparedRequest is an opaque request capability bound to one validated
// Target. Its URL and headers cannot be replaced by callers between trust-
// boundary reconstruction and credential injection.
type PreparedRequest struct {
	target                  *Target
	request                 *http.Request
	state                   *preparedRequestState
	traceContextPropagation TraceContextPropagation
}

// TraceContextPropagation is the closed, server-selected propagation policy
// carried by one prepared request. Client headers can never select this mode.
type TraceContextPropagation uint8

const (
	TraceContextPropagationNone TraceContextPropagation = iota
	TraceContextPropagationW3C
)

type preparedRequestState struct {
	mu   sync.Mutex
	used bool
}

// PrepareRequest reconstructs a provider request from an inspected client
// request and one server-selected target. It never carries client routing,
// credential, hop-by-hop, forwarding, or Latchway control headers across the
// trust boundary. Credentials are deliberately applied later, while their
// secret-store callback is active.
func PrepareRequest(
	incoming *http.Request,
	target *Target,
	requestPath string,
	forwardedHeaders []string,
	staticHeaders map[string]string,
	traceContextPropagation ...TraceContextPropagation,
) (PreparedRequest, error) {
	if target == nil {
		return PreparedRequest{}, errors.New("invalid upstream request")
	}
	resolved, err := target.ResolveURL(requestPath)
	if err != nil {
		return PreparedRequest{}, err
	}
	mode, err := requestedTraceContextPropagation(traceContextPropagation)
	if err != nil {
		return PreparedRequest{}, err
	}
	return prepareRequestAtURL(incoming, target, resolved, forwardedHeaders, staticHeaders, mode)
}

// PrepareBaseRequest reconstructs a server-selected public-resource request to
// the target's exact configured base URL. It exists for fixed endpoints such as
// JWKS documents, where appending a provider route would change the resource.
func PrepareBaseRequest(
	incoming *http.Request,
	target *Target,
	forwardedHeaders []string,
	staticHeaders map[string]string,
) (PreparedRequest, error) {
	if target == nil || target.baseURL == nil {
		return PreparedRequest{}, errors.New("invalid upstream request")
	}
	resolved := *target.baseURL
	if resolved.Path == "" {
		resolved.Path = "/"
	}
	return prepareRequestAtURL(
		incoming, target, &resolved, forwardedHeaders, staticHeaders, TraceContextPropagationNone,
	)
}

func prepareRequestAtURL(
	incoming *http.Request,
	target *Target,
	resolved *url.URL,
	forwardedHeaders []string,
	staticHeaders map[string]string,
	traceContextPropagation TraceContextPropagation,
) (PreparedRequest, error) {
	if incoming == nil || incoming.URL == nil || incoming.Context() == nil || target == nil || resolved == nil || incoming.Method == "" {
		return PreparedRequest{}, errors.New("invalid upstream request")
	}
	// Inspection operates on the exact bytes sent upstream. Dropping this
	// header would relabel compressed bytes as JSON, while forwarding it would
	// make protocol validation and accounting depend on opaque decompression.
	if err := validateSingletonRequestHeaders(incoming.Header); err != nil {
		return PreparedRequest{}, err
	}
	if len(headerValues(incoming.Header, "Content-Encoding")) != 0 {
		return PreparedRequest{}, errors.New("encoded upstream request bodies are not supported")
	}
	headers, err := ForwardHeaders(incoming.Header, forwardedHeaders)
	if err != nil {
		return PreparedRequest{}, err
	}
	if err := ApplyStaticHeaders(headers, staticHeaders); err != nil {
		return PreparedRequest{}, err
	}
	// Protocol observers inspect the unmodified provider bytes. Request identity
	// compression explicitly so a provider cannot make metering depend on an
	// implicit transport decompressor or opaque compressed frames.
	headers.Set("Accept-Encoding", "identity")

	outbound := incoming.Clone(incoming.Context())
	outbound.URL = resolved
	outbound.RequestURI = ""
	outbound.Host = ""
	outbound.Header = headers
	outbound.TransferEncoding = nil
	outbound.Trailer = nil
	outbound.Close = false
	prepared := PreparedRequest{
		target: target, request: outbound, state: &preparedRequestState{},
		traceContextPropagation: traceContextPropagation,
	}
	if err := target.validatePreparedRequest(prepared); err != nil {
		return PreparedRequest{}, err
	}
	return prepared, nil
}

func (target *Target) validatePreparedRequest(prepared PreparedRequest) error {
	request := prepared.request
	if target == nil || target.baseURL == nil || target.client == nil || prepared.target != target ||
		prepared.state == nil || request == nil || request.URL == nil || request.Context() == nil || !validHeaderName(request.Method) {
		return errors.New("invalid prepared upstream request")
	}
	if prepared.traceContextPropagation != TraceContextPropagationNone &&
		prepared.traceContextPropagation != TraceContextPropagationW3C {
		return errors.New("prepared upstream request has an invalid trace-context policy")
	}
	if request.URL.Scheme != target.baseURL.Scheme || request.URL.Host != target.baseURL.Host ||
		request.URL.User != nil || request.URL.Opaque != "" || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" ||
		!canonicalUpstreamPath(request.URL.Path, false) {
		return errors.New("prepared upstream request escaped its target")
	}
	basePath := strings.TrimSuffix(target.baseURL.Path, "/")
	if basePath != "" && request.URL.Path != basePath && !strings.HasPrefix(request.URL.Path, basePath+"/") {
		return errors.New("prepared upstream request escaped its target path")
	}
	if request.RequestURI != "" || request.Host != "" || len(request.TransferEncoding) != 0 ||
		len(request.Trailer) != 0 || request.Close || requestContainsCredential(request.Header) ||
		validateSingletonRequestHeaders(request.Header) != nil {
		return errors.New("prepared upstream request retained transport or credential state")
	}
	encodings := headerValues(request.Header, "Accept-Encoding")
	if len(encodings) != 1 || encodings[0] != "identity" || len(headerValues(request.Header, "Content-Encoding")) != 0 {
		return errors.New("prepared upstream request has ambiguous body encoding")
	}
	totalHeaderBytes := 0
	for name, values := range request.Header {
		canonical := http.CanonicalHeaderKey(name)
		if !validHeaderName(name) || (canonical != "Accept-Encoding" && isForbiddenHeader(canonical)) {
			return errors.New("prepared upstream request contains a forbidden header")
		}
		for _, value := range values {
			totalHeaderBytes += len(canonical) + len(value)
			if !validHeaderValue(value) || totalHeaderBytes > maximumPreparedHeaderBytes {
				return errors.New("prepared upstream request headers are invalid")
			}
		}
	}
	return nil
}

func validateInjectedTraceContext(headers http.Header) error {
	if headers == nil || len(headerValues(headers, "Traceparent")) > 1 ||
		len(headerValues(headers, "Tracestate")) > 1 || len(headerValues(headers, "Baggage")) != 0 {
		return errors.New("injected upstream trace context is invalid")
	}
	totalHeaderBytes := 0
	for name, values := range headers {
		if !validHeaderName(name) || len(values) == 0 {
			return errors.New("injected upstream trace context is invalid")
		}
		canonical := http.CanonicalHeaderKey(name)
		for _, value := range values {
			totalHeaderBytes += len(canonical) + len(value)
			if !validHeaderValue(value) || totalHeaderBytes > maximumPreparedHeaderBytes {
				return errors.New("injected upstream trace context is invalid")
			}
		}
	}
	return nil
}

func requestedTraceContextPropagation(values []TraceContextPropagation) (TraceContextPropagation, error) {
	if len(values) == 0 {
		return TraceContextPropagationNone, nil
	}
	if len(values) != 1 || (values[0] != TraceContextPropagationNone && values[0] != TraceContextPropagationW3C) {
		return TraceContextPropagationNone, errors.New("invalid upstream trace-context policy")
	}
	return values[0], nil
}

func (target *Target) claimPreparedRequest(prepared PreparedRequest) error {
	if err := target.validatePreparedRequest(prepared); err != nil {
		return err
	}
	prepared.state.mu.Lock()
	defer prepared.state.mu.Unlock()
	if prepared.state.used {
		return errors.New("prepared upstream request was already dispatched")
	}
	prepared.state.used = true
	return nil
}
