// Package opaquehttp implements the deliberately restricted generic HTTP
// protocol. It never selects a destination, injects credentials, interprets
// provider payloads, or reports measured usage.
package opaquehttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/latchway/latchway/internal/protocol"
)

const (
	ID = protocol.OpaqueHTTPID

	defaultMaximumBody = int64(1 << 20)
	maximumPolicyBytes = int64(100 << 20)
)

var featurePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// Adapter preserves an opaque request body while enforcing the immutable
// public shape and the method, path, body, and response-mode portions of the
// server-owned policy supplied at ApplyFeature time.
type Adapter struct {
	MaximumBodyBytes int64
}

var _ protocol.Adapter = Adapter{}

type appliedPolicy struct {
	streamingAllowed bool
}

type appliedPolicyContextKey struct{}

func (Adapter) ID() string { return ID }

// Match accepts only canonical /proxy/{feature}/{path...} requests. The data
// plane separately proves that the feature path segment equals the signed
// X-Latchway-Feature declaration.
func (Adapter) Match(request *http.Request) bool {
	if request == nil || request.URL == nil || !slices.Contains([]string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	}, request.Method) || request.URL.Opaque != "" || request.URL.User != nil ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.Fragment != "" || request.URL.RawFragment != "" ||
		len(request.URL.Path) > protocol.MaximumOpaqueHTTPProviderPathBytes ||
		request.URL.EscapedPath() != request.URL.Path ||
		!strings.HasPrefix(request.URL.Path, protocol.OpaqueHTTPPublicPrefix) {
		return false
	}
	remainder := strings.TrimPrefix(request.URL.Path, protocol.OpaqueHTTPPublicPrefix)
	feature, providerPath, found := strings.Cut(remainder, "/")
	return found && featurePattern.MatchString(feature) && protocol.ValidOpaqueHTTPProviderPath("/"+providerPath)
}

func (Adapter) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Streaming: true}
}

func (adapter Adapter) InspectRequest(ctx context.Context, request *http.Request) (protocol.RequestMetadata, error) {
	if ctx == nil {
		return protocol.RequestMetadata{}, requestMalformed("request context is required")
	}
	if err := ctx.Err(); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if !adapter.Match(request) {
		return protocol.RequestMetadata{}, requestMalformed("a canonical opaque HTTP endpoint is required")
	}
	body, err := adapter.readBody(ctx, request, adapter.maximumBodyBytes())
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	return protocol.RequestMetadata{RequestBytes: int64(len(body))}, nil
}

func (adapter Adapter) ApplyFeature(
	ctx context.Context,
	request *http.Request,
	decision protocol.FeatureDecision,
) (int64, error) {
	if ctx == nil {
		return 0, requestMalformed("request context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	featureID, providerPath, matches := publicBinding(request)
	if !matches || decision.DefaultOutputTokens != 0 ||
		decision.MaximumOutputTokens != 0 || decision.OpaqueHTTP == nil {
		return 0, errors.New("valid opaque HTTP feature policy is required")
	}
	policy := decision.OpaqueHTTP
	if !validDecision(*policy) || policy.FeatureID != featureID || policy.ProviderPath != providerPath {
		return 0, errors.New("opaque HTTP policy does not match the selected public endpoint")
	}
	if !slices.Contains(policy.AllowedMethods, request.Method) {
		return 0, requestMalformed("the method is not allowed for this opaque HTTP feature")
	}
	if !pathAllowed(policy.ProviderPath, policy.PathPrefixes, policy.PathTemplates) {
		return 0, requestMalformed("the path is not allowed for this opaque HTTP feature")
	}
	body, err := adapter.readBody(ctx, request, policy.MaximumBodyBytes)
	if err != nil {
		return 0, err
	}
	installRequestBody(request, body)
	*request = *request.WithContext(context.WithValue(
		request.Context(),
		appliedPolicyContextKey{},
		appliedPolicy{streamingAllowed: policy.StreamingAllowed},
	))
	return 0, nil
}

// MeasureRequest binds the exact opaque body installed by ApplyFeature. The
// adapter cannot interpret structured image or tool semantics, so their known
// flags remain false and hard rules for those metrics fail closed upstream.
func (adapter Adapter) MeasureRequest(
	ctx context.Context,
	request *http.Request,
) (protocol.RequestMeasurements, error) {
	if ctx == nil || request == nil {
		return protocol.RequestMeasurements{}, requestMalformed("request context is required")
	}
	if _, ok := request.Context().Value(appliedPolicyContextKey{}).(appliedPolicy); !ok {
		return protocol.RequestMeasurements{}, errors.New("request is missing its opaque HTTP policy marker")
	}
	body, err := adapter.readBody(ctx, request, maximumPolicyBytes)
	if err != nil {
		return protocol.RequestMeasurements{}, err
	}
	return protocol.RequestMeasurements{
		Protocol: ID, RewrittenBodySHA256: sha256.Sum256(body), RequestBytes: int64(len(body)),
	}, nil
}

func (Adapter) ObserveResponse(ctx context.Context, response *http.Response) (protocol.ResponseObserver, error) {
	if ctx == nil {
		return nil, errors.New("response context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if response == nil || response.Request == nil {
		return nil, errors.New("response and response request are required")
	}
	policy, ok := response.Request.Context().Value(appliedPolicyContextKey{}).(appliedPolicy)
	if !ok {
		return nil, errors.New("response request is missing its opaque HTTP policy marker")
	}
	contentTypes := headerValues(response.Header, "Content-Type")
	if len(contentTypes) > 1 {
		return nil, upstreamMalformed("upstream response must not contain duplicate Content-Type headers")
	}
	if len(contentTypes) == 1 {
		mediaType, _, err := mime.ParseMediaType(contentTypes[0])
		if err != nil {
			return nil, upstreamMalformed("upstream response Content-Type is invalid")
		}
		if strings.EqualFold(mediaType, "text/event-stream") && !policy.streamingAllowed {
			return nil, upstreamMalformed("streaming is not allowed for this opaque HTTP route")
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return unknownUsageObserver{}, nil
	}
	return unknownUsageObserver{}, nil
}

func (adapter Adapter) readBody(ctx context.Context, request *http.Request, limit int64) ([]byte, error) {
	if request == nil {
		return nil, requestMalformed("opaque HTTP request is required")
	}
	if request.Body == nil || request.Body == http.NoBody {
		if request.ContentLength != 0 {
			return nil, requestMalformed("opaque HTTP request body length is inconsistent")
		}
		installRequestBody(request, nil)
		return nil, nil
	}
	if limit < 0 || limit > maximumPolicyBytes || len(headerValues(request.Header, "Content-Encoding")) != 0 {
		return nil, requestMalformed("encoded opaque HTTP request bodies are not supported")
	}
	if request.ContentLength < -1 || request.ContentLength > limit {
		return nil, requestMalformed("opaque HTTP request exceeds the configured body limit")
	}
	body, readErr := io.ReadAll(io.LimitReader(request.Body, limit+1))
	closeErr := request.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, requestMalformed("opaque HTTP request body could not be read")
	}
	if int64(len(body)) > limit {
		return nil, requestMalformed("opaque HTTP request exceeds the configured body limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	installRequestBody(request, body)
	return body, nil
}

func (adapter Adapter) maximumBodyBytes() int64 {
	if adapter.MaximumBodyBytes > 0 && adapter.MaximumBodyBytes <= maximumPolicyBytes {
		return adapter.MaximumBodyBytes
	}
	return defaultMaximumBody
}

func validDecision(policy protocol.OpaqueHTTPDecision) bool {
	if !featurePattern.MatchString(policy.FeatureID) || !protocol.ValidOpaqueHTTPProviderPath(policy.ProviderPath) ||
		len(policy.AllowedMethods) == 0 || len(policy.AllowedMethods) > 5 ||
		(len(policy.PathPrefixes) == 0) == (len(policy.PathTemplates) == 0) ||
		len(policy.PathPrefixes) > protocol.MaximumOpaqueHTTPPathRules ||
		len(policy.AllowedRequestHeaders) > 32 || policy.MaximumBodyBytes < 0 ||
		policy.MaximumBodyBytes > maximumPolicyBytes || policy.MaximumResponseBytes <= 0 ||
		policy.MaximumResponseBytes > maximumPolicyBytes {
		return false
	}
	seenMethods := make(map[string]struct{}, len(policy.AllowedMethods))
	for _, method := range policy.AllowedMethods {
		if !slices.Contains([]string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		}, method) {
			return false
		}
		if _, duplicate := seenMethods[method]; duplicate {
			return false
		}
		seenMethods[method] = struct{}{}
	}
	seenPrefixes := make(map[string]struct{}, len(policy.PathPrefixes))
	for _, prefix := range policy.PathPrefixes {
		if len(prefix) > protocol.MaximumOpaqueHTTPPathTemplateBytes ||
			(prefix != "/" && !protocol.ValidOpaqueHTTPProviderPath(prefix)) {
			return false
		}
		if _, duplicate := seenPrefixes[prefix]; duplicate {
			return false
		}
		seenPrefixes[prefix] = struct{}{}
	}
	if len(policy.PathTemplates) > 0 && !protocol.ValidOpaqueHTTPPathTemplates(policy.PathTemplates) {
		return false
	}
	return true
}

func publicBinding(request *http.Request) (string, string, bool) {
	if !(Adapter{}).Match(request) {
		return "", "", false
	}
	remainder := strings.TrimPrefix(request.URL.Path, protocol.OpaqueHTTPPublicPrefix)
	featureID, remaining, found := strings.Cut(remainder, "/")
	return featureID, "/" + remaining, found
}

func pathAllowed(providerPath string, prefixes, templates []string) bool {
	if len(templates) > 0 {
		for _, template := range templates {
			if protocol.OpaqueHTTPPathMatchesTemplate(providerPath, template) {
				return true
			}
		}
		return false
	}
	for _, prefix := range prefixes {
		if prefix == "/" || providerPath == prefix {
			return true
		}
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(providerPath, prefix) {
				return true
			}
			continue
		}
		if strings.HasPrefix(providerPath, prefix+"/") {
			return true
		}
	}
	return false
}

func installRequestBody(request *http.Request, body []byte) {
	if len(body) == 0 {
		request.Body = http.NoBody
		request.ContentLength = 0
		request.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}

func headerValues(headers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range headers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func requestMalformed(detail string) error {
	return &protocol.Error{Code: "request_invalid", Detail: detail}
}

func upstreamMalformed(detail string) error {
	return &protocol.Error{Code: "upstream_response_invalid", Detail: detail}
}

type unknownUsageObserver struct{}

func (unknownUsageObserver) Observe([]byte) error { return nil }

func (unknownUsageObserver) Finalize() (protocol.Usage, error) {
	return protocol.Usage{Known: false}, nil
}
