package opaquehttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestAdapterPreservesBoundedOpaqueBytesAndReportsUnknownUsage(t *testing.T) {
	adapter := Adapter{MaximumBodyBytes: 64}
	request := httptest.NewRequest(http.MethodPost, "/proxy/weather/v2/current", strings.NewReader("\x00opaque\xff"))
	request.Header.Set("Content-Type", "application/octet-stream")

	metadata, err := adapter.InspectRequest(context.Background(), request)
	if err != nil || metadata.RequestBytes != 8 || metadata.Streaming || metadata.ClientModel != "" {
		t.Fatalf("InspectRequest() metadata=%+v error=%v", metadata, err)
	}
	decision := opaqueDecision()
	if applied, err := adapter.ApplyFeature(context.Background(), request, decision); err != nil || applied != 0 {
		t.Fatalf("ApplyFeature() applied=%d error=%v", applied, err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "\x00opaque\xff" {
		t.Fatalf("rewritten body=%q error=%v", body, err)
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
		Request:    request,
	}
	observer, err := adapter.ObserveResponse(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Observe([]byte("provider bytes")); err != nil {
		t.Fatal(err)
	}
	usage, err := observer.Finalize()
	if err != nil || usage.Known || usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.TotalTokens != 0 {
		t.Fatalf("opaque usage=%+v error=%v", usage, err)
	}
}

func TestAdapterEnforcesConfiguredMethodPathAndBody(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		body     string
		decision func() protocol.FeatureDecision
	}{
		{name: "method", method: http.MethodDelete, path: "/proxy/weather/v2/current", decision: opaqueDecision},
		{name: "segment boundary", method: http.MethodPost, path: "/proxy/weather/v20/current", decision: func() protocol.FeatureDecision {
			value := opaqueDecision()
			value.OpaqueHTTP.ProviderPath = "/v20/current"
			return value
		}},
		{name: "body", method: http.MethodPost, path: "/proxy/weather/v2/current", body: "12345", decision: func() protocol.FeatureDecision {
			value := opaqueDecision()
			value.OpaqueHTTP.MaximumBodyBytes = 4
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := Adapter{MaximumBodyBytes: 64}
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
				t.Fatalf("InspectRequest() error=%v", err)
			}
			if _, err := adapter.ApplyFeature(context.Background(), request, test.decision()); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("ApplyFeature() error=%v", err)
			}
		})
	}
}

func TestAdapterAllowsAnExplicitRootPathPrefix(t *testing.T) {
	adapter := Adapter{}
	request := httptest.NewRequest(http.MethodPost, "/proxy/weather/v2/current", nil)
	if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	decision := opaqueDecision()
	decision.OpaqueHTTP.PathPrefixes = []string{"/"}
	if _, err := adapter.ApplyFeature(context.Background(), request, decision); err != nil {
		t.Fatalf("root path prefix rejected: %v", err)
	}
}

func TestAdapterMatchesExactDepthPathTemplatesAndPreservesLegacyPrefixes(t *testing.T) {
	t.Parallel()

	adapter := Adapter{}
	templateDecision := opaqueDecision()
	templateDecision.OpaqueHTTP.PathPrefixes = nil
	templateDecision.OpaqueHTTP.PathTemplates = []string{
		"/v2/current", "/v2/users/{user_id}",
	}
	for _, path := range []string{
		"/proxy/weather/v2/current",
		"/proxy/weather/v2/users/alice",
	} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		templateDecision.OpaqueHTTP.ProviderPath = strings.TrimPrefix(path, "/proxy/weather")
		if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
			t.Fatalf("InspectRequest(%q): %v", path, err)
		}
		if _, err := adapter.ApplyFeature(context.Background(), request, templateDecision); err != nil {
			t.Fatalf("template ApplyFeature(%q): %v", path, err)
		}
	}
	for _, path := range []string{
		"/proxy/weather/v2/users/alice/events",
		"/proxy/weather/v2/groups/alice",
	} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		templateDecision.OpaqueHTTP.ProviderPath = strings.TrimPrefix(path, "/proxy/weather")
		if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
			t.Fatalf("InspectRequest(%q): %v", path, err)
		}
		if _, err := adapter.ApplyFeature(context.Background(), request, templateDecision); !protocol.IsCode(err, "request_invalid") {
			t.Fatalf("out-of-template ApplyFeature(%q) error = %v", path, err)
		}
	}

	legacy := opaqueDecision()
	for _, path := range []string{"/v2", "/v2/current", "/v2/users/alice"} {
		legacy.OpaqueHTTP.ProviderPath = path
		request := httptest.NewRequest(http.MethodPost, "/proxy/weather"+path, nil)
		if _, err := adapter.ApplyFeature(context.Background(), request, legacy); err != nil {
			t.Fatalf("legacy segment-bound prefix %q changed behavior: %v", path, err)
		}
	}
	legacy.OpaqueHTTP.ProviderPath = "/v20/current"
	request := httptest.NewRequest(http.MethodPost, "/proxy/weather/v20/current", nil)
	if _, err := adapter.ApplyFeature(context.Background(), request, legacy); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("legacy prefix escaped its segment boundary: %v", err)
	}
}

func TestAdapterRejectsMixedOrAmbiguousTemplatePolicy(t *testing.T) {
	t.Parallel()

	adapter := Adapter{}
	request := httptest.NewRequest(http.MethodPost, "/proxy/weather/v2/current", nil)
	for name, mutate := range map[string]func(*protocol.OpaqueHTTPDecision){
		"mixed template and legacy prefix": func(policy *protocol.OpaqueHTTPDecision) {
			policy.PathTemplates = []string{"/v2/{resource_id}"}
		},
		"ambiguous templates": func(policy *protocol.OpaqueHTTPDecision) {
			policy.PathPrefixes = nil
			policy.PathTemplates = []string{"/v2/{resource_id}", "/v2/current"}
		},
		"open wildcard": func(policy *protocol.OpaqueHTTPDecision) {
			policy.PathPrefixes = nil
			policy.PathTemplates = []string{"/v2/*"}
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			decision := opaqueDecision()
			mutate(decision.OpaqueHTTP)
			if _, err := adapter.ApplyFeature(context.Background(), request.Clone(context.Background()), decision); err == nil {
				t.Fatalf("unsafe opaque path policy was accepted: %+v", decision.OpaqueHTTP)
			}
		})
	}
}

func TestAdapterRejectsNonCanonicalPublicInputsAndEncodedBodies(t *testing.T) {
	adapter := Adapter{MaximumBodyBytes: 8}
	for _, target := range []string{
		"/proxy/weather/v2/../private",
		"/proxy/Weather/v2/current",
		"/proxy/weather/v2/current?destination=https://evil.example",
		"/proxy/weather/v2//current",
		"/proxy/weather/v2/%2fprivate",
	} {
		request := httptest.NewRequest(http.MethodPost, target, nil)
		if adapter.Match(request) {
			t.Fatalf("Match(%q) accepted", target)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/proxy/weather/v2/current", strings.NewReader("gzip"))
	request.Header.Set("Content-Encoding", "gzip")
	if _, err := adapter.InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("encoded InspectRequest() error=%v", err)
	}
}

func TestAdapterEnforcesOpaqueStreamingDeclaration(t *testing.T) {
	adapter := Adapter{}
	request := httptest.NewRequest(http.MethodGet, "/proxy/weather/v2/events", nil)
	decision := opaqueDecision()
	decision.OpaqueHTTP.AllowedMethods = []string{http.MethodGet}
	decision.OpaqueHTTP.ProviderPath = "/v2/events"
	if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ApplyFeature(context.Background(), request, decision); err != nil {
		t.Fatal(err)
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}},
		Request:    request,
	}
	if _, err := adapter.ObserveResponse(context.Background(), response); !protocol.IsCode(err, "upstream_response_invalid") {
		t.Fatalf("non-streaming ObserveResponse() error=%v", err)
	}
	response.StatusCode = http.StatusInternalServerError
	if _, err := adapter.ObserveResponse(context.Background(), response); !protocol.IsCode(err, "upstream_response_invalid") {
		t.Fatalf("non-streaming error SSE ObserveResponse() error=%v", err)
	}

	decision.OpaqueHTTP.StreamingAllowed = true
	if _, err := adapter.ApplyFeature(context.Background(), request, decision); err != nil {
		t.Fatal(err)
	}
	response.Request = request
	if _, err := adapter.ObserveResponse(context.Background(), response); err != nil {
		t.Fatalf("streaming ObserveResponse() error=%v", err)
	}
}

func opaqueDecision() protocol.FeatureDecision {
	return protocol.FeatureDecision{OpaqueHTTP: &protocol.OpaqueHTTPDecision{
		FeatureID:             "weather",
		ProviderPath:          "/v2/current",
		AllowedMethods:        []string{http.MethodPost},
		PathPrefixes:          []string{"/v2"},
		MaximumBodyBytes:      16,
		AllowedRequestHeaders: []string{"Content-Type"},
		MaximumResponseBytes:  32,
	}}
}
