package dataplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchway/latchway/adapters/protocol/anthropicmessages"
	"github.com/latchway/latchway/adapters/protocol/opaquehttp"
	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/adapters/protocol/openaiembeddings"
	"github.com/latchway/latchway/adapters/protocol/openairesponses"
	"github.com/latchway/latchway/internal/protocol"
)

func TestEndpointRegistryDerivesExactPublicBindingSeparatelyFromProviderPath(t *testing.T) {
	origin, err := canonicalPublicOrigin("https://gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newEndpointRegistry(origin, structuredEndpointAdapters())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"https://untrusted.example/v1/chat/completions",
		nil,
	)
	match, violation := registry.match(request)
	if violation != nil {
		t.Fatalf("match violation = %+v", violation)
	}
	if match.protocolID != protocol.OpenAIChatID || match.publicMethod != http.MethodPost ||
		match.publicURL.String() != "https://gateway.example/v1/chat/completions" ||
		match.providerPath != "/chat/completions" || match.adapter.ID() != protocol.OpenAIChatID {
		t.Fatalf("endpoint match = %+v", match)
	}
	if match.publicURL.Host == request.Host || match.providerPath == match.publicURL.Path {
		t.Fatalf("public proof binding and provider mapping were conflated: %+v", match)
	}
}

func TestEndpointRegistryRejectsUnsupportedAdapterActivation(t *testing.T) {
	origin, err := canonicalPublicOrigin("https://gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newEndpointRegistry(origin, []protocol.Adapter{
		futureProtocolAdapter{Adapter: openaichat.Adapter{}},
	}); err == nil {
		t.Fatal("future protocol adapter activated without an executable endpoint capability")
	}
	duplicate := append(structuredEndpointAdapters(), openaichat.Adapter{})
	if _, err := newEndpointRegistry(origin, duplicate); err == nil {
		t.Fatal("duplicate protocol adapters activated")
	}
	if _, err := newEndpointRegistry(origin, structuredEndpointAdapters()[:3]); err == nil {
		t.Fatal("incomplete executable adapter registry activated")
	}
}

func TestEndpointRegistryRejectsAnotherMethodBeforeAdapterDispatch(t *testing.T) {
	origin, err := canonicalPublicOrigin("https://gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newEndpointRegistry(origin, structuredEndpointAdapters())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, protocol.OpenAIChatPublicPath, nil)
	_, violation := registry.match(request)
	if violation == nil || violation.code != "request_invalid" || violation.allowValue != http.MethodPost {
		t.Fatalf("wrong-method violation = %+v", violation)
	}
}

func TestEndpointRegistryBoundsAndCanonicalizesOpaqueShape(t *testing.T) {
	origin, err := canonicalPublicOrigin("https://gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newEndpointRegistry(origin, structuredEndpointAdapters())
	if err != nil {
		t.Fatal(err)
	}
	canonical := httptest.NewRequest(http.MethodPost, "/proxy/weather/v2/current", nil)
	match, violation := registry.match(canonical)
	if violation != nil || match.protocolID != protocol.OpaqueHTTPID || match.opaqueRoute != "weather" ||
		match.opaquePath != "/v2/current" || match.providerPath != "/v2/current" {
		t.Fatalf("canonical opaque match = %+v violation=%+v", match, violation)
	}
	absolute := httptest.NewRequest(
		http.MethodPost, "https://attacker.example/proxy/weather/v2/current", nil,
	)
	match, violation = registry.match(absolute)
	if violation != nil || match.publicURL.String() != "https://gateway.example/proxy/weather/v2/current" ||
		match.providerPath != "/v2/current" {
		t.Fatalf("client authority changed opaque binding: match=%+v violation=%+v", match, violation)
	}
	for _, test := range []struct {
		name string
		path string
		code string
	}{
		{name: "missing remaining path", path: "/proxy/weather", code: "resource_not_found"},
		{name: "invalid route key", path: "/proxy/Weather/v2/current", code: "resource_not_found"},
		{name: "dot segment", path: "/proxy/weather/v2/../private", code: "resource_not_found"},
		{name: "empty segment", path: "/proxy/weather/v2//current", code: "resource_not_found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, nil)
			_, violation := registry.match(request)
			if violation == nil || violation.code != test.code {
				t.Fatalf("registry match violation = %+v, want %q", violation, test.code)
			}
		})
	}
}

type futureProtocolAdapter struct {
	openaichat.Adapter
}

func (futureProtocolAdapter) ID() string { return protocol.OpenAIResponsesID }

func structuredEndpointAdapters() []protocol.Adapter {
	return []protocol.Adapter{
		openairesponses.Adapter{},
		openaichat.Adapter{},
		openaiembeddings.Adapter{},
		anthropicmessages.Adapter{},
		opaquehttp.Adapter{},
	}
}
