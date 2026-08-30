package protocol

import (
	"net/http"
	"slices"
	"testing"
)

func TestEndpointCatalogIsBoundedUniqueAndFailClosed(t *testing.T) {
	endpoints := Endpoints()
	if len(endpoints) != MaximumEndpointCount {
		t.Fatalf("endpoint count = %d, want %d", len(endpoints), MaximumEndpointCount)
	}
	seenProtocols := make(map[string]struct{}, len(endpoints))
	seenPaths := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Protocol == "" || endpoint.PublicPath == "" || len(endpoint.AllowedMethods()) == 0 {
			t.Fatalf("invalid endpoint catalog entry = %+v", endpoint)
		}
		if _, duplicate := seenProtocols[endpoint.Protocol]; duplicate {
			t.Fatalf("duplicate protocol = %q", endpoint.Protocol)
		}
		if _, duplicate := seenPaths[endpoint.PublicPath]; duplicate {
			t.Fatalf("duplicate public path = %q", endpoint.PublicPath)
		}
		seenProtocols[endpoint.Protocol] = struct{}{}
		seenPaths[endpoint.PublicPath] = struct{}{}
		if !endpoint.Executable {
			t.Fatalf("protocol %q executable = %t", endpoint.Protocol, endpoint.Executable)
		}
	}

	chat, ok := EndpointForProtocol(OpenAIChatID)
	if !ok || !chat.Executable || chat.Prefix || chat.PublicPath != "/v1/chat/completions" ||
		chat.ProviderPath != "/chat/completions" ||
		!slices.Equal(chat.AllowedMethods(), []string{http.MethodPost}) {
		t.Fatalf("chat endpoint = %+v methods=%v", chat, chat.AllowedMethods())
	}
	if ProtocolExecutable("unknown") {
		t.Fatal("unknown protocol reported executable")
	}
	for _, protocolID := range []string{OpenAIResponsesID, OpenAIChatID, OpenAIEmbeddingsID, AnthropicMessagesID, OpaqueHTTPID} {
		if !ProtocolExecutable(protocolID) {
			t.Fatalf("structured protocol %q is not executable", protocolID)
		}
	}
}

func TestRequiredUpstreamTypeIsBoundedToCatalog(t *testing.T) {
	tests := map[string]string{
		OpenAIResponsesID:   "openai_compatible",
		OpenAIChatID:        "openai_compatible",
		OpenAIEmbeddingsID:  "openai_compatible",
		AnthropicMessagesID: "anthropic",
		OpaqueHTTPID:        "generic",
	}
	for protocolID, want := range tests {
		got, ok := RequiredUpstreamType(protocolID)
		if !ok || got != want {
			t.Fatalf("RequiredUpstreamType(%q) = %q, %t; want %q, true", protocolID, got, ok, want)
		}
	}
	if got, ok := RequiredUpstreamType("unknown"); ok || got != "" {
		t.Fatalf("unknown upstream family = %q, %t", got, ok)
	}
}

func TestEndpointAllowedMethodsReturnsDetachedCopy(t *testing.T) {
	opaque, ok := EndpointForProtocol(OpaqueHTTPID)
	if !ok {
		t.Fatal("opaque endpoint missing")
	}
	methods := opaque.AllowedMethods()
	methods[0] = http.MethodConnect
	if opaque.AllowedMethods()[0] != http.MethodGet || opaque.AllowsMethod(http.MethodConnect) {
		t.Fatalf("opaque endpoint methods were mutable: %v", opaque.AllowedMethods())
	}
}
