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
		if endpoint.Executable != (endpoint.Protocol == OpenAIChatID) {
			t.Fatalf("protocol %q executable = %t", endpoint.Protocol, endpoint.Executable)
		}
	}

	chat, ok := EndpointForProtocol(OpenAIChatID)
	if !ok || !chat.Executable || chat.Prefix || chat.PublicPath != "/v1/chat/completions" ||
		chat.ProviderPath != "/chat/completions" ||
		!slices.Equal(chat.AllowedMethods(), []string{http.MethodPost}) {
		t.Fatalf("chat endpoint = %+v methods=%v", chat, chat.AllowedMethods())
	}
	for _, protocolID := range []string{
		OpenAIResponsesID, OpenAIEmbeddingsID, AnthropicMessagesID, OpaqueHTTPID, "unknown",
	} {
		if ProtocolExecutable(protocolID) {
			t.Fatalf("unsupported protocol %q reported executable", protocolID)
		}
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
