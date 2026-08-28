package dataplane

import (
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/protocol"
)

const maximumPublicEndpointPathBytes = 2048

type registeredEndpoint struct {
	description protocol.Endpoint
	adapter     protocol.Adapter
}

// endpointMatch is a request-scoped immutable mapping. Its public method and
// URL are the sole DPoP binding inputs; providerPath is carried separately and
// is only resolved against the server-selected upstream target after policy.
type endpointMatch struct {
	protocolID   string
	publicMethod string
	publicURL    url.URL
	providerPath string
	opaqueRoute  string
	opaquePath   string
	adapter      protocol.Adapter
}

type endpointRegistry struct {
	origin    url.URL
	endpoints []registeredEndpoint
}

func newEndpointRegistry(origin url.URL, adapters []protocol.Adapter) (endpointRegistry, error) {
	descriptions := protocol.Endpoints()
	if len(descriptions) == 0 || len(descriptions) > protocol.MaximumEndpointCount ||
		len(adapters) == 0 || len(adapters) > protocol.MaximumEndpointCount {
		return endpointRegistry{}, errInvalidConfiguration
	}
	registered := make(map[string]protocol.Adapter, len(adapters))
	for _, adapter := range adapters {
		if nilDependency(adapter) {
			return endpointRegistry{}, errInvalidConfiguration
		}
		protocolID := adapter.ID()
		description, known := protocol.EndpointForProtocol(protocolID)
		if !known || !description.Executable || !adapterCapabilitiesValid(protocolID, adapter.Capabilities()) {
			return endpointRegistry{}, errInvalidConfiguration
		}
		if _, duplicate := registered[protocolID]; duplicate {
			return endpointRegistry{}, errInvalidConfiguration
		}
		registered[protocolID] = adapter
	}

	entries := make([]registeredEndpoint, 0, len(descriptions))
	for _, description := range descriptions {
		adapter := registered[description.Protocol]
		if description.Executable && nilDependency(adapter) {
			return endpointRegistry{}, errInvalidConfiguration
		}
		entries = append(entries, registeredEndpoint{description: description, adapter: adapter})
	}
	return endpointRegistry{origin: origin, endpoints: entries}, nil
}

func adapterCapabilitiesValid(protocolID string, capabilities protocol.Capabilities) bool {
	var expected protocol.Capabilities
	switch protocolID {
	case protocol.OpenAIChatID:
		expected = protocol.Capabilities{
			Streaming: true, ModelRewrite: true, OutputTokenClamp: true,
			ProviderUsage: true, TrustedInputPreflight: true,
		}
	case protocol.OpenAIResponsesID, protocol.AnthropicMessagesID:
		expected = protocol.Capabilities{
			Streaming: true, ModelRewrite: true, OutputTokenClamp: true,
			ProviderUsage: true,
		}
	case protocol.OpenAIEmbeddingsID:
		expected = protocol.Capabilities{ModelRewrite: true, ProviderUsage: true}
	case protocol.OpaqueHTTPID:
		expected = protocol.Capabilities{Streaming: true}
	default:
		return false
	}
	return capabilities == expected
}

func (registry endpointRegistry) match(request *http.Request) (endpointMatch, *violation) {
	if request == nil || request.URL == nil {
		return endpointMatch{}, requestViolation("request", "A valid HTTP request is required.")
	}
	if request.URL.Opaque != "" || request.URL.User != nil || request.URL.Fragment != "" ||
		request.URL.RawFragment != "" || request.URL.RawPath != "" ||
		request.URL.EscapedPath() != request.URL.Path ||
		len(request.URL.Path) == 0 || len(request.URL.Path) > maximumPublicEndpointPathBytes ||
		!utf8.ValidString(request.URL.Path) {
		return endpointMatch{}, requestViolation("path", "A canonical bounded public endpoint path is required.")
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		return endpointMatch{}, requestViolation("query", "Query parameters are not supported by this endpoint.")
	}

	entry, opaqueRoute, opaquePath, ok := registry.endpointForPath(request.URL.Path)
	if !ok {
		return endpointMatch{}, endpointNotFoundViolation()
	}
	if !entry.description.AllowsMethod(request.Method) {
		allowed := entry.description.AllowedMethods()
		result := requestViolation("method", "The HTTP method is not supported by this endpoint.")
		result.allowValue = strings.Join(allowed, ", ")
		return endpointMatch{}, result
	}
	if !entry.description.Executable || nilDependency(entry.adapter) {
		return endpointMatch{}, endpointNotFoundViolation()
	}
	if !entry.adapter.Match(request) {
		return endpointMatch{}, requestViolation(
			"path", "The request does not match the registered protocol adapter endpoint.",
		)
	}

	publicURL := registry.origin
	publicURL.Path = request.URL.Path
	providerPath := entry.description.ProviderPath
	if entry.description.Protocol == protocol.OpaqueHTTPID {
		providerPath = opaquePath
	}
	return endpointMatch{
		protocolID: entry.description.Protocol, publicMethod: request.Method,
		publicURL: publicURL, providerPath: providerPath,
		opaqueRoute: opaqueRoute, opaquePath: opaquePath, adapter: entry.adapter,
	}, nil
}

func (registry endpointRegistry) endpointForPath(publicPath string) (registeredEndpoint, string, string, bool) {
	for _, entry := range registry.endpoints {
		if !entry.description.Prefix {
			if publicPath == entry.description.PublicPath {
				return entry, "", "", true
			}
			continue
		}
		if !strings.HasPrefix(publicPath, entry.description.PublicPath) {
			continue
		}
		routeAndPath := strings.TrimPrefix(publicPath, entry.description.PublicPath)
		route, remaining, found := strings.Cut(routeAndPath, "/")
		opaquePath := "/" + remaining
		if !found || !identifierPattern.MatchString(route) || !validOpaquePublicPath(opaquePath) {
			return registeredEndpoint{}, "", "", false
		}
		return entry, route, opaquePath, true
	}
	return registeredEndpoint{}, "", "", false
}

func validOpaquePublicPath(value string) bool {
	if len(value) < 2 || len(value) > maximumPublicEndpointPathBytes ||
		value[0] != '/' || strings.Contains(value, "\\") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, "%?#") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character >= 0x7f {
			return false
		}
	}
	if (&url.URL{Path: value}).EscapedPath() != value {
		return false
	}
	canonical := pathpkg.Clean(value)
	if strings.HasSuffix(value, "/") && canonical != "/" {
		canonical += "/"
	}
	return canonical == value
}

func endpointNotFoundViolation() *violation {
	return &violation{
		code: "resource_not_found", detail: "The protected endpoint is not available in this server build.",
	}
}
