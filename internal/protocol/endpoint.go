package protocol

import "net/http"

const (
	OpenAIResponsesID   = "openai_responses"
	OpenAIChatID        = "openai_chat"
	OpenAIEmbeddingsID  = "openai_embeddings"
	AnthropicMessagesID = "anthropic_messages"
	OpaqueHTTPID        = "opaque_http"

	OpenAIResponsesPublicPath   = "/v1/responses"
	OpenAIChatPublicPath        = "/v1/chat/completions"
	OpenAIEmbeddingsPublicPath  = "/v1/embeddings"
	AnthropicMessagesPublicPath = "/v1/messages"
	OpaqueHTTPPublicPrefix      = "/proxy/"

	OpenAIResponsesProviderPath   = "/responses"
	OpenAIChatProviderPath        = "/chat/completions"
	OpenAIEmbeddingsProviderPath  = "/embeddings"
	AnthropicMessagesProviderPath = "/messages"

	// MaximumEndpointCount is the hard upper bound for the built-in public
	// protocol surface. Adding a protocol is an explicit source change; active
	// configuration can never manufacture a new public endpoint or destination.
	MaximumEndpointCount = 5
)

type endpointMethodSet uint8

const (
	endpointMethodGet endpointMethodSet = 1 << iota
	endpointMethodPost
	endpointMethodPut
	endpointMethodPatch
	endpointMethodDelete
)

// Endpoint describes one built-in public protocol shape independently from
// any configured upstream hostname, credential, or transport. PublicPath is
// exact unless Prefix is true. ProviderPath is a provider-relative protocol
// path, never an absolute destination; opaque routes derive it only after
// their configured route and path policies have been enforced.
type Endpoint struct {
	Protocol     string
	PublicPath   string
	ProviderPath string
	Prefix       bool
	Executable   bool
	methods      endpointMethodSet
}

// AllowsMethod reports whether method is part of the endpoint's immutable
// public shape.
func (endpoint Endpoint) AllowsMethod(method string) bool {
	mask := endpointMethodMask(method)
	return mask != 0 && endpoint.methods&mask != 0
}

// AllowedMethods returns a detached, stable-order method list suitable for an
// Allow response header.
func (endpoint Endpoint) AllowedMethods() []string {
	methods := make([]string, 0, 5)
	for _, method := range []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	} {
		if endpoint.AllowsMethod(method) {
			methods = append(methods, method)
		}
	}
	return methods
}

var endpointCatalog = [...]Endpoint{
	{
		Protocol: OpenAIResponsesID, PublicPath: OpenAIResponsesPublicPath,
		ProviderPath: OpenAIResponsesProviderPath, Executable: true,
		methods: endpointMethodPost,
	},
	{
		Protocol: OpenAIChatID, PublicPath: OpenAIChatPublicPath,
		ProviderPath: OpenAIChatProviderPath, Executable: true,
		methods: endpointMethodPost,
	},
	{
		Protocol: OpenAIEmbeddingsID, PublicPath: OpenAIEmbeddingsPublicPath,
		ProviderPath: OpenAIEmbeddingsProviderPath, Executable: true,
		methods: endpointMethodPost,
	},
	{
		Protocol: AnthropicMessagesID, PublicPath: AnthropicMessagesPublicPath,
		ProviderPath: AnthropicMessagesProviderPath, Executable: true,
		methods: endpointMethodPost,
	},
	{
		Protocol: OpaqueHTTPID, PublicPath: OpaqueHTTPPublicPrefix, Prefix: true,
		Executable: true,
		methods: endpointMethodGet | endpointMethodPost | endpointMethodPut |
			endpointMethodPatch | endpointMethodDelete,
	},
}

// Endpoints returns a detached copy of the complete bounded endpoint catalog.
func Endpoints() []Endpoint {
	result := make([]Endpoint, len(endpointCatalog))
	copy(result, endpointCatalog[:])
	return result
}

// EndpointForProtocol returns the only built-in endpoint for protocol.
func EndpointForProtocol(protocolID string) (Endpoint, bool) {
	for _, endpoint := range endpointCatalog {
		if endpoint.Protocol == protocolID {
			return endpoint, true
		}
	}
	return Endpoint{}, false
}

// ProtocolExecutable reports whether this binary contains an endpoint and
// adapter implementation that may participate in configuration activation.
// Draft schema support is intentionally broader than this runtime gate.
func ProtocolExecutable(protocolID string) bool {
	endpoint, ok := EndpointForProtocol(protocolID)
	return ok && endpoint.Executable
}

// RequiredUpstreamType returns the only server-owned upstream family that may
// execute protocolID. Keeping this mapping beside the immutable endpoint
// catalog prevents configuration validation and dispatch from drifting apart.
func RequiredUpstreamType(protocolID string) (string, bool) {
	switch protocolID {
	case OpenAIResponsesID, OpenAIChatID, OpenAIEmbeddingsID:
		return "openai_compatible", true
	case AnthropicMessagesID:
		return "anthropic", true
	case OpaqueHTTPID:
		return "generic", true
	default:
		return "", false
	}
}

func endpointMethodMask(method string) endpointMethodSet {
	switch method {
	case http.MethodGet:
		return endpointMethodGet
	case http.MethodPost:
		return endpointMethodPost
	case http.MethodPut:
		return endpointMethodPut
	case http.MethodPatch:
		return endpointMethodPatch
	case http.MethodDelete:
		return endpointMethodDelete
	default:
		return 0
	}
}
