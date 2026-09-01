package adminapi

// serverCapability is a binary feature implemented by this exact server
// build. It is independent from administrator authorization capabilities.
type serverCapability string

const (
	serverCapabilityAppAttest                 serverCapability = "app_attest"
	serverCapabilityPlayIntegrity             serverCapability = "play_integrity"
	serverCapabilityFirebaseAppCheck          serverCapability = "firebase_app_check"
	serverCapabilityTurnstile                 serverCapability = "turnstile"
	serverCapabilityComponentDelegation       serverCapability = "component_delegation"
	serverCapabilityCostLimits                serverCapability = "cost_limits"
	serverCapabilityOpenAIResponses           serverCapability = "openai_responses"
	serverCapabilityOpenAIChat                serverCapability = "openai_chat"
	serverCapabilityOpenAIEmbeddings          serverCapability = "openai_embeddings"
	serverCapabilityAnthropicMessages         serverCapability = "anthropic_messages"
	serverCapabilityOpaqueHTTP                serverCapability = "opaque_http"
	serverCapabilityConfigurationImportExport serverCapability = "configuration_import_export"
	serverCapabilityAdminSessionManagement    serverCapability = "admin_session_management"
	serverCapabilityAdminEventStream          serverCapability = "admin_event_stream"
)

// supportedServerCapabilities is intentionally ordered and closed. Append-only
// changes require an Admin API contract update and a compatibility decision.
var supportedServerCapabilities = [...]serverCapability{
	serverCapabilityAppAttest,
	serverCapabilityPlayIntegrity,
	serverCapabilityFirebaseAppCheck,
	serverCapabilityTurnstile,
	serverCapabilityComponentDelegation,
	serverCapabilityCostLimits,
	serverCapabilityOpenAIResponses,
	serverCapabilityOpenAIChat,
	serverCapabilityOpenAIEmbeddings,
	serverCapabilityAnthropicMessages,
	serverCapabilityOpaqueHTTP,
	serverCapabilityConfigurationImportExport,
	serverCapabilityAdminSessionManagement,
	serverCapabilityAdminEventStream,
}

func serverCapabilities() []serverCapability {
	result := make([]serverCapability, len(supportedServerCapabilities))
	copy(result, supportedServerCapabilities[:])
	return result
}
