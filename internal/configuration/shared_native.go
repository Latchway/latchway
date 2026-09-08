package configuration

import (
	"github.com/latchway/latchway/internal/clientruntime"
	"slices"
)

// SharedNativeCallersValid rejects misplaced/ambiguous opt-ins even when an old
// compiled snapshot did not pass the current JSON schema validator.
func SharedNativeCallersValid(platform string, selection PlatformAttestation) bool {
	if len(selection.SharedNativeCallers) == 0 {
		return true
	}
	if selection.Mode != "required" || (platform != "ios" && platform != "android") || len(selection.SharedNativeCallers) > 2 {
		return false
	}
	seen := make(map[string]bool)
	for _, caller := range selection.SharedNativeCallers {
		if seen[caller] || !clientruntime.MatchesHost(clientruntime.SharedSDK, caller, platform) {
			return false
		}
		seen[caller] = true
	}
	return true
}

// AllowsClientRuntime applies the explicit native host caller policy. Delegated
// components still need independent credentials and component/family validation;
// this attribution decision cannot turn their credentials into root credentials.
func (snapshot ActiveSnapshot) AllowsClientRuntime(sdk, caller, platform string, delegated bool) bool {
	if !clientruntime.MatchesHost(sdk, caller, platform) {
		return false
	}
	if sdk != clientruntime.SharedSDK {
		return true
	}
	_, selection, ok := snapshot.RequiredAttestationForPlatform(platform)
	return ok && SharedNativeCallersValid(platform, selection) && slices.Contains(selection.SharedNativeCallers, caller)
}

// AllowsDelegatedClientRuntime binds shared attribution to the actual parent
// host, in addition to the component's independent session and feature checks.
func (snapshot ActiveSnapshot) AllowsDelegatedClientRuntime(sdk, caller, hostPlatform, definitionID string) bool {
	if sdk != "native" {
		return true
	}
	definition, ok := snapshot.ComponentDefinition(definitionID)
	return ok && definition.FamilyRole == "delegated" && definition.Platform == hostPlatform &&
		snapshot.AllowsClientRuntime(sdk, caller, hostPlatform, true)
}
