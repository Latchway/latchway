package session

import (
	"errors"
	"github.com/latchway/latchway/internal/clientruntime"
	"github.com/latchway/latchway/internal/configuration"
)

// ErrClientRuntime means the caller declaration is incompatible with the
// attested host/policy. It is not evidence that the underlying session revoked.
var ErrClientRuntime = errors.New("client runtime is not allowed for this host")

func requestRuntimeAllowed(snapshot configuration.ActiveSnapshot, declaration clientruntime.Declaration, platform string, delegated bool) bool {
	// Package-internal maintenance and test callers predate HTTP metadata. Public
	// HTTP parsers always populate SDK; an incomplete shared declaration fails.
	if declaration.SDK == "" {
		return declaration.Caller == "" && declaration.Protocol == ""
	}
	if declaration.SDK == clientruntime.SharedSDK && declaration.Validate() != nil {
		return false
	}
	return snapshot.AllowsClientRuntime(declaration.SDK, declaration.Caller, platform, delegated)
}

// Shared native delegated requests are limited to the same iOS/Android host
// boundary as the parent installation. A watch/remote or runtime-specific legacy
// definition is not silently converted by supplying the new attribution header.
func requestDelegatedRuntimeAllowed(snapshot configuration.ActiveSnapshot, declaration clientruntime.Declaration, hostPlatform, definitionID string) bool {
	if declaration.SDK != clientruntime.SharedSDK {
		return true
	}
	return declaration.Validate() == nil && snapshot.AllowsDelegatedClientRuntime(
		declaration.SDK, declaration.Caller, hostPlatform, definitionID)
}
