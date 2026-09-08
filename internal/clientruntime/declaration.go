// Package clientruntime defines the shared native backend's wire declaration.
// It does not authenticate callers; configuration and attestation authorize them.
package clientruntime

import "errors"

const SharedSDK = "native"
const CallerHeader = "X-Latchway-Caller"

var ErrDeclaration = errors.New("invalid client runtime declaration")

type Declaration struct {
	Protocol string
	SDK      string
	Caller   string
}

func (declaration Declaration) Validate() error {
	return Validate(declaration.Protocol, declaration.SDK, declaration.Caller)
}

// Validate rejects caller headers on legacy SDKs and requires an explicit
// protocol-3 caller for a shared native backend. Empty/multi-value headers must
// be rejected by the HTTP parser before this function is called.
func Validate(protocol, sdk, caller string) error {
	if sdk == SharedSDK {
		if protocol == "3" && (caller == "ios" || caller == "android" || caller == "react-native") {
			return nil
		}
		return ErrDeclaration
	}
	if caller != "" || (sdk != "ios" && sdk != "android" && sdk != "react-native" && sdk != "javascript") {
		return ErrDeclaration
	}
	if protocol != "1" && protocol != "2" && protocol != "3" {
		return ErrDeclaration
	}
	return nil
}

// MatchesHost is only the syntactic declaration check. A shared request also
// requires explicit server policy approval for its caller on that native host.
func MatchesHost(sdk, caller, platform string) bool {
	if sdk == SharedSDK {
		return platform == "ios" && (caller == "ios" || caller == "react-native") ||
			platform == "android" && (caller == "android" || caller == "react-native")
	}
	if caller != "" {
		return false
	}
	switch sdk {
	case "ios":
		return platform == "ios" || platform == "watchos"
	case "android":
		return platform == "android"
	case "react-native":
		return platform == "react_native_ios" || platform == "react_native_android"
	case "javascript":
		return platform == "web" || platform == "node"
	default:
		return false
	}
}

// FrameworkSDK preserves the caller's framework namespace without turning an
// attribution header into a trust claim.
func FrameworkSDK(sdk, caller string) string {
	if sdk == SharedSDK {
		return caller
	}
	return sdk
}
