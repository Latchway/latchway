// Package frameworkcompat exposes the bounded runtime projection of the
// canonical compatibility/frameworks.yaml registry. The registry remains the
// source of public support claims; this package only validates transport
// declarations and their owning Latchway SDK.
package frameworkcompat

import (
	"slices"
	"strings"
)

var ids = []string{
	"android-okhttp",
	"foundation-models",
	"langchain-js",
	"macpaw-openai",
	"openai-js",
	"react-native-fetch",
	"swift-openai",
	"vercel-ai-sdk",
}

// IDs returns the canonical sorted framework identifiers accepted on the
// wire. The returned slice is detached from package state.
func IDs() []string { return append([]string(nil), ids...) }

// Known reports whether framework is a canonical registry identifier.
func Known(framework string) bool { return slices.Contains(ids, framework) }

// Compatible reports whether a canonical framework integration belongs to
// the declared first-party Latchway SDK.
func Compatible(sdk, framework string) bool {
	switch sdk {
	case "ios":
		return slices.Contains([]string{"foundation-models", "macpaw-openai", "swift-openai"}, framework)
	case "android":
		return framework == "android-okhttp"
	case "javascript":
		return slices.Contains([]string{"langchain-js", "openai-js", "vercel-ai-sdk"}, framework)
	case "react-native":
		return framework == "react-native-fetch"
	default:
		return false
	}
}

// ValidVersion accepts exactly one bounded canonical SemVer 2.0.0 value.
// Build metadata is allowed but never changes the registry integration ID.
func ValidVersion(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	version, build, hasBuild := strings.Cut(value, "+")
	if hasBuild && !validIdentifiers(build, false) {
		return false
	}
	core, prerelease, hasPrerelease := strings.Cut(version, "-")
	if hasPrerelease && !validIdentifiers(prerelease, true) {
		return false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !validNumericIdentifier(part) {
			return false
		}
	}
	return true
}

func validIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for index := 0; index < len(identifier); index++ {
			character := identifier[index]
			if character >= '0' && character <= '9' {
				continue
			}
			numeric = false
			if (character < 'A' || character > 'Z') &&
				(character < 'a' || character > 'z') && character != '-' {
				return false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func validNumericIdentifier(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
