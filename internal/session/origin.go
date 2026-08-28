package session

import (
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/weborigin"
)

// platformOriginAllowed is the durable browser-authority check. CORS may let a
// syntactically valid origin deliver a request, but only an exact origin from
// the active immutable platform selection can authorize a web session. Native
// sessions reject both an Origin header and corrupt origin-bearing policy.
func platformOriginAllowed(selection configuration.PlatformAttestation, platform, origin string) bool {
	if platform != "web" {
		return origin == "" && len(selection.AllowedOrigins) == 0
	}
	if selection.Mode != "required" || !weborigin.Canonical(origin) ||
		len(selection.AllowedOrigins) == 0 || len(selection.AllowedOrigins) > 32 {
		return false
	}
	found := false
	seen := make(map[string]struct{}, len(selection.AllowedOrigins))
	for _, allowed := range selection.AllowedOrigins {
		if !weborigin.Canonical(allowed) {
			return false
		}
		if _, duplicate := seen[allowed]; duplicate {
			return false
		}
		seen[allowed] = struct{}{}
		if allowed == origin {
			found = true
		}
	}
	return found
}

func snapshotOriginAllowed(snapshot configuration.ActiveSnapshot, platform, origin string) bool {
	// Origin is a browser authority. Native transports must omit it, but a
	// missing or changed native attestation selection is evaluated separately by
	// the session policy path so callers receive the stable step-up result.
	if platform != "web" {
		return origin == ""
	}
	_, selection, ok := snapshot.RequiredAttestationForPlatform(platform)
	return ok && platformOriginAllowed(selection, platform, origin)
}
