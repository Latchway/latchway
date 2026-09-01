package adminapi

import (
	"reflect"
	"testing"
)

func TestServerCapabilitiesAreClosedAndStablyOrdered(t *testing.T) {
	t.Parallel()

	want := []serverCapability{
		"app_attest",
		"play_integrity",
		"firebase_app_check",
		"turnstile",
		"component_delegation",
		"cost_limits",
		"openai_responses",
		"openai_chat",
		"openai_embeddings",
		"anthropic_messages",
		"opaque_http",
		"configuration_import_export",
		"admin_session_management",
		"admin_event_stream",
	}
	first := serverCapabilities()
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("serverCapabilities() = %q, want %q", first, want)
	}
	first[0] = "unknown"
	if second := serverCapabilities(); !reflect.DeepEqual(second, want) {
		t.Fatalf("serverCapabilities() did not return a defensive stable copy: %q", second)
	}
	seen := make(map[serverCapability]struct{}, len(want))
	for _, capability := range serverCapabilities() {
		if _, duplicate := seen[capability]; duplicate {
			t.Fatalf("serverCapabilities() contains duplicate %q", capability)
		}
		seen[capability] = struct{}{}
	}
	if _, supported := seen["admin_event_stream"]; !supported {
		t.Fatal("serverCapabilities() omits supported admin_event_stream")
	}
}
