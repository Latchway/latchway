package upstream

import (
	"net/http"
	"testing"
)

func TestForwardHeadersStripsCredentialsAndHopByHop(t *testing.T) {
	t.Parallel()

	incoming := http.Header{
		"Authorization":      {"DPoP client-token"},
		"X-Api-Key":          {"client-secret"},
		"X-Latchway-Feature": {"habit-assistant"},
		"Connection":         {"X-Remove-Me"},
		"X-Remove-Me":        {"hop-by-hop"},
		"Content-Type":       {"application/json"},
		"Accept":             {"text/event-stream"},
	}
	outbound, err := ForwardHeaders(incoming, []string{"Content-Type", "Accept", "X-Remove-Me"})
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Get("Authorization") != "" || outbound.Get("X-Api-Key") != "" || outbound.Get("X-Latchway-Feature") != "" || outbound.Get("X-Remove-Me") != "" {
		t.Fatalf("forbidden header forwarded: %#v", outbound)
	}
	if outbound.Get("Content-Type") != "application/json" || outbound.Get("Accept") != "text/event-stream" {
		t.Fatalf("allowed header missing: %#v", outbound)
	}
}

func TestApplyBearerCredentialReplacesIncomingValue(t *testing.T) {
	t.Parallel()

	headers := http.Header{"Authorization": {"client value", "duplicate"}}
	if err := ApplyBearerCredential(headers, []byte("server-secret")); err != nil {
		t.Fatal(err)
	}
	if values := headers.Values("Authorization"); len(values) != 1 || values[0] != "Bearer server-secret" {
		t.Fatalf("authorization values = %#v", values)
	}
}

func TestAllowlistCannotPermitCredentials(t *testing.T) {
	t.Parallel()

	if _, err := ForwardHeaders(http.Header{}, []string{"Authorization"}); err == nil {
		t.Fatal("credential header allowlisted")
	}
}
