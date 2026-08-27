package upstream

import (
	"net/http"
	"testing"
)

func TestForwardHeadersStripsCredentialsAndHopByHop(t *testing.T) {
	t.Parallel()

	incoming := http.Header{
		"Authorization":      {"DPoP client-token"},
		"DPoP":               {"client.proof.signature"},
		"DPoP-Nonce":         {"client-nonce"},
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
	if outbound.Get("Authorization") != "" || outbound.Get("DPoP") != "" || outbound.Get("DPoP-Nonce") != "" || outbound.Get("X-Api-Key") != "" || outbound.Get("X-Latchway-Feature") != "" || outbound.Get("X-Remove-Me") != "" {
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

	for _, name := range []string{"Authorization", "DPoP", "DPoP-Nonce", "Content-Length", "Host", "X-Auth-Token"} {
		if _, err := ForwardHeaders(http.Header{}, []string{name}); err == nil {
			t.Fatalf("credential or transport-control header %q was allowlisted", name)
		}
	}
}
