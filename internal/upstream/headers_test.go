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

func TestBearerCredentialScopeIsEphemeralAndRejectsIncomingValue(t *testing.T) {
	t.Parallel()

	headers := make(http.Header)
	if err := withBearerCredential(headers, []byte("server-secret"), func() error {
		if values := headers.Values("Authorization"); len(values) != 1 || values[0] != "Bearer server-secret" {
			t.Fatalf("authorization values inside scope = %#v", values)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if values := headers.Values("Authorization"); len(values) != 0 {
		t.Fatalf("authorization survived scope = %#v", values)
	}
	headers.Set("Authorization", "client value")
	if err := withBearerCredential(headers, []byte("server-secret"), func() error { return nil }); err == nil {
		t.Fatal("preexisting authorization value accepted")
	}
}

func TestApplyConfiguredHeadersFailClosed(t *testing.T) {
	t.Parallel()

	headers := http.Header{"X-Provider-Tenant": {"client"}}
	if err := ApplyStaticHeaders(headers, map[string]string{"X-Provider-Tenant": "configured"}); err != nil {
		t.Fatal(err)
	}
	if got := headers.Get("X-Provider-Tenant"); got != "configured" {
		t.Fatalf("static header = %q", got)
	}
	if err := withHeaderCredential(headers, "X-Api-Key", []byte("server secret"), func() error {
		if got := headers.Get("X-Api-Key"); got != "server secret" {
			t.Fatalf("header credential inside scope = %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := headers.Get("X-Api-Key"); got != "" {
		t.Fatalf("header credential survived scope = %q", got)
	}

	for _, test := range []struct {
		name       string
		headers    map[string]string
		credential []byte
		headerName string
	}{
		{name: "static authorization", headers: map[string]string{"Authorization": "secret"}},
		{name: "static control", headers: map[string]string{"X-Latchway-Route": "override"}},
		{name: "static accept", headers: map[string]string{"Accept": "application/json"}},
		{name: "static content type", headers: map[string]string{"Content-Type": "application/json"}},
		{name: "static line break", headers: map[string]string{"X-Provider-Tenant": "bad\nvalue"}},
		{name: "header control", credential: []byte("secret"), headerName: "Content-Type"},
		{name: "header invalid name", credential: []byte("secret"), headerName: "X Provider Key"},
		{name: "credential line break", credential: []byte("bad\nsecret"), headerName: "X-Provider-Key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := make(http.Header)
			var err error
			if test.headers != nil {
				err = ApplyStaticHeaders(copy, test.headers)
			} else {
				err = withHeaderCredential(copy, test.headerName, test.credential, func() error { return nil })
			}
			if err == nil {
				t.Fatal("unsafe configured header accepted")
			}
			if len(copy) != 0 {
				t.Fatalf("headers mutated on validation failure: %#v", copy)
			}
		})
	}
}

func TestBearerCredentialRejectsUnsafeBytesWithoutMutation(t *testing.T) {
	t.Parallel()

	for _, credential := range [][]byte{nil, []byte("bad secret"), []byte("bad\nsecret"), []byte("one,two"), {0xff}} {
		headers := make(http.Header)
		if err := withBearerCredential(headers, credential, func() error { return nil }); err == nil {
			t.Fatalf("credential %q accepted", credential)
		}
		if got := headers.Values("Authorization"); len(got) != 0 {
			t.Fatalf("headers mutated for rejected credential: %#v", got)
		}
	}
}

func TestAllowlistCannotPermitCredentials(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"Authorization", "DPoP", "DPoP-Nonce", "Content-Encoding", "Content-Length", "Expect", "Host", "X-Auth-Token"} {
		if _, err := ForwardHeaders(http.Header{}, []string{name}); err == nil {
			t.Fatalf("credential or transport-control header %q was allowlisted", name)
		}
	}
}

func TestForwardHeadersRejectsDuplicateSingletonSemantics(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		incoming  http.Header
		allowlist []string
	}{
		{name: "accept", incoming: http.Header{"Accept": {"application/json", "text/event-stream"}}, allowlist: []string{"Accept"}},
		{name: "content type case variants", incoming: http.Header{"Content-Type": {"application/json"}, "content-type": {"text/plain"}}, allowlist: []string{"Content-Type"}},
		{name: "authorization even when stripped", incoming: http.Header{"Authorization": {"DPoP one", "DPoP two"}}},
		{name: "dpop even when stripped", incoming: http.Header{"Dpop": {"one", "two"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ForwardHeaders(test.incoming, test.allowlist); err == nil {
				t.Fatal("duplicate singleton header accepted")
			}
		})
	}
}
