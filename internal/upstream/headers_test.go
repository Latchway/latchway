package upstream

import (
	"encoding/base64"
	"net/http"
	"strings"
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

func TestAnthropicVersionCanOnlyFlowThroughTrustedForwarding(t *testing.T) {
	t.Parallel()

	incoming := http.Header{"Anthropic-Version": {"2023-06-01"}}
	forwarded, err := ForwardHeaders(incoming, []string{"Anthropic-Version"})
	if err != nil || forwarded.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("trusted Anthropic version forwarding = %#v, err=%v", forwarded, err)
	}
	if err := ApplyStaticHeaders(http.Header{}, map[string]string{"Anthropic-Version": "2099-01-01"}); err == nil {
		t.Fatal("administrator static Anthropic version override accepted")
	}
	if err := withHeaderCredential(http.Header{}, "Anthropic-Version", []byte("secret"), func() error { return nil }); err == nil {
		t.Fatal("Anthropic version accepted as a credential header")
	}
	if _, err := ForwardHeaders(http.Header{
		"Anthropic-Version": {"2023-06-01"}, "anthropic-version": {"2099-01-01"},
	}, []string{"Anthropic-Version"}); err == nil {
		t.Fatal("duplicate case-variant Anthropic versions accepted")
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

func TestBasicCredentialScopeIsEphemeralAndFailClosed(t *testing.T) {
	t.Parallel()

	password := []byte{'p', 0, 'a', 's', 's'}
	want := "Basic " + base64.StdEncoding.EncodeToString(append([]byte("user:"), password...))
	headers := make(http.Header)
	if err := withBasicCredential(headers, "user", password, func() error {
		if values := headers.Values("Authorization"); len(values) != 1 || values[0] != want {
			t.Fatalf("authorization values inside scope = %#v, want %q", values, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if values := headers.Values("Authorization"); len(values) != 0 {
		t.Fatalf("authorization survived scope = %#v", values)
	}

	for _, test := range []struct {
		name     string
		username string
		password []byte
		headers  http.Header
	}{
		{name: "empty username", password: []byte("secret")},
		{name: "colon in username", username: "user:name", password: []byte("secret")},
		{name: "space in username", username: "user name", password: []byte("secret")},
		{name: "control in username", username: "user\n", password: []byte("secret")},
		{name: "oversized username", username: strings.Repeat("u", 257), password: []byte("secret")},
		{name: "empty password", username: "user"},
		{name: "oversized password", username: "user", password: make([]byte, maximumForwardedHeaderBytes+1)},
		{name: "preexisting authorization", username: "user", password: []byte("secret"), headers: http.Header{"Authorization": {"client"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.headers == nil {
				test.headers = make(http.Header)
			}
			before := test.headers.Clone()
			if err := withBasicCredential(test.headers, test.username, test.password, func() error {
				t.Fatal("operation ran for invalid Basic credential")
				return nil
			}); err == nil {
				t.Fatal("invalid Basic credential accepted")
			}
			if got, want := test.headers.Get("Authorization"), before.Get("Authorization"); got != want {
				t.Fatalf("authorization mutated on failure = %q, want %q", got, want)
			}
		})
	}
}

func TestMultipleHeaderCredentialScopeIsAtomicEphemeralAndBounded(t *testing.T) {
	t.Parallel()

	headers := http.Header{"X-Static": {"configured"}}
	credentials := []HeaderCredential{
		{Name: "X-Provider-Key", Value: []byte("server secret")},
		{Name: "x-provider-tenant", Value: []byte("tenant secret")},
	}
	if err := withHeaderCredentials(headers, credentials, func() error {
		if headers.Get("X-Provider-Key") != "server secret" || headers.Get("X-Provider-Tenant") != "tenant secret" {
			t.Fatalf("credential headers inside scope = %#v", headers)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if headers.Get("X-Provider-Key") != "" || headers.Get("X-Provider-Tenant") != "" || headers.Get("X-Static") != "configured" {
		t.Fatalf("headers after scope = %#v", headers)
	}

	nine := make([]HeaderCredential, 9)
	for index := range nine {
		nine[index] = HeaderCredential{Name: "X-Key-" + string(rune('A'+index)), Value: []byte("secret")}
	}
	for _, test := range []struct {
		name        string
		headers     http.Header
		credentials []HeaderCredential
	}{
		{name: "empty"},
		{name: "too many", credentials: nine},
		{name: "duplicate case variant", credentials: []HeaderCredential{{Name: "X-Provider-Key", Value: []byte("one")}, {Name: "x-provider-key", Value: []byte("two")}}},
		{name: "forbidden", credentials: []HeaderCredential{{Name: "Content-Type", Value: []byte("secret")}}},
		{name: "oversized name", credentials: []HeaderCredential{{Name: "X" + strings.Repeat("a", 256), Value: []byte("secret")}}},
		{name: "malformed value", credentials: []HeaderCredential{{Name: "X-Provider-Key", Value: []byte("secret\nvalue")}}},
		{name: "preexisting collision", headers: http.Header{"X-Provider-Key": {"static"}}, credentials: []HeaderCredential{{Name: "x-provider-key", Value: []byte("secret")}}},
		{name: "aggregate too large", credentials: []HeaderCredential{
			{Name: "X-Provider-Key", Value: []byte(strings.Repeat("a", maximumForwardedHeaderBytes/2))},
			{Name: "X-Provider-Tenant", Value: []byte(strings.Repeat("b", maximumForwardedHeaderBytes/2))},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.headers == nil {
				test.headers = make(http.Header)
			}
			before := test.headers.Clone()
			if err := withHeaderCredentials(test.headers, test.credentials, func() error {
				t.Fatal("operation ran for invalid multiple-header credentials")
				return nil
			}); err == nil {
				t.Fatal("invalid multiple-header credentials accepted")
			}
			if len(test.headers) != len(before) {
				t.Fatalf("headers mutated on failure: before=%#v after=%#v", before, test.headers)
			}
			for name, values := range before {
				if got := test.headers.Values(name); strings.Join(got, "\x00") != strings.Join(values, "\x00") {
					t.Fatalf("%s mutated on failure: before=%#v after=%#v", name, values, got)
				}
			}
		})
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
		{name: "static Anthropic version", headers: map[string]string{"Anthropic-Version": "2099-01-01"}},
		{name: "static line break", headers: map[string]string{"X-Provider-Tenant": "bad\nvalue"}},
		{name: "header control", credential: []byte("secret"), headerName: "Content-Type"},
		{name: "header Anthropic version", credential: []byte("secret"), headerName: "Anthropic-Version"},
		{name: "header invalid name", credential: []byte("secret"), headerName: "X Provider Key"},
		{name: "header oversized name", credential: []byte("secret"), headerName: "X" + strings.Repeat("a", 256)},
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
		{name: "Anthropic version", incoming: http.Header{"Anthropic-Version": {"2023-06-01", "2099-01-01"}}, allowlist: []string{"Anthropic-Version"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ForwardHeaders(test.incoming, test.allowlist); err == nil {
				t.Fatal("duplicate singleton header accepted")
			}
		})
	}
}
