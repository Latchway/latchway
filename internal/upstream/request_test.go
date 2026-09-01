package upstream

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPrepareRequestReconstructsTrustBoundary(t *testing.T) {
	t.Parallel()

	target, err := NewTarget("https://api.example.test/provider", DestinationPolicy{}, Timeouts{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions?client=ignored", strings.NewReader(`{"messages":[{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	incoming.Header = http.Header{
		"Authorization":          {"DPoP client-token"},
		"Dpop":                   {"client.proof"},
		"X-Latchway-Feature":     {"assistant"},
		"X-Forwarded-For":        {"127.0.0.1"},
		"Accept-Encoding":        {"gzip"},
		"Content-Type":           {"application/json"},
		"Accept":                 {"text/event-stream"},
		"Traceparent":            {"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"},
		"Tracestate":             {"attacker=value"},
		"Baggage":                {"private=value"},
		"X-Provider-Tenant":      {"client"},
		"X-Unlisted-Application": {"drop"},
	}
	incoming.TransferEncoding = []string{"chunked"}
	incoming.Trailer = http.Header{"X-Trailer": {"drop"}}

	prepared, err := PrepareRequest(
		incoming,
		target,
		"/v1/chat/completions",
		[]string{"Content-Type", "Accept", "X-Provider-Tenant"},
		map[string]string{"X-Provider-Tenant": "configured"},
	)
	if err != nil {
		t.Fatal(err)
	}
	outbound := prepared.request
	if got, want := outbound.URL.String(), "https://api.example.test/provider/v1/chat/completions"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if outbound.RequestURI != "" || outbound.Host != "" || len(outbound.TransferEncoding) != 0 || len(outbound.Trailer) != 0 {
		t.Fatalf("transport controls survived reconstruction: %#v", outbound)
	}
	if got := outbound.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if got := outbound.Header.Get("Accept"); got != "text/event-stream" {
		t.Fatalf("accept = %q", got)
	}
	if got := outbound.Header.Get("X-Provider-Tenant"); got != "configured" {
		t.Fatalf("static override = %q", got)
	}
	if got := outbound.Header.Get("Accept-Encoding"); got != "identity" {
		t.Fatalf("accept encoding = %q", got)
	}
	for _, name := range []string{"Authorization", "Dpop", "X-Latchway-Feature", "X-Forwarded-For", "X-Unlisted-Application", "Traceparent", "Tracestate", "Baggage"} {
		if got := outbound.Header.Get(name); got != "" {
			t.Fatalf("unsafe header %s = %q", name, got)
		}
	}
	if body, _ := io.ReadAll(outbound.Body); string(body) != `{"messages":[{}]}` {
		t.Fatalf("body = %q", body)
	}
	if incoming.URL.RawQuery != "client=ignored" || incoming.Header.Get("Authorization") == "" {
		t.Fatal("incoming request was mutated")
	}
}

func TestPrepareRequestRejectsUnsafeConfiguredHeaders(t *testing.T) {
	t.Parallel()

	target, err := NewTarget("https://api.example.test", DestinationPolicy{}, Timeouts{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	incoming, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader("{}"))
	if _, err := PrepareRequest(incoming, target, "/v1/chat/completions", nil, map[string]string{"Accept-Encoding": "gzip"}); err == nil {
		t.Fatal("configured response-obscuring compression accepted")
	}
	for _, name := range []string{"Traceparent", "Tracestate", "Baggage"} {
		if _, err := PrepareRequest(incoming, target, "/v1/chat/completions", nil, map[string]string{name: "attacker-controlled"}); err == nil {
			t.Fatalf("configured %s override accepted", name)
		}
		if _, err := PrepareRequest(incoming, target, "/v1/chat/completions", []string{name}, nil); err == nil {
			t.Fatalf("client %s forwarding accepted", name)
		}
	}
	if _, err := PrepareRequest(
		incoming, target, "/v1/chat/completions", nil, nil,
		TraceContextPropagationW3C, TraceContextPropagationNone,
	); err == nil {
		t.Fatal("multiple trace-context propagation modes accepted")
	}
	if _, err := PrepareRequest(
		incoming, target, "/v1/chat/completions", nil, nil, TraceContextPropagation(255),
	); err == nil {
		t.Fatal("unknown trace-context propagation mode accepted")
	}
}

func TestPrepareBaseRequestUsesExactConfiguredResource(t *testing.T) {
	t.Parallel()

	target, err := NewTarget("https://keys.example.test/.well-known/jwks.json", DestinationPolicy{}, Timeouts{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := http.NewRequest(http.MethodGet, "https://gateway.example/attacker-selected?ignored=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	incoming.Header.Set("Accept", "application/json")
	incoming.Header.Set("If-None-Match", `"v1"`)
	prepared, err := PrepareBaseRequest(incoming, target, []string{"Accept", "If-None-Match"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := prepared.request.URL.String(), "https://keys.example.test/.well-known/jwks.json"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if got := prepared.request.Header.Get("If-None-Match"); got != `"v1"` {
		t.Fatalf("conditional validator = %q", got)
	}
}

func TestPrepareRequestRejectsEncodedAndAmbiguousSemanticHeaders(t *testing.T) {
	t.Parallel()

	target, err := NewTarget("https://api.example.test", DestinationPolicy{}, Timeouts{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		header http.Header
	}{
		{name: "content encoding", header: http.Header{"Content-Encoding": {"gzip"}}},
		{name: "lowercase content encoding", header: http.Header{"content-encoding": {"gzip"}}},
		{name: "duplicate content type", header: http.Header{"Content-Type": {"application/json", "text/plain"}}},
		{name: "case variant authorization", header: http.Header{"Authorization": {"DPoP one"}, "authorization": {"DPoP two"}}},
		{name: "duplicate dpop", header: http.Header{"Dpop": {"one", "two"}}},
		{name: "duplicate accept", header: http.Header{"Accept": {"application/json", "text/event-stream"}}},
		{name: "duplicate expect", header: http.Header{"Expect": {"100-continue", "100-continue"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			incoming, requestErr := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader("{}"))
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			incoming.Header = test.header
			if _, err := PrepareRequest(incoming, target, "/v1/chat/completions", []string{"Content-Type", "Accept"}, nil); err == nil {
				t.Fatal("unsafe request headers accepted")
			}
		})
	}
}
