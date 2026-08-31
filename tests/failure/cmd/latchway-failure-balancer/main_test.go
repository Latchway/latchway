package main

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

func TestBalancerSelectsExplicitAndRoundRobinBackends(t *testing.T) {
	t.Parallel()
	token := "0123456789abcdef0123456789abcdef"
	proxy, err := newBalancer("127.0.0.1:18080", []string{"http://127.0.0.1:8080", "http://127.0.0.2:8080"}, token, false)
	if err != nil {
		t.Fatal(err)
	}
	incoming := httptest.NewRequest(http.MethodGet, "http://failure.local/readyz", nil)
	incoming.RemoteAddr = "127.0.0.9:12345"
	incoming.Header.Set(routeHeader, "1")
	outgoing := incoming.Clone(incoming.Context())
	proxy.proxies[0].Rewrite(&httputil.ProxyRequest{In: incoming, Out: outgoing})
	if outgoing.Header.Get(routeHeader) != "" || outgoing.URL.Host != "127.0.0.1:8080" ||
		outgoing.Header.Get("X-Forwarded-For") != "127.0.0.9" {
		t.Fatalf("rewritten request = %s %q %q", outgoing.URL, outgoing.Header.Get(routeHeader), outgoing.Header.Get("X-Forwarded-For"))
	}
	if index, ok := proxy.backendIndex("2"); !ok || index != 1 {
		t.Fatalf("explicit selection = %d/%t", index, ok)
	}
	if _, ok := proxy.backendIndex("02"); ok {
		t.Fatal("noncanonical explicit backend was accepted")
	}
	for want := 0; want < 2; want++ {
		if got, ok := proxy.backendIndex(""); !ok || got != want {
			t.Fatalf("round-robin selection = %d/%t, want %d", got, ok, want)
		}
	}
	proxy.counts[0].Add(2)
	proxy.counts[1].Add(3)
	stats := httptest.NewRequest(http.MethodGet, "http://failure.local"+statsPath, nil)
	stats.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	proxy.serveStats(recorder, stats)
	if recorder.Code != http.StatusOK || recorder.Body.String() == "" {
		t.Fatalf("stats response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestBalancerRejectsUnsafeCoordinates(t *testing.T) {
	t.Parallel()
	token := "0123456789abcdef0123456789abcdef"
	backends := []string{"http://127.0.0.1:8080", "http://127.0.0.2:8080"}
	if _, err := newBalancer("0.0.0.0:18080", backends, token, false); err == nil {
		t.Fatal("wildcard listen without isolated acknowledgement was accepted")
	}
	if _, err := newBalancer("8.8.8.8:18080", backends, token, true); err == nil {
		t.Fatal("public listen address was accepted")
	}
	if _, err := newBalancer("127.0.0.1:18080", []string{"https://example.com", "http://127.0.0.2:8080"}, token, false); err == nil {
		t.Fatal("public or TLS backend coordinate was accepted")
	}
}
