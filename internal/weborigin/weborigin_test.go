package weborigin

import (
	"net/http"
	"reflect"
	"testing"
)

func TestCanonicalOriginAndExactHeader(t *testing.T) {
	t.Parallel()
	valid := []string{
		"https://app.example.test",
		"https://app.example.test:8443",
		"https://127.0.0.1:8443",
		"https://[::1]:8443",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		"http://[::1]:5173",
	}
	for _, value := range valid {
		if !Canonical(value) {
			t.Errorf("Canonical(%q) = false", value)
		}
		header := http.Header{"Origin": []string{value}}
		if got, err := Read(header); err != nil || got != value {
			t.Errorf("Read(%q) = %q, %v", value, got, err)
		}
	}
	invalid := []string{
		"null", "http://app.example.test", "http://localhost:80", "https://App.example.test",
		"https://app.example.test/", "https://app.example.test:443",
		"https://app.example.test/path", "https://user@app.example.test",
		"https://app.example.test?x=1", "https://app.example.test#x",
		"https://app.example.test.", "https://bad..example.test",
		" https://app.example.test", "https://app_example.test",
		"https://app.example.test:08443",
		"https://127.000.000.001", "https://[0:0:0:0:0:0:0:1]:8443",
	}
	for _, value := range invalid {
		if Canonical(value) {
			t.Errorf("Canonical(%q) = true", value)
		}
	}
	if !Secure("https://app.example.test") || Secure("http://localhost:5173") ||
		!LoopbackHTTP("http://127.0.0.1:5173") || LoopbackHTTP("https://127.0.0.1:5173") {
		t.Fatal("origin security classification is inconsistent")
	}
	duplicate := http.Header{"Origin": []string{"https://app.example.test", "https://other.example.test"}}
	if _, err := Read(duplicate); err == nil {
		t.Fatal("duplicate Origin was accepted")
	}
}

func TestCORSRequestDeclarationsAreBounded(t *testing.T) {
	t.Parallel()
	header := http.Header{
		"Access-Control-Request-Method":  []string{"POST"},
		"Access-Control-Request-Headers": []string{"Content-Type, DPoP, X-Latchway-SDK"},
	}
	if method, err := RequestedMethod(header); err != nil || method != "POST" {
		t.Fatalf("RequestedMethod() = %q, %v", method, err)
	}
	want := []string{"content-type", "dpop", "x-latchway-sdk"}
	if got, err := RequestedHeaders(header); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("RequestedHeaders() = %#v, %v", got, err)
	}
	header["Access-Control-Request-Headers"] = []string{"DPoP, dpop"}
	if _, err := RequestedHeaders(header); err == nil {
		t.Fatal("duplicate requested header was accepted")
	}
	header["Access-Control-Request-Method"] = []string{"post"}
	if _, err := RequestedMethod(header); err == nil {
		t.Fatal("non-canonical requested method was accepted")
	}
}

func TestResponseHeadersNeverEnableCookieCredentials(t *testing.T) {
	t.Parallel()
	header := make(http.Header)
	header.Set("Vary", "Accept-Encoding")
	SetResponseHeaders(header, "https://app.example.test")
	SetResponseHeaders(header, "https://app.example.test")
	if header.Get("Access-Control-Allow-Origin") != "https://app.example.test" ||
		header.Get("Access-Control-Allow-Credentials") != "" ||
		len(header.Values("Vary")) != 2 {
		t.Fatalf("response headers = %#v", header)
	}
}
