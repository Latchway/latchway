package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	console "github.com/latchway/latchway/web/console"
)

func TestConsoleHandler(t *testing.T) {
	t.Parallel()

	assets, err := console.Assets()
	if err != nil {
		t.Fatal(err)
	}
	handler := newConsoleHandler(assets)

	t.Run("index", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Latchway Console") {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("console CSP is missing frame protection")
		}
	})

	t.Run("client route fallback", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system-health", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Latchway Console") {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("reserved API route", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/unknown", nil))
		if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "route_not_found") {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	})
}
