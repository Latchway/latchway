package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/id"
)

func TestHealthHandler(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	healthHandler(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
}

func TestAdminAPIIsMountedAheadOfConsoleFallback(t *testing.T) {
	t.Parallel()

	admin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/probe" {
			t.Fatalf("mounted admin path = %q, want /admin/v1/probe", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server, err := New(config.Config{
		ListenAddress: "127.0.0.1:8080",
		ReadTimeout:   time.Second,
		IdleTimeout:   time.Second,
	}, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), Handlers{
		AdminAPI: admin,
		ClientAPI: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("client API should not handle an admin request")
		}),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/probe", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("admin route status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if err := id.Validate(recorder.Header().Get("X-Latchway-Request-ID"), id.LogicalRequest); err != nil {
		t.Fatalf("response request ID is not canonical: %v", err)
	}
}

func TestClientAPIIsMountedAtUnstrippedPathsAheadOfConsoleFallback(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 8)
	client := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	server, err := New(config.Config{
		ListenAddress: "127.0.0.1:8080",
		ReadTimeout:   time.Second,
		IdleTimeout:   time.Second,
	}, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), Handlers{
		AdminAPI:  http.NotFoundHandler(),
		ClientAPI: client,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, path := range []string{
		"/client/v1/session-challenges",
		"/client/v1/not-a-real-endpoint",
		"/v1/responses",
		"/v1/not-a-real-endpoint",
		"/proxy/configured-route/remaining/path",
		"/.well-known/jwks.json",
		"/.well-known/latchway",
		"/.well-known/not-a-real-endpoint",
	} {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("client route %q status = %d, want %d", path, recorder.Code, http.StatusNoContent)
		}
		if got := <-seen; got != path {
			t.Fatalf("client route path = %q, want %q", got, path)
		}
	}
}

func TestServerPreservesSafeClientRequestIDHint(t *testing.T) {
	t.Parallel()

	const hint = "client.request-123"
	server, err := New(config.Config{
		ListenAddress: "127.0.0.1:8080",
		ReadTimeout:   time.Second,
		IdleTimeout:   time.Second,
	}, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), Handlers{
		AdminAPI: http.NotFoundHandler(),
		ClientAPI: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Context().Value(middleware.RequestIDKey); got != hint {
				t.Fatalf("middleware request ID = %v, want %q", got, hint)
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	request.Header.Set("X-Latchway-Request-ID", hint)
	recorder := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("X-Latchway-Request-ID"); got != hint {
		t.Fatalf("response request ID = %q, want %q", got, hint)
	}
}

func TestSafeRequestIDHintRejectsAmbiguousOrUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{name: "too short", values: []string{"short"}},
		{name: "comma joined", values: []string{"request-one,request-two"}},
		{name: "whitespace inside", values: []string{"request id unsafe"}},
		{name: "multiple fields", values: []string{"request-one", "request-two"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range test.values {
				header.Add("X-Latchway-Request-ID", value)
			}
			if got := safeRequestIDHint(header); got != "" {
				t.Fatalf("unsafe request ID hint = %q", got)
			}
		})
	}
}

func TestRecovererWritesRegisteredProblem(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := latchwayRequestID(requestIDHeader(recoverer(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("test panic")
	}))))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if recorder.Code != http.StatusInternalServerError || recorder.Header().Get("Content-Type") != "application/problem+json" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected panic response: status=%d headers=%v", recorder.Code, recorder.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode panic problem: %v", err)
	}
	requestID := recorder.Header().Get("X-Latchway-Request-ID")
	if body["code"] != "internal_error" || body["request_id"] != requestID || body["retryable"] != false || body["detail"] == "" {
		t.Fatalf("incomplete panic problem: %#v", body)
	}
}
