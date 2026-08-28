package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
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
		DataPlane: http.NotFoundHandler(),
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
		DataPlane: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, path := range []string{
		"/client/v1/session-challenges",
		"/client/v1/not-a-real-endpoint",
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

func TestDataPlaneOwnsTheReservedBoundedProtocolSpaces(t *testing.T) {
	t.Parallel()

	seenDataPlane := make(chan string, 16)
	seenClientAPI := make(chan string, 4)
	dataPlane := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requestidentity.FromContext(r.Context()); !ok {
			t.Fatal("data-plane request is missing its logical request identity")
		}
		target := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		seenDataPlane <- r.Method + " " + target
		w.WriteHeader(http.StatusAccepted)
	})
	clientAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenClientAPI <- r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	server, err := New(config.Config{
		ListenAddress: "127.0.0.1:8080",
		ReadTimeout:   time.Second,
		IdleTimeout:   time.Second,
	}, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), Handlers{
		AdminAPI: http.NotFoundHandler(), ClientAPI: clientAPI, DataPlane: dataPlane,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, candidate := range []struct {
		method string
		target string
	}{
		{method: http.MethodPost, target: "/v1/chat/completions"},
		{method: http.MethodGet, target: "/v1/chat/completions"},
		{method: http.MethodPost, target: "/v1/responses"},
		{method: http.MethodPost, target: "/v1/embeddings"},
		{method: http.MethodPost, target: "/v1/messages"},
		{method: http.MethodPost, target: "/proxy/weather/v2/current"},
		{method: http.MethodPost, target: "/v1/not-a-real-endpoint"},
		{method: http.MethodPost, target: "/proxy/not-a-real-endpoint"},
	} {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(
			recorder, httptest.NewRequest(candidate.method, candidate.target, nil),
		)
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("reserved data-plane target %q status = %d, want %d",
				candidate.target, recorder.Code, http.StatusAccepted)
		}
		if got := <-seenDataPlane; got != candidate.method+" "+candidate.target {
			t.Fatalf("data-plane request = %q", got)
		}
	}
	for _, target := range []string{
		"/v1/chat/completions?unexpected=true",
		"/v1/%63hat/completions",
	} {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, target, nil))
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("non-canonical data-plane target %q status = %d, want %d", target, recorder.Code, http.StatusAccepted)
		}
		if got := <-seenDataPlane; got != http.MethodPost+" "+target {
			t.Fatalf("data-plane request = %q, want target %q", got, target)
		}
	}

	for _, path := range []string{"/client/v1/sessions", "/.well-known/latchway"} {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("neighboring client route %q status = %d, want %d", path, recorder.Code, http.StatusNoContent)
		}
		if got := <-seenClientAPI; got != http.MethodPost+" "+path {
			t.Fatalf("client API request = %q", got)
		}
	}
}

func TestNewRejectsMissingDataPlaneHandler(t *testing.T) {
	t.Parallel()

	_, err := New(config.Config{}, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), Handlers{
		AdminAPI: http.NotFoundHandler(), ClientAPI: http.NotFoundHandler(),
	})
	if err == nil || err.Error() != "data-plane handler is nil" {
		t.Fatalf("New() error = %v, want data-plane handler validation", err)
	}
}

func TestServerPreservesSafeClientRequestIDHintWithoutTrustingItAsLogicalIdentity(t *testing.T) {
	t.Parallel()

	const hint = "req_01K3NQ7M8P9RSTVWXYZABCDE12"
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
			logicalID, ok := requestidentity.FromContext(r.Context())
			if !ok {
				t.Fatal("logical request identity is missing")
			}
			if err := id.Validate(logicalID.String(), id.LogicalRequest); err != nil {
				t.Fatalf("logical request ID is not canonical: %v", err)
			}
			if logicalID.String() == hint {
				t.Fatalf("client correlation hint became logical request ID: %q", hint)
			}
			w.WriteHeader(http.StatusNoContent)
		}),
		DataPlane: http.NotFoundHandler(),
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

func TestServerGeneratesDistinctLogicalIDsAndUsesThemAsCorrelationFallback(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 2)
	server, err := New(config.Config{
		ListenAddress: "127.0.0.1:8080",
		ReadTimeout:   time.Second,
		IdleTimeout:   time.Second,
	}, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), Handlers{
		AdminAPI: http.NotFoundHandler(),
		ClientAPI: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logicalID, ok := requestidentity.FromContext(r.Context())
			if !ok {
				t.Fatal("logical request identity is missing")
			}
			seen <- logicalID.String()
			w.WriteHeader(http.StatusNoContent)
		}),
		DataPlane: http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	responseIDs := make([]string, 0, 2)
	for range 2 {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
		}
		logicalID := <-seen
		if err := id.Validate(logicalID, id.LogicalRequest); err != nil {
			t.Fatalf("logical request ID is not canonical: %v", err)
		}
		if got := recorder.Header().Get("X-Latchway-Request-ID"); got != logicalID {
			t.Fatalf("correlation fallback = %q, want logical request ID %q", got, logicalID)
		}
		responseIDs = append(responseIDs, logicalID)
	}
	if responseIDs[0] == responseIDs[1] {
		t.Fatalf("logical request ID was reused: %q", responseIDs[0])
	}
}

func TestServerFallsBackSafelyForAmbiguousOrUnsafeCorrelationHints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{name: "comma joined", values: []string{"request-one,request-two"}},
		{name: "whitespace inside", values: []string{"request id unsafe"}},
		{name: "multiple fields", values: []string{"request-one", "request-two"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var internalID string
			handler := latchwayRequestID(correlationIDHeader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logicalID, ok := requestidentity.FromContext(r.Context())
				if !ok {
					t.Fatal("logical request identity is missing")
				}
				internalID = logicalID.String()
				if got := middleware.GetReqID(r.Context()); got != internalID {
					t.Fatalf("correlation fallback = %q, want %q", got, internalID)
				}
				w.WriteHeader(http.StatusNoContent)
			})))
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, value := range test.values {
				request.Header.Add("X-Latchway-Request-ID", value)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
			}
			if got := recorder.Header().Get("X-Latchway-Request-ID"); got != internalID {
				t.Fatalf("response correlation fallback = %q, want %q", got, internalID)
			}
		})
	}
}

func TestLogicalRequestIdentitySurvivesInterveningMiddleware(t *testing.T) {
	t.Parallel()

	type middlewareKey struct{}
	var want string
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logicalID, ok := requestidentity.FromContext(r.Context())
		if !ok || logicalID.String() != want {
			t.Fatalf("downstream logical identity = %q, %t; want %q", logicalID.String(), ok, want)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	intervening := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logicalID, ok := requestidentity.FromContext(r.Context())
		if !ok {
			t.Fatal("logical request identity is missing before intervening middleware")
		}
		want = logicalID.String()
		ctx := context.WithValue(r.Context(), middlewareKey{}, "retained")
		downstream.ServeHTTP(w, r.WithContext(ctx))
	})
	recorder := httptest.NewRecorder()
	latchwayRequestID(intervening).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestLogicalRequestGenerationFailureStopsBeforeHandler(t *testing.T) {
	t.Parallel()

	called := false
	handler := latchwayRequestIDWithContext(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}), func(context.Context) (context.Context, error) {
		return nil, errors.New("entropy unavailable")
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Latchway-Request-ID", "req_01K3NQ7M8P9RSTVWXYZABCDE12")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if called {
		t.Fatal("downstream handler ran after logical request generation failed")
	}
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("X-Latchway-Request-ID") != "unavailable" {
		t.Fatalf("failure response: status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode failure problem: %v", err)
	}
	if body["code"] != "server_not_ready" || body["request_id"] != "unavailable" {
		t.Fatalf("failure problem = %#v", body)
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
	handler := latchwayRequestID(correlationIDHeader(recoverer(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
