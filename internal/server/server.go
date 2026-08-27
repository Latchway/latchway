// Package server owns the public HTTP process lifecycle.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
	console "github.com/latchway/latchway/web/console"
)

// Server is the Latchway HTTP process.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
}

// Handlers contains the independently constructed HTTP surfaces exposed by
// the process. Keeping them explicit prevents the admin console fallback from
// accidentally handling public client API paths.
type Handlers struct {
	AdminAPI  http.Handler
	ClientAPI http.Handler
}

// New builds a server whose readiness reflects PostgreSQL and schema state.
func New(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger, handlers Handlers) (*Server, error) {
	if handlers.AdminAPI == nil {
		return nil, errors.New("admin API handler is nil")
	}
	if handlers.ClientAPI == nil {
		return nil, errors.New("client API handler is nil")
	}
	consoleAssets, err := console.Assets()
	if err != nil {
		return nil, fmt.Errorf("load embedded admin console: %w", err)
	}
	router := chi.NewRouter()
	router.Use(latchwayRequestID)
	router.Use(requestIDHeader)
	router.Use(recoverer(logger))
	router.Use(securityHeaders)
	router.Use(accessLog(logger))

	router.Get("/healthz", healthHandler)
	router.Get("/readyz", readinessHandler(pool))
	router.Mount("/admin/v1", handlers.AdminAPI)
	router.Handle("/client/v1", handlers.ClientAPI)
	router.Handle("/client/v1/*", handlers.ClientAPI)
	router.Handle("/v1", handlers.ClientAPI)
	router.Handle("/v1/*", handlers.ClientAPI)
	router.Handle("/proxy", handlers.ClientAPI)
	router.Handle("/proxy/*", handlers.ClientAPI)
	router.Handle("/.well-known/*", handlers.ClientAPI)
	router.NotFound(newConsoleHandler(consoleAssets).ServeHTTP)

	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.ListenAddress,
			Handler:           router,
			ReadHeaderTimeout: cfg.ReadTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    32 << 10,
		},
		logger: logger,
	}, nil
}

func latchwayRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := safeRequestIDHint(r.Header)
		if requestID == "" {
			var err error
			requestID, err = id.New(id.LogicalRequest)
			if err != nil {
				const unavailableRequestID = "unavailable"
				w.Header().Set("X-Latchway-Request-ID", unavailableRequestID)
				problem.Write(w, unavailableRequestID, problem.Error{
					Code: "server_not_ready", Detail: "The server could not initialize request processing.",
				})
				return
			}
		}
		ctx := context.WithValue(r.Context(), middleware.RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var safeRequestIDHintPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

func safeRequestIDHint(header http.Header) string {
	values := header.Values("X-Latchway-Request-ID")
	if len(values) != 1 {
		return ""
	}
	candidate := strings.TrimSpace(values[0])
	if len(candidate) < 8 || len(candidate) > 128 || strings.ContainsAny(candidate, "\r\n\x00,") || !safeRequestIDHintPattern.MatchString(candidate) {
		return ""
	}
	return candidate
}

// Run serves until context cancellation and then drains in-flight work.
func (s *Server) Run(ctx context.Context, shutdownTimeout time.Duration) error {
	serveErr := make(chan error, 1)
	go func() {
		s.logger.Info("HTTP server listening", "address", s.httpServer.Addr)
		serveErr <- s.httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		_ = s.httpServer.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"build":  buildinfo.Current(),
	})
}

func readinessHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		checks := map[string]string{"database": "ok", "schema": "ok"}
		status := http.StatusOK
		if err := pool.Ping(ctx); err != nil {
			checks["database"] = "unavailable"
			checks["schema"] = "unknown"
			status = http.StatusServiceUnavailable
		} else {
			current, available, err := database.NewMigrator(pool).Status(ctx)
			if err != nil || current != available {
				checks["schema"] = "incompatible"
				status = http.StatusServiceUnavailable
			}
		}
		state := "ready"
		if status != http.StatusOK {
			state = "not_ready"
		}
		writeJSON(w, status, map[string]any{"status": state, "checks": checks})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func requestIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Latchway-Request-ID", middleware.GetReqID(r.Context()))
		next.ServeHTTP(w, r)
	})
}

func accessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(wrapped, r)
			logger.InfoContext(r.Context(), "HTTP request",
				"request_id", middleware.GetReqID(r.Context()),
				"method", r.Method,
				"path", r.URL.EscapedPath(),
				"status", wrapped.Status(),
				"bytes", wrapped.BytesWritten(),
				"duration_ms", time.Since(started).Milliseconds(),
			)
		})
	}
}

func recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.ErrorContext(r.Context(), "HTTP panic recovered", "stack", string(debug.Stack()))
					problem.Write(w, middleware.GetReqID(r.Context()), problem.Error{
						Code: "internal_error", Detail: "The request could not be completed.",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
