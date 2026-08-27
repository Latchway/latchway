// Package server owns the public HTTP process lifecycle.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	console "github.com/latchway/latchway/web/console"
)

// Server is the Latchway HTTP process.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
}

// New builds a server whose readiness reflects PostgreSQL and schema state.
func New(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger, adminHandler http.Handler) (*Server, error) {
	if adminHandler == nil {
		return nil, errors.New("admin API handler is nil")
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
	router.Mount("/admin/v1", adminHandler)
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
		requestID, err := id.New(id.LogicalRequest)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"type":      "about:blank",
				"title":     "Service Unavailable",
				"status":    http.StatusServiceUnavailable,
				"code":      "server_not_ready",
				"retryable": true,
			})
			return
		}
		ctx := context.WithValue(r.Context(), middleware.RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"type":       "about:blank",
						"title":      "Internal Server Error",
						"status":     http.StatusInternalServerError,
						"code":       "internal_error",
						"request_id": middleware.GetReqID(r.Context()),
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
