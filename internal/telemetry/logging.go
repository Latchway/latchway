// Package telemetry configures audit-safe process telemetry.
package telemetry

import (
	"io"
	"log/slog"
)

// NewLogger creates a structured JSON logger with a validated level.
func NewLogger(output io.Writer, level string) *slog.Logger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slogLevel}))
}
