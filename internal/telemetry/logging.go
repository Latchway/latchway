// Package telemetry configures audit-safe process telemetry.
package telemetry

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

const redactedValue = "[REDACTED]"

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
	return slog.New(newRedactingHandler(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slogLevel})))
}

// redactingHandler applies a final, centralized deny-list before structured
// records reach an output. Call sites should still avoid passing private
// material at all; this boundary protects against accidental attributes and
// nested groups added by future instrumentation.
type redactingHandler struct {
	next           slog.Handler
	forceRedaction bool
}

func newRedactingHandler(next slog.Handler) slog.Handler {
	return redactingHandler{next: next}
}

func (handler redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return handler.next.Enabled(ctx, level)
}

func (handler redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	redacted := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attribute slog.Attr) bool {
		redacted.AddAttrs(redactAttribute(attribute, handler.forceRedaction))
		return true
	})
	return handler.next.Handle(ctx, redacted)
}

func (handler redactingHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, 0, len(attributes))
	for _, attribute := range attributes {
		redacted = append(redacted, redactAttribute(attribute, handler.forceRedaction))
	}
	return redactingHandler{next: handler.next.WithAttrs(redacted), forceRedaction: handler.forceRedaction}
}

func (handler redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{
		next:           handler.next.WithGroup(name),
		forceRedaction: handler.forceRedaction || sensitiveTelemetryKey(name),
	}
}

func redactAttribute(attribute slog.Attr, force bool) slog.Attr {
	attribute.Value = attribute.Value.Resolve()
	if force || sensitiveTelemetryKey(attribute.Key) {
		return slog.String(attribute.Key, redactedValue)
	}
	if attribute.Value.Kind() != slog.KindGroup {
		return attribute
	}
	children := attribute.Value.Group()
	redacted := make([]slog.Attr, 0, len(children))
	for _, child := range children {
		redacted = append(redacted, redactAttribute(child, false))
	}
	return slog.Group(attribute.Key, attrsToAny(redacted)...)
}

func attrsToAny(attributes []slog.Attr) []any {
	values := make([]any, len(attributes))
	for index := range attributes {
		values[index] = attributes[index]
	}
	return values
}

func sensitiveTelemetryKey(key string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "", "/", "").Replace(strings.ToLower(key))
	for _, fragment := range []string{
		"authorization", "cookie", "credential", "privatekey", "ciphertext",
		"providerkey", "apikey", "secret", "refreshtoken", "identitytoken", "accesstoken", "dpop",
		"attestationevidence", "signedassertion", "serviceaccount", "password",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return normalized == "proof" || normalized == "nonce" || strings.HasSuffix(normalized, "headers") ||
		normalized == "requestbody" || normalized == "responsebody" || normalized == "rawbody"
}
