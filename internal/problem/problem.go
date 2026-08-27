// Package problem writes redaction-safe RFC 9457 problem responses.
package problem

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Definition is generated conceptually from api/error-codes.yaml. Contract
// validation ensures every OpenAPI problem code remains registered there.
type Definition struct {
	Status    int
	Title     string
	Retryable bool
}

// Error is safe structured context for one HTTP response. Detail must never
// contain wrapped database, token, provider, or attestation errors.
type Error struct {
	Code                      string
	Detail                    string
	RetryAfterSeconds         int
	Feature                   string
	SupportedProtocolVersions []int
	Fields                    []FieldError
}

// FieldError identifies invalid request input without echoing its value.
type FieldError struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type document struct {
	Type                      string       `json:"type"`
	Title                     string       `json:"title"`
	Status                    int          `json:"status"`
	Detail                    string       `json:"detail"`
	Code                      string       `json:"code"`
	RequestID                 string       `json:"request_id"`
	Retryable                 bool         `json:"retryable"`
	RetryAfter                *string      `json:"retry_after,omitempty"`
	Feature                   string       `json:"feature,omitempty"`
	SupportedProtocolVersions []int        `json:"supported_protocol_versions,omitempty"`
	Errors                    []FieldError `json:"errors,omitempty"`
}

// Write emits one registered problem. Unknown codes become internal_error.
func Write(w http.ResponseWriter, requestID string, value Error) {
	definition, ok := Registry[value.Code]
	if !ok {
		value = Error{Code: "internal_error", Detail: "The request could not be completed."}
		definition = Registry[value.Code]
	}
	detail := strings.TrimSpace(value.Detail)
	if detail == "" {
		detail = definition.Title + "."
	}
	if len(detail) > 2048 {
		detail = detail[:2048]
	}
	if value.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(value.RetryAfterSeconds))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(definition.Status)
	var retryAfter *string
	if value.RetryAfterSeconds > 0 {
		formatted := time.Now().UTC().Add(time.Duration(value.RetryAfterSeconds) * time.Second).Format(time.RFC3339)
		retryAfter = &formatted
	}
	_ = json.NewEncoder(w).Encode(document{
		Type:                      "https://latchway.dev/problems/" + value.Code,
		Title:                     definition.Title,
		Status:                    definition.Status,
		Detail:                    detail,
		Code:                      value.Code,
		RequestID:                 requestID,
		Retryable:                 definition.Retryable,
		RetryAfter:                retryAfter,
		Feature:                   value.Feature,
		SupportedProtocolVersions: value.SupportedProtocolVersions,
		Errors:                    value.Fields,
	})
}
