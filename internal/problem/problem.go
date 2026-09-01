// Package problem writes redaction-safe RFC 9457 problem responses.
package problem

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/id"
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
	OperationID               string
	Feature                   string
	SupportedProtocolVersions []int
	Fields                    []FieldError
	ValidationIssues          []ValidationIssue
}

// FieldError identifies invalid request input without echoing its value.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ValidationIssue is the richer Admin API configuration-validation shape.
// It is intentionally separate because the Client API field-error contract
// permits only path and message.
type ValidationIssue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type document struct {
	Type                      string  `json:"type"`
	DocumentationURL          string  `json:"documentation_url"`
	Title                     string  `json:"title"`
	Status                    int     `json:"status"`
	Detail                    string  `json:"detail"`
	Code                      string  `json:"code"`
	RequestID                 string  `json:"request_id"`
	Retryable                 bool    `json:"retryable"`
	RetryAfter                *string `json:"retry_after,omitempty"`
	OperationID               string  `json:"operation_id,omitempty"`
	Feature                   string  `json:"feature,omitempty"`
	SupportedProtocolVersions []int   `json:"supported_protocol_versions,omitempty"`
	Errors                    any     `json:"errors,omitempty"`
}

// DocumentationURL returns the stable public remediation page for one
// canonical error code. Public pages use readable hyphenated slugs while the
// machine code remains underscore-delimited.
func DocumentationURL(code string) string {
	return "https://docs.latchway.dev/errors/" + strings.ReplaceAll(code, "_", "-")
}

// Write emits one registered problem. Unknown codes become internal_error.
func Write(w http.ResponseWriter, requestID string, value Error) {
	definition, ok := Registry[value.Code]
	operationIDValid := value.OperationID == "" || id.Validate(value.OperationID, id.AdminRequest) == nil
	operationIDRequired := value.Code == "operation_indeterminate"
	if !ok || (len(value.Fields) > 0 && len(value.ValidationIssues) > 0) ||
		!operationIDValid || operationIDRequired != (value.OperationID != "") {
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
	var responseErrors any
	if len(value.Fields) > 0 {
		responseErrors = value.Fields
	} else if len(value.ValidationIssues) > 0 {
		responseErrors = value.ValidationIssues
	}
	documentationURL := DocumentationURL(value.Code)
	_ = json.NewEncoder(w).Encode(document{
		Type:                      documentationURL,
		DocumentationURL:          documentationURL,
		Title:                     definition.Title,
		Status:                    definition.Status,
		Detail:                    detail,
		Code:                      value.Code,
		RequestID:                 requestID,
		Retryable:                 definition.Retryable,
		RetryAfter:                retryAfter,
		OperationID:               value.OperationID,
		Feature:                   value.Feature,
		SupportedProtocolVersions: value.SupportedProtocolVersions,
		Errors:                    responseErrors,
	})
}
