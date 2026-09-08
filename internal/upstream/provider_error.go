package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	maximumProviderErrorBytes = 16 << 10
	maximumProviderErrorWait  = 2 * time.Second
	maximumProviderErrorID    = 128
	maximumProviderParameter  = 128
)

var (
	// ErrProviderErrorRead deliberately excludes the provider-controlled error
	// returned by its reader. Neither error text nor a partial body is safe to
	// persist or use as proof that no generation occurred.
	ErrProviderErrorRead     = errors.New("upstream error diagnostic read failed")
	ErrProviderErrorTimeout  = errors.New("upstream error diagnostic deadline exceeded")
	providerParameterPattern = regexp.MustCompile(`^[a-z_]+(?:\[[0-9]{1,6}\])?(?:\.(?:[a-z_]+|[0-9]{1,6})(?:\[[0-9]{1,6}\])?)*$`)
)

// ProviderErrorMode is a closed, server-selected parser/trust policy. An
// arbitrary OpenAI-compatible server is not automatically OpenRouter.
type ProviderErrorMode uint8

const (
	ProviderErrorModeNone ProviderErrorMode = iota
	ProviderErrorModeOpenRouter
)

// ProviderErrorCategory contains only the provider's documented, closed error
// vocabulary, never its free-form message. Empty means no recognized category.
type ProviderErrorCategory string

// ProviderErrorCategoryUnknown is Latchway's diagnostic fallback, not an
// assertion that the provider supplied a typed error category.
const ProviderErrorCategoryUnknown ProviderErrorCategory = "unknown"

// ProviderErrorDiagnostics contains safe, bounded correlation and validation
// metadata only. It intentionally cannot hold provider messages, raw metadata,
// user IDs, prompts, response contents, credentials, URLs, or arbitrary codes.
type ProviderErrorDiagnostics struct {
	Category     ProviderErrorCategory `json:"category,omitempty"`
	Parameter    string                `json:"parameter,omitempty"`
	ProviderCode string                `json:"provider_code,omitempty"`
	GenerationID string                `json:"generation_id,omitempty"`
	RequestID    string                `json:"request_id,omitempty"`
}

// Validate checks the complete safe-to-persist value boundary. An empty value
// is valid. This validates data shape, not the origin or truth of its evidence.
func (diagnostics ProviderErrorDiagnostics) Validate() error {
	if diagnostics == (ProviderErrorDiagnostics{}) {
		return nil
	}
	if (diagnostics.Category != ProviderErrorCategoryUnknown && !knownProviderCategory(string(diagnostics.Category))) ||
		(diagnostics.Parameter != "" && safeProviderParameter(diagnostics.Parameter) != diagnostics.Parameter) ||
		(diagnostics.ProviderCode != "" && safeProviderCode(diagnostics.ProviderCode) != diagnostics.ProviderCode) ||
		(diagnostics.GenerationID != "" && !validProviderID(diagnostics.GenerationID, "gen-")) ||
		(diagnostics.RequestID != "" && !validProviderID(diagnostics.RequestID, "req-")) {
		return errors.New("invalid upstream provider error diagnostics")
	}
	return nil
}

// AllowsPreGenerationRejection checks only the status/category value boundary.
// Callers must ALSO require RelayOutcome.RejectionConfirmed from a trusted
// provider-mode parser. Safe-looking strings alone do not prove non-generation.
func (diagnostics ProviderErrorDiagnostics) AllowsPreGenerationRejection(status int) bool {
	return diagnostics.Validate() == nil && status == http.StatusBadRequest && preGenerationInvalidCategory(diagnostics.Category)
}

func validProviderErrorMode(mode ProviderErrorMode) bool {
	return mode == ProviderErrorModeNone || mode == ProviderErrorModeOpenRouter
}

func inspectProviderError(
	ctx context.Context, response *http.Response, body *onceReadCloser,
	abort func(), config ResponseRelayConfig,
) (ProviderErrorDiagnostics, bool, error) {
	var diagnostics ProviderErrorDiagnostics
	// Validate even discarded headers before considering provider-specific
	// evidence. Encoded, ambiguous, and SSE error bodies cannot confirm rejection.
	headers, eventStream, headerErr := responseHeaders(response.Header)
	data, readErr := readProviderError(ctx, body, abort, config)
	if headerErr != nil || config.ProviderErrorMode != ProviderErrorModeOpenRouter {
		return diagnostics, false, readErr
	}
	diagnostics.Category = ProviderErrorCategoryUnknown
	diagnostics.GenerationID = providerHeaderID(response.Header, "X-Generation-Id", "gen-")
	diagnostics.RequestID = providerHeaderID(response.Header, "X-Request-Id", "req-")
	if readErr != nil || eventStream {
		return diagnostics, false, readErr
	}
	mediaType, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return diagnostics, false, nil
	}
	value, err := jsonsafe.Decode(data)
	if err != nil {
		return diagnostics, false, nil
	}
	document, ok := value.(map[string]any)
	if !ok {
		return diagnostics, false, nil
	}
	envelope, ok := document["error"].(map[string]any)
	if !ok || len(envelope) == 0 {
		return diagnostics, false, nil
	}
	metadata, _ := envelope["metadata"].(map[string]any)
	// All three OpenRouter skins carry the canonical error_type, but in
	// different places. Conflicting, mistyped or unknown values are not proof.
	category, unambiguous := providerCategory(document, envelope, metadata)
	if category != "" {
		diagnostics.Category = category
	}
	diagnostics.Parameter = safeProviderParameter(envelope["param"])
	diagnostics.ProviderCode = safeProviderCode(metadata["provider_code"])
	if diagnostics.ProviderCode == "" {
		diagnostics.ProviderCode = safeProviderCode(envelope["code"])
	}
	if diagnostics.ProviderCode == "" {
		diagnostics.ProviderCode = safeProviderCode(envelope["type"])
	}
	for _, object := range []map[string]any{document, envelope, metadata} {
		diagnostics.GenerationID = combineProviderID(diagnostics.GenerationID, object["id"], "gen-")
		diagnostics.GenerationID = combineProviderID(diagnostics.GenerationID, object["generation_id"], "gen-")
		diagnostics.GenerationID = combineProviderID(diagnostics.GenerationID, object["request_id"], "gen-")
		diagnostics.RequestID = combineProviderID(diagnostics.RequestID, object["request_id"], "req-")
	}
	// A sentinel makes conflicting identifiers stay discarded across all
	// candidate locations instead of allowing a later value to replace them.
	if diagnostics.GenerationID == conflictingProviderID {
		diagnostics.GenerationID = ""
	}
	if diagnostics.RequestID == conflictingProviderID {
		diagnostics.RequestID = ""
	}
	confirmed := response.StatusCode == http.StatusBadRequest && unambiguous &&
		preGenerationInvalidCategory(category) && !providerMayHaveGenerated(document, envelope, metadata) &&
		providerRejectionCodesConsistent(category, envelope, metadata)
	if kind, present := document["type"]; present && kind != "error" {
		confirmed = false
	}
	if value, present := envelope["metadata"]; present && value != nil && metadata == nil {
		confirmed = false
	}
	return diagnostics, confirmed, nil
}

// The absolute deadline cannot be extended by a peer trickling one byte per
// read. Exact RoundTrip cancellation and body closure reuse the relay's proven
// controller; no unowned read goroutine is left behind on cancellation.
func readProviderError(ctx context.Context, body *onceReadCloser, abort func(), config ResponseRelayConfig) ([]byte, error) {
	limit := min(int64(maximumProviderErrorBytes), config.MaxBodyBytes)
	wait := min(maximumProviderErrorWait, config.IdleTimeout)
	if config.FirstByteTimeout > 0 {
		wait = min(wait, config.FirstByteTimeout)
	}
	deadline := time.Now().Add(wait)
	controller := newResponseReadController(ctx, abort)
	defer controller.Close()
	buffer := make([]byte, limit+1)
	used := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			abort()
			return nil, ErrProviderErrorTimeout
		}
		count, readErr, waitErr := controller.Read(body, buffer[used:], remaining, ErrProviderErrorTimeout)
		if waitErr != nil {
			return nil, waitErr
		}
		if count < 0 || count > len(buffer)-used || (count == 0 && readErr == nil) {
			return nil, ErrProviderErrorRead
		}
		used += count
		if int64(used) > limit {
			return nil, ErrResponseBodyTooLarge
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return nil, ErrProviderErrorRead
			}
			return buffer[:used], nil
		}
	}
}

// https://openrouter.ai/docs/api_reference/errors-and-debugging documents the
// canonical error_type vocabulary. Native error.type / error.code fields are
// lossy (e.g. Anthropic invalid_request_error includes content-policy errors),
// so neither those nor message text establishes pre-generation rejection.
func providerCategory(objects ...map[string]any) (ProviderErrorCategory, bool) {
	var category ProviderErrorCategory
	for _, object := range objects {
		value, present := object["error_type"]
		if !present {
			continue
		}
		candidate, ok := value.(string)
		if !ok || !knownProviderCategory(candidate) || (category != "" && string(category) != candidate) {
			return "", false
		}
		category = ProviderErrorCategory(candidate)
	}
	return category, category != ""
}

func knownProviderCategory(category string) bool {
	switch category {
	case "context_length_exceeded", "max_tokens_exceeded", "token_limit_exceeded", "string_too_long",
		"authentication", "permission_denied", "payment_required", "rate_limit_exceeded",
		"provider_overloaded", "provider_unavailable", "invalid_request", "invalid_prompt", "not_found",
		"precondition_failed", "payload_too_large", "unprocessable", "content_policy_violation", "refusal",
		"invalid_image", "image_too_large", "image_too_small", "unsupported_image_format", "image_not_found",
		"image_download_failed", "server", "timeout", "unmapped":
		return true
	default:
		return false
	}
}

func preGenerationInvalidCategory(category ProviderErrorCategory) bool {
	switch category {
	case "invalid_request", "invalid_prompt", "context_length_exceeded", "string_too_long",
		"invalid_image", "unsupported_image_format":
		return true
	default:
		return false
	}
}

func providerRejectionCodesConsistent(category ProviderErrorCategory, envelope, metadata map[string]any) bool {
	for _, value := range []any{envelope["code"], envelope["type"], metadata["provider_code"]} {
		switch code := value.(type) {
		case nil:
			continue
		case json.Number:
			if code.String() != "400" {
				return false
			}
		case string:
			switch code {
			case "invalid_request", "invalid_prompt", "invalid_request_error", "invalid_value", "invalid_argument",
				"unsupported_parameter", "unsupported_value", "missing_required_parameter", "string_above_max_length",
				"context_length_exceeded", "string_too_long", "invalid_image", "unsupported_image_format":
			case "server_error":
				// OpenRouter's Responses skin maps these canonical categories to
				// server_error. The type remains mandatory; the native code alone
				// never qualifies. Other contradictory provider codes fail closed.
				if category != "invalid_prompt" && category != "string_too_long" &&
					category != "invalid_image" && category != "unsupported_image_format" {
					return false
				}
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}

func providerMayHaveGenerated(objects ...map[string]any) bool {
	for _, object := range objects {
		for _, key := range []string{"usage", "choices", "output", "output_text", "content", "completion",
			"response", "status", "finish_reason", "native_finish_reason", "completed_at", "partial",
			"prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens", "cost"} {
			if _, present := object[key]; present {
				return true
			}
		}
	}
	return false
}

func safeProviderCode(value any) string {
	code, ok := value.(string)
	if !ok || len(code) > 64 {
		return ""
	}
	if knownProviderCategory(code) {
		return code
	}
	switch code {
	case "invalid_request_error", "invalid_value", "invalid_argument", "unsupported_parameter",
		"unsupported_value", "missing_required_parameter", "string_above_max_length", "rate_limited",
		"insufficient_quota", "invalid_api_key", "authentication_error", "permission_error", "billing_error",
		"not_found_error", "rate_limit_error", "overloaded_error", "timeout_error", "api_error",
		"server_error", "image_content_policy_violation":
		return code
	default:
		return ""
	}
}

func safeProviderParameter(value any) string {
	parameter, ok := value.(string)
	if !ok || len(parameter) == 0 || len(parameter) > maximumProviderParameter || !providerParameterPattern.MatchString(parameter) {
		return ""
	}
	// A character regex alone would permit a prompt, user identifier or secret
	// encoded as a property name. Only fixed API field names and array indices
	// may leave the parser; arbitrary JSON-schema property names are excluded.
	for _, component := range strings.FieldsFunc(parameter, func(r rune) bool { return r == '.' || r == '[' || r == ']' }) {
		if component[0] >= '0' && component[0] <= '9' {
			continue
		}
		switch component {
		case "messages", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "functions", "function_call",
			"function", "name", "description", "parameters", "properties", "required", "additional_properties", "strict",
			"type", "role", "content", "text", "image_url", "url", "detail", "input_audio", "data", "format",
			"tool_calls", "tool_call_id", "id", "arguments", "result", "model", "stream", "stream_options", "include_usage",
			"max_tokens", "max_completion_tokens", "max_output_tokens", "temperature", "top_p", "top_k", "seed", "stop",
			"frequency_penalty", "presence_penalty", "repetition_penalty", "logprobs", "top_logprobs", "logit_bias",
			"response_format", "json_schema", "schema", "reasoning", "effort", "summary", "reasoning_effort",
			"verbosity", "metadata", "user", "store", "previous_response_id", "truncation", "modalities", "audio",
			"voice", "prediction", "service_tier", "n", "encoding_format", "dimensions":
		default:
			return ""
		}
	}
	return parameter
}

const conflictingProviderID = "!conflicting"

func combineProviderID(current string, value any, prefix string) string {
	if current == conflictingProviderID {
		return current
	}
	candidate, _ := value.(string)
	if !validProviderID(candidate, prefix) {
		return current
	}
	if current != "" && current != candidate {
		return conflictingProviderID
	}
	return candidate
}

func providerHeaderID(headers http.Header, name, prefix string) string {
	values := headerValues(headers, name)
	if len(values) != 1 || !validProviderID(values[0], prefix) {
		return ""
	}
	for _, connection := range headerValues(headers, "Connection") {
		for _, token := range strings.Split(connection, ",") {
			if strings.EqualFold(strings.TrimSpace(token), name) {
				return ""
			}
		}
	}
	return values[0]
}

func validProviderID(value, prefix string) bool {
	if len(value) < len(prefix)+6 || len(value) > maximumProviderErrorID || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, c := range value[len(prefix):] {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
