// Package openairesponses implements the OpenAI Responses protocol without
// coupling it to an upstream hostname, credential, or tool executor.
package openairesponses

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/adapters/protocol/internal/openaiusage"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

const (
	ID = protocol.OpenAIResponsesID

	defaultMaximumBody      = int64(1 << 20)
	maximumObservedJSON     = int64(4 << 20)
	maximumSSEEvent         = 1 << 20
	maximumSSEEvents        = 1 << 20
	maximumInputItems       = 4096
	maximumContentParts     = 4096
	maximumTools            = 128
	maximumEventTypeBytes   = 128
	providerUsageProvenance = "provider_reported"
)

// Adapter inspects and rewrites OpenAI Responses requests. Tool definitions
// and tool-call items are relayed as provider data; this package deliberately
// has no facility for executing them.
type Adapter struct {
	MaximumBodyBytes int64
}

var _ protocol.Adapter = Adapter{}
var _ protocol.InputPreflighter = Adapter{}

type responseMode uint8

const (
	responseModeJSON responseMode = iota + 1
	responseModeSSE
)

type responseModeContextKey struct{}

func (a Adapter) ID() string { return ID }

// Match accepts only the single canonical public Responses endpoint. Encoded
// aliases, query strings, and fragments cannot reach protocol processing.
func (a Adapter) Match(request *http.Request) bool {
	return request != nil && request.Method == http.MethodPost && request.URL != nil &&
		request.URL.Path == protocol.OpenAIResponsesPublicPath && request.URL.RawPath == "" &&
		request.URL.Opaque == "" && request.URL.RawQuery == "" && !request.URL.ForceQuery && request.URL.Fragment == "" &&
		request.URL.RawFragment == ""
}

func (a Adapter) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{
		Streaming:             true,
		ModelRewrite:          true,
		OutputTokenClamp:      true,
		ProviderUsage:         true,
		ExactInputPreflight:   false,
		TrustedInputPreflight: true,
	}
}

func (a Adapter) InspectRequest(ctx context.Context, request *http.Request) (protocol.RequestMetadata, error) {
	if ctx == nil {
		return protocol.RequestMetadata{}, requestMalformed("request context is required")
	}
	if err := ctx.Err(); err != nil {
		return protocol.RequestMetadata{}, err
	}
	object, raw, err := a.readRequest(ctx, request)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	return inspectRequestObject(object, raw)
}

func inspectRequestObject(object map[string]any, raw []byte) (protocol.RequestMetadata, error) {
	if err := validateRootMembers(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	model, ok := object["model"].(string)
	if !ok || !safeIdentifierValue(model, 256) {
		return protocol.RequestMetadata{}, requestMalformed("model must be a non-empty safe string")
	}
	tools, err := validateTools(object)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateInput(object["input"], tools); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateInstructions(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateToolChoice(object, tools); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if _, err := optionalBool(object, "parallel_tool_calls"); err != nil {
		return protocol.RequestMetadata{}, err
	}
	streaming, err := optionalBool(object, "stream")
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateBackground(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validatePrivacyBoundary(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateGenerationControls(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateStreamOptions(object, streaming); err != nil {
		return protocol.RequestMetadata{}, err
	}
	requested, err := requestedOutputLimit(object)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	return protocol.RequestMetadata{
		ClientModel:          model,
		Streaming:            streaming,
		RequestedOutputLimit: requested,
		// This remains an untrusted scheduling hint. Only PreflightInput after
		// route selection and rewriting can produce a quota-safe bound.
		EstimatedInputTokens: (int64(len(raw)) + 2) / 3,
		RequestBytes:         int64(len(raw)),
	}, nil
}

func (a Adapter) ApplyFeature(ctx context.Context, request *http.Request, decision protocol.FeatureDecision) (int64, error) {
	if ctx == nil {
		return 0, requestMalformed("request context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !safeIdentifierValue(decision.PhysicalModel, 256) {
		return 0, errors.New("valid physical model is required")
	}
	if decision.DefaultOutputTokens <= 0 || decision.MaximumOutputTokens <= 0 ||
		decision.DefaultOutputTokens > decision.MaximumOutputTokens {
		return 0, errors.New("valid output-token bounds are required")
	}

	object, raw, err := a.readRequest(ctx, request)
	if err != nil {
		return 0, err
	}
	metadata, err := inspectRequestObject(object, raw)
	if err != nil {
		return 0, err
	}
	effective := metadata.RequestedOutputLimit
	if effective == 0 {
		effective = decision.DefaultOutputTokens
	}
	if effective > decision.MaximumOutputTokens {
		effective = decision.MaximumOutputTokens
	}

	object["model"] = decision.PhysicalModel
	object["max_output_tokens"] = effective
	// Responses otherwise retain application state by default. This is a
	// server-owned privacy decision and is installed even when the client
	// omitted the field.
	object["store"] = false
	rewritten, err := json.Marshal(object)
	if err != nil {
		return 0, fmt.Errorf("encode rewritten Responses request: %w", err)
	}
	if int64(len(rewritten)) > a.maximumBodyBytes() {
		return 0, errors.New("rewritten Responses request exceeds configured limit")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	installRequestBody(request, rewritten)
	replaceHeader(request.Header, "Content-Type", "application/json")
	mode := responseModeJSON
	if metadata.Streaming {
		mode = responseModeSSE
	}
	*request = *request.WithContext(context.WithValue(request.Context(), responseModeContextKey{}, mode))
	return effective, nil
}

// PreflightInput proves a conservative bound over the exact rewritten
// Responses body. The proof deliberately accepts only local text input and
// text message items. Files, media, tools, provider-hosted state, schemas, and
// every other richer shape remain usable when trusted input accounting is not
// selected, but fail closed here.
func (a Adapter) PreflightInput(
	ctx context.Context,
	request *http.Request,
	profile protocol.TrustedInputProfile,
) (protocol.TrustedInputPreflight, error) {
	if ctx == nil {
		return protocol.TrustedInputPreflight{}, requestMalformed("request context is required")
	}
	if err := ctx.Err(); err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	if err := validateTrustedInputProfile(profile); err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	object, raw, err := a.readRequest(ctx, request)
	if err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	itemCount, outputBound, err := validateTrustedInputRequest(object, profile)
	if err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	requestBytes, ok := checkedLength(len(raw))
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input request size overflows int64")
	}
	itemFraming, ok := checkedMultiply(itemCount, profile.MaximumFramingTokensPerMessage)
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input item framing overflows int64")
	}
	inputBound, ok := checkedAdd(requestBytes, profile.MaximumFramingTokensPerRequest)
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input request framing overflows int64")
	}
	inputBound, ok = checkedAdd(inputBound, itemFraming)
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input bound overflows int64")
	}
	totalBound, ok := checkedAdd(inputBound, outputBound)
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted total-token bound overflows int64")
	}
	if totalBound > profile.MaximumContextTokens {
		return protocol.TrustedInputPreflight{}, requestMalformed("request and output maximum exceed the physical model context window")
	}

	installRequestBody(request, raw)
	return protocol.TrustedInputPreflight{
		ProfileID: profile.ID, ProfileDigest: profile.Digest(), Protocol: profile.Protocol,
		Method: profile.Method, PhysicalModel: profile.PhysicalModel,
		RewrittenBodySHA256: sha256.Sum256(raw), RequestBytes: requestBytes,
		MessageCount: itemCount, InputTokenBound: inputBound,
		OutputTokenBound: outputBound, TotalTokenBound: totalBound,
	}, nil
}

func validateTrustedInputProfile(profile protocol.TrustedInputProfile) error {
	if !safeIdentifierValue(profile.ID, 63) {
		return errors.New("valid trusted input profile ID is required")
	}
	if profile.Protocol != ID {
		return errors.New("trusted input profile protocol does not match OpenAI Responses")
	}
	if profile.Method != protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1 {
		return errors.New("trusted input profile method is unsupported")
	}
	if !safeIdentifierValue(profile.PhysicalModel, 256) {
		return errors.New("valid trusted input profile physical model is required")
	}
	if profile.MaximumFramingTokensPerRequest < 0 || profile.MaximumFramingTokensPerMessage < 0 ||
		profile.MaximumContextTokens <= 0 {
		return errors.New("valid trusted input profile token bounds are required")
	}
	return nil
}

func validateTrustedInputRequest(
	object map[string]any,
	profile protocol.TrustedInputProfile,
) (int64, int64, error) {
	if !hasOnlyMembers(
		object,
		"model", "input", "instructions", "max_output_tokens", "stream", "stream_options", "store",
	) {
		return 0, 0, requestMalformed("trusted input preflight supports only bounded text request fields")
	}
	model, ok := object["model"].(string)
	if !ok || model != profile.PhysicalModel {
		return 0, 0, errors.New("trusted input profile physical model does not match rewritten request")
	}
	if store, ok := object["store"].(bool); !ok || store {
		return 0, 0, errors.New("rewritten request is missing store=false")
	}
	if _, err := optionalBool(object, "stream"); err != nil {
		return 0, 0, err
	}
	streaming, _ := optionalBool(object, "stream")
	if err := validateStreamOptions(object, streaming); err != nil {
		return 0, 0, err
	}
	if err := validateInstructions(object); err != nil {
		return 0, 0, err
	}
	itemCount, err := trustedTextInputItemCount(object["input"])
	if err != nil {
		return 0, 0, err
	}
	outputBound, err := requestedOutputLimit(object)
	if err != nil {
		return 0, 0, err
	}
	if outputBound <= 0 {
		return 0, 0, errors.New("rewritten request is missing its output-token maximum")
	}
	return itemCount, outputBound, nil
}

func trustedTextInputItemCount(value any) (int64, error) {
	switch typed := value.(type) {
	case string:
		if typed == "" || !utf8.ValidString(typed) || strings.ContainsRune(typed, '\x00') {
			return 0, requestMalformed("trusted input must be non-empty local text")
		}
		return 1, nil
	case []any:
		if len(typed) == 0 || len(typed) > maximumInputItems {
			return 0, requestMalformed("trusted input items must be a non-empty bounded array")
		}
		for _, value := range typed {
			item, ok := value.(map[string]any)
			if !ok || !hasOnlyMembers(item, "type", "role", "content") {
				return 0, requestMalformed("trusted input supports only text message items")
			}
			if itemType, present := item["type"]; present && itemType != "message" {
				return 0, requestMalformed("trusted input supports only text message items")
			}
			role, ok := item["role"].(string)
			if !ok || !stringIn(role, "developer", "system", "user", "assistant") ||
				!trustedMessageContent(item["content"], role) {
				return 0, requestMalformed("trusted input supports only text message items")
			}
		}
		return int64(len(typed)), nil
	default:
		return 0, requestMalformed("trusted input supports only local text or text message items")
	}
}

func trustedMessageContent(value any, role string) bool {
	switch typed := value.(type) {
	case string:
		return utf8.ValidString(typed) && !strings.ContainsRune(typed, '\x00')
	case []any:
		if len(typed) == 0 || len(typed) > maximumContentParts {
			return false
		}
		for _, value := range typed {
			part, ok := value.(map[string]any)
			partType, typeOK := part["type"].(string)
			text, textOK := part["text"].(string)
			if !ok || !hasOnlyMembers(part, "type", "text") || !typeOK || !textOK ||
				!utf8.ValidString(text) || strings.ContainsRune(text, '\x00') ||
				(partType != "input_text" && (partType != "output_text" || role != "assistant")) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func checkedLength(value int) (int64, bool) {
	converted := int64(value)
	return converted, converted >= 0 && int(converted) == value
}

func checkedMultiply(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || (left != 0 && right > math.MaxInt64/left) {
		return 0, false
	}
	return left * right, true
}

func checkedAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

func (a Adapter) ObserveResponse(ctx context.Context, response *http.Response) (protocol.ResponseObserver, error) {
	if ctx == nil {
		return nil, errors.New("response context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("response is required")
	}
	if response.Request == nil {
		return nil, errors.New("response request is required")
	}
	mode, ok := response.Request.Context().Value(responseModeContextKey{}).(responseMode)
	if !ok || (mode != responseModeJSON && mode != responseModeSSE) {
		return nil, errors.New("response request is missing its protocol mode")
	}

	// Error bodies are provider-controlled and must not influence usage or
	// client-visible error details. The relay classifies their HTTP status before
	// reading the body; this observer remains safe even if called independently.
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return discardObserver{}, nil
	}
	contentTypes := caseInsensitiveHeaderValues(response.Header, "Content-Type")
	if len(contentTypes) != 1 {
		return nil, upstreamMalformed("upstream response must contain exactly one Content-Type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || (mediaType != "application/json" && mediaType != "text/event-stream") {
		return nil, upstreamMalformed("upstream response Content-Type is unsupported")
	}
	if (mode == responseModeSSE) != (mediaType == "text/event-stream") {
		return nil, upstreamMalformed("upstream response Content-Type does not match the request mode")
	}
	if mode == responseModeSSE {
		return &sseObserver{}, nil
	}
	return &jsonObserver{}, nil
}

func (a Adapter) readRequest(ctx context.Context, request *http.Request) (map[string]any, []byte, error) {
	if !a.Match(request) {
		return nil, nil, requestMalformed("POST /v1/responses without encoding or a query is required")
	}
	if request.Body == nil {
		return nil, nil, requestMalformed("JSON request body is required")
	}
	contentTypes := caseInsensitiveHeaderValues(request.Header, "Content-Type")
	if len(contentTypes) != 1 {
		return nil, nil, requestMalformed("exactly one content type is required")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return nil, nil, requestMalformed("content type must be application/json")
	}
	if len(caseInsensitiveHeaderValues(request.Header, "Content-Encoding")) != 0 {
		return nil, nil, requestMalformed("encoded request bodies are not supported")
	}
	limit := a.maximumBodyBytes()
	if request.ContentLength > limit {
		return nil, nil, requestMalformed("Responses request exceeds configured limit")
	}
	raw, readErr := io.ReadAll(io.LimitReader(request.Body, limit+1))
	closeErr := request.Body.Close()
	if readErr != nil {
		return nil, nil, requestMalformed("request body could not be read")
	}
	if closeErr != nil {
		return nil, nil, requestMalformed("request body could not be closed")
	}
	if int64(len(raw)) > limit {
		return nil, nil, requestMalformed("Responses request exceeds configured limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	value, err := jsonsafe.Decode(raw)
	if err != nil {
		return nil, nil, requestMalformed("request body must be strict JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil, requestMalformed("request body must be a JSON object")
	}
	installRequestBody(request, raw)
	return object, raw, nil
}

func (a Adapter) maximumBodyBytes() int64 {
	if a.MaximumBodyBytes > 0 {
		return a.MaximumBodyBytes
	}
	return defaultMaximumBody
}

type localToolKind uint8

const (
	localFunctionTool localToolKind = iota + 1
	localCustomTool
)

type localCall struct {
	kind localToolKind
	name string
}

// validateRootMembers pins the exact v1 request surface. OpenAI adds
// provider-hosted state, identity, spend, and execution controls over time;
// treating unknown members as harmless pass-through would silently widen the
// trust boundary on upgrade.
func validateRootMembers(root map[string]any) error {
	if !hasOnlyMembers(
		root,
		"model", "input", "instructions", "max_output_tokens",
		"stream", "stream_options", "background", "tools", "tool_choice", "parallel_tool_calls",
		"store", "temperature", "top_p", "top_logprobs", "truncation", "text",
	) {
		return requestMalformed("Responses request contains an unsupported root member")
	}
	return nil
}

func validateGenerationControls(root map[string]any) error {
	if err := optionalNumberRange(root, "temperature", 0, 2); err != nil {
		return err
	}
	if err := optionalNumberRange(root, "top_p", 0, 1); err != nil {
		return err
	}
	if value, present := root["top_logprobs"]; present {
		number, ok := value.(json.Number)
		if !ok {
			return requestMalformed("top_logprobs must be an integer between 0 and 20")
		}
		parsed, err := number.Int64()
		if err != nil || parsed < 0 || parsed > 20 {
			return requestMalformed("top_logprobs must be an integer between 0 and 20")
		}
	}
	if value, present := root["truncation"]; present {
		strategy, ok := value.(string)
		if !ok || !stringIn(strategy, "auto", "disabled") {
			return requestMalformed("truncation must be auto or disabled")
		}
	}
	return validateTextControl(root)
}

func optionalNumberRange(root map[string]any, key string, minimum, maximum float64) error {
	value, present := root[key]
	if !present {
		return nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return requestMalformed(key + " must be a finite number in range")
	}
	parsed, err := number.Float64()
	if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) || parsed < minimum || parsed > maximum {
		return requestMalformed(key + " must be a finite number in range")
	}
	return nil
}

func validateTextControl(root map[string]any) error {
	value, present := root["text"]
	if !present {
		return nil
	}
	text, ok := value.(map[string]any)
	if !ok || !hasOnlyMembers(text, "format", "verbosity") {
		return requestMalformed("text must be a supported local output configuration")
	}
	if value, present := text["verbosity"]; present {
		verbosity, ok := value.(string)
		if !ok || !stringIn(verbosity, "low", "medium", "high") {
			return requestMalformed("text verbosity is unsupported")
		}
	}
	formatValue, present := text["format"]
	if !present {
		return nil
	}
	format, ok := formatValue.(map[string]any)
	formatType, typeOK := format["type"].(string)
	if !ok || !typeOK {
		return requestMalformed("text format must be a supported object")
	}
	switch formatType {
	case "text", "json_object":
		if !hasOnlyMembers(format, "type") {
			return requestMalformed("text format contains unsupported members")
		}
	case "json_schema":
		if !hasOnlyMembers(format, "type", "name", "description", "schema", "strict") {
			return requestMalformed("JSON schema format contains unsupported members")
		}
		name, nameOK := format["name"].(string)
		schema, schemaOK := format["schema"].(map[string]any)
		if !nameOK || !validFunctionName(name) || !schemaOK || !safeLocalJSONSchema(schema) {
			return requestMalformed("JSON schema format requires a bounded name and safe schema")
		}
		if description, present := format["description"]; present {
			text, ok := description.(string)
			if !ok || len(text) > 8192 || strings.ContainsRune(text, '\x00') {
				return requestMalformed("JSON schema format description must be bounded text")
			}
		}
		if strict, present := format["strict"]; present {
			if _, ok := strict.(bool); !ok {
				return requestMalformed("JSON schema format strict must be a boolean")
			}
		}
	default:
		return requestMalformed("text format is unsupported")
	}
	return nil
}

func validateTools(root map[string]any) (map[string]localToolKind, error) {
	result := make(map[string]localToolKind)
	value, present := root["tools"]
	if !present {
		return result, nil
	}
	tools, ok := value.([]any)
	if !ok || len(tools) > maximumTools {
		return nil, requestMalformed("tools must be a bounded array of local function or custom definitions")
	}
	for _, value := range tools {
		tool, ok := value.(map[string]any)
		toolType, typeOK := tool["type"].(string)
		if !ok || !typeOK {
			return nil, requestMalformed("each tool must be a local function or custom definition")
		}
		name, nameOK := tool["name"].(string)
		if !nameOK || !validFunctionName(name) {
			return nil, requestMalformed("each tool requires a bounded local name")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, requestMalformed("tool names must be unique")
		}
		var kind localToolKind
		switch toolType {
		case "function":
			if err := validateFunctionTool(tool); err != nil {
				return nil, err
			}
			kind = localFunctionTool
		case "custom":
			if err := validateCustomTool(tool); err != nil {
				return nil, err
			}
			kind = localCustomTool
		default:
			return nil, requestMalformed("provider-hosted and remote tools are not supported")
		}
		result[name] = kind
	}
	return result, nil
}

func validateFunctionTool(tool map[string]any) error {
	if !hasOnlyMembers(tool, "type", "name", "description", "parameters", "strict") {
		return requestMalformed("function tools contain unsupported members")
	}
	if description, present := tool["description"]; present {
		text, ok := description.(string)
		if !ok || len(text) > 8192 || strings.ContainsRune(text, '\x00') {
			return requestMalformed("function tool descriptions must be bounded text")
		}
	}
	if parameters, present := tool["parameters"]; present {
		schema, ok := parameters.(map[string]any)
		if !ok || !safeLocalJSONSchema(schema) {
			return requestMalformed("function tool parameters must be a safe JSON object")
		}
	}
	if strict, present := tool["strict"]; present {
		if _, ok := strict.(bool); !ok {
			return requestMalformed("function tool strict must be a boolean")
		}
	}
	return nil
}

func validateCustomTool(tool map[string]any) error {
	if !hasOnlyMembers(tool, "type", "name", "description", "format") {
		return requestMalformed("custom tools contain unsupported members")
	}
	if description, present := tool["description"]; present {
		text, ok := description.(string)
		if !ok || len(text) > 8192 || strings.ContainsRune(text, '\x00') {
			return requestMalformed("custom tool descriptions must be bounded text")
		}
	}
	formatValue, present := tool["format"]
	if !present {
		return nil
	}
	format, ok := formatValue.(map[string]any)
	formatType, typeOK := format["type"].(string)
	if !ok || !typeOK {
		return requestMalformed("custom tool format must be a supported object")
	}
	switch formatType {
	case "text":
		if !hasOnlyMembers(format, "type") {
			return requestMalformed("custom text format contains unsupported members")
		}
	case "grammar":
		if !hasOnlyMembers(format, "type", "syntax", "definition") {
			return requestMalformed("custom grammar format contains unsupported members")
		}
		syntax, syntaxOK := format["syntax"].(string)
		definition, definitionOK := format["definition"].(string)
		if !syntaxOK || (syntax != "lark" && syntax != "regex") || !definitionOK ||
			definition == "" || len(definition) > int(defaultMaximumBody) || strings.ContainsRune(definition, '\x00') {
			return requestMalformed("custom grammar format is invalid")
		}
	default:
		return requestMalformed("custom tool format is unsupported")
	}
	return nil
}

func validateInput(value any, tools map[string]localToolKind) error {
	switch typed := value.(type) {
	case string:
		if typed == "" || strings.ContainsRune(typed, '\x00') {
			return requestMalformed("input must be non-empty text or a bounded local item array")
		}
		return nil
	case []any:
		if len(typed) == 0 || len(typed) > maximumInputItems {
			return requestMalformed("input must be non-empty text or a bounded local item array")
		}
		return validateInputItems(typed, tools)
	default:
		return requestMalformed("input must be non-empty text or a bounded local item array")
	}
}

func validateInputItems(values []any, tools map[string]localToolKind) error {
	calls := make(map[string]localCall)
	outputs := make(map[string]struct{})
	outputItems := make([]map[string]any, 0)
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok || len(item) == 0 {
			return requestMalformed("each input item must be a supported local object")
		}
		itemType := "message"
		if value, present := item["type"]; present {
			var typeOK bool
			itemType, typeOK = value.(string)
			if !typeOK {
				return requestMalformed("input item type must be a string")
			}
		}
		switch itemType {
		case "message":
			if err := validateMessageItem(item); err != nil {
				return err
			}
		case "function_call":
			callID, name, err := validateFunctionCallItem(item)
			if err != nil {
				return err
			}
			if tools[name] != localFunctionTool {
				return requestMalformed("function call input must name a declared local function tool")
			}
			if _, duplicate := calls[callID]; duplicate {
				return requestMalformed("input tool call identifiers must be unique")
			}
			calls[callID] = localCall{kind: localFunctionTool, name: name}
		case "custom_tool_call":
			callID, name, err := validateCustomCallItem(item)
			if err != nil {
				return err
			}
			if tools[name] != localCustomTool {
				return requestMalformed("custom call input must name a declared local custom tool")
			}
			if _, duplicate := calls[callID]; duplicate {
				return requestMalformed("input tool call identifiers must be unique")
			}
			calls[callID] = localCall{kind: localCustomTool, name: name}
		case "function_call_output", "custom_tool_call_output":
			outputItems = append(outputItems, item)
		default:
			return requestMalformed("remote, file, media, reasoning, and provider-hosted input items are not supported")
		}
	}
	for _, item := range outputItems {
		callID, kind, err := validateCallOutputItem(item)
		if err != nil {
			return err
		}
		call, exists := calls[callID]
		if !exists || call.kind != kind {
			return requestMalformed("tool output input must match a local call in the same request")
		}
		if _, duplicate := outputs[callID]; duplicate {
			return requestMalformed("input tool outputs must be unique")
		}
		outputs[callID] = struct{}{}
	}
	return nil
}

func validateMessageItem(item map[string]any) error {
	if !hasOnlyMembers(item, "type", "role", "content") {
		return requestMalformed("message input items contain unsupported members")
	}
	if itemType, present := item["type"]; present && itemType != "message" {
		return requestMalformed("message input item type is invalid")
	}
	role, ok := item["role"].(string)
	if !ok || !stringIn(role, "developer", "system", "user", "assistant") {
		return requestMalformed("message input items require a supported role")
	}
	content, present := item["content"]
	if !present || !validMessageContent(content, role) {
		return requestMalformed("message input content must be bounded local text")
	}
	return nil
}

func validMessageContent(value any, role string) bool {
	switch typed := value.(type) {
	case string:
		return !strings.ContainsRune(typed, '\x00')
	case []any:
		if len(typed) == 0 || len(typed) > maximumContentParts {
			return false
		}
		for _, value := range typed {
			part, ok := value.(map[string]any)
			if !ok || !hasOnlyMembers(part, "type", "text") {
				return false
			}
			partType, typeOK := part["type"].(string)
			text, textOK := part["text"].(string)
			if !typeOK || !textOK || strings.ContainsRune(text, '\x00') ||
				(partType != "input_text" && (partType != "output_text" || role != "assistant")) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validateFunctionCallItem(item map[string]any) (string, string, error) {
	if !hasOnlyMembers(item, "type", "call_id", "name", "arguments") {
		return "", "", requestMalformed("function call input contains unsupported members")
	}
	callID, callOK := item["call_id"].(string)
	name, nameOK := item["name"].(string)
	arguments, argumentsOK := item["arguments"].(string)
	if item["type"] != "function_call" || !callOK || !safeIdentifierValue(callID, 256) ||
		!nameOK || !validFunctionName(name) || !argumentsOK || strings.ContainsRune(arguments, '\x00') {
		return "", "", requestMalformed("function call input is invalid")
	}
	return callID, name, nil
}

func validateCustomCallItem(item map[string]any) (string, string, error) {
	if !hasOnlyMembers(item, "type", "call_id", "name", "input") {
		return "", "", requestMalformed("custom call input contains unsupported members")
	}
	callID, callOK := item["call_id"].(string)
	name, nameOK := item["name"].(string)
	input, inputOK := item["input"].(string)
	if item["type"] != "custom_tool_call" || !callOK || !safeIdentifierValue(callID, 256) ||
		!nameOK || !validFunctionName(name) || !inputOK || strings.ContainsRune(input, '\x00') {
		return "", "", requestMalformed("custom call input is invalid")
	}
	return callID, name, nil
}

func validateCallOutputItem(item map[string]any) (string, localToolKind, error) {
	if !hasOnlyMembers(item, "type", "call_id", "output") {
		return "", 0, requestMalformed("tool output input contains unsupported members")
	}
	itemType, typeOK := item["type"].(string)
	callID, callOK := item["call_id"].(string)
	output, outputOK := item["output"].(string)
	if !typeOK || !callOK || !safeIdentifierValue(callID, 256) || !outputOK || strings.ContainsRune(output, '\x00') {
		return "", 0, requestMalformed("tool output input is invalid")
	}
	switch itemType {
	case "function_call_output":
		return callID, localFunctionTool, nil
	case "custom_tool_call_output":
		return callID, localCustomTool, nil
	default:
		return "", 0, requestMalformed("tool output input type is invalid")
	}
}

func validateInstructions(root map[string]any) error {
	value, present := root["instructions"]
	if !present {
		return nil
	}
	text, ok := value.(string)
	if !ok || strings.ContainsRune(text, '\x00') {
		return requestMalformed("instructions must be local text")
	}
	return nil
}

func validateToolChoice(root map[string]any, tools map[string]localToolKind) error {
	value, present := root["tool_choice"]
	if !present {
		return nil
	}
	choice, ok := value.(string)
	if !ok || !stringIn(choice, "none", "auto", "required") {
		return requestMalformed("tool_choice must select only local tools")
	}
	if choice == "required" && len(tools) == 0 {
		return requestMalformed("tool_choice=required requires a local tool")
	}
	return nil
}

func validatePrivacyBoundary(root map[string]any) error {
	if value, present := root["store"]; present {
		store, ok := value.(bool)
		if !ok || store {
			return requestMalformed("store must be false")
		}
	}
	for _, field := range []string{
		"previous_response_id", "conversation", "prompt", "context_management", "include",
		"prompt_cache_key", "prompt_cache_options", "prompt_cache_retention",
		"user", "safety_identifier", "max_tool_calls", "modalities", "audio",
	} {
		if _, present := root[field]; present {
			return requestMalformed("provider-hosted state and remote references are not supported")
		}
	}
	return nil
}

func safeLocalJSONSchema(value any) bool {
	switch typed := value.(type) {
	case nil, bool, json.Number:
		return true
	case string:
		return !strings.ContainsRune(typed, '\x00')
	case []any:
		for _, item := range typed {
			if !safeLocalJSONSchema(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for key, item := range typed {
			if strings.ContainsRune(key, '\x00') {
				return false
			}
			if key == "$ref" {
				reference, ok := item.(string)
				if !ok || !strings.HasPrefix(reference, "#") || strings.ContainsRune(reference, '\x00') {
					return false
				}
				continue
			}
			if !safeLocalJSONSchema(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func hasOnlyMembers(object map[string]any, allowed ...string) bool {
	for key := range object {
		if !stringIn(key, allowed...) {
			return false
		}
	}
	return true
}

func validFunctionName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func stringIn(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateBackground(object map[string]any) error {
	value, present := object["background"]
	if !present {
		return nil
	}
	background, ok := value.(bool)
	if !ok {
		return requestMalformed("background must be a boolean")
	}
	if background {
		return requestMalformed("background Responses are not supported")
	}
	return nil
}

func validateStreamOptions(object map[string]any, streaming bool) error {
	value, present := object["stream_options"]
	if !present {
		return nil
	}
	if !streaming {
		return requestMalformed("stream_options requires stream=true")
	}
	options, ok := value.(map[string]any)
	if !ok {
		return requestMalformed("stream_options must be an object")
	}
	for key, option := range options {
		if key != "include_obfuscation" {
			return requestMalformed("stream_options contains an unsupported member")
		}
		if _, ok := option.(bool); !ok {
			return requestMalformed("include_obfuscation must be a boolean")
		}
	}
	return nil
}

func requestedOutputLimit(object map[string]any) (int64, error) {
	value, present := object["max_output_tokens"]
	if !present {
		return 0, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, requestMalformed("max_output_tokens must be a positive integer")
	}
	parsed, err := number.Int64()
	if err != nil || parsed <= 0 {
		return 0, requestMalformed("max_output_tokens must be a positive integer")
	}
	return parsed, nil
}

func optionalBool(object map[string]any, key string) (bool, error) {
	value, present := object[key]
	if !present {
		return false, nil
	}
	parsed, ok := value.(bool)
	if !ok {
		return false, requestMalformed(key + " must be a boolean")
	}
	return parsed, nil
}

func installRequestBody(request *http.Request, body []byte) {
	owned := bytes.Clone(body)
	request.Body = io.NopCloser(bytes.NewReader(owned))
	request.ContentLength = int64(len(owned))
	request.TransferEncoding = nil
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(owned)), nil
	}
	deleteHeader(request.Header, "Content-Length")
}

func replaceHeader(headers http.Header, name, value string) {
	if headers == nil {
		return
	}
	deleteHeader(headers, name)
	headers.Set(name, value)
}

func deleteHeader(headers http.Header, name string) {
	for candidate := range headers {
		if strings.EqualFold(candidate, name) {
			delete(headers, candidate)
		}
	}
}

func caseInsensitiveHeaderValues(headers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range headers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func requestMalformed(detail string) error {
	return &protocol.Error{Code: "request_invalid", Detail: detail}
}

func upstreamMalformed(detail string) error {
	return &protocol.Error{Code: "upstream_protocol_error", Detail: detail}
}

func safeIdentifierValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) == -1
}

type discardObserver struct{}

func (discardObserver) Observe([]byte) error { return nil }

func (discardObserver) Finalize() (protocol.Usage, error) { return unknownUsage(), nil }

type jsonObserver struct {
	buffer   bytes.Buffer
	overflow bool
}

func (o *jsonObserver) Observe(chunk []byte) error {
	if o.overflow {
		return nil
	}
	if int64(o.buffer.Len()) > maximumObservedJSON-int64(len(chunk)) {
		o.overflow = true
		o.buffer.Reset()
		return nil
	}
	_, _ = o.buffer.Write(chunk)
	return nil
}

func (o *jsonObserver) Finalize() (protocol.Usage, error) {
	if o.overflow {
		return unknownUsage(), nil
	}
	value, err := jsonsafe.Decode(o.buffer.Bytes())
	if err != nil {
		return protocol.Usage{}, upstreamMalformed("upstream returned malformed JSON")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return protocol.Usage{}, upstreamMalformed("upstream JSON must be an object")
	}
	return usageFromResponseObject(root)
}

type sseObserver struct {
	pending    []byte
	scanOffset int
	lineStart  int
	eventEnd   int
	events     int
	usage      protocol.Usage
	done       bool
}

func (o *sseObserver) Observe(chunk []byte) error {
	if o.done && len(chunk) > 0 {
		return upstreamMalformed("upstream SSE stream contains bytes after response.completed")
	}
	for len(chunk) > 0 {
		room := maximumSSEEvent + 4 - len(o.pending)
		if room <= 0 {
			return upstreamMalformed("upstream SSE event exceeds limit")
		}
		if room > len(chunk) {
			room = len(chunk)
		}
		o.pending = append(o.pending, chunk[:room]...)
		chunk = chunk[room:]
		if err := o.drainEvents(false); err != nil {
			return err
		}
		if o.done && (len(o.pending) > 0 || len(chunk) > 0) {
			return upstreamMalformed("upstream SSE stream contains bytes after response.completed")
		}
	}
	return nil
}

func (o *sseObserver) Finalize() (protocol.Usage, error) {
	if err := o.drainEvents(true); err != nil {
		return protocol.Usage{}, err
	}
	if len(o.pending) > 0 {
		return protocol.Usage{}, upstreamMalformed("upstream SSE stream ended with an incomplete event")
	}
	if !o.done {
		return protocol.Usage{}, upstreamMalformed("upstream SSE stream ended before response.completed")
	}
	return o.usage, nil
}

func (o *sseObserver) drainEvents(eof bool) error {
	eventStart := 0
	for o.scanOffset < len(o.pending) {
		lineEnd := o.scanOffset
		endingLength := 0
		switch o.pending[o.scanOffset] {
		case '\n':
			endingLength = 1
		case '\r':
			if o.scanOffset+1 == len(o.pending) && !eof {
				o.compactSSEPrefix(eventStart)
				return nil
			}
			endingLength = 1
			if o.scanOffset+1 < len(o.pending) && o.pending[o.scanOffset+1] == '\n' {
				endingLength = 2
			}
		default:
			o.scanOffset++
			continue
		}

		endingEnd := lineEnd + endingLength
		if lineEnd == o.lineStart {
			if o.eventEnd-eventStart > maximumSSEEvent {
				return upstreamMalformed("upstream SSE event exceeds limit")
			}
			if err := o.observeEvent(o.pending[eventStart:o.eventEnd]); err != nil {
				return err
			}
			eventStart = endingEnd
			o.lineStart = endingEnd
			o.eventEnd = endingEnd
			o.scanOffset = endingEnd
			continue
		}
		o.eventEnd = lineEnd
		o.lineStart = endingEnd
		o.scanOffset = endingEnd
	}
	o.compactSSEPrefix(eventStart)
	return nil
}

func (o *sseObserver) compactSSEPrefix(consumed int) {
	if consumed == 0 {
		return
	}
	copy(o.pending, o.pending[consumed:])
	o.pending = o.pending[:len(o.pending)-consumed]
	o.scanOffset -= consumed
	o.lineStart -= consumed
	o.eventEnd -= consumed
}

func (o *sseObserver) observeEvent(event []byte) error {
	if o.done {
		return upstreamMalformed("upstream SSE stream contains bytes after response.completed")
	}
	if o.events >= maximumSSEEvents {
		return upstreamMalformed("upstream SSE stream contains too many events")
	}
	if o.events == 0 {
		event = bytes.TrimPrefix(event, []byte{0xef, 0xbb, 0xbf})
	}
	o.events++
	eventName, data, hasData, err := sseEventFields(event)
	if err != nil {
		return err
	}
	if !hasData {
		return nil
	}
	value, err := jsonsafe.Decode(data)
	if err != nil {
		return upstreamMalformed("upstream returned malformed SSE data")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return upstreamMalformed("upstream SSE data must be an object")
	}
	eventType, ok := root["type"].(string)
	if !ok || !safeIdentifierValue(eventType, maximumEventTypeBytes) {
		return upstreamMalformed("upstream SSE data requires a safe event type")
	}
	if eventName != "" && eventName != eventType {
		return upstreamMalformed("upstream SSE event and data types do not match")
	}
	if eventType != "response.completed" {
		return nil
	}
	response, ok := root["response"].(map[string]any)
	if !ok {
		return upstreamMalformed("response.completed must contain a response object")
	}
	usage, err := usageFromResponseObject(response)
	if err != nil {
		return err
	}
	o.usage = usage
	o.done = true
	return nil
}

func sseEventFields(event []byte) (string, []byte, bool, error) {
	dataLines := make([][]byte, 0, 1)
	eventName := ""
	eventSeen := false
	for len(event) > 0 {
		line := event
		if index := bytes.IndexAny(event, "\r\n"); index >= 0 {
			line = event[:index]
			separatorLength := 1
			if event[index] == '\r' && index+1 < len(event) && event[index+1] == '\n' {
				separatorLength = 2
			}
			event = event[index+separatorLength:]
		} else {
			event = nil
		}
		if len(line) > 0 && line[0] == ':' {
			continue
		}
		field := line
		value := []byte(nil)
		if colon := bytes.IndexByte(line, ':'); colon >= 0 {
			field = line[:colon]
			value = line[colon+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}
		switch {
		case bytes.Equal(field, []byte("data")):
			dataLines = append(dataLines, value)
		case bytes.Equal(field, []byte("event")):
			if eventSeen {
				return "", nil, false, upstreamMalformed("upstream SSE event contains duplicate event fields")
			}
			eventSeen = true
			eventName = string(value)
			if !safeIdentifierValue(eventName, maximumEventTypeBytes) {
				return "", nil, false, upstreamMalformed("upstream SSE event type is invalid")
			}
		}
	}
	if len(dataLines) == 0 {
		return eventName, nil, false, nil
	}
	return eventName, bytes.Join(dataLines, []byte("\n")), true, nil
}

func usageFromResponseObject(root map[string]any) (protocol.Usage, error) {
	usageValue, present := root["usage"]
	if !present || usageValue == nil {
		return unknownUsage(), nil
	}
	usageObject, ok := usageValue.(map[string]any)
	if !ok {
		return protocol.Usage{}, upstreamMalformed("upstream usage must be an object")
	}
	reportedCost := openaiusage.ReportedCost(usageObject)
	input, inputPresent, err := usageInteger(usageObject, "input_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	output, outputPresent, err := usageInteger(usageObject, "output_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	total, totalPresent, err := usageInteger(usageObject, "total_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	if !inputPresent || !outputPresent || !totalPresent {
		usage := unknownUsage()
		usage.ReportedCost = reportedCost
		return usage, nil
	}
	if input > math.MaxInt64-output || total != input+output {
		return protocol.Usage{}, upstreamMalformed("upstream usage totals are inconsistent")
	}
	return protocol.Usage{
		InputTokens: input, OutputTokens: output, TotalTokens: total,
		Known: true, Provenance: providerUsageProvenance, ReportedCost: reportedCost,
	}, nil
}

func usageInteger(object map[string]any, key string) (int64, bool, error) {
	value, present := object[key]
	if !present {
		return 0, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false, upstreamMalformed("upstream usage values must be non-negative integers")
	}
	parsed, err := number.Int64()
	if err != nil || parsed < 0 {
		return 0, false, upstreamMalformed("upstream usage values must be non-negative integers")
	}
	return parsed, true, nil
}

func unknownUsage() protocol.Usage {
	return protocol.Usage{Known: false, Provenance: "unknown"}
}
