// Package openaichat implements the OpenAI Chat Completions protocol without
// coupling it to an upstream hostname or credential.
package openaichat

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
	ID                      = protocol.OpenAIChatID
	defaultMaximumBody      = int64(1 << 20)
	maximumObservedResponse = int64(4 << 20)
	maximumSSEEvent         = 1 << 20
)

// Adapter inspects and rewrites Chat Completions requests.
type Adapter struct {
	MaximumBodyBytes int64
}

type responseMode uint8

const (
	responseModeJSON responseMode = iota + 1
	responseModeSSE
)

type responseModeContextKey struct{}

func (a Adapter) ID() string { return ID }

func (a Adapter) Match(request *http.Request) bool {
	return request != nil && request.Method == http.MethodPost && request.URL != nil &&
		request.URL.Path == "/v1/chat/completions" && request.URL.RawPath == "" &&
		request.URL.RawQuery == "" && !request.URL.ForceQuery
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
	object, raw, err := a.readRequest(request)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	return inspectRequestObject(object, raw)
}

func inspectRequestObject(object map[string]any, raw []byte) (protocol.RequestMetadata, error) {
	model, ok := object["model"].(string)
	if !ok || !safeIdentifierValue(model, 256) {
		return protocol.RequestMetadata{}, requestMalformed("model must be a non-empty string")
	}
	streaming, err := optionalBool(object, "stream")
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateMessages(object["messages"]); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateTools(object["tools"]); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if count, present, err := optionalPositiveInteger(object, "n"); err != nil {
		return protocol.RequestMetadata{}, err
	} else if present && count != 1 {
		return protocol.RequestMetadata{}, requestMalformed("n must be 1 for quota-safe chat requests")
	}
	requested, _, err := requestedOutputLimit(object)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	return protocol.RequestMetadata{
		ClientModel:          model,
		Streaming:            streaming,
		RequestedOutputLimit: requested,
		// This pre-route raw-body heuristic is intentionally untrusted. Only
		// PreflightInput can produce a quota-safe input-token bound.
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
	if decision.DefaultOutputTokens <= 0 || decision.MaximumOutputTokens <= 0 || decision.DefaultOutputTokens > decision.MaximumOutputTokens {
		return 0, errors.New("valid output-token bounds are required")
	}
	object, raw, err := a.readRequest(request)
	if err != nil {
		return 0, err
	}
	if _, err := inspectRequestObject(object, raw); err != nil {
		return 0, err
	}
	requested, outputLimitField, err := requestedOutputLimit(object)
	if err != nil {
		return 0, err
	}
	effective := requested
	if effective == 0 {
		effective = decision.DefaultOutputTokens
	}
	if effective > decision.MaximumOutputTokens {
		effective = decision.MaximumOutputTokens
	}
	object["model"] = decision.PhysicalModel
	streaming, _ := optionalBool(object, "stream")
	if streaming {
		streamOptions, present := object["stream_options"]
		if !present || streamOptions == nil {
			streamOptions = map[string]any{}
		}
		optionsObject, ok := streamOptions.(map[string]any)
		if !ok {
			return 0, requestMalformed("stream_options must be an object")
		}
		optionsObject["include_usage"] = true
		object["stream_options"] = optionsObject
	}
	delete(object, "max_tokens")
	delete(object, "max_completion_tokens")
	object[outputLimitField] = effective
	rewritten, err := json.Marshal(object)
	if err != nil {
		return 0, fmt.Errorf("encode rewritten chat request: %w", err)
	}
	if int64(len(rewritten)) > a.maximumBodyBytes() {
		return 0, errors.New("rewritten chat request exceeds configured limit")
	}
	installRequestBody(request, rewritten)
	request.Header.Set("Content-Type", "application/json")
	mode := responseModeJSON
	if streaming {
		mode = responseModeSSE
	}
	*request = *request.WithContext(context.WithValue(request.Context(), responseModeContextKey{}, mode))
	return effective, nil
}

// MeasureRequest counts the closed Chat v1 image and historical tool-call
// locations after ApplyFeature has installed the exact provider body. Tool
// definitions and tool results are not calls; each assistant tool_calls entry
// and legacy function_call is one tool_calls unit.
func (a Adapter) MeasureRequest(
	ctx context.Context,
	request *http.Request,
) (protocol.RequestMeasurements, error) {
	if ctx == nil {
		return protocol.RequestMeasurements{}, requestMalformed("request context is required")
	}
	if err := ctx.Err(); err != nil {
		return protocol.RequestMeasurements{}, err
	}
	object, raw, err := a.readRequest(request)
	if err != nil {
		return protocol.RequestMeasurements{}, err
	}
	if _, err := inspectRequestObject(object, raw); err != nil {
		return protocol.RequestMeasurements{}, err
	}
	images, calls := countRequestUnits(object)
	installRequestBody(request, raw)
	return protocol.RequestMeasurements{
		Protocol: ID, RewrittenBodySHA256: sha256.Sum256(raw), RequestBytes: int64(len(raw)),
		ImageUnits: images, ToolCalls: calls, ImageUnitsKnown: true, ToolCallsKnown: true,
	}, nil
}

func countRequestUnits(object map[string]any) (int64, int64) {
	var images, calls int64
	messages, _ := object["messages"].([]any)
	for _, value := range messages {
		message, _ := value.(map[string]any)
		if content, ok := message["content"].([]any); ok {
			for _, partValue := range content {
				part, _ := partValue.(map[string]any)
				if part["type"] == "image_url" {
					images++
				}
			}
		}
		if toolCalls, ok := message["tool_calls"].([]any); ok {
			calls += int64(len(toolCalls))
		} else if message["function_call"] != nil {
			calls++
		}
	}
	return images, calls
}

// PreflightInput proves a conservative input-token bound over the exact body
// installed by ApplyFeature. It intentionally supports only a strict
// text-only subset of Chat Completions. Rich requests remain available when
// trusted input accounting is not required, but they fail closed here because
// tools, files, media, and provider extensions can add input not bounded by
// the JSON bytes alone.
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
	object, raw, err := a.readRequest(request)
	if err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	messageCount, outputBound, err := validateTrustedInputRequest(object, profile)
	if err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	requestBytes, ok := checkedLength(len(raw))
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input request size overflows int64")
	}
	messageFraming, ok := checkedMultiply(messageCount, profile.MaximumFramingTokensPerMessage)
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input message framing overflows int64")
	}
	inputBound, ok := checkedAdd(requestBytes, profile.MaximumFramingTokensPerRequest)
	if !ok {
		return protocol.TrustedInputPreflight{}, errors.New("trusted input request framing overflows int64")
	}
	inputBound, ok = checkedAdd(inputBound, messageFraming)
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

	// Rebind every body accessor to the exact bytes that were hashed and
	// validated. The owned slice is not exposed and later integrity checks can
	// compare against RewrittenBodySHA256 before dispatch.
	installRequestBody(request, raw)
	return protocol.TrustedInputPreflight{
		ProfileID:           profile.ID,
		ProfileDigest:       profile.Digest(),
		Protocol:            profile.Protocol,
		Method:              profile.Method,
		PhysicalModel:       profile.PhysicalModel,
		RewrittenBodySHA256: sha256.Sum256(raw),
		RequestBytes:        requestBytes,
		MessageCount:        messageCount,
		InputTokenBound:     inputBound,
		OutputTokenBound:    outputBound,
		TotalTokenBound:     totalBound,
	}, nil
}

func validateTrustedInputProfile(profile protocol.TrustedInputProfile) error {
	if !safeIdentifierValue(profile.ID, 63) {
		return errors.New("valid trusted input profile ID is required")
	}
	if profile.Protocol != ID {
		return errors.New("trusted input profile protocol does not match OpenAI Chat")
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
	allowedRoot := map[string]struct{}{
		"model": {}, "messages": {}, "stream": {}, "stream_options": {}, "n": {},
		"max_tokens": {}, "max_completion_tokens": {},
	}
	for key := range object {
		if _, ok := allowedRoot[key]; !ok {
			return 0, 0, requestMalformed("trusted input preflight supports only bounded text request fields")
		}
	}
	model, ok := object["model"].(string)
	if !ok || model != profile.PhysicalModel {
		return 0, 0, errors.New("trusted input profile physical model does not match rewritten request")
	}
	messages, ok := object["messages"].([]any)
	if !ok || len(messages) == 0 || len(messages) > 4096 {
		return 0, 0, requestMalformed("messages must be a non-empty bounded array")
	}
	for _, value := range messages {
		message, ok := value.(map[string]any)
		if !ok || len(message) != 2 {
			return 0, 0, requestMalformed("trusted input messages must contain exactly role and content")
		}
		role, roleOK := message["role"].(string)
		content, contentOK := message["content"].(string)
		if !roleOK || !slicesContainsString([]string{"developer", "system", "user", "assistant"}, role) {
			return 0, 0, requestMalformed("trusted input messages must use a text-only role")
		}
		if !contentOK || !utf8.ValidString(content) || strings.ContainsRune(content, '\x00') {
			return 0, 0, requestMalformed("trusted input message content must be a non-null UTF-8 string")
		}
	}
	streaming := false
	if value, present := object["stream"]; present {
		streaming, ok = value.(bool)
		if !ok {
			return 0, 0, requestMalformed("stream must be a boolean for trusted input preflight")
		}
	}
	if value, present := object["stream_options"]; present {
		options, objectOK := value.(map[string]any)
		includeUsage, usageOK := options["include_usage"].(bool)
		if !streaming || !objectOK || len(options) != 1 || !usageOK || !includeUsage {
			return 0, 0, requestMalformed("stream_options must contain only include_usage=true for a streaming request")
		}
	} else if streaming {
		return 0, 0, errors.New("rewritten streaming request is missing provider usage reporting")
	}
	if value, present := object["n"]; present {
		number, numberOK := value.(json.Number)
		parsed, parseErr := number.Int64()
		if !numberOK || parseErr != nil || parsed != 1 {
			return 0, 0, requestMalformed("n must be exactly 1 for trusted input preflight")
		}
	}
	outputBound, outputField, err := requestedOutputLimit(object)
	if err != nil {
		return 0, 0, err
	}
	if outputBound <= 0 {
		return 0, 0, errors.New("rewritten request is missing its output-token maximum")
	}
	otherOutputField := "max_tokens"
	if outputField == otherOutputField {
		otherOutputField = "max_completion_tokens"
	}
	if _, present := object[otherOutputField]; present {
		return 0, 0, errors.New("rewritten request contains ambiguous output-token maxima")
	}
	messageCount, ok := checkedLength(len(messages))
	if !ok {
		return 0, 0, errors.New("trusted input message count overflows int64")
	}
	return messageCount, outputBound, nil
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

func installRequestBody(request *http.Request, body []byte) {
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	request.Header.Del("Content-Length")
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
	if response.Request == nil || response.Request.Context() == nil {
		return nil, errors.New("response request is required")
	}
	mode, ok := response.Request.Context().Value(responseModeContextKey{}).(responseMode)
	if !ok || (mode != responseModeJSON && mode != responseModeSSE) {
		return nil, errors.New("response request is missing its protocol mode")
	}
	// Provider error bodies are never relayed or observed. Return a non-nil
	// observer so the transport boundary can classify the status before looking
	// at success-payload MIME; OpenAI commonly returns JSON errors for streaming
	// requests whose successful response would have been SSE.
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return &jsonObserver{}, nil
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

func caseInsensitiveHeaderValues(headers http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range headers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func (a Adapter) readRequest(request *http.Request) (map[string]any, []byte, error) {
	if !a.Match(request) {
		return nil, nil, requestMalformed("POST /v1/chat/completions without a query is required")
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
		return nil, nil, requestMalformed("chat request exceeds configured limit")
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	closeErr := request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, requestMalformed("request body could not be read")
	}
	if closeErr != nil {
		return nil, nil, requestMalformed("request body could not be closed")
	}
	if int64(len(raw)) > limit {
		return nil, nil, requestMalformed("chat request exceeds configured limit")
	}
	value, err := jsonsafe.Decode(raw)
	if err != nil {
		return nil, nil, requestMalformed("request body must be strict JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil, requestMalformed("request body must be a JSON object")
	}
	return object, raw, nil
}

func (a Adapter) maximumBodyBytes() int64 {
	if a.MaximumBodyBytes > 0 {
		return a.MaximumBodyBytes
	}
	return defaultMaximumBody
}

func requestedOutputLimit(object map[string]any) (int64, string, error) {
	legacy, hasLegacy, err := optionalPositiveInteger(object, "max_tokens")
	if err != nil {
		return 0, "", err
	}
	completion, hasCompletion, err := optionalPositiveInteger(object, "max_completion_tokens")
	if err != nil {
		return 0, "", err
	}
	if hasLegacy && hasCompletion {
		return 0, "", requestMalformed("max_tokens and max_completion_tokens cannot both be set")
	}
	if hasCompletion {
		return completion, "max_completion_tokens", nil
	}
	if hasLegacy {
		return legacy, "max_tokens", nil
	}
	_, legacyPresent := object["max_tokens"]
	_, completionPresent := object["max_completion_tokens"]
	if legacyPresent && !completionPresent {
		return 0, "max_tokens", nil
	}
	return 0, "max_completion_tokens", nil
}

func optionalPositiveInteger(object map[string]any, key string) (int64, bool, error) {
	value, present := object[key]
	if !present {
		return 0, false, nil
	}
	if value == nil {
		return 0, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false, requestMalformed(key + " must be a positive integer")
	}
	parsed, err := number.Int64()
	if err != nil || parsed <= 0 {
		return 0, false, requestMalformed(key + " must be a positive integer")
	}
	return parsed, true, nil
}

func optionalBool(object map[string]any, key string) (bool, error) {
	value, present := object[key]
	if !present {
		return false, nil
	}
	if value == nil {
		return false, nil
	}
	parsed, ok := value.(bool)
	if !ok {
		return false, requestMalformed(key + " must be a boolean")
	}
	return parsed, nil
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

func validateMessages(value any) error {
	messages, ok := value.([]any)
	if !ok || len(messages) == 0 || len(messages) > 4096 {
		return requestMalformed("messages must be a non-empty bounded array")
	}
	for _, value := range messages {
		message, ok := value.(map[string]any)
		if !ok {
			return requestMalformed("each message must be an object")
		}
		role, ok := message["role"].(string)
		if !ok || !safeIdentifierValue(role, 32) || !slicesContainsString(
			[]string{"developer", "system", "user", "assistant", "tool", "function"}, role,
		) {
			return requestMalformed("each message must have a supported role")
		}
		toolCalls, err := validateMessageToolCalls(message["tool_calls"])
		if err != nil {
			return err
		}
		functionCall, err := validateMessageFunctionCall(message["function_call"])
		if err != nil {
			return err
		}
		if toolCalls && functionCall {
			return requestMalformed("assistant messages cannot contain both tool_calls and function_call")
		}
		if role != "assistant" && (toolCalls || functionCall) {
			return requestMalformed("only assistant messages may contain tool calls")
		}
		content, hasContent := message["content"]
		if (role == "function" && !hasContent) ||
			((!hasContent || content == nil) && role != "function" && !(role == "assistant" && (toolCalls || functionCall))) {
			return requestMalformed("each message must contain content or a tool call")
		}
		if hasContent && !validMessageContent(content, role) {
			return requestMalformed("message content must be text, null, or a content-part array")
		}
		if role == "tool" {
			toolCallID, ok := message["tool_call_id"].(string)
			if !ok || !safeIdentifierValue(toolCallID, 256) {
				return requestMalformed("tool messages require a tool_call_id")
			}
		}
		if role == "function" {
			name, ok := message["name"].(string)
			if !ok || !validFunctionName(name) {
				return requestMalformed("function messages require a bounded name")
			}
		}
	}
	return nil
}

func validMessageContent(value any, role string) bool {
	switch typed := value.(type) {
	case nil:
		return role == "assistant" || role == "function"
	case string:
		return !strings.ContainsRune(typed, '\x00')
	case []any:
		if role == "function" || len(typed) == 0 || len(typed) > 4096 {
			return false
		}
		refusals := 0
		for _, part := range typed {
			object, ok := part.(map[string]any)
			refusal, valid := validMessageContentPart(object, role)
			if !ok || !valid {
				return false
			}
			if refusal {
				refusals++
			}
		}
		return refusals == 0 || (role == "assistant" && refusals == 1 && len(typed) == 1)
	default:
		return false
	}
}

func validMessageContentPart(object map[string]any, role string) (refusal bool, valid bool) {
	partType, ok := object["type"].(string)
	if !ok {
		return false, false
	}
	switch partType {
	case "text":
		text, ok := object["text"].(string)
		return false, ok && !strings.ContainsRune(text, '\x00')
	case "refusal":
		refusal, ok := object["refusal"].(string)
		return true, role == "assistant" && ok && !strings.ContainsRune(refusal, '\x00')
	case "image_url":
		if role != "user" {
			return false, false
		}
		image, ok := object["image_url"].(map[string]any)
		url, urlOK := image["url"].(string)
		if !ok || !urlOK || url == "" || strings.ContainsAny(url, "\r\n\x00") {
			return false, false
		}
		if detail, present := image["detail"]; present && detail != nil {
			value, ok := detail.(string)
			if !ok || !safeIdentifierValue(value, 32) {
				return false, false
			}
		}
		return false, true
	case "input_audio":
		if role != "user" {
			return false, false
		}
		audio, ok := object["input_audio"].(map[string]any)
		data, dataOK := audio["data"].(string)
		format, formatOK := audio["format"].(string)
		return false, ok && dataOK && data != "" && !strings.ContainsRune(data, '\x00') &&
			formatOK && slicesContainsString([]string{"mp3", "wav"}, format)
	case "file":
		if role != "user" {
			return false, false
		}
		file, ok := object["file"].(map[string]any)
		if !ok {
			return false, false
		}
		fileData, hasData, validData := optionalStringMember(file, "file_data")
		fileID, hasID, validID := optionalStringMember(file, "file_id")
		if !validData || !validID || hasData == hasID ||
			(hasData && (fileData == "" || strings.ContainsRune(fileData, '\x00'))) ||
			(hasID && !safeIdentifierValue(fileID, 256)) {
			return false, false
		}
		if filename, present := file["filename"]; present && filename != nil {
			value, ok := filename.(string)
			if !ok || value == "" || strings.ContainsAny(value, "\r\n\x00") {
				return false, false
			}
		}
		return false, true
	default:
		return false, false
	}
}

func optionalStringMember(object map[string]any, key string) (string, bool, bool) {
	value, present := object[key]
	if !present || value == nil {
		return "", false, true
	}
	text, ok := value.(string)
	return text, ok, ok
}

func validateMessageToolCalls(value any) (bool, error) {
	if value == nil {
		return false, nil
	}
	calls, ok := value.([]any)
	if !ok || len(calls) == 0 || len(calls) > 128 {
		return false, requestMalformed("tool_calls must be a non-empty bounded array")
	}
	seenIDs := make(map[string]struct{}, len(calls))
	for _, value := range calls {
		call, ok := value.(map[string]any)
		idValue, idOK := call["id"].(string)
		callType, typeOK := call["type"].(string)
		if !ok || !idOK || !safeIdentifierValue(idValue, 256) || !typeOK {
			return false, requestMalformed("assistant tool calls must have bounded identifiers and supported types")
		}
		if _, duplicate := seenIDs[idValue]; duplicate {
			return false, requestMalformed("assistant tool call identifiers must be unique")
		}
		seenIDs[idValue] = struct{}{}
		switch callType {
		case "function":
			if !validateFunctionCallObject(call["function"]) {
				return false, requestMalformed("assistant function tool calls require a name and arguments")
			}
		case "custom":
			if !validateCustomToolCallObject(call["custom"]) {
				return false, requestMalformed("assistant custom tool calls require a name and input")
			}
		default:
			return false, requestMalformed("assistant tool calls have an unsupported type")
		}
	}
	return true, nil
}

func validateCustomToolCallObject(value any) bool {
	custom, ok := value.(map[string]any)
	if !ok {
		return false
	}
	name, nameOK := custom["name"].(string)
	input, inputOK := custom["input"].(string)
	return nameOK && validFunctionName(name) && inputOK && len(input) <= int(defaultMaximumBody) &&
		!strings.ContainsRune(input, '\x00')
}

func validateMessageFunctionCall(value any) (bool, error) {
	if value == nil {
		return false, nil
	}
	if !validateFunctionCallObject(value) {
		return false, requestMalformed("assistant function_call requires a function name and arguments")
	}
	return true, nil
}

func validateFunctionCallObject(value any) bool {
	function, ok := value.(map[string]any)
	if !ok {
		return false
	}
	name, nameOK := function["name"].(string)
	arguments, argumentsOK := function["arguments"].(string)
	return nameOK && validFunctionName(name) && argumentsOK && !strings.ContainsRune(arguments, '\x00')
}

func validateTools(value any) error {
	if value == nil {
		return nil
	}
	tools, ok := value.([]any)
	if !ok || len(tools) > 128 {
		return requestMalformed("tools must be a bounded array")
	}
	seenNames := make(map[string]struct{}, len(tools))
	for _, value := range tools {
		tool, ok := value.(map[string]any)
		toolType, typeOK := tool["type"].(string)
		if !ok || !typeOK {
			return requestMalformed("tools must have a supported type")
		}
		var name string
		switch toolType {
		case "function":
			function, ok := tool["function"].(map[string]any)
			nameValue, nameOK := function["name"].(string)
			if !ok || !nameOK || !validFunctionName(nameValue) {
				return requestMalformed("function tools require a bounded name")
			}
			name = nameValue
			if description, present := function["description"]; present && description != nil {
				value, ok := description.(string)
				if !ok || len(value) > 8192 || strings.ContainsRune(value, '\x00') {
					return requestMalformed("function tool descriptions must be bounded text")
				}
			}
			if parameters, present := function["parameters"]; present && parameters != nil {
				if _, ok := parameters.(map[string]any); !ok {
					return requestMalformed("function tool parameters must be an object")
				}
			}
			if strict, present := function["strict"]; present && strict != nil {
				if _, ok := strict.(bool); !ok {
					return requestMalformed("function tool strict must be a boolean")
				}
			}
		case "custom":
			var valid bool
			name, valid = validateCustomToolDefinition(tool["custom"])
			if !valid {
				return requestMalformed("custom tools require a bounded name and valid input format")
			}
		default:
			return requestMalformed("tool type is unsupported")
		}
		if _, duplicate := seenNames[name]; duplicate {
			return requestMalformed("tool names must be unique")
		}
		seenNames[name] = struct{}{}
	}
	return nil
}

func validateCustomToolDefinition(value any) (string, bool) {
	custom, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	name, nameOK := custom["name"].(string)
	if !nameOK || !validFunctionName(name) {
		return "", false
	}
	if description, present := custom["description"]; present && description != nil {
		text, ok := description.(string)
		if !ok || len(text) > 8192 || strings.ContainsRune(text, '\x00') {
			return "", false
		}
	}
	formatValue, present := custom["format"]
	if !present || formatValue == nil {
		return name, true
	}
	format, ok := formatValue.(map[string]any)
	formatType, typeOK := format["type"].(string)
	if !ok || !typeOK {
		return "", false
	}
	switch formatType {
	case "text":
		return name, true
	case "grammar":
		grammar, ok := format["grammar"].(map[string]any)
		definition, definitionOK := grammar["definition"].(string)
		syntax, syntaxOK := grammar["syntax"].(string)
		return name, ok && definitionOK && definition != "" && len(definition) <= int(defaultMaximumBody) &&
			!strings.ContainsRune(definition, '\x00') && syntaxOK &&
			slicesContainsString([]string{"lark", "regex"}, syntax)
	default:
		return "", false
	}
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

func slicesContainsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type jsonObserver struct {
	buffer   bytes.Buffer
	overflow bool
}

func (o *jsonObserver) Observe(chunk []byte) error {
	if o.overflow {
		return nil
	}
	if int64(o.buffer.Len()+len(chunk)) > maximumObservedResponse {
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
	return usageFromValue(value)
}

type sseObserver struct {
	pending    []byte
	scanOffset int
	lineStart  int
	eventEnd   int
	usage      protocol.Usage
	found      bool
	done       bool
	events     int
}

func (o *sseObserver) Observe(chunk []byte) error {
	if o.done && len(chunk) > 0 {
		return upstreamMalformed("upstream SSE stream contains bytes after [DONE]")
	}
	for len(chunk) > 0 {
		if o.done {
			return upstreamMalformed("upstream SSE stream contains bytes after [DONE]")
		}
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
		if o.done && len(o.pending) > 0 {
			return upstreamMalformed("upstream SSE stream contains bytes after [DONE]")
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
		return protocol.Usage{}, upstreamMalformed("upstream SSE stream ended before [DONE]")
	}
	if !o.found {
		return unknownUsage(), nil
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
		return upstreamMalformed("upstream SSE stream contains bytes after [DONE]")
	}
	if o.events == 0 {
		event = bytes.TrimPrefix(event, []byte{0xef, 0xbb, 0xbf})
	}
	o.events++
	data, hasData := sseEventData(event)
	if !hasData {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
		o.done = true
		return nil
	}
	if o.found {
		return upstreamMalformed("upstream SSE stream contains data after its usage chunk")
	}
	value, err := jsonsafe.Decode(data)
	if err != nil {
		return upstreamMalformed("upstream returned malformed SSE data")
	}
	usage, err := usageFromValue(value)
	if err != nil {
		return err
	}
	if usage.Known {
		o.usage = usage
		o.found = true
	}
	return nil
}

func sseEventData(event []byte) ([]byte, bool) {
	dataLines := make([][]byte, 0, 1)
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
		if bytes.Equal(field, []byte("data")) {
			dataLines = append(dataLines, value)
		}
	}
	if len(dataLines) == 0 {
		return nil, false
	}
	return bytes.Join(dataLines, []byte("\n")), true
}

func usageFromValue(value any) (protocol.Usage, error) {
	root, ok := value.(map[string]any)
	if !ok {
		return protocol.Usage{}, upstreamMalformed("upstream JSON must be an object")
	}
	usageValue, present := root["usage"]
	if !present || usageValue == nil {
		return unknownUsage(), nil
	}
	usageObject, ok := usageValue.(map[string]any)
	if !ok {
		return protocol.Usage{}, upstreamMalformed("upstream usage must be an object")
	}
	reportedCost := openaiusage.ReportedCost(usageObject)
	input, inputPresent, err := usageInteger(usageObject, "prompt_tokens", "input_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	output, outputPresent, err := usageInteger(usageObject, "completion_tokens", "output_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	total, totalPresent, err := usageInteger(usageObject, "total_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	if !inputPresent && !outputPresent && !totalPresent {
		usage := unknownUsage()
		usage.ReportedCost = reportedCost
		return usage, nil
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
		Known: true, Provenance: "provider_reported", ReportedCost: reportedCost,
	}, nil
}

func usageInteger(object map[string]any, keys ...string) (int64, bool, error) {
	var selected any
	found := false
	for _, key := range keys {
		value, present := object[key]
		if !present {
			continue
		}
		if found {
			return 0, false, upstreamMalformed("upstream usage contains ambiguous aliases")
		}
		selected = value
		found = true
	}
	if !found {
		return 0, false, nil
	}
	number, ok := selected.(json.Number)
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
