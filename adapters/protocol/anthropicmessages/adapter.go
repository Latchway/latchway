// Package anthropicmessages implements the Anthropic Messages protocol
// without coupling it to an upstream hostname, credential, or tool executor.
package anthropicmessages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

const (
	ID = protocol.AnthropicMessagesID

	// CanonicalAPIVersion is server-owned. Client requests carrying any
	// Anthropic version or beta header are rejected; ApplyFeature installs this
	// exact value only after the body has passed protocol inspection.
	CanonicalAPIVersion = "2023-06-01"

	defaultMaximumBody      = int64(1 << 20)
	maximumProviderBody     = int64(32 << 20)
	maximumObservedJSON     = int64(4 << 20)
	maximumSSEEvent         = 1 << 20
	maximumSSEEvents        = 1 << 20
	maximumMessages         = 4096
	maximumContentBlocks    = 4096
	maximumTools            = 128
	maximumStopSequences    = 128
	maximumEventTypeBytes   = 128
	maximumDescriptionBytes = 8192
	providerUsageProvenance = "provider_reported"
)

// Adapter inspects and rewrites Messages requests. Client-tool definitions,
// tool-use blocks, and tool-result blocks are relayed only as provider data;
// this package deliberately has no facility for executing tools.
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
type trustedVersionContextKey struct{}

func (a Adapter) ID() string { return ID }

// Match accepts only the canonical public Messages endpoint. Encoded aliases,
// query strings, and fragments do not enter protocol processing.
func (a Adapter) Match(request *http.Request) bool {
	return request != nil && request.Method == http.MethodPost && request.URL != nil &&
		request.URL.Path == protocol.AnthropicMessagesPublicPath && request.URL.RawPath == "" &&
		request.URL.Opaque == "" && request.URL.User == nil &&
		request.URL.RawQuery == "" && !request.URL.ForceQuery && request.URL.Fragment == "" &&
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
	if !objectContainsOnly(object, map[string]struct{}{
		"model": {}, "messages": {}, "max_tokens": {}, "stream": {}, "system": {},
		"stop_sequences": {}, "temperature": {}, "top_k": {}, "top_p": {},
		"tools": {}, "tool_choice": {},
	}) {
		return protocol.RequestMetadata{}, requestMalformed("request contains unsupported provider fields")
	}
	model, ok := object["model"].(string)
	if !ok || !safeIdentifierValue(model, 256) {
		return protocol.RequestMetadata{}, requestMalformed("model must be a non-empty safe string")
	}
	toolNames, err := validateTools(object)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateMessages(object["messages"]); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateSystem(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateStopSequences(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateSamplingControls(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateToolChoice(object, toolNames); err != nil {
		return protocol.RequestMetadata{}, err
	}
	streaming, err := optionalBool(object, "stream")
	if err != nil {
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
		// This is only an untrusted scheduling hint. Only PreflightInput after
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
	object["max_tokens"] = effective
	rewritten, err := json.Marshal(object)
	if err != nil {
		return 0, fmt.Errorf("encode rewritten Anthropic Messages request: %w", err)
	}
	if int64(len(rewritten)) > a.maximumBodyBytes() {
		return 0, errors.New("rewritten Anthropic Messages request exceeds configured limit")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	installRequestBody(request, rewritten)
	replaceHeader(request.Header, "Content-Type", "application/json")
	deleteAnthropicHeaders(request.Header)
	request.Header.Set("Anthropic-Version", CanonicalAPIVersion)
	mode := responseModeJSON
	if metadata.Streaming {
		mode = responseModeSSE
	}
	requestContext := context.WithValue(request.Context(), trustedVersionContextKey{}, true)
	requestContext = context.WithValue(requestContext, responseModeContextKey{}, mode)
	*request = *request.WithContext(requestContext)
	return effective, nil
}

// MeasureRequest counts every supported image block, including images nested
// in tool_result content, and every explicit assistant tool_use block in the
// exact rewritten Messages body. Tool definitions and results are not calls.
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
	object, raw, err := a.readRequest(ctx, request)
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
	for _, messageValue := range messages {
		message, _ := messageValue.(map[string]any)
		blocks, _ := message["content"].([]any)
		for _, blockValue := range blocks {
			block, _ := blockValue.(map[string]any)
			switch block["type"] {
			case "image":
				images++
			case "tool_use":
				calls++
			case "tool_result":
				nested, _ := block["content"].([]any)
				for _, nestedValue := range nested {
					nestedBlock, _ := nestedValue.(map[string]any)
					if nestedBlock["type"] == "image" {
						images++
					}
				}
			}
		}
	}
	return images, calls
}

// PreflightInput proves a conservative bound over the exact rewritten
// Anthropic Messages body. Only text messages and text system blocks are in
// the proof surface; images, tools, binary sources, and provider extensions
// fail closed whenever trusted input accounting is selected.
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

	installRequestBody(request, raw)
	return protocol.TrustedInputPreflight{
		ProfileID: profile.ID, ProfileDigest: profile.Digest(), Protocol: profile.Protocol,
		Method: profile.Method, PhysicalModel: profile.PhysicalModel,
		RewrittenBodySHA256: sha256.Sum256(raw), RequestBytes: requestBytes,
		MessageCount: messageCount, InputTokenBound: inputBound,
		OutputTokenBound: outputBound, TotalTokenBound: totalBound,
	}, nil
}

func validateTrustedInputProfile(profile protocol.TrustedInputProfile) error {
	if !safeIdentifierValue(profile.ID, 63) {
		return errors.New("valid trusted input profile ID is required")
	}
	if profile.Protocol != ID {
		return errors.New("trusted input profile protocol does not match Anthropic Messages")
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
	if !objectContainsOnly(object, map[string]struct{}{
		"model": {}, "messages": {}, "max_tokens": {}, "stream": {}, "system": {},
		"stop_sequences": {}, "temperature": {}, "top_k": {}, "top_p": {},
	}) {
		return 0, 0, requestMalformed("trusted input preflight supports only bounded text request fields")
	}
	model, ok := object["model"].(string)
	if !ok || model != profile.PhysicalModel {
		return 0, 0, errors.New("trusted input profile physical model does not match rewritten request")
	}
	if _, err := optionalBool(object, "stream"); err != nil {
		return 0, 0, err
	}
	if err := validateSystem(object); err != nil {
		return 0, 0, err
	}
	messages, ok := object["messages"].([]any)
	if !ok || len(messages) == 0 || len(messages) > maximumMessages {
		return 0, 0, requestMalformed("messages must be a non-empty bounded array")
	}
	for _, value := range messages {
		message, ok := value.(map[string]any)
		role, roleOK := message["role"].(string)
		if !ok || !objectContainsOnly(message, map[string]struct{}{"role": {}, "content": {}}) ||
			!roleOK || (role != "user" && role != "assistant") ||
			!trustedTextMessageContent(message["content"]) {
			return 0, 0, requestMalformed("trusted input messages must contain only text")
		}
	}
	outputBound, err := requestedOutputLimit(object)
	if err != nil {
		return 0, 0, err
	}
	if outputBound <= 0 {
		return 0, 0, errors.New("rewritten request is missing its output-token maximum")
	}
	return int64(len(messages)), outputBound, nil
}

func trustedTextMessageContent(value any) bool {
	switch typed := value.(type) {
	case string:
		return typed != "" && utf8.ValidString(typed) && !strings.ContainsRune(typed, '\x00')
	case []any:
		if len(typed) == 0 || len(typed) > maximumContentBlocks {
			return false
		}
		for _, value := range typed {
			block, ok := value.(map[string]any)
			blockType, typeOK := block["type"].(string)
			text, textOK := block["text"].(string)
			if !ok || !objectContainsOnly(block, map[string]struct{}{"type": {}, "text": {}}) ||
				!typeOK || blockType != "text" || !textOK || text == "" ||
				!utf8.ValidString(text) || strings.ContainsRune(text, '\x00') {
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
	if response.Request == nil || response.Request.Context() == nil {
		return nil, errors.New("response request is required")
	}
	mode, ok := response.Request.Context().Value(responseModeContextKey{}).(responseMode)
	if !ok || (mode != responseModeJSON && mode != responseModeSSE) {
		return nil, errors.New("response request is missing its protocol mode")
	}

	// Provider-controlled non-success bodies never influence metering or safe
	// client errors. The relay classifies the status without relaying the body.
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return discardObserver{ctx: ctx}, nil
	}
	contentTypes := caseInsensitiveHeaderValues(response.Header, "Content-Type")
	if len(contentTypes) != 1 {
		return nil, upstreamMalformed("upstream response must contain exactly one Content-Type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || (!strings.EqualFold(mediaType, "application/json") &&
		!strings.EqualFold(mediaType, "text/event-stream")) {
		return nil, upstreamMalformed("upstream response Content-Type is unsupported")
	}
	isSSE := strings.EqualFold(mediaType, "text/event-stream")
	if (mode == responseModeSSE) != isSSE {
		return nil, upstreamMalformed("upstream response Content-Type does not match the request mode")
	}
	if isSSE {
		return &sseObserver{ctx: ctx}, nil
	}
	return &jsonObserver{ctx: ctx}, nil
}

func (a Adapter) readRequest(ctx context.Context, request *http.Request) (map[string]any, []byte, error) {
	if !a.Match(request) {
		return nil, nil, requestMalformed("POST /v1/messages without encoding or a query is required")
	}
	if request.Body == nil {
		return nil, nil, requestMalformed("JSON request body is required")
	}
	if err := validateProviderHeaders(request); err != nil {
		return nil, nil, err
	}
	contentTypes := caseInsensitiveHeaderValues(request.Header, "Content-Type")
	if len(contentTypes) != 1 {
		return nil, nil, requestMalformed("exactly one content type is required")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return nil, nil, requestMalformed("content type must be application/json")
	}
	if hasHeaderName(request.Header, "Content-Encoding") {
		return nil, nil, requestMalformed("encoded request bodies are not supported")
	}
	limit := a.maximumBodyBytes()
	if request.ContentLength < -1 || request.ContentLength > limit {
		return nil, nil, requestMalformed("Anthropic Messages request exceeds configured limit")
	}
	raw, readErr := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: request.Body}, limit+1))
	closeErr := request.Body.Close()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if readErr != nil {
		return nil, nil, requestMalformed("request body could not be read")
	}
	if closeErr != nil {
		return nil, nil, requestMalformed("request body could not be closed")
	}
	if int64(len(raw)) > limit {
		return nil, nil, requestMalformed("Anthropic Messages request exceeds configured limit")
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
	limit := a.MaximumBodyBytes
	if limit <= 0 {
		limit = defaultMaximumBody
	}
	if limit > maximumProviderBody {
		return maximumProviderBody
	}
	return limit
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(destination []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(destination)
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

func validateProviderHeaders(request *http.Request) error {
	trusted, _ := request.Context().Value(trustedVersionContextKey{}).(bool)
	versions := caseInsensitiveHeaderValues(request.Header, "Anthropic-Version")
	if hasHeaderName(request.Header, "Anthropic-Version") &&
		(!trusted || len(versions) != 1 || versions[0] != CanonicalAPIVersion) {
		return requestMalformed("client Anthropic version headers are not accepted")
	}
	for name := range request.Header {
		if !strings.HasPrefix(strings.ToLower(name), "anthropic-") || strings.EqualFold(name, "Anthropic-Version") {
			continue
		}
		return requestMalformed("client Anthropic extension headers are not accepted")
	}
	if hasHeaderName(request.Header, "X-Api-Key") {
		return requestMalformed("client provider credentials are not accepted")
	}
	return nil
}

func requestedOutputLimit(object map[string]any) (int64, error) {
	value, present := object["max_tokens"]
	if !present {
		return 0, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, requestMalformed("max_tokens must be a positive integer")
	}
	parsed, err := number.Int64()
	if err != nil || parsed <= 0 {
		return 0, requestMalformed("max_tokens must be a positive integer")
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

func validateMessages(value any) error {
	messages, ok := value.([]any)
	if !ok || len(messages) == 0 || len(messages) > maximumMessages {
		return requestMalformed("messages must be a non-empty bounded array")
	}
	toolUses := make(map[string]struct{})
	toolResults := make(map[string]struct{})
	pendingToolUses := make(map[string]struct{})
	for messageIndex, messageValue := range messages {
		message, ok := messageValue.(map[string]any)
		if !ok || !objectContainsOnly(message, map[string]struct{}{"role": {}, "content": {}}) {
			return requestMalformed("each message must contain only role and content")
		}
		role, ok := message["role"].(string)
		if !ok || (role != "user" && role != "assistant") {
			return requestMalformed("each message must use the user or assistant role")
		}
		if messageIndex == 0 && role != "user" {
			return requestMalformed("messages must begin with a user message")
		}
		expectedResults := pendingToolUses
		if len(expectedResults) > 0 && role != "user" {
			return requestMalformed("tool_result messages must immediately follow tool_use messages")
		}
		content, present := message["content"]
		if !present {
			return requestMalformed("each message must contain content")
		}
		switch typed := content.(type) {
		case string:
			if typed == "" || strings.ContainsRune(typed, '\x00') {
				return requestMalformed("message text must be non-empty safe text")
			}
			if len(expectedResults) > 0 {
				return requestMalformed("pending tool uses require tool_result blocks")
			}
		case []any:
			if len(typed) == 0 || len(typed) > maximumContentBlocks {
				return requestMalformed("message content must be a non-empty bounded block array")
			}
			messageToolUses := make(map[string]struct{})
			messageToolResults := make(map[string]struct{})
			seenNonToolResult := false
			for _, blockValue := range typed {
				block, _ := blockValue.(map[string]any)
				blockType, _ := block["type"].(string)
				if blockType == "tool_result" {
					if seenNonToolResult {
						return requestMalformed("tool_result blocks must come before other user content")
					}
				} else {
					seenNonToolResult = true
				}
				if err := validateContentBlock(blockValue, role, toolUses, toolResults); err != nil {
					return err
				}
				switch blockType {
				case "tool_use":
					messageToolUses[block["id"].(string)] = struct{}{}
				case "tool_result":
					messageToolResults[block["tool_use_id"].(string)] = struct{}{}
				}
			}
			if role == "user" {
				if len(messageToolResults) > 0 && len(expectedResults) == 0 {
					return requestMalformed("tool_result blocks must immediately follow their tool_use message")
				}
				if len(expectedResults) > 0 {
					if len(messageToolResults) != len(expectedResults) {
						return requestMalformed("each pending tool_use requires one immediate tool_result")
					}
					for id := range expectedResults {
						if _, present := messageToolResults[id]; !present {
							return requestMalformed("each pending tool_use requires one immediate tool_result")
						}
					}
				}
				pendingToolUses = make(map[string]struct{})
			} else {
				pendingToolUses = messageToolUses
			}
		default:
			return requestMalformed("message content must be text or a content block array")
		}
	}
	if len(pendingToolUses) > 0 {
		return requestMalformed("request ends with unresolved tool_use blocks")
	}
	return nil
}

func validateContentBlock(value any, role string, toolUses, toolResults map[string]struct{}) error {
	block, ok := value.(map[string]any)
	if !ok {
		return requestMalformed("each message content block must be an object")
	}
	blockType, ok := block["type"].(string)
	if !ok {
		return requestMalformed("each message content block must have a supported type")
	}
	switch blockType {
	case "text":
		if !objectContainsOnly(block, map[string]struct{}{"type": {}, "text": {}}) {
			return requestMalformed("text content blocks contain unsupported fields")
		}
		text, ok := block["text"].(string)
		if !ok || text == "" || strings.ContainsRune(text, '\x00') {
			return requestMalformed("text content blocks require non-empty safe text")
		}
	case "image":
		if role != "user" || !objectContainsOnly(block, map[string]struct{}{"type": {}, "source": {}}) ||
			!validImageSource(block["source"]) {
			return requestMalformed("image content blocks require a supported base64 source in a user message")
		}
	case "tool_use":
		if role != "assistant" || !objectContainsOnly(block, map[string]struct{}{
			"type": {}, "id": {}, "name": {}, "input": {},
		}) {
			return requestMalformed("tool_use blocks require the supported assistant shape")
		}
		id, idOK := block["id"].(string)
		name, nameOK := block["name"].(string)
		input, inputOK := block["input"].(map[string]any)
		if !idOK || !safeIdentifierValue(id, 256) || !nameOK || !validToolName(name) ||
			!inputOK || !safeRelayJSON(input) {
			return requestMalformed("tool_use blocks require safe identifiers and object input")
		}
		if _, duplicate := toolUses[id]; duplicate {
			return requestMalformed("tool_use identifiers must be unique")
		}
		toolUses[id] = struct{}{}
	case "tool_result":
		if role != "user" || !objectContainsOnly(block, map[string]struct{}{
			"type": {}, "tool_use_id": {}, "content": {}, "is_error": {},
		}) {
			return requestMalformed("tool_result blocks require the supported user shape")
		}
		id, idOK := block["tool_use_id"].(string)
		if !idOK || !safeIdentifierValue(id, 256) {
			return requestMalformed("tool_result blocks require a safe tool_use_id")
		}
		if _, known := toolUses[id]; !known {
			return requestMalformed("tool_result blocks must reference an earlier tool_use")
		}
		if _, duplicate := toolResults[id]; duplicate {
			return requestMalformed("each tool_use may have only one tool_result")
		}
		if content, present := block["content"]; present {
			if err := validateToolResultContent(content); err != nil {
				return err
			}
		}
		if isError, present := block["is_error"]; present {
			if _, ok := isError.(bool); !ok {
				return requestMalformed("tool_result is_error must be a boolean")
			}
		}
		toolResults[id] = struct{}{}
	default:
		return requestMalformed("message content block type is unsupported")
	}
	return nil
}

func validateToolResultContent(value any) error {
	switch typed := value.(type) {
	case string:
		if strings.ContainsRune(typed, '\x00') {
			return requestMalformed("tool_result content must be safe text or supported blocks")
		}
		return nil
	case []any:
		if len(typed) == 0 || len(typed) > maximumContentBlocks {
			return requestMalformed("tool_result content must be safe text or supported blocks")
		}
		for _, value := range typed {
			block, ok := value.(map[string]any)
			if !ok {
				return requestMalformed("tool_result content must contain supported blocks")
			}
			blockType, _ := block["type"].(string)
			switch blockType {
			case "text":
				text, textOK := block["text"].(string)
				if !objectContainsOnly(block, map[string]struct{}{"type": {}, "text": {}}) ||
					!textOK || strings.ContainsRune(text, '\x00') {
					return requestMalformed("tool_result text blocks are invalid")
				}
			case "image":
				if !objectContainsOnly(block, map[string]struct{}{"type": {}, "source": {}}) ||
					!validImageSource(block["source"]) {
					return requestMalformed("tool_result image blocks are invalid")
				}
			default:
				return requestMalformed("tool_result content block type is unsupported")
			}
		}
		return nil
	default:
		return requestMalformed("tool_result content must be safe text or supported blocks")
	}
}

func validImageSource(value any) bool {
	source, ok := value.(map[string]any)
	if !ok || !objectContainsOnly(source, map[string]struct{}{
		"type": {}, "media_type": {}, "data": {},
	}) {
		return false
	}
	sourceType, typeOK := source["type"].(string)
	mediaType, mediaOK := source["media_type"].(string)
	data, dataOK := source["data"].(string)
	if !typeOK || sourceType != "base64" || !mediaOK || !containsString(
		[]string{"image/jpeg", "image/png", "image/gif", "image/webp"}, mediaType,
	) || !dataOK || data == "" || strings.ContainsRune(data, '\x00') {
		return false
	}
	_, err := base64.StdEncoding.Strict().DecodeString(data)
	return err == nil
}

func validateSystem(object map[string]any) error {
	value, present := object["system"]
	if !present {
		return nil
	}
	switch typed := value.(type) {
	case string:
		if typed == "" || strings.ContainsRune(typed, '\x00') {
			return requestMalformed("system must be non-empty safe text or text blocks")
		}
	case []any:
		if len(typed) == 0 || len(typed) > maximumContentBlocks {
			return requestMalformed("system must be non-empty safe text or text blocks")
		}
		for _, blockValue := range typed {
			block, ok := blockValue.(map[string]any)
			text, textOK := block["text"].(string)
			blockType, typeOK := block["type"].(string)
			if !ok || !objectContainsOnly(block, map[string]struct{}{"type": {}, "text": {}}) ||
				!typeOK || blockType != "text" || !textOK || text == "" || strings.ContainsRune(text, '\x00') {
				return requestMalformed("system text blocks contain unsupported fields")
			}
		}
	default:
		return requestMalformed("system must be non-empty safe text or text blocks")
	}
	return nil
}

func validateStopSequences(object map[string]any) error {
	value, present := object["stop_sequences"]
	if !present {
		return nil
	}
	sequences, ok := value.([]any)
	if !ok || len(sequences) == 0 || len(sequences) > maximumStopSequences {
		return requestMalformed("stop_sequences must be a non-empty bounded string array")
	}
	seen := make(map[string]struct{}, len(sequences))
	for _, value := range sequences {
		sequence, ok := value.(string)
		if !ok || sequence == "" || len(sequence) > maximumDescriptionBytes || strings.ContainsRune(sequence, '\x00') {
			return requestMalformed("stop_sequences must contain bounded non-empty safe strings")
		}
		if _, duplicate := seen[sequence]; duplicate {
			return requestMalformed("stop_sequences must be unique")
		}
		seen[sequence] = struct{}{}
	}
	return nil
}

func validateSamplingControls(object map[string]any) error {
	for _, field := range []struct {
		name        string
		minimum     float64
		maximum     float64
		minimumOK   bool
		integerOnly bool
	}{
		{name: "temperature", minimum: 0, maximum: 1, minimumOK: true},
		{name: "top_p", minimum: 0, maximum: 1, minimumOK: true},
		{name: "top_k", minimum: 0, minimumOK: true, integerOnly: true},
	} {
		value, present := object[field.name]
		if !present {
			continue
		}
		number, ok := value.(json.Number)
		if !ok {
			return requestMalformed(field.name + " must be a supported number")
		}
		if field.integerOnly {
			parsed, err := number.Int64()
			if err != nil || parsed < int64(field.minimum) {
				return requestMalformed(field.name + " must be a supported integer")
			}
			continue
		}
		parsed, err := strconv.ParseFloat(string(number), 64)
		minimumValid := parsed > field.minimum || (field.minimumOK && parsed == field.minimum)
		if err != nil || !minimumValid || parsed > field.maximum {
			return requestMalformed(field.name + " must be within its supported range")
		}
	}
	return nil
}

func validateTools(object map[string]any) (map[string]struct{}, error) {
	names := make(map[string]struct{})
	value, present := object["tools"]
	if !present {
		return names, nil
	}
	tools, ok := value.([]any)
	if !ok || len(tools) > maximumTools {
		return nil, requestMalformed("tools must be a bounded array of client-tool definitions")
	}
	for _, toolValue := range tools {
		tool, ok := toolValue.(map[string]any)
		if !ok || !objectContainsOnly(tool, map[string]struct{}{
			"name": {}, "description": {}, "input_schema": {},
		}) {
			return nil, requestMalformed("server tools and extended tool fields are not supported")
		}
		name, nameOK := tool["name"].(string)
		schema, schemaOK := tool["input_schema"].(map[string]any)
		if !nameOK || !validToolName(name) || !schemaOK || !safeLocalJSONSchema(schema) || schema["type"] != "object" {
			return nil, requestMalformed("client tools require a safe name and object input_schema")
		}
		if _, duplicate := names[name]; duplicate {
			return nil, requestMalformed("client tool names must be unique")
		}
		if description, present := tool["description"]; present {
			text, ok := description.(string)
			if !ok || len(text) > maximumDescriptionBytes || strings.ContainsRune(text, '\x00') {
				return nil, requestMalformed("client tool descriptions must be bounded safe text")
			}
		}
		names[name] = struct{}{}
	}
	return names, nil
}

func validateToolChoice(object map[string]any, toolNames map[string]struct{}) error {
	value, present := object["tool_choice"]
	if !present {
		return nil
	}
	choice, ok := value.(map[string]any)
	if !ok {
		return requestMalformed("tool_choice must be an object")
	}
	choiceType, ok := choice["type"].(string)
	if !ok {
		return requestMalformed("tool_choice requires a supported type")
	}
	switch choiceType {
	case "auto", "any":
		if len(toolNames) == 0 || !objectContainsOnly(choice, map[string]struct{}{
			"type": {}, "disable_parallel_tool_use": {},
		}) {
			return requestMalformed("tool_choice requires supported client tools and fields")
		}
	case "tool":
		if !objectContainsOnly(choice, map[string]struct{}{
			"type": {}, "name": {}, "disable_parallel_tool_use": {},
		}) {
			return requestMalformed("named tool_choice contains unsupported fields")
		}
		name, nameOK := choice["name"].(string)
		if !nameOK {
			return requestMalformed("named tool_choice requires a tool name")
		}
		if _, known := toolNames[name]; !known {
			return requestMalformed("named tool_choice must select a declared client tool")
		}
	case "none":
		if !objectContainsOnly(choice, map[string]struct{}{"type": {}}) {
			return requestMalformed("none tool_choice contains unsupported fields")
		}
	default:
		return requestMalformed("tool_choice type is unsupported")
	}
	if value, present := choice["disable_parallel_tool_use"]; present {
		if _, ok := value.(bool); !ok {
			return requestMalformed("disable_parallel_tool_use must be a boolean")
		}
	}
	return nil
}

func objectContainsOnly(object map[string]any, allowed map[string]struct{}) bool {
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

func safeRelayJSON(value any) bool {
	switch typed := value.(type) {
	case nil, bool, json.Number:
		return true
	case string:
		return !strings.ContainsRune(typed, '\x00')
	case []any:
		for _, item := range typed {
			if !safeRelayJSON(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for key, item := range typed {
			if strings.ContainsRune(key, '\x00') || !safeRelayJSON(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
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

func validToolName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range value {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
	deleteHeader(headers, name)
	headers.Set(name, value)
}

func deleteAnthropicHeaders(headers http.Header) {
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "anthropic-") {
			delete(headers, name)
		}
	}
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

func hasHeaderName(headers http.Header, name string) bool {
	for candidate := range headers {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
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

type discardObserver struct {
	ctx context.Context
}

func (observer discardObserver) Observe([]byte) error {
	return observer.ctx.Err()
}

func (observer discardObserver) Finalize() (protocol.Usage, error) {
	if err := observer.ctx.Err(); err != nil {
		return protocol.Usage{}, err
	}
	return unknownUsage(), nil
}

type jsonObserver struct {
	ctx      context.Context
	buffer   bytes.Buffer
	overflow bool
}

func (observer *jsonObserver) Observe(chunk []byte) error {
	if err := observer.ctx.Err(); err != nil {
		return err
	}
	if observer.overflow {
		return upstreamMalformed("upstream JSON response exceeds observation limit")
	}
	if int64(len(chunk)) > maximumObservedJSON-int64(observer.buffer.Len()) {
		observer.overflow = true
		observer.buffer = bytes.Buffer{}
		return upstreamMalformed("upstream JSON response exceeds observation limit")
	}
	_, _ = observer.buffer.Write(chunk)
	return observer.ctx.Err()
}

func (observer *jsonObserver) Finalize() (protocol.Usage, error) {
	if err := observer.ctx.Err(); err != nil {
		return protocol.Usage{}, err
	}
	if observer.overflow {
		return protocol.Usage{}, upstreamMalformed("upstream JSON response exceeds observation limit")
	}
	value, err := jsonsafe.Decode(observer.buffer.Bytes())
	if err != nil {
		return protocol.Usage{}, upstreamMalformed("upstream returned malformed JSON")
	}
	root, ok := value.(map[string]any)
	if !ok || root["type"] != "message" {
		return protocol.Usage{}, upstreamMalformed("upstream JSON must be an Anthropic message object")
	}
	usage, present := root["usage"]
	if !present {
		return protocol.Usage{}, upstreamMalformed("upstream message is missing usage")
	}
	return normalizedUsageFromValue(usage, true, true)
}

type sseObserver struct {
	ctx context.Context

	pending    []byte
	scanOffset int
	lineStart  int
	eventEnd   int
	events     int

	startSeen        bool
	messageDeltaSeen bool
	done             bool
	inputTokens      int64
	outputTokens     int64
	usage            protocol.Usage
}

func (observer *sseObserver) Observe(chunk []byte) error {
	if err := observer.ctx.Err(); err != nil {
		return err
	}
	if observer.done && len(chunk) > 0 {
		return upstreamMalformed("upstream SSE stream contains bytes after message_stop")
	}
	for len(chunk) > 0 {
		if err := observer.ctx.Err(); err != nil {
			return err
		}
		room := maximumSSEEvent + 4 - len(observer.pending)
		if room <= 0 {
			return upstreamMalformed("upstream SSE event exceeds limit")
		}
		if room > len(chunk) {
			room = len(chunk)
		}
		observer.pending = append(observer.pending, chunk[:room]...)
		chunk = chunk[room:]
		if err := observer.drainEvents(false); err != nil {
			return err
		}
		if observer.done && (len(observer.pending) > 0 || len(chunk) > 0) {
			return upstreamMalformed("upstream SSE stream contains bytes after message_stop")
		}
	}
	return observer.ctx.Err()
}

func (observer *sseObserver) Finalize() (protocol.Usage, error) {
	if err := observer.ctx.Err(); err != nil {
		return protocol.Usage{}, err
	}
	if err := observer.drainEvents(true); err != nil {
		return protocol.Usage{}, err
	}
	if len(observer.pending) > 0 {
		return protocol.Usage{}, upstreamMalformed("upstream SSE stream ended with an incomplete event")
	}
	if !observer.done {
		return protocol.Usage{}, upstreamMalformed("upstream SSE stream ended before message_stop")
	}
	return observer.usage, nil
}

func (observer *sseObserver) drainEvents(eof bool) error {
	eventStart := 0
	for observer.scanOffset < len(observer.pending) {
		if err := observer.ctx.Err(); err != nil {
			return err
		}
		lineEnd := observer.scanOffset
		endingLength := 0
		switch observer.pending[observer.scanOffset] {
		case '\n':
			endingLength = 1
		case '\r':
			if observer.scanOffset+1 == len(observer.pending) && !eof {
				observer.compactSSEPrefix(eventStart)
				return nil
			}
			endingLength = 1
			if observer.scanOffset+1 < len(observer.pending) && observer.pending[observer.scanOffset+1] == '\n' {
				endingLength = 2
			}
		default:
			observer.scanOffset++
			continue
		}

		endingEnd := lineEnd + endingLength
		if lineEnd == observer.lineStart {
			if observer.eventEnd-eventStart > maximumSSEEvent {
				return upstreamMalformed("upstream SSE event exceeds limit")
			}
			if err := observer.observeEvent(observer.pending[eventStart:observer.eventEnd]); err != nil {
				return err
			}
			eventStart = endingEnd
			observer.lineStart = endingEnd
			observer.eventEnd = endingEnd
			observer.scanOffset = endingEnd
			continue
		}
		observer.eventEnd = lineEnd
		observer.lineStart = endingEnd
		observer.scanOffset = endingEnd
	}
	observer.compactSSEPrefix(eventStart)
	return nil
}

func (observer *sseObserver) compactSSEPrefix(consumed int) {
	if consumed == 0 {
		return
	}
	copy(observer.pending, observer.pending[consumed:])
	observer.pending = observer.pending[:len(observer.pending)-consumed]
	observer.scanOffset -= consumed
	observer.lineStart -= consumed
	observer.eventEnd -= consumed
}

func (observer *sseObserver) observeEvent(event []byte) error {
	if observer.done {
		return upstreamMalformed("upstream SSE stream contains events after message_stop")
	}
	if observer.events >= maximumSSEEvents {
		return upstreamMalformed("upstream SSE stream contains too many events")
	}
	if observer.events == 0 {
		event = bytes.TrimPrefix(event, []byte{0xef, 0xbb, 0xbf})
	}
	observer.events++
	eventName, data, hasData, err := sseEventFields(event)
	if err != nil {
		return err
	}
	if !hasData {
		return nil
	}
	if eventName == "" {
		return upstreamMalformed("upstream Anthropic SSE events must be named")
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
	if !ok || !safeIdentifierValue(eventType, maximumEventTypeBytes) || eventName != eventType {
		return upstreamMalformed("upstream SSE event and data types do not match")
	}
	if eventType == "error" {
		return upstreamMalformed("upstream Anthropic stream reported an error")
	}
	if !observer.startSeen && eventType != "message_start" {
		return upstreamMalformed("upstream Anthropic stream must begin with message_start")
	}

	switch eventType {
	case "message_start":
		if observer.startSeen {
			return upstreamMalformed("upstream Anthropic stream contains duplicate message_start")
		}
		message, ok := root["message"].(map[string]any)
		if !ok || message["type"] != "message" {
			return upstreamMalformed("message_start must contain an Anthropic message")
		}
		usageValue, present := message["usage"]
		if !present {
			return upstreamMalformed("message_start is missing usage")
		}
		usage, err := normalizedUsageFromValue(usageValue, true, true)
		if err != nil {
			return err
		}
		observer.inputTokens = usage.InputTokens
		observer.outputTokens = usage.OutputTokens
		observer.startSeen = true
	case "message_delta":
		if observer.messageDeltaSeen && observer.done {
			return upstreamMalformed("message_delta appears after message_stop")
		}
		usageObject, ok := root["usage"].(map[string]any)
		if !ok {
			return upstreamMalformed("message_delta must contain usage")
		}
		input, inputPresent, err := usageInteger(usageObject, "input_tokens")
		if err != nil {
			return err
		}
		output, outputPresent, err := usageInteger(usageObject, "output_tokens")
		if err != nil {
			return err
		}
		if !outputPresent {
			return upstreamMalformed("message_delta usage is missing output_tokens")
		}
		if inputPresent {
			if input < observer.inputTokens {
				return upstreamMalformed("message_delta input usage decreased")
			}
			observer.inputTokens = input
		}
		if output < observer.outputTokens {
			return upstreamMalformed("message_delta output usage decreased")
		}
		observer.outputTokens = output
		observer.messageDeltaSeen = true
	case "message_stop":
		if !observer.messageDeltaSeen {
			return upstreamMalformed("message_stop arrived before terminal message usage")
		}
		usage, err := normalizedUsage(observer.inputTokens, observer.outputTokens)
		if err != nil {
			return err
		}
		observer.usage = usage
		observer.done = true
	}
	return observer.ctx.Err()
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
		fieldValue := []byte(nil)
		if colon := bytes.IndexByte(line, ':'); colon >= 0 {
			field = line[:colon]
			fieldValue = line[colon+1:]
			if len(fieldValue) > 0 && fieldValue[0] == ' ' {
				fieldValue = fieldValue[1:]
			}
		}
		switch {
		case bytes.Equal(field, []byte("data")):
			dataLines = append(dataLines, fieldValue)
		case bytes.Equal(field, []byte("event")):
			if eventSeen {
				return "", nil, false, upstreamMalformed("upstream SSE event contains duplicate event fields")
			}
			eventSeen = true
			eventName = string(fieldValue)
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

func normalizedUsageFromValue(value any, requireInput, requireOutput bool) (protocol.Usage, error) {
	usageObject, ok := value.(map[string]any)
	if !ok {
		return protocol.Usage{}, upstreamMalformed("upstream usage must be an object")
	}
	input, inputPresent, err := usageInteger(usageObject, "input_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	output, outputPresent, err := usageInteger(usageObject, "output_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	if (requireInput && !inputPresent) || (requireOutput && !outputPresent) {
		return protocol.Usage{}, upstreamMalformed("upstream usage is missing required token counts")
	}
	return normalizedUsage(input, output)
}

func normalizedUsage(input, output int64) (protocol.Usage, error) {
	if input < 0 || output < 0 || input > math.MaxInt64-output {
		return protocol.Usage{}, upstreamMalformed("upstream usage total overflows")
	}
	return protocol.Usage{
		InputTokens: input, OutputTokens: output, TotalTokens: input + output,
		Known: true, Provenance: providerUsageProvenance,
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
