// Package openaiembeddings implements the non-streaming OpenAI Embeddings
// protocol without coupling it to an upstream hostname or credential.
package openaiembeddings

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
	ID = protocol.OpenAIEmbeddingsID

	defaultMaximumBody      = int64(1 << 20)
	maximumObservedJSON     = int64(4 << 20)
	maximumBatchInputs      = 2048
	maximumTokensPerInput   = 8192
	maximumTotalTokenInputs = 300_000
	maximumTokenID          = math.MaxInt32
	maximumDimensions       = int64(65_536)
	providerUsageProvenance = "provider_reported"
)

// Adapter inspects and rewrites OpenAI Embeddings requests. It deliberately
// accepts only the local, stateless v1 subset: text or caller-supplied token
// arrays, with an optional encoding format and output dimension count.
type Adapter struct {
	MaximumBodyBytes int64
}

var _ protocol.Adapter = Adapter{}
var _ protocol.InputPreflighter = Adapter{}

type appliedContextKey struct{}

func (a Adapter) ID() string { return ID }

// Match accepts only the single canonical public Embeddings endpoint. Encoded
// aliases, query strings, and fragments cannot reach protocol processing.
func (a Adapter) Match(request *http.Request) bool {
	return request != nil && request.Method == http.MethodPost && request.URL != nil &&
		request.URL.Path == protocol.OpenAIEmbeddingsPublicPath && request.URL.RawPath == "" &&
		request.URL.Opaque == "" && request.URL.RawQuery == "" && !request.URL.ForceQuery && request.URL.Fragment == "" &&
		request.URL.RawFragment == ""
}

func (a Adapter) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{
		Streaming:             false,
		ModelRewrite:          true,
		OutputTokenClamp:      false,
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
	if !hasOnlyMembers(object, "model", "input", "encoding_format", "dimensions") {
		return protocol.RequestMetadata{}, requestMalformed("Embeddings request contains an unsupported root member")
	}
	model, ok := object["model"].(string)
	if !ok || !safeIdentifierValue(model, 256) {
		return protocol.RequestMetadata{}, requestMalformed("model must be a non-empty safe string")
	}
	if err := validateEncodingFormat(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	if err := validateDimensions(object); err != nil {
		return protocol.RequestMetadata{}, err
	}
	stats, err := validateInput(object["input"])
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	estimate := (int64(len(raw)) + 2) / 3
	if stats.tokenized {
		estimate = stats.tokens
	}
	return protocol.RequestMetadata{
		ClientModel:          model,
		Streaming:            false,
		RequestedOutputLimit: 0,
		EstimatedInputTokens: estimate,
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
	if decision.DefaultOutputTokens != 0 || decision.MaximumOutputTokens != 0 {
		return 0, errors.New("Embeddings output-token bounds must be zero")
	}

	object, raw, err := a.readRequest(ctx, request)
	if err != nil {
		return 0, err
	}
	if _, err := inspectRequestObject(object, raw); err != nil {
		return 0, err
	}
	object["model"] = decision.PhysicalModel
	rewritten, err := json.Marshal(object)
	if err != nil {
		return 0, fmt.Errorf("encode rewritten Embeddings request: %w", err)
	}
	if int64(len(rewritten)) > a.maximumBodyBytes() {
		return 0, errors.New("rewritten Embeddings request exceeds configured limit")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	installRequestBody(request, rewritten)
	replaceHeader(request.Header, "Content-Type", "application/json")
	*request = *request.WithContext(context.WithValue(request.Context(), appliedContextKey{}, true))
	// Embeddings have no generated-token output maximum. The zero is
	// intentional and is paired with OutputTokenClamp=false.
	return 0, nil
}

// MeasureRequest binds the exact rewritten Embeddings body. Its closed v1
// request grammar has neither images nor tool calls, so both counts are exact
// zeroes rather than omitted measurements.
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
	installRequestBody(request, raw)
	return protocol.RequestMeasurements{
		Protocol: ID, RewrittenBodySHA256: sha256.Sum256(raw), RequestBytes: int64(len(raw)),
		ImageUnitsKnown: true, ToolCallsKnown: true,
	}, nil
}

// PreflightInput proves a conservative bound for text-only Embeddings input.
// Caller-supplied token IDs and nested token batches deliberately fail closed:
// this proof method is tied to the exact physical model's byte-level BPE and
// does not treat client tokenization as authoritative.
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
	itemCount, err := validateTrustedInputRequest(object, profile)
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
	if inputBound > profile.MaximumContextTokens {
		return protocol.TrustedInputPreflight{}, requestMalformed("request exceeds the physical model context window")
	}

	installRequestBody(request, raw)
	return protocol.TrustedInputPreflight{
		ProfileID: profile.ID, ProfileDigest: profile.Digest(), Protocol: profile.Protocol,
		Method: profile.Method, PhysicalModel: profile.PhysicalModel,
		RewrittenBodySHA256: sha256.Sum256(raw), RequestBytes: requestBytes,
		MessageCount: itemCount, InputTokenBound: inputBound,
		OutputTokenBound: 0, TotalTokenBound: inputBound,
	}, nil
}

func validateTrustedInputProfile(profile protocol.TrustedInputProfile) error {
	if !safeIdentifierValue(profile.ID, 63) {
		return errors.New("valid trusted input profile ID is required")
	}
	if profile.Protocol != ID {
		return errors.New("trusted input profile protocol does not match OpenAI Embeddings")
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

func validateTrustedInputRequest(object map[string]any, profile protocol.TrustedInputProfile) (int64, error) {
	model, ok := object["model"].(string)
	if !ok || model != profile.PhysicalModel {
		return 0, errors.New("trusted input profile physical model does not match rewritten request")
	}
	switch typed := object["input"].(type) {
	case string:
		if !validTextInput(typed) {
			return 0, requestMalformed("trusted input must be non-empty local text")
		}
		return 1, nil
	case []any:
		if len(typed) == 0 || len(typed) > maximumBatchInputs {
			return 0, requestMalformed("trusted input text batches must be non-empty and bounded")
		}
		for _, value := range typed {
			text, ok := value.(string)
			if !ok || !validTextInput(text) {
				return 0, requestMalformed("trusted input supports only text batches")
			}
		}
		return int64(len(typed)), nil
	default:
		return 0, requestMalformed("trusted input supports only text or text batches")
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
	applied, _ := response.Request.Context().Value(appliedContextKey{}).(bool)
	if !applied {
		return nil, errors.New("response request is missing its protocol marker")
	}

	// Error bodies are provider-controlled. They never influence accounting or
	// leak provider details through protocol parsing.
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return discardObserver{}, nil
	}
	contentTypes := caseInsensitiveHeaderValues(response.Header, "Content-Type")
	if len(contentTypes) != 1 {
		return nil, upstreamMalformed("upstream response must contain exactly one Content-Type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return nil, upstreamMalformed("upstream response Content-Type must be application/json")
	}
	return &jsonObserver{}, nil
}

func (a Adapter) readRequest(ctx context.Context, request *http.Request) (map[string]any, []byte, error) {
	if !a.Match(request) {
		return nil, nil, requestMalformed("POST /v1/embeddings without encoding or a query is required")
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
		return nil, nil, requestMalformed("Embeddings request exceeds configured limit")
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
		return nil, nil, requestMalformed("Embeddings request exceeds configured limit")
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

func validateEncodingFormat(root map[string]any) error {
	value, present := root["encoding_format"]
	if !present {
		return nil
	}
	format, ok := value.(string)
	if !ok || (format != "float" && format != "base64") {
		return requestMalformed("encoding_format must be float or base64")
	}
	return nil
}

func validateDimensions(root map[string]any) error {
	value, present := root["dimensions"]
	if !present {
		return nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return requestMalformed("dimensions must be a positive bounded integer")
	}
	dimensions, err := number.Int64()
	if err != nil || dimensions <= 0 || dimensions > maximumDimensions {
		return requestMalformed("dimensions must be a positive bounded integer")
	}
	return nil
}

type inputStats struct {
	tokens    int64
	tokenized bool
}

func validateInput(value any) (inputStats, error) {
	switch typed := value.(type) {
	case string:
		if !validTextInput(typed) {
			return inputStats{}, requestMalformed("input must be non-empty local text or a supported bounded array")
		}
		return inputStats{}, nil
	case []any:
		return validateArrayInput(typed)
	default:
		return inputStats{}, requestMalformed("input must be non-empty local text or a supported bounded array")
	}
}

func validateArrayInput(input []any) (inputStats, error) {
	if len(input) == 0 {
		return inputStats{}, requestMalformed("input arrays must not be empty")
	}
	switch input[0].(type) {
	case string:
		if len(input) > maximumBatchInputs {
			return inputStats{}, requestMalformed("text input batches exceed the item limit")
		}
		for _, value := range input {
			text, ok := value.(string)
			if !ok || !validTextInput(text) {
				return inputStats{}, requestMalformed("text input batches must contain only non-empty local text")
			}
		}
		return inputStats{}, nil
	case json.Number:
		tokens, err := validateTokenArray(input)
		if err != nil {
			return inputStats{}, err
		}
		return inputStats{tokens: tokens, tokenized: true}, nil
	case []any:
		if len(input) > maximumBatchInputs {
			return inputStats{}, requestMalformed("token input batches exceed the item limit")
		}
		var total int64
		for _, value := range input {
			tokens, ok := value.([]any)
			if !ok {
				return inputStats{}, requestMalformed("token input batches must contain only token arrays")
			}
			count, err := validateTokenArray(tokens)
			if err != nil {
				return inputStats{}, err
			}
			if total > maximumTotalTokenInputs-count {
				return inputStats{}, requestMalformed("token input batches exceed the total token limit")
			}
			total += count
		}
		return inputStats{tokens: total, tokenized: true}, nil
	default:
		return inputStats{}, requestMalformed("input arrays must contain only text, token IDs, or token arrays")
	}
}

func validateTokenArray(tokens []any) (int64, error) {
	if len(tokens) == 0 || len(tokens) > maximumTokensPerInput {
		return 0, requestMalformed("each token input must contain between 1 and 8192 token IDs")
	}
	for _, value := range tokens {
		number, ok := value.(json.Number)
		if !ok {
			return 0, requestMalformed("token inputs must contain only non-negative integers")
		}
		token, err := number.Int64()
		if err != nil || token < 0 || token > maximumTokenID {
			return 0, requestMalformed("token inputs must contain only non-negative integers")
		}
	}
	return int64(len(tokens)), nil
}

func validTextInput(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func hasOnlyMembers(object map[string]any, allowed ...string) bool {
	for key := range object {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
	if int64(len(chunk)) > maximumObservedJSON-int64(o.buffer.Len()) {
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
	prompt, promptPresent, err := usageInteger(usageObject, "prompt_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	total, totalPresent, err := usageInteger(usageObject, "total_tokens")
	if err != nil {
		return protocol.Usage{}, err
	}
	if !promptPresent || !totalPresent {
		usage := unknownUsage()
		usage.ReportedCost = reportedCost
		return usage, nil
	}
	if total != prompt {
		return protocol.Usage{}, upstreamMalformed("upstream Embeddings usage totals are inconsistent")
	}
	return protocol.Usage{
		InputTokens: prompt, OutputTokens: 0, TotalTokens: total,
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
