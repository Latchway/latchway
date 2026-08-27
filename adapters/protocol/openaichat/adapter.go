// Package openaichat implements the OpenAI Chat Completions protocol without
// coupling it to an upstream hostname or credential.
package openaichat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

const (
	ID                      = "openai_chat"
	defaultMaximumBody      = int64(1 << 20)
	maximumObservedResponse = int64(4 << 20)
	maximumSSEEvent         = 1 << 20
)

// Adapter inspects and rewrites Chat Completions requests.
type Adapter struct {
	MaximumBodyBytes int64
}

func (a Adapter) ID() string { return ID }

func (a Adapter) Match(request *http.Request) bool {
	return request != nil && request.Method == http.MethodPost && request.URL != nil && request.URL.Path == "/v1/chat/completions"
}

func (a Adapter) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{
		Streaming:           true,
		ModelRewrite:        true,
		OutputTokenClamp:    true,
		ProviderUsage:       true,
		ExactInputPreflight: false,
	}
}

func (a Adapter) InspectRequest(_ context.Context, request *http.Request) (protocol.RequestMetadata, error) {
	object, raw, err := a.readRequest(request)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	model, _ := object["model"].(string)
	streaming, err := optionalBool(object, "stream")
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	if messages, ok := object["messages"].([]any); !ok || len(messages) == 0 {
		return protocol.RequestMetadata{}, malformed("messages must be a non-empty array")
	}
	requested, err := requestedOutputLimit(object)
	if err != nil {
		return protocol.RequestMetadata{}, err
	}
	return protocol.RequestMetadata{
		ClientModel:          model,
		Streaming:            streaming,
		RequestedOutputLimit: requested,
		EstimatedInputTokens: (int64(len(raw)) + 2) / 3,
		RequestBytes:         int64(len(raw)),
	}, nil
}

func (a Adapter) ApplyFeature(_ context.Context, request *http.Request, decision protocol.FeatureDecision) error {
	if decision.PhysicalModel == "" {
		return errors.New("physical model is required")
	}
	if decision.DefaultOutputTokens <= 0 || decision.MaximumOutputTokens <= 0 || decision.DefaultOutputTokens > decision.MaximumOutputTokens {
		return errors.New("valid output-token bounds are required")
	}
	object, _, err := a.readRequest(request)
	if err != nil {
		return err
	}
	requested, err := requestedOutputLimit(object)
	if err != nil {
		return err
	}
	effective := requested
	if effective == 0 {
		effective = decision.DefaultOutputTokens
	}
	if effective > decision.MaximumOutputTokens {
		effective = decision.MaximumOutputTokens
	}
	object["model"] = decision.PhysicalModel
	if _, usedLegacy := object["max_tokens"]; usedLegacy {
		object["max_tokens"] = effective
	} else {
		object["max_completion_tokens"] = effective
	}
	if streaming, _ := optionalBool(object, "stream"); streaming {
		streamOptions, present := object["stream_options"]
		if !present {
			streamOptions = map[string]any{}
		}
		optionsObject, ok := streamOptions.(map[string]any)
		if !ok {
			return malformed("stream_options must be an object")
		}
		optionsObject["include_usage"] = true
		object["stream_options"] = optionsObject
	}
	rewritten, err := json.Marshal(object)
	if err != nil {
		return fmt.Errorf("encode rewritten chat request: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(rewritten))
	request.ContentLength = int64(len(rewritten))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(rewritten)), nil
	}
	request.Header.Set("Content-Type", "application/json")
	return nil
}

func (a Adapter) ObserveResponse(_ context.Context, response *http.Response) (protocol.ResponseObserver, error) {
	if response == nil {
		return nil, errors.New("response is required")
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if strings.EqualFold(mediaType, "text/event-stream") {
		return &sseObserver{}, nil
	}
	return &jsonObserver{}, nil
}

func (a Adapter) readRequest(request *http.Request) (map[string]any, []byte, error) {
	if request == nil || request.Body == nil {
		return nil, nil, malformed("JSON request body is required")
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return nil, nil, malformed("content type must be application/json")
	}
	limit := a.MaximumBodyBytes
	if limit <= 0 {
		limit = defaultMaximumBody
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	closeErr := request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, malformed("request body could not be read")
	}
	if closeErr != nil {
		return nil, nil, malformed("request body could not be closed")
	}
	if int64(len(raw)) > limit {
		return nil, nil, &protocol.Error{Code: "request_too_large", Detail: "chat request exceeds configured limit"}
	}
	value, err := jsonsafe.Decode(raw)
	if err != nil {
		return nil, nil, malformed("request body must be strict JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil, malformed("request body must be a JSON object")
	}
	return object, raw, nil
}

func requestedOutputLimit(object map[string]any) (int64, error) {
	legacy, hasLegacy, err := optionalPositiveInteger(object, "max_tokens")
	if err != nil {
		return 0, err
	}
	completion, hasCompletion, err := optionalPositiveInteger(object, "max_completion_tokens")
	if err != nil {
		return 0, err
	}
	if hasLegacy && hasCompletion {
		return 0, malformed("max_tokens and max_completion_tokens cannot both be set")
	}
	if hasCompletion {
		return completion, nil
	}
	return legacy, nil
}

func optionalPositiveInteger(object map[string]any, key string) (int64, bool, error) {
	value, present := object[key]
	if !present {
		return 0, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false, malformed(key + " must be a positive integer")
	}
	parsed, err := number.Int64()
	if err != nil || parsed <= 0 {
		return 0, false, malformed(key + " must be a positive integer")
	}
	return parsed, true, nil
}

func optionalBool(object map[string]any, key string) (bool, error) {
	value, present := object[key]
	if !present {
		return false, nil
	}
	parsed, ok := value.(bool)
	if !ok {
		return false, malformed(key + " must be a boolean")
	}
	return parsed, nil
}

func malformed(detail string) error {
	return &protocol.Error{Code: "upstream_protocol_error", Detail: detail}
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
		return protocol.Usage{}, malformed("upstream returned malformed JSON")
	}
	return usageFromValue(value)
}

type sseObserver struct {
	pending bytes.Buffer
	usage   protocol.Usage
	found   bool
}

func (o *sseObserver) Observe(chunk []byte) error {
	if o.pending.Len()+len(chunk) > maximumSSEEvent {
		return malformed("upstream SSE event exceeds limit")
	}
	_, _ = o.pending.Write(chunk)
	for {
		data := o.pending.Bytes()
		index, separatorLength := nextEventBoundary(data)
		if index < 0 {
			return nil
		}
		event := append([]byte(nil), data[:index]...)
		rest := append([]byte(nil), data[index+separatorLength:]...)
		o.pending.Reset()
		_, _ = o.pending.Write(rest)
		if err := o.observeEvent(event); err != nil {
			return err
		}
	}
}

func (o *sseObserver) Finalize() (protocol.Usage, error) {
	if o.pending.Len() > 0 {
		if err := o.observeEvent(o.pending.Bytes()); err != nil {
			return protocol.Usage{}, err
		}
	}
	if !o.found {
		return unknownUsage(), nil
	}
	return o.usage, nil
}

func (o *sseObserver) observeEvent(event []byte) error {
	lines := bytes.Split(bytes.ReplaceAll(event, []byte("\r\n"), []byte("\n")), []byte("\n"))
	dataLines := make([][]byte, 0, 1)
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("data:")) {
			value := bytes.TrimPrefix(line, []byte("data:"))
			value = bytes.TrimPrefix(value, []byte(" "))
			dataLines = append(dataLines, value)
		}
	}
	if len(dataLines) == 0 {
		return nil
	}
	data := bytes.Join(dataLines, []byte("\n"))
	if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
		return nil
	}
	value, err := jsonsafe.Decode(data)
	if err != nil {
		return malformed("upstream returned malformed SSE data")
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

func usageFromValue(value any) (protocol.Usage, error) {
	root, ok := value.(map[string]any)
	if !ok {
		return protocol.Usage{}, malformed("upstream JSON must be an object")
	}
	usageValue, present := root["usage"]
	if !present || usageValue == nil {
		return unknownUsage(), nil
	}
	usageObject, ok := usageValue.(map[string]any)
	if !ok {
		return protocol.Usage{}, malformed("upstream usage must be an object")
	}
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
		return unknownUsage(), nil
	}
	if !totalPresent {
		total = input + output
	}
	if total < input || total < output {
		return protocol.Usage{}, malformed("upstream usage totals are inconsistent")
	}
	return protocol.Usage{InputTokens: input, OutputTokens: output, TotalTokens: total, Known: true, Provenance: "provider_reported"}, nil
}

func usageInteger(object map[string]any, keys ...string) (int64, bool, error) {
	for _, key := range keys {
		value, present := object[key]
		if !present {
			continue
		}
		number, ok := value.(json.Number)
		if !ok {
			return 0, false, malformed("upstream usage values must be non-negative integers")
		}
		parsed, err := number.Int64()
		if err != nil || parsed < 0 {
			return 0, false, malformed("upstream usage values must be non-negative integers")
		}
		return parsed, true, nil
	}
	return 0, false, nil
}

func unknownUsage() protocol.Usage {
	return protocol.Usage{Known: false, Provenance: "unknown"}
}

func nextEventBoundary(data []byte) (int, int) {
	lf := bytes.Index(data, []byte("\n\n"))
	crlf := bytes.Index(data, []byte("\r\n\r\n"))
	switch {
	case lf < 0:
		if crlf < 0 {
			return -1, 0
		}
		return crlf, 4
	case crlf < 0 || lf < crlf:
		return lf, 2
	default:
		return crlf, 4
	}
}
