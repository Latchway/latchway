package mockupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

const (
	fixedCreatedAt = int64(1_787_820_000)
	fixedModel     = "latchway-mock-model"
	fixedText      = "Deterministic mock response."
)

func (h *Handler) writeProtocolJSON(w *responseTracker, selectedProtocol protocol, scenario Scenario, includeUsage, toolCall bool) {
	var payload map[string]any
	switch selectedProtocol {
	case protocolOpenAIChat:
		payload = h.openAIChatResponse(includeUsage, toolCall)
	case protocolOpenAIResponses:
		payload = h.openAIResponsesResponse(includeUsage, toolCall)
	case protocolOpenAIEmbeddings:
		payload = h.openAIEmbeddingsResponse(includeUsage)
	case protocolAnthropicMessages:
		payload = h.anthropicMessagesResponse(includeUsage, toolCall)
	default:
		h.writeProblem(w, scenario, http.StatusNotFound, "mock_route_not_found", "Mock upstream route not found")
		return
	}
	h.writeJSON(w, scenario, http.StatusOK, payload, true)
}

func (h *Handler) openAIChatResponse(includeUsage, toolCall bool) map[string]any {
	message := map[string]any{
		"content": fixedText,
		"role":    "assistant",
	}
	finishReason := "stop"
	if toolCall {
		delete(message, "content")
		message["tool_calls"] = []any{
			map[string]any{
				"function": map[string]any{
					"arguments": `{"city":"Paris"}`,
					"name":      "lookup_weather",
				},
				"id":   "call_mock_0001",
				"type": "function",
			},
		}
		finishReason = "tool_calls"
	}
	payload := map[string]any{
		"choices": []any{
			map[string]any{
				"finish_reason": finishReason,
				"index":         0,
				"message":       message,
			},
		},
		"created": fixedCreatedAt,
		"id":      "chatcmpl_mock_0001",
		"model":   fixedModel,
		"object":  "chat.completion",
	}
	if includeUsage {
		payload["usage"] = h.openAITokenUsage()
	}
	return payload
}

func (h *Handler) openAIResponsesResponse(includeUsage, toolCall bool) map[string]any {
	output := []any{openAIResponsesTextItem()}
	if toolCall {
		output = []any{openAIResponsesToolItem("completed", `{"city":"Paris"}`)}
	}
	payload := map[string]any{
		"created_at": fixedCreatedAt,
		"error":      nil,
		"id":         "resp_mock_0001",
		"model":      fixedModel,
		"object":     "response",
		"output":     output,
		"status":     "completed",
	}
	if includeUsage {
		payload["usage"] = h.responsesTokenUsage()
	}
	return payload
}

func openAIResponsesTextItem() map[string]any {
	return map[string]any{
		"content": []any{
			map[string]any{
				"annotations": []any{},
				"text":        fixedText,
				"type":        "output_text",
			},
		},
		"id":     "msg_mock_0001",
		"role":   "assistant",
		"status": "completed",
		"type":   "message",
	}
}

func openAIResponsesToolItem(status, arguments string) map[string]any {
	return map[string]any{
		"arguments": arguments,
		"call_id":   "call_mock_0001",
		"id":        "fc_mock_0001",
		"name":      "lookup_weather",
		"status":    status,
		"type":      "function_call",
	}
}

func (h *Handler) openAIEmbeddingsResponse(includeUsage bool) map[string]any {
	payload := map[string]any{
		"data": []any{
			map[string]any{
				"embedding": []float64{0.125, -0.25, 0.5},
				"index":     0,
				"object":    "embedding",
			},
		},
		"model":  fixedModel,
		"object": "list",
	}
	if includeUsage {
		payload["usage"] = map[string]any{
			"prompt_tokens":            h.cfg.fixedUsage.InputTokens,
			"total_tokens":             h.cfg.fixedUsage.InputTokens,
			"x_latchway_cost_nano_usd": h.cfg.fixedCostNanoUSD,
		}
	}
	return payload
}

func (h *Handler) anthropicMessagesResponse(includeUsage, toolCall bool) map[string]any {
	content := []any{
		map[string]any{
			"text": fixedText,
			"type": "text",
		},
	}
	stopReason := "end_turn"
	if toolCall {
		content = []any{
			map[string]any{
				"id":    "toolu_mock_0001",
				"input": map[string]any{"city": "Paris"},
				"name":  "lookup_weather",
				"type":  "tool_use",
			},
		}
		stopReason = "tool_use"
	}
	payload := map[string]any{
		"content":     content,
		"id":          "msg_mock_0001",
		"model":       fixedModel,
		"role":        "assistant",
		"stop_reason": stopReason,
		"type":        "message",
	}
	if includeUsage {
		payload["usage"] = h.anthropicTokenUsage()
	}
	return payload
}

func (h *Handler) openAITokenUsage() map[string]any {
	return map[string]any{
		"completion_tokens":        h.cfg.fixedUsage.OutputTokens,
		"prompt_tokens":            h.cfg.fixedUsage.InputTokens,
		"total_tokens":             h.cfg.fixedUsage.TotalTokens(),
		"x_latchway_cost_nano_usd": h.cfg.fixedCostNanoUSD,
	}
}

func (h *Handler) responsesTokenUsage() map[string]any {
	return map[string]any{
		"input_tokens":             h.cfg.fixedUsage.InputTokens,
		"output_tokens":            h.cfg.fixedUsage.OutputTokens,
		"total_tokens":             h.cfg.fixedUsage.TotalTokens(),
		"x_latchway_cost_nano_usd": h.cfg.fixedCostNanoUSD,
	}
}

func (h *Handler) anthropicTokenUsage() map[string]any {
	return map[string]any{
		"input_tokens":             h.cfg.fixedUsage.InputTokens,
		"output_tokens":            h.cfg.fixedUsage.OutputTokens,
		"x_latchway_cost_nano_usd": h.cfg.fixedCostNanoUSD,
	}
}

type sseEvent struct {
	name string
	data any
	raw  string
}

func (h *Handler) writeProtocolStream(w *responseTracker, ctx context.Context, selectedProtocol protocol, scenario Scenario, includeUsage, toolCall bool) {
	events, err := h.protocolEvents(selectedProtocol, includeUsage, toolCall)
	if err != nil {
		h.writeProblem(w, scenario, http.StatusBadRequest, "mock_scenario_unsupported", err.Error())
		return
	}
	chunks, total, err := encodeSSE(events)
	if err != nil {
		h.writeProblem(w, scenario, http.StatusInternalServerError, "mock_encoding_failed", "Could not encode deterministic SSE fixture")
		return
	}
	if total > h.cfg.maxOutputBytes {
		h.writeProblem(w, scenario, http.StatusInternalServerError, "mock_output_limit_exceeded", "Fixture exceeds configured output limit")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set(ScenarioHeader, string(scenario))
	w.Header().Set(CostHeader, formatCost(h.cfg.fixedCostNanoUSD))
	w.WriteHeader(http.StatusOK)
	for _, chunk := range chunks {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := w.Write(chunk); err != nil {
			return
		}
		w.Flush()
	}
}

func (h *Handler) protocolEvents(selectedProtocol protocol, includeUsage, toolCall bool) ([]sseEvent, error) {
	switch selectedProtocol {
	case protocolOpenAIChat:
		return h.openAIChatEvents(includeUsage, toolCall), nil
	case protocolOpenAIResponses:
		return h.openAIResponsesEvents(includeUsage, toolCall), nil
	case protocolAnthropicMessages:
		return h.anthropicMessagesEvents(includeUsage, toolCall), nil
	default:
		return nil, errors.New("streaming is not supported for this protocol")
	}
}

func (h *Handler) openAIChatEvents(includeUsage, toolCall bool) []sseEvent {
	base := func(delta map[string]any, finishReason any) map[string]any {
		return map[string]any{
			"choices": []any{
				map[string]any{
					"delta":         delta,
					"finish_reason": finishReason,
					"index":         0,
				},
			},
			"created": fixedCreatedAt,
			"id":      "chatcmpl_mock_0001",
			"model":   fixedModel,
			"object":  "chat.completion.chunk",
		}
	}
	events := []sseEvent{{data: base(map[string]any{"role": "assistant"}, nil)}}
	finishReason := "stop"
	if toolCall {
		events = append(events, sseEvent{data: base(map[string]any{
			"tool_calls": []any{
				map[string]any{
					"function": map[string]any{
						"arguments": `{"city":"Paris"}`,
						"name":      "lookup_weather",
					},
					"id":    "call_mock_0001",
					"index": 0,
					"type":  "function",
				},
			},
		}, nil)})
		finishReason = "tool_calls"
	} else {
		events = append(events,
			sseEvent{data: base(map[string]any{"content": "Deterministic "}, nil)},
			sseEvent{data: base(map[string]any{"content": "mock response."}, nil)},
		)
	}
	final := base(map[string]any{}, finishReason)
	if includeUsage {
		final["usage"] = h.openAITokenUsage()
	}
	events = append(events, sseEvent{data: final}, sseEvent{raw: "[DONE]"})
	return events
}

func (h *Handler) openAIResponsesEvents(includeUsage, toolCall bool) []sseEvent {
	response := h.openAIResponsesResponse(false, toolCall)
	response["output"] = []any{}
	response["status"] = "in_progress"
	events := []sseEvent{
		{name: "response.created", data: map[string]any{"response": response, "type": "response.created"}},
	}
	if toolCall {
		item := openAIResponsesToolItem("in_progress", "")
		events = append(events,
			sseEvent{name: "response.output_item.added", data: map[string]any{"item": item, "output_index": 0, "type": "response.output_item.added"}},
			sseEvent{name: "response.function_call_arguments.delta", data: map[string]any{"delta": `{"city":"Paris"}`, "item_id": "fc_mock_0001", "output_index": 0, "type": "response.function_call_arguments.delta"}},
			sseEvent{name: "response.function_call_arguments.done", data: map[string]any{"arguments": `{"city":"Paris"}`, "item_id": "fc_mock_0001", "output_index": 0, "type": "response.function_call_arguments.done"}},
			sseEvent{name: "response.output_item.done", data: map[string]any{"item": openAIResponsesToolItem("completed", `{"city":"Paris"}`), "output_index": 0, "type": "response.output_item.done"}},
		)
	} else {
		contentPart := map[string]any{"annotations": []any{}, "text": "", "type": "output_text"}
		events = append(events,
			sseEvent{name: "response.output_item.added", data: map[string]any{"item": map[string]any{"id": "msg_mock_0001", "role": "assistant", "status": "in_progress", "type": "message"}, "output_index": 0, "type": "response.output_item.added"}},
			sseEvent{name: "response.content_part.added", data: map[string]any{"content_index": 0, "item_id": "msg_mock_0001", "output_index": 0, "part": contentPart, "type": "response.content_part.added"}},
			sseEvent{name: "response.output_text.delta", data: map[string]any{"content_index": 0, "delta": fixedText, "item_id": "msg_mock_0001", "output_index": 0, "type": "response.output_text.delta"}},
			sseEvent{name: "response.output_text.done", data: map[string]any{"content_index": 0, "item_id": "msg_mock_0001", "output_index": 0, "text": fixedText, "type": "response.output_text.done"}},
			sseEvent{name: "response.content_part.done", data: map[string]any{"content_index": 0, "item_id": "msg_mock_0001", "output_index": 0, "part": map[string]any{"annotations": []any{}, "text": fixedText, "type": "output_text"}, "type": "response.content_part.done"}},
			sseEvent{name: "response.output_item.done", data: map[string]any{"item": openAIResponsesTextItem(), "output_index": 0, "type": "response.output_item.done"}},
		)
	}
	completed := h.openAIResponsesResponse(includeUsage, toolCall)
	events = append(events, sseEvent{name: "response.completed", data: map[string]any{"response": completed, "type": "response.completed"}})
	return events
}

func (h *Handler) anthropicMessagesEvents(includeUsage, toolCall bool) []sseEvent {
	message := h.anthropicMessagesResponse(false, toolCall)
	delete(message, "content")
	message["content"] = []any{}
	message["stop_reason"] = nil
	if includeUsage {
		message["usage"] = map[string]any{
			"input_tokens":  h.cfg.fixedUsage.InputTokens,
			"output_tokens": 0,
		}
	}
	events := []sseEvent{
		{name: "message_start", data: map[string]any{"message": message, "type": "message_start"}},
	}
	stopReason := "end_turn"
	if toolCall {
		events = append(events,
			sseEvent{name: "content_block_start", data: map[string]any{"content_block": map[string]any{"id": "toolu_mock_0001", "input": map[string]any{}, "name": "lookup_weather", "type": "tool_use"}, "index": 0, "type": "content_block_start"}},
			sseEvent{name: "content_block_delta", data: map[string]any{"delta": map[string]any{"partial_json": `{"city":"Paris"}`, "type": "input_json_delta"}, "index": 0, "type": "content_block_delta"}},
		)
		stopReason = "tool_use"
	} else {
		events = append(events,
			sseEvent{name: "content_block_start", data: map[string]any{"content_block": map[string]any{"text": "", "type": "text"}, "index": 0, "type": "content_block_start"}},
			sseEvent{name: "content_block_delta", data: map[string]any{"delta": map[string]any{"text": fixedText, "type": "text_delta"}, "index": 0, "type": "content_block_delta"}},
		)
	}
	events = append(events, sseEvent{name: "content_block_stop", data: map[string]any{"index": 0, "type": "content_block_stop"}})
	delta := map[string]any{"stop_reason": stopReason}
	messageDelta := map[string]any{"delta": delta, "type": "message_delta"}
	if includeUsage {
		messageDelta["usage"] = map[string]any{
			"output_tokens":            h.cfg.fixedUsage.OutputTokens,
			"x_latchway_cost_nano_usd": h.cfg.fixedCostNanoUSD,
		}
	}
	events = append(events,
		sseEvent{name: "message_delta", data: messageDelta},
		sseEvent{name: "message_stop", data: map[string]any{"type": "message_stop"}},
	)
	return events
}

func encodeSSE(events []sseEvent) ([][]byte, int, error) {
	chunks := make([][]byte, 0, len(events))
	total := 0
	for _, event := range events {
		var data []byte
		if event.raw != "" {
			data = []byte(event.raw)
		} else {
			encoded, err := json.Marshal(event.data)
			if err != nil {
				return nil, 0, err
			}
			data = encoded
		}
		var chunk bytes.Buffer
		if event.name != "" {
			chunk.WriteString("event: ")
			chunk.WriteString(event.name)
			chunk.WriteByte('\n')
		}
		chunk.WriteString("data: ")
		chunk.Write(data)
		chunk.WriteString("\n\n")
		chunks = append(chunks, chunk.Bytes())
		total += chunk.Len()
	}
	return chunks, total, nil
}

func formatCost(cost int64) string {
	return strconv.FormatInt(cost, 10)
}
