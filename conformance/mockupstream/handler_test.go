package mockupstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const validRequestBody = `{"model":"client-selected-model"}`

func TestHandlerProtocolJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		objectType string
		usageKey   string
	}{
		{name: "OpenAI Chat", path: "/v1/chat/completions", objectType: "chat.completion", usageKey: "prompt_tokens"},
		{name: "OpenAI Responses", path: "/v1/responses", objectType: "response", usageKey: "input_tokens"},
		{name: "OpenAI Embeddings", path: "/v1/embeddings", objectType: "list", usageKey: "prompt_tokens"},
		{name: "Anthropic Messages", path: "/v1/messages", objectType: "message", usageKey: "input_tokens"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, Config{})
			response := performRequest(t, handler, http.MethodPost, test.path, validRequestBody, "")

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("content type = %q", got)
			}
			if got := response.Header().Get(CostHeader); got != "123456" {
				t.Fatalf("cost header = %q", got)
			}
			payload := decodeObject(t, response.Body.Bytes())
			if got := payload["object"]; got != test.objectType && payload["type"] != test.objectType {
				t.Fatalf("object/type = %v/%v, want %q", got, payload["type"], test.objectType)
			}
			usage := objectField(t, payload, "usage")
			if _, ok := usage[test.usageKey]; !ok {
				t.Fatalf("usage missing %q: %#v", test.usageKey, usage)
			}
			if got := usage["x_latchway_cost_nano_usd"]; got != float64(123_456) {
				t.Fatalf("body cost = %v", got)
			}
		})
	}
}

func TestHandlerProtocolStreaming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		contains []string
	}{
		{
			name:     "OpenAI Chat",
			path:     "/v1/chat/completions",
			contains: []string{`"object":"chat.completion.chunk"`, `"usage"`, "data: [DONE]"},
		},
		{
			name:     "OpenAI Responses",
			path:     "/v1/responses",
			contains: []string{"event: response.created", "event: response.output_text.delta", "event: response.completed", `"usage"`},
		},
		{
			name:     "Anthropic Messages",
			path:     "/v1/messages",
			contains: []string{"event: message_start", "event: content_block_delta", "event: message_stop", `"usage"`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, Config{})
			response := performRequest(t, handler, http.MethodPost, test.path, `{"stream":true}`, "")
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Content-Type"); got != "text/event-stream" {
				t.Fatalf("content type = %q", got)
			}
			for _, expected := range test.contains {
				if !strings.Contains(response.Body.String(), expected) {
					t.Errorf("stream does not contain %q:\n%s", expected, response.Body.String())
				}
			}
		})
	}
}

func TestHandlerFixedUsageAndCost(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Config{
		FixedUsage:       Usage{InputTokens: 3, OutputTokens: 5},
		FixedCostNanoUSD: 999,
	})
	response := performRequest(t, handler, http.MethodPost, "/v1/chat/completions", validRequestBody, "")
	payload := decodeObject(t, response.Body.Bytes())
	usage := objectField(t, payload, "usage")

	if got := response.Header().Get(CostHeader); got != "999" {
		t.Fatalf("cost header = %q", got)
	}
	if usage["prompt_tokens"] != float64(3) || usage["completion_tokens"] != float64(5) || usage["total_tokens"] != float64(8) {
		t.Fatalf("unexpected usage: %#v", usage)
	}
}

func TestHandlerHTTPFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scenario   Scenario
		status     int
		code       string
		retryAfter string
	}{
		{scenario: ScenarioHTTP408, status: http.StatusRequestTimeout, code: "mock_upstream_timeout"},
		{scenario: ScenarioHTTP429, status: http.StatusTooManyRequests, code: "mock_rate_limited", retryAfter: "2"},
		{scenario: ScenarioHTTP500, status: http.StatusInternalServerError, code: "mock_internal_error"},
	}

	for _, test := range tests {
		t.Run(string(test.scenario), func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, Config{AllowScenarioHeader: true})
			response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, test.scenario)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			payload := decodeObject(t, response.Body.Bytes())
			errorPayload := objectField(t, payload, "error")
			if errorPayload["code"] != test.code {
				t.Fatalf("code = %v, want %q", errorPayload["code"], test.code)
			}
			if got := response.Header().Get("Retry-After"); got != test.retryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, test.retryAfter)
			}
		})
	}
}

func TestHandlerMalformedAndMissingUsageScenarios(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Config{AllowScenarioHeader: true})

	t.Run("malformed JSON", func(t *testing.T) {
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, ScenarioMalformedJSON)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d", response.Code)
		}
		if json.Valid(response.Body.Bytes()) {
			t.Fatalf("malformed fixture is valid JSON: %s", response.Body.String())
		}
	})

	t.Run("malformed SSE", func(t *testing.T) {
		response := performRequest(t, handler, http.MethodPost, "/v1/chat/completions", validRequestBody, ScenarioMalformedSSE)
		if got := response.Header().Get("Content-Type"); got != "text/event-stream" {
			t.Fatalf("content type = %q", got)
		}
		data := strings.TrimPrefix(response.Body.String(), "event: broken\ndata: ")
		data = strings.TrimSpace(data)
		if json.Valid([]byte(data)) {
			t.Fatalf("malformed SSE data is valid JSON: %q", data)
		}
	})

	t.Run("missing usage JSON", func(t *testing.T) {
		response := performRequest(t, handler, http.MethodPost, "/v1/messages", validRequestBody, ScenarioMissingUsage)
		payload := decodeObject(t, response.Body.Bytes())
		if _, exists := payload["usage"]; exists {
			t.Fatalf("usage unexpectedly present: %#v", payload["usage"])
		}
	})

	t.Run("missing usage stream", func(t *testing.T) {
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", `{"stream":true}`, ScenarioMissingUsage)
		if strings.Contains(response.Body.String(), `"usage"`) {
			t.Fatalf("usage unexpectedly present:\n%s", response.Body.String())
		}
	})
}

func TestHandlerOversizedEventIsBounded(t *testing.T) {
	t.Parallel()

	const (
		outputLimit = 32 << 10
		eventSize   = 16 << 10
	)
	handler := newTestHandler(t, Config{
		AllowScenarioHeader: true,
		MaxOutputBytes:      outputLimit,
		OversizedEventBytes: eventSize,
	})
	response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, ScenarioOversizedEvent)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	if response.Body.Len() <= eventSize {
		t.Fatalf("event body = %d bytes, want more than %d", response.Body.Len(), eventSize)
	}
	if response.Body.Len() > outputLimit {
		t.Fatalf("event body = %d bytes, limit = %d", response.Body.Len(), outputLimit)
	}
	if !strings.HasPrefix(response.Body.String(), "event: mock.oversized\n") {
		t.Fatalf("unexpected oversized event prefix")
	}
}

func TestHandlerToolCalls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		contains []string
	}{
		{path: "/v1/chat/completions", contains: []string{`"tool_calls"`, "lookup_weather", `"finish_reason":"tool_calls"`}},
		{path: "/v1/responses", contains: []string{`"type":"function_call"`, "lookup_weather", "call_mock_0001"}},
		{path: "/v1/messages", contains: []string{`"type":"tool_use"`, "lookup_weather", "toolu_mock_0001"}},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, Config{AllowScenarioHeader: true})
			response := performRequest(t, handler, http.MethodPost, test.path, validRequestBody, ScenarioToolCall)
			for _, expected := range test.contains {
				if !strings.Contains(response.Body.String(), expected) {
					t.Errorf("tool response does not contain %q: %s", expected, response.Body.String())
				}
			}
		})
	}

	t.Run("streaming", func(t *testing.T) {
		t.Parallel()
		handler := newTestHandler(t, Config{AllowScenarioHeader: true})
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", `{"stream":true}`, ScenarioToolCall)
		for _, expected := range []string{"event: response.function_call_arguments.delta", "lookup_weather", `{\"city\":\"Paris\"}`} {
			if !strings.Contains(response.Body.String(), expected) {
				t.Errorf("tool stream does not contain %q: %s", expected, response.Body.String())
			}
		}
	})
}

func TestHandlerDelayedFirstByte(t *testing.T) {
	t.Parallel()

	const delay = 40 * time.Millisecond
	handler := newTestHandler(t, Config{Scenario: ScenarioDelayedFirstByte, FirstByteDelay: delay})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/responses", strings.NewReader(validRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	elapsed := time.Since(started)
	if elapsed < delay-(10*time.Millisecond) {
		t.Fatalf("first response arrived after %s, configured delay = %s", elapsed, delay)
	}
}

func TestHandlerMidStreamDisconnect(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Config{Scenario: ScenarioMidStreamDisconnect})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(validRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	response, requestErr := server.Client().Do(request)
	if requestErr == nil {
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr == nil {
			t.Fatalf("stream ended cleanly; body = %q", body)
		}
		if !strings.Contains(string(body), "mock.started") {
			t.Fatalf("partial body = %q", body)
		}
	}

	waitForTest(t, time.Second, func() bool { return len(handler.Observations()) == 1 })
	observation := handler.Observations()[0]
	if !observation.ConnectionAborted || !observation.ResponseStarted {
		t.Fatalf("unexpected observation: %+v", observation)
	}
}

func TestHandlerObservesClientCancellation(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Config{
		Scenario:         ScenarioClientCancellation,
		CancellationWait: time.Second,
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/responses", strings.NewReader(validRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := server.Client().Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- requestErr
	}()

	waitForTest(t, time.Second, func() bool { return handler.ActiveRequests() == 1 })
	cancel()
	if err := <-requestDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("client error = %v, want context cancellation", err)
	}
	waitForTest(t, time.Second, func() bool { return len(handler.Observations()) == 1 })
	observation := handler.Observations()[0]
	if !observation.Canceled || observation.ResponseStarted || observation.StatusCode != 0 {
		t.Fatalf("unexpected cancellation observation: %+v", observation)
	}
}

func TestHandlerCancellationScenarioTimesOutSafely(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Config{
		Scenario:         ScenarioClientCancellation,
		CancellationWait: 5 * time.Millisecond,
	})
	response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, "")
	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
	}
	if handler.Observations()[0].Canceled {
		t.Fatalf("timeout recorded as client cancellation")
	}
}

func TestHandlerScenarioSelectionIsExplicit(t *testing.T) {
	t.Parallel()

	t.Run("header disabled", func(t *testing.T) {
		handler := newTestHandler(t, Config{})
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, ScenarioHTTP500)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		handler := newTestHandler(t, Config{AllowScenarioHeader: true})
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, Scenario("unbounded-output"))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
	})

	t.Run("enabled header", func(t *testing.T) {
		handler := newTestHandler(t, Config{AllowScenarioHeader: true})
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", validRequestBody, ScenarioHTTP500)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
		}
		if got := response.Header().Get(ScenarioHeader); got != string(ScenarioHTTP500) {
			t.Fatalf("scenario response header = %q", got)
		}
	})

	t.Run("fixed config", func(t *testing.T) {
		handler := newTestHandler(t, Config{Scenario: ScenarioHTTP408})
		response := performRequest(t, handler, http.MethodPost, "/v1/messages", validRequestBody, "")
		if response.Code != http.StatusRequestTimeout {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
		}
	})
}

func TestHandlerRejectsUnboundedOrInvalidInput(t *testing.T) {
	t.Parallel()

	t.Run("body too large", func(t *testing.T) {
		handler := newTestHandler(t, Config{MaxRequestBodyBytes: 16})
		response := performRequest(t, handler, http.MethodPost, "/v1/responses", strings.Repeat("x", 32), "")
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
		}
		observation := handler.Observations()[0]
		if observation.RequestBytes != 17 {
			t.Fatalf("observed request bytes = %d, want bounded read of 17", observation.RequestBytes)
		}
	})

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{name: "unknown route", method: http.MethodPost, path: "/v1/unknown", body: validRequestBody, status: http.StatusNotFound},
		{name: "method", method: http.MethodGet, path: "/v1/responses", status: http.StatusMethodNotAllowed},
		{name: "invalid JSON", method: http.MethodPost, path: "/v1/responses", body: `{`, status: http.StatusBadRequest},
		{name: "embeddings stream", method: http.MethodPost, path: "/v1/embeddings", body: `{"stream":true}`, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, Config{})
			response := performRequest(t, handler, test.method, test.path, test.body, "")
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestConfigValidationAndSupportedScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "scenario", cfg: Config{Scenario: "unknown"}},
		{name: "request limit", cfg: Config{MaxRequestBodyBytes: maximumRequestBodyBytes + 1}},
		{name: "output limit", cfg: Config{MaxOutputBytes: maximumOutputBytes + 1}},
		{name: "oversized event", cfg: Config{MaxOutputBytes: 8 << 10, OversizedEventBytes: 8 << 10}},
		{name: "delay", cfg: Config{FirstByteDelay: maximumFirstByteDelay + time.Millisecond}},
		{name: "cancellation", cfg: Config{CancellationWait: maximumCancellationWait + time.Millisecond}},
		{name: "usage", cfg: Config{FixedUsage: Usage{InputTokens: -1}}},
		{name: "cost", cfg: Config{FixedCostNanoUSD: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.cfg); err == nil {
				t.Fatal("New() accepted invalid config")
			}
		})
	}

	scenarios := SupportedScenarios()
	if !slices.IsSorted(scenarios) {
		t.Fatalf("scenarios are not sorted: %v", scenarios)
	}
	if !slices.Contains(scenarios, ScenarioClientCancellation) || !slices.Contains(scenarios, ScenarioToolCall) {
		t.Fatalf("required scenarios missing: %v", scenarios)
	}
}

func TestHandlerObservations(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Config{})
	response := performRequest(t, handler, http.MethodPost, "/v1/embeddings", validRequestBody, "")
	observations := handler.Observations()
	if len(observations) != 1 {
		t.Fatalf("observation count = %d", len(observations))
	}
	observation := observations[0]
	if observation.Sequence != 1 || observation.Method != http.MethodPost || observation.Path != "/v1/embeddings" {
		t.Fatalf("unexpected request observation: %+v", observation)
	}
	if observation.StatusCode != response.Code || observation.ResponseBytes != int64(response.Body.Len()) || !observation.ResponseStarted {
		t.Fatalf("unexpected response observation: %+v", observation)
	}
	if observation.RequestBytes != len(validRequestBody) || observation.Canceled || observation.ConnectionAborted {
		t.Fatalf("unexpected bounded observation: %+v", observation)
	}

	handler.ResetObservations()
	if got := handler.Observations(); len(got) != 0 {
		t.Fatalf("observations remain after reset: %+v", got)
	}
}

func newTestHandler(t *testing.T, cfg Config) *Handler {
	t.Helper()
	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return handler
}

func performRequest(t *testing.T, handler http.Handler, method, path, body string, scenario Scenario) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if scenario != "" {
		request.Header.Set(ScenarioHeader, string(scenario))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode JSON: %v; body = %s", err, data)
	}
	return result
}

func objectField(t *testing.T, object map[string]any, field string) map[string]any {
	t.Helper()
	value, ok := object[field].(map[string]any)
	if !ok {
		t.Fatalf("field %q is not an object: %#v", field, object[field])
	}
	return value
}

func waitForTest(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s", timeout)
		}
		runtime.Gosched()
	}
}
