package mockupstream

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type protocol int

const (
	protocolUnknown protocol = iota
	protocolOpenAIChat
	protocolOpenAIResponses
	protocolOpenAIEmbeddings
	protocolAnthropicMessages
)

type requestEnvelope struct {
	Stream bool `json:"stream"`
}

type responseTracker struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseTracker) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseTracker) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(payload)
	w.bytes += int64(written)
	return written, err
}

func (w *responseTracker) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseTracker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *responseTracker) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ServeHTTP handles only deterministic fixture routes. ScenarioHeader is
// rejected unless the handler was constructed with AllowScenarioHeader.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tracker := &responseTracker{ResponseWriter: w}
	observation := h.beginObservation(r.Method, r.URL.EscapedPath())
	defer func() {
		observation.StatusCode = tracker.status
		observation.ResponseBytes = tracker.bytes
		observation.ResponseStarted = tracker.status != 0
		observation.Canceled = r.Context().Err() != nil
		h.finishObservation(observation)
	}()

	selectedProtocol := protocolForPath(r.URL.Path)
	if selectedProtocol == protocolUnknown {
		h.writeProblem(tracker, ScenarioDefault, http.StatusNotFound, "mock_route_not_found", "Mock upstream route not found")
		return
	}
	if r.Method != http.MethodPost {
		tracker.Header().Set("Allow", http.MethodPost)
		h.writeProblem(tracker, ScenarioDefault, http.StatusMethodNotAllowed, "mock_method_not_allowed", "Mock upstream accepts POST requests only")
		return
	}

	scenario, err := h.scenarioForRequest(r)
	if err != nil {
		h.writeProblem(tracker, ScenarioDefault, http.StatusBadRequest, "mock_scenario_invalid", err.Error())
		return
	}
	observation.Scenario = scenario

	body, tooLarge, err := readBoundedBody(r.Body, h.cfg.maxRequestBodyBytes)
	observation.RequestBytes = len(body)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		h.writeProblem(tracker, scenario, http.StatusBadRequest, "mock_request_read_failed", "Could not read the mock upstream request")
		return
	}
	if tooLarge {
		h.writeProblem(tracker, scenario, http.StatusRequestEntityTooLarge, "mock_request_too_large", "Mock upstream request exceeds the configured body limit")
		return
	}

	var request requestEnvelope
	if err := json.Unmarshal(body, &request); err != nil {
		h.writeProblem(tracker, scenario, http.StatusBadRequest, "mock_request_invalid", "Mock upstream request must contain one valid JSON object")
		return
	}

	if scenario == ScenarioClientCancellation {
		h.waitForClientCancellation(tracker, r.Context(), scenario)
		return
	}
	if scenario == ScenarioDelayedFirstByte && !waitForContext(r.Context(), h.cfg.firstByteDelay) {
		return
	}

	switch scenario {
	case ScenarioHTTP408:
		h.writeProblem(tracker, scenario, http.StatusRequestTimeout, "mock_upstream_timeout", "Deterministic mock upstream timeout")
		return
	case ScenarioHTTP429:
		tracker.Header().Set("Retry-After", "2")
		h.writeProblem(tracker, scenario, http.StatusTooManyRequests, "mock_rate_limited", "Deterministic mock upstream rate limit")
		return
	case ScenarioHTTP500:
		h.writeProblem(tracker, scenario, http.StatusInternalServerError, "mock_internal_error", "Deterministic mock upstream failure")
		return
	case ScenarioMalformedJSON:
		h.writeRaw(tracker, scenario, http.StatusOK, "application/json", []byte(`{"id":"broken"`), true)
		return
	case ScenarioMalformedSSE:
		if selectedProtocol == protocolOpenAIEmbeddings {
			h.writeUnsupportedScenario(tracker, scenario, selectedProtocol)
			return
		}
		h.writeRaw(tracker, scenario, http.StatusOK, "text/event-stream", []byte("event: broken\ndata: {\"unterminated\":\n\n"), true)
		return
	case ScenarioOversizedEvent:
		if selectedProtocol == protocolOpenAIEmbeddings {
			h.writeUnsupportedScenario(tracker, scenario, selectedProtocol)
			return
		}
		h.writeOversizedEvent(tracker, scenario)
		return
	case ScenarioMidStreamDisconnect:
		if selectedProtocol == protocolOpenAIEmbeddings {
			h.writeUnsupportedScenario(tracker, scenario, selectedProtocol)
			return
		}
		observation.ConnectionAborted = h.writeMidStreamDisconnect(tracker, scenario)
		return
	case ScenarioToolCall:
		if selectedProtocol == protocolOpenAIEmbeddings {
			h.writeUnsupportedScenario(tracker, scenario, selectedProtocol)
			return
		}
	}

	stream := request.Stream || scenario == ScenarioStream
	if stream && selectedProtocol == protocolOpenAIEmbeddings {
		h.writeUnsupportedScenario(tracker, scenario, selectedProtocol)
		return
	}

	includeUsage := scenario != ScenarioMissingUsage
	toolCall := scenario == ScenarioToolCall
	if stream {
		h.writeProtocolStream(tracker, r.Context(), selectedProtocol, scenario, includeUsage, toolCall)
		return
	}
	h.writeProtocolJSON(tracker, selectedProtocol, scenario, includeUsage, toolCall)
}

func protocolForPath(requestPath string) protocol {
	switch requestPath {
	case "/v1/chat/completions":
		return protocolOpenAIChat
	case "/v1/responses":
		return protocolOpenAIResponses
	case "/v1/embeddings":
		return protocolOpenAIEmbeddings
	case "/v1/messages":
		return protocolAnthropicMessages
	default:
		return protocolUnknown
	}
}

func (h *Handler) scenarioForRequest(r *http.Request) (Scenario, error) {
	values := r.Header.Values(ScenarioHeader)
	if len(values) == 0 {
		return h.cfg.scenario, nil
	}
	if !h.cfg.allowScenarioHeader {
		return "", errors.New("scenario header overrides are disabled for this handler")
	}
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return "", errors.New("scenario header must contain exactly one value")
	}
	scenario := Scenario(strings.TrimSpace(values[0]))
	if !isSupportedScenario(scenario) {
		return "", fmt.Errorf("unsupported mock upstream scenario %q", scenario)
	}
	return scenario, nil
}

func readBoundedBody(reader io.Reader, maximum int64) ([]byte, bool, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return payload, false, err
	}
	return payload, int64(len(payload)) > maximum, nil
}

func waitForContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (h *Handler) waitForClientCancellation(w *responseTracker, ctx context.Context, scenario Scenario) {
	timer := time.NewTimer(h.cfg.cancellationWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		h.writeProblem(w, scenario, http.StatusRequestTimeout, "mock_cancellation_not_observed", "Client did not cancel within the configured observation window")
	}
}

func (h *Handler) writeUnsupportedScenario(w *responseTracker, scenario Scenario, selectedProtocol protocol) {
	h.writeProblem(
		w,
		scenario,
		http.StatusBadRequest,
		"mock_scenario_unsupported",
		fmt.Sprintf("Scenario %q is not supported for %s", scenario, selectedProtocol),
	)
}

func (h *Handler) writeProblem(w *responseTracker, scenario Scenario, status int, code, message string) {
	payload := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"type":    "mock_upstream_error",
		},
	}
	h.writeJSON(w, scenario, status, payload, false)
}

func (h *Handler) writeJSON(w *responseTracker, scenario Scenario, status int, payload any, includeCost bool) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		h.writeRaw(w, scenario, http.StatusInternalServerError, "application/json", []byte(`{"error":{"code":"mock_encoding_failed","message":"Could not encode deterministic fixture","type":"mock_upstream_error"}}`), false)
		return
	}
	encoded = append(encoded, '\n')
	h.writeRaw(w, scenario, status, "application/json", encoded, includeCost)
}

func (h *Handler) writeRaw(w *responseTracker, scenario Scenario, status int, contentType string, payload []byte, includeCost bool) {
	if len(payload) > h.cfg.maxOutputBytes {
		fallback := []byte(`{"error":{"code":"mock_output_limit_exceeded","message":"Fixture exceeds configured output limit","type":"mock_upstream_error"}}`)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(ScenarioHeader, string(scenario))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(fallback)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(ScenarioHeader, string(scenario))
	if includeCost {
		w.Header().Set(CostHeader, strconv.FormatInt(h.cfg.fixedCostNanoUSD, 10))
	}
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func (h *Handler) writeOversizedEvent(w *responseTracker, scenario Scenario) {
	payload := strings.Repeat("x", h.cfg.oversizedEventBytes)
	event := []byte("event: mock.oversized\ndata: {\"type\":\"mock.oversized\",\"payload\":\"" + payload + "\"}\n\n")
	h.writeRaw(w, scenario, http.StatusOK, "text/event-stream", event, true)
}

func (h *Handler) writeMidStreamDisconnect(w *responseTracker, scenario Scenario) bool {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(ScenarioHeader, string(scenario))
	w.Header().Set(CostHeader, strconv.FormatInt(h.cfg.fixedCostNanoUSD, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("event: mock.started\ndata: {\"type\":\"mock.started\"}\n\n"))
	w.Flush()

	connection, _, err := w.Hijack()
	if err != nil {
		_, _ = w.Write([]byte("event: mock.partial\ndata: {\"type\":\"mock.partial\""))
		return false
	}
	_ = connection.Close()
	return true
}

func (p protocol) String() string {
	switch p {
	case protocolOpenAIChat:
		return "OpenAI Chat Completions"
	case protocolOpenAIResponses:
		return "OpenAI Responses"
	case protocolOpenAIEmbeddings:
		return "OpenAI Embeddings"
	case protocolAnthropicMessages:
		return "Anthropic Messages"
	default:
		return "unknown protocol"
	}
}
