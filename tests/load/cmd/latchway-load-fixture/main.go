// latchway-load-fixture is a deterministic localhost-only upstream for load
// and failure evidence. It is deliberately not part of the production image.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const maximumBodyBytes = 1 << 20

type state struct {
	mode                  atomic.Value
	delayNanos            atomic.Int64
	holdNanos             atomic.Int64
	active                atomic.Int64
	total                 atomic.Int64
	canceled              atomic.Int64
	disconnected          atomic.Int64
	waitingBeforeResponse atomic.Int64
	waitingAfterFirstByte atomic.Int64
	controlToken          string
}

type requestDocument struct {
	Stream bool `json:"stream"`
}

func main() {
	var listen string
	var streamHold, firstByteDelay time.Duration
	var controlTokenEnv string
	var acknowledgeIsolatedContainerNetwork bool
	flag.StringVar(&listen, "listen", "127.0.0.1:19090", "localhost listen address")
	flag.DurationVar(&streamHold, "stream-hold", 90*time.Second, "how long valid SSE responses remain open")
	flag.DurationVar(&firstByteDelay, "first-byte-delay", 0, "healthy-response first-byte delay")
	flag.StringVar(&controlTokenEnv, "control-token-env", "LATCHWAY_LOAD_FIXTURE_CONTROL_TOKEN", "optional control-token environment variable")
	flag.BoolVar(&acknowledgeIsolatedContainerNetwork, "acknowledge-isolated-container-network", false, "allow one exact non-loopback IP on an operator-created internal-only container network")
	flag.Parse()
	if streamHold < time.Second || streamHold > 10*time.Minute || firstByteDelay < 0 || firstByteDelay > time.Minute {
		fmt.Fprintln(os.Stderr, "stream hold and first-byte delay are outside bounded test ranges")
		os.Exit(2)
	}
	fixture := &state{controlToken: os.Getenv(controlTokenEnv)}
	if fixture.controlToken != "" && (len(fixture.controlToken) < 32 || len(fixture.controlToken) > 256 || strings.ContainsAny(fixture.controlToken, "\r\n\x00")) {
		fmt.Fprintln(os.Stderr, "fixture control token must be 32-256 safe characters when enabled")
		os.Exit(2)
	}
	if err := validateListenAddress(listen, acknowledgeIsolatedContainerNetwork, fixture.controlToken != ""); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fixture.mode.Store("healthy")
	fixture.holdNanos.Store(int64(streamHold))
	fixture.delayNanos.Store(int64(firstByteDelay))
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", fixture.health)
	mux.HandleFunc("/__latchway_test/control", fixture.control)
	mux.HandleFunc("/__latchway_test/observations", fixture.observations)
	mux.HandleFunc("/v1/chat/completions", fixture.upstream)
	server := &http.Server{
		Addr: listen, Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func validateListenAddress(listen string, acknowledgeIsolatedContainerNetwork, hasControlToken bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("fixture listen address must contain one explicit host and port")
	}
	if host == "localhost" {
		return nil
	}
	address := net.ParseIP(host)
	if address == nil {
		return errors.New("fixture listen host must be localhost or one exact IP address")
	}
	if address.IsLoopback() {
		return nil
	}
	if !address.IsPrivate() || !acknowledgeIsolatedContainerNetwork || !hasControlToken {
		return errors.New("a non-loopback fixture requires -acknowledge-isolated-container-network and an authenticated control token")
	}
	if address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return errors.New("fixture cannot bind a wildcard, multicast, or link-local address")
	}
	return nil
}

func (fixture *state) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"status":"ok","fixture":true}`+"\n")
}

func (fixture *state) upstream(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fixture.active.Add(1)
	fixture.total.Add(1)
	defer fixture.active.Add(-1)
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumBodyBytes+1))
	if err != nil || len(body) > maximumBodyBytes {
		http.Error(w, "invalid bounded request", http.StatusBadRequest)
		return
	}
	var document requestDocument
	if err := json.Unmarshal(body, &document); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	mode := fixture.mode.Load().(string)
	if mode == "hold-before-response" || (mode == "drain-hold" && !document.Stream) {
		fixture.waitingBeforeResponse.Add(1)
		defer fixture.waitingBeforeResponse.Add(-1)
		if !fixture.waitWhileMode(request.Context(), mode) {
			fixture.canceled.Add(1)
			return
		}
		mode = fixture.mode.Load().(string)
	}
	if delay := time.Duration(fixture.delayNanos.Load()); delay > 0 || mode == "delayed-first-byte" {
		if mode == "delayed-first-byte" && delay == 0 {
			delay = time.Second
		}
		select {
		case <-request.Context().Done():
			fixture.canceled.Add(1)
			return
		case <-time.After(delay):
		}
	}
	switch mode {
	case "fail-500":
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"type": "fixture_error", "code": "fixture_failure", "message": "deterministic fixture failure"}})
		return
	case "disconnect-before-response":
		fixture.disconnect(w)
		return
	}
	if document.Stream {
		fixture.stream(w, request, mode)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "chatcmpl_load_fixture", "object": "chat.completion", "model": "fixture-model",
		"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": "fixture"}}},
		"usage":   map[string]any{"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
	})
}

func (fixture *state) stream(w http.ResponseWriter, request *http.Request, mode string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl_load_fixture\",\"object\":\"chat.completion.chunk\",\"model\":\"fixture-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n")
	flusher.Flush()
	if mode == "drain-hold" {
		fixture.waitingAfterFirstByte.Add(1)
		if !fixture.waitWhileMode(request.Context(), mode) {
			fixture.waitingAfterFirstByte.Add(-1)
			fixture.canceled.Add(1)
			return
		}
		fixture.waitingAfterFirstByte.Add(-1)
		fixture.finishStream(w, flusher)
		return
	}
	if mode == "disconnect-during-stream" {
		fixture.disconnect(w)
		return
	}
	select {
	case <-request.Context().Done():
		fixture.canceled.Add(1)
		return
	case <-time.After(time.Duration(fixture.holdNanos.Load())):
	}
	fixture.finishStream(w, flusher)
}

func (*state) finishStream(w http.ResponseWriter, flusher http.Flusher) {
	_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl_load_fixture\",\"object\":\"chat.completion.chunk\",\"model\":\"fixture-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\ndata: [DONE]\n\n")
	flusher.Flush()
}

func (fixture *state) waitWhileMode(ctx context.Context, mode string) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for fixture.mode.Load().(string) == mode {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
	return true
}

func (fixture *state) disconnect(w http.ResponseWriter) {
	if hijacker, ok := w.(http.Hijacker); ok {
		connection, _, err := hijacker.Hijack()
		if err == nil {
			fixture.disconnected.Add(1)
			_ = connection.Close()
			return
		}
	}
}

func (fixture *state) control(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if fixture.controlToken == "" || !constantToken(request.Header.Get("Authorization"), fixture.controlToken) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var input struct {
		Mode                 string `json:"mode"`
		FirstByteDelayMillis int64  `json:"first_byte_delay_ms"`
		StreamHoldMillis     int64  `json:"stream_hold_ms"`
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 4097))
	if err != nil || len(body) > 4096 {
		http.Error(w, "invalid control document", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !supportedMode(input.Mode) || input.FirstByteDelayMillis < 0 || input.FirstByteDelayMillis > 60_000 || input.StreamHoldMillis < 1_000 || input.StreamHoldMillis > 600_000 {
		http.Error(w, "invalid control document", http.StatusBadRequest)
		return
	}
	input.Mode = strings.TrimSpace(input.Mode)
	fixture.delayNanos.Store(int64(time.Duration(input.FirstByteDelayMillis) * time.Millisecond))
	fixture.holdNanos.Store(int64(time.Duration(input.StreamHoldMillis) * time.Millisecond))
	fixture.mode.Store(input.Mode)
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "mode": input.Mode})
}

func (fixture *state) observations(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || fixture.controlToken == "" || !constantToken(request.Header.Get("Authorization"), fixture.controlToken) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": fixture.mode.Load().(string), "active": fixture.active.Load(), "total": fixture.total.Load(),
		"canceled": fixture.canceled.Load(), "disconnected": fixture.disconnected.Load(),
		"waiting_before_response":  fixture.waitingBeforeResponse.Load(),
		"waiting_after_first_byte": fixture.waitingAfterFirstByte.Load(),
	})
}

func constantToken(header, token string) bool {
	want := "Bearer " + token
	return len(header) == len(want) && subtle.ConstantTimeCompare([]byte(header), []byte(want)) == 1
}

func supportedMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "healthy", "fail-500", "delayed-first-byte", "disconnect-before-response", "disconnect-during-stream", "hold-before-response", "drain-hold":
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
