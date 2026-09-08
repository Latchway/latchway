package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProviderErrorDiagnosticsTypedOpenRouterRejection(t *testing.T) {
	t.Parallel()
	config := validRelayConfig()
	config.ProviderErrorMode = ProviderErrorModeOpenRouter
	body := `{"error":{"code":400,"message":"SECRET prompt and credential must not escape","param":"messages[0].content","metadata":{"error_type":"invalid_request","provider_code":"invalid_value","raw":"SECRET","flagged_input":"SECRET"}},"user_id":"SECRET","request_id":"req-1727282430-aBcDeFgHiJkLmNoPqRsT"}`
	response := validRelayResponse(io.NopCloser(strings.NewReader(body)))
	response.StatusCode = 400
	response.Header.Set("X-Generation-Id", "gen-1727282430-aBcDeFgHiJkLmNoPqRsT")
	response.Header.Set("X-Provider-Key", "SECRET")
	writer := newRelayResponseWriter()
	observer := &recordingResponseObserver{}
	config.OnFirstByte = func(context.Context) error { t.Error("first byte hook called for rejection"); return nil }
	config.OnFirstToken = func(context.Context) { t.Error("first token hook called for rejection") }
	outcome, err := RelayResponse(context.Background(), writer, response, observer, config)
	want := ProviderErrorDiagnostics{Category: "invalid_request", Parameter: "messages[0].content", ProviderCode: "invalid_value", GenerationID: "gen-1727282430-aBcDeFgHiJkLmNoPqRsT", RequestID: "req-1727282430-aBcDeFgHiJkLmNoPqRsT"}
	if !errors.Is(err, ErrUpstreamNonSuccess) || !outcome.RejectionConfirmed || outcome.ProviderError != want || outcome.ProviderError.Validate() != nil {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	encoded, _ := json.Marshal(outcome)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(err.Error(), "SECRET") || writer.started || writer.body.Len() != 0 || outcome.BodyBytes != 0 || outcome.Usage.Known || observer.observed.Len() != 0 || observer.finalizeCalls != 0 {
		t.Fatalf("provider data escaped or was reported as usage: outcome=%s err=%v", encoded, err)
	}
}

func TestProviderErrorConfirmationIsClosedAndConservative(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		status    int
		body      string
		confirmed bool
	}{
		{"canonical invalid", 400, `{"error":{"code":400,"metadata":{"error_type":"invalid_request"}}}`, true},
		{"responses canonical", 400, `{"error":{"code":"invalid_prompt"},"error_type":"invalid_prompt"}`, true},
		{"anthropic canonical", 400, `{"error":{"type":"invalid_request_error","error_type":"context_length_exceeded"}}`, true},
		{"long string", 400, `{"error":{"metadata":{"error_type":"string_too_long"}}}`, true},
		{"invalid image", 400, `{"error":{"metadata":{"error_type":"invalid_image"}}}`, true},
		{"image format", 400, `{"error":{"metadata":{"error_type":"unsupported_image_format"}}}`, true},
		{"only status and message", 400, `{"error":{"code":400,"message":"Invalid request"}}`, false},
		{"lossy anthropic", 400, `{"error":{"type":"invalid_request_error"}}`, false},
		{"lossy responses", 400, `{"error":{"code":"invalid_prompt"}}`, false},
		{"unknown category", 400, `{"error":{"metadata":{"error_type":"private_prompt"}}}`, false},
		{"timeout", 400, `{"error":{"metadata":{"error_type":"timeout"}}}`, false},
		{"server", 500, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, false},
		{"semantic 422", 422, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, false},
		{"rate limit", 429, `{"error":{"metadata":{"error_type":"rate_limit_exceeded"}}}`, false},
		{"content filter", 400, `{"error":{"metadata":{"error_type":"content_policy_violation"}}}`, false},
		{"generation token limit", 400, `{"error":{"metadata":{"error_type":"max_tokens_exceeded"}}}`, false},
		{"budget token limit", 400, `{"error":{"metadata":{"error_type":"token_limit_exceeded"}}}`, false},
		{"contradicting status", 400, `{"error":{"code":500,"metadata":{"error_type":"invalid_request"}}}`, false},
		{"contradicting provider code", 400, `{"error":{"metadata":{"error_type":"invalid_request","provider_code":"timeout"}}}`, false},
		{"unexpected provider code", 400, `{"error":{"metadata":{"error_type":"invalid_request","provider_code":"new_unknown_code"}}}`, false},
		{"mistyped code", 400, `{"error":{"code":{},"metadata":{"error_type":"invalid_request"}}}`, false},
		{"lossy allowed responses code", 400, `{"error_type":"invalid_prompt","error":{"code":"server_error"}}`, true},
		{"SSE event envelope", 400, `{"type":"response.error","error_type":"invalid_request","error":{"code":"invalid_prompt"}}`, false},
		{"malformed metadata", 400, `{"error_type":"invalid_request","error":{"metadata":[]}}`, false},
		{"duplicate error", 400, `{"error":{"metadata":{"error_type":"timeout"}},"error":{"metadata":{"error_type":"invalid_request"}}}`, false},
		{"conflicting categories", 400, `{"error_type":"timeout","error":{"metadata":{"error_type":"invalid_request"}}}`, false},
		{"wrong typed category", 400, `{"error_type":null,"error":{"metadata":{"error_type":"invalid_request"}}}`, false},
		{"positive usage", 400, `{"error":{"metadata":{"error_type":"invalid_request"}},"usage":{"input_tokens":10}}`, false},
		{"even null usage uncertain", 400, `{"error":{"metadata":{"error_type":"invalid_request"}},"usage":null}`, false},
		{"partial output", 400, `{"error":{"metadata":{"error_type":"invalid_request"}},"output":[{"text":"SECRET"}]}`, false},
		{"choice", 400, `{"error":{"metadata":{"error_type":"invalid_request"}},"choices":[]}`, false},
		{"response failed state", 400, `{"status":"failed","error_type":"invalid_request","error":{"code":"invalid_prompt"}}`, false},
		{"embedded usage", 400, `{"error":{"metadata":{"error_type":"invalid_request","input_tokens":10}}}`, false},
		{"not object", 400, `[{"error_type":"invalid_request"}]`, false},
		{"no error object", 400, `{"error_type":"invalid_request"}`, false},
		{"malformed", 400, `{"error":{"metadata":{"error_type":"invalid_request"}}`, false},
		{"trailing document", 400, `{"error":{"metadata":{"error_type":"invalid_request"}}}{}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validRelayConfig()
			config.ProviderErrorMode = ProviderErrorModeOpenRouter
			response := validRelayResponse(io.NopCloser(strings.NewReader(test.body)))
			response.StatusCode = test.status
			outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
			if !errors.Is(err, ErrUpstreamNonSuccess) || outcome.RejectionConfirmed != test.confirmed || outcome.ClientStarted || outcome.ProviderError.Validate() != nil {
				t.Fatalf("outcome=%#v err=%v", outcome, err)
			}
		})
	}
}

func TestProviderErrorDoesNotTrustUnselectedModeOrSuccessStatus(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		status int
		mode   ProviderErrorMode
	}{{400, ProviderErrorModeNone}, {200, ProviderErrorModeOpenRouter}} {
		config := validRelayConfig()
		config.ProviderErrorMode = test.mode
		response := validRelayResponse(io.NopCloser(strings.NewReader(`{"error":{"metadata":{"error_type":"invalid_request"}}}`)))
		response.StatusCode = test.status
		outcome, _ := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
		if outcome.RejectionConfirmed || outcome.ProviderError != (ProviderErrorDiagnostics{}) {
			t.Fatalf("mode/status conferred unwarranted trust: %#v", outcome)
		}
	}
	config := validRelayConfig()
	config.ProviderErrorMode = 255
	outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), validRelayResponse(io.NopCloser(strings.NewReader("{}"))), &recordingResponseObserver{}, config)
	if !errors.Is(err, ErrInvalidResponseRelay) || outcome.RejectionConfirmed {
		t.Fatalf("unknown mode accepted: outcome=%#v err=%v", outcome, err)
	}
}

func TestProviderErrorReadHasByteBoundAndNoPartialEvidence(t *testing.T) {
	t.Parallel()
	for _, limit := range []int64{maximumProviderErrorBytes, 128} {
		config := validRelayConfig()
		config.ProviderErrorMode = ProviderErrorModeOpenRouter
		config.MaxBodyBytes = limit
		body := `{"error":{"metadata":{"error_type":"invalid_request"}},"message":"` + strings.Repeat("x", maximumProviderErrorBytes) + `"}`
		counting := &countingProviderErrorBody{Reader: strings.NewReader(body)}
		response := validRelayResponse(counting)
		response.StatusCode = 400
		response.Header.Set("X-Generation-Id", "gen-abcdefgh12345678")
		outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
		if !errors.Is(err, ErrUpstreamNonSuccess) || !errors.Is(err, ErrResponseBodyTooLarge) || counting.read != limit+1 || counting.closes != 1 || outcome.RejectionConfirmed || outcome.ProviderError.Category != ProviderErrorCategoryUnknown {
			t.Fatalf("limit=%d read=%d closes=%d outcome=%#v err=%v", limit, counting.read, counting.closes, outcome, err)
		}
	}
}

type countingProviderErrorBody struct {
	*strings.Reader
	read   int64
	closes int
}

func (body *countingProviderErrorBody) Read(buffer []byte) (int, error) {
	count, err := body.Reader.Read(buffer)
	body.read += int64(count)
	return count, err
}
func (body *countingProviderErrorBody) Close() error { body.closes++; return nil }

func TestProviderErrorReadDeadlineAndCancellationCloseOwnedBody(t *testing.T) {
	t.Parallel()
	for _, canceled := range []bool{false, true} {
		body := newBlockingResponseBody()
		response := validRelayResponse(body)
		response.StatusCode = 400
		config := validRelayConfig()
		config.ProviderErrorMode = ProviderErrorModeOpenRouter
		config.FirstByteTimeout = 20 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		started := time.Now()
		outcome, err := RelayResponse(ctx, newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
		cancel()
		want := ErrProviderErrorTimeout
		if canceled {
			want = context.Canceled
		}
		if !errors.Is(err, ErrUpstreamNonSuccess) || !errors.Is(err, want) || outcome.RejectionConfirmed || body.closeCalls.Load() != 1 || time.Since(started) > time.Second {
			t.Fatalf("canceled=%t outcome=%#v err=%v closes=%d", canceled, outcome, err, body.closeCalls.Load())
		}
	}
}

func TestProviderErrorTricklingCannotExtendAbsoluteDeadline(t *testing.T) {
	t.Parallel()
	reader, writer := io.Pipe()
	defer writer.Close()
	response := validRelayResponse(reader)
	response.StatusCode = 400
	config := validRelayConfig()
	config.ProviderErrorMode = ProviderErrorModeOpenRouter
	config.FirstByteTimeout = 60 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := writer.Write([]byte(" ")); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	started := time.Now()
	outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
	<-done
	if !errors.Is(err, ErrProviderErrorTimeout) || outcome.RejectionConfirmed || time.Since(started) > time.Second {
		t.Fatalf("trickling body escaped deadline: outcome=%#v err=%v", outcome, err)
	}
}

func TestProviderErrorReaderErrorsAreNotExposed(t *testing.T) {
	t.Parallel()
	for _, step := range []responseRead{{data: `{"error":{"metadata":{"error_type":"invalid_request"}}}`, err: errors.New("SECRET body from provider")}, {}} {
		response := validRelayResponse(&scriptedResponseBody{steps: []responseRead{step}})
		response.StatusCode = 400
		config := validRelayConfig()
		config.ProviderErrorMode = ProviderErrorModeOpenRouter
		outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
		if !errors.Is(err, ErrProviderErrorRead) || strings.Contains(err.Error(), "SECRET") || outcome.RejectionConfirmed {
			t.Fatalf("unsafe reader error: outcome=%#v err=%v", outcome, err)
		}
	}
}

func TestProviderErrorDiagnosticsRejectUnboundedAndSensitiveFields(t *testing.T) {
	t.Parallel()
	valid := ProviderErrorDiagnostics{Category: "invalid_request", Parameter: "tools[0].function.parameters", ProviderCode: "unsupported_parameter", GenerationID: "gen-abcdefgh12345678", RequestID: "req-abcdefgh12345678"}
	if valid.Validate() != nil || !valid.AllowsPreGenerationRejection(400) || valid.AllowsPreGenerationRejection(422) {
		t.Fatal("valid evidence boundary rejected")
	}
	for _, parameter := range []string{"SECRET", "messages[0].secret_prompt", "tools.0.function.parameters.properties.personal_name", "messages[0].content\nSECRET", "messages[-1].content", "messages[1234567]", strings.Repeat("messages.", 30), "https://example.test", "messages['user']"} {
		candidate := valid
		candidate.Parameter = parameter
		if candidate.Validate() == nil || safeProviderParameter(parameter) != "" {
			t.Errorf("unsafe parameter accepted: %q", parameter)
		}
	}
	for _, value := range []string{"SECRET", "sk-abcdefgh1234567890", "gen-SECRET\n", "gen-https://example.test", "gen-abc", "gen-" + strings.Repeat("a", 129)} {
		candidate := valid
		candidate.GenerationID = value
		if candidate.Validate() == nil {
			t.Errorf("unsafe identifier accepted: %q", value)
		}
	}
	for _, value := range []string{"private_prompt", "", strings.Repeat("a", 65)} {
		candidate := valid
		candidate.Category = ProviderErrorCategory(value)
		if candidate.Validate() == nil {
			t.Errorf("unsafe category accepted: %q", value)
		}
	}
	for _, value := range []string{"private_prompt", "invalid_request\n", strings.Repeat("a", 65)} {
		candidate := valid
		candidate.ProviderCode = value
		if candidate.Validate() == nil {
			t.Errorf("unsafe provider code accepted: %q", value)
		}
	}
}

func TestProviderErrorHeaderAndEnvelopeBoundaries(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		headers    http.Header
		body       string
		confirmed  bool
		generation string
	}{
		{"encoded", http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, false, ""},
		{"event stream", http.Header{"Content-Type": {"text/event-stream"}}, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, false, ""},
		{"html", http.Header{"Content-Type": {"text/html"}}, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, false, ""},
		{"duplicate content type", http.Header{"Content-Type": {"application/json", "application/json"}}, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, false, ""},
		{"duplicate generation header", http.Header{"Content-Type": {"application/json"}, "X-Generation-Id": {"gen-abcdefgh12345678", "gen-abcdefgh12345678"}}, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, true, ""},
		{"hop by hop generation", http.Header{"Content-Type": {"application/json"}, "X-Generation-Id": {"gen-abcdefgh12345678"}, "Connection": {"X-Generation-Id"}}, `{"error":{"metadata":{"error_type":"invalid_request"}}}`, true, ""},
		{"conflicting generation", http.Header{"Content-Type": {"application/json"}, "X-Generation-Id": {"gen-abcdefgh12345678"}}, `{"id":"gen-87654321abcdefgh","error":{"id":"gen-abcdefgh12345678","metadata":{"error_type":"invalid_request"}}}`, true, ""},
		{"anthropic request id is generation", http.Header{"Content-Type": {"application/json"}}, `{"request_id":"gen-abcdefgh12345678","error":{"error_type":"invalid_request"}}`, true, "gen-abcdefgh12345678"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validRelayConfig()
			config.ProviderErrorMode = ProviderErrorModeOpenRouter
			response := validRelayResponse(io.NopCloser(strings.NewReader(test.body)))
			response.StatusCode = 400
			response.Header = test.headers
			outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
			if !errors.Is(err, ErrUpstreamNonSuccess) || outcome.RejectionConfirmed != test.confirmed || outcome.ProviderError.GenerationID != test.generation || outcome.ProviderError.Validate() != nil {
				t.Fatalf("outcome=%#v err=%v", outcome, err)
			}
		})
	}
}

// A transport may only unblock its body when the exact request context is
// canceled, not when Body.Close is called. Diagnostics preserve that ownership.
func TestProviderErrorDeadlineCancelsExactRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &contextOnlyProviderErrorBody{ctx: ctx}
	response := testDispatchedResponse(&http.Response{StatusCode: 400, Header: http.Header{"Content-Type": {"application/json"}}, Body: body}, cancel)
	config := validRelayConfig()
	config.ProviderErrorMode = ProviderErrorModeOpenRouter
	config.FirstByteTimeout = 20 * time.Millisecond
	outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), response, &recordingResponseObserver{}, config)
	if !errors.Is(err, ErrProviderErrorTimeout) || outcome.RejectionConfirmed || ctx.Err() != context.Canceled {
		t.Fatalf("outcome=%#v err=%v context=%v", outcome, err, ctx.Err())
	}
}

type contextOnlyProviderErrorBody struct {
	ctx  context.Context
	once sync.Once
}

func (body *contextOnlyProviderErrorBody) Read([]byte) (int, error) {
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}
func (body *contextOnlyProviderErrorBody) Close() error { body.once.Do(func() {}); return nil }
