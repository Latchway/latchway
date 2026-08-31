package upstream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/protocol"
)

func TestRelayResponseStreamsChunksAndReturnsNormalizedOutcome(t *testing.T) {
	t.Parallel()

	writer := newRelayResponseWriter()
	body := &scriptedResponseBody{steps: []responseRead{
		{data: "first-"},
		{data: "second-"},
		{data: "third", err: io.EOF},
	}}
	body.beforeRead = func(index int) error {
		if index > 0 && writer.body.Len() == 0 {
			return errors.New("relay requested another chunk before writing the first")
		}
		return nil
	}
	observer := &recordingResponseObserver{usage: protocol.Usage{
		InputTokens: 4, OutputTokens: 3, TotalTokens: 7, Known: true, Provenance: "provider_reported",
	}}
	hookCalls := 0
	config := validRelayConfig()
	config.OnFirstByte = func(context.Context) error {
		hookCalls++
		if writer.started || writer.body.Len() != 0 || observer.observed.Len() != 0 {
			t.Fatal("first-byte hook ran after the response started")
		}
		return nil
	}
	outcome, err := RelayResponse(context.Background(), writer, testDispatchedResponse(&http.Response{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       body,
	}, func() {}), observer, config)
	if err != nil {
		t.Fatalf("RelayResponse() error = %v", err)
	}
	if outcome.StatusCode != http.StatusCreated || outcome.BodyBytes != int64(len("first-second-third")) || !outcome.ClientStarted {
		t.Fatalf("outcome = %#v", outcome)
	}
	if outcome.Usage != observer.usage {
		t.Fatalf("usage = %#v, want %#v", outcome.Usage, observer.usage)
	}
	if writer.status != http.StatusCreated || writer.body.String() != "first-second-third" {
		t.Fatalf("client response: status=%d body=%q", writer.status, writer.body.String())
	}
	if observer.observed.String() != writer.body.String() {
		t.Fatalf("observed bytes = %q, written bytes = %q", observer.observed.String(), writer.body.String())
	}
	if got, want := observer.chunks, []string{"first-", "second-", "third"}; !equalStrings(got, want) {
		t.Fatalf("observer chunks = %#v, want %#v", got, want)
	}
	if hookCalls != 1 || observer.finalizeCalls != 1 || body.closeCalls.Load() != 1 {
		t.Fatalf("calls: hook=%d finalize=%d close=%d", hookCalls, observer.finalizeCalls, body.closeCalls.Load())
	}
}

func TestRelayResponseFirstTokenHookWaitsForObserverSignal(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{
		{data: "lifecycle"},
		{data: "content"},
		{data: "terminal", err: io.EOF},
	}}
	observer := &recordingResponseObserver{firstTokenAfterChunks: 2}
	writer := newRelayResponseWriter()
	firstByteCalls, firstTokenCalls := 0, 0
	config := validRelayConfig()
	config.OnFirstByte = func(context.Context) error {
		firstByteCalls++
		return nil
	}
	config.OnFirstToken = func(context.Context) {
		firstTokenCalls++
		if got := writer.body.String(); got != "lifecyclecontent" {
			t.Fatalf("first-token hook observed client body %q", got)
		}
	}
	if _, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, config); err != nil {
		t.Fatal(err)
	}
	if firstByteCalls != 1 || firstTokenCalls != 1 {
		t.Fatalf("hooks: first_byte=%d first_token=%d", firstByteCalls, firstTokenCalls)
	}
}

func TestRelayResponseFirstTokenHookCanBeFinalizationAware(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{data: "complete-json", err: io.EOF}}}
	observer := &recordingResponseObserver{firstTokenOnFinalize: true}
	firstTokenCalls := 0
	config := validRelayConfig()
	config.OnFirstToken = func(context.Context) { firstTokenCalls++ }
	if _, err := RelayResponse(context.Background(), newRelayResponseWriter(), validRelayResponse(body), observer, config); err != nil {
		t.Fatal(err)
	}
	if firstTokenCalls != 1 {
		t.Fatalf("first-token hook calls = %d", firstTokenCalls)
	}
}

func TestRelayResponseConvertsSilentPartialWriteToShortWrite(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{data: "abcdef", err: io.EOF}}}
	observer := &recordingResponseObserver{}
	writer := newRelayResponseWriter()
	writer.maximumWrite = 2
	outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, validRelayConfig())
	if !errors.Is(err, io.ErrShortWrite) || outcome.BodyBytes != 2 || !outcome.ClientStarted {
		t.Fatalf("short write: outcome=%#v err=%v", outcome, err)
	}
	if writer.body.String() != "ab" || observer.observed.String() != "ab" {
		t.Fatalf("short write bytes: client=%q observed=%q", writer.body.String(), observer.observed.String())
	}
}

func TestRelayResponseObservesOnlyBytesAcceptedByPartialClientWrite(t *testing.T) {
	t.Parallel()

	writeFailure := errors.New("client disconnected")
	body := &scriptedResponseBody{steps: []responseRead{{data: "abcdef", err: io.EOF}}}
	observer := &recordingResponseObserver{}
	writer := newRelayResponseWriter()
	writer.maximumWrite = 3
	writer.writeErr = writeFailure
	outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, validRelayConfig())
	if !errors.Is(err, writeFailure) {
		t.Fatalf("RelayResponse() error = %v, want client failure", err)
	}
	if !outcome.ClientStarted || outcome.BodyBytes != 3 || outcome.StatusCode != http.StatusOK {
		t.Fatalf("outcome = %#v", outcome)
	}
	if writer.body.String() != "abc" || observer.observed.String() != "abc" || observer.finalizeCalls != 0 {
		t.Fatalf("partial write: client=%q observed=%q finalize=%d", writer.body.String(), observer.observed.String(), observer.finalizeCalls)
	}
	if body.closeCalls.Load() != 1 {
		t.Fatalf("body close calls = %d", body.closeCalls.Load())
	}
}

func TestRelayResponseObserverErrorsBeforeAndAfterClientStart(t *testing.T) {
	t.Parallel()

	t.Run("finalize before empty response starts", func(t *testing.T) {
		t.Parallel()
		observerFailure := errors.New("invalid empty response")
		body := &scriptedResponseBody{steps: []responseRead{{err: io.EOF}}}
		observer := &recordingResponseObserver{finalizeErr: observerFailure}
		writer := newRelayResponseWriter()
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, validRelayConfig())
		if !errors.Is(err, observerFailure) || outcome.ClientStarted || writer.started {
			t.Fatalf("pre-start observer error: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
		}
		if observer.finalizeCalls != 1 || body.closeCalls.Load() != 1 {
			t.Fatalf("calls: finalize=%d close=%d", observer.finalizeCalls, body.closeCalls.Load())
		}
	})

	t.Run("observe after successful client write", func(t *testing.T) {
		t.Parallel()
		observerFailure := errors.New("malformed streamed event")
		body := &scriptedResponseBody{steps: []responseRead{{data: "visible", err: io.EOF}}}
		observer := &recordingResponseObserver{observeErr: observerFailure}
		writer := newRelayResponseWriter()
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, validRelayConfig())
		if !errors.Is(err, observerFailure) || !outcome.ClientStarted || outcome.BodyBytes != 7 {
			t.Fatalf("post-start observer error: outcome=%#v err=%v", outcome, err)
		}
		if writer.body.String() != "visible" || observer.observed.String() != "visible" || observer.finalizeCalls != 0 {
			t.Fatalf("post-start bytes: client=%q observed=%q finalize=%d", writer.body.String(), observer.observed.String(), observer.finalizeCalls)
		}
	})
}

func TestRelayResponseEmptyBodyStartsWithoutFirstByteHook(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{err: io.EOF}}}
	observer := &recordingResponseObserver{}
	writer := newRelayResponseWriter()
	hookCalls := 0
	config := validRelayConfig()
	config.OnFirstByte = func(context.Context) error {
		hookCalls++
		return nil
	}
	outcome, err := RelayResponse(context.Background(), writer, testDispatchedResponse(&http.Response{
		StatusCode: http.StatusNoContent,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       body,
	}, func() {}), observer, config)
	if err != nil {
		t.Fatalf("RelayResponse() error = %v", err)
	}
	if !outcome.ClientStarted || outcome.StatusCode != http.StatusNoContent || outcome.BodyBytes != 0 || writer.status != http.StatusNoContent || writer.body.Len() != 0 {
		t.Fatalf("empty response outcome=%#v writer_status=%d body=%q", outcome, writer.status, writer.body.String())
	}
	if outcome.Usage.Known || outcome.Usage.Provenance != "unknown" || hookCalls != 0 || observer.finalizeCalls != 1 {
		t.Fatalf("empty response usage=%#v hook=%d finalize=%d", outcome.Usage, hookCalls, observer.finalizeCalls)
	}
}

func TestRelayResponseRejectsInvalidNormalizedUsageBeforeEmptyResponseStarts(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{err: io.EOF}}}
	observer := &recordingResponseObserver{usage: protocol.Usage{
		InputTokens: -1, TotalTokens: 1, Known: true, Provenance: "provider_reported",
	}}
	writer := newRelayResponseWriter()
	outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, validRelayConfig())
	if !errors.Is(err, ErrInvalidResponseRelay) || outcome.ClientStarted || writer.started {
		t.Fatalf("invalid usage: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
	}
	if body.closeCalls.Load() != 1 || observer.finalizeCalls != 1 {
		t.Fatalf("calls: close=%d finalize=%d", body.closeCalls.Load(), observer.finalizeCalls)
	}
}

func TestNormalizedUsageRequiresOverflowSafeExactTokenTotal(t *testing.T) {
	t.Parallel()

	for _, usage := range []protocol.Usage{
		{Known: true, Provenance: "provider_reported"},
		{
			InputTokens: math.MaxInt64 - 1, OutputTokens: 1,
			TotalTokens: math.MaxInt64, Known: true, Provenance: "provider_reported",
		},
		{
			OutputTokens: math.MaxInt64, TotalTokens: math.MaxInt64,
			Known: true, Provenance: "provider_reported",
		},
	} {
		got, err := normalizedUsage(usage)
		if err != nil || got != usage {
			t.Fatalf("valid exact usage %#v normalized to %#v, %v", usage, got, err)
		}
	}

	for _, usage := range []protocol.Usage{
		{
			InputTokens: 2, OutputTokens: 3, TotalTokens: 4,
			Known: true, Provenance: "provider_reported",
		},
		{
			InputTokens: 2, OutputTokens: 3, TotalTokens: 6,
			Known: true, Provenance: "provider_reported",
		},
		{
			InputTokens: math.MaxInt64, OutputTokens: 1,
			TotalTokens: math.MaxInt64, Known: true, Provenance: "provider_reported",
		},
	} {
		if _, err := normalizedUsage(usage); !errors.Is(err, ErrInvalidResponseRelay) {
			t.Fatalf("inconsistent or overflowing usage %#v returned %v", usage, err)
		}
	}
}

func TestNormalizedUsagePreservesBoundedProviderCostState(t *testing.T) {
	t.Parallel()
	valid := []protocol.Usage{
		{Known: false, Provenance: "unknown", ReportedCost: protocol.ProviderReportedCost{Present: true}},
		{
			InputTokens: 1, TotalTokens: 1, Known: true, Provenance: "provider_reported",
			ReportedCost: protocol.ProviderReportedCost{NanoUSD: 7, Present: true, Known: true},
		},
	}
	for _, usage := range valid {
		got, err := normalizedUsage(usage)
		if err != nil || got != usage {
			t.Fatalf("valid provider cost state %+v normalized to %+v, %v", usage, got, err)
		}
	}
	for _, usage := range []protocol.Usage{
		{ReportedCost: protocol.ProviderReportedCost{Known: true}},
		{ReportedCost: protocol.ProviderReportedCost{NanoUSD: 1, Present: true}},
		{ReportedCost: protocol.ProviderReportedCost{NanoUSD: -1, Present: true, Known: true}},
	} {
		if _, err := normalizedUsage(usage); !errors.Is(err, ErrInvalidResponseRelay) {
			t.Fatalf("invalid provider cost state %+v returned %v", usage, err)
		}
	}
}

func TestRelayResponseCancellationClosesBodyBeforeClientStart(t *testing.T) {
	t.Parallel()

	body := newBlockingResponseBody()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-body.readStarted
		cancel()
	}()
	writer := newRelayResponseWriter()
	var upstreamCancelCalls atomic.Int32
	config := validRelayConfig()
	dispatched := validRelayResponse(body)
	dispatched.cancel = sync.OnceFunc(func() { upstreamCancelCalls.Add(1) })
	outcome, err := RelayResponse(ctx, writer, dispatched, &recordingResponseObserver{}, config)
	if !errors.Is(err, context.Canceled) || outcome.ClientStarted || writer.started {
		t.Fatalf("canceled relay: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
	}
	if body.closeCalls.Load() != 1 {
		t.Fatalf("body close calls = %d", body.closeCalls.Load())
	}
	if upstreamCancelCalls.Load() != 1 {
		t.Fatalf("upstream cancel calls = %d", upstreamCancelCalls.Load())
	}
	waitForResponseRead(t, body)
}

func TestRelayResponseFirstByteTimeoutClosesBodyBeforeClientStart(t *testing.T) {
	t.Parallel()

	body := newBlockingResponseBody()
	writer := newRelayResponseWriter()
	var upstreamCancelCalls atomic.Int32
	config := validRelayConfig()
	config.FirstByteTimeout = 20 * time.Millisecond
	config.IdleTimeout = time.Second
	dispatched := validRelayResponse(body)
	dispatched.cancel = sync.OnceFunc(func() { upstreamCancelCalls.Add(1) })
	started := time.Now()
	outcome, err := RelayResponse(context.Background(), writer, dispatched, &recordingResponseObserver{}, config)
	if !errors.Is(err, ErrResponseFirstByteTimeout) || outcome.ClientStarted || writer.started {
		t.Fatalf("first-byte relay: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("first-byte timeout returned after %v", elapsed)
	}
	if body.closeCalls.Load() != 1 {
		t.Fatalf("body close calls = %d", body.closeCalls.Load())
	}
	if upstreamCancelCalls.Load() != 1 {
		t.Fatalf("upstream cancel calls = %d", upstreamCancelCalls.Load())
	}
	waitForResponseRead(t, body)
}

func TestRelayResponseIdleTimeoutClosesBodyAfterClientStart(t *testing.T) {
	t.Parallel()

	blocked := newBlockingResponseBody()
	body := &firstChunkThenBlockingResponseBody{blockingResponseBody: blocked}
	writer := newRelayResponseWriter()
	var upstreamCancelCalls atomic.Int32
	config := validRelayConfig()
	config.FirstByteTimeout = time.Second
	config.IdleTimeout = 20 * time.Millisecond
	dispatched := validRelayResponse(body)
	dispatched.cancel = sync.OnceFunc(func() { upstreamCancelCalls.Add(1) })
	started := time.Now()
	outcome, err := RelayResponse(context.Background(), writer, dispatched, &recordingResponseObserver{}, config)
	if !errors.Is(err, ErrResponseIdleTimeout) || !outcome.ClientStarted || !writer.started || outcome.BodyBytes != int64(len("first")) {
		t.Fatalf("idle relay: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("idle timeout returned after %v", elapsed)
	}
	if blocked.closeCalls.Load() != 1 {
		t.Fatalf("body close calls = %d", blocked.closeCalls.Load())
	}
	if upstreamCancelCalls.Load() != 1 {
		t.Fatalf("upstream cancel calls = %d", upstreamCancelCalls.Load())
	}
	waitForResponseRead(t, blocked)
}

func TestRelayResponseRejectsProviderErrorBodyBeforeClientStart(t *testing.T) {
	t.Parallel()

	for _, statusCode := range []int{http.StatusTemporaryRedirect, http.StatusTooManyRequests} {
		statusCode := statusCode
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			t.Parallel()
			body := &scriptedResponseBody{steps: []responseRead{{data: `{"provider_secret":"must not pass"}`, err: io.EOF}}}
			response := validRelayResponse(body)
			response.StatusCode = statusCode
			response.Header.Set("Location", "https://attacker.example")
			writer := newRelayResponseWriter()
			observer := &recordingResponseObserver{}
			var upstreamCancelCalls atomic.Int32
			config := validRelayConfig()
			response.cancel = sync.OnceFunc(func() { upstreamCancelCalls.Add(1) })
			outcome, err := RelayResponse(context.Background(), writer, response, observer, config)
			if !errors.Is(err, ErrUpstreamNonSuccess) || outcome.StatusCode != statusCode || outcome.ClientStarted || writer.started {
				t.Fatalf("provider error: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
			}
			if body.index != 0 || writer.body.Len() != 0 || observer.observed.Len() != 0 || observer.finalizeCalls != 0 {
				t.Fatalf("provider error body was consumed or exposed: reads=%d client=%q observed=%q finalize=%d", body.index, writer.body.String(), observer.observed.String(), observer.finalizeCalls)
			}
			if body.closeCalls.Load() != 1 || upstreamCancelCalls.Load() != 1 {
				t.Fatalf("cleanup calls: close=%d cancel=%d", body.closeCalls.Load(), upstreamCancelCalls.Load())
			}
		})
	}
}

func TestNormalizeResponseStatusUsesStableProductionClasses(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusNoContent} {
		if err := NormalizeResponseStatus(status); err != nil {
			t.Fatalf("success status %d rejected: %v", status, err)
		}
	}
	for _, status := range []int{http.StatusMultipleChoices, http.StatusBadRequest, http.StatusTooManyRequests, 599} {
		if err := NormalizeResponseStatus(status); !errors.Is(err, ErrUpstreamNonSuccess) {
			t.Fatalf("provider status %d normalized as %v", status, err)
		}
	}
	for _, status := range []int{0, http.StatusContinue, 600} {
		if err := NormalizeResponseStatus(status); !errors.Is(err, ErrInvalidResponseRelay) {
			t.Fatalf("invalid status %d normalized as %v", status, err)
		}
	}
}

func TestRelayResponseEnforcesMaximumBodyBytes(t *testing.T) {
	t.Parallel()

	t.Run("known length before start", func(t *testing.T) {
		t.Parallel()
		body := &scriptedResponseBody{steps: []responseRead{{data: "abcdef", err: io.EOF}}}
		response := validRelayResponse(body)
		response.ContentLength = 6
		config := validRelayConfig()
		config.MaxBodyBytes = 5
		writer := newRelayResponseWriter()
		outcome, err := RelayResponse(context.Background(), writer, response, &recordingResponseObserver{}, config)
		if !errors.Is(err, ErrResponseBodyTooLarge) || outcome.ClientStarted || writer.started || body.index != 0 {
			t.Fatalf("known length: outcome=%#v writer_started=%t reads=%d err=%v", outcome, writer.started, body.index, err)
		}
	})

	t.Run("first chunk before start", func(t *testing.T) {
		t.Parallel()
		body := &scriptedResponseBody{steps: []responseRead{{data: "abcdef", err: io.EOF}}}
		config := validRelayConfig()
		config.MaxBodyBytes = 5
		writer := newRelayResponseWriter()
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), &recordingResponseObserver{}, config)
		if !errors.Is(err, ErrResponseBodyTooLarge) || outcome.ClientStarted || writer.started || writer.body.Len() != 0 {
			t.Fatalf("first chunk: outcome=%#v writer_started=%t body=%q err=%v", outcome, writer.started, writer.body.String(), err)
		}
	})

	t.Run("stream crosses limit", func(t *testing.T) {
		t.Parallel()
		body := &scriptedResponseBody{steps: []responseRead{{data: "abc"}, {data: "def", err: io.EOF}}}
		config := validRelayConfig()
		config.MaxBodyBytes = 5
		writer := newRelayResponseWriter()
		observer := &recordingResponseObserver{}
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, config)
		if !errors.Is(err, ErrResponseBodyTooLarge) || !outcome.ClientStarted || outcome.BodyBytes != 3 {
			t.Fatalf("crossed limit: outcome=%#v err=%v", outcome, err)
		}
		if writer.body.String() != "abc" || observer.observed.String() != "abc" {
			t.Fatalf("bytes beyond limit were exposed: client=%q observed=%q", writer.body.String(), observer.observed.String())
		}
	})
}

func TestRelayResponseRequiresAndBoundsClientWriteDeadline(t *testing.T) {
	t.Parallel()

	t.Run("unsupported writer", func(t *testing.T) {
		t.Parallel()
		body := &scriptedResponseBody{steps: []responseRead{{data: "visible", err: io.EOF}}}
		writer := httptest.NewRecorder()
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), &recordingResponseObserver{}, validRelayConfig())
		if !errors.Is(err, http.ErrNotSupported) || outcome.ClientStarted || writer.Body.Len() != 0 {
			t.Fatalf("unsupported writer: outcome=%#v body=%q err=%v", outcome, writer.Body.String(), err)
		}
	})

	t.Run("deadline setter failure", func(t *testing.T) {
		t.Parallel()
		deadlineFailure := errors.New("connection deadline unavailable")
		body := &scriptedResponseBody{steps: []responseRead{{data: "visible", err: io.EOF}}}
		writer := newRelayResponseWriter()
		writer.writeDeadlineErr = deadlineFailure
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), &recordingResponseObserver{}, validRelayConfig())
		if !errors.Is(err, deadlineFailure) || outcome.ClientStarted || writer.started || writer.body.Len() != 0 {
			t.Fatalf("deadline failure: outcome=%#v writer_started=%t body=%q err=%v", outcome, writer.started, writer.body.String(), err)
		}
	})

	t.Run("deadline clear failure preserves committed boundary", func(t *testing.T) {
		t.Parallel()
		clearFailure := errors.New("connection deadline could not be cleared")
		body := &scriptedResponseBody{steps: []responseRead{{data: "visible", err: io.EOF}}}
		writer := newRelayResponseWriter()
		writer.clearWriteDeadlineErr = clearFailure
		outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), &recordingResponseObserver{}, validRelayConfig())
		if !errors.Is(err, clearFailure) || !outcome.ClientStarted || !writer.started || writer.body.Len() != 0 {
			t.Fatalf("deadline clear failure: outcome=%#v writer_started=%t body=%q err=%v", outcome, writer.started, writer.body.String(), err)
		}
	})

	t.Run("context deadline is the upper bound", func(t *testing.T) {
		t.Parallel()
		contextDeadline := time.Now().Add(500 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), contextDeadline)
		defer cancel()
		body := &scriptedResponseBody{steps: []responseRead{{data: "visible", err: io.EOF}}}
		writer := newRelayResponseWriter()
		config := validRelayConfig()
		config.ClientWriteTimeout = time.Hour
		outcome, err := RelayResponse(ctx, writer, validRelayResponse(body), &recordingResponseObserver{}, config)
		if err != nil || !outcome.ClientStarted || len(writer.writeDeadlines) < 2 {
			t.Fatalf("bounded deadline: outcome=%#v deadlines=%#v err=%v", outcome, writer.writeDeadlines, err)
		}
		for index, deadline := range writer.writeDeadlines {
			if index%2 == 1 {
				if !deadline.IsZero() {
					t.Fatalf("write deadline was not cleared after client operation: %#v", writer.writeDeadlines)
				}
				continue
			}
			if deadline.IsZero() {
				t.Fatalf("client operation was not given a write deadline: %#v", writer.writeDeadlines)
			}
			if deadline.After(contextDeadline) {
				t.Fatalf("write deadline %v exceeds context deadline %v", deadline, contextDeadline)
			}
		}
		if len(writer.writeDeadlines)%2 != 0 {
			t.Fatalf("write deadline set/clear calls are unbalanced: %#v", writer.writeDeadlines)
		}
	})
}

func TestRelayResponseClearsWriteDeadlineWhileWaitingForNextSSEChunk(t *testing.T) {
	t.Parallel()

	writer := newRelayResponseWriter()
	body := &scriptedResponseBody{steps: []responseRead{
		{data: "data: one\n\n"},
		{data: "data: two\n\n", err: io.EOF},
	}}
	body.beforeRead = func(index int) error {
		if index != 1 {
			return nil
		}
		if len(writer.writeDeadlines) == 0 || !writer.writeDeadlines[len(writer.writeDeadlines)-1].IsZero() {
			return errors.New("client write deadline remained armed between upstream chunks")
		}
		return nil
	}
	response := validRelayResponse(body)
	response.Header.Set("Content-Type", "text/event-stream")
	outcome, err := RelayResponse(context.Background(), writer, response, &recordingResponseObserver{}, validRelayConfig())
	if err != nil || !outcome.ClientStarted || outcome.BodyBytes == 0 {
		t.Fatalf("sparse SSE relay: outcome=%#v deadlines=%#v err=%v", outcome, writer.writeDeadlines, err)
	}
}

func TestRelayResponseFiltersHeadersAndForcesNoStore(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{data: "limited", err: io.EOF}}}
	writer := newRelayResponseWriter()
	writer.header.Set("X-Latchway-Request-ID", "gateway-correlation")
	response := testDispatchedResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":               {"application/problem+json"},
			"Content-Encoding":           {"IDENTITY"},
			"Retry-After":                {"17"},
			"Cache-Control":              {"public, max-age=3600"},
			"Connection":                 {"X-Hop, Keep-Alive"},
			"X-Hop":                      {"discard"},
			"Keep-Alive":                 {"timeout=60"},
			"Transfer-Encoding":          {"chunked"},
			"Content-Length":             {"7"},
			"Set-Cookie":                 {"provider=secret"},
			"X-Latchway-Upstream-Secret": {"discard"},
			"Alt-Svc":                    {`h3=":443"`},
			"Location":                   {"https://attacker.example/redirect"},
			"Refresh":                    {"0; url=https://attacker.example"},
			"Etag":                       {`"safe"`},
			"X-Safe-Metadata":            {"one", "two"},
			"X-Content-Type-Options":     {"off"},
			"X-Frame-Options":            {"ALLOWALL"},
			"Referrer-Policy":            {"unsafe-url"},
		},
		Body: body,
	}, func() {})
	outcome, err := RelayResponse(context.Background(), writer, response, &recordingResponseObserver{}, validRelayConfig())
	if err != nil {
		t.Fatalf("RelayResponse() error = %v", err)
	}
	if outcome.StatusCode != http.StatusOK || writer.status != http.StatusOK {
		t.Fatalf("status: outcome=%d writer=%d", outcome.StatusCode, writer.status)
	}
	if writer.header.Get("Content-Type") != "application/problem+json" || writer.header.Get("Retry-After") != "17" || writer.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("preserved headers = %#v", writer.header)
	}
	if writer.header.Get("Content-Encoding") != "identity" {
		t.Fatalf("content encoding = %q, want identity", writer.header.Get("Content-Encoding"))
	}
	if writer.header.Get("X-Content-Type-Options") != "nosniff" || writer.header.Get("X-Frame-Options") != "DENY" || writer.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("gateway security headers = %#v", writer.header)
	}
	if writer.header.Get("X-Latchway-Request-ID") != "gateway-correlation" {
		t.Fatalf("gateway correlation header was removed: %#v", writer.header)
	}
	for _, name := range []string{"Connection", "X-Hop", "Keep-Alive", "Transfer-Encoding", "Content-Length", "Set-Cookie", "X-Latchway-Upstream-Secret", "Alt-Svc", "Location", "Refresh", "Etag", "X-Safe-Metadata"} {
		if values := writer.header.Values(name); len(values) != 0 {
			t.Fatalf("forbidden response header %s = %#v", name, values)
		}
	}
}

func TestRelayResponseClearsStaleProviderSemanticHeaders(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{data: "plain", err: io.EOF}}}
	writer := newRelayResponseWriter()
	writer.header.Set("Content-Type", "application/stale")
	writer.header.Set("Content-Encoding", "gzip")
	writer.header.Set("Retry-After", "999")
	response := testDispatchedResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       body,
	}, func() {})

	outcome, err := RelayResponse(context.Background(), writer, response, &recordingResponseObserver{}, validRelayConfig())
	if err != nil || !outcome.ClientStarted {
		t.Fatalf("RelayResponse(): outcome=%#v err=%v", outcome, err)
	}
	for _, name := range []string{"Content-Type", "Content-Encoding", "Retry-After"} {
		if values := writer.header.Values(name); len(values) != 0 {
			t.Fatalf("stale response header %s survived = %#v", name, values)
		}
	}
}

func TestRelayResponseRejectsNoProgressReadImmediately(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{{}}}
	started := time.Now()
	outcome, err := RelayResponse(context.Background(), newRelayResponseWriter(), validRelayResponse(body), &recordingResponseObserver{}, validRelayConfig())
	if !errors.Is(err, ErrInvalidResponseRelay) || outcome.ClientStarted {
		t.Fatalf("no-progress relay: outcome=%#v err=%v", outcome, err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("no-progress read waited %v instead of failing immediately", elapsed)
	}
}

func TestRelayResponseFirstByteHookFailureDoesNotStartClient(t *testing.T) {
	t.Parallel()

	hookFailure := errors.New("quota state unavailable")
	body := &scriptedResponseBody{steps: []responseRead{{data: "must-not-pass", err: io.EOF}}}
	observer := &recordingResponseObserver{}
	writer := newRelayResponseWriter()
	hookCalls := 0
	config := validRelayConfig()
	config.OnFirstByte = func(context.Context) error {
		hookCalls++
		return hookFailure
	}
	outcome, err := RelayResponse(context.Background(), writer, validRelayResponse(body), observer, config)
	if !errors.Is(err, hookFailure) || outcome.ClientStarted || writer.started || writer.body.Len() != 0 || observer.observed.Len() != 0 {
		t.Fatalf("hook failure: outcome=%#v writer_started=%t body=%q observed=%q err=%v", outcome, writer.started, writer.body.String(), observer.observed.String(), err)
	}
	if hookCalls != 1 || body.closeCalls.Load() != 1 {
		t.Fatalf("calls: hook=%d close=%d", hookCalls, body.closeCalls.Load())
	}
}

func TestRelayResponseClosesBodyForInvalidInputs(t *testing.T) {
	t.Parallel()

	missingIdleTimeout := validRelayConfig()
	missingIdleTimeout.IdleTimeout = 0
	negativeFirstByteTimeout := validRelayConfig()
	negativeFirstByteTimeout.FirstByteTimeout = -time.Second
	missingWriteTimeout := validRelayConfig()
	missingWriteTimeout.ClientWriteTimeout = 0
	missingBodyLimit := validRelayConfig()
	missingBodyLimit.MaxBodyBytes = 0
	tests := []struct {
		name     string
		response func(*scriptedResponseBody) *DispatchedResponse
		observer func() protocol.ResponseObserver
		config   ResponseRelayConfig
	}{
		{
			name: "missing body",
			response: func(*scriptedResponseBody) *DispatchedResponse {
				return testDispatchedResponse(&http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}, func() {})
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "informational status",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return testDispatchedResponse(&http.Response{StatusCode: http.StatusContinue, Header: make(http.Header), Body: body}, func() {})
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "switching protocols status",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return testDispatchedResponse(&http.Response{StatusCode: http.StatusSwitchingProtocols, Header: make(http.Header), Body: body}, func() {})
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "typed nil observer",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return validRelayResponse(body)
			},
			observer: func() protocol.ResponseObserver {
				var observer *recordingResponseObserver
				return observer
			},
			config: validRelayConfig(),
		},
		{
			name: "non-positive idle timeout",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return validRelayResponse(body)
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   missingIdleTimeout,
		},
		{
			name: "negative first-byte timeout",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return validRelayResponse(body)
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   negativeFirstByteTimeout,
		},
		{
			name: "non-positive client write timeout",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return validRelayResponse(body)
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   missingWriteTimeout,
		},
		{
			name: "non-positive response body limit",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return validRelayResponse(body)
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   missingBodyLimit,
		},
		{
			name: "missing upstream cancellation",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				return testDispatchedResponse(validRelayResponse(body).Response, nil)
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "unsafe response header",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				response := validRelayResponse(body)
				response.Header.Set("X-Unsafe", "line\nbreak")
				return response
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "encoded response body",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				response := validRelayResponse(body)
				response.Header.Set("Content-Encoding", "gzip")
				return response
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "ambiguous response content type",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				response := validRelayResponse(body)
				response.Header["content-type"] = []string{"text/plain"}
				return response
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
		{
			name: "reader makes no progress",
			response: func(body *scriptedResponseBody) *DispatchedResponse {
				body.steps = []responseRead{{}}
				return validRelayResponse(body)
			},
			observer: func() protocol.ResponseObserver { return &recordingResponseObserver{} },
			config:   validRelayConfig(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := &scriptedResponseBody{steps: []responseRead{{err: io.EOF}}}
			writer := newRelayResponseWriter()
			outcome, err := RelayResponse(context.Background(), writer, test.response(body), test.observer(), test.config)
			if !errors.Is(err, ErrInvalidResponseRelay) || outcome.ClientStarted || writer.started {
				t.Fatalf("invalid relay: outcome=%#v writer_started=%t err=%v", outcome, writer.started, err)
			}
			if test.name != "missing body" && body.closeCalls.Load() != 1 {
				t.Fatalf("body close calls = %d", body.closeCalls.Load())
			}
		})
	}
}

func TestRelayResponseFlushesEverySSEChunk(t *testing.T) {
	t.Parallel()

	body := &scriptedResponseBody{steps: []responseRead{
		{data: "data: one\n\n"},
		{data: "data: two\n\n", err: io.EOF},
	}}
	writer := newRelayResponseWriter()
	response := validRelayResponse(body)
	response.Header.Set("Content-Type", "text/event-stream; charset=utf-8")
	outcome, err := RelayResponse(context.Background(), writer, response, &recordingResponseObserver{}, validRelayConfig())
	if err != nil {
		t.Fatalf("RelayResponse() error = %v", err)
	}
	if outcome.BodyBytes != int64(len("data: one\n\ndata: two\n\n")) || writer.flushCalls != 2 {
		t.Fatalf("SSE outcome=%#v flushes=%d body=%q", outcome, writer.flushCalls, writer.body.String())
	}
	if len(writer.writeDeadlines) < 10 || len(writer.writeDeadlines)%2 != 0 {
		t.Fatalf("SSE writes and flushes were not individually bounded: deadlines=%d", len(writer.writeDeadlines))
	}
	for index := 1; index < len(writer.writeDeadlines); index += 2 {
		if !writer.writeDeadlines[index].IsZero() {
			t.Fatalf("SSE write deadline was not cleared: %#v", writer.writeDeadlines)
		}
	}
}

func validRelayResponse(body io.ReadCloser) *DispatchedResponse {
	return testDispatchedResponse(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       body,
	}, func() {})
}

func testDispatchedResponse(response *http.Response, cancel context.CancelFunc) *DispatchedResponse {
	var cancelOnce context.CancelFunc
	if cancel != nil {
		cancelOnce = sync.OnceFunc(cancel)
	}
	var body *onceReadCloser
	if response != nil && !nilInterface(response.Body) {
		body = &onceReadCloser{ReadCloser: response.Body}
		response.Body = body
	}
	return &DispatchedResponse{Response: response, body: body, cancel: cancelOnce}
}

func validRelayConfig() ResponseRelayConfig {
	return ResponseRelayConfig{
		FirstByteTimeout:   time.Second,
		IdleTimeout:        time.Second,
		ClientWriteTimeout: time.Second,
		MaxBodyBytes:       1 << 20,
	}
}

type responseRead struct {
	data string
	err  error
}

type scriptedResponseBody struct {
	steps      []responseRead
	index      int
	beforeRead func(int) error
	closeCalls atomic.Int32
}

func (body *scriptedResponseBody) Read(destination []byte) (int, error) {
	if body.beforeRead != nil {
		if err := body.beforeRead(body.index); err != nil {
			return 0, err
		}
	}
	if body.index >= len(body.steps) {
		return 0, io.EOF
	}
	step := body.steps[body.index]
	body.index++
	count := copy(destination, step.data)
	return count, step.err
}

func (body *scriptedResponseBody) Close() error {
	body.closeCalls.Add(1)
	return nil
}

type blockingResponseBody struct {
	readStarted  chan struct{}
	readFinished chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	finishOnce   sync.Once
	closeOnce    sync.Once
	closeCalls   atomic.Int32
}

type firstChunkThenBlockingResponseBody struct {
	*blockingResponseBody
	firstReturned bool
}

func (body *firstChunkThenBlockingResponseBody) Read(destination []byte) (int, error) {
	if !body.firstReturned {
		body.firstReturned = true
		return copy(destination, "first"), nil
	}
	return body.blockingResponseBody.Read(destination)
}

func newBlockingResponseBody() *blockingResponseBody {
	return &blockingResponseBody{
		readStarted:  make(chan struct{}),
		readFinished: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (body *blockingResponseBody) Read(destination []byte) (int, error) {
	body.startOnce.Do(func() { close(body.readStarted) })
	<-body.closed
	count := copy(destination, "late bytes after close")
	body.finishOnce.Do(func() { close(body.readFinished) })
	return count, errors.New("body closed")
}

func (body *blockingResponseBody) Close() error {
	body.closeCalls.Add(1)
	body.closeOnce.Do(func() { close(body.closed) })
	return nil
}

func waitForResponseRead(t *testing.T, body *blockingResponseBody) {
	t.Helper()
	select {
	case <-body.readFinished:
	case <-time.After(time.Second):
		t.Fatal("response body read did not finish after Close")
	}
}

type recordingResponseObserver struct {
	observed              bytes.Buffer
	chunks                []string
	usage                 protocol.Usage
	observeErr            error
	finalizeErr           error
	finalizeCalls         int
	firstTokenAfterChunks int
	firstTokenOnFinalize  bool
	firstToken            bool
}

func (observer *recordingResponseObserver) Observe(chunk []byte) error {
	observer.chunks = append(observer.chunks, string(chunk))
	_, _ = observer.observed.Write(chunk)
	if observer.firstTokenAfterChunks > 0 && len(observer.chunks) >= observer.firstTokenAfterChunks {
		observer.firstToken = true
	}
	return observer.observeErr
}

func (observer *recordingResponseObserver) Finalize() (protocol.Usage, error) {
	observer.finalizeCalls++
	if observer.firstTokenOnFinalize {
		observer.firstToken = true
	}
	return observer.usage, observer.finalizeErr
}

func (observer *recordingResponseObserver) FirstTokenObserved() bool { return observer.firstToken }

type relayResponseWriter struct {
	header                http.Header
	status                int
	started               bool
	body                  bytes.Buffer
	maximumWrite          int
	writeErr              error
	flushErr              error
	flushCalls            int
	writeDeadlineErr      error
	clearWriteDeadlineErr error
	writeDeadlines        []time.Time
}

func newRelayResponseWriter() *relayResponseWriter {
	return &relayResponseWriter{header: make(http.Header), maximumWrite: -1}
}

func (writer *relayResponseWriter) Header() http.Header { return writer.header }

func (writer *relayResponseWriter) WriteHeader(statusCode int) {
	if writer.started {
		return
	}
	writer.started = true
	writer.status = statusCode
}

func (writer *relayResponseWriter) Write(value []byte) (int, error) {
	if !writer.started {
		writer.WriteHeader(http.StatusOK)
	}
	count := len(value)
	if writer.maximumWrite >= 0 && count > writer.maximumWrite {
		count = writer.maximumWrite
	}
	_, _ = writer.body.Write(value[:count])
	return count, writer.writeErr
}

func (writer *relayResponseWriter) FlushError() error {
	writer.flushCalls++
	return writer.flushErr
}

func (writer *relayResponseWriter) SetWriteDeadline(deadline time.Time) error {
	writer.writeDeadlines = append(writer.writeDeadlines, deadline)
	if deadline.IsZero() && writer.clearWriteDeadlineErr != nil {
		return writer.clearWriteDeadlineErr
	}
	return writer.writeDeadlineErr
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ http.ResponseWriter = (*relayResponseWriter)(nil)
var _ protocol.ResponseObserver = (*recordingResponseObserver)(nil)
var _ io.ReadCloser = (*scriptedResponseBody)(nil)
var _ io.ReadCloser = (*blockingResponseBody)(nil)
var _ io.ReadCloser = (*firstChunkThenBlockingResponseBody)(nil)
