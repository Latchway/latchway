package dataplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/upstream"
)

func assertTransportAbort(t *testing.T, serve func()) {
	t.Helper()
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("expected transport abort, got %v", got)
		}
	}()
	serve()
}

type impossibleQuota struct{}

func (impossibleQuota) Error() string      { return "private database detail" }
func (impossibleQuota) Unwrap() error      { return quota.ErrExceeded }
func (impossibleQuota) RequestBound() bool { return true }

func TestRequestBoundQuotaIsPermanentAndProtocolDetailIsPreserved(t *testing.T) {
	fixture := newHandlerFixture(t)
	code, retry := errorCode(impossibleQuota{}, fixture.now)
	if code != "request_invalid" || retry != 0 {
		t.Fatalf("impossible request: %s/%d", code, retry)
	}
	value := mappedProblem("request_invalid", "assistant", 0, &protocol.Error{Code: "request_invalid", Detail: "function tool parameters must be an object"})
	if value.Detail != "function tool parameters must be an object" || len(value.Fields) != 1 || value.Fields[0].Path != "body" {
		t.Fatalf("safe validation detail lost: %+v", value)
	}
	value = mappedProblem("request_invalid", "assistant", 0, errors.New("SECRET-provider-body"))
	if strings.Contains(value.Detail, "SECRET") {
		t.Fatal("wrapped error leaked")
	}
}

func TestUpstreamErrorClassificationPreservesStableContractAndRetryHint(t *testing.T) {
	for _, test := range []struct {
		status int
		code   string
		retry  bool
	}{
		{400, "request_invalid", false}, {401, "configuration_invalid", false},
		{403, "configuration_invalid", false}, {404, "configuration_invalid", false},
		{413, "request_invalid", false}, {422, "request_invalid", false},
		{429, "upstream_unavailable", true}, {503, "upstream_unavailable", true},
	} {
		fixture := newHandlerFixture(t)
		recorder := httptest.NewRecorder()
		fixture.handler(t).writeExecutionError(recorder, "request_error_test", "assistant", executionResult{
			err:   errors.Join(upstream.ErrUpstreamNonSuccess, errors.New("SECRET-provider-body")),
			relay: upstream.RelayOutcome{StatusCode: test.status, RetryAfterSeconds: 17},
		})
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["code"] != test.code || body["retryable"] != test.retry || strings.Contains(recorder.Body.String(), "SECRET") {
			t.Fatalf("status %d: %s", test.status, recorder.Body.String())
		}
		if test.retry != (recorder.Header().Get("Retry-After") == "17") {
			t.Fatalf("status %d retry hint: %v", test.status, recorder.Header())
		}
	}
}

func TestObserverFailureKeepsProtocolFailureCode(t *testing.T) {
	if got := failureCode(&protocol.Error{Code: "upstream_protocol_error", Detail: "upstream stream failed"}); got != "upstream_protocol_error" {
		t.Fatal(got)
	}
}
