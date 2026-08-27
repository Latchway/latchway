package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/upstream"
)

func TestHandlerSuccessUsesCanonicalAuthorizationPolicyQuotaAndDispatch(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusOK, BodyBytes: 11, ClientStarted: true}
	fixture.relayer.body = `{"ok":true}`
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	if response.Code != http.StatusOK || response.Body.String() != `{"ok":true}` {
		t.Fatalf("response = (%d, %q); calls verify/session/snapshot/policy/reserve/target/prepare/begin/dispatch/relay/settle/release=%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d",
			response.Code, response.Body.String(), fixture.verifier.calls, fixture.sessions.calls, fixture.snapshots.calls,
			fixture.policies.calls, fixture.quotas.reserveCalls, fixture.targets.calls, fixture.target.prepareCalls,
			fixture.quotas.beginCalls, fixture.target.dispatchCalls, fixture.relayer.calls, fixture.quotas.settleCalls,
			fixture.quotas.releaseCalls)
	}
	if fixture.verifier.calls != 1 || fixture.sessions.calls != 1 || fixture.snapshots.calls != 1 || fixture.policies.calls != 1 {
		t.Fatalf("auth/config/policy calls = %d/%d/%d/%d", fixture.verifier.calls, fixture.sessions.calls, fixture.snapshots.calls, fixture.policies.calls)
	}
	if got := fixture.sessions.input.RequestURI.String(); got != "https://gateway.example/v1/chat/completions" {
		t.Fatalf("authorized URL = %q", got)
	}
	if fixture.sessions.input.HTTPMethod != http.MethodPost {
		t.Fatalf("authorized method = %q", fixture.sessions.input.HTTPMethod)
	}
	if fixture.policies.metadata.ClientModel != "client-model" || fixture.policies.metadata.Streaming {
		t.Fatalf("protocol metadata = %#v", fixture.policies.metadata)
	}
	if fixture.quotas.reserveCalls != 1 || fixture.quotas.beginCalls != 1 || fixture.quotas.settleCalls != 1 || fixture.quotas.releaseCalls != 0 {
		t.Fatalf("quota lifecycle reserve/begin/settle/release = %d/%d/%d/%d", fixture.quotas.reserveCalls, fixture.quotas.beginCalls, fixture.quotas.settleCalls, fixture.quotas.releaseCalls)
	}
	if fixture.quotas.reserveInput.LogicalRequestID.String() == "" ||
		fixture.quotas.reserveInput.ClientRequestID != "client-request-123" ||
		fixture.quotas.reserveInput.PhysicalModel != "provider-model" ||
		fixture.quotas.reserveInput.Pricing != (quota.PricingSelection{}) ||
		fixture.quotas.reserveInput.Streaming {
		t.Fatalf("quota input = %#v", fixture.quotas.reserveInput)
	}
	if fixture.quotas.settleOutcome != (quota.Outcome{
		Status: quota.AttemptSucceeded, HTTPStatus: http.StatusOK, Usage: unknownQuotaUsage(),
	}) {
		t.Fatalf("settlement = %#v", fixture.quotas.settleOutcome)
	}
	if fixture.target.preparePath != providerChatPath || fixture.target.dispatchCalls != 1 ||
		fixture.target.beforeCalls != 1 || fixture.target.roundTripCalls != 1 ||
		fixture.target.bearerCalls != 0 || fixture.target.headerCalls != 0 || fixture.targets.releaseCalls != 1 {
		t.Fatalf("target path/dispatch/gate/round-trip/bearer/header/release = %q/%d/%d/%d/%d/%d/%d",
			fixture.target.preparePath, fixture.target.dispatchCalls, fixture.target.beforeCalls,
			fixture.target.roundTripCalls, fixture.target.bearerCalls, fixture.target.headerCalls,
			fixture.targets.releaseCalls)
	}
	if fixture.target.preparedBody == "" || strings.Contains(fixture.target.preparedBody, "client-model") || !strings.Contains(fixture.target.preparedBody, "provider-model") {
		t.Fatalf("provider body was not rewritten: %q", fixture.target.preparedBody)
	}
}

func TestHandlerDoesNotDispatchWhenAttemptOwnershipIsReplay(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.quotas.beginOwner = false
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "conflict", http.StatusConflict)
	if fixture.target.dispatchCalls != 1 || fixture.target.beforeCalls != 1 || fixture.target.roundTripCalls != 0 ||
		fixture.target.bearerCalls != 0 || fixture.target.headerCalls != 0 {
		t.Fatalf("replay gate/transport lifecycle = %#v", fixture.target)
	}
	if fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 0 {
		t.Fatalf("replay mutated terminal quota state: release=%d settle=%d", fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.targets.releaseCalls != 1 {
		t.Fatalf("replay target lease releases = %d", fixture.targets.releaseCalls)
	}
}

func TestHandlerNeverReleasesAfterBeginAttempt(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.target.dispatchErr = errors.New("provider transport private failure")
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "upstream_unavailable", http.StatusServiceUnavailable)
	if strings.Contains(response.Body.String(), "provider transport private failure") {
		t.Fatal("problem response leaked a transport error")
	}
	if fixture.quotas.beginCalls != 1 || fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 1 {
		t.Fatalf("quota lifecycle begin/release/settle = %d/%d/%d", fixture.quotas.beginCalls, fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.quotas.settleOutcome.Status != quota.AttemptFailed || fixture.quotas.settleOutcome.HTTPStatus != 0 || fixture.quotas.settleOutcome.FailureCode != "upstream_unavailable" {
		t.Fatalf("failed dispatch settlement = %#v", fixture.quotas.settleOutcome)
	}
}

func TestHandlerClassifiesDispatchDeadlineAsTimeout(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.target.dispatchErr = context.DeadlineExceeded
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "upstream_timeout", http.StatusGatewayTimeout)
	if fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 1 {
		t.Fatalf("dispatch timeout release/settle = %d/%d", fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.quotas.settleOutcome != (quota.Outcome{
		Status: quota.AttemptTimedOut, FailureCode: "upstream_timeout", Usage: unknownQuotaUsage(),
	}) {
		t.Fatalf("dispatch timeout settlement = %#v", fixture.quotas.settleOutcome)
	}
}

func TestHandlerClassifiesGenericRelayFailureAsUpstreamUnavailable(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusOK}
	fixture.relayer.err = errors.New("private provider body read failure")
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "upstream_unavailable", http.StatusServiceUnavailable)
	if strings.Contains(response.Body.String(), "private provider body read failure") {
		t.Fatal("problem response leaked a relay error")
	}
	if fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 1 {
		t.Fatalf("relay failure release/settle = %d/%d", fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.quotas.settleOutcome != (quota.Outcome{
		Status: quota.AttemptFailed, HTTPStatus: http.StatusOK, FailureCode: "upstream_unavailable",
		Usage: unknownQuotaUsage(),
	}) {
		t.Fatalf("relay failure settlement = %#v", fixture.quotas.settleOutcome)
	}
}

func TestHandlerDoesNotReleaseWhenBeginAttemptItselfFails(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.quotas.beginErr = quota.ErrDependency
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "server_not_ready", http.StatusServiceUnavailable)
	if fixture.quotas.beginCalls != 1 || fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 0 {
		t.Fatalf("ambiguous begin lifecycle begin/release/settle = %d/%d/%d", fixture.quotas.beginCalls, fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.target.dispatchCalls != 1 || fixture.target.beforeCalls != 1 || fixture.target.roundTripCalls != 0 {
		t.Fatalf("failed attempt start gate/transport = %d/%d/%d",
			fixture.target.dispatchCalls, fixture.target.beforeCalls, fixture.target.roundTripCalls)
	}
	if fixture.targets.releaseCalls != 1 {
		t.Fatalf("failed attempt start target lease releases = %d", fixture.targets.releaseCalls)
	}
}

func TestHandlerReleasesWhenSecretFailsBeforeAttempt(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.Upstream.Authentication = configuration.UpstreamAuthentication{
		Type: "bearer", SecretRef: "secret/provider_key",
	}
	fixture.secret.err = secrets.ErrUnavailable
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "upstream_unavailable", http.StatusServiceUnavailable)
	if fixture.quotas.beginCalls != 0 || fixture.quotas.releaseCalls != 1 || fixture.quotas.settleCalls != 0 {
		t.Fatalf("quota lifecycle begin/release/settle = %d/%d/%d", fixture.quotas.beginCalls, fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.quotas.releaseFailure != "upstream_unavailable" {
		t.Fatalf("release failure code = %q", fixture.quotas.releaseFailure)
	}
	if fixture.target.dispatchCalls != 0 || fixture.target.bearerCalls != 0 {
		t.Fatal("secret failure reached upstream dispatch")
	}
}

func TestProductionCredentialValidationReleasesBeforeAttempt(t *testing.T) {
	tests := []struct {
		name           string
		authentication configuration.UpstreamAuthentication
	}{
		{
			name: "malformed bearer secret",
			authentication: configuration.UpstreamAuthentication{
				Type: "bearer", SecretRef: "secret/provider_key",
			},
		},
		{
			name: "malformed header secret",
			authentication: configuration.UpstreamAuthentication{
				Type: "header", SecretRef: "secret/provider_key", HeaderName: "X-Provider-Key",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			productionTarget, resolver := newProductionDispatchTarget(t)
			fixture := newHandlerFixture(t)
			fixture.targets.target = productionTarget
			fixture.decision.Upstream.Authentication = test.authentication
			fixture.secret.value = []byte("malformed\nsecret")
			handler := fixture.handler(t)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, fixture.request(t))

			assertProblemCode(t, response, "upstream_unavailable", http.StatusServiceUnavailable)
			if fixture.quotas.reserveCalls != 1 || fixture.quotas.beginCalls != 0 ||
				fixture.quotas.releaseCalls != 1 || fixture.quotas.settleCalls != 0 {
				t.Fatalf("credential validation reserve/begin/release/settle = %d/%d/%d/%d",
					fixture.quotas.reserveCalls, fixture.quotas.beginCalls,
					fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
			}
			if resolver.calls.Load() != 0 || fixture.targets.releaseCalls != 1 {
				t.Fatalf("credential validation resolver/lease releases = %d/%d",
					resolver.calls.Load(), fixture.targets.releaseCalls)
			}
		})
	}
}

func TestProductionCanceledContextBeforeGateReleasesReservation(t *testing.T) {
	productionTarget, resolver := newProductionDispatchTarget(t)
	fixture := newHandlerFixture(t)
	fixture.targets.target = productionTarget
	request := fixture.request(t)
	requestContext, cancelRequest := context.WithCancel(request.Context())
	request = request.WithContext(requestContext)
	fixture.quotas.reserveHook = cancelRequest
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Body.Len() != 0 {
		t.Fatalf("canceled request received a problem body: %q", response.Body.String())
	}
	if fixture.quotas.reserveCalls != 1 || fixture.quotas.beginCalls != 0 ||
		fixture.quotas.releaseCalls != 1 || fixture.quotas.settleCalls != 0 {
		t.Fatalf("canceled pre-gate reserve/begin/release/settle = %d/%d/%d/%d",
			fixture.quotas.reserveCalls, fixture.quotas.beginCalls,
			fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.quotas.releaseFailure != "client_cancelled" || resolver.calls.Load() != 0 ||
		fixture.targets.releaseCalls != 1 {
		t.Fatalf("canceled pre-gate failure/resolver/lease releases = %q/%d/%d",
			fixture.quotas.releaseFailure, resolver.calls.Load(), fixture.targets.releaseCalls)
	}
}

func TestHandlerReleasesWhenTargetFailsBeforeAttempt(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*handlerFixture)
	}{
		{name: "resolve", setup: func(fixture *handlerFixture) {
			fixture.targets.err = errors.New("private target resolution failure")
		}},
		{name: "prepare", setup: func(fixture *handlerFixture) {
			fixture.target.prepareErr = errors.New("private request reconstruction failure")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			test.setup(fixture)
			handler := fixture.handler(t)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, fixture.request(t))

			assertProblemCode(t, response, "configuration_invalid", http.StatusUnprocessableEntity)
			if strings.Contains(response.Body.String(), "private") {
				t.Fatal("problem response leaked target failure details")
			}
			if fixture.quotas.reserveCalls != 1 || fixture.quotas.beginCalls != 0 ||
				fixture.quotas.releaseCalls != 1 || fixture.quotas.settleCalls != 0 {
				t.Fatalf("target failure reserve/begin/release/settle = %d/%d/%d/%d",
					fixture.quotas.reserveCalls, fixture.quotas.beginCalls,
					fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
			}
			if fixture.quotas.releaseFailure != "configuration_invalid" || fixture.target.dispatchCalls != 0 {
				t.Fatalf("target failure release/dispatch = %q/%d", fixture.quotas.releaseFailure, fixture.target.dispatchCalls)
			}
		})
	}
}

func TestCredentialScopeContainsBeginObserveAndRelayButNotSettlement(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.Upstream.Authentication = configuration.UpstreamAuthentication{
		Type: "bearer", SecretRef: "secret/provider_key",
	}
	fixture.secret.invoke = true
	fixture.target.secret = fixture.secret
	fixture.quotas.secret = fixture.secret
	fixture.relayer.secret = fixture.secret
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusOK, BodyBytes: 2, ClientStarted: true}
	fixture.relayer.body = `{}`
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	if response.Code != http.StatusOK || fixture.target.bearerCalls != 1 || fixture.target.dispatchCalls != 0 {
		t.Fatalf("scoped dispatch response/calls = %d/%d/%d", response.Code, fixture.target.bearerCalls, fixture.target.dispatchCalls)
	}
	if !fixture.quotas.beginInsideSecret || !fixture.target.dispatchInsideSecret || !fixture.relayer.insideSecret {
		t.Fatalf("secret scope begin/dispatch/relay = %t/%t/%t", fixture.quotas.beginInsideSecret, fixture.target.dispatchInsideSecret, fixture.relayer.insideSecret)
	}
	if fixture.quotas.settleInsideSecret {
		t.Fatal("quota settlement retained provider plaintext scope")
	}
}

func TestFixedHeaderCredentialScopeContainsDispatchAndRelay(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.Upstream.Authentication = configuration.UpstreamAuthentication{
		Type: "header", SecretRef: "secret/provider_key", HeaderName: "X-Provider-Key",
	}
	fixture.secret.invoke = true
	fixture.target.secret = fixture.secret
	fixture.quotas.secret = fixture.secret
	fixture.relayer.secret = fixture.secret
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusOK, BodyBytes: 2, ClientStarted: true}
	fixture.relayer.body = `{}`
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	if response.Code != http.StatusOK || fixture.target.headerCalls != 1 ||
		fixture.target.bearerCalls != 0 || fixture.target.dispatchCalls != 0 {
		t.Fatalf("fixed-header response/header/bearer/plain calls = %d/%d/%d/%d",
			response.Code, fixture.target.headerCalls, fixture.target.bearerCalls, fixture.target.dispatchCalls)
	}
	if !fixture.quotas.beginInsideSecret || !fixture.target.dispatchInsideSecret || !fixture.relayer.insideSecret {
		t.Fatalf("secret scope begin/dispatch/relay = %t/%t/%t",
			fixture.quotas.beginInsideSecret, fixture.target.dispatchInsideSecret, fixture.relayer.insideSecret)
	}
	if fixture.quotas.settleInsideSecret || fixture.quotas.settleCalls != 1 || fixture.quotas.releaseCalls != 0 {
		t.Fatalf("fixed-header settlement scope/calls/release = %t/%d/%d",
			fixture.quotas.settleInsideSecret, fixture.quotas.settleCalls, fixture.quotas.releaseCalls)
	}
}

func TestHandlerDoesNotAppendProblemAfterClientResponseStarts(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.relayer.outcome = upstream.RelayOutcome{
		StatusCode: http.StatusOK, BodyBytes: int64(len("partial")), ClientStarted: true,
	}
	fixture.relayer.body = "partial"
	fixture.relayer.err = upstream.ErrResponseIdleTimeout
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	if response.Code != http.StatusOK || response.Body.String() != "partial" {
		t.Fatalf("started response was corrupted: (%d, %q)", response.Code, response.Body.String())
	}
	if fixture.quotas.markCalls != 1 || fixture.quotas.settleCalls != 1 || fixture.quotas.releaseCalls != 0 {
		t.Fatalf("quota first-byte/settle/release = %d/%d/%d", fixture.quotas.markCalls, fixture.quotas.settleCalls, fixture.quotas.releaseCalls)
	}
	if fixture.quotas.settleOutcome.Status != quota.AttemptTimedOut || fixture.quotas.settleOutcome.HTTPStatus != http.StatusOK || fixture.quotas.settleOutcome.FailureCode != "upstream_timeout" {
		t.Fatalf("partial response settlement = %#v", fixture.quotas.settleOutcome)
	}
}

func TestHandlerBoundsFirstBytePersistenceBeforeStartingClientResponse(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.quotas.markBlock = true
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusOK, BodyBytes: 2, ClientStarted: true}
	fixture.relayer.body = `{}`
	handler := fixture.handler(t)
	handler.persistenceTimeout = 25 * time.Millisecond

	response := httptest.NewRecorder()
	startedAt := time.Now()
	handler.ServeHTTP(response, fixture.request(t))
	elapsed := time.Since(startedAt)

	assertProblemCode(t, response, "server_not_ready", http.StatusServiceUnavailable)
	if strings.Contains(response.Body.String(), `{}`) {
		t.Fatal("client response started before the first-byte persistence hook completed")
	}
	if elapsed > time.Second {
		t.Fatalf("blocking first-byte persistence took %s", elapsed)
	}
	if fixture.quotas.markCalls != 1 || fixture.quotas.markTimeout <= 0 || fixture.quotas.markTimeout > 100*time.Millisecond {
		t.Fatalf("first-byte calls/deadline = %d/%s", fixture.quotas.markCalls, fixture.quotas.markTimeout)
	}
	if fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 1 ||
		fixture.quotas.settleOutcome.Status != quota.AttemptFailed ||
		fixture.quotas.settleOutcome.FailureCode != "quota_state_unavailable" {
		t.Fatalf("first-byte timeout release/settlement = %d/%#v",
			fixture.quotas.releaseCalls, fixture.quotas.settleOutcome)
	}
}

func TestStreamingProviderJSONErrorIsNotRelayedAndSettlesUnavailable(t *testing.T) {
	fixture := newHandlerFixture(t)
	providerBody := &trackingReadCloser{reader: strings.NewReader(`{"provider_private":"do not relay"}`)}
	fixture.target.response = &upstream.DispatchedResponse{Response: &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       providerBody,
	}}
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusTooManyRequests}
	fixture.relayer.err = upstream.ErrUpstreamNonSuccess
	handler := fixture.handler(t)
	request := fixture.request(t)
	requestBody := `{"model":"client-model","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	request.Body = io.NopCloser(strings.NewReader(requestBody))
	request.ContentLength = int64(len(requestBody))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertProblemCode(t, response, "upstream_unavailable", http.StatusServiceUnavailable)
	if strings.Contains(response.Body.String(), "provider_private") {
		t.Fatal("provider error body reached the client")
	}
	if providerBody.readCalls != 0 {
		t.Fatalf("provider error body was read %d times", providerBody.readCalls)
	}
	if fixture.quotas.markCalls != 0 || fixture.quotas.settleCalls != 1 || fixture.quotas.releaseCalls != 0 {
		t.Fatalf("quota first-byte/settle/release = %d/%d/%d", fixture.quotas.markCalls, fixture.quotas.settleCalls, fixture.quotas.releaseCalls)
	}
	if fixture.quotas.settleOutcome != (quota.Outcome{
		Status: quota.AttemptFailed, HTTPStatus: http.StatusTooManyRequests, FailureCode: "upstream_non_success",
		Usage: unknownQuotaUsage(),
	}) {
		t.Fatalf("provider error settlement = %#v", fixture.quotas.settleOutcome)
	}
	if !strings.Contains(fixture.target.preparedBody, `"stream":true`) ||
		!strings.Contains(fixture.target.preparedBody, `"model":"provider-model"`) {
		t.Fatalf("provider request was not reconstructed for streaming: %q", fixture.target.preparedBody)
	}
}

func TestProductionRelayTruncatedProviderBodySettlesUnavailable(t *testing.T) {
	listener, err := privateIPv4Listener()
	if err != nil {
		t.Skipf("private test listener unavailable in this test sandbox: %v", err)
	}
	provider := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("Content-Length", "32")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		connection, _, hijackErr := writer.(http.Hijacker).Hijack()
		if hijackErr != nil {
			t.Errorf("hijack provider connection: %v", hijackErr)
			return
		}
		_ = connection.Close()
	}))
	provider.Listener = listener
	provider.Start()
	defer provider.Close()

	nativeTarget, err := upstream.NewTarget(provider.URL, upstream.DestinationPolicy{AllowPrivate: true}, upstream.Timeouts{
		Connect: time.Second, TLSHandshake: time.Second, ResponseHeader: time.Second, IdleConnection: time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("construct loopback upstream target: %v", err)
	}
	fixture := newHandlerFixture(t)
	fixture.targets.target = &protectedDispatchTarget{target: nativeTarget}
	fixture.relayer = nil // Use responseRelayer and upstream.RelayResponse.
	handler := fixture.handler(t)
	request := fixture.request(t)
	requestBody := `{"model":"client-model","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	request.Body = io.NopCloser(strings.NewReader(requestBody))
	request.ContentLength = int64(len(requestBody))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertProblemCode(t, response, "upstream_unavailable", http.StatusServiceUnavailable)
	if fixture.quotas.markCalls != 0 || fixture.quotas.releaseCalls != 0 || fixture.quotas.settleCalls != 1 {
		t.Fatalf("truncated response first-byte/release/settle = %d/%d/%d",
			fixture.quotas.markCalls, fixture.quotas.releaseCalls, fixture.quotas.settleCalls)
	}
	if fixture.quotas.settleOutcome != (quota.Outcome{
		Status: quota.AttemptFailed, HTTPStatus: http.StatusOK, FailureCode: "upstream_unavailable",
		Usage: unknownQuotaUsage(),
	}) {
		t.Fatalf("truncated response settlement = %#v", fixture.quotas.settleOutcome)
	}
}

func privateIPv4Listener() (net.Listener, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || !ip.IsPrivate() || ip.IsLoopback() {
				continue
			}
			listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
			if err == nil {
				return listener, nil
			}
		}
	}
	return nil, errors.New("no bindable private IPv4 address")
}

func TestHandlerRejectsCanonicalPathAndDeclarationFailuresBeforeAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(*http.Request)
		code   string
		status int
	}{
		{name: "method", edit: func(request *http.Request) { request.Method = http.MethodGet }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "query", edit: func(request *http.Request) { request.URL.RawQuery = "debug=true" }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "force query", edit: func(request *http.Request) { request.URL.ForceQuery = true }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "raw path", edit: func(request *http.Request) { request.URL.RawPath = "/v1/%63hat/completions" }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "wrong path", edit: func(request *http.Request) { request.URL.Path = "/v1/responses" }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "duplicate protocol", edit: func(request *http.Request) { request.Header.Add("X-Latchway-Protocol-Version", "1") }, code: "protocol_version_unsupported", status: http.StatusUpgradeRequired},
		{name: "case duplicate SDK", edit: func(request *http.Request) { request.Header["x-latchway-sdk"] = []string{"ios"} }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "missing SDK version", edit: func(request *http.Request) { request.Header.Del("X-Latchway-SDK-Version") }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "missing feature", edit: func(request *http.Request) { request.Header.Del("X-Latchway-Feature") }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "duplicate authorization", edit: func(request *http.Request) { request.Header.Add("Authorization", "DPoP "+strings.Repeat("b", 64)) }, code: "request_invalid", status: http.StatusBadRequest},
		{name: "missing proof", edit: func(request *http.Request) { request.Header.Del("DPoP") }, code: "dpop_missing", status: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			handler := fixture.handler(t)
			request := fixture.request(t)
			test.edit(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertProblemCode(t, response, test.code, test.status)
			if fixture.verifier.calls != 0 || fixture.sessions.calls != 0 || fixture.quotas.reserveCalls != 0 || fixture.targets.calls != 0 {
				t.Fatalf("invalid request reached trusted dependencies: verify/session/reserve/target=%d/%d/%d/%d", fixture.verifier.calls, fixture.sessions.calls, fixture.quotas.reserveCalls, fixture.targets.calls)
			}
		})
	}
}

func TestValidSemVer(t *testing.T) {
	tests := []struct {
		value string
		valid bool
	}{
		{value: "0.0.0", valid: true},
		{value: "1.2.3", valid: true},
		{value: "1.0.0-alpha", valid: true},
		{value: "1.0.0-alpha.1", valid: true},
		{value: "1.0.0-0.3.7", valid: true},
		{value: "1.0.0-x-7.z.92", valid: true},
		{value: "1.0.0+001", valid: true},
		{value: "1.0.0-beta+exp.sha.5114f85", valid: true},
		{value: "", valid: false},
		{value: "1", valid: false},
		{value: "1.2", valid: false},
		{value: "1.2.3.4", valid: false},
		{value: "01.2.3", valid: false},
		{value: "1.02.3", valid: false},
		{value: "1.2.03", valid: false},
		{value: "1.0.0-", valid: false},
		{value: "1.0.0-..", valid: false},
		{value: "1.0.0-alpha..1", valid: false},
		{value: "1.0.0-01", valid: false},
		{value: "1.0.0+", valid: false},
		{value: "1.0.0+build..1", valid: false},
		{value: "1.0.0+build+again", valid: false},
		{value: "1.0.0-α", valid: false},
		{value: "v1.2.3", valid: false},
		{value: "1.0.0+" + strings.Repeat("a", 123), valid: false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := validSemVer(test.value); got != test.valid {
				t.Fatalf("validSemVer(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestValidDecisionWindowUsesDeterministicOneYearBounds(t *testing.T) {
	t.Parallel()

	valid := []string{"1m", "527040m", "1h", "8784h", "1d", "366d", "1mo", "12mo"}
	for _, window := range valid {
		window := window
		t.Run("valid_"+window, func(t *testing.T) {
			t.Parallel()
			if !validDecisionWindow(window) {
				t.Fatalf("expected %q to be accepted", window)
			}
		})
	}

	invalid := []string{
		"", "0d", "01d", "1w",
		"527041m", "8785h", "367d", "13mo",
		"9223372036854775808d",
	}
	for _, window := range invalid {
		window := window
		t.Run("invalid_"+window, func(t *testing.T) {
			t.Parallel()
			if validDecisionWindow(window) {
				t.Fatalf("expected %q to be rejected", window)
			}
		})
	}
}

func TestHandlerTranslatesMultipleCanonicalLimitRulesBeforeReservation(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.LimitPlan.Limits[0].Scope = []string{"user", "environment"}
	fixture.decision.LimitPlan.Limits = append(fixture.decision.LimitPlan.Limits, configuration.Limit{
		Metric: quota.LogicalRequestsMetric, Algorithm: quota.CalendarAlgorithm,
		Scope: []string{"feature", "application"}, Window: "1mo", Maximum: 1, Hard: true,
	})
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	if response.Code != http.StatusOK || fixture.quotas.reserveCalls != 1 || len(fixture.quotas.reserveInput.Rules) != 2 {
		t.Fatalf("multi-rule response/reserve/rules = %d/%d/%#v",
			response.Code, fixture.quotas.reserveCalls, fixture.quotas.reserveInput.Rules)
	}
	first, second := fixture.quotas.reserveInput.Rules[0], fixture.quotas.reserveInput.Rules[1]
	if !slices.Equal(first.Scope, []string{"environment", "user"}) ||
		!slices.Equal(second.Scope, []string{"application", "feature"}) ||
		first.Window != "1d" || first.Maximum != 100 || second.Window != "1mo" || second.Maximum != 1 {
		t.Fatalf("translated canonical rules = %#v", fixture.quotas.reserveInput.Rules)
	}
}

func TestHandlerTranslatesConcurrencyRulesAndPropagatesStreaming(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.LimitPlan.Limits = []configuration.Limit{
		{
			Metric: quota.ConcurrentRequestsMetric, Algorithm: quota.ConcurrencyAlgorithm,
			Scope: []string{"feature", "environment"}, Maximum: 3, Hard: true,
		},
		{
			Metric: quota.ConcurrentStreamsMetric, Algorithm: quota.ConcurrencyAlgorithm,
			Scope: []string{"user", "environment"}, Maximum: 1, Hard: true,
		},
	}
	fixture.target.response.Response.Header.Set("Content-Type", "text/event-stream")
	handler := fixture.handler(t)
	request := fixture.request(t)
	body := `{"model":"client-model","messages":[{"role":"user","content":"hello"}],"stream":true}`
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || fixture.quotas.reserveCalls != 1 ||
		!fixture.quotas.reserveInput.Streaming || len(fixture.quotas.reserveInput.Rules) != 2 {
		t.Fatalf("concurrency status/reserve/streaming/rules = %d/%d/%t/%#v",
			response.Code, fixture.quotas.reserveCalls, fixture.quotas.reserveInput.Streaming,
			fixture.quotas.reserveInput.Rules)
	}
	requestsRule, streamsRule := fixture.quotas.reserveInput.Rules[0], fixture.quotas.reserveInput.Rules[1]
	if requestsRule.Metric != quota.ConcurrentRequestsMetric ||
		requestsRule.Algorithm != quota.ConcurrencyAlgorithm || requestsRule.Window != "" ||
		requestsRule.Maximum != 3 || requestsRule.PerRequestMaximum != 0 ||
		requestsRule.ReservedUnits != 0 || !requestsRule.Hard ||
		!slices.Equal(requestsRule.Scope, []string{"environment", "feature"}) {
		t.Fatalf("translated concurrent-request rule = %#v", requestsRule)
	}
	if streamsRule.Metric != quota.ConcurrentStreamsMetric ||
		streamsRule.Algorithm != quota.ConcurrencyAlgorithm || streamsRule.Window != "" ||
		streamsRule.Maximum != 1 || streamsRule.PerRequestMaximum != 0 ||
		streamsRule.ReservedUnits != 0 || !streamsRule.Hard ||
		!slices.Equal(streamsRule.Scope, []string{"environment", "user"}) {
		t.Fatalf("translated concurrent-stream rule = %#v", streamsRule)
	}
}

func TestHandlerAppliesSmallestPerRequestCapAndReservesExactWrittenMaximum(t *testing.T) {
	perRequestLimits := []configuration.Limit{
		{
			Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
			Scope: []string{"model", "environment"}, PerRequestMaximum: 96, Hard: true,
		},
		{
			Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
			Scope: []string{"user", "feature"}, PerRequestMaximum: 40, Hard: true,
		},
	}
	for _, reverse := range []bool{false, true} {
		name := "configured order"
		if reverse {
			name = "reversed order"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			limits := append([]configuration.Limit(nil), perRequestLimits...)
			if reverse {
				slices.Reverse(limits)
			}
			fixture.decision.LimitPlan.Limits = append(fixture.decision.LimitPlan.Limits, configuration.Limit{
				Metric: quota.OutputTokensMetric, Algorithm: quota.CalendarAlgorithm,
				Scope: []string{"feature", "environment"}, Window: "1mo", Maximum: 10_000, Hard: true,
			})
			fixture.decision.LimitPlan.Limits = append(fixture.decision.LimitPlan.Limits, limits...)
			handler := fixture.handler(t)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, fixture.request(t))

			if response.Code != http.StatusOK || fixture.quotas.reserveCalls != 1 {
				t.Fatalf("response/reserve = %d/%d", response.Code, fixture.quotas.reserveCalls)
			}
			if !strings.Contains(fixture.target.preparedBody, `"max_completion_tokens":40`) {
				t.Fatalf("provider request did not use effective default/cap 40: %s", fixture.target.preparedBody)
			}
			if len(fixture.quotas.reserveInput.Rules) != 4 {
				t.Fatalf("reserved rules = %#v", fixture.quotas.reserveInput.Rules)
			}
			for _, rule := range fixture.quotas.reserveInput.Rules {
				if rule.Metric == quota.LogicalRequestsMetric {
					if rule.ReservedUnits != 0 {
						t.Fatalf("logical rule reserved units = %d, want store-derived unit", rule.ReservedUnits)
					}
					continue
				}
				if rule.Metric != quota.OutputTokensMetric || rule.ReservedUnits != 40 {
					t.Fatalf("output rule = %#v, want exact applied reservation 40", rule)
				}
			}
		})
	}
}

func TestHandlerRunsDurableLifecycleForPerRequestOnlyPlan(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.LimitPlan.Limits = []configuration.Limit{{
		Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
		Scope: []string{"user", "environment"}, PerRequestMaximum: 64, Hard: true,
	}}
	handler := fixture.handler(t)
	request := fixture.request(t)
	body := `{"model":"client-model","messages":[{"role":"user","content":"hello"}],"max_tokens":20}`
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || fixture.quotas.reserveCalls != 1 ||
		fixture.quotas.beginCalls != 1 || fixture.quotas.settleCalls != 1 || fixture.quotas.releaseCalls != 0 {
		t.Fatalf("per-request lifecycle status/reserve/begin/settle/release = %d/%d/%d/%d/%d",
			response.Code, fixture.quotas.reserveCalls, fixture.quotas.beginCalls,
			fixture.quotas.settleCalls, fixture.quotas.releaseCalls)
	}
	if len(fixture.quotas.reserveInput.Rules) != 1 {
		t.Fatalf("per-request rules = %#v", fixture.quotas.reserveInput.Rules)
	}
	rule := fixture.quotas.reserveInput.Rules[0]
	if rule.Metric != quota.OutputTokensMetric || rule.Algorithm != quota.PerRequestAlgorithm ||
		rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum != 64 || rule.ReservedUnits != 20 ||
		!slices.Equal(rule.Scope, []string{"environment", "user"}) {
		t.Fatalf("per-request rule = %#v", rule)
	}
	if !strings.Contains(fixture.target.preparedBody, `"max_tokens":20`) ||
		strings.Contains(fixture.target.preparedBody, "max_completion_tokens") {
		t.Fatalf("provider request did not retain the exact legacy limit: %s", fixture.target.preparedBody)
	}
}

func TestHandlerRejectsUnsupportedOrDuplicateLimitRulesBeforeReservation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*configuration.LimitPlan)
	}{
		{name: "no rules", mutate: func(plan *configuration.LimitPlan) { plan.Limits = nil }},
		{name: "too many rules", mutate: func(plan *configuration.LimitPlan) {
			base := plan.Limits[0]
			plan.Limits = make([]configuration.Limit, maximumDecisionLimitRules+1)
			for index := range plan.Limits {
				plan.Limits[index] = base
				plan.Limits[index].Window = "1d"
			}
		}},
		{name: "future metric", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Metric = "input_tokens" }},
		{name: "future algorithm", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Algorithm = "token_bucket" }},
		{name: "concurrent metric with calendar algorithm", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.ConcurrentRequestsMetric
		}},
		{name: "logical metric with concurrency algorithm", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
			plan.Limits[0].Window = ""
		}},
		{name: "hard cost concurrency", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.CostNanoUSDMetric
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
			plan.Limits[0].Window = ""
		}},
		{name: "concurrency window", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.ConcurrentStreamsMetric
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
		}},
		{name: "concurrency zero maximum", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.ConcurrentStreamsMetric
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].Maximum = 0
		}},
		{name: "concurrency per-request field", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.ConcurrentStreamsMetric
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].PerRequestMaximum = 1
		}},
		{name: "concurrency capacity field", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.ConcurrentRequestsMetric
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].Capacity = 1
		}},
		{name: "concurrency refill field", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.ConcurrentRequestsMetric
			plan.Limits[0].Algorithm = quota.ConcurrencyAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].RefillPerSecond = "1"
		}},
		{name: "soft", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Hard = false }},
		{name: "empty scope", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Scope = nil }},
		{name: "duplicate scope", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Scope = []string{"user", "user"} }},
		{name: "unknown scope", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Scope = []string{"claim"} }},
		{name: "unsupported window unit", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Window = "1w" }},
		{name: "window above executable bound", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Window = "367d" }},
		{name: "overflowing window", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Window = "9223372036854775808d" }},
		{name: "zero maximum", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Maximum = 0 }},
		{name: "per request field", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].PerRequestMaximum = 1 }},
		{name: "logical per request algorithm", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Algorithm = quota.PerRequestAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].Maximum = 0
			plan.Limits[0].PerRequestMaximum = 1
		}},
		{name: "output calendar with per request maximum", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.OutputTokensMetric
			plan.Limits[0].PerRequestMaximum = 1
		}},
		{name: "output per request with window", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.OutputTokensMetric
			plan.Limits[0].Algorithm = quota.PerRequestAlgorithm
			plan.Limits[0].Maximum = 0
			plan.Limits[0].PerRequestMaximum = 1
		}},
		{name: "output per request with maximum", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.OutputTokensMetric
			plan.Limits[0].Algorithm = quota.PerRequestAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].PerRequestMaximum = 1
		}},
		{name: "output per request without maximum", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits[0].Metric = quota.OutputTokensMetric
			plan.Limits[0].Algorithm = quota.PerRequestAlgorithm
			plan.Limits[0].Window = ""
			plan.Limits[0].Maximum = 0
		}},
		{name: "capacity field", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].Capacity = 1 }},
		{name: "refill field", mutate: func(plan *configuration.LimitPlan) { plan.Limits[0].RefillPerSecond = "1" }},
		{name: "duplicate immutable identity", mutate: func(plan *configuration.LimitPlan) {
			duplicate := plan.Limits[0]
			duplicate.Scope = append([]string(nil), duplicate.Scope...)
			duplicate.Scope = []string{"user", "environment"}
			duplicate.Maximum++
			plan.Limits = append(plan.Limits, duplicate)
		}},
		{name: "duplicate output per request identity", mutate: func(plan *configuration.LimitPlan) {
			plan.Limits = []configuration.Limit{
				{
					Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
					Scope: []string{"user", "environment"}, PerRequestMaximum: 50, Hard: true,
				},
				{
					Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
					Scope: []string{"environment", "user"}, PerRequestMaximum: 40, Hard: true,
				},
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			test.mutate(&fixture.decision.LimitPlan)
			handler := fixture.handler(t)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, fixture.request(t))

			assertProblemCode(t, response, "configuration_invalid", http.StatusUnprocessableEntity)
			if fixture.quotas.reserveCalls != 0 || fixture.targets.calls != 0 {
				t.Fatal("unsupported limit plan reached quota or target")
			}
		})
	}
}

func TestHandlerTreatsUncommittedSuccessfulRelayAsProtocolFailure(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.relayer.outcome = upstream.RelayOutcome{StatusCode: http.StatusOK, ClientStarted: false}
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "upstream_protocol_error", http.StatusBadGateway)
	if fixture.quotas.settleCalls != 1 || fixture.quotas.settleOutcome.Status != quota.AttemptFailed ||
		fixture.quotas.settleOutcome.HTTPStatus != http.StatusOK ||
		fixture.quotas.settleOutcome.FailureCode != "upstream_protocol_error" {
		t.Fatalf("uncommitted relay settlement = %#v", fixture.quotas.settleOutcome)
	}
}

func TestQuotaOutcomeCarriesNormalizedUsageThroughSuccessUnknownAndFailure(t *testing.T) {
	t.Parallel()

	reported := protocol.Usage{
		InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
		Known: true, Provenance: quota.ProviderReportedProvenance,
	}
	tests := []struct {
		name       string
		relay      upstream.RelayOutcome
		execution  error
		wantStatus string
		wantCode   string
		wantUsage  quota.Usage
	}{
		{
			name: "known successful usage", relay: upstream.RelayOutcome{StatusCode: http.StatusOK, Usage: reported},
			wantStatus: quota.AttemptSucceeded,
			wantUsage: quota.Usage{
				InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
				Known: true, Provenance: quota.ProviderReportedProvenance,
			},
		},
		{
			name: "unknown successful usage", relay: upstream.RelayOutcome{StatusCode: http.StatusOK},
			wantStatus: quota.AttemptSucceeded, wantUsage: unknownQuotaUsage(),
		},
		{
			name: "known usage retained on failure", relay: upstream.RelayOutcome{StatusCode: http.StatusOK, Usage: reported},
			execution: errors.New("private body failure"), wantStatus: quota.AttemptFailed,
			wantCode: "upstream_unavailable",
			wantUsage: quota.Usage{
				InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
				Known: true, Provenance: quota.ProviderReportedProvenance,
			},
		},
		{
			name: "unknown usage retained on failure", relay: upstream.RelayOutcome{StatusCode: http.StatusBadGateway},
			execution: upstream.ErrUpstreamNonSuccess, wantStatus: quota.AttemptFailed,
			wantCode: "upstream_non_success", wantUsage: unknownQuotaUsage(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := quotaOutcome(test.relay, quota.Cost{}, test.execution)
			if outcome.Status != test.wantStatus || outcome.HTTPStatus != test.relay.StatusCode ||
				outcome.FailureCode != test.wantCode || outcome.Usage != test.wantUsage {
				t.Fatalf("quota outcome = %#v, want status=%s code=%s usage=%#v",
					outcome, test.wantStatus, test.wantCode, test.wantUsage)
			}
		})
	}
}

func TestConfiguredPricingCaptureAndCostCalculation(t *testing.T) {
	t.Parallel()
	revision := id.Must(id.ConfigRevision)
	effectiveAt := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	catalog := configuration.PricingCatalog{
		ID: "standard", Currency: quota.USDCurrency, EffectiveAt: &effectiveAt,
		Entries: []configuration.PricingEntry{{
			ModelID: "provider_model", InputNanoUSDPerMillion: 2_000_000_001,
			OutputNanoUSDPerMillion: 6_000_000_001, RequestNanoUSD: 1_234,
		}},
	}
	selected, err := captureConfiguredPricing(
		"standard", revision, "provider_model", catalog, catalog.Entries[0], effectiveAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("capture configured pricing: %v", err)
	}
	if !selected.configured || selected.quotaSelection != (quota.PricingSelection{
		CatalogID: "standard", Currency: quota.USDCurrency,
	}) || selected.source.CatalogID() != "standard" || selected.source.PriceRevision() != revision {
		t.Fatalf("captured configured pricing = %#v", selected)
	}

	cost, executionErr := calculateConfiguredCost(selected, protocol.Usage{
		InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
		Known: true, Provenance: quota.ProviderReportedProvenance,
	}, nil)
	if executionErr != nil || cost != (quota.Cost{
		NanoUSD: 65_236, Known: true, Confidence: quota.CalculatedCostConfidence,
	}) {
		t.Fatalf("calculated configured cost = %#v err=%v", cost, executionErr)
	}

	providerFailure := fmt.Errorf("%w: private failure", errUpstreamRelay)
	cost, executionErr = calculateConfiguredCost(selected, protocol.Usage{
		InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
		Known: true, Provenance: quota.ProviderReportedProvenance,
	}, providerFailure)
	if cost.NanoUSD != 65_236 || !cost.Known || executionErr != providerFailure {
		t.Fatalf("known failed-attempt cost = %#v err=%v", cost, executionErr)
	}
	failedOutcome := quotaOutcome(upstream.RelayOutcome{
		StatusCode: http.StatusOK,
		Usage: protocol.Usage{
			InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
			Known: true, Provenance: quota.ProviderReportedProvenance,
		},
	}, cost, executionErr)
	if failedOutcome.Status != quota.AttemptFailed ||
		failedOutcome.FailureCode != "upstream_unavailable" || failedOutcome.Cost != cost {
		t.Fatalf("known failed-attempt outcome = %#v", failedOutcome)
	}
}

func TestConfiguredPricingDistinguishesZeroUnknownAndUnpricedCost(t *testing.T) {
	t.Parallel()
	source, err := pricing.NewSource("free", id.Must(id.ConfigRevision))
	if err != nil {
		t.Fatalf("construct configured pricing source: %v", err)
	}
	selected := configuredPricing{
		configured: true,
		quotaSelection: quota.PricingSelection{
			CatalogID: "free", Currency: quota.USDCurrency,
		},
		source: source,
	}
	knownUsage := protocol.Usage{Known: true, Provenance: quota.ProviderReportedProvenance}

	zero, executionErr := calculateConfiguredCost(selected, knownUsage, nil)
	if executionErr != nil || zero != (quota.Cost{
		Known: true, Confidence: quota.CalculatedCostConfidence,
	}) {
		t.Fatalf("known zero configured cost = %#v err=%v", zero, executionErr)
	}
	unknown, executionErr := calculateConfiguredCost(selected, protocol.Usage{}, nil)
	if executionErr != nil || unknown != (quota.Cost{}) {
		t.Fatalf("unknown configured cost = %#v err=%v", unknown, executionErr)
	}
	unpriced, executionErr := calculateConfiguredCost(configuredPricing{}, knownUsage, nil)
	if executionErr != nil || unpriced != (quota.Cost{}) {
		t.Fatalf("unpriced cost = %#v err=%v", unpriced, executionErr)
	}
}

func TestConfiguredPricingOverflowClassificationPreservesEarlierFailure(t *testing.T) {
	t.Parallel()
	source, err := pricing.NewSource("expensive", id.Must(id.ConfigRevision))
	if err != nil {
		t.Fatalf("construct configured pricing source: %v", err)
	}
	selected := configuredPricing{
		configured: true,
		quotaSelection: quota.PricingSelection{
			CatalogID: "expensive", Currency: quota.USDCurrency,
		},
		rates:  pricing.Rates{InputNanoUSDPerMillion: math.MaxInt64},
		source: source,
	}
	usage := protocol.Usage{
		InputTokens: math.MaxInt64, Known: true,
		Provenance: quota.ProviderReportedProvenance,
	}
	cost, executionErr := calculateConfiguredCost(selected, usage, nil)
	if cost != (quota.Cost{}) || !errors.Is(executionErr, errPricingUnavailable) {
		t.Fatalf("overflow classification = cost:%#v err:%v", cost, executionErr)
	}

	providerFailure := fmt.Errorf("%w: private failure", errUpstreamRelay)
	cost, executionErr = calculateConfiguredCost(selected, usage, providerFailure)
	if cost != (quota.Cost{}) || executionErr != providerFailure ||
		errors.Is(executionErr, errPricingUnavailable) {
		t.Fatalf("overflow masked earlier failure = cost:%#v err:%v", cost, executionErr)
	}
}

func TestConfiguredPricingCaptureRejectsFutureAndStructuralCorruption(t *testing.T) {
	t.Parallel()
	revision := id.Must(id.ConfigRevision)
	now := time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC)
	validEntry := configuration.PricingEntry{
		ModelID: "provider_model", InputNanoUSDPerMillion: 1,
		OutputNanoUSDPerMillion: 2, RequestNanoUSD: 3,
	}
	future := now.Add(time.Hour)
	_, err := captureConfiguredPricing(
		"standard", revision, "provider_model",
		configuration.PricingCatalog{
			ID: "standard", Currency: quota.USDCurrency, EffectiveAt: &future,
			Entries: []configuration.PricingEntry{validEntry},
		},
		validEntry,
		now,
	)
	if !errors.Is(err, errPricingUnavailable) {
		t.Fatalf("future pricing error = %v", err)
	}

	tests := []struct {
		name    string
		ref     string
		modelID string
		catalog configuration.PricingCatalog
		entry   configuration.PricingEntry
	}{
		{
			name: "bad reference", ref: "Bad", modelID: "provider_model",
			catalog: configuration.PricingCatalog{
				ID: "Bad", Currency: quota.USDCurrency, Entries: []configuration.PricingEntry{validEntry},
			}, entry: validEntry,
		},
		{
			name: "catalog mismatch", ref: "standard", modelID: "provider_model",
			catalog: configuration.PricingCatalog{
				ID: "other", Currency: quota.USDCurrency, Entries: []configuration.PricingEntry{validEntry},
			}, entry: validEntry,
		},
		{
			name: "currency mismatch", ref: "standard", modelID: "provider_model",
			catalog: configuration.PricingCatalog{
				ID: "standard", Currency: "EUR", Entries: []configuration.PricingEntry{validEntry},
			}, entry: validEntry,
		},
		{
			name: "entry mismatch", ref: "standard", modelID: "provider_model",
			catalog: configuration.PricingCatalog{
				ID: "standard", Currency: quota.USDCurrency, Entries: []configuration.PricingEntry{validEntry},
			}, entry: configuration.PricingEntry{ModelID: "other"},
		},
		{
			name: "duplicate model entry", ref: "standard", modelID: "provider_model",
			catalog: configuration.PricingCatalog{
				ID: "standard", Currency: quota.USDCurrency,
				Entries: []configuration.PricingEntry{validEntry, validEntry},
			}, entry: validEntry,
		},
		{
			name: "negative rate", ref: "standard", modelID: "provider_model",
			catalog: configuration.PricingCatalog{
				ID: "standard", Currency: quota.USDCurrency,
				Entries: []configuration.PricingEntry{{ModelID: "provider_model", RequestNanoUSD: -1}},
			}, entry: configuration.PricingEntry{ModelID: "provider_model", RequestNanoUSD: -1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, captureErr := captureConfiguredPricing(
				test.ref, revision, test.modelID, test.catalog, test.entry, now,
			)
			if !errors.Is(captureErr, policy.ErrConfiguration) {
				t.Fatalf("capture error = %v", captureErr)
			}
		})
	}
}

func TestHandlerRejectsMissingConfiguredPricingBeforeQuotaOrDispatch(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.Model.PricingRef = "missing"
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "configuration_invalid", http.StatusUnprocessableEntity)
	if fixture.quotas.reserveCalls != 0 || fixture.quotas.beginCalls != 0 ||
		fixture.targets.calls != 0 || fixture.target.dispatchCalls != 0 {
		t.Fatalf("missing pricing reached quota/target/dispatch: %d/%d/%d/%d",
			fixture.quotas.reserveCalls, fixture.quotas.beginCalls,
			fixture.targets.calls, fixture.target.dispatchCalls)
	}
}

func TestPricingUnavailableUsesStableRetryableFeatureProblem(t *testing.T) {
	t.Parallel()
	if code := failureCode(errPricingUnavailable); code != "pricing_unavailable" {
		t.Fatalf("pricing failure code = %q", code)
	}
	code, retryAfter := errorCode(errPricingUnavailable, time.Now())
	if code != "pricing_unavailable" || retryAfter != 0 || !problemIncludesFeature(code) ||
		safeProblemDetail(code) != "The configured price for the selected model is not available." {
		t.Fatalf("pricing problem mapping = %q retry=%d feature=%t detail=%q",
			code, retryAfter, problemIncludesFeature(code), safeProblemDetail(code))
	}
	recorder := httptest.NewRecorder()
	writeProblem(recorder, "request_pricing_test", code, "assistant", retryAfter)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("pricing problem status = %d", recorder.Code)
	}
	var document struct {
		Code      string `json:"code"`
		Feature   string `json:"feature"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode pricing problem: %v", err)
	}
	if document.Code != "pricing_unavailable" || document.Feature != "assistant" || !document.Retryable {
		t.Fatalf("pricing problem = %+v", document)
	}
}

func TestHandlerMapsConcurrencyDenialBeforeDispatch(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.LimitPlan.Limits = []configuration.Limit{{
		Metric: quota.ConcurrentRequestsMetric, Algorithm: quota.ConcurrencyAlgorithm,
		Scope: []string{"environment", "feature"}, Maximum: 1, Hard: true,
	}}
	fixture.quotas.reserveErr = fmt.Errorf("durable concurrency decision: %w", quota.ErrConcurrencyExceeded)
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	assertProblemCode(t, response, "concurrency_exceeded", http.StatusTooManyRequests)
	if response.Header().Get("Retry-After") != "" {
		t.Fatalf("concurrency denial Retry-After = %q, want absent", response.Header().Get("Retry-After"))
	}
	var document struct {
		Code       string  `json:"code"`
		Detail     string  `json:"detail"`
		Feature    string  `json:"feature"`
		Retryable  bool    `json:"retryable"`
		RetryAfter *string `json:"retry_after"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode concurrency problem: %v", err)
	}
	if document.Code != "concurrency_exceeded" ||
		document.Detail != "The configured concurrency limit has been reached." ||
		document.Feature != "assistant" || !document.Retryable || document.RetryAfter != nil {
		t.Fatalf("concurrency problem = %+v", document)
	}
	code, retryAfter := errorCode(quota.ErrConcurrencyExceeded, fixture.now)
	if code != "concurrency_exceeded" || retryAfter != 0 || !problemIncludesFeature(code) ||
		safeProblemDetail(code) != "The configured concurrency limit has been reached." {
		t.Fatalf("concurrency mapping = %q retry=%d feature=%t detail=%q",
			code, retryAfter, problemIncludesFeature(code), safeProblemDetail(code))
	}
	if fixture.quotas.reserveCalls != 1 || fixture.quotas.beginCalls != 0 ||
		fixture.targets.calls != 0 || fixture.target.dispatchCalls != 0 {
		t.Fatalf("concurrency denial reached post-reservation lifecycle: reserve/begin/target/dispatch=%d/%d/%d/%d",
			fixture.quotas.reserveCalls, fixture.quotas.beginCalls,
			fixture.targets.calls, fixture.target.dispatchCalls)
	}
}

func TestHandlerClassifiesProviderUsageAboveAppliedMaximumWithoutRewritingClientResponse(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.decision.LimitPlan.Limits = []configuration.Limit{{
		Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
		Scope: []string{"environment", "user"}, PerRequestMaximum: 8, Hard: true,
	}}
	fixture.relayer.outcome = upstream.RelayOutcome{
		StatusCode: http.StatusOK, BodyBytes: 11, ClientStarted: true,
		Usage: protocol.Usage{
			InputTokens: 2, OutputTokens: 9, TotalTokens: 11,
			Known: true, Provenance: quota.ProviderReportedProvenance,
		},
	}
	fixture.relayer.body = `{"ok":true}`
	handler := fixture.handler(t)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, fixture.request(t))

	if response.Code != http.StatusOK || response.Body.String() != `{"ok":true}` {
		t.Fatalf("already-relayed client response = (%d, %q)", response.Code, response.Body.String())
	}
	if fixture.quotas.settleCalls != 1 || fixture.quotas.settleOutcome.Status != quota.AttemptFailed ||
		fixture.quotas.settleOutcome.HTTPStatus != http.StatusOK ||
		fixture.quotas.settleOutcome.FailureCode != "upstream_protocol_error" {
		t.Fatalf("over-reported settlement classification = %#v", fixture.quotas.settleOutcome)
	}
	wantUsage := quota.Usage{
		InputTokens: 2, OutputTokens: 9, TotalTokens: 11,
		Known: true, Provenance: quota.ProviderReportedProvenance,
	}
	if fixture.quotas.settleOutcome.Usage != wantUsage {
		t.Fatalf("over-reported measured usage = %#v, want %#v", fixture.quotas.settleOutcome.Usage, wantUsage)
	}
	if len(fixture.quotas.reserveInput.Rules) != 1 || fixture.quotas.reserveInput.Rules[0].ReservedUnits != 8 {
		t.Fatalf("over-reported request reservation = %#v, want conservative full cap 8",
			fixture.quotas.reserveInput.Rules)
	}
}

func TestPolicyEngineRejectsUnsealedAuthorizationBeforeCELResolution(t *testing.T) {
	resolver := &fakePolicyResolver{}
	engine, err := NewPolicyEngine(resolver)
	if err != nil {
		t.Fatalf("construct policy engine: %v", err)
	}
	ctx, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatalf("create logical request context: %v", err)
	}
	logicalID, ok := requestidentity.FromContext(ctx)
	if !ok {
		t.Fatal("logical request identity missing")
	}

	_, err = engine.Resolve(
		ctx,
		configuration.ActiveSnapshot{},
		"assistant",
		session.Authorization{},
		logicalID,
		protocol.RequestMetadata{},
	)
	if !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("unsealed authorization error = %v", err)
	}
	if resolver.calls != 0 {
		t.Fatal("unsealed authorization reached CEL resolution")
	}
}

type handlerFixture struct {
	now           time.Time
	authorization session.Authorization
	snapshot      configuration.ActiveSnapshot
	decision      policy.Decision
	verifier      *fakeAccessVerifier
	sessions      *fakeSessionAuthorizer
	snapshots     *fakeSnapshotLoader
	policies      *fakePolicyEngine
	quotas        *fakeQuotaStore
	secret        *fakeSecretStore
	target        *fakeDispatchTarget
	targets       *fakeTargetFactory
	relayer       *fakeRelayer
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	now := time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC)
	authorization := session.Authorization{
		OrganizationID: id.Must(id.Organization), ApplicationID: id.Must(id.Application),
		EnvironmentID: id.Must(id.Environment), EnvironmentKind: "development",
		ApplicationUserID: id.Must(id.ApplicationUser), InstallationID: id.Must(id.Installation),
		InstallationPlatform: "ios", SessionGrantID: id.Must(id.SessionGrant),
		PolicyRevisionID: id.Must(id.ConfigRevision),
	}
	decision := testDecision()
	secret := &fakeSecretStore{value: []byte("provider-token")}
	quotas := &fakeQuotaStore{beginOwner: true}
	target := &fakeDispatchTarget{response: testDispatchedResponse()}
	fixture := &handlerFixture{
		now: now, authorization: authorization,
		snapshot: configuration.ActiveSnapshot{
			RevisionID: authorization.PolicyRevisionID, EnvironmentID: authorization.EnvironmentID,
		},
		decision: decision,
		verifier: &fakeAccessVerifier{},
		sessions: &fakeSessionAuthorizer{authorization: authorization},
		quotas:   quotas, secret: secret, target: target,
		relayer: &fakeRelayer{outcome: upstream.RelayOutcome{StatusCode: http.StatusOK, ClientStarted: true}},
	}
	fixture.snapshots = &fakeSnapshotLoader{snapshot: fixture.snapshot}
	fixture.policies = &fakePolicyEngine{decision: decision}
	fixture.targets = &fakeTargetFactory{target: target}
	return fixture
}

func (fixture *handlerFixture) handler(t *testing.T) *Handler {
	t.Helper()
	fixture.sessions.authorization = fixture.authorization
	fixture.snapshots.snapshot = fixture.snapshot
	fixture.policies.decision = fixture.decision
	handler, err := New(Config{
		AccessTokens: fixture.verifier, Sessions: fixture.sessions,
		Configuration: fixture.snapshots, Policies: fixture.policies,
		Quotas: fixture.quotas, Secrets: fixture.secret, Targets: fixture.targets,
		Relayer: fixture.relayer, PublicOrigin: "https://gateway.example",
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	return handler
}

func (fixture *handlerFixture) request(t *testing.T) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://untrusted.example/v1/chat/completions", strings.NewReader(
		`{"model":"client-model","messages":[{"role":"user","content":"hello"}]}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", "ios")
	request.Header.Set("X-Latchway-SDK-Version", "1.2.3")
	request.Header.Set("X-Latchway-Feature", "assistant")
	request.Header.Set("X-Latchway-Request-ID", "client-request-123")
	request.Header.Set("Authorization", "DPoP "+strings.Repeat("t", 64))
	request.Header.Set("DPoP", strings.Repeat("a", 60)+".b.c")
	ctx, err := requestidentity.NewContext(request.Context())
	if err != nil {
		t.Fatalf("install logical request identity: %v", err)
	}
	return request.WithContext(ctx)
}

func testDecision() policy.Decision {
	return policy.Decision{
		Feature: configuration.Feature{
			ID: "assistant", Protocol: "openai_chat",
			Output: &configuration.OutputPolicy{DefaultMaximumTokens: 128, AbsoluteMaximumTokens: 512},
		},
		LimitPlan: configuration.LimitPlan{ID: "starter", Limits: []configuration.Limit{{
			Metric: quota.LogicalRequestsMetric, Algorithm: quota.CalendarAlgorithm,
			Scope: []string{"environment", "user"}, Window: "1d", Maximum: 100, Hard: true,
		}}},
		Route: configuration.Route{ID: "primary", ModelID: "provider_model", StickyBy: "none", Weight: 1},
		Model: configuration.Model{
			ID: "provider_model", UpstreamID: "provider", UpstreamModel: "provider-model",
			Capabilities: []string{"openai_chat"},
		},
		Upstream: configuration.Upstream{
			ID: "provider", Type: "openai_compatible", BaseURL: "https://provider.example/v1",
			Authentication: configuration.UpstreamAuthentication{Type: "none"},
			Timeouts: configuration.UpstreamTimeouts{
				Connect: time.Second, FirstByte: 2 * time.Second, Idle: 3 * time.Second, Total: time.Minute,
			},
			DestinationPolicy: configuration.UpstreamDestinationPolicy{
				AllowedPorts: []int{443}, DNSPinning: true,
			},
		},
	}
}

func testDispatchedResponse() *upstream.DispatchedResponse {
	return &upstream.DispatchedResponse{Response: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)),
	}}
}

func unknownQuotaUsage() quota.Usage {
	return quota.Usage{Known: false, Provenance: quota.UnknownUsageProvenance}
}

func assertProblemCode(t *testing.T, response *httptest.ResponseRecorder, code string, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d want %d; body=%s", response.Code, status, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("problem headers = %#v", response.Header())
	}
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if document["code"] != code || document["request_id"] != response.Header().Get("X-Latchway-Request-ID") {
		t.Fatalf("problem = %#v", document)
	}
}

type fakeAccessVerifier struct {
	calls     int
	principal session.AccessPrincipal
	err       error
}

func (fake *fakeAccessVerifier) Verify(_ context.Context, _ session.AccessToken) (session.AccessPrincipal, error) {
	fake.calls++
	return fake.principal, fake.err
}

type fakeSessionAuthorizer struct {
	calls         int
	input         session.AccessRequestInput
	authorization session.Authorization
	err           error
}

func (fake *fakeSessionAuthorizer) AuthorizeAccess(_ context.Context, input session.AccessRequestInput) (session.Authorization, error) {
	fake.calls++
	fake.input = input
	return fake.authorization, fake.err
}

type fakeSnapshotLoader struct {
	calls    int
	scope    configuration.TenantScope
	snapshot configuration.ActiveSnapshot
	err      error
}

func (fake *fakeSnapshotLoader) ActiveSnapshot(_ context.Context, scope configuration.TenantScope) (configuration.ActiveSnapshot, error) {
	fake.calls++
	fake.scope = scope
	return fake.snapshot, fake.err
}

type fakePolicyEngine struct {
	calls         int
	feature       string
	authorization session.Authorization
	logicalID     requestidentity.LogicalID
	metadata      protocol.RequestMetadata
	decision      policy.Decision
	err           error
}

type fakePolicyResolver struct {
	calls int
}

func (fake *fakePolicyResolver) Resolve(context.Context, policy.Snapshot, string, policy.Input) (policy.Decision, error) {
	fake.calls++
	return policy.Decision{}, nil
}

func (fake *fakePolicyEngine) Resolve(
	_ context.Context,
	_ configuration.ActiveSnapshot,
	feature string,
	authorization session.Authorization,
	logicalID requestidentity.LogicalID,
	metadata protocol.RequestMetadata,
) (policy.Decision, error) {
	fake.calls++
	fake.feature = feature
	fake.authorization = authorization
	fake.logicalID = logicalID
	fake.metadata = metadata
	return fake.decision, fake.err
}

type fakeQuotaStore struct {
	reserveCalls       int
	reserveInput       quota.ReserveInput
	reserveErr         error
	reserveHook        func()
	reservation        quota.Reservation
	beginCalls         int
	beginOwner         bool
	beginErr           error
	attempt            quota.Attempt
	markCalls          int
	markErr            error
	markBlock          bool
	markTimeout        time.Duration
	settleCalls        int
	settleOutcome      quota.Outcome
	settleErr          error
	releaseCalls       int
	releaseFailure     string
	releaseErr         error
	secret             *fakeSecretStore
	beginInsideSecret  bool
	settleInsideSecret bool
}

func (fake *fakeQuotaStore) Reserve(_ context.Context, input quota.ReserveInput) (quota.Reservation, error) {
	fake.reserveCalls++
	fake.reserveInput = input
	if fake.reserveHook != nil {
		fake.reserveHook()
	}
	return fake.reservation, fake.reserveErr
}

func (fake *fakeQuotaStore) BeginAttempt(_ context.Context, _ quota.Reservation) (quota.Attempt, bool, error) {
	fake.beginCalls++
	if fake.secret != nil {
		fake.beginInsideSecret = fake.secret.inside
	}
	return fake.attempt, fake.beginOwner, fake.beginErr
}

func (fake *fakeQuotaStore) MarkFirstByte(ctx context.Context, _ quota.Attempt) error {
	fake.markCalls++
	if deadline, ok := ctx.Deadline(); ok {
		fake.markTimeout = time.Until(deadline)
	}
	if fake.markBlock {
		<-ctx.Done()
		return ctx.Err()
	}
	return fake.markErr
}

func (fake *fakeQuotaStore) Settle(_ context.Context, _ quota.Attempt, outcome quota.Outcome) error {
	fake.settleCalls++
	fake.settleOutcome = outcome
	if fake.secret != nil {
		fake.settleInsideSecret = fake.secret.inside
	}
	return fake.settleErr
}

func (fake *fakeQuotaStore) ReleaseBeforeDispatch(_ context.Context, _ quota.Reservation, failure string) error {
	fake.releaseCalls++
	fake.releaseFailure = failure
	return fake.releaseErr
}

type fakeSecretStore struct {
	calls  int
	value  []byte
	err    error
	invoke bool
	inside bool
}

func (fake *fakeSecretStore) Use(_ context.Context, _ secrets.Scope, _ string, consume func([]byte) error) error {
	fake.calls++
	if fake.err != nil && !fake.invoke {
		return fake.err
	}
	fake.inside = true
	consumeErr := consume(append([]byte(nil), fake.value...))
	fake.inside = false
	if fake.err != nil {
		return fake.err
	}
	return consumeErr
}

type fakeTargetFactory struct {
	calls        int
	target       DispatchTarget
	err          error
	releaseCalls int
}

func (fake *fakeTargetFactory) Acquire(_ configuration.Upstream) (TargetLease, error) {
	fake.calls++
	if fake.err != nil {
		return nil, fake.err
	}
	return &fakeTargetLease{DispatchTarget: fake.target, release: func() { fake.releaseCalls++ }}, nil
}

type fakeTargetLease struct {
	DispatchTarget
	release func()
	once    sync.Once
}

func (lease *fakeTargetLease) Release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		if lease.release != nil {
			lease.release()
		}
	})
}

type fakeDispatchTarget struct {
	prepareCalls         int
	preparePath          string
	preparedBody         string
	preparedRequest      *http.Request
	prepareErr           error
	dispatchCalls        int
	bearerCalls          int
	headerCalls          int
	beforeCalls          int
	roundTripCalls       int
	preflightErr         error
	dispatchErr          error
	response             *upstream.DispatchedResponse
	closeCalls           int
	secret               *fakeSecretStore
	dispatchInsideSecret bool
}

func (fake *fakeDispatchTarget) Prepare(request *http.Request, path string, _ []string, _ map[string]string) (ProviderRequest, error) {
	fake.prepareCalls++
	fake.preparePath = path
	fake.preparedRequest = request
	if request != nil && request.Body != nil {
		body, _ := io.ReadAll(request.Body)
		fake.preparedBody = string(body)
		request.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	return ProviderRequest{}, fake.prepareErr
}

func (fake *fakeDispatchTarget) DispatchWithBeforeRoundTrip(
	ctx context.Context,
	_ ProviderRequest,
	beforeRoundTrip func() error,
) (*upstream.DispatchedResponse, error) {
	fake.dispatchCalls++
	if err := fake.runBeforeRoundTrip(ctx, beforeRoundTrip); err != nil {
		return nil, err
	}
	fake.roundTripCalls++
	fake.bindResponseRequest()
	return fake.response, fake.dispatchErr
}

func (fake *fakeDispatchTarget) WithBearerDispatchWithBeforeRoundTrip(
	ctx context.Context,
	_ ProviderRequest,
	_ []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	fake.bearerCalls++
	return fake.scoped(ctx, beforeRoundTrip, consume)
}

func (fake *fakeDispatchTarget) WithHeaderDispatchWithBeforeRoundTrip(
	ctx context.Context,
	_ ProviderRequest,
	_ string,
	_ []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	fake.headerCalls++
	return fake.scoped(ctx, beforeRoundTrip, consume)
}

func (fake *fakeDispatchTarget) runBeforeRoundTrip(ctx context.Context, beforeRoundTrip func() error) error {
	if fake.preflightErr != nil {
		return fake.preflightErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if beforeRoundTrip == nil {
		return errors.New("missing fake before-round-trip callback")
	}
	fake.beforeCalls++
	return beforeRoundTrip()
}

func (fake *fakeDispatchTarget) scoped(
	ctx context.Context,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if fake.secret != nil {
		fake.dispatchInsideSecret = fake.secret.inside
	}
	if err := fake.runBeforeRoundTrip(ctx, beforeRoundTrip); err != nil {
		return err
	}
	fake.roundTripCalls++
	if fake.dispatchErr != nil {
		return fake.dispatchErr
	}
	fake.bindResponseRequest()
	return consume(fake.response)
}

func (fake *fakeDispatchTarget) bindResponseRequest() {
	if fake.response != nil && fake.response.Response != nil {
		fake.response.Response.Request = fake.preparedRequest
	}
}

func (fake *fakeDispatchTarget) CloseIdleConnections() { fake.closeCalls++ }

type countingResolver struct {
	calls atomic.Int32
}

func (resolver *countingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	resolver.calls.Add(1)
	return nil, errors.New("unexpected production test DNS lookup")
}

func newProductionDispatchTarget(t *testing.T) (*protectedDispatchTarget, *countingResolver) {
	t.Helper()
	resolver := &countingResolver{}
	target, err := upstream.NewTarget(
		"https://provider.example/v1",
		upstream.DestinationPolicy{AllowPrivate: false},
		upstream.Timeouts{
			Connect: time.Second, TLSHandshake: time.Second,
			ResponseHeader: time.Second, IdleConnection: time.Second,
		},
		resolver,
	)
	if err != nil {
		t.Fatalf("construct production dispatch target: %v", err)
	}
	t.Cleanup(target.CloseIdleConnections)
	return &protectedDispatchTarget{target: target}, resolver
}

type fakeRelayer struct {
	calls        int
	outcome      upstream.RelayOutcome
	err          error
	body         string
	secret       *fakeSecretStore
	insideSecret bool
}

type trackingReadCloser struct {
	reader    io.Reader
	readCalls int
	closed    bool
}

func (body *trackingReadCloser) Read(destination []byte) (int, error) {
	body.readCalls++
	return body.reader.Read(destination)
}

func (body *trackingReadCloser) Close() error {
	body.closed = true
	return nil
}

func (fake *fakeRelayer) Relay(
	ctx context.Context,
	writer http.ResponseWriter,
	_ *upstream.DispatchedResponse,
	_ protocol.ResponseObserver,
	config upstream.ResponseRelayConfig,
) (upstream.RelayOutcome, error) {
	fake.calls++
	if fake.secret != nil {
		fake.insideSecret = fake.secret.inside
	}
	if config.OnFirstByte != nil && fake.body != "" {
		if err := config.OnFirstByte(ctx); err != nil {
			return upstream.RelayOutcome{}, err
		}
	}
	if fake.outcome.ClientStarted {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(fake.outcome.StatusCode)
		_, _ = writer.Write([]byte(fake.body))
	}
	return fake.outcome, fake.err
}
