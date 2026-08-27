package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithBearerDispatchRetainsCredentialUntilExactBodyClose(t *testing.T) {
	t.Parallel()

	body := &credentialObservingBody{}
	var outbound *http.Request
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		outbound = request
		body.request = request
		if got := request.Header.Get("Authorization"); got != "Bearer server-secret" {
			t.Fatalf("authorization during RoundTrip = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       body,
			Request:    request,
		}, nil
	}))
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	prepared := testPreparedRequest(t, parent, target)

	consumed := false
	err := target.WithBearerDispatch(parent, prepared, []byte("server-secret"), func(dispatched *DispatchedResponse) error {
		consumed = true
		if dispatched == nil || dispatched.Response == nil || dispatched.Request == nil {
			t.Fatal("consumer received an invalid response")
		}
		if got := dispatched.Request.Header.Get("Authorization"); got != "" {
			t.Fatalf("consumer-visible response request retained authorization = %q", got)
		}
		if got := outbound.Header.Get("Authorization"); got != "Bearer server-secret" {
			t.Fatalf("transport request lost authorization before body close = %q", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBearerDispatch() error = %v", err)
	}
	if !consumed || outbound == nil || outbound == prepared.request || outbound.Context() == parent {
		t.Fatal("dispatch did not clone and consume the request on a dedicated child context")
	}
	if got := prepared.request.Header.Get("Authorization"); got != "" {
		t.Fatalf("prepared request retained authorization = %q", got)
	}
	if got := outbound.Header.Get("Authorization"); got != "" {
		t.Fatalf("transport request retained authorization after body close = %q", got)
	}
	if got := body.credentialAtClose; got != "Bearer server-secret" {
		t.Fatalf("authorization during Body.Close = %q", got)
	}
	if body.closeCalls.Load() != 1 {
		t.Fatalf("response body close calls = %d, want one", body.closeCalls.Load())
	}
	select {
	case <-outbound.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("dedicated RoundTrip context was not canceled")
	}
	if parent.Err() != nil {
		t.Fatalf("closing RoundTrip canceled parent request: %v", parent.Err())
	}
}

func TestWithHeaderDispatchRetainsCredentialUntilExactBodyClose(t *testing.T) {
	t.Parallel()

	body := &credentialObservingBody{headerName: "X-Provider-Key"}
	var outbound *http.Request
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		outbound = request
		body.request = request
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	}))
	prepared := testPreparedRequest(t, context.Background(), target)
	if err := target.WithHeaderDispatch(context.Background(), prepared, "X-Provider-Key", []byte("server secret"), func(dispatched *DispatchedResponse) error {
		if got := outbound.Header.Get("X-Provider-Key"); got != "server secret" {
			t.Fatalf("credential during consumer = %q", got)
		}
		if got := dispatched.Request.Header.Get("X-Provider-Key"); got != "" {
			t.Fatalf("consumer-visible response request retained fixed credential = %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithHeaderDispatch() error = %v", err)
	}
	if got := body.credentialAtClose; got != "server secret" {
		t.Fatalf("fixed credential during Body.Close = %q", got)
	}
	if got := outbound.Header.Get("X-Provider-Key"); got != "" {
		t.Fatalf("transport request retained fixed credential = %q", got)
	}
}

func TestDispatchWithBeforeRoundTripOrdersHookImmediatelyBeforeTransport(t *testing.T) {
	t.Parallel()

	events := make([]string, 0, 2)
	hookCalls := 0
	transportCalls := 0
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		transportCalls++
		if got := strings.Join(events, ","); got != "before" {
			t.Fatalf("events before RoundTrip = %q, want before", got)
		}
		events = append(events, "round-trip")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    request,
		}, nil
	}))
	prepared := testPreparedRequest(t, context.Background(), target)

	response, err := target.DispatchWithBeforeRoundTrip(context.Background(), prepared, func() error {
		hookCalls++
		events = append(events, "before")
		return nil
	})
	if err != nil {
		t.Fatalf("DispatchWithBeforeRoundTrip() error = %v", err)
	}
	if err := response.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if hookCalls != 1 || transportCalls != 1 {
		t.Fatalf("hook calls=%d transport calls=%d, want one each", hookCalls, transportCalls)
	}
	if got := strings.Join(events, ","); got != "before,round-trip" {
		t.Fatalf("events = %q, want before,round-trip", got)
	}
}

func TestCredentialDispatchWithBeforeRoundTripOrdersCredentialHookTransportAndConsumer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headerName string
		wantValue  string
		dispatch   func(*Target, PreparedRequest, func() error, func(*DispatchedResponse) error) error
	}{
		{
			name:       "bearer",
			headerName: "Authorization",
			wantValue:  "Bearer server-secret",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithBearerDispatchWithBeforeRoundTrip(context.Background(), prepared, []byte("server-secret"), before, consume)
			},
		},
		{
			name:       "fixed header",
			headerName: "X-Provider-Key",
			wantValue:  "server secret",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(context.Background(), prepared, "X-Provider-Key", []byte("server secret"), before, consume)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			events := make([]string, 0, 3)
			hookCalls := 0
			body := &credentialObservingBody{headerName: test.headerName}
			var outbound *http.Request
			target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				outbound = request
				body.request = request
				if got := strings.Join(events, ","); got != "before" {
					t.Fatalf("events before RoundTrip = %q, want before", got)
				}
				if got := request.Header.Get(test.headerName); got != test.wantValue {
					t.Fatalf("credential during RoundTrip = %q, want %q", got, test.wantValue)
				}
				events = append(events, "round-trip")
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
			}))
			prepared := testPreparedRequest(t, context.Background(), target)

			err := test.dispatch(target, prepared, func() error {
				hookCalls++
				events = append(events, "before")
				return nil
			}, func(dispatched *DispatchedResponse) error {
				if got := dispatched.Request.Header.Get(test.headerName); got != "" {
					t.Fatalf("consumer-visible request retained credential = %q", got)
				}
				events = append(events, "consume")
				return nil
			})
			if err != nil {
				t.Fatalf("credential dispatch error = %v", err)
			}
			if hookCalls != 1 {
				t.Fatalf("hook calls = %d, want one", hookCalls)
			}
			if got := strings.Join(events, ","); got != "before,round-trip,consume" {
				t.Fatalf("events = %q, want before,round-trip,consume", got)
			}
			if got := body.credentialAtClose; got != test.wantValue {
				t.Fatalf("credential during Body.Close = %q, want %q", got, test.wantValue)
			}
			if got := outbound.Header.Get(test.headerName); got != "" {
				t.Fatalf("transport request retained credential after scope = %q", got)
			}
		})
	}
}

func TestSuccessfulBeforeRoundTripTransfersRequestBodyOwnershipAcrossAuthenticationModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dispatch func(*Target, PreparedRequest, func() error, func(*DispatchedResponse) error) error
	}{
		{
			name: "none",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, _ func(*DispatchedResponse) error) error {
				response, err := target.DispatchWithBeforeRoundTrip(context.Background(), prepared, before)
				if response != nil {
					_ = response.Close()
				}
				return err
			},
		},
		{
			name: "bearer",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithBearerDispatchWithBeforeRoundTrip(context.Background(), prepared, []byte("server-secret"), before, consume)
			},
		},
		{
			name: "fixed header",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(context.Background(), prepared, "X-Provider-Key", []byte("server secret"), before, consume)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requestBody := &trackingRequestBody{}
			target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if err := request.Body.Close(); err != nil {
					t.Fatalf("transport request Body.Close() error = %v", err)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
			}))
			prepared := testPreparedRequest(t, context.Background(), target)
			prepared.request.Body = requestBody
			err := test.dispatch(target, prepared, func() error { return nil }, func(*DispatchedResponse) error { return nil })
			if err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			if requestBody.closeCalls.Load() != 1 {
				t.Fatalf("request body close calls = %d, want transport's one close", requestBody.closeCalls.Load())
			}
		})
	}
}

func TestBeforeRoundTripRejectsInvalidPreparedRequestWithoutHook(t *testing.T) {
	t.Parallel()

	var hookCalls atomic.Int32
	var transportCalls atomic.Int32
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		transportCalls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}, nil
	}))
	claimed := testPreparedRequest(t, context.Background(), target)
	response, err := target.Dispatch(context.Background(), claimed)
	if err != nil {
		t.Fatalf("initial Dispatch() error = %v", err)
	}
	_ = response.Close()
	if _, err := target.DispatchWithBeforeRoundTrip(context.Background(), claimed, func() error {
		hookCalls.Add(1)
		return nil
	}); err == nil {
		t.Fatal("claimed prepared request was accepted")
	}

	invalid := testPreparedRequest(t, context.Background(), target)
	invalid.request.Header.Set("Authorization", "client-secret")
	if _, err := target.DispatchWithBeforeRoundTrip(context.Background(), invalid, func() error {
		hookCalls.Add(1)
		return nil
	}); err == nil {
		t.Fatal("invalid prepared request was accepted")
	}
	if hookCalls.Load() != 0 {
		t.Fatalf("hook calls = %d, want zero", hookCalls.Load())
	}
	if transportCalls.Load() != 1 {
		t.Fatalf("transport calls = %d, want only the initial dispatch", transportCalls.Load())
	}
}

func TestCredentialBeforeRoundTripRejectsMalformedConfigurationWithoutHookOrTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dispatch func(*Target, PreparedRequest, func() error) error
	}{
		{
			name: "malformed bearer credential",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error) error {
				return target.WithBearerDispatchWithBeforeRoundTrip(context.Background(), prepared, []byte("secret\nvalue"), before, func(*DispatchedResponse) error { return nil })
			},
		},
		{
			name: "forbidden fixed header",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(context.Background(), prepared, "Content-Type", []byte("secret"), before, func(*DispatchedResponse) error { return nil })
			},
		},
		{
			name: "malformed fixed credential",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(context.Background(), prepared, "X-Provider-Key", []byte("secret\nvalue"), before, func(*DispatchedResponse) error { return nil })
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var hookCalls atomic.Int32
			var transportCalls atomic.Int32
			target := testDispatchTarget(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls.Add(1)
				return nil, errors.New("transport must not run")
			}))
			prepared := testPreparedRequest(t, context.Background(), target)
			err := test.dispatch(target, prepared, func() error {
				hookCalls.Add(1)
				return nil
			})
			if err == nil {
				t.Fatal("malformed credential configuration was accepted")
			}
			if hookCalls.Load() != 0 || transportCalls.Load() != 0 {
				t.Fatalf("hook calls=%d transport calls=%d, want zero each", hookCalls.Load(), transportCalls.Load())
			}
		})
	}
}

func TestBeforeRoundTripErrorPreventsEveryAuthenticationModeTransport(t *testing.T) {
	t.Parallel()

	hookFailure := errors.New("quota ownership unavailable")
	tests := []struct {
		name     string
		dispatch func(*Target, PreparedRequest, func() error, func(*DispatchedResponse) error) error
	}{
		{
			name: "none",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, _ func(*DispatchedResponse) error) error {
				response, err := target.DispatchWithBeforeRoundTrip(context.Background(), prepared, before)
				if response != nil {
					_ = response.Close()
				}
				return err
			},
		},
		{
			name: "bearer",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithBearerDispatchWithBeforeRoundTrip(context.Background(), prepared, []byte("server-secret"), before, consume)
			},
		},
		{
			name: "fixed header",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(context.Background(), prepared, "X-Provider-Key", []byte("server secret"), before, consume)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var hookCalls atomic.Int32
			var transportCalls atomic.Int32
			var consumeCalls atomic.Int32
			target := testDispatchTarget(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls.Add(1)
				return nil, errors.New("transport must not run")
			}))
			prepared := testPreparedRequest(t, context.Background(), target)
			requestBody := &trackingRequestBody{}
			prepared.request.Body = requestBody
			err := test.dispatch(target, prepared, func() error {
				hookCalls.Add(1)
				return hookFailure
			}, func(*DispatchedResponse) error {
				consumeCalls.Add(1)
				return nil
			})
			if !errors.Is(err, hookFailure) {
				t.Fatalf("dispatch error = %v, want wrapped hook failure", err)
			}
			if hookCalls.Load() != 1 || transportCalls.Load() != 0 || consumeCalls.Load() != 0 {
				t.Fatalf("hook calls=%d transport calls=%d consume calls=%d, want 1,0,0", hookCalls.Load(), transportCalls.Load(), consumeCalls.Load())
			}
			if requestBody.closeCalls.Load() != 1 {
				t.Fatalf("request body close calls = %d, want one", requestBody.closeCalls.Load())
			}
		})
	}
}

func TestCanceledContextPreventsBeforeRoundTripAndEveryAuthenticationModeTransport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dispatch func(context.Context, *Target, PreparedRequest, func() error, func(*DispatchedResponse) error) error
	}{
		{
			name: "none",
			dispatch: func(ctx context.Context, target *Target, prepared PreparedRequest, before func() error, _ func(*DispatchedResponse) error) error {
				response, err := target.DispatchWithBeforeRoundTrip(ctx, prepared, before)
				if response != nil {
					_ = response.Close()
				}
				return err
			},
		},
		{
			name: "bearer",
			dispatch: func(ctx context.Context, target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithBearerDispatchWithBeforeRoundTrip(ctx, prepared, []byte("server-secret"), before, consume)
			},
		},
		{
			name: "fixed header",
			dispatch: func(ctx context.Context, target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(ctx, prepared, "X-Provider-Key", []byte("server secret"), before, consume)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var hookCalls atomic.Int32
			var transportCalls atomic.Int32
			var consumeCalls atomic.Int32
			target := testDispatchTarget(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls.Add(1)
				return nil, errors.New("transport must not run")
			}))
			prepared := testPreparedRequest(t, context.Background(), target)
			requestBody := &trackingRequestBody{}
			prepared.request.Body = requestBody
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := test.dispatch(ctx, target, prepared, func() error {
				hookCalls.Add(1)
				return nil
			}, func(*DispatchedResponse) error {
				consumeCalls.Add(1)
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("dispatch error = %v, want context canceled", err)
			}
			if hookCalls.Load() != 0 || transportCalls.Load() != 0 || consumeCalls.Load() != 0 {
				t.Fatalf("hook calls=%d transport calls=%d consume calls=%d, want zero each", hookCalls.Load(), transportCalls.Load(), consumeCalls.Load())
			}
			if requestBody.closeCalls.Load() != 1 {
				t.Fatalf("request body close calls = %d, want one", requestBody.closeCalls.Load())
			}
		})
	}
}

func TestBeforeRoundTripPanicClosesRequestBodyAcrossEveryAuthenticationMode(t *testing.T) {
	t.Parallel()

	panicValue := &struct{ message string }{message: "quota panic"}
	tests := []struct {
		name     string
		dispatch func(*Target, PreparedRequest, func() error, func(*DispatchedResponse) error) error
	}{
		{
			name: "none",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, _ func(*DispatchedResponse) error) error {
				response, err := target.DispatchWithBeforeRoundTrip(context.Background(), prepared, before)
				if response != nil {
					_ = response.Close()
				}
				return err
			},
		},
		{
			name: "bearer",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithBearerDispatchWithBeforeRoundTrip(context.Background(), prepared, []byte("server-secret"), before, consume)
			},
		},
		{
			name: "fixed header",
			dispatch: func(target *Target, prepared PreparedRequest, before func() error, consume func(*DispatchedResponse) error) error {
				return target.WithHeaderDispatchWithBeforeRoundTrip(context.Background(), prepared, "X-Provider-Key", []byte("server secret"), before, consume)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var hookCalls atomic.Int32
			var transportCalls atomic.Int32
			var consumeCalls atomic.Int32
			target := testDispatchTarget(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				transportCalls.Add(1)
				return nil, errors.New("transport must not run")
			}))
			prepared := testPreparedRequest(t, context.Background(), target)
			requestBody := &trackingRequestBody{}
			prepared.request.Body = requestBody
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_ = test.dispatch(target, prepared, func() error {
					hookCalls.Add(1)
					panic(panicValue)
				}, func(*DispatchedResponse) error {
					consumeCalls.Add(1)
					return nil
				})
			}()
			if recovered != panicValue {
				t.Fatalf("recovered panic = %#v, want original panic", recovered)
			}
			if hookCalls.Load() != 1 || transportCalls.Load() != 0 || consumeCalls.Load() != 0 {
				t.Fatalf("hook calls=%d transport calls=%d consume calls=%d, want 1,0,0", hookCalls.Load(), transportCalls.Load(), consumeCalls.Load())
			}
			if requestBody.closeCalls.Load() != 1 {
				t.Fatalf("request body close calls = %d, want one", requestBody.closeCalls.Load())
			}
		})
	}
}

func TestCredentialScopeSurvivesBodyCloseAndCleansOnEveryPreRoundTripExit(t *testing.T) {
	t.Parallel()

	hookFailure := errors.New("before-round-trip failure")
	panicValue := &struct{ message string }{message: "before-round-trip panic"}
	authenticationModes := []struct {
		name       string
		headerName string
		wantValue  string
		credential credentialScope
	}{
		{
			name:       "bearer",
			headerName: "Authorization",
			wantValue:  "Bearer server-secret",
			credential: func(headers http.Header, operation func() error) error {
				return withBearerCredential(headers, []byte("server-secret"), operation)
			},
		},
		{
			name:       "fixed header",
			headerName: "X-Provider-Key",
			wantValue:  "server secret",
			credential: func(headers http.Header, operation func() error) error {
				return withHeaderCredential(headers, "X-Provider-Key", []byte("server secret"), operation)
			},
		},
	}
	scenarios := []struct {
		name          string
		context       func() context.Context
		before        func() error
		wantError     error
		wantPanic     any
		wantHookCalls int32
	}{
		{
			name: "canceled context",
			context: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			before:    func() error { return nil },
			wantError: context.Canceled,
		},
		{
			name:          "hook error",
			context:       context.Background,
			before:        func() error { return hookFailure },
			wantError:     hookFailure,
			wantHookCalls: 1,
		},
		{
			name:    "hook panic",
			context: context.Background,
			before: func() error {
				panic(panicValue)
			},
			wantPanic:     panicValue,
			wantHookCalls: 1,
		},
	}

	for _, authentication := range authenticationModes {
		for _, scenario := range scenarios {
			t.Run(authentication.name+"/"+scenario.name, func(t *testing.T) {
				t.Parallel()

				var scopedHeaders http.Header
				var credentialAtBodyClose string
				var hookCalls atomic.Int32
				var transportCalls atomic.Int32
				var consumeCalls atomic.Int32
				target := testDispatchTarget(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
					transportCalls.Add(1)
					return nil, errors.New("transport must not run")
				}))
				prepared := testPreparedRequest(t, context.Background(), target)
				requestBody := &trackingRequestBody{onClose: func() {
					credentialAtBodyClose = scopedHeaders.Get(authentication.headerName)
				}}
				prepared.request.Body = requestBody
				captureScope := func(headers http.Header, operation func() error) error {
					scopedHeaders = headers
					return authentication.credential(headers, operation)
				}
				var dispatchErr error
				var recovered any
				func() {
					defer func() { recovered = recover() }()
					dispatchErr = target.withCredentialDispatch(scenario.context(), prepared, func() error {
						hookCalls.Add(1)
						return scenario.before()
					}, func(*DispatchedResponse) error {
						consumeCalls.Add(1)
						return nil
					}, captureScope)
				}()
				if recovered != scenario.wantPanic {
					t.Fatalf("recovered panic = %#v, want %#v", recovered, scenario.wantPanic)
				}
				if scenario.wantPanic == nil && !errors.Is(dispatchErr, scenario.wantError) {
					t.Fatalf("dispatch error = %v, want %v", dispatchErr, scenario.wantError)
				}
				if hookCalls.Load() != scenario.wantHookCalls || transportCalls.Load() != 0 || consumeCalls.Load() != 0 {
					t.Fatalf("hook calls=%d transport calls=%d consume calls=%d, want %d,0,0", hookCalls.Load(), transportCalls.Load(), consumeCalls.Load(), scenario.wantHookCalls)
				}
				if requestBody.closeCalls.Load() != 1 {
					t.Fatalf("request body close calls = %d, want one", requestBody.closeCalls.Load())
				}
				if credentialAtBodyClose != authentication.wantValue {
					t.Fatalf("credential during request Body.Close = %q, want %q", credentialAtBodyClose, authentication.wantValue)
				}
				if got := scopedHeaders.Get(authentication.headerName); got != "" {
					t.Fatalf("credential survived pre-RoundTrip exit = %q", got)
				}
			})
		}
	}
}

func TestCredentialScopesDeleteHeadersWhenOperationPanics(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		header    string
		operation func(http.Header)
	}{
		{
			name:   "bearer",
			header: "Authorization",
			operation: func(headers http.Header) {
				_ = withBearerCredential(headers, []byte("server-secret"), func() error {
					panic("transport panic")
				})
			},
		},
		{
			name:   "fixed header",
			header: "X-Provider-Key",
			operation: func(headers http.Header) {
				_ = withHeaderCredential(headers, "X-Provider-Key", []byte("server secret"), func() error {
					panic("transport panic")
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			headers := make(http.Header)
			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("credential operation did not panic")
					}
				}()
				test.operation(headers)
			}()
			if values := headers.Values(test.header); len(values) != 0 {
				t.Fatalf("credential survived panic = %#v", values)
			}
		})
	}
}

func TestScopedDispatchClosesBodyBeforePanicLeavesCredentialScope(t *testing.T) {
	t.Parallel()

	body := &credentialObservingBody{}
	var outbound *http.Request
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		outbound = request
		body.request = request
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	}))
	prepared := testPreparedRequest(t, context.Background(), target)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("consumer did not panic")
			}
		}()
		_ = target.WithBearerDispatch(context.Background(), prepared, []byte("server-secret"), func(*DispatchedResponse) error {
			panic("consumer panic")
		})
	}()
	if got := body.credentialAtClose; got != "Bearer server-secret" {
		t.Fatalf("authorization during panic cleanup Body.Close = %q", got)
	}
	if got := outbound.Header.Get("Authorization"); got != "" {
		t.Fatalf("authorization survived panic cleanup = %q", got)
	}
}

func TestDispatchRejectsRetainedClientCredentialBeforeTransport(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	target := testDispatchTarget(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("transport must not run")
	}))
	for _, name := range []string{"Authorization", "DPoP", "Cookie", "X-Api-Key", "Anthropic-Api-Key"} {
		prepared := testPreparedRequest(t, context.Background(), target)
		prepared.request.Header.Set(name, "client-secret")
		if _, err := target.Dispatch(context.Background(), prepared); err == nil {
			t.Fatalf("retained client credential %s was accepted", name)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("transport calls = %d, want zero", calls.Load())
	}
}

func TestDispatchRejectsPreparedRequestForAnotherAuthority(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("transport must not run")
	})
	first := testDispatchTarget(t, transport)
	secondURL, err := url.Parse("https://other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	second := &Target{baseURL: secondURL, client: &http.Client{Transport: transport}}
	prepared := testPreparedRequest(t, context.Background(), first)
	if _, err := second.Dispatch(context.Background(), prepared); err == nil {
		t.Fatal("prepared request was accepted by a different target")
	}
	prepared.request.URL, _ = url.Parse("https://attacker.example/steal")
	if _, err := first.Dispatch(context.Background(), prepared); err == nil {
		t.Fatal("prepared request with replaced authority was accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("transport calls = %d, want zero", calls.Load())
	}
}

func TestPreparedRequestIsOneShotAcrossCopies(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}, nil
	}))
	prepared := testPreparedRequest(t, context.Background(), target)
	copyOfCapability := prepared

	start := make(chan struct{})
	errorsByCall := make(chan error, 2)
	for _, capability := range []PreparedRequest{prepared, copyOfCapability} {
		go func(candidate PreparedRequest) {
			<-start
			response, err := target.Dispatch(context.Background(), candidate)
			if response != nil {
				_ = response.Close()
			}
			errorsByCall <- err
		}(capability)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-errorsByCall; err == nil {
			successes++
		}
	}
	if successes != 1 || calls.Load() != 1 {
		t.Fatalf("dispatch successes=%d transport calls=%d, want one each", successes, calls.Load())
	}
}

func TestRelayIdleTimeoutCancelsRoundTripWhenBodyCloseCannotUnblockRead(t *testing.T) {
	t.Parallel()

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	body := &cancelOnlyResponseBody{readStarted: make(chan struct{}), readFinished: make(chan struct{})}
	var roundTripContext context.Context
	target := testDispatchTarget(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		roundTripContext = request.Context()
		body.ctx = request.Context()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       body,
			Request:    request,
		}, nil
	}))
	prepared := testPreparedRequest(t, parent, target)
	dispatched, err := target.Dispatch(parent, prepared)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	config := validRelayConfig()
	config.IdleTimeout = 20 * time.Millisecond
	started := time.Now()
	outcome, err := RelayResponse(parent, newRelayResponseWriter(), dispatched, &recordingResponseObserver{}, config)
	if !errors.Is(err, ErrResponseIdleTimeout) || outcome.ClientStarted {
		t.Fatalf("idle timeout: outcome=%#v err=%v", outcome, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("relay did not return after canceling the RoundTrip context")
	}
	select {
	case <-body.readFinished:
	case <-time.After(time.Second):
		t.Fatal("body read remained blocked after RoundTrip cancellation")
	}
	if roundTripContext == nil || roundTripContext.Err() == nil {
		t.Fatal("dedicated RoundTrip context was not canceled")
	}
	if parent.Err() != nil {
		t.Fatalf("relay canceled the handler context: %v", parent.Err())
	}
	if body.closeCalls.Load() == 0 {
		t.Fatal("relay did not close the upstream response body")
	}
}

func testDispatchTarget(t *testing.T, transport http.RoundTripper) *Target {
	t.Helper()
	baseURL, err := url.Parse("https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return &Target{baseURL: baseURL, client: &http.Client{Transport: transport}}
}

func testPreparedRequest(t *testing.T, ctx context.Context, target *Target) PreparedRequest {
	t.Helper()
	incoming, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://gateway.example.test/v1/chat/completions", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	incoming.Header.Set("Content-Type", "application/json")
	prepared, err := PrepareRequest(incoming, target, "/v1/chat/completions", []string{"Content-Type"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type credentialObservingBody struct {
	request           *http.Request
	headerName        string
	credentialAtClose string
	closeCalls        atomic.Int32
}

type trackingRequestBody struct {
	closeCalls atomic.Int32
	onClose    func()
}

func (*trackingRequestBody) Read([]byte) (int, error) { return 0, io.EOF }

func (body *trackingRequestBody) Close() error {
	body.closeCalls.Add(1)
	if body.onClose != nil {
		body.onClose()
	}
	return nil
}

func (body *credentialObservingBody) Read([]byte) (int, error) { return 0, io.EOF }

func (body *credentialObservingBody) Close() error {
	body.closeCalls.Add(1)
	name := body.headerName
	if name == "" {
		name = "Authorization"
	}
	if body.request != nil {
		body.credentialAtClose = body.request.Header.Get(name)
	}
	return nil
}

type cancelOnlyResponseBody struct {
	ctx          context.Context
	readStarted  chan struct{}
	readFinished chan struct{}
	startOnce    sync.Once
	finishOnce   sync.Once
	closeCalls   atomic.Int32
}

func (body *cancelOnlyResponseBody) Read([]byte) (int, error) {
	body.startOnce.Do(func() { close(body.readStarted) })
	<-body.ctx.Done()
	body.finishOnce.Do(func() { close(body.readFinished) })
	return 0, body.ctx.Err()
}

func (body *cancelOnlyResponseBody) Close() error {
	body.closeCalls.Add(1)
	return nil
}

var _ http.RoundTripper = roundTripFunc(nil)
var _ io.ReadCloser = (*cancelOnlyResponseBody)(nil)
