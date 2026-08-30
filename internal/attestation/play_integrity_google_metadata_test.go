package attestation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoogleMetadataTokenSourceUsesExactEndpointCachesAndRefreshes(t *testing.T) {
	t.Parallel()
	now := playIntegrityTestNow
	var calls int
	transport := playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		query := request.URL.Query()
		if request.Method != http.MethodGet || request.URL.String() != googleMetadataTokenEndpoint ||
			len(query) != 2 || query.Get("enforce_scopes") != "true" ||
			query.Get("scopes") != googlePlayIntegrityScope ||
			request.Header.Get(googleMetadataFlavorHeader) != googleMetadataFlavorExpectedValue ||
			request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected metadata request: %s %s headers=%v",
				request.Method, request.URL.Redacted(), request.Header)
		}
		response := googleDecodeResponse(
			http.StatusOK, "application/json; charset=UTF-8",
			[]byte(`{"access_token":"ya29.metadata-access-token-value","expires_in":3600,"token_type":"Bearer"}`),
		)
		response.Header.Set(googleMetadataFlavorHeader, googleMetadataFlavorExpectedValue)
		return response, nil
	})
	source := mustGoogleMetadataTokenSource(t, GoogleMetadataTokenSourceOptions{
		Transport: transport, Now: func() time.Time { return now },
	})

	first, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("first metadata token: %v", err)
	}
	second, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("cached metadata token: %v", err)
	}
	if first != second || calls != 1 || !first.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("token/cache/calls = %#v/%#v/%d", first, second, calls)
	}
	if strings.Contains(fmt.Sprint(source), first.Value) ||
		strings.Contains(fmt.Sprintf("%#v", source), first.Value) ||
		strings.Contains(fmt.Sprintf("%#v", *source), first.Value) {
		t.Fatal("metadata source formatting exposed a bearer token")
	}
	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("credential", "source", *source)
	if strings.Contains(logOutput.String(), first.Value) ||
		!strings.Contains(logOutput.String(), "REDACTED") {
		t.Fatalf("structured metadata source log was not redacted: %s", logOutput.String())
	}

	now = playIntegrityTestNow.Add(59 * time.Minute)
	refreshed, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("refresh metadata token: %v", err)
	}
	if calls != 2 || !refreshed.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("refresh calls/expiry = %d/%s", calls, refreshed.ExpiresAt)
	}
}

func TestGoogleMetadataTokenSourceDefaultTransportNeverUsesEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	source := mustGoogleMetadataTokenSource(t, GoogleMetadataTokenSourceOptions{
		Now: func() time.Time { return playIntegrityTestNow },
	})
	transport, ok := source.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default metadata transport type = %T", source.client.Transport)
	}
	if transport.Proxy != nil {
		request, err := http.NewRequest(http.MethodGet, googleMetadataTokenEndpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, proxyErr := transport.Proxy(request)
		t.Fatalf("default metadata transport proxy=%v err=%v, want direct transport", proxy, proxyErr)
	}
}

func TestGoogleMetadataTokenSourceSingleFlightsAndCancellationIsPrompt(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	transport := playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		response := googleDecodeResponse(
			http.StatusOK, "application/json",
			[]byte(`{"access_token":"ya29.concurrent-metadata-token","expires_in":3600,"token_type":"Bearer"}`),
		)
		response.Header.Set(googleMetadataFlavorHeader, googleMetadataFlavorExpectedValue)
		return response, nil
	})
	source := mustGoogleMetadataTokenSource(t, GoogleMetadataTokenSourceOptions{
		Transport: transport, Now: func() time.Time { return playIntegrityTestNow },
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := source.AccessToken(context.Background())
		firstDone <- err
	}()
	<-started

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelDone := make(chan error, 1)
	go func() {
		_, err := source.AccessToken(canceled)
		cancelDone <- err
	}()
	select {
	case err := <-cancelDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("gate cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled metadata waiter remained blocked on the single-flight gate")
	}

	const waiters = 24
	errorsOut := make(chan error, waiters)
	for range waiters {
		go func() {
			_, err := source.AccessToken(context.Background())
			errorsOut <- err
		}()
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first metadata request: %v", err)
	}
	for range waiters {
		if err := <-errorsOut; err != nil {
			t.Fatalf("concurrent metadata request: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent metadata calls = %d, want 1", calls.Load())
	}
}

func TestGoogleMetadataTokenSourceRejectsAndSanitizesFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		status         int
		contentType    string
		metadataFlavor string
		body           []byte
		transportErr   error
	}{
		{name: "provider error", status: http.StatusForbidden, contentType: "application/json", metadataFlavor: "Google", body: []byte(`{"error":"credential-secret"}`)},
		{name: "redirect", status: http.StatusTemporaryRedirect, contentType: "text/html", metadataFlavor: "Google", body: []byte(`redirect`)},
		{name: "missing metadata flavor", status: http.StatusOK, contentType: "application/json", body: []byte(`{"access_token":"ya29.valid-metadata-token","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "wrong metadata flavor", status: http.StatusOK, contentType: "application/json", metadataFlavor: "Attacker", body: []byte(`{"access_token":"ya29.valid-metadata-token","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", metadataFlavor: "Google", body: []byte(`{"access_token":"ya29.valid-metadata-token","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "duplicate", status: http.StatusOK, contentType: "application/json", metadataFlavor: "Google", body: []byte(`{"access_token":"ya29.valid-metadata-token","access_token":"credential-secret","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", metadataFlavor: "Google", body: make([]byte, maximumGoogleTokenResponseBytes+1)},
		{name: "transport", transportErr: errors.New("transport included credential-secret")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transport := playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
				if test.transportErr != nil {
					return nil, test.transportErr
				}
				response := googleDecodeResponse(test.status, test.contentType, test.body)
				response.Header.Set(googleMetadataFlavorHeader, test.metadataFlavor)
				if test.status >= 300 && test.status < 400 {
					response.Header.Set("Location", "https://attacker.invalid/steal")
					response.Request = request
				}
				return response, nil
			})
			source := mustGoogleMetadataTokenSource(t, GoogleMetadataTokenSourceOptions{
				Transport: transport, Now: func() time.Time { return playIntegrityTestNow },
			})
			_, err := source.AccessToken(context.Background())
			if !errors.Is(err, ErrPlayIntegrityService) || strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatalf("metadata token error = %v, want sanitized service error", err)
			}
		})
	}
}

func TestGoogleMetadataTokenSourceConfigurationAndZeroValue(t *testing.T) {
	t.Parallel()
	var nilTransport *playIntegrityPointerRoundTripper
	tests := []struct {
		name    string
		options GoogleMetadataTokenSourceOptions
	}{
		{name: "short timeout", options: GoogleMetadataTokenSourceOptions{Timeout: time.Millisecond}},
		{name: "long timeout", options: GoogleMetadataTokenSourceOptions{Timeout: time.Minute}},
		{name: "typed nil transport", options: GoogleMetadataTokenSourceOptions{Transport: nilTransport}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewGoogleMetadataTokenSource(test.options); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("metadata source configuration error = %v", err)
			}
		})
	}
	var zero GoogleMetadataTokenSource
	if _, err := zero.AccessToken(context.Background()); !errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("zero-value metadata source error = %v", err)
	}
	if _, err := (*GoogleMetadataTokenSource)(nil).AccessToken(context.Background()); !errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("nil metadata source error = %v", err)
	}
}

func TestGoogleMetadataTokenSourceHonorsCancellationBeforeCaching(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	source := mustGoogleMetadataTokenSource(t, GoogleMetadataTokenSourceOptions{
		Transport: playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
			cancel()
			response := googleDecodeResponse(
				http.StatusOK, "application/json",
				[]byte(`{"access_token":"ya29.canceled-metadata-token","expires_in":3600,"token_type":"Bearer"}`),
			)
			response.Header.Set(googleMetadataFlavorHeader, googleMetadataFlavorExpectedValue)
			return response, nil
		}),
		Now: func() time.Time { return playIntegrityTestNow },
	})
	if _, err := source.AccessToken(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-response metadata cancellation error = %v", err)
	}
	if source.cached.Value != "" {
		t.Fatal("canceled metadata token response was cached")
	}
}

type playIntegrityPointerRoundTripper struct{}

func (*playIntegrityPointerRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("must not dispatch")
}

func mustGoogleMetadataTokenSource(
	t *testing.T,
	options GoogleMetadataTokenSourceOptions,
) *GoogleMetadataTokenSource {
	t.Helper()
	source, err := NewGoogleMetadataTokenSource(options)
	if err != nil {
		t.Fatalf("construct Google metadata token source: %v", err)
	}
	return source
}
