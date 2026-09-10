package attestation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoogleTokenSourceCancellationWhileWaitingDoesNotWaitForRefresh(t *testing.T) {
	t.Parallel()
	started, release := make(chan struct{}), make(chan struct{})
	source := newGoogleTokenSource(time.Second, func() time.Time { return playIntegrityTestNow },
		func(context.Context, time.Time) (PlayIntegrityAccessToken, error) {
			close(started)
			<-release
			return PlayIntegrityAccessToken{Value: "ya29.concurrent-access-token", ExpiresAt: playIntegrityTestNow.Add(time.Hour)}, nil
		})
	first := make(chan error, 1)
	go func() { _, err := source.AccessToken(context.Background()); first <- err }()
	<-started
	waiter, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() { _, err := source.AccessToken(waiter); waiting <- err }()
	cancel()
	select {
	case err := <-waiting:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waiting cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Error("canceled waiter blocked behind in-flight refresh")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestGoogleTokenSourceRefreshFailureDoesNotReturnStaleToken(t *testing.T) {
	t.Parallel()
	now, calls := playIntegrityTestNow, 0
	source := newGoogleTokenSource(time.Second, func() time.Time { return now },
		func(_ context.Context, now time.Time) (PlayIntegrityAccessToken, error) {
			calls++
			if calls == 2 {
				return PlayIntegrityAccessToken{}, errors.New("provider-secret")
			}
			return PlayIntegrityAccessToken{Value: "ya29.refreshed-access-token", ExpiresAt: now.Add(time.Hour)}, nil
		})
	if _, err := source.AccessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The existing decoder validity guard adds five seconds to the configured
	// one-minute refresh margin. Preserve that exact boundary.
	now = now.Add(59*time.Minute - 5*time.Second - time.Nanosecond)
	if _, err := source.AccessToken(context.Background()); err != nil || calls != 1 {
		t.Fatalf("early refresh: calls=%d err=%v", calls, err)
	}
	now = now.Add(time.Nanosecond)
	if token, err := source.AccessToken(context.Background()); !errors.Is(err, ErrPlayIntegrityService) || token.Value != "" {
		t.Fatalf("failed refresh returned a stale token or raw error: %v", err)
	}
	if token, err := source.AccessToken(context.Background()); err != nil || calls != 3 || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("retry after failed refresh: calls=%d err=%v", calls, err)
	}
}

func TestGoogleTokenSourcesEnforceRequestContextAndDoNotCacheFailure(t *testing.T) {
	t.Parallel()
	for _, metadataSource := range []bool{false, true} {
		t.Run(map[bool]string{false: "service-account", true: "metadata"}[metadataSource], func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			transport := playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				if _, ok := request.Context().Deadline(); !ok {
					t.Error("Google library request has no deadline")
				}
				<-request.Context().Done()
				return nil, request.Context().Err()
			})
			var source PlayIntegrityAccessTokenSource
			if metadataSource {
				source = mustGoogleMetadataTokenSource(t, GoogleMetadataTokenSourceOptions{Transport: transport})
			} else {
				source = mustGoogleServiceAccountTokenSource(t, googleServiceAccountCredentials(t, googleTestPrivateKey(t), nil),
					GoogleServiceAccountTokenSourceOptions{Transport: transport})
			}
			for range 2 {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				_, err := source.AccessToken(ctx)
				cancel()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline result = %v", err)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("timed-out request was cached or retried: %d calls", calls.Load())
			}
		})
	}
}

func TestGoogleTokenTransportBoundsReadsClosesBodiesAndNeverFollowsRedirects(t *testing.T) {
	t.Parallel()
	endpoint, _ := url.Parse(googleOAuthTokenEndpoint)
	for _, status := range []int{http.StatusOK, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			body := &googleTrackingBody{remaining: maximumGoogleTokenResponseBytes * 2}
			calls := 0
			transport := &googleTokenTransport{endpoint: *endpoint,
				base: playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: status, Body: body, Request: request,
						Header: http.Header{"Content-Type": {"application/json"}, "Location": {"https://attacker.invalid/steal"}}}, nil
				})}
			client := &http.Client{Transport: transport}
			request, _ := http.NewRequest(http.MethodPost, endpoint.String(), strings.NewReader("assertion=secret"))
			_, err := client.Do(request)
			if err == nil || calls != 1 || body.read != maximumGoogleTokenResponseBytes+1 || !body.closed {
				t.Fatalf("response bounds: calls=%d read=%d closed=%v err=%v", calls, body.read, body.closed, err)
			}
		})
	}
}

type googleTrackingBody struct {
	remaining int
	read      int
	closed    bool
}

func (body *googleTrackingBody) Read(p []byte) (int, error) {
	if body.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), body.remaining)
	for index := range p[:n] {
		p[index] = 'x'
	}
	body.remaining -= n
	body.read += n
	return n, nil
}

func (body *googleTrackingBody) Close() error {
	body.closed = true
	return nil
}
