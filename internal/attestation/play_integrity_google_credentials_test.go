package attestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	googleTestRSAOnce sync.Once
	googleTestRSAKey  *rsa.PrivateKey
	googleTestRSAErr  error
)

func TestGoogleServiceAccountTokenSourceSignsCachesAndRefreshes(t *testing.T) {
	t.Parallel()
	privateKey := googleTestPrivateKey(t)
	now := playIntegrityTestNow
	var calls int
	transport := playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost || request.URL.String() != googleOAuthTokenEndpoint ||
			request.Header.Get("Authorization") != "" ||
			request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("unexpected OAuth token request: %s %s headers=%v",
				request.Method, request.URL.Redacted(), request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || form.Get("grant_type") != googleServiceAccountGrantType || len(form) != 2 {
			t.Fatalf("invalid OAuth form: %v %#v", err, form)
		}
		assertGoogleServiceAccountAssertion(t, form.Get("assertion"), &privateKey.PublicKey, now)
		return googleDecodeResponse(
			http.StatusOK, "application/json",
			[]byte(`{"access_token":"ya29.service-account-access-token-01","expires_in":3600,"token_type":"Bearer"}`),
		), nil
	})
	source := mustGoogleServiceAccountTokenSource(t, googleServiceAccountCredentials(t, privateKey, nil),
		GoogleServiceAccountTokenSourceOptions{
			Transport: transport, Now: func() time.Time { return now },
		})

	first, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("first access token: %v", err)
	}
	second, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("cached access token: %v", err)
	}
	if first != second || calls != 1 || !first.ExpiresAt.Equal(playIntegrityTestNow.Add(time.Hour)) {
		t.Fatalf("token/cache/calls = %#v/%#v/%d", first, second, calls)
	}
	if strings.Contains(fmt.Sprint(source), "fixture-service") ||
		strings.Contains(fmt.Sprintf("%#v", source), "PRIVATE") ||
		strings.Contains(fmt.Sprint(first), first.Value) {
		t.Fatal("service-account source or access token formatting leaked credentials")
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", *source), fmt.Sprintf("%#v", *source),
		fmt.Sprintf("%+x", source), fmt.Sprintf("%d", *source),
	} {
		if rendered != "GoogleServiceAccountTokenSource{[REDACTED]}" {
			t.Fatalf("service-account source formatter = %q", rendered)
		}
	}
	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("credential", "source", *source)
	if strings.Contains(logOutput.String(), source.clientEmail) ||
		strings.Contains(logOutput.String(), source.privateKeyID) ||
		!strings.Contains(logOutput.String(), "REDACTED") {
		t.Fatalf("structured service-account source log was not redacted: %s", logOutput.String())
	}

	now = playIntegrityTestNow.Add(59 * time.Minute)
	refreshed, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("refresh access token: %v", err)
	}
	if calls != 2 || !refreshed.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("refresh calls/expiry = %d/%s", calls, refreshed.ExpiresAt)
	}
}

func TestGoogleServiceAccountTokenSourceSingleFlightsAndCancellationIsPrompt(t *testing.T) {
	privateKey := googleTestPrivateKey(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	transport := playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return googleDecodeResponse(
			http.StatusOK, "application/json",
			[]byte(`{"access_token":"ya29.concurrent-access-token-value","expires_in":3600,"token_type":"Bearer"}`),
		), nil
	})
	source := mustGoogleServiceAccountTokenSource(t, googleServiceAccountCredentials(t, privateKey, nil),
		GoogleServiceAccountTokenSourceOptions{
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
		t.Fatal("canceled token waiter remained blocked on the single-flight gate")
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
		t.Fatalf("first token request: %v", err)
	}
	for range waiters {
		if err := <-errorsOut; err != nil {
			t.Fatalf("concurrent token request: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent OAuth calls = %d, want 1", calls.Load())
	}
}

func TestGoogleServiceAccountTokenSourceRejectsUnsafeCredentials(t *testing.T) {
	t.Parallel()
	privateKey := googleTestPrivateKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))
	tests := []struct {
		name   string
		mutate func(map[string]any)
		raw    []byte
	}{
		{name: "duplicate JSON member", raw: []byte(`{"type":"service_account","type":"service_account"}`)},
		{name: "type", mutate: func(value map[string]any) { value["type"] = "authorized_user" }},
		{name: "email", mutate: func(value map[string]any) { value["client_email"] = "attacker@example.com" }},
		{name: "key id", mutate: func(value map[string]any) { value["private_key_id"] = "short" }},
		{name: "private key", mutate: func(value map[string]any) { value["private_key"] = "not PEM" }},
		{name: "EC private key", mutate: func(value map[string]any) { value["private_key"] = ecPEM }},
		{name: "token URI", mutate: func(value map[string]any) { value["token_uri"] = "https://attacker.invalid/token" }},
		{name: "oversized", raw: make([]byte, maximumServiceAccountJSONBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded := test.raw
			if encoded == nil {
				values := googleServiceAccountCredentialMap(t, privateKey)
				test.mutate(values)
				var marshalErr error
				encoded, marshalErr = json.Marshal(values)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
			}
			if _, err := NewGoogleServiceAccountTokenSource(
				encoded, GoogleServiceAccountTokenSourceOptions{},
			); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("credential error = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestGoogleServiceAccountTokenSourceSanitizesTokenEndpointFailures(t *testing.T) {
	t.Parallel()
	privateKey := googleTestPrivateKey(t)
	tests := []struct {
		name         string
		status       int
		contentType  string
		body         []byte
		transportErr error
	}{
		{name: "provider error", status: http.StatusBadRequest, contentType: "application/json", body: []byte(`{"error":"private-key-secret"}`)},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", body: []byte(`{"access_token":"ya29.valid-access-token-value","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "duplicate", status: http.StatusOK, contentType: "application/json", body: []byte(`{"access_token":"ya29.valid-access-token-value","access_token":"secret","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "short token", status: http.StatusOK, contentType: "application/json", body: []byte(`{"access_token":"short","expires_in":3600,"token_type":"Bearer"}`)},
		{name: "token type", status: http.StatusOK, contentType: "application/json", body: []byte(`{"access_token":"ya29.valid-access-token-value","expires_in":3600,"token_type":"MAC"}`)},
		{name: "expiry", status: http.StatusOK, contentType: "application/json", body: []byte(`{"access_token":"ya29.valid-access-token-value","expires_in":1,"token_type":"Bearer"}`)},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: make([]byte, maximumGoogleTokenResponseBytes+1)},
		{name: "transport", transportErr: errors.New("transport included private-key-secret")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transport := playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
				if test.transportErr != nil {
					return nil, test.transportErr
				}
				return googleDecodeResponse(test.status, test.contentType, test.body), nil
			})
			source := mustGoogleServiceAccountTokenSource(
				t, googleServiceAccountCredentials(t, privateKey, nil),
				GoogleServiceAccountTokenSourceOptions{
					Transport: transport, Now: func() time.Time { return playIntegrityTestNow },
				},
			)
			_, err := source.AccessToken(context.Background())
			if !errors.Is(err, ErrPlayIntegrityService) || strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatalf("token endpoint error = %v, want sanitized service error", err)
			}
		})
	}
}

func TestGoogleServiceAccountTokenSourceConfigurationAndZeroValue(t *testing.T) {
	t.Parallel()
	privateKey := googleTestPrivateKey(t)
	credentials := googleServiceAccountCredentials(t, privateKey, nil)
	var nilTransport *playIntegrityPointerRoundTripper
	tests := []struct {
		name    string
		options GoogleServiceAccountTokenSourceOptions
	}{
		{name: "short timeout", options: GoogleServiceAccountTokenSourceOptions{Timeout: time.Millisecond}},
		{name: "long timeout", options: GoogleServiceAccountTokenSourceOptions{Timeout: time.Minute}},
		{name: "typed nil transport", options: GoogleServiceAccountTokenSourceOptions{Transport: nilTransport}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewGoogleServiceAccountTokenSource(credentials, test.options); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("service-account source configuration error = %v", err)
			}
		})
	}

	var zero GoogleServiceAccountTokenSource
	if _, err := zero.AccessToken(context.Background()); !errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("zero-value service-account source error = %v", err)
	}
	if _, err := (*GoogleServiceAccountTokenSource)(nil).AccessToken(context.Background()); !errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("nil service-account source error = %v", err)
	}
}

func TestGoogleServiceAccountTokenSourceHonorsCancellationBeforeCaching(t *testing.T) {
	t.Parallel()
	privateKey := googleTestPrivateKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	source := mustGoogleServiceAccountTokenSource(
		t, googleServiceAccountCredentials(t, privateKey, nil),
		GoogleServiceAccountTokenSourceOptions{
			Transport: playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
				cancel()
				return googleDecodeResponse(
					http.StatusOK, "application/json",
					[]byte(`{"access_token":"ya29.canceled-service-account-token","expires_in":3600,"token_type":"Bearer"}`),
				), nil
			}),
			Now: func() time.Time { return playIntegrityTestNow },
		},
	)
	if _, err := source.AccessToken(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-response service-account cancellation error = %v", err)
	}
	if source.cached.Value != "" {
		t.Fatal("canceled service-account token response was cached")
	}
}

func assertGoogleServiceAccountAssertion(
	t *testing.T,
	assertion string,
	publicKey *rsa.PublicKey,
	now time.Time,
) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT assertion segments = %d", len(parts))
	}
	decode := func(part string) map[string]any {
		t.Helper()
		encoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			t.Fatalf("decode assertion segment: %v", err)
		}
		var value map[string]any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("parse assertion segment: %v", err)
		}
		return value
	}
	header := decode(parts[0])
	claims := decode(parts[1])
	if header["alg"] != "RS256" || header["typ"] != "JWT" ||
		header["kid"] != "0123456789abcdef0123456789abcdef01234567" ||
		claims["aud"] != googleOAuthTokenEndpoint || claims["iss"] != "fixture-service@fixture-project.iam.gserviceaccount.com" ||
		claims["scope"] != googlePlayIntegrityScope ||
		int64(claims["iat"].(float64)) != now.Unix() ||
		int64(claims["exp"].(float64)) != now.Add(time.Hour).Unix() {
		t.Fatalf("unexpected assertion header/claims: %#v %#v", header, claims)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("verify service-account assertion: %v", err)
	}
}

func googleTestPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	googleTestRSAOnce.Do(func() {
		googleTestRSAKey, googleTestRSAErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if googleTestRSAErr != nil {
		t.Fatalf("generate RSA fixture key: %v", googleTestRSAErr)
	}
	return googleTestRSAKey
}

func googleServiceAccountCredentialMap(t *testing.T, privateKey *rsa.PrivateKey) map[string]any {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"type":           "service_account",
		"project_id":     "fixture-project",
		"private_key_id": "0123456789abcdef0123456789abcdef01234567",
		"private_key": string(pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: encoded,
		})),
		"client_email": "fixture-service@fixture-project.iam.gserviceaccount.com",
		"client_id":    "123456789012345678901",
		"token_uri":    googleOAuthTokenEndpoint,
	}
}

func googleServiceAccountCredentials(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	values := googleServiceAccountCredentialMap(t, privateKey)
	if mutate != nil {
		mutate(values)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustGoogleServiceAccountTokenSource(
	t *testing.T,
	credentials []byte,
	options GoogleServiceAccountTokenSourceOptions,
) *GoogleServiceAccountTokenSource {
	t.Helper()
	source, err := NewGoogleServiceAccountTokenSource(credentials, options)
	if err != nil {
		t.Fatalf("construct Google service-account token source: %v", err)
	}
	return source
}
