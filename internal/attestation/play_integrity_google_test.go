package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

type playIntegrityRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip playIntegrityRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type fakePlayIntegrityAccessTokenSource struct {
	token PlayIntegrityAccessToken
	err   error
	calls int
}

func (source *fakePlayIntegrityAccessTokenSource) AccessToken(
	_ context.Context,
) (PlayIntegrityAccessToken, error) {
	source.calls++
	return source.token, source.err
}

func TestGooglePlayIntegrityDecoderUsesExactAuthenticatedEndpoint(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(21)
	wantResponse := playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, nil)
	access := &fakePlayIntegrityAccessTokenSource{token: PlayIntegrityAccessToken{
		Value:     "ya29.valid-access-token-for-play-integrity",
		ExpiresAt: playIntegrityTestNow.Add(time.Hour),
	}}
	var calls int
	transport := playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost ||
			request.URL.String() != "https://playintegrity.googleapis.com/v1/com.latchway.fixture:decodeIntegrityToken" ||
			request.Header.Get("Authorization") != "Bearer "+access.token.Value ||
			request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected Google decode request: %s %s headers=%v",
				request.Method, request.URL.Redacted(), request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"integrityToken":"valid.standard_integrity-token_01"}` {
			t.Fatalf("decode request body = %q", body)
		}
		return googleDecodeResponse(http.StatusOK, "application/json; charset=UTF-8", wantResponse), nil
	})
	decoder := mustGooglePlayIntegrityDecoder(t, GooglePlayIntegrityDecoderConfig{
		CloudProjectNumber: 123456789, TokenSource: access, Transport: transport,
		Now: func() time.Time { return playIntegrityTestNow },
	})

	got, err := decoder.DecodeIntegrityToken(
		context.Background(), "com.latchway.fixture", "valid.standard_integrity-token_01",
	)
	if err != nil {
		t.Fatalf("decode integrity token: %v", err)
	}
	if string(got) != string(wantResponse) || calls != 1 || access.calls != 1 ||
		decoder.CloudProjectNumber() != 123456789 {
		t.Fatalf("decode result/calls/project = %q/%d/%d/%d",
			got, calls, access.calls, decoder.CloudProjectNumber())
	}
	got[0] ^= 0xff
	if wantResponse[0] == got[0] {
		t.Fatal("decoder returned aliased response bytes")
	}
	if strings.Contains(fmt.Sprint(decoder), access.token.Value) ||
		strings.Contains(fmt.Sprintf("%#v", decoder), access.token.Value) ||
		strings.Contains(fmt.Sprintf("%#v", *decoder), access.token.Value) ||
		strings.Contains(fmt.Sprint(access.token), access.token.Value) {
		t.Fatal("Google decoder or access token formatting exposed a bearer token")
	}
	encodedToken, err := json.Marshal(access.token)
	if err != nil {
		t.Fatalf("marshal redacted access token: %v", err)
	}
	textToken, err := access.token.MarshalText()
	if err != nil {
		t.Fatalf("marshal redacted access token text: %v", err)
	}
	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("credential", "token", access.token)
	for _, rendered := range []string{
		string(encodedToken), string(textToken), logOutput.String(),
		fmt.Sprintf("%d", access.token), fmt.Sprintf("%+x", &access.token),
	} {
		if strings.Contains(rendered, access.token.Value) || !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("access token serialization was not redacted: %q", rendered)
		}
	}
}

func TestGooglePlayIntegrityDecoderClassifiesAndSanitizesFailures(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(22)
	validResponse := playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, nil)
	tests := []struct {
		name         string
		status       int
		contentType  string
		body         []byte
		transportErr error
		want         error
	}{
		{name: "token rejected", status: http.StatusBadRequest, contentType: "application/json", body: []byte(`{"error":{"message":"secret provider payload"}}`), want: ErrPlayIntegrityTokenRejected},
		{name: "unauthorized", status: http.StatusUnauthorized, contentType: "application/json", body: []byte(`{"error":"credential secret"}`), want: ErrPlayIntegrityService},
		{name: "quota", status: http.StatusTooManyRequests, contentType: "application/json", body: []byte(`{}`), want: ErrPlayIntegrityService},
		{name: "redirect", status: http.StatusTemporaryRedirect, contentType: "text/html", body: []byte(`redirect`), want: ErrPlayIntegrityService},
		{name: "wrong content type", status: http.StatusOK, contentType: "text/plain", body: validResponse, want: ErrPlayIntegrityService},
		{name: "duplicate JSON", status: http.StatusOK, contentType: "application/json", body: []byte(`{"a":1,"a":2}`), want: ErrPlayIntegrityService},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: make([]byte, maxPlayIntegrityDecodedBytes+1), want: ErrPlayIntegrityService},
		{name: "transport", transportErr: errors.New("dial included secret-token-value"), want: ErrPlayIntegrityService},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			access := &fakePlayIntegrityAccessTokenSource{token: PlayIntegrityAccessToken{
				Value:     "ya29.valid-access-token-for-play-integrity",
				ExpiresAt: playIntegrityTestNow.Add(time.Hour),
			}}
			transport := playIntegrityRoundTripper(func(request *http.Request) (*http.Response, error) {
				if test.transportErr != nil {
					return nil, test.transportErr
				}
				response := googleDecodeResponse(test.status, test.contentType, test.body)
				if test.status >= 300 && test.status < 400 {
					response.Header.Set("Location", "https://attacker.invalid/steal")
					response.Request = request
				}
				return response, nil
			})
			decoder := mustGooglePlayIntegrityDecoder(t, GooglePlayIntegrityDecoderConfig{
				CloudProjectNumber: 123456789, TokenSource: access, Transport: transport,
				Now: func() time.Time { return playIntegrityTestNow },
			})
			_, err := decoder.DecodeIntegrityToken(
				context.Background(), "com.latchway.fixture", "valid.standard_integrity-token_01",
			)
			if !errors.Is(err, test.want) || strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatalf("decode error = %v, want sanitized %v", err, test.want)
			}
		})
	}
}

func TestGooglePlayIntegrityDecoderRejectsUnsafeCredentialAndInput(t *testing.T) {
	t.Parallel()
	validAccess := PlayIntegrityAccessToken{
		Value:     "ya29.valid-access-token-for-play-integrity",
		ExpiresAt: playIntegrityTestNow.Add(time.Hour),
	}
	tests := []struct {
		name        string
		packageName string
		token       string
		access      PlayIntegrityAccessToken
		sourceErr   error
	}{
		{name: "package", packageName: "../attacker", token: "valid.standard_integrity-token_01", access: validAccess},
		{name: "token", packageName: "com.latchway.fixture", token: "token with whitespace", access: validAccess},
		{name: "expired access", packageName: "com.latchway.fixture", token: "valid.standard_integrity-token_01", access: PlayIntegrityAccessToken{
			Value: validAccess.Value, ExpiresAt: playIntegrityTestNow,
		}},
		{name: "header injection", packageName: "com.latchway.fixture", token: "valid.standard_integrity-token_01", access: PlayIntegrityAccessToken{
			Value: "ya29.invalid\r\nInjected: true", ExpiresAt: validAccess.ExpiresAt,
		}},
		{name: "source failure", packageName: "com.latchway.fixture", token: "valid.standard_integrity-token_01", sourceErr: errors.New("credential JSON secret")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var transportCalls int
			source := &fakePlayIntegrityAccessTokenSource{token: test.access, err: test.sourceErr}
			decoder := mustGooglePlayIntegrityDecoder(t, GooglePlayIntegrityDecoderConfig{
				CloudProjectNumber: 123456789, TokenSource: source,
				Transport: playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
					transportCalls++
					return nil, errors.New("must not dispatch")
				}),
				Now: func() time.Time { return playIntegrityTestNow },
			})
			_, err := decoder.DecodeIntegrityToken(context.Background(), test.packageName, test.token)
			if !errors.Is(err, ErrPlayIntegrityService) || strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatalf("unsafe decoder input error = %v", err)
			}
			if transportCalls != 0 {
				t.Fatal("unsafe decoder input reached transport")
			}
		})
	}
}

func TestGooglePlayIntegrityDecoderHonorsCancellationBeforeReturningDecodedPayload(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(24)
	responseBody := playIntegrityResponse(t, binding, playIntegrityTestNow, certificate, nil)
	ctx, cancel := context.WithCancel(context.Background())
	decoder := mustGooglePlayIntegrityDecoder(t, GooglePlayIntegrityDecoderConfig{
		CloudProjectNumber: 123456789,
		TokenSource: &fakePlayIntegrityAccessTokenSource{token: PlayIntegrityAccessToken{
			Value: "ya29.valid-access-token-for-play-integrity", ExpiresAt: playIntegrityTestNow.Add(time.Hour),
		}},
		Transport: playIntegrityRoundTripper(func(*http.Request) (*http.Response, error) {
			cancel()
			return googleDecodeResponse(http.StatusOK, "application/json", responseBody), nil
		}),
		Now: func() time.Time { return playIntegrityTestNow },
	})
	if _, err := decoder.DecodeIntegrityToken(
		ctx, "com.latchway.fixture", "valid.standard_integrity-token_01",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-response cancellation error = %v", err)
	}
}

func TestPlayIntegrityVerifierMapsGoogleTokenRejectionToInvalidEvidence(t *testing.T) {
	t.Parallel()
	binding := playIntegrityBinding("android")
	certificate := playIntegrityTestCertificate(23)
	decoder := &fakePlayIntegrityDecoder{project: 123456789, err: ErrPlayIntegrityTokenRejected}
	verifier := mustPlayIntegrityVerifier(t, playIntegrityConfig(decoder, certificate))
	_, err := verifier.Verify(
		context.Background(), playIntegrityEvidence(t, "rejected.standard_integrity-token_01"), binding,
	)
	if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("Google token rejection mapping = %v", err)
	}
}

func TestGooglePlayIntegrityDecoderConfiguration(t *testing.T) {
	t.Parallel()
	validSource := &fakePlayIntegrityAccessTokenSource{}
	var typedNilSource *fakePlayIntegrityAccessTokenSource
	var typedNilTransport *playIntegrityPointerRoundTripper
	tests := []struct {
		name string
		edit func(*GooglePlayIntegrityDecoderConfig)
	}{
		{name: "project", edit: func(config *GooglePlayIntegrityDecoderConfig) { config.CloudProjectNumber = 0 }},
		{name: "source", edit: func(config *GooglePlayIntegrityDecoderConfig) { config.TokenSource = nil }},
		{name: "typed nil source", edit: func(config *GooglePlayIntegrityDecoderConfig) {
			config.TokenSource = typedNilSource
		}},
		{name: "typed nil transport", edit: func(config *GooglePlayIntegrityDecoderConfig) {
			config.Transport = typedNilTransport
		}},
		{name: "short timeout", edit: func(config *GooglePlayIntegrityDecoderConfig) { config.Timeout = time.Millisecond }},
		{name: "long timeout", edit: func(config *GooglePlayIntegrityDecoderConfig) { config.Timeout = time.Minute }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := GooglePlayIntegrityDecoderConfig{
				CloudProjectNumber: 123456789, TokenSource: validSource,
			}
			test.edit(&config)
			if _, err := NewGooglePlayIntegrityDecoder(config); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("decoder configuration error = %v", err)
			}
		})
	}

	var zero GooglePlayIntegrityDecoder
	if _, err := zero.DecodeIntegrityToken(
		context.Background(), "com.latchway.fixture", "valid.standard_integrity-token_01",
	); !errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("zero-value decoder error = %v", err)
	}
	if _, err := (*GooglePlayIntegrityDecoder)(nil).DecodeIntegrityToken(
		context.Background(), "com.latchway.fixture", "valid.standard_integrity-token_01",
	); !errors.Is(err, ErrPlayIntegrityService) {
		t.Fatalf("nil decoder error = %v", err)
	}
}

func mustGooglePlayIntegrityDecoder(
	t *testing.T,
	config GooglePlayIntegrityDecoderConfig,
) *GooglePlayIntegrityDecoder {
	t.Helper()
	decoder, err := NewGooglePlayIntegrityDecoder(config)
	if err != nil {
		t.Fatalf("construct Google Play Integrity decoder: %v", err)
	}
	return decoder
}

func googleDecodeResponse(status int, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d test", status),
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}
