package attestation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	turnstileTestToken  = "turnstile-test-token-which-is-opaque"
	turnstileTestSecret = "turnstile-provider-secret-value"
)

var turnstileTestNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

type ephemeralTurnstileSecret struct {
	material []byte
	err      error
	mu       sync.Mutex
	uses     int
	last     []byte
}

func (secret *ephemeralTurnstileSecret) Use(ctx context.Context, consume func([]byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	secret.mu.Lock()
	secret.uses++
	secret.mu.Unlock()
	if secret.err != nil {
		return secret.err
	}
	buffer := append([]byte(nil), secret.material...)
	secret.mu.Lock()
	secret.last = buffer
	secret.mu.Unlock()
	defer clear(buffer)
	return consume(buffer)
}

func (secret *ephemeralTurnstileSecret) usageCount() int {
	secret.mu.Lock()
	defer secret.mu.Unlock()
	return secret.uses
}

func (secret *ephemeralTurnstileSecret) lastCleared() bool {
	secret.mu.Lock()
	defer secret.mu.Unlock()
	return len(secret.last) > 0 && bytes.Equal(secret.last, make([]byte, len(secret.last)))
}

func TestTurnstileVerifierUsesExactBoundSiteverifyRequest(t *testing.T) {
	binding := turnstileBinding(turnstileTestNow)
	bindingHash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	secret := &ephemeralTurnstileSecret{material: []byte(turnstileTestSecret)}
	var capturedID string
	transport := webAttestationRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != turnstileSiteverifyURL ||
			request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected Siteverify request: %s %s headers=%v", request.Method, request.URL.Redacted(), request.Header)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		form, parseErr := url.ParseQuery(string(body))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		capturedID = form.Get("idempotency_key")
		if len(form) != 3 || form.Get("secret") != turnstileTestSecret ||
			form.Get("response") != turnstileTestToken || !turnstileUUIDPattern.MatchString(capturedID) {
			t.Fatalf("unexpected Siteverify form: keys=%v id=%q", form, capturedID)
		}
		return turnstileResponse(http.StatusOK, fmt.Sprintf(
			`{"success":true,"challenge_ts":%q,"hostname":"app.example.com","action":"latchway_session","cdata":%q,"error-codes":[]}`,
			turnstileTestNow.Add(-time.Minute).Format(time.RFC3339Nano), bindingHash,
		)), nil
	})
	verifier := mustTurnstileVerifier(t, TurnstileConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "latchway_session",
		Secret: secret, Transport: transport, Now: func() time.Time { return turnstileTestNow },
	})
	evidence := mustWebEvidence(t, turnstileProvider, turnstileTestToken)
	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("verify Turnstile token: %v", err)
	}
	if result.Provider != turnstileProvider || result.TrustLevel != "web_risk_verified" ||
		result.NormalizedSignals["risk_valid"] != true || result.NormalizedSignals["binding_verified"] != true ||
		result.NormalizedSignals["verified_hostname"] != "app.example.com" ||
		result.NormalizedSignals["verified_action"] != "latchway_session" ||
		secret.usageCount() != 1 || capturedID == "" || !secret.lastCleared() {
		t.Fatalf("unexpected Turnstile result=%#v secret uses=%d", result, secret.usageCount())
	}
	for _, rendered := range []string{fmt.Sprint(verifier), fmt.Sprintf("%#v", verifier), fmt.Sprintf("%+v", *verifier)} {
		if strings.Contains(rendered, turnstileTestSecret) || !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("Turnstile verifier formatting was unsafe: %q", rendered)
		}
	}
	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("turnstile", "verifier", *verifier)
	if strings.Contains(logOutput.String(), turnstileTestSecret) || !strings.Contains(logOutput.String(), "REDACTED") {
		t.Fatalf("Turnstile structured logging was unsafe: %s", logOutput.String())
	}
}

func TestTurnstileVerifierRetriesOnlyTransientFailuresWithStableIdempotency(t *testing.T) {
	binding := turnstileBinding(turnstileTestNow)
	bindingHash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		first func() (*http.Response, error)
	}{
		{name: "network", first: func() (*http.Response, error) { return nil, errors.New("dial leaked-provider-token") }},
		{name: "server", first: func() (*http.Response, error) {
			return turnstileResponse(http.StatusServiceUnavailable, `{"secret":"provider-body"}`), nil
		}},
		{name: "internal verdict", first: func() (*http.Response, error) {
			return turnstileResponse(http.StatusOK, `{"success":false,"error-codes":["internal-error"]}`), nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret := &ephemeralTurnstileSecret{material: []byte(turnstileTestSecret)}
			var calls int
			var ids []string
			transport := webAttestationRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				body, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				form, parseErr := url.ParseQuery(string(body))
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				ids = append(ids, form.Get("idempotency_key"))
				if calls == 1 {
					return test.first()
				}
				return turnstileResponse(http.StatusOK, fmt.Sprintf(
					`{"success":true,"challenge_ts":%q,"hostname":"app.example.com","action":"latchway_session","cdata":%q}`,
					turnstileTestNow.Format(time.RFC3339Nano), bindingHash,
				)), nil
			})
			verifier := mustTurnstileVerifier(t, TurnstileConfig{
				ApplicationID: "app_habitify", EnvironmentID: "production",
				AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "latchway_session",
				Secret: secret, Transport: transport, Now: func() time.Time { return turnstileTestNow },
				MaximumAttempts: 2, RetryDelay: time.Nanosecond,
			})
			_, err := verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, turnstileTestToken), binding)
			if err != nil || calls != 2 || secret.usageCount() != 2 || len(ids) != 2 || ids[0] == "" || ids[0] != ids[1] {
				t.Fatalf("retry result calls=%d uses=%d ids=%v err=%v", calls, secret.usageCount(), ids, err)
			}
		})
	}
}

func TestTurnstileVerifierRetriesPerAttemptTimeout(t *testing.T) {
	binding := turnstileBinding(turnstileTestNow)
	bindingHash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	var ids []string
	transport := webAttestationRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		form, parseErr := url.ParseQuery(string(body))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		ids = append(ids, form.Get("idempotency_key"))
		if calls == 1 {
			<-request.Context().Done()
			return nil, request.Context().Err()
		}
		return turnstileResponse(http.StatusOK, fmt.Sprintf(
			`{"success":true,"challenge_ts":%q,"hostname":"app.example.com","action":"latchway_session","cdata":%q}`,
			turnstileTestNow.Format(time.RFC3339Nano), bindingHash,
		)), nil
	})
	verifier := mustTurnstileVerifier(t, TurnstileConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "latchway_session",
		Secret:    &ephemeralTurnstileSecret{material: []byte(turnstileTestSecret)},
		Transport: transport, Now: func() time.Time { return turnstileTestNow },
		MaximumAttempts: 2, RetryDelay: time.Nanosecond,
	})
	verifier.timeout = 20 * time.Millisecond
	_, err = verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, turnstileTestToken), binding)
	if err != nil || calls != 2 || len(ids) != 2 || ids[0] == "" || ids[0] != ids[1] {
		t.Fatalf("timeout retry calls=%d ids=%v err=%v", calls, ids, err)
	}
}

func TestTurnstilePermanentVerdictsAndHTTPFailuresDoNotRetry(t *testing.T) {
	binding := turnstileBinding(turnstileTestNow)
	tests := []struct {
		name     string
		status   int
		body     string
		want     error
		attempts int
	}{
		{name: "invalid token", status: http.StatusOK, body: `{"success":false,"error-codes":["invalid-input-response"]}`, want: ErrInvalid, attempts: 1},
		{name: "mixed internal and permanent", status: http.StatusOK, body: `{"success":false,"error-codes":["internal-error","invalid-input-response"]}`, want: ErrInvalid, attempts: 1},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"success":false,"error-codes":["invalid-input-secret"],"secret":"must-not-leak"}`, want: ErrTurnstileService, attempts: 1},
		{name: "exhaust server retry", status: http.StatusBadGateway, body: `{"provider":"must-not-leak"}`, want: ErrTurnstileService, attempts: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			transport := webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
				calls++
				return turnstileResponse(test.status, test.body), nil
			})
			verifier := mustTurnstileVerifier(t, TurnstileConfig{
				ApplicationID: "app_habitify", EnvironmentID: "production",
				AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "latchway_session",
				Secret:    &ephemeralTurnstileSecret{material: []byte(turnstileTestSecret)},
				Transport: transport, Now: func() time.Time { return turnstileTestNow },
				MaximumAttempts: 2, RetryDelay: time.Nanosecond,
			})
			_, err := verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, turnstileTestToken), binding)
			if !errors.Is(err, test.want) || calls != test.attempts || strings.Contains(fmt.Sprint(err), "must-not-leak") {
				t.Fatalf("error=%v calls=%d, want %v/%d", err, calls, test.want, test.attempts)
			}
		})
	}
}

func TestTurnstileVerifierChecksFreshnessHostnameActionAndBinding(t *testing.T) {
	binding := turnstileBinding(turnstileTestNow)
	bindingHash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		timestamp time.Time
		hostname  string
		action    string
		cdata     string
	}{
		{name: "stale", timestamp: turnstileTestNow.Add(-6 * time.Minute), hostname: "app.example.com", action: "latchway_session", cdata: bindingHash},
		{name: "future", timestamp: turnstileTestNow.Add(time.Minute), hostname: "app.example.com", action: "latchway_session", cdata: bindingHash},
		{name: "hostname", timestamp: turnstileTestNow, hostname: "attacker.example.com", action: "latchway_session", cdata: bindingHash},
		{name: "action", timestamp: turnstileTestNow, hostname: "app.example.com", action: "other_action", cdata: bindingHash},
		{name: "binding", timestamp: turnstileTestNow, hostname: "app.example.com", action: "latchway_session", cdata: strings.Repeat("A", 43)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
				return turnstileResponse(http.StatusOK, fmt.Sprintf(
					`{"success":true,"challenge_ts":%q,"hostname":%q,"action":%q,"cdata":%q}`,
					test.timestamp.Format(time.RFC3339Nano), test.hostname, test.action, test.cdata,
				)), nil
			})
			verifier := mustTurnstileVerifier(t, TurnstileConfig{
				ApplicationID: "app_habitify", EnvironmentID: "production",
				AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "latchway_session",
				Secret:    &ephemeralTurnstileSecret{material: []byte(turnstileTestSecret)},
				Transport: transport, Now: func() time.Time { return turnstileTestNow }, MaximumAttempts: 1,
			})
			_, err := verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, turnstileTestToken), binding)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("verification error = %v", err)
			}
		})
	}
}

func TestTurnstileConfigurationInputAndResponseBounds(t *testing.T) {
	base := TurnstileConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		AllowedHostnames: []string{"app.example.com"}, ExpectedAction: "latchway_session",
		Secret: &ephemeralTurnstileSecret{material: []byte(turnstileTestSecret)},
	}
	var typedNilSecret *ephemeralTurnstileSecret
	var typedNilTransport *appCheckNilRoundTripper
	invalid := []TurnstileConfig{
		withTurnstileConfig(base, func(config *TurnstileConfig) { config.AllowedHostnames = []string{"App.Example.com"} }),
		withTurnstileConfig(base, func(config *TurnstileConfig) { config.ExpectedAction = "action with spaces" }),
		withTurnstileConfig(base, func(config *TurnstileConfig) { config.Secret = typedNilSecret }),
		withTurnstileConfig(base, func(config *TurnstileConfig) { config.Transport = typedNilTransport }),
		withTurnstileConfig(base, func(config *TurnstileConfig) { config.MaximumAttempts = 4 }),
		withTurnstileConfig(base, func(config *TurnstileConfig) { config.Timeout = 31 * time.Second }),
	}
	for index, config := range invalid {
		if _, err := NewTurnstileVerifier(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("invalid config %d error = %v", index, err)
		}
	}

	var calls int
	verifier := mustTurnstileVerifier(t, withTurnstileConfig(base, func(config *TurnstileConfig) {
		config.Now = func() time.Time { return turnstileTestNow }
		config.MaximumAttempts = 1
		config.Transport = webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
			calls++
			return turnstileResponse(http.StatusOK, strings.Repeat("x", maxTurnstileResponseBytes+1)), nil
		})
	}))
	tooLarge := strings.Repeat("a", maxTurnstileTokenBytes+1)
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, tooLarge), turnstileBinding(turnstileTestNow)); !errors.Is(err, ErrInvalid) || calls != 0 {
		t.Fatalf("oversized token error=%v calls=%d", err, calls)
	}
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, turnstileTestToken), turnstileBinding(turnstileTestNow)); !errors.Is(err, ErrTurnstileService) || calls != 1 {
		t.Fatalf("oversized response error=%v calls=%d", err, calls)
	}
	badSecret := &ephemeralTurnstileSecret{material: []byte("bad\nsecret")}
	verifier = mustTurnstileVerifier(t, withTurnstileConfig(base, func(config *TurnstileConfig) {
		config.Secret = badSecret
		config.Transport = webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("invalid secret reached network")
			return nil, nil
		})
	}))
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, turnstileProvider, turnstileTestToken), turnstileBinding(turnstileTestNow)); !errors.Is(err, ErrTurnstileService) {
		t.Fatalf("invalid secret error = %v", err)
	}
}

func TestTurnstileUUIDIsCanonicalV4(t *testing.T) {
	seen := make(map[string]struct{})
	for range 64 {
		value, err := newTurnstileUUID()
		if err != nil || !turnstileUUIDPattern.MatchString(value) {
			t.Fatalf("UUID=%q err=%v", value, err)
		}
		if _, duplicate := seen[value]; duplicate {
			t.Fatalf("duplicate UUID %q", value)
		}
		seen[value] = struct{}{}
	}
}

func TestTurnstileSiteverifyBodyEscapesSecretWithoutRetainingItsBuffer(t *testing.T) {
	secret := []byte("secret&value=with+reserved%characters~")
	body := turnstileSiteverifyBody(secret, "token/value?and space", "request-id")
	encoded := string(body)
	form, err := url.ParseQuery(encoded)
	if err != nil {
		t.Fatalf("parse Siteverify body: %v", err)
	}
	if len(form) != 3 || form.Get("secret") != string(secret) ||
		form.Get("response") != "token/value?and space" || form.Get("idempotency_key") != "request-id" {
		t.Fatalf("unexpected Siteverify form: %q", encoded)
	}
	clear(secret)
	if strings.Contains(encoded, "secret&value") || !strings.Contains(encoded, "secret%26value%3Dwith%2Breserved%25characters~") {
		t.Fatalf("secret was not independently form encoded: %q", encoded)
	}
	clear(body)
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("Siteverify request body was not clearable")
	}
}

func FuzzParseTurnstileResponse(f *testing.F) {
	f.Add([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	f.Add([]byte(`{"success":true,"challenge_ts":"2026-08-29T12:00:00Z","hostname":"app.example.com","action":"session","cdata":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _, err := parseTurnstileResponse(encoded)
		if err != nil && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrTurnstileService) {
			t.Fatalf("unexpected parser error: %v", err)
		}
	})
}

func mustTurnstileVerifier(t *testing.T, config TurnstileConfig) *TurnstileVerifier {
	t.Helper()
	verifier, err := NewTurnstileVerifier(config)
	if err != nil {
		t.Fatalf("construct Turnstile verifier: %v", err)
	}
	return verifier
}

func turnstileBinding(now time.Time) Binding {
	binding := testBinding()
	binding.Platform = "web"
	binding.IssuedAt = now.Add(-2 * time.Minute).Unix()
	return binding
}

func turnstileResponse(status int, body string) *http.Response {
	response := &http.Response{
		StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)),
	}
	response.Header.Set("Content-Type", "application/json; charset=UTF-8")
	return response
}

func withTurnstileConfig(config TurnstileConfig, mutate func(*TurnstileConfig)) TurnstileConfig {
	mutate(&config)
	return config
}
