package attestation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	appCheckTestProject = "123456789012"
	appCheckTestAppID   = "1:123456789012:ios:0123456789abcdef"
)

var appCheckTestNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

type webAttestationRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip webAttestationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestFirebaseAppCheckVerifierAcceptsExactOfficialJWT(t *testing.T) {
	key := mustAppCheckRSAKey(t)
	var requests atomic.Int64
	transport := webAttestationRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.URL.String() != firebaseAppCheckJWKSURL ||
			request.Header.Get("Accept") != "application/json" || request.Header.Get("If-None-Match") != "" {
			t.Fatalf("unexpected App Check key request: %s %s headers=%v", request.Method, request.URL.Redacted(), request.Header)
		}
		return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "app-check-key", &key.PublicKey), map[string]string{
			"Cache-Control": "public, max-age=21600", "ETag": `"app-check-v1"`,
		}), nil
	})
	verifier := mustFirebaseAppCheckVerifier(t, FirebaseAppCheckConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		ProjectNumber: appCheckTestProject, AllowedAppIDs: []string{appCheckTestAppID},
		Transport: transport, Now: func() time.Time { return appCheckTestNow },
	})
	binding := appCheckBinding("react_native_ios", appCheckTestNow)
	token := signAppCheckToken(t, key, "app-check-key", "JWT", appCheckClaims(
		appCheckTestAppID, appCheckTestProject, appCheckTestNow,
	))
	evidence := mustWebEvidence(t, firebaseAppCheckProvider, token)

	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("verify App Check token: %v", err)
	}
	if result.Provider != firebaseAppCheckProvider || result.TrustLevel != "app_verified" ||
		!result.VerifiedAt.Equal(appCheckTestNow) || !result.ExpiresAt.Equal(appCheckTestNow.Add(10*time.Minute)) ||
		result.NormalizedSignals["app_identity_valid"] != true ||
		result.NormalizedSignals["verified_app_id"] != appCheckTestAppID ||
		result.NormalizedSignals["project_number"] != appCheckTestProject || requests.Load() != 1 {
		t.Fatalf("unexpected App Check result=%#v requests=%d", result, requests.Load())
	}
	bindingHash, hashErr := binding.Hash()
	if hashErr != nil {
		t.Fatal(hashErr)
	}
	if _, err := result.ValidatedSnapshot(bindingHash, appCheckTestNow); err != nil {
		t.Fatalf("validate App Check result: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), evidence, binding); err != nil || requests.Load() != 1 {
		t.Fatalf("fresh JWKS was not cached: requests=%d err=%v", requests.Load(), err)
	}
	for _, rendered := range []string{fmt.Sprint(verifier), fmt.Sprintf("%#v", verifier), fmt.Sprintf("%+v", *verifier)} {
		if strings.Contains(rendered, token) || !strings.Contains(rendered, "REDACTED") {
			t.Fatalf("App Check verifier formatting was unsafe: %q", rendered)
		}
	}
}

func TestFirebaseAppCheckVerifierRejectsHeaderClaimsAndScope(t *testing.T) {
	key := mustAppCheckRSAKey(t)
	transport := webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
		return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "valid-key", &key.PublicKey), nil), nil
	})
	verifier := mustFirebaseAppCheckVerifier(t, FirebaseAppCheckConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		ProjectNumber: appCheckTestProject, AllowedAppIDs: []string{appCheckTestAppID},
		Transport: transport, Now: func() time.Time { return appCheckTestNow },
	})
	validClaims := appCheckClaims(appCheckTestAppID, appCheckTestProject, appCheckTestNow)
	tests := []struct {
		name    string
		typ     string
		claims  jwt.MapClaims
		binding Binding
	}{
		{name: "missing typ", claims: validClaims, binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "lowercase typ", typ: "jwt", claims: validClaims, binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "wrong issuer", typ: "JWT", claims: withAppCheckClaim(validClaims, "iss", firebaseAppCheckIssuerPrefix+"999999999999"), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "wrong audience", typ: "JWT", claims: withAppCheckClaim(validClaims, "aud", []string{"projects/999999999999"}), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "ambiguous audience", typ: "JWT", claims: withAppCheckClaim(validClaims, "aud", []string{"projects/" + appCheckTestProject, "other"}), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "wrong subject", typ: "JWT", claims: withAppCheckClaim(validClaims, "sub", "1:123456789012:ios:not-allowed"), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "expired", typ: "JWT", claims: withAppCheckClaim(validClaims, "exp", appCheckTestNow.Add(-time.Minute).Unix()), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "future issued at", typ: "JWT", claims: withAppCheckClaim(validClaims, "iat", appCheckTestNow.Add(2*time.Minute).Unix()), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "future not before", typ: "JWT", claims: withAppCheckClaim(validClaims, "nbf", appCheckTestNow.Add(2*time.Minute).Unix()), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "not before after expiry", typ: "JWT", claims: withAppCheckClaims(validClaims, map[string]any{"nbf": appCheckTestNow.Add(20 * time.Second).Unix(), "exp": appCheckTestNow.Add(10 * time.Second).Unix()}), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "excess lifetime", typ: "JWT", claims: withAppCheckClaim(validClaims, "exp", appCheckTestNow.Add(8*24*time.Hour).Unix()), binding: appCheckBinding("ios", appCheckTestNow)},
		{name: "wrong application", typ: "JWT", claims: validClaims, binding: withAppCheckBindingApplication(appCheckBinding("ios", appCheckTestNow), "app_other")},
		{name: "node platform", typ: "JWT", claims: validClaims, binding: appCheckBinding("node", appCheckTestNow)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signAppCheckToken(t, key, "valid-key", test.typ, test.claims)
			_, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, token), test.binding)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("verification error = %v, want ErrInvalid", err)
			}
		})
	}

	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims)
	hmac.Header["kid"] = "valid-key"
	hmac.Header["typ"] = "JWT"
	hmacToken, err := hmac.SignedString([]byte("not-an-rsa-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, hmacToken), appCheckBinding("ios", appCheckTestNow)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("HS256 token error = %v", err)
	}
}

func TestFirebaseAppCheckJWKSCacheIsBoundedRefreshesAndUsesLastKnownGood(t *testing.T) {
	key1 := mustAppCheckRSAKey(t)
	key2 := mustAppCheckRSAKey(t)
	now := appCheckTestNow
	var calls atomic.Int64
	status := atomic.Int64{}
	status.Store(http.StatusOK)
	transport := webAttestationRoundTripper(func(request *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if request.URL.String() != firebaseAppCheckJWKSURL {
			t.Fatalf("JWKS URL = %s", request.URL.Redacted())
		}
		if status.Load() != http.StatusOK {
			return appCheckJSONResponse(int(status.Load()), `{"provider_body":"must-not-leak"}`, nil), nil
		}
		if call == 1 {
			return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "key-1", &key1.PublicKey), map[string]string{
				"Cache-Control": "max-age=999999999", "ETag": `"v1"`,
			}), nil
		}
		return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "key-2", &key2.PublicKey), map[string]string{
			"Cache-Control": "max-age=60", "ETag": `"v2"`,
		}), nil
	})
	verifier := mustFirebaseAppCheckVerifier(t, FirebaseAppCheckConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		ProjectNumber: appCheckTestProject, AllowedAppIDs: []string{appCheckTestAppID},
		Transport: transport, Now: func() time.Time { return now },
	})
	binding := appCheckBinding("android", now)
	token1 := signAppCheckToken(t, key1, "key-1", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, now))
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, token1), binding); err != nil {
		t.Fatalf("prime App Check cache: %v", err)
	}
	now = now.Add(firebaseAppCheckMaximumJWKSCache - time.Second)
	binding.IssuedAt = now.Add(-time.Second).Unix()
	token1 = signAppCheckToken(t, key1, "key-1", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, now))
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, token1), binding); err != nil || calls.Load() != 1 {
		t.Fatalf("capped fresh cache was not reused: calls=%d err=%v", calls.Load(), err)
	}
	now = now.Add(2 * time.Second)
	binding.IssuedAt = now.Add(-time.Second).Unix()
	token1 = signAppCheckToken(t, key1, "key-1", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, now))
	status.Store(http.StatusServiceUnavailable)
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, token1), binding); err != nil || calls.Load() != 2 {
		t.Fatalf("transient refresh did not use last-known-good: calls=%d err=%v", calls.Load(), err)
	}
	status.Store(http.StatusOK)
	token2 := signAppCheckToken(t, key2, "key-2", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, now))
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, token2), binding); err != nil || calls.Load() != 3 {
		t.Fatalf("unknown kid did not force one bounded refresh: calls=%d err=%v", calls.Load(), err)
	}
	unknown := signAppCheckToken(t, key1, "attacker-selected-kid", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, now))
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, unknown), binding); !errors.Is(err, ErrFirebaseAppCheckService) || calls.Load() != 3 {
		t.Fatalf("unknown-kid refresh was not throttled: calls=%d err=%v", calls.Load(), err)
	}
}

func TestFirebaseAppCheckUnknownKidRefreshIsSingleFlight(t *testing.T) {
	key1 := mustAppCheckRSAKey(t)
	key2 := mustAppCheckRSAKey(t)
	var calls atomic.Int64
	release := make(chan struct{})
	transport := webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
		call := calls.Add(1)
		if call == 1 {
			return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "key-1", &key1.PublicKey), map[string]string{"Cache-Control": "max-age=3600"}), nil
		}
		<-release
		return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "key-2", &key2.PublicKey), map[string]string{"Cache-Control": "max-age=3600"}), nil
	})
	verifier := mustFirebaseAppCheckVerifier(t, FirebaseAppCheckConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		ProjectNumber: appCheckTestProject, AllowedAppIDs: []string{appCheckTestAppID},
		Transport: transport, Now: func() time.Time { return appCheckTestNow },
	})
	binding := appCheckBinding("react_native_android", appCheckTestNow)
	prime := signAppCheckToken(t, key1, "key-1", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, appCheckTestNow))
	if _, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, prime), binding); err != nil {
		t.Fatal(err)
	}
	rotated := signAppCheckToken(t, key2, "key-2", "JWT", appCheckClaims(appCheckTestAppID, appCheckTestProject, appCheckTestNow))
	const workers = 16
	start := make(chan struct{})
	errorsChannel := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := verifier.Verify(context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, rotated), binding)
			errorsChannel <- err
		}()
	}
	close(start)
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() < 2 {
		close(release)
		t.Fatal("unknown-kid refresh did not start")
	}
	close(release)
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("single-flight verifier error: %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("unknown kid caused %d JWKS requests, want 1 refresh", calls.Load()-1)
	}
}

func TestFirebaseAppCheckJWKSFailuresAreBoundedAndSanitized(t *testing.T) {
	key := mustAppCheckRSAKey(t)
	token := signAppCheckToken(t, key, "key", "JWT", appCheckClaims(
		appCheckTestAppID, appCheckTestProject, appCheckTestNow,
	))
	tests := []struct {
		name         string
		status       int
		body         string
		transportErr error
	}{
		{name: "duplicate JSON", status: http.StatusOK, body: `{"keys":[],"keys":[{"provider":"must-not-leak"}]}`},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", (1<<20)+1)},
		{name: "redirect", status: http.StatusTemporaryRedirect, body: `{"provider":"must-not-leak"}`},
		{name: "server", status: http.StatusServiceUnavailable, body: `{"provider":"must-not-leak"}`},
		{name: "network", transportErr: errors.New("dial error included must-not-leak")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := webAttestationRoundTripper(func(request *http.Request) (*http.Response, error) {
				if test.transportErr != nil {
					return nil, test.transportErr
				}
				response := appCheckJSONResponse(test.status, test.body, nil)
				if test.status >= 300 && test.status < 400 {
					response.Header.Set("Location", "https://attacker.invalid/steal")
					response.Request = request
				}
				return response, nil
			})
			verifier := mustFirebaseAppCheckVerifier(t, FirebaseAppCheckConfig{
				ApplicationID: "app_habitify", EnvironmentID: "production",
				ProjectNumber: appCheckTestProject, AllowedAppIDs: []string{appCheckTestAppID},
				Transport: transport, Now: func() time.Time { return appCheckTestNow },
			})
			_, err := verifier.Verify(
				context.Background(), mustWebEvidence(t, firebaseAppCheckProvider, token),
				appCheckBinding("ios", appCheckTestNow),
			)
			if !errors.Is(err, ErrFirebaseAppCheckService) || strings.Contains(fmt.Sprint(err), "must-not-leak") {
				t.Fatalf("JWKS failure = %v, want sanitized service error", err)
			}
		})
	}
}

func TestFirebaseAppCheckConfigurationAndEvidenceAreBounded(t *testing.T) {
	key := mustAppCheckRSAKey(t)
	var typedNilTransport *appCheckNilRoundTripper
	base := FirebaseAppCheckConfig{
		ApplicationID: "app_habitify", EnvironmentID: "production",
		ProjectNumber: appCheckTestProject, AllowedAppIDs: []string{appCheckTestAppID},
	}
	invalid := []FirebaseAppCheckConfig{
		withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) { config.ProjectNumber = "012345678901" }),
		withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) { config.AllowedAppIDs = nil }),
		withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) {
			config.AllowedAppIDs = []string{appCheckTestAppID, appCheckTestAppID}
		}),
		withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) { config.Transport = typedNilTransport }),
		withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) { config.Timeout = 31 * time.Second }),
		withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) { config.MaxTokenLifetime = 8 * 24 * time.Hour }),
	}
	for index, config := range invalid {
		if _, err := NewFirebaseAppCheckVerifier(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("invalid config %d error = %v", index, err)
		}
	}
	verifier := mustFirebaseAppCheckVerifier(t, withFirebaseConfig(base, func(config *FirebaseAppCheckConfig) {
		config.Transport = webAttestationRoundTripper(func(_ *http.Request) (*http.Response, error) {
			return appCheckJSONResponse(http.StatusOK, appCheckJWKS(t, "key", &key.PublicKey), nil), nil
		})
		config.Now = func() time.Time { return appCheckTestNow }
	}))
	tooLarge := strings.Repeat("a", maxFirebaseAppCheckTokenBytes+1)
	evidence, err := NewEvidence(firebaseAppCheckProvider, map[string]any{"token": tooLarge})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), evidence, appCheckBinding("ios", appCheckTestNow)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized App Check token error = %v", err)
	}
}

func FuzzFirebaseAppCheckJWTPreflight(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleSIsInR5cCI6IkpXVCJ9.e30.AA")
	f.Add("not-a-jwt")
	f.Fuzz(func(t *testing.T, token string) {
		err := preflightFirebaseAppCheckJWT(token)
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Fatalf("unexpected preflight error: %v", err)
		}
		if err == nil {
			err = validateFirebaseAppCheckJWTDates(token, appCheckTestNow, defaultFirebaseAppCheckSkew, defaultFirebaseAppCheckLifetime)
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected date error: %v", err)
			}
		}
	})
}

type appCheckNilRoundTripper struct{}

func (*appCheckNilRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

func mustFirebaseAppCheckVerifier(t *testing.T, config FirebaseAppCheckConfig) *FirebaseAppCheckVerifier {
	t.Helper()
	verifier, err := NewFirebaseAppCheckVerifier(config)
	if err != nil {
		t.Fatalf("construct Firebase App Check verifier: %v", err)
	}
	return verifier
}

func mustAppCheckRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func appCheckClaims(appID, projectNumber string, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": firebaseAppCheckIssuerPrefix + projectNumber,
		"sub": appID,
		"aud": []string{"projects/" + projectNumber},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	}
}

func withAppCheckClaim(source jwt.MapClaims, key string, value any) jwt.MapClaims {
	result := make(jwt.MapClaims, len(source))
	for name, item := range source {
		result[name] = item
	}
	result[key] = value
	return result
}

func withAppCheckClaims(source jwt.MapClaims, replacements map[string]any) jwt.MapClaims {
	result := make(jwt.MapClaims, len(source))
	for name, item := range source {
		result[name] = item
	}
	for name, item := range replacements {
		result[name] = item
	}
	return result
}

func signAppCheckToken(t *testing.T, key *rsa.PrivateKey, kid, typ string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	if typ == "" {
		delete(token.Header, "typ")
	} else {
		token.Header["typ"] = typ
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func appCheckJWKS(t *testing.T, kid string, key *rsa.PublicKey) string {
	t.Helper()
	exponent := big.NewInt(int64(key.E)).Bytes()
	document := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "key_ops": []any{"verify"},
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func appCheckJSONResponse(status int, body string, headers map[string]string) *http.Response {
	response := &http.Response{
		StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(body)),
	}
	response.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		response.Header.Set(name, value)
	}
	return response
}

func appCheckBinding(platform string, now time.Time) Binding {
	binding := testBinding()
	binding.Platform = platform
	binding.IssuedAt = now.Add(-30 * time.Second).Unix()
	return binding
}

func withAppCheckBindingApplication(binding Binding, applicationID string) Binding {
	binding.ApplicationID = applicationID
	return binding
}

func mustWebEvidence(t *testing.T, provider, token string) Evidence {
	t.Helper()
	evidence, err := NewEvidence(provider, map[string]any{"token": token})
	if err != nil {
		t.Fatalf("construct %s evidence: %v", provider, err)
	}
	return evidence
}

func withFirebaseConfig(config FirebaseAppCheckConfig, mutate func(*FirebaseAppCheckConfig)) FirebaseAppCheckConfig {
	mutate(&config)
	return config
}
