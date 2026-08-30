package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteKeySourceCachesRevalidatesRotatesAndThrottles(t *testing.T) {
	key1 := mustRSAKey(t)
	key2 := mustRSAKey(t)
	now := verifierTestNow
	var calls int
	handler := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			if request.Header.Get("If-None-Match") != "" {
				t.Fatal("initial key request unexpectedly used a validator")
			}
			return jsonResponse(http.StatusOK, jwksJSON(t, rsaJWK("key-1", "RS256", &key1.PublicKey)), map[string]string{
				"Cache-Control": "public, max-age=60", "ETag": `"v1"`,
			}), nil
		case 2:
			if request.Header.Get("If-None-Match") != `"v1"` {
				t.Fatalf("expected conditional request, got %q", request.Header.Get("If-None-Match"))
			}
			return jsonResponse(http.StatusNotModified, "", map[string]string{"Cache-Control": "max-age=60"}), nil
		case 3:
			return jsonResponse(http.StatusOK, jwksJSON(t, rsaJWK("key-2", "RS256", &key2.PublicKey)), map[string]string{
				"Cache-Control": "max-age=60", "ETag": `"v2"`,
			}), nil
		default:
			t.Fatalf("unexpected remote key request %d", calls)
			return nil, errors.New("unexpected request")
		}
	})
	source := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: "https://keys.example.test/.well-known/jwks.json", Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: handler}, Now: func() time.Time { return now },
		ForcedRefreshMinimum: 30 * time.Second,
	})

	resolved, err := source.Key(context.Background(), "key-1", "RS256")
	if err != nil || resolved.(*rsa.PublicKey).N.Cmp(key1.N) != 0 {
		t.Fatalf("resolve initial key: %v", err)
	}
	if _, err := source.Key(context.Background(), "key-1", "RS256"); err != nil || calls != 1 {
		t.Fatalf("fresh cache was not reused: calls=%d err=%v", calls, err)
	}

	now = now.Add(61 * time.Second)
	if _, err := source.Key(context.Background(), "key-1", "RS256"); err != nil || calls != 2 {
		t.Fatalf("conditional refresh failed: calls=%d err=%v", calls, err)
	}
	resolved, err = source.Key(context.Background(), "key-2", "RS256")
	if err != nil || resolved.(*rsa.PublicKey).N.Cmp(key2.N) != 0 || calls != 3 {
		t.Fatalf("unknown-key rotation failed: calls=%d err=%v", calls, err)
	}
	if _, err := source.Key(context.Background(), "attacker-controlled", "RS256"); !errors.Is(err, ErrKeyUnavailable) || calls != 3 {
		t.Fatalf("forced-refresh throttle failed: calls=%d err=%v", calls, err)
	}
}

func TestRemoteKeySourceUsesLastKnownGoodOnlyForTransientFailures(t *testing.T) {
	key := mustRSAKey(t)
	now := verifierTestNow
	status := http.StatusOK
	calls := 0
	handler := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		if status == http.StatusOK {
			return jsonResponse(http.StatusOK, jwksJSON(t, rsaJWK("key-1", "RS256", &key.PublicKey)), map[string]string{"Cache-Control": "max-age=1"}), nil
		}
		return jsonResponse(status, "", nil), nil
	})
	source := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: "https://keys.example.test/jwks", Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: handler}, Now: func() time.Time { return now }, StaleGrace: 2 * time.Minute,
	})
	if _, err := source.Key(context.Background(), "key-1", "RS256"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}

	status = http.StatusServiceUnavailable
	now = now.Add(2 * time.Second)
	if _, err := source.Key(context.Background(), "key-1", "RS256"); err != nil {
		t.Fatalf("expected transient last-known-good fallback, got %v", err)
	}
	status = http.StatusUnauthorized
	if _, err := source.Key(context.Background(), "key-1", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("permanent endpoint failure must fail closed, got %v", err)
	}
	status = http.StatusServiceUnavailable
	now = now.Add(3 * time.Minute)
	if _, err := source.Key(context.Background(), "key-1", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("expired stale grace must fail closed, got %v", err)
	}
	if calls != 4 {
		t.Fatalf("unexpected refresh count: %d", calls)
	}
}

func TestRemoteKeySourceDoesNotRetainNoStoreResponseForStaleFallback(t *testing.T) {
	key := mustRSAKey(t)
	calls := 0
	handler := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(http.StatusOK, jwksJSON(t, rsaJWK("key-1", "RS256", &key.PublicKey)), map[string]string{"Cache-Control": "no-store"}), nil
		}
		return jsonResponse(http.StatusServiceUnavailable, "", nil), nil
	})
	source := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: "https://keys.example.test/jwks", Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: handler}, Now: func() time.Time { return verifierTestNow }, StaleGrace: time.Hour,
	})
	if _, err := source.Key(context.Background(), "key-1", "RS256"); err != nil {
		t.Fatalf("resolve no-store response for current request: %v", err)
	}
	if _, err := source.Key(context.Background(), "key-1", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("no-store response must not be used as stale fallback: %v", err)
	}
}

func TestRemoteKeySourceSingleFlightsConcurrentRefresh(t *testing.T) {
	key := mustRSAKey(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	handler := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return jsonResponse(http.StatusOK, jwksJSON(t, rsaJWK("key-1", "RS256", &key.PublicKey)), map[string]string{"Cache-Control": "max-age=300"}), nil
	})
	source := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: "https://keys.example.test/jwks", Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: handler}, Now: func() time.Time { return verifierTestNow },
	})

	const workers = 24
	errorsByWorker := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := source.Key(context.Background(), "key-1", "RS256")
			errorsByWorker <- err
		}()
	}
	<-started
	close(release)
	group.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent key resolution: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one network refresh, got %d", calls.Load())
	}
}

func TestRemoteKeySourceRejectsMalformedAndConfusedJWKSets(t *testing.T) {
	key := mustRSAKey(t)
	valid := rsaJWK("same", "RS256", &key.PublicKey)
	confused := rsaJWK("same", "HS256", &key.PublicKey)
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate JSON member", body: `{"keys":[],"keys":[]}`},
		{name: "duplicate key ID", body: jwksJSON(t, valid, valid)},
		{name: "algorithm confusion", body: jwksJSON(t, confused)},
		{name: "padded modulus", body: jwksJSON(t, map[string]any{"kty": "RSA", "kid": "key", "alg": "RS256", "n": valid["n"].(string) + "=", "e": valid["e"]})},
		{name: "token key material", body: `{"keys":[{"kty":"oct","kid":"key","k":"c2VjcmV0"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, test.body, nil), nil
			})
			source := mustRemoteKeys(t, RemoteKeySourceConfig{
				URL: "https://keys.example.test/jwks", Format: RemoteKeyFormatJWKS,
				Client: &http.Client{Transport: handler}, Now: func() time.Time { return verifierTestNow },
			})
			if _, err := source.Key(context.Background(), "same", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
				t.Fatalf("expected malformed set to fail closed, got %v", err)
			}
		})
	}
}

func TestRemoteKeySourceParsesES256AndFirebaseCertificateMap(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecHandler := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, jwksJSON(t, ecJWK(t, "ec-1", "ES256", &ecKey.PublicKey)), nil), nil
	})
	ecSource := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL: "https://keys.example.test/jwks", Format: RemoteKeyFormatJWKS,
		Client: &http.Client{Transport: ecHandler}, Now: func() time.Time { return verifierTestNow },
	})
	if _, err := ecSource.Key(context.Background(), "ec-1", "ES256"); err != nil {
		t.Fatalf("resolve ES256 JWK: %v", err)
	}
	if _, err := ecSource.Key(context.Background(), "ec-1", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("cross-family algorithm confusion must fail: %v", err)
	}

	rsaKey := mustRSAKey(t)
	certificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "firebase fixture"},
		NotBefore: verifierTestNow.Add(-time.Hour), NotAfter: verifierTestNow.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	encoded, err := json.Marshal(map[string]string{"firebase-key": certificatePEM})
	if err != nil {
		t.Fatalf("marshal certificate map: %v", err)
	}
	certHandler := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, string(encoded), nil), nil
	})
	certSource := mustRemoteKeys(t, RemoteKeySourceConfig{
		URL:    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
		Format: RemoteKeyFormatX509Certificate, Client: &http.Client{Transport: certHandler},
		Now: func() time.Time { return verifierTestNow },
	})
	if _, err := certSource.Key(context.Background(), "firebase-key", "RS256"); err != nil {
		t.Fatalf("resolve certificate-map key: %v", err)
	}
}

func TestCacheLifetimeHonorsMetadataAndBounds(t *testing.T) {
	now := verifierTestNow
	tests := []struct {
		name    string
		headers http.Header
		want    time.Duration
	}{
		{name: "max age and age", headers: http.Header{"Cache-Control": {"public, max-age=120"}, "Age": {"20"}}, want: 100 * time.Second},
		{name: "no cache", headers: http.Header{"Cache-Control": {"no-cache"}}, want: 0},
		{name: "expires", headers: http.Header{"Expires": {now.Add(45 * time.Second).Format(http.TimeFormat)}}, want: 45 * time.Second},
		{name: "maximum", headers: http.Header{"Cache-Control": {"max-age=999999"}}, want: time.Hour},
		{name: "fallback", headers: http.Header{}, want: 5 * time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cacheLifetime(test.headers, now, 5*time.Minute, time.Hour); got != test.want {
				t.Fatalf("cache lifetime: got %v want %v", got, test.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	if status == http.StatusOK {
		header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for name, value := range headers {
		header.Set(name, value)
	}
	return &http.Response{
		StatusCode: status, Status: strconv.Itoa(status), Header: header,
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

func mustRemoteKeys(t *testing.T, config RemoteKeySourceConfig) *RemoteKeySource {
	t.Helper()
	source, err := NewRemoteKeySource(config)
	if err != nil {
		t.Fatalf("construct remote key source: %v", err)
	}
	return source
}

func jwksJSON(t *testing.T, keys ...map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return string(encoded)
}

func rsaJWK(kid, algorithm string, key *rsa.PublicKey) map[string]any {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": algorithm, "use": "sig", "key_ops": []string{"verify"},
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func ecJWK(t *testing.T, kid, algorithm string, key *ecdsa.PublicKey) map[string]any {
	t.Helper()
	encoded, err := key.Bytes()
	if err != nil || (len(encoded) != 65 && len(encoded) != 97) || encoded[0] != 4 {
		t.Fatalf("encode EC JWK fixture: bytes=%d err=%v", len(encoded), err)
	}
	coordinateSize := (len(encoded) - 1) / 2
	x := encoded[1 : 1+coordinateSize]
	y := encoded[1+coordinateSize:]
	curve := "P-256"
	if coordinateSize == 48 {
		curve = "P-384"
	}
	return map[string]any{
		"kty": "EC", "kid": kid, "alg": algorithm, "use": "sig", "key_ops": []string{"verify"}, "crv": curve,
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
	}
}
