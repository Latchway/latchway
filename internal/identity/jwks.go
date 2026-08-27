package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	maxRemoteKeyDocumentBytes = 1 << 20
	maxRemoteKeys             = 100
)

// RemoteKeyFormat identifies the two public-key document formats used by the
// supported identity providers.
type RemoteKeyFormat string

const (
	RemoteKeyFormatJWKS            RemoteKeyFormat = "jwks"
	RemoteKeyFormatX509Certificate RemoteKeyFormat = "x509_certificate_map"
)

// RemoteKeySourceConfig configures a fixed, server-selected public-key URL.
// When Client is nil, a DNS-rebinding-resistant, redirect-disabled client is
// built with the same outbound destination policy as AI upstreams. Client is
// injectable so tests can use an in-memory RoundTripper without opening ports.
type RemoteKeySourceConfig struct {
	URL                  string
	Format               RemoteKeyFormat
	Client               *http.Client
	Now                  func() time.Time
	DefaultTTL           time.Duration
	MaximumTTL           time.Duration
	StaleGrace           time.Duration
	ForcedRefreshMinimum time.Duration
}

// RemoteKeySource implements a bounded conditional cache with single-flight
// refreshes. A token can select only a key ID; it can never select the URL.
type RemoteKeySource struct {
	url                  string
	format               RemoteKeyFormat
	client               *http.Client
	now                  func() time.Time
	defaultTTL           time.Duration
	maximumTTL           time.Duration
	staleGrace           time.Duration
	forcedRefreshMinimum time.Duration

	mu             sync.Mutex
	keys           map[string]staticKey
	etag           string
	freshUntil     time.Time
	staleUntil     time.Time
	lastForced     time.Time
	refreshing     bool
	refreshDone    chan struct{}
	refreshOutcome error
}

// NewRemoteKeySource validates config and constructs a public-key source.
func NewRemoteKeySource(config RemoteKeySourceConfig) (*RemoteKeySource, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.String() != config.URL {
		return nil, fmt.Errorf("%w: remote key URL", ErrConfiguration)
	}
	if config.Format != RemoteKeyFormatJWKS && config.Format != RemoteKeyFormatX509Certificate {
		return nil, fmt.Errorf("%w: remote key format", ErrConfiguration)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 5 * time.Minute
	}
	if config.MaximumTTL == 0 {
		config.MaximumTTL = 24 * time.Hour
	}
	if config.StaleGrace == 0 {
		config.StaleGrace = 15 * time.Minute
	}
	if config.ForcedRefreshMinimum == 0 {
		config.ForcedRefreshMinimum = 10 * time.Second
	}
	if config.DefaultTTL < 0 || config.MaximumTTL <= 0 || config.DefaultTTL > config.MaximumTTL || config.StaleGrace < 0 || config.StaleGrace > 24*time.Hour || config.ForcedRefreshMinimum < 0 || config.ForcedRefreshMinimum > time.Hour {
		return nil, fmt.Errorf("%w: remote key cache durations", ErrConfiguration)
	}

	client := config.Client
	if client == nil {
		target, targetErr := upstream.NewTarget(config.URL, upstream.DestinationPolicy{}, upstream.Timeouts{
			Connect: 5 * time.Second, TLSHandshake: 5 * time.Second, ResponseHeader: 10 * time.Second,
		}, nil)
		if targetErr != nil {
			return nil, fmt.Errorf("%w: protected remote key target", ErrConfiguration)
		}
		client = target.Client()
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 15 * time.Second
	}

	return &RemoteKeySource{
		url: config.URL, format: config.Format, client: &clientCopy, now: config.Now,
		defaultTTL: config.DefaultTTL, maximumTTL: config.MaximumTTL, staleGrace: config.StaleGrace,
		forcedRefreshMinimum: config.ForcedRefreshMinimum, keys: make(map[string]staticKey),
	}, nil
}

// Key resolves kid and refreshes stale or unknown key sets as needed.
func (source *RemoteKeySource) Key(ctx context.Context, kid, algorithm string) (any, error) {
	if source == nil || kid == "" || len(kid) > 256 || strings.ContainsAny(kid, "\r\n\x00") {
		return nil, ErrKeyUnavailable
	}
	if _, supported := allowedJWTAlgs[algorithm]; !supported || algorithm == "HS256" {
		return nil, ErrKeyUnavailable
	}

	now := source.now().UTC()
	record, found, fresh, staleAllowed := source.snapshot(kid, algorithm, now)
	if found && fresh {
		return record.key, nil
	}
	forced := !found && source.hasKeys()
	refreshErr := source.refresh(ctx, forced)
	if refreshErr == nil {
		record, found, _, _ = source.snapshot(kid, algorithm, source.now().UTC())
		if found {
			return record.key, nil
		}
		return nil, ErrKeyUnavailable
	}
	if errors.Is(refreshErr, context.Canceled) || errors.Is(refreshErr, context.DeadlineExceeded) {
		return nil, refreshErr
	}
	if found && staleAllowed && isTransientKeyFetch(refreshErr) {
		return record.key, nil
	}
	return nil, ErrKeyUnavailable
}

func (source *RemoteKeySource) snapshot(kid, algorithm string, now time.Time) (staticKey, bool, bool, bool) {
	source.mu.Lock()
	defer source.mu.Unlock()
	record, found := source.keys[kid]
	if found && ((record.alg != "" && record.alg != algorithm) || !keySupportsAlgorithm(record.key, algorithm)) {
		found = false
	}
	return record, found, found && now.Before(source.freshUntil), found && now.Before(source.staleUntil)
}

func (source *RemoteKeySource) hasKeys() bool {
	source.mu.Lock()
	defer source.mu.Unlock()
	return len(source.keys) > 0
}

func (source *RemoteKeySource) refresh(ctx context.Context, forced bool) error {
	for {
		now := source.now().UTC()
		source.mu.Lock()
		if source.refreshing {
			done := source.refreshDone
			source.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
				source.mu.Lock()
				outcome := source.refreshOutcome
				source.mu.Unlock()
				return outcome
			}
		}
		if !forced && len(source.keys) > 0 && now.Before(source.freshUntil) {
			source.mu.Unlock()
			return nil
		}
		if forced && !source.lastForced.IsZero() && now.Sub(source.lastForced) < source.forcedRefreshMinimum {
			source.mu.Unlock()
			return transientKeyFetch(errors.New("forced key refresh is throttled"))
		}
		if forced {
			source.lastForced = now
		}
		source.refreshing = true
		source.refreshDone = make(chan struct{})
		etag := source.etag
		source.mu.Unlock()

		result, err := source.fetch(ctx, etag, now)

		source.mu.Lock()
		if err == nil {
			if result.notModified {
				if len(source.keys) == 0 {
					err = errors.New("key endpoint returned not-modified without a cached set")
				} else {
					source.freshUntil = now.Add(result.ttl)
					source.staleUntil = source.freshUntil.Add(result.staleGrace(source.staleGrace))
				}
			} else {
				source.keys = result.keys
				source.etag = result.etag
				source.freshUntil = now.Add(result.ttl)
				source.staleUntil = source.freshUntil.Add(result.staleGrace(source.staleGrace))
			}
		}
		source.refreshOutcome = err
		source.refreshing = false
		close(source.refreshDone)
		source.mu.Unlock()
		return err
	}
}

type remoteKeyFetchResult struct {
	keys        map[string]staticKey
	etag        string
	ttl         time.Duration
	notModified bool
	noStore     bool
}

func (result remoteKeyFetchResult) staleGrace(configured time.Duration) time.Duration {
	if result.noStore {
		return 0
	}
	return configured
}

func (source *RemoteKeySource) fetch(ctx context.Context, etag string, now time.Time) (remoteKeyFetchResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
	if err != nil {
		return remoteKeyFetchResult{}, errors.New("construct remote key request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway-gateway/key-refresh")
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := source.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return remoteKeyFetchResult{}, ctx.Err()
		}
		return remoteKeyFetchResult{}, transientKeyFetch(errors.New("remote key request failed"))
	}
	defer response.Body.Close()

	ttl := cacheLifetime(response.Header, now, source.defaultTTL, source.maximumTTL)
	noStore := cacheControlContains(response.Header, "no-store")
	if response.StatusCode == http.StatusNotModified {
		return remoteKeyFetchResult{ttl: ttl, notModified: true, noStore: noStore}, nil
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return remoteKeyFetchResult{}, transientKeyFetch(fmt.Errorf("remote key status %d", response.StatusCode))
		}
		return remoteKeyFetchResult{}, fmt.Errorf("remote key status %d", response.StatusCode)
	}
	if mediaType := response.Header.Get("Content-Type"); mediaType != "" {
		parsed, _, parseErr := mime.ParseMediaType(mediaType)
		if parseErr != nil || parsed != "application/json" {
			return remoteKeyFetchResult{}, errors.New("remote key content type is invalid")
		}
	}
	value, err := jsonsafe.DecodeReader(response.Body, maxRemoteKeyDocumentBytes)
	if err != nil {
		return remoteKeyFetchResult{}, errors.New("remote key document is invalid")
	}
	var keys map[string]staticKey
	switch source.format {
	case RemoteKeyFormatJWKS:
		keys, err = parseJWKSet(value)
	case RemoteKeyFormatX509Certificate:
		keys, err = parseX509CertificateMap(value, now)
	default:
		err = ErrConfiguration
	}
	if err != nil {
		return remoteKeyFetchResult{}, err
	}
	return remoteKeyFetchResult{keys: keys, etag: boundedETag(response.Header.Get("ETag")), ttl: ttl, noStore: noStore}, nil
}

func parseJWKSet(value any) (map[string]staticKey, error) {
	document, ok := value.(map[string]any)
	if !ok || len(document) == 0 || len(document) > 16 {
		return nil, errors.New("JWKS document shape is invalid")
	}
	entries, ok := document["keys"].([]any)
	if !ok || len(entries) == 0 || len(entries) > maxRemoteKeys {
		return nil, errors.New("JWKS key count is invalid")
	}
	keys := make(map[string]staticKey, len(entries))
	seenIDs := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		jwk, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New("JWKS key is not an object")
		}
		kid, ok := jwkString(jwk, "kid", true)
		if !ok || len(kid) > 256 || strings.ContainsAny(kid, "\r\n\x00") {
			return nil, errors.New("JWKS key ID is invalid")
		}
		if _, duplicate := seenIDs[kid]; duplicate {
			return nil, errors.New("JWKS contains duplicate key IDs")
		}
		seenIDs[kid] = struct{}{}
		if use, present := jwk["use"]; present && use != "sig" {
			continue
		}
		if operations, present := jwk["key_ops"]; present {
			if !jwkAllowsVerify(operations) {
				continue
			}
		}
		algorithm, ok := jwkString(jwk, "alg", false)
		if !ok {
			return nil, errors.New("JWKS algorithm is invalid")
		}
		if algorithm != "" {
			if _, allowed := allowedJWTAlgs[algorithm]; !allowed || algorithm == "HS256" {
				continue
			}
		}
		key, err := parseJWKPublicKey(jwk)
		if err != nil {
			return nil, err
		}
		if algorithm != "" && !keySupportsAlgorithm(key, algorithm) {
			return nil, errors.New("JWKS algorithm and key type disagree")
		}
		keys[kid] = staticKey{key: key, alg: algorithm}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable signature keys")
	}
	return keys, nil
}

func parseJWKPublicKey(jwk map[string]any) (any, error) {
	keyType, ok := jwkString(jwk, "kty", true)
	if !ok {
		return nil, errors.New("JWKS key type is invalid")
	}
	switch keyType {
	case "RSA":
		modulusText, modulusOK := jwkString(jwk, "n", true)
		exponentText, exponentOK := jwkString(jwk, "e", true)
		if !modulusOK || !exponentOK {
			return nil, errors.New("JWKS RSA parameters are invalid")
		}
		modulus, err := decodeCanonicalBase64URL(modulusText, 1024)
		if err != nil || len(modulus) < 256 {
			return nil, errors.New("JWKS RSA modulus is invalid")
		}
		exponentBytes, err := decodeCanonicalBase64URL(exponentText, 4)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			return nil, errors.New("JWKS RSA exponent is invalid")
		}
		exponent := 0
		for _, item := range exponentBytes {
			exponent = exponent<<8 | int(item)
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
		if err := validateAsymmetricKey(key); err != nil {
			return nil, errors.New("JWKS RSA public key is unsafe")
		}
		return key, nil
	case "EC":
		curveName, curveOK := jwkString(jwk, "crv", true)
		xText, xOK := jwkString(jwk, "x", true)
		yText, yOK := jwkString(jwk, "y", true)
		if !curveOK || !xOK || !yOK {
			return nil, errors.New("JWKS EC parameters are invalid")
		}
		var curve elliptic.Curve
		var coordinateBytes int
		switch curveName {
		case "P-256":
			curve, coordinateBytes = elliptic.P256(), 32
		case "P-384":
			curve, coordinateBytes = elliptic.P384(), 48
		default:
			return nil, errors.New("JWKS EC curve is unsupported")
		}
		x, errX := decodeCanonicalBase64URL(xText, coordinateBytes)
		y, errY := decodeCanonicalBase64URL(yText, coordinateBytes)
		if errX != nil || errY != nil || len(x) != coordinateBytes || len(y) != coordinateBytes {
			return nil, errors.New("JWKS EC coordinates are invalid")
		}
		key := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if err := validateAsymmetricKey(key); err != nil {
			return nil, errors.New("JWKS EC public key is unsafe")
		}
		return key, nil
	default:
		return nil, errors.New("JWKS key type is unsupported")
	}
}

func parseX509CertificateMap(value any, now time.Time) (map[string]staticKey, error) {
	document, ok := value.(map[string]any)
	if !ok || len(document) == 0 || len(document) > maxRemoteKeys {
		return nil, errors.New("certificate map shape is invalid")
	}
	keys := make(map[string]staticKey, len(document))
	for kid, raw := range document {
		certificatePEM, ok := raw.(string)
		if !ok || kid == "" || len(kid) > 256 || strings.ContainsAny(kid, "\r\n\x00") || len(certificatePEM) > 64<<10 {
			return nil, errors.New("certificate map entry is invalid")
		}
		block, remainder := pem.Decode([]byte(certificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(remainder))) != 0 {
			return nil, errors.New("certificate map PEM is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, errors.New("certificate map certificate is invalid")
		}
		if err := validateAsymmetricKey(certificate.PublicKey); err != nil {
			return nil, errors.New("certificate map public key is unsafe")
		}
		keys[kid] = staticKey{key: certificate.PublicKey}
	}
	return keys, nil
}

func jwkString(jwk map[string]any, name string, required bool) (string, bool) {
	value, present := jwk[name]
	if !present {
		return "", !required
	}
	text, ok := value.(string)
	if !ok || (required && text == "") || len(text) > 4096 || strings.ContainsRune(text, '\x00') {
		return "", false
	}
	return text, true
}

func jwkAllowsVerify(value any) bool {
	operations, ok := value.([]any)
	if !ok || len(operations) == 0 || len(operations) > 8 {
		return false
	}
	seenVerify := false
	for _, operation := range operations {
		text, ok := operation.(string)
		if !ok {
			return false
		}
		if text == "verify" {
			seenVerify = true
		}
	}
	return seenVerify
}

func decodeCanonicalBase64URL(value string, maximum int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errors.New("base64url value is invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("base64url value is invalid")
	}
	return decoded, nil
}

func cacheLifetime(headers http.Header, now time.Time, fallback, maximum time.Duration) time.Duration {
	if cacheControl := headers.Values("Cache-Control"); len(cacheControl) > 0 {
		for _, field := range cacheControl {
			for _, directive := range strings.Split(field, ",") {
				name, raw, hasValue := strings.Cut(strings.TrimSpace(directive), "=")
				if strings.EqualFold(name, "no-store") || strings.EqualFold(name, "no-cache") {
					return 0
				}
				if strings.EqualFold(name, "max-age") && hasValue {
					seconds, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64)
					if err == nil && seconds >= 0 {
						lifetime := time.Duration(seconds) * time.Second
						if age, ageErr := strconv.ParseInt(headers.Get("Age"), 10, 64); ageErr == nil && age > 0 {
							lifetime -= time.Duration(age) * time.Second
						}
						return clampCacheLifetime(lifetime, maximum)
					}
				}
			}
		}
	}
	if expires, err := http.ParseTime(headers.Get("Expires")); err == nil {
		return clampCacheLifetime(expires.Sub(now), maximum)
	}
	return clampCacheLifetime(fallback, maximum)
}

func cacheControlContains(headers http.Header, expected string) bool {
	for _, field := range headers.Values("Cache-Control") {
		for _, directive := range strings.Split(field, ",") {
			name, _, _ := strings.Cut(strings.TrimSpace(directive), "=")
			if strings.EqualFold(name, expected) {
				return true
			}
		}
	}
	return false
}

func clampCacheLifetime(value, maximum time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	if value > maximum {
		return maximum
	}
	return value
}

func boundedETag(value string) string {
	if len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
		return ""
	}
	return value
}

type keyFetchError struct {
	err error
}

func (err keyFetchError) Error() string { return err.err.Error() }
func (err keyFetchError) Unwrap() error { return err.err }

func transientKeyFetch(err error) error { return keyFetchError{err: err} }

func isTransientKeyFetch(err error) bool {
	var transient keyFetchError
	return errors.As(err, &transient)
}
