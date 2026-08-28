package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"sort"
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
	Issuer               string
	Format               RemoteKeyFormat
	Client               *http.Client
	SharedCache          RemoteKeyDocumentCache
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
	target               *upstream.Target
	identity             remoteKeyIdentity
	sharedCache          RemoteKeyDocumentCache
	now                  func() time.Time
	defaultTTL           time.Duration
	maximumTTL           time.Duration
	staleGrace           time.Duration
	forcedRefreshMinimum time.Duration

	mu             sync.Mutex
	keys           map[string]staticKey
	document       []byte
	documentHash   [sha256.Size]byte
	etag           string
	lastModified   *time.Time
	fetchedAt      time.Time
	freshUntil     time.Time
	staleUntil     time.Time
	lastForced     time.Time
	refreshing     bool
	refreshDone    chan struct{}
	refreshOutcome error
	sharedOutcome  error
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
	if config.Issuer == "" {
		config.Issuer = config.URL
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Hostname() == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.String() != config.Issuer {
		return nil, fmt.Errorf("%w: remote key issuer", ErrConfiguration)
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
	var target *upstream.Target
	if client == nil {
		target, err = upstream.NewTarget(config.URL, upstream.DestinationPolicy{}, upstream.Timeouts{
			Connect: 5 * time.Second, TLSHandshake: 5 * time.Second, ResponseHeader: 10 * time.Second,
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: protected remote key target", ErrConfiguration)
		}
	} else {
		clientCopy := *client
		clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		if clientCopy.Timeout == 0 {
			clientCopy.Timeout = 15 * time.Second
		}
		client = &clientCopy
	}

	return &RemoteKeySource{
		url: config.URL, format: config.Format, client: client, target: target, now: config.Now,
		identity: newRemoteKeyIdentity(config.Issuer, config.URL, config.Format), sharedCache: config.SharedCache,
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
	refreshErr := source.refresh(ctx, forced, false)
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
	record, found, _, staleAllowed = source.snapshot(kid, algorithm, source.now().UTC())
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

// Refresh performs a conditional refresh of this fixed configured endpoint.
// Unlike request-time resolution, it reports a shared-cache write failure so
// the durable worker retries until API-only replicas can consume the result.
func (source *RemoteKeySource) Refresh(ctx context.Context) error {
	if source == nil || ctx == nil {
		return errors.New("remote key source is unavailable")
	}
	return source.refresh(ctx, false, true)
}

func (source *RemoteKeySource) refresh(ctx context.Context, forced, requireShared bool) error {
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
				outcome := source.refreshError(requireShared)
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
		local := source.cachedRecordLocked()
		source.mu.Unlock()

		result := source.refreshRemote(ctx, local, forced, now)

		source.mu.Lock()
		if len(result.keys) != 0 && len(result.record.document) != 0 {
			source.applyRecordLocked(result.record, result.keys)
		}
		source.refreshOutcome = result.err
		source.sharedOutcome = result.sharedErr
		source.refreshing = false
		close(source.refreshDone)
		outcome := source.refreshError(requireShared)
		source.mu.Unlock()
		return outcome
	}
}

func (source *RemoteKeySource) refreshError(requireShared bool) error {
	if source.refreshOutcome != nil {
		return source.refreshOutcome
	}
	if requireShared && source.sharedOutcome != nil {
		return source.sharedOutcome
	}
	return nil
}

func (source *RemoteKeySource) cachedRecordLocked() cachedRemoteKeyDocument {
	record := cachedRemoteKeyDocument{
		document: append([]byte(nil), source.document...), documentHash: source.documentHash,
		etag: source.etag, fetchedAt: source.fetchedAt,
		freshUntil: source.freshUntil, staleUntil: source.staleUntil,
	}
	if source.lastModified != nil {
		value := source.lastModified.UTC()
		record.lastModified = &value
	}
	return record
}

func (source *RemoteKeySource) applyRecordLocked(record cachedRemoteKeyDocument, keys map[string]staticKey) {
	source.keys = keys
	source.document = append(source.document[:0], record.document...)
	source.documentHash = record.documentHash
	source.etag = record.etag
	source.lastModified = record.lastModified
	source.fetchedAt = record.fetchedAt
	source.freshUntil = record.freshUntil
	source.staleUntil = record.staleUntil
}

type remoteRefreshResult struct {
	record    cachedRemoteKeyDocument
	keys      map[string]staticKey
	err       error
	sharedErr error
}

func (source *RemoteKeySource) refreshRemote(
	ctx context.Context,
	local cachedRemoteKeyDocument,
	forced bool,
	now time.Time,
) remoteRefreshResult {
	base, baseKeys, baseFound := local, map[string]staticKey(nil), len(local.document) != 0
	if baseFound {
		baseKeys, _ = source.parseCachedDocument(local, now)
	}
	if source.sharedCache == nil {
		return source.fetchAndBuild(ctx, remoteKeyRefreshLease{}, base, baseKeys, baseFound, false, now)
	}

	var sharedErr error
	shared, found, err := source.sharedCache.load(ctx, source.identity)
	if err != nil {
		sharedErr = err
	} else if found {
		keys, parseErr := source.parseCachedDocument(shared, now)
		if parseErr != nil {
			sharedErr = parseErr
		} else {
			base, baseKeys, baseFound = shared, keys, true
			if !forced && now.Before(shared.freshUntil) {
				return remoteRefreshResult{record: shared, keys: keys}
			}
		}
	}

	lease, leasedRecord, leasedFound, acquired, err := source.sharedCache.acquire(ctx, source.identity)
	if err != nil {
		if sharedErr == nil {
			sharedErr = err
		}
		result := source.fetchAndBuild(ctx, lease, base, baseKeys, baseFound, acquired, now)
		result.sharedErr = sharedErr
		return result
	}
	if leasedFound {
		keys, parseErr := source.parseCachedDocument(leasedRecord, now)
		if parseErr != nil {
			if acquired {
				source.releaseLease(ctx, lease)
			}
			result := source.fetchAndBuild(ctx, remoteKeyRefreshLease{}, base, baseKeys, baseFound, false, now)
			result.sharedErr = parseErr
			return result
		}
		base, baseKeys, baseFound = leasedRecord, keys, true
	}
	if !acquired {
		if leasedFound && now.Before(leasedRecord.freshUntil) {
			return remoteRefreshResult{record: leasedRecord, keys: baseKeys}
		}
		return remoteRefreshResult{
			record: base, keys: baseKeys,
			err: transientKeyFetch(errors.New("identity key refresh is already in progress")),
		}
	}
	result := source.fetchAndBuild(ctx, lease, base, baseKeys, baseFound, true, now)
	if sharedErr != nil && result.sharedErr == nil {
		result.sharedErr = sharedErr
	}
	return result
}

func (source *RemoteKeySource) fetchAndBuild(
	ctx context.Context,
	lease remoteKeyRefreshLease,
	base cachedRemoteKeyDocument,
	baseKeys map[string]staticKey,
	baseFound, ownsLease bool,
	now time.Time,
) remoteRefreshResult {
	fetched, err := source.fetch(ctx, base.etag, base.lastModified, now)
	if err != nil {
		if ownsLease {
			source.releaseLease(ctx, lease)
		}
		return remoteRefreshResult{record: base, keys: baseKeys, err: err}
	}
	var record cachedRemoteKeyDocument
	keys := fetched.keys
	if fetched.notModified {
		if !baseFound || len(base.document) == 0 || len(baseKeys) == 0 {
			if ownsLease {
				source.releaseLease(ctx, lease)
			}
			return remoteRefreshResult{err: errors.New("key endpoint returned not-modified without a cached set")}
		}
		record, keys = base, baseKeys
		if fetched.etag != "" {
			record.etag = fetched.etag
		}
		if fetched.lastModified != nil {
			record.lastModified = fetched.lastModified
		}
	} else {
		record = cachedRemoteKeyDocument{
			document: fetched.document, documentHash: sha256.Sum256(fetched.document),
			etag: fetched.etag, lastModified: fetched.lastModified,
		}
	}
	record.fetchedAt = now
	record.freshUntil = now.Add(fetched.ttl)
	record.staleUntil = record.freshUntil.Add(fetched.staleGrace(source.staleGrace))
	if ownsLease {
		if err := source.sharedCache.complete(ctx, lease, record, fetched.noStore); err != nil {
			return remoteRefreshResult{record: record, keys: keys, sharedErr: err}
		}
	}
	return remoteRefreshResult{record: record, keys: keys}
}

func (source *RemoteKeySource) releaseLease(parent context.Context, lease remoteKeyRefreshLease) {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	_ = source.sharedCache.release(releaseCtx, lease)
}

func (source *RemoteKeySource) parseCachedDocument(record cachedRemoteKeyDocument, now time.Time) (map[string]staticKey, error) {
	if len(record.document) < 2 || len(record.document) > maxRemoteKeyDocumentBytes ||
		sha256.Sum256(record.document) != record.documentHash || record.fetchedAt.IsZero() ||
		record.fetchedAt.After(now.Add(5*time.Minute)) || record.freshUntil.Before(record.fetchedAt) ||
		record.freshUntil.Sub(record.fetchedAt) > source.maximumTTL ||
		record.staleUntil.Before(record.freshUntil) || record.staleUntil.Sub(record.freshUntil) > 24*time.Hour {
		return nil, errors.New("shared identity key document is invalid")
	}
	value, err := jsonsafe.Decode(record.document)
	if err != nil {
		return nil, errors.New("shared identity key document is invalid")
	}
	switch source.format {
	case RemoteKeyFormatJWKS:
		return parseJWKSet(value)
	case RemoteKeyFormatX509Certificate:
		return parseX509CertificateMap(value, now)
	default:
		return nil, ErrConfiguration
	}
}

type remoteKeyFetchResult struct {
	keys         map[string]staticKey
	document     []byte
	etag         string
	lastModified *time.Time
	ttl          time.Duration
	notModified  bool
	noStore      bool
}

func (result remoteKeyFetchResult) staleGrace(configured time.Duration) time.Duration {
	if result.noStore {
		return 0
	}
	return configured
}

func (source *RemoteKeySource) fetch(ctx context.Context, etag string, lastModified *time.Time, now time.Time) (remoteKeyFetchResult, error) {
	requestContext := ctx
	var cancel context.CancelFunc
	if source.target != nil {
		requestContext, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, source.url, nil)
	if err != nil {
		return remoteKeyFetchResult{}, errors.New("construct remote key request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway-gateway/key-refresh")
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	if lastModified != nil {
		request.Header.Set("If-Modified-Since", lastModified.UTC().Format(http.TimeFormat))
	}
	var response *http.Response
	var dispatched *upstream.DispatchedResponse
	if source.target != nil {
		prepared, prepareErr := upstream.PrepareBaseRequest(
			request,
			source.target,
			[]string{"Accept", "User-Agent", "If-None-Match", "If-Modified-Since"},
			nil,
		)
		if prepareErr != nil {
			return remoteKeyFetchResult{}, errors.New("construct protected remote key request")
		}
		dispatched, err = source.target.Dispatch(requestContext, prepared)
		if dispatched != nil {
			response = dispatched.Response
		}
	} else {
		response, err = source.client.Do(request)
	}
	if err != nil {
		if ctx.Err() != nil {
			return remoteKeyFetchResult{}, ctx.Err()
		}
		return remoteKeyFetchResult{}, transientKeyFetch(errors.New("remote key request failed"))
	}
	if response == nil || response.Body == nil {
		return remoteKeyFetchResult{}, transientKeyFetch(errors.New("remote key response is unavailable"))
	}
	if dispatched != nil {
		defer dispatched.Close()
	} else {
		defer response.Body.Close()
	}

	ttl := cacheLifetime(response.Header, now, source.defaultTTL, source.maximumTTL)
	noStore := cacheControlContains(response.Header, "no-store")
	responseETag := boundedETag(response.Header.Get("ETag"))
	responseLastModified := boundedLastModified(response.Header.Get("Last-Modified"))
	if response.StatusCode == http.StatusNotModified {
		return remoteKeyFetchResult{etag: responseETag, lastModified: responseLastModified, ttl: ttl, notModified: true, noStore: noStore}, nil
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
	document, err := publicRemoteKeyDocument(source.format, value, keys)
	if err != nil || len(document) < 2 || len(document) > maxRemoteKeyDocumentBytes {
		return remoteKeyFetchResult{}, errors.New("remote key document is invalid")
	}
	return remoteKeyFetchResult{
		keys: keys, document: document, etag: responseETag, lastModified: responseLastModified,
		ttl: ttl, noStore: noStore,
	}, nil
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

// publicRemoteKeyDocument canonicalizes only the verification material that
// survived parsing. Provider extensions and every private JWK member are
// deliberately discarded before a document can reach PostgreSQL.
func publicRemoteKeyDocument(format RemoteKeyFormat, value any, keys map[string]staticKey) ([]byte, error) {
	switch format {
	case RemoteKeyFormatJWKS:
		ids := make([]string, 0, len(keys))
		for kid := range keys {
			ids = append(ids, kid)
		}
		sort.Strings(ids)
		entries := make([]map[string]any, 0, len(ids))
		for _, kid := range ids {
			record := keys[kid]
			entry := map[string]any{
				"kid": kid, "use": "sig", "key_ops": []string{"verify"},
			}
			if record.alg != "" {
				entry["alg"] = record.alg
			}
			switch key := record.key.(type) {
			case *rsa.PublicKey:
				if key == nil || key.N == nil || key.E <= 0 {
					return nil, errors.New("JWKS RSA public key is invalid")
				}
				exponent := big.NewInt(int64(key.E)).Bytes()
				entry["kty"] = "RSA"
				entry["n"] = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
				entry["e"] = base64.RawURLEncoding.EncodeToString(exponent)
			case *ecdsa.PublicKey:
				if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
					return nil, errors.New("JWKS EC public key is invalid")
				}
				var curve string
				switch key.Curve {
				case elliptic.P256():
					curve = "P-256"
				case elliptic.P384():
					curve = "P-384"
				default:
					return nil, errors.New("JWKS EC public key is unsupported")
				}
				coordinateBytes := (key.Curve.Params().BitSize + 7) / 8
				entry["kty"] = "EC"
				entry["crv"] = curve
				entry["x"] = base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, coordinateBytes)))
				entry["y"] = base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, coordinateBytes)))
			default:
				return nil, errors.New("JWKS public key type is unsupported")
			}
			entries = append(entries, entry)
		}
		return json.Marshal(map[string]any{"keys": entries})
	case RemoteKeyFormatX509Certificate:
		// parseX509CertificateMap has already proven every value is a bounded
		// public certificate and rejects all other document members.
		return json.Marshal(value)
	default:
		return nil, ErrConfiguration
	}
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

func boundedLastModified(value string) *time.Time {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return nil
	}
	parsed, err := http.ParseTime(value)
	if err != nil {
		return nil
	}
	parsed = parsed.UTC().Truncate(time.Second)
	return &parsed
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
