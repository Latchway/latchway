package dataplane

import (
	"container/list"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/upstream"
)

const defaultTargetCacheCapacity = 128

var errTargetCacheClosed = errors.New("protected target cache is closed")

type cachedDispatchTarget interface {
	DispatchTarget
	CloseIdleConnections()
}

type targetBuilder func(configuration.Upstream) (cachedDispatchTarget, error)

// TargetCache is a bounded concurrency-safe cache of protected upstream
// transports. It stores no authentication, secret, static-header, request, or
// response data. Callers must release every successfully acquired lease.
type TargetCache struct {
	mu       sync.Mutex
	capacity int
	build    targetBuilder
	entries  map[targetCacheKey]*targetCacheEntry
	lru      list.List
	closed   bool
}

type targetCacheKey struct {
	upstreamID              string
	upstreamType            string
	baseURL                 string
	insecureHTTP            bool
	traceContextPropagation string
	allowRedirects          bool
	allowPrivate            bool
	dnsPinning              bool
	allowedPorts            string
	allowedCIDRs            string
	connectTimeout          time.Duration
	responseHeaderTimeout   time.Duration
	firstByteTimeout        time.Duration
	idleTimeout             time.Duration
	totalTimeout            time.Duration
}

type targetCacheEntry struct {
	key     targetCacheKey
	target  cachedDispatchTarget
	element *list.Element
	active  int
	retired bool
	closed  bool
}

// NewTargetCache constructs the production cache with the fixed data-plane
// capacity. The application may pass it through Config.Targets and defer Close;
// when Config.Targets is nil, Handler owns an equivalent cache and Close must be
// called on the Handler instead.
func NewTargetCache() *TargetCache {
	cache, _ := newTargetCache(defaultTargetCacheCapacity, buildProtectedTarget)
	return cache
}

func newTargetCache(capacity int, build targetBuilder) (*TargetCache, error) {
	if capacity < 1 || build == nil {
		return nil, errInvalidConfiguration
	}
	return &TargetCache{
		capacity: capacity,
		build:    build,
		entries:  make(map[targetCacheKey]*targetCacheEntry, capacity),
	}, nil
}

// Acquire validates every transport/security field before consulting the
// cache. Construction is serialized with lookup so concurrent misses for one
// key create exactly one target.
func (cache *TargetCache) Acquire(config configuration.Upstream) (TargetLease, error) {
	key, err := protectedTargetKey(config)
	if err != nil {
		return nil, err
	}
	if cache == nil {
		return nil, errTargetCacheClosed
	}

	var retired cachedDispatchTarget
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		return nil, errTargetCacheClosed
	}
	if cache.capacity < 1 || cache.build == nil || cache.entries == nil {
		cache.mu.Unlock()
		return nil, errInvalidConfiguration
	}
	if entry := cache.entries[key]; entry != nil {
		entry.active++
		cache.lru.MoveToFront(entry.element)
		lease := newCachedTargetLease(cache, entry)
		cache.mu.Unlock()
		return lease, nil
	}

	target, err := cache.build(config)
	if err != nil || nilDependency(target) {
		cache.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, errTargetConfiguration
	}
	if len(cache.entries) >= cache.capacity {
		retired = cache.retireLRULocked()
	}
	entry := &targetCacheEntry{key: key, target: target, active: 1}
	entry.element = cache.lru.PushFront(entry)
	cache.entries[key] = entry
	lease := newCachedTargetLease(cache, entry)
	cache.mu.Unlock()

	closeCachedTarget(retired)
	return lease, nil
}

// Close rejects future acquisitions and retires every cached target. Idle
// targets close immediately; leased targets close after their final Release.
func (cache *TargetCache) Close() error {
	if cache == nil {
		return nil
	}
	var retired []cachedDispatchTarget
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		return nil
	}
	cache.closed = true
	for key, entry := range cache.entries {
		delete(cache.entries, key)
		entry.retired = true
		entry.element = nil
		if entry.active == 0 && !entry.closed {
			entry.closed = true
			retired = append(retired, entry.target)
		}
	}
	cache.lru.Init()
	cache.mu.Unlock()

	for _, target := range retired {
		closeCachedTarget(target)
	}
	return nil
}

func (cache *TargetCache) retireLRULocked() cachedDispatchTarget {
	element := cache.lru.Back()
	if element == nil {
		return nil
	}
	entry, _ := element.Value.(*targetCacheEntry)
	cache.lru.Remove(element)
	if entry == nil {
		return nil
	}
	delete(cache.entries, entry.key)
	entry.element = nil
	entry.retired = true
	if entry.active == 0 && !entry.closed {
		entry.closed = true
		return entry.target
	}
	return nil
}

func (cache *TargetCache) release(entry *targetCacheEntry) {
	if cache == nil || entry == nil {
		return
	}
	var retired cachedDispatchTarget
	cache.mu.Lock()
	if entry.active > 0 {
		entry.active--
	}
	if entry.active == 0 && entry.retired && !entry.closed {
		entry.closed = true
		retired = entry.target
	}
	cache.mu.Unlock()
	closeCachedTarget(retired)
}

func closeCachedTarget(target cachedDispatchTarget) {
	if !nilDependency(target) {
		target.CloseIdleConnections()
	}
}

type cachedTargetLease struct {
	cache    *TargetCache
	entry    *targetCacheEntry
	target   cachedDispatchTarget
	released atomic.Bool
}

func newCachedTargetLease(cache *TargetCache, entry *targetCacheEntry) *cachedTargetLease {
	return &cachedTargetLease{cache: cache, entry: entry, target: entry.target}
}

func (lease *cachedTargetLease) Release() {
	if lease == nil || !lease.released.CompareAndSwap(false, true) {
		return
	}
	lease.cache.release(lease.entry)
}

func (lease *cachedTargetLease) activeTarget() (cachedDispatchTarget, error) {
	if lease == nil || lease.released.Load() || nilDependency(lease.target) {
		return nil, errTargetConfiguration
	}
	return lease.target, nil
}

func (lease *cachedTargetLease) Prepare(
	incoming *http.Request,
	requestPath string,
	forwardedHeaders []string,
	staticHeaders map[string]string,
) (ProviderRequest, error) {
	target, err := lease.activeTarget()
	if err != nil {
		return ProviderRequest{}, err
	}
	return target.Prepare(incoming, requestPath, forwardedHeaders, staticHeaders)
}

func (lease *cachedTargetLease) DispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	beforeRoundTrip func() error,
) (*upstream.DispatchedResponse, error) {
	target, err := lease.activeTarget()
	if err != nil {
		return nil, err
	}
	return target.DispatchWithBeforeRoundTrip(ctx, request, beforeRoundTrip)
}

func (lease *cachedTargetLease) WithBearerDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	target, err := lease.activeTarget()
	if err != nil {
		return err
	}
	return target.WithBearerDispatchWithBeforeRoundTrip(
		ctx, request, credential, beforeRoundTrip, consume,
	)
}

func (lease *cachedTargetLease) WithHeaderDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	name string,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	target, err := lease.activeTarget()
	if err != nil {
		return err
	}
	return target.WithHeaderDispatchWithBeforeRoundTrip(
		ctx, request, name, credential, beforeRoundTrip, consume,
	)
}

func (lease *cachedTargetLease) WithBasicDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	username string,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	target, err := lease.activeTarget()
	if err != nil {
		return err
	}
	return target.WithBasicDispatchWithBeforeRoundTrip(
		ctx, request, username, credential, beforeRoundTrip, consume,
	)
}

func (lease *cachedTargetLease) WithHeadersDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	credentials []upstream.HeaderCredential,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	target, err := lease.activeTarget()
	if err != nil {
		return err
	}
	return target.WithHeadersDispatchWithBeforeRoundTrip(
		ctx, request, credentials, beforeRoundTrip, consume,
	)
}

func protectedTargetKey(config configuration.Upstream) (targetCacheKey, error) {
	if !identifierPattern.MatchString(config.ID) || !validProtectedUpstreamType(config.Type) ||
		config.BaseURL == "" || !validTargetTimeouts(config.Timeouts) ||
		!validUpstreamAuthentication(config.Authentication) ||
		config.DestinationPolicy.AllowRedirects ||
		!config.DestinationPolicy.DNSPinning || len(config.DestinationPolicy.AllowedPorts) == 0 {
		return targetCacheKey{}, errTargetConfiguration
	}
	if _, err := configuredTraceContextPropagation(config.TraceContextPropagation); err != nil {
		return targetCacheKey{}, errTargetConfiguration
	}
	destinationPolicy := upstream.DestinationPolicy{
		AllowPrivate: config.DestinationPolicy.AllowPrivateNetworks,
		AllowedCIDRs: append([]netip.Prefix(nil), config.DestinationPolicy.AllowedCIDRs...),
	}
	if err := upstream.ValidateDestination(config.BaseURL, destinationPolicy); err != nil {
		return targetCacheKey{}, errTargetConfiguration
	}
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed == nil || (parsed.Scheme == "http" && !config.DangerousAllowInsecureHTTP) {
		return targetCacheKey{}, errTargetConfiguration
	}

	port := 0
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil {
			return targetCacheKey{}, errTargetConfiguration
		}
	} else if parsed.Scheme == "https" {
		port = 443
	} else if parsed.Scheme == "http" {
		port = 80
	}
	ports := append([]int(nil), config.DestinationPolicy.AllowedPorts...)
	sort.Ints(ports)
	for index, allowed := range ports {
		if allowed < 1 || allowed > 65535 || (index > 0 && ports[index-1] == allowed) {
			return targetCacheKey{}, errTargetConfiguration
		}
	}
	portIndex := sort.SearchInts(ports, port)
	if port == 0 || portIndex == len(ports) || ports[portIndex] != port {
		return targetCacheKey{}, errTargetConfiguration
	}
	var encodedPorts strings.Builder
	for _, allowed := range ports {
		encodedPorts.WriteString(strconv.Itoa(allowed))
		encodedPorts.WriteByte(',')
	}
	privateCIDRs := make([]string, len(destinationPolicy.AllowedCIDRs))
	for index, prefix := range destinationPolicy.AllowedCIDRs {
		privateCIDRs[index] = prefix.String()
	}
	sort.Strings(privateCIDRs)
	var encodedCIDRs strings.Builder
	for _, prefix := range privateCIDRs {
		encodedCIDRs.WriteString(prefix)
		encodedCIDRs.WriteByte(',')
	}

	return targetCacheKey{
		upstreamID: config.ID, upstreamType: config.Type, baseURL: config.BaseURL,
		insecureHTTP:            config.DangerousAllowInsecureHTTP,
		traceContextPropagation: config.TraceContextPropagation,
		allowRedirects:          config.DestinationPolicy.AllowRedirects,
		allowPrivate:            config.DestinationPolicy.AllowPrivateNetworks,
		dnsPinning:              config.DestinationPolicy.DNSPinning,
		allowedPorts:            encodedPorts.String(),
		allowedCIDRs:            encodedCIDRs.String(),
		connectTimeout:          config.Timeouts.Connect, responseHeaderTimeout: config.Timeouts.ResponseHeader,
		firstByteTimeout: config.Timeouts.FirstByte,
		idleTimeout:      config.Timeouts.Idle, totalTimeout: config.Timeouts.Total,
	}, nil
}

func validProtectedUpstreamType(value string) bool {
	switch value {
	case "openai_compatible", "anthropic", "generic":
		return true
	default:
		return false
	}
}
