package dataplane

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/upstream"
)

func TestTargetCacheConcurrentAcquireReusesSingleConstruction(t *testing.T) {
	cache, builder := newTargetCacheHarness(t, 4)
	config := cacheTestUpstream("primary")

	const workers = 64
	start := make(chan struct{})
	leases := make(chan TargetLease, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			lease, err := cache.Acquire(config)
			if err != nil {
				errorsFound <- err
				return
			}
			leases <- lease
		}()
	}
	close(start)
	wait.Wait()
	close(leases)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent Acquire() error = %v", err)
	}

	var first cachedDispatchTarget
	count := 0
	for lease := range leases {
		concrete, ok := lease.(*cachedTargetLease)
		if !ok {
			t.Fatalf("lease type = %T", lease)
		}
		if first == nil {
			first = concrete.target
		} else if concrete.target != first {
			t.Fatal("concurrent acquisitions returned different targets")
		}
		lease.Release()
		lease.Release()
		count++
	}
	if count != workers || builder.calls.Load() != 1 {
		t.Fatalf("leases/constructions = %d/%d", count, builder.calls.Load())
	}
	target := builder.onlyTarget(t, "primary")
	if target.closes.Load() != 0 {
		t.Fatal("cached target closed while still resident")
	}
	if err := cache.Close(); err != nil || target.closes.Load() != 1 {
		t.Fatalf("Close() error/closes = %v/%d", err, target.closes.Load())
	}
}

func TestProtectedTargetKeyCoversTransportFieldsAndExcludesCredentials(t *testing.T) {
	base := cacheTestUpstream("primary")
	base.DestinationPolicy.AllowedPorts = []int{8443, 443}
	key, err := protectedTargetKey(base)
	if err != nil {
		t.Fatalf("protectedTargetKey() error = %v", err)
	}
	if key.upstreamID != base.ID || key.upstreamType != base.Type || key.baseURL != base.BaseURL ||
		key.insecureHTTP != base.DangerousAllowInsecureHTTP ||
		key.allowRedirects != base.DestinationPolicy.AllowRedirects ||
		key.allowPrivate != base.DestinationPolicy.AllowPrivateNetworks ||
		key.dnsPinning != base.DestinationPolicy.DNSPinning || key.allowedPorts != "443,8443," ||
		key.connectTimeout != base.Timeouts.Connect || key.firstByteTimeout != base.Timeouts.FirstByte ||
		key.idleTimeout != base.Timeouts.Idle || key.totalTimeout != base.Timeouts.Total {
		t.Fatalf("cache key omitted a transport field: %#v", key)
	}

	reordered := cloneCacheTestUpstream(base)
	reordered.DestinationPolicy.AllowedPorts = []int{443, 8443}
	reorderedKey, err := protectedTargetKey(reordered)
	if err != nil || reorderedKey != key {
		t.Fatalf("port ordering changed canonical key: %#v err=%v", reorderedKey, err)
	}

	credentialChanged := cloneCacheTestUpstream(base)
	credentialChanged.Authentication = configuration.UpstreamAuthentication{
		Type: "header", SecretRef: "secret/provider_private", HeaderName: "X-Provider-Key",
	}
	credentialChanged.StaticHeaders = map[string]string{"X-Provider-Tenant": "private-tenant-value"}
	credentialKey, err := protectedTargetKey(credentialChanged)
	if err != nil || credentialKey != key {
		t.Fatalf("credentials or static headers entered target key: %#v err=%v", credentialKey, err)
	}

	variations := []struct {
		name string
		edit func(*configuration.Upstream)
	}{
		{name: "upstream ID", edit: func(value *configuration.Upstream) { value.ID = "secondary" }},
		{name: "base URL path", edit: func(value *configuration.Upstream) { value.BaseURL = "https://provider.example/v2" }},
		{name: "insecure flag", edit: func(value *configuration.Upstream) { value.DangerousAllowInsecureHTTP = true }},
		{name: "allowed ports", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowedPorts = []int{443, 9443} }},
		{name: "connect timeout", edit: func(value *configuration.Upstream) { value.Timeouts.Connect += time.Millisecond }},
		{name: "first byte timeout", edit: func(value *configuration.Upstream) { value.Timeouts.FirstByte += time.Millisecond }},
		{name: "idle timeout", edit: func(value *configuration.Upstream) { value.Timeouts.Idle += time.Millisecond }},
		{name: "total timeout", edit: func(value *configuration.Upstream) { value.Timeouts.Total += time.Millisecond }},
	}
	for _, test := range variations {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCacheTestUpstream(base)
			test.edit(&changed)
			changedKey, err := protectedTargetKey(changed)
			if err != nil {
				t.Fatalf("changed key error = %v", err)
			}
			if changedKey == key {
				t.Fatalf("%s did not change cache key", test.name)
			}
		})
	}
}

func TestTargetCacheRejectsInvalidConfigurationBeforeLookupOrConstruction(t *testing.T) {
	cache, builder := newTargetCacheHarness(t, 2)
	base := cacheTestUpstream("primary")
	validLease, err := cache.Acquire(base)
	if err != nil {
		t.Fatalf("valid Acquire() error = %v", err)
	}
	validLease.Release()

	tests := []struct {
		name string
		edit func(*configuration.Upstream)
	}{
		{name: "identifier", edit: func(value *configuration.Upstream) { value.ID = "INVALID" }},
		{name: "type", edit: func(value *configuration.Upstream) { value.Type = "unknown" }},
		{name: "URL query", edit: func(value *configuration.Upstream) { value.BaseURL += "?private=1" }},
		{name: "insecure HTTP", edit: func(value *configuration.Upstream) {
			value.BaseURL = "http://provider.example/v1"
			value.DestinationPolicy.AllowedPorts = []int{80}
		}},
		{name: "redirect", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowRedirects = true }},
		{name: "private network", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowPrivateNetworks = true }},
		{name: "DNS pinning", edit: func(value *configuration.Upstream) { value.DestinationPolicy.DNSPinning = false }},
		{name: "ports missing", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowedPorts = nil }},
		{name: "ports duplicate", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowedPorts = []int{443, 443} }},
		{name: "port invalid", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowedPorts = []int{0, 443} }},
		{name: "base port absent", edit: func(value *configuration.Upstream) { value.DestinationPolicy.AllowedPorts = []int{8443} }},
		{name: "timeout", edit: func(value *configuration.Upstream) { value.Timeouts.Connect = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := cloneCacheTestUpstream(base)
			test.edit(&invalid)
			if lease, err := cache.Acquire(invalid); err == nil || lease != nil {
				t.Fatalf("Acquire() = (%T, %v), want validation failure", lease, err)
			}
			if builder.calls.Load() != 1 {
				t.Fatalf("invalid config reached construction: calls=%d", builder.calls.Load())
			}
		})
	}
	if lease, err := (&TargetCache{}).Acquire(base); err == nil || lease != nil {
		t.Fatalf("zero cache Acquire() = (%T, %v)", lease, err)
	}
	if _, err := newTargetCache(0, builder.build); err == nil {
		t.Fatal("zero-capacity cache accepted")
	}
	if _, err := newTargetCache(1, nil); err == nil {
		t.Fatal("nil target builder accepted")
	}
}

func TestTargetCacheCapacityUsesLRUAndClosesIdleEvictions(t *testing.T) {
	cache, builder := newTargetCacheHarness(t, 2)
	a := cacheTestUpstream("target_a")
	b := cacheTestUpstream("target_b")
	c := cacheTestUpstream("target_c")

	acquireAndRelease(t, cache, a)
	acquireAndRelease(t, cache, b)
	acquireAndRelease(t, cache, a) // A is most recently used; B is the victim.
	targetA := builder.onlyTarget(t, a.ID)
	targetB := builder.onlyTarget(t, b.ID)
	acquireAndRelease(t, cache, c)
	targetC := builder.onlyTarget(t, c.ID)

	if builder.calls.Load() != 3 || targetA.closes.Load() != 0 ||
		targetB.closes.Load() != 1 || targetC.closes.Load() != 0 {
		t.Fatalf("LRU constructions/A/B/C closes = %d/%d/%d/%d",
			builder.calls.Load(), targetA.closes.Load(), targetB.closes.Load(), targetC.closes.Load())
	}
	cache.mu.Lock()
	entryCount := len(cache.entries)
	_, hasA := cache.entries[mustTargetKey(t, a)]
	_, hasB := cache.entries[mustTargetKey(t, b)]
	_, hasC := cache.entries[mustTargetKey(t, c)]
	cache.mu.Unlock()
	if entryCount != 2 || !hasA || hasB || !hasC {
		t.Fatalf("LRU entries count/A/B/C = %d/%t/%t/%t", entryCount, hasA, hasB, hasC)
	}
	_ = cache.Close()
	if targetA.closes.Load() != 1 || targetB.closes.Load() != 1 || targetC.closes.Load() != 1 {
		t.Fatalf("close after LRU A/B/C = %d/%d/%d",
			targetA.closes.Load(), targetB.closes.Load(), targetC.closes.Load())
	}
}

func TestTargetCacheActiveEvictionClosesOnlyAfterFinalRelease(t *testing.T) {
	cache, builder := newTargetCacheHarness(t, 1)
	a := cacheTestUpstream("target_a")
	b := cacheTestUpstream("target_b")

	leaseA, err := cache.Acquire(a)
	if err != nil {
		t.Fatalf("Acquire(A) error = %v", err)
	}
	targetA := builder.onlyTarget(t, a.ID)
	leaseB, err := cache.Acquire(b)
	if err != nil {
		t.Fatalf("Acquire(B) error = %v", err)
	}
	targetB := builder.onlyTarget(t, b.ID)
	if targetA.closes.Load() != 0 {
		t.Fatal("active evicted target closed before lease release")
	}
	leaseB.Release()
	if targetB.closes.Load() != 0 {
		t.Fatal("resident idle target closed on lease release")
	}
	leaseA.Release()
	leaseA.Release()
	if targetA.closes.Load() != 1 {
		t.Fatalf("active evicted target closes = %d", targetA.closes.Load())
	}
	if _, err := leaseA.Prepare(nil, providerChatPath, nil, nil); !errors.Is(err, errTargetConfiguration) {
		t.Fatalf("released lease Prepare() error = %v", err)
	}
	_ = cache.Close()
	if targetB.closes.Load() != 1 {
		t.Fatalf("resident target closes after cache Close = %d", targetB.closes.Load())
	}
}

func TestTargetCacheCloseIsIdempotentAndWaitsForActiveLease(t *testing.T) {
	cache, builder := newTargetCacheHarness(t, 2)
	a := cacheTestUpstream("target_a")
	b := cacheTestUpstream("target_b")
	leaseA, err := cache.Acquire(a)
	if err != nil {
		t.Fatalf("Acquire(A) error = %v", err)
	}
	leaseB, err := cache.Acquire(b)
	if err != nil {
		t.Fatalf("Acquire(B) error = %v", err)
	}
	leaseB.Release()
	targetA := builder.onlyTarget(t, a.ID)
	targetB := builder.onlyTarget(t, b.ID)

	if err := cache.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if targetA.closes.Load() != 0 || targetB.closes.Load() != 1 {
		t.Fatalf("close with active lease A/B = %d/%d", targetA.closes.Load(), targetB.closes.Load())
	}
	if lease, err := cache.Acquire(a); !errors.Is(err, errTargetCacheClosed) || lease != nil {
		t.Fatalf("Acquire after Close = (%T, %v)", lease, err)
	}
	leaseA.Release()
	leaseA.Release()
	if targetA.closes.Load() != 1 || targetB.closes.Load() != 1 {
		t.Fatalf("final active release A/B closes = %d/%d", targetA.closes.Load(), targetB.closes.Load())
	}
	var nilCache *TargetCache
	if err := nilCache.Close(); err != nil {
		t.Fatalf("nil cache Close() error = %v", err)
	}
}

func TestHandlerCloseOwnsOnlyImplicitTargetCache(t *testing.T) {
	fixture := newHandlerFixture(t)
	implicit, err := New(Config{
		AccessTokens: fixture.verifier, Sessions: fixture.sessions,
		Configuration: fixture.snapshots, Policies: fixture.policies,
		Quotas: fixture.quotas, Secrets: fixture.secret,
		Relayer: fixture.relayer, PublicOrigin: "https://gateway.example",
	})
	if err != nil {
		t.Fatalf("construct handler with implicit cache: %v", err)
	}
	if implicit.ownedTargets == nil {
		t.Fatal("handler did not own its implicit target cache")
	}
	if implicit.ownedTargets.capacity != defaultTargetCacheCapacity || defaultTargetCacheCapacity != 128 {
		t.Fatalf("implicit/default target cache capacity = %d/%d",
			implicit.ownedTargets.capacity, defaultTargetCacheCapacity)
	}
	if err := implicit.Close(); err != nil {
		t.Fatalf("handler Close() error = %v", err)
	}
	if err := implicit.Close(); err != nil {
		t.Fatalf("second handler Close() error = %v", err)
	}
	if lease, err := implicit.ownedTargets.Acquire(cacheTestUpstream("primary")); !errors.Is(err, errTargetCacheClosed) || lease != nil {
		t.Fatalf("implicit cache Acquire after handler Close = (%T, %v)", lease, err)
	}

	explicit := NewTargetCache()
	explicitHandler, err := New(Config{
		AccessTokens: fixture.verifier, Sessions: fixture.sessions,
		Configuration: fixture.snapshots, Policies: fixture.policies,
		Quotas: fixture.quotas, Secrets: fixture.secret, Targets: explicit,
		Relayer: fixture.relayer, PublicOrigin: "https://gateway.example",
	})
	if err != nil {
		t.Fatalf("construct handler with explicit cache: %v", err)
	}
	if explicitHandler.ownedTargets != nil {
		t.Fatal("handler claimed ownership of caller-provided cache")
	}
	if err := explicitHandler.Close(); err != nil {
		t.Fatalf("explicit handler Close() error = %v", err)
	}
	lease, err := explicit.Acquire(cacheTestUpstream("primary"))
	if err != nil {
		t.Fatalf("caller-owned cache was closed by Handler.Close: %v", err)
	}
	lease.Release()
	_ = explicit.Close()
}

type cacheTestBuilder struct {
	calls   atomic.Int32
	mu      sync.Mutex
	targets map[string][]*cacheTestTarget
}

func (builder *cacheTestBuilder) build(config configuration.Upstream) (cachedDispatchTarget, error) {
	builder.calls.Add(1)
	target := &cacheTestTarget{}
	builder.mu.Lock()
	builder.targets[config.ID] = append(builder.targets[config.ID], target)
	builder.mu.Unlock()
	return target, nil
}

func (builder *cacheTestBuilder) onlyTarget(t *testing.T, upstreamID string) *cacheTestTarget {
	t.Helper()
	builder.mu.Lock()
	defer builder.mu.Unlock()
	targets := builder.targets[upstreamID]
	if len(targets) != 1 {
		t.Fatalf("constructed targets for %q = %d, want 1", upstreamID, len(targets))
	}
	return targets[0]
}

type cacheTestTarget struct {
	closes atomic.Int32
}

func (*cacheTestTarget) Prepare(*http.Request, string, []string, map[string]string) (ProviderRequest, error) {
	return ProviderRequest{}, errors.New("cache test target does not prepare requests")
}

func (*cacheTestTarget) DispatchWithBeforeRoundTrip(context.Context, ProviderRequest, func() error) (*upstream.DispatchedResponse, error) {
	return nil, errors.New("cache test target does not dispatch")
}

func (*cacheTestTarget) WithBearerDispatchWithBeforeRoundTrip(context.Context, ProviderRequest, []byte, func() error, func(*upstream.DispatchedResponse) error) error {
	return errors.New("cache test target does not dispatch")
}

func (*cacheTestTarget) WithHeaderDispatchWithBeforeRoundTrip(context.Context, ProviderRequest, string, []byte, func() error, func(*upstream.DispatchedResponse) error) error {
	return errors.New("cache test target does not dispatch")
}

func (target *cacheTestTarget) CloseIdleConnections() { target.closes.Add(1) }

func newTargetCacheHarness(t *testing.T, capacity int) (*TargetCache, *cacheTestBuilder) {
	t.Helper()
	builder := &cacheTestBuilder{targets: make(map[string][]*cacheTestTarget)}
	cache, err := newTargetCache(capacity, builder.build)
	if err != nil {
		t.Fatalf("newTargetCache() error = %v", err)
	}
	return cache, builder
}

func cacheTestUpstream(upstreamID string) configuration.Upstream {
	return configuration.Upstream{
		ID: upstreamID, Type: "openai_compatible", BaseURL: "https://provider.example/v1",
		Authentication: configuration.UpstreamAuthentication{Type: "none"},
		Timeouts: configuration.UpstreamTimeouts{
			Connect: time.Second, FirstByte: 2 * time.Second,
			Idle: 3 * time.Second, Total: time.Minute,
		},
		DestinationPolicy: configuration.UpstreamDestinationPolicy{
			AllowedPorts: []int{443}, DNSPinning: true,
		},
	}
}

func cloneCacheTestUpstream(value configuration.Upstream) configuration.Upstream {
	value.DestinationPolicy.AllowedPorts = append([]int(nil), value.DestinationPolicy.AllowedPorts...)
	if value.StaticHeaders != nil {
		clonedHeaders := make(map[string]string, len(value.StaticHeaders))
		for name, headerValue := range value.StaticHeaders {
			clonedHeaders[name] = headerValue
		}
		value.StaticHeaders = clonedHeaders
	}
	return value
}

func acquireAndRelease(t *testing.T, cache *TargetCache, config configuration.Upstream) {
	t.Helper()
	lease, err := cache.Acquire(config)
	if err != nil {
		t.Fatalf("Acquire(%q) error = %v", config.ID, err)
	}
	lease.Release()
}

func mustTargetKey(t *testing.T, config configuration.Upstream) targetCacheKey {
	t.Helper()
	key, err := protectedTargetKey(config)
	if err != nil {
		t.Fatalf("protectedTargetKey(%q) error = %v", config.ID, err)
	}
	return key
}
