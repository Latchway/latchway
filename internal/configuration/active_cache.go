package configuration

import (
	"context"
	"sync"
	"time"
)

const (
	activeSnapshotCacheCapacity              = 1024
	activeSnapshotFullReconciliationInterval = 30 * time.Second
)

type activeSnapshotCacheKey struct {
	organizationID string
	applicationID  string
	environmentID  string
}

func newActiveSnapshotCacheKey(scope TenantScope) activeSnapshotCacheKey {
	return activeSnapshotCacheKey{
		organizationID: scope.OrganizationID,
		applicationID:  scope.ApplicationID,
		environmentID:  scope.EnvironmentID,
	}
}

type activeSnapshotCacheEntry struct {
	snapshot ActiveSnapshot
	loadedAt time.Time
}

type activeSnapshotCache struct {
	mu      sync.RWMutex
	entries map[activeSnapshotCacheKey]activeSnapshotCacheEntry
}

func (cache *activeSnapshotCache) get(key activeSnapshotCacheKey) (activeSnapshotCacheEntry, bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	entry, ok := cache.entries[key]
	return entry, ok
}

func (cache *activeSnapshotCache) put(
	key activeSnapshotCacheKey,
	snapshot ActiveSnapshot,
	loadedAt time.Time,
) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entries == nil {
		cache.entries = make(map[activeSnapshotCacheKey]activeSnapshotCacheEntry)
	}
	if _, exists := cache.entries[key]; !exists && len(cache.entries) >= activeSnapshotCacheCapacity {
		var oldestKey activeSnapshotCacheKey
		var oldestTime time.Time
		for candidateKey, candidate := range cache.entries {
			if oldestTime.IsZero() || candidate.loadedAt.Before(oldestTime) {
				oldestKey = candidateKey
				oldestTime = candidate.loadedAt
			}
		}
		delete(cache.entries, oldestKey)
	}
	cache.entries[key] = activeSnapshotCacheEntry{snapshot: snapshot, loadedAt: loadedAt}
}

func activeSnapshotCacheEntryIsFresh(entry activeSnapshotCacheEntry, now time.Time) bool {
	age := now.Sub(entry.loadedAt)
	return age >= 0 && age < activeSnapshotFullReconciliationInterval
}

type requestActiveSnapshotCacheContextKey struct{}

type requestActiveSnapshotCacheKey struct {
	store *Store
	scope activeSnapshotCacheKey
}

type requestActiveSnapshotCache struct {
	mu      sync.Mutex
	entries map[requestActiveSnapshotCacheKey]ActiveSnapshot
}

// WithActiveSnapshotCache binds a request-local memo to ctx. Configuration
// readers in one request therefore observe one immutable revision even if an
// administrator activates a different revision while the request is running.
func WithActiveSnapshotCache(ctx context.Context) context.Context {
	if _, ok := ctx.Value(requestActiveSnapshotCacheContextKey{}).(*requestActiveSnapshotCache); ok {
		return ctx
	}
	return context.WithValue(ctx, requestActiveSnapshotCacheContextKey{}, &requestActiveSnapshotCache{
		entries: make(map[requestActiveSnapshotCacheKey]ActiveSnapshot),
	})
}

func beginRequestActiveSnapshot(
	ctx context.Context,
	store *Store,
	scope activeSnapshotCacheKey,
) (ActiveSnapshot, bool, func(ActiveSnapshot, bool)) {
	cache, ok := ctx.Value(requestActiveSnapshotCacheContextKey{}).(*requestActiveSnapshotCache)
	if !ok {
		return ActiveSnapshot{}, false, func(ActiveSnapshot, bool) {}
	}
	cache.mu.Lock()
	key := requestActiveSnapshotCacheKey{store: store, scope: scope}
	if snapshot, exists := cache.entries[key]; exists {
		cache.mu.Unlock()
		return snapshot, true, func(ActiveSnapshot, bool) {}
	}
	finished := false
	return ActiveSnapshot{}, false, func(snapshot ActiveSnapshot, retain bool) {
		if finished {
			return
		}
		finished = true
		if retain {
			cache.entries[key] = snapshot
		}
		cache.mu.Unlock()
	}
}
