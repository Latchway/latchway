package configuration

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errActiveSnapshotRefreshIncomplete = errors.New("active configuration refresh did not complete")

const (
	activeSnapshotCacheCapacity = 1024
	// The budget is per Store. A role=all process retains one shared API/admin
	// Store and one worker Store, for a conservative 48 MiB process ceiling.
	activeSnapshotCacheMaximumEstimatedBytes = int64(24 << 20)
	activeSnapshotCacheEntryBaseBytes        = int64(16 << 10)
	activeSnapshotCacheExpansionFactor       = int64(8)
	activeSnapshotFullReconciliationInterval = 30 * time.Second
	activeSnapshotRefreshTimeout             = 5 * time.Second
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
	snapshot       ActiveSnapshot
	loadedAt       time.Time
	estimatedBytes int64
}

type activeSnapshotRefresh struct {
	done     chan struct{}
	snapshot ActiveSnapshot
	err      error
	waiters  int
}

type activeSnapshotCache struct {
	mu             sync.RWMutex
	entries        map[activeSnapshotCacheKey]activeSnapshotCacheEntry
	refreshes      map[activeSnapshotCacheKey]*activeSnapshotRefresh
	estimatedBytes int64
}

// ActiveSnapshotCacheStatus is a redaction-safe, process-local summary used
// by the canonical system doctor. It deliberately exposes neither tenant
// identifiers nor configuration documents.
type ActiveSnapshotCacheStatus struct {
	Available                     bool       `json:"available"`
	Entries                       int64      `json:"entries"`
	FreshEntries                  int64      `json:"fresh_entries"`
	StaleEntries                  int64      `json:"stale_entries"`
	RefreshesInFlight             int64      `json:"refreshes_in_flight"`
	EstimatedBytes                int64      `json:"estimated_bytes"`
	MaximumEntries                int64      `json:"maximum_entries"`
	MaximumEstimatedBytes         int64      `json:"maximum_estimated_bytes"`
	ReconciliationIntervalSeconds int64      `json:"reconciliation_interval_seconds"`
	NewestLoadedAt                *time.Time `json:"newest_loaded_at,omitempty"`
}

// ActiveSnapshotCacheStatus returns a bounded snapshot of this Store's lazy
// active-configuration cache. An empty cache is valid: entries are populated
// only when an environment first serves traffic or is activated locally.
func (store *Store) ActiveSnapshotCacheStatus(now time.Time) ActiveSnapshotCacheStatus {
	status := ActiveSnapshotCacheStatus{
		MaximumEntries:                activeSnapshotCacheCapacity,
		MaximumEstimatedBytes:         activeSnapshotCacheMaximumEstimatedBytes,
		ReconciliationIntervalSeconds: int64(activeSnapshotFullReconciliationInterval / time.Second),
	}
	if store == nil || now.IsZero() {
		return status
	}
	status.Available = true
	now = now.UTC()
	store.activeSnapshots.mu.RLock()
	defer store.activeSnapshots.mu.RUnlock()
	status.Entries = int64(len(store.activeSnapshots.entries))
	status.RefreshesInFlight = int64(len(store.activeSnapshots.refreshes))
	status.EstimatedBytes = store.activeSnapshots.estimatedBytes
	for _, entry := range store.activeSnapshots.entries {
		if activeSnapshotCacheEntryIsFresh(entry, now) {
			status.FreshEntries++
		} else {
			status.StaleEntries++
		}
		if status.NewestLoadedAt == nil || entry.loadedAt.After(*status.NewestLoadedAt) {
			loadedAt := entry.loadedAt.UTC()
			status.NewestLoadedAt = &loadedAt
		}
	}
	return status
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
	estimatedBytes := estimateActiveSnapshotBytes(snapshot)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entries == nil {
		cache.entries = make(map[activeSnapshotCacheKey]activeSnapshotCacheEntry)
	}
	if existing, exists := cache.entries[key]; exists {
		cache.estimatedBytes -= existing.estimatedBytes
		delete(cache.entries, key)
	}
	if estimatedBytes > activeSnapshotCacheMaximumEstimatedBytes {
		return
	}
	for len(cache.entries) >= activeSnapshotCacheCapacity ||
		cache.estimatedBytes > activeSnapshotCacheMaximumEstimatedBytes-estimatedBytes {
		var oldestKey activeSnapshotCacheKey
		var oldestTime time.Time
		for candidateKey, candidate := range cache.entries {
			if oldestTime.IsZero() || candidate.loadedAt.Before(oldestTime) {
				oldestKey = candidateKey
				oldestTime = candidate.loadedAt
			}
		}
		cache.estimatedBytes -= cache.entries[oldestKey].estimatedBytes
		delete(cache.entries, oldestKey)
	}
	cache.entries[key] = activeSnapshotCacheEntry{
		snapshot: snapshot, loadedAt: loadedAt, estimatedBytes: estimatedBytes,
	}
	cache.estimatedBytes += estimatedBytes
}

func estimateActiveSnapshotBytes(snapshot ActiveSnapshot) int64 {
	rawBytes := int64(len(snapshot.document)) + int64(len(snapshot.compiled))
	maximumRawBytes := (activeSnapshotCacheMaximumEstimatedBytes - activeSnapshotCacheEntryBaseBytes) /
		activeSnapshotCacheExpansionFactor
	if rawBytes > maximumRawBytes {
		return activeSnapshotCacheMaximumEstimatedBytes + 1
	}
	return activeSnapshotCacheEntryBaseBytes + rawBytes*activeSnapshotCacheExpansionFactor
}

func (cache *activeSnapshotCache) refresh(
	ctx context.Context,
	key activeSnapshotCacheKey,
	load func(context.Context) (ActiveSnapshot, error),
) (ActiveSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ActiveSnapshot{}, err
	}
	cache.mu.Lock()
	if cache.refreshes == nil {
		cache.refreshes = make(map[activeSnapshotCacheKey]*activeSnapshotRefresh)
	}
	if existing, ok := cache.refreshes[key]; ok {
		existing.waiters++
		cache.mu.Unlock()
		return waitForActiveSnapshotRefresh(ctx, existing)
	}
	refresh := &activeSnapshotRefresh{
		done: make(chan struct{}), err: errActiveSnapshotRefreshIncomplete,
	}
	cache.refreshes[key] = refresh
	cache.mu.Unlock()

	refreshCtx, cancelRefresh := context.WithTimeout(context.WithoutCancel(ctx), activeSnapshotRefreshTimeout)
	go func() {
		completed := false
		defer func() {
			_ = recover()
			cancelRefresh()
			if !completed {
				refresh.snapshot = ActiveSnapshot{}
				refresh.err = errActiveSnapshotRefreshIncomplete
			}
			cache.mu.Lock()
			if cache.refreshes[key] == refresh {
				delete(cache.refreshes, key)
			}
			close(refresh.done)
			cache.mu.Unlock()
		}()
		refresh.snapshot, refresh.err = load(refreshCtx)
		completed = true
	}()
	return waitForActiveSnapshotRefresh(ctx, refresh)
}

func waitForActiveSnapshotRefresh(
	ctx context.Context,
	refresh *activeSnapshotRefresh,
) (ActiveSnapshot, error) {
	select {
	case <-ctx.Done():
		return ActiveSnapshot{}, ctx.Err()
	case <-refresh.done:
		return refresh.snapshot, refresh.err
	}
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
