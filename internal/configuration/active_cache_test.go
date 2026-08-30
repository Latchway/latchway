package configuration

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestActiveSnapshotCacheIsBounded(t *testing.T) {
	t.Parallel()
	var cache activeSnapshotCache
	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	for index := 0; index <= activeSnapshotCacheCapacity; index++ {
		key := activeSnapshotCacheKey{environmentID: fmt.Sprintf("environment-%04d", index)}
		cache.put(key, ActiveSnapshot{RevisionID: fmt.Sprintf("revision-%04d", index)}, base.Add(time.Duration(index)*time.Second))
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if len(cache.entries) != activeSnapshotCacheCapacity {
		t.Fatalf("cache entries = %d, want %d", len(cache.entries), activeSnapshotCacheCapacity)
	}
	if _, ok := cache.entries[activeSnapshotCacheKey{environmentID: "environment-0000"}]; ok {
		t.Fatal("cache retained the oldest entry after reaching its bound")
	}
	if _, ok := cache.entries[activeSnapshotCacheKey{environmentID: fmt.Sprintf("environment-%04d", activeSnapshotCacheCapacity)}]; !ok {
		t.Fatal("cache evicted the newly inserted entry")
	}
}

func TestActiveSnapshotCacheIsByteBounded(t *testing.T) {
	t.Parallel()
	var cache activeSnapshotCache
	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	rawBytesPerEntry := int((activeSnapshotCacheMaximumEstimatedBytes/2 - activeSnapshotCacheEntryBaseBytes) /
		activeSnapshotCacheExpansionFactor)
	for index := 0; index < 3; index++ {
		cache.put(
			activeSnapshotCacheKey{environmentID: fmt.Sprintf("large-%d", index)},
			ActiveSnapshot{
				RevisionID: fmt.Sprintf("revision-%d", index),
				document:   make([]byte, rawBytesPerEntry),
			},
			base.Add(time.Duration(index)*time.Second),
		)
	}

	cache.mu.RLock()
	if cache.estimatedBytes > activeSnapshotCacheMaximumEstimatedBytes {
		cache.mu.RUnlock()
		t.Fatalf("estimated cache bytes = %d, maximum %d", cache.estimatedBytes, activeSnapshotCacheMaximumEstimatedBytes)
	}
	if _, ok := cache.entries[activeSnapshotCacheKey{environmentID: "large-0"}]; ok {
		cache.mu.RUnlock()
		t.Fatal("byte budget retained the oldest large entry")
	}
	if _, ok := cache.entries[activeSnapshotCacheKey{environmentID: "large-2"}]; !ok {
		cache.mu.RUnlock()
		t.Fatal("byte budget evicted the newest large entry")
	}
	cache.mu.RUnlock()

	maximumRawBytes := int((activeSnapshotCacheMaximumEstimatedBytes-activeSnapshotCacheEntryBaseBytes)/
		activeSnapshotCacheExpansionFactor) + 1
	oversizedKey := activeSnapshotCacheKey{environmentID: "oversized"}
	cache.put(oversizedKey, ActiveSnapshot{RevisionID: "oversized", document: make([]byte, maximumRawBytes)}, base)
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if _, ok := cache.entries[oversizedKey]; ok {
		t.Fatal("cache retained a snapshot larger than the complete byte budget")
	}
	if cache.estimatedBytes > activeSnapshotCacheMaximumEstimatedBytes {
		t.Fatalf("estimated cache bytes after rejection = %d, maximum %d", cache.estimatedBytes, activeSnapshotCacheMaximumEstimatedBytes)
	}
}

func TestActiveSnapshotCacheCoalescesRefreshByScope(t *testing.T) {
	t.Parallel()
	var cache activeSnapshotCache
	key := activeSnapshotCacheKey{environmentID: "environment"}
	want := ActiveSnapshot{RevisionID: "revision"}
	loaderStarted := make(chan struct{})
	releaseLoader := make(chan struct{})
	leaderError := make(chan error, 1)
	var loaderCalls atomic.Int32
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	go func() {
		_, err := cache.refresh(leaderContext, key, func(refreshCtx context.Context) (ActiveSnapshot, error) {
			loaderCalls.Add(1)
			deadline, hasDeadline := refreshCtx.Deadline()
			if !hasDeadline || time.Until(deadline) <= 0 || time.Until(deadline) > activeSnapshotRefreshTimeout {
				return ActiveSnapshot{}, errors.New("shared refresh context is not independently bounded")
			}
			close(loaderStarted)
			<-releaseLoader
			if err := refreshCtx.Err(); err != nil {
				return ActiveSnapshot{}, fmt.Errorf("shared refresh inherited leader cancellation: %w", err)
			}
			return want, nil
		})
		leaderError <- err
	}()
	<-loaderStarted
	cancelLeader()
	if err := <-leaderError; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled leader error = %v, want context cancellation", err)
	}

	waiterResult := make(chan ActiveSnapshot, 1)
	waiterError := make(chan error, 1)
	go func() {
		snapshot, err := cache.refresh(context.Background(), key, func(context.Context) (ActiveSnapshot, error) {
			loaderCalls.Add(1)
			return ActiveSnapshot{RevisionID: "unexpected-second-load"}, nil
		})
		waiterResult <- snapshot
		waiterError <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cache.mu.RLock()
		refresh := cache.refreshes[key]
		waiters := 0
		if refresh != nil {
			waiters = refresh.waiters
		}
		cache.mu.RUnlock()
		if waiters >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh waiter did not join the in-flight load")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseLoader)

	if err := <-waiterError; err != nil {
		t.Fatalf("waiter refresh error = %v", err)
	}
	if got := <-waiterResult; got.PolicyRevision() != want.PolicyRevision() {
		t.Fatalf("waiter revision = %q, want %q", got.PolicyRevision(), want.PolicyRevision())
	}
	if calls := loaderCalls.Load(); calls != 1 {
		t.Fatalf("refresh loader calls = %d, want 1", calls)
	}
}

func TestActiveSnapshotCacheContainsLoaderPanic(t *testing.T) {
	t.Parallel()
	var cache activeSnapshotCache
	key := activeSnapshotCacheKey{environmentID: "environment"}

	if _, err := cache.refresh(context.Background(), key, func(context.Context) (ActiveSnapshot, error) {
		panic("loader panic")
	}); !errors.Is(err, errActiveSnapshotRefreshIncomplete) {
		t.Fatalf("panicking refresh error = %v, want incomplete refresh", err)
	}
	want := ActiveSnapshot{RevisionID: "recovered"}
	got, err := cache.refresh(context.Background(), key, func(context.Context) (ActiveSnapshot, error) {
		return want, nil
	})
	if err != nil {
		t.Fatalf("refresh after panic error = %v", err)
	}
	if got.PolicyRevision() != want.PolicyRevision() {
		t.Fatalf("revision after panic = %q, want %q", got.PolicyRevision(), want.PolicyRevision())
	}
}

func TestActiveSnapshotCacheFreshnessIsClockSafe(t *testing.T) {
	t.Parallel()
	loadedAt := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	entry := activeSnapshotCacheEntry{loadedAt: loadedAt}
	for _, test := range []struct {
		name  string
		now   time.Time
		fresh bool
	}{
		{name: "same instant", now: loadedAt, fresh: true},
		{name: "inside interval", now: loadedAt.Add(activeSnapshotFullReconciliationInterval - time.Nanosecond), fresh: true},
		{name: "at interval", now: loadedAt.Add(activeSnapshotFullReconciliationInterval), fresh: false},
		{name: "clock moved backwards", now: loadedAt.Add(-time.Nanosecond), fresh: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := activeSnapshotCacheEntryIsFresh(entry, test.now); got != test.fresh {
				t.Fatalf("fresh = %t, want %t", got, test.fresh)
			}
		})
	}
}

func TestRequestActiveSnapshotCacheIsBoundToStoreAndScope(t *testing.T) {
	t.Parallel()
	ctx := WithActiveSnapshotCache(context.Background())
	firstStore := &Store{}
	secondStore := &Store{}
	firstScope := activeSnapshotCacheKey{organizationID: "org", applicationID: "app", environmentID: "one"}
	secondScope := activeSnapshotCacheKey{organizationID: "org", applicationID: "app", environmentID: "two"}
	want := ActiveSnapshot{RevisionID: "revision-one", EnvironmentID: "one"}
	_, hit, finish := beginRequestActiveSnapshot(ctx, firstStore, firstScope)
	if hit {
		t.Fatal("empty request cache reported a hit")
	}
	finish(want, true)

	if got, ok, _ := beginRequestActiveSnapshot(ctx, firstStore, firstScope); !ok || got.PolicyRevision() != want.PolicyRevision() {
		t.Fatalf("memoized snapshot = %#v, present=%t", got, ok)
	}
	if _, ok, finish := beginRequestActiveSnapshot(ctx, secondStore, firstScope); ok {
		t.Fatal("request cache crossed configuration store boundaries")
	} else {
		finish(ActiveSnapshot{}, false)
	}
	if _, ok, finish := beginRequestActiveSnapshot(ctx, firstStore, secondScope); ok {
		t.Fatal("request cache crossed tenant-scope boundaries")
	} else {
		finish(ActiveSnapshot{}, false)
	}
	if nested := WithActiveSnapshotCache(ctx); nested != ctx {
		t.Fatal("nested cache wrapper replaced the existing request memo")
	}
}

func TestRequestActiveSnapshotCacheSerializesConcurrentFirstLoad(t *testing.T) {
	t.Parallel()
	ctx := WithActiveSnapshotCache(context.Background())
	store := &Store{}
	scope := activeSnapshotCacheKey{organizationID: "org", applicationID: "app", environmentID: "one"}
	want := ActiveSnapshot{RevisionID: "revision-one", EnvironmentID: "one"}
	_, hit, finishFirst := beginRequestActiveSnapshot(ctx, store, scope)
	if hit {
		t.Fatal("empty request cache reported a hit")
	}

	type result struct {
		snapshot ActiveSnapshot
		hit      bool
	}
	started := make(chan struct{})
	resultChannel := make(chan result, 1)
	go func() {
		close(started)
		snapshot, cacheHit, finish := beginRequestActiveSnapshot(ctx, store, scope)
		finish(ActiveSnapshot{}, false)
		resultChannel <- result{snapshot: snapshot, hit: cacheHit}
	}()
	<-started
	finishFirst(want, true)
	got := <-resultChannel
	if !got.hit || got.snapshot.PolicyRevision() != want.PolicyRevision() {
		t.Fatalf("concurrent request snapshot = %#v, hit=%t", got.snapshot, got.hit)
	}
}
