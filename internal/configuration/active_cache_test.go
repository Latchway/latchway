package configuration

import (
	"context"
	"fmt"
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
