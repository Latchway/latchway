package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestStorePostgreSQLActiveSnapshotCacheReconcilesAcrossReplicas(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedConfigurationPool(t, ctx, databaseURL)
	principal, scope := seedConfigurationTenant(t, ctx, pool)
	firstStore, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	instant := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	firstStore.now = func() time.Time { return instant }
	secondStore.now = func() time.Time { return instant }

	activateNext := func(store *Store, baseRevisionID string) Revision {
		t.Helper()
		input := CreateInput{EnvironmentID: scope.EnvironmentID, Document: validConfigurationDocument(t)}
		if baseRevisionID != "" {
			input.Document = nil
			input.BaseRevisionID = baseRevisionID
		}
		revision, createErr := store.CreateRevision(ctx, principal, input)
		if createErr != nil {
			t.Fatalf("CreateRevision() error = %v", createErr)
		}
		report, validateErr := store.ValidateRevision(ctx, principal, revision.ID)
		if validateErr != nil || !report.Valid {
			t.Fatalf("ValidateRevision() report=%+v error=%v", report, validateErr)
		}
		revision, activateErr := store.ActivateRevision(ctx, principal, revision.ID, revision.ETag)
		if activateErr != nil {
			t.Fatalf("ActivateRevision() error = %v", activateErr)
		}
		return revision
	}

	initial := activateNext(firstStore, "")
	initialSnapshot, err := firstStore.ActiveSnapshot(ctx, scope)
	if err != nil {
		t.Fatalf("ActiveSnapshot(initial) error = %v", err)
	}
	cacheKey := newActiveSnapshotCacheKey(scope)
	entry, ok := firstStore.activeSnapshots.get(cacheKey)
	if !ok {
		t.Fatal("activation did not warm the process cache")
	}
	marker := json.RawMessage(`{"cache":"marker"}`)
	entry.snapshot.compiled = append(json.RawMessage(nil), marker...)
	firstStore.activeSnapshots.put(cacheKey, entry.snapshot, entry.loadedAt)

	cachedSnapshot, err := firstStore.ActiveSnapshot(ctx, scope)
	if err != nil {
		t.Fatalf("ActiveSnapshot(cache hit) error = %v", err)
	}
	if !bytes.Equal(cachedSnapshot.CompiledJSON(), marker) {
		t.Fatal("fresh cache hit unnecessarily reloaded the immutable snapshot")
	}

	instant = instant.Add(activeSnapshotFullReconciliationInterval)
	reconciledSnapshot, err := firstStore.ActiveSnapshot(ctx, scope)
	if err != nil {
		t.Fatalf("ActiveSnapshot(reconciliation) error = %v", err)
	}
	if !bytes.Equal(reconciledSnapshot.CompiledJSON(), initialSnapshot.CompiledJSON()) {
		t.Fatal("periodic reconciliation did not restore the durable compiled snapshot")
	}

	second := activateNext(secondStore, initial.ID)
	observedSecond, err := firstStore.ActiveSnapshot(ctx, scope)
	if err != nil {
		t.Fatalf("ActiveSnapshot(second replica activation) error = %v", err)
	}
	if observedSecond.PolicyRevision() != second.ID {
		t.Fatalf("revision after second-replica activation = %q, want %q", observedSecond.PolicyRevision(), second.ID)
	}

	requestContext := WithActiveSnapshotCache(ctx)
	requestSnapshot, err := firstStore.ActiveSnapshot(requestContext, scope)
	if err != nil {
		t.Fatal(err)
	}
	third := activateNext(secondStore, second.ID)
	stableRequestSnapshot, err := firstStore.ActiveSnapshot(requestContext, scope)
	if err != nil {
		t.Fatal(err)
	}
	if stableRequestSnapshot.PolicyRevision() != requestSnapshot.PolicyRevision() {
		t.Fatalf("one request observed revisions %q and %q", requestSnapshot.PolicyRevision(), stableRequestSnapshot.PolicyRevision())
	}
	newRequestSnapshot, err := firstStore.ActiveSnapshot(WithActiveSnapshotCache(ctx), scope)
	if err != nil {
		t.Fatal(err)
	}
	if newRequestSnapshot.PolicyRevision() != third.ID {
		t.Fatalf("new request revision = %q, want %q", newRequestSnapshot.PolicyRevision(), third.ID)
	}
}
