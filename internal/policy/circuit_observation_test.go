package policy

import (
	"sync"
	"testing"
	"time"
)

func TestCircuitObservationsTransitionWithoutChangingPolicy(t *testing.T) {
	t.Parallel()

	observations, err := NewCircuitObservations(CircuitObservationConfig{
		MaximumEntries: 4, FailureThreshold: 2,
		OpenInterval: 10 * time.Second, StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := circuitObservationTestKey("primary")
	at := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	assertCircuitObservationState(t, observations, key, at, CircuitObservationStale)

	observations.RecordRetryableFailure(key, at)
	assertCircuitObservationState(t, observations, key, at, CircuitObservationClosed)
	observations.RecordRetryableFailure(key, at.Add(time.Second))
	assertCircuitObservationState(t, observations, key, at.Add(5*time.Second), CircuitObservationOpen)
	assertCircuitObservationState(t, observations, key, at.Add(11*time.Second), CircuitObservationHalfOpen)

	observations.RecordRetryableFailure(key, at.Add(11*time.Second))
	assertCircuitObservationState(t, observations, key, at.Add(12*time.Second), CircuitObservationOpen)
	observations.RecordSuccess(key, at.Add(13*time.Second))
	assertCircuitObservationState(t, observations, key, at.Add(13*time.Second), CircuitObservationClosed)

	// A delayed result cannot overwrite the newer success.
	observations.RecordRetryableFailure(key, at.Add(12*time.Second))
	assertCircuitObservationState(t, observations, key, at.Add(13*time.Second), CircuitObservationClosed)
	assertCircuitObservationState(t, observations, key, at.Add(73*time.Second), CircuitObservationStale)

	// Expired failure history must not make one fresh failure reopen the
	// observation. The new outcome begins a new consecutive-failure window.
	staleKey := circuitObservationTestKey("stale-reset")
	observations.RecordRetryableFailure(staleKey, at)
	observations.RecordRetryableFailure(staleKey, at.Add(time.Second))
	assertCircuitObservationState(t, observations, staleKey, at.Add(time.Second), CircuitObservationOpen)
	assertCircuitObservationState(t, observations, staleKey, at.Add(61*time.Second), CircuitObservationStale)
	observations.RecordRetryableFailure(staleKey, at.Add(61*time.Second))
	assertCircuitObservationState(t, observations, staleKey, at.Add(61*time.Second), CircuitObservationClosed)
	observations.RecordRetryableFailure(staleKey, at.Add(62*time.Second))
	assertCircuitObservationState(t, observations, staleKey, at.Add(62*time.Second), CircuitObservationOpen)
}

func TestCircuitObservationsAreBoundedAndRejectUnboundedKeys(t *testing.T) {
	t.Parallel()

	observations, err := NewCircuitObservations(CircuitObservationConfig{
		MaximumEntries: 2, FailureThreshold: 2,
		OpenInterval: time.Second, StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	alpha := circuitObservationTestKey("alpha")
	beta := circuitObservationTestKey("beta")
	gamma := circuitObservationTestKey("gamma")
	observations.RecordSuccess(beta, at)
	observations.RecordSuccess(alpha, at)
	observations.RecordSuccess(gamma, at)

	// Equal observation timestamps evict the lexically first key, making the
	// bounded-cache behavior deterministic despite randomized map iteration.
	assertCircuitObservationState(t, observations, alpha, at, CircuitObservationStale)
	assertCircuitObservationState(t, observations, beta, at, CircuitObservationClosed)
	assertCircuitObservationState(t, observations, gamma, at, CircuitObservationClosed)
	if len(observations.entries) != 2 {
		t.Fatalf("entry count = %d", len(observations.entries))
	}

	invalid := circuitObservationTestKey(" invalid ")
	observations.RecordRetryableFailure(invalid, at)
	assertCircuitObservationState(t, observations, invalid, at, CircuitObservationStale)
	if len(observations.entries) != 2 {
		t.Fatalf("invalid key changed entry count = %d", len(observations.entries))
	}
}

func TestCircuitObservationsSerializeConcurrentOutcomes(t *testing.T) {
	t.Parallel()

	observations, err := NewCircuitObservations(CircuitObservationConfig{
		MaximumEntries: 2, FailureThreshold: 3,
		OpenInterval: time.Second, StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := circuitObservationTestKey("primary")
	at := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			observations.RecordRetryableFailure(key, at)
		}()
	}
	workers.Wait()
	assertCircuitObservationState(t, observations, key, at, CircuitObservationOpen)
}

func TestCircuitObservationConfigurationIsBounded(t *testing.T) {
	t.Parallel()

	for _, config := range []CircuitObservationConfig{
		{MaximumEntries: -1},
		{FailureThreshold: maximumCircuitObservationFailureThreshold + 1},
		{OpenInterval: maximumCircuitObservationOpenInterval + time.Second},
		{OpenInterval: time.Minute, StaleAfter: time.Minute},
		{StaleAfter: maximumCircuitObservationStaleAfter + time.Second},
	} {
		if _, err := NewCircuitObservations(config); err == nil {
			t.Fatalf("configuration accepted: %#v", config)
		}
	}
	if _, err := NewCircuitObservations(CircuitObservationConfig{}); err != nil {
		t.Fatalf("default configuration: %v", err)
	}
}

func circuitObservationTestKey(route string) CircuitObservationKey {
	return CircuitObservationKey{
		EnvironmentID: "env_00000000000000000000000000",
		RevisionID:    "rev_00000000000000000000000000",
		RouteID:       route,
		UpstreamID:    "provider",
		ModelID:       "model",
	}
}

func assertCircuitObservationState(
	t *testing.T,
	observations *CircuitObservations,
	key CircuitObservationKey,
	at time.Time,
	want string,
) {
	t.Helper()
	if got := string(observations.State(key, at)); got != want {
		t.Fatalf("state at %s = %q want %q", at, got, want)
	}
}
