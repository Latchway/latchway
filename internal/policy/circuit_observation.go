package policy

import (
	"strings"
	"sync"
	"time"
)

const (
	// CircuitObservationStale means that this process has no recent outcome for
	// the physical route. The state is deliberately observational: it never
	// changes route order or authorizes, suppresses, or delays a dispatch.
	CircuitObservationStale = "stale"
	// CircuitObservationClosed means recent outcomes have not crossed the
	// bounded consecutive-failure threshold.
	CircuitObservationClosed = "closed"
	// CircuitObservationOpen means recent retryable failures have crossed the
	// threshold and the observation cooldown has not elapsed.
	CircuitObservationOpen = "open"
	// CircuitObservationHalfOpen means the observation cooldown elapsed without
	// a newer outcome. It does not reserve a probe or gate concurrent attempts.
	CircuitObservationHalfOpen = "half_open"

	defaultCircuitObservationEntries          = 4_096
	defaultCircuitObservationFailureThreshold = 3
	defaultCircuitObservationOpenInterval     = 30 * time.Second
	defaultCircuitObservationStaleAfter       = 5 * time.Minute
	maximumCircuitObservationEntries          = 65_536
	maximumCircuitObservationFailureThreshold = 100
	maximumCircuitObservationOpenInterval     = time.Hour
	maximumCircuitObservationStaleAfter       = 24 * time.Hour
	maximumCircuitObservationKeyPartBytes     = 128
)

// CircuitObservationState is a closed, low-cardinality description of recent
// physical-route outcomes observed by one process.
type CircuitObservationState string

// CircuitObservationKey contains only server-owned routing dimensions. The
// configuration revision prevents outcomes from a retired route definition
// from affecting observations for its replacement.
type CircuitObservationKey struct {
	EnvironmentID string
	RevisionID    string
	RouteID       string
	UpstreamID    string
	ModelID       string
}

// CircuitObservationConfig bounds the in-process observation cache and state
// windows. Zero fields select server-owned defaults.
type CircuitObservationConfig struct {
	MaximumEntries   int
	FailureThreshold int
	OpenInterval     time.Duration
	StaleAfter       time.Duration
}

// CircuitObservations records recent attempt outcomes for telemetry. It is
// intentionally not consumed by Resolver or the data-plane admission path.
// Replicas therefore retain deterministic route plans without shared mutable
// circuit state.
type CircuitObservations struct {
	mu               sync.Mutex
	maximumEntries   int
	failureThreshold int
	openInterval     time.Duration
	staleAfter       time.Duration
	entries          map[CircuitObservationKey]circuitObservationEntry
}

type circuitObservationEntry struct {
	consecutiveFailures int
	openedAt            time.Time
	lastObservedAt      time.Time
}

// NewCircuitObservations constructs an empty bounded observation cache.
func NewCircuitObservations(config CircuitObservationConfig) (*CircuitObservations, error) {
	if config.MaximumEntries == 0 {
		config.MaximumEntries = defaultCircuitObservationEntries
	}
	if config.FailureThreshold == 0 {
		config.FailureThreshold = defaultCircuitObservationFailureThreshold
	}
	if config.OpenInterval == 0 {
		config.OpenInterval = defaultCircuitObservationOpenInterval
	}
	if config.StaleAfter == 0 {
		config.StaleAfter = defaultCircuitObservationStaleAfter
	}
	if config.MaximumEntries < 1 || config.MaximumEntries > maximumCircuitObservationEntries ||
		config.FailureThreshold < 1 || config.FailureThreshold > maximumCircuitObservationFailureThreshold ||
		config.OpenInterval <= 0 || config.OpenInterval > maximumCircuitObservationOpenInterval ||
		config.StaleAfter <= config.OpenInterval || config.StaleAfter > maximumCircuitObservationStaleAfter {
		return nil, ErrConfiguration
	}
	return &CircuitObservations{
		maximumEntries: config.MaximumEntries, failureThreshold: config.FailureThreshold,
		openInterval: config.OpenInterval, staleAfter: config.StaleAfter,
		entries: make(map[CircuitObservationKey]circuitObservationEntry, config.MaximumEntries),
	}, nil
}

// State returns the state that an attempt would observe at dispatch time.
func (observations *CircuitObservations) State(key CircuitObservationKey, at time.Time) CircuitObservationState {
	if observations == nil || !validCircuitObservationKey(key) || at.IsZero() {
		return CircuitObservationState(CircuitObservationStale)
	}
	at = at.UTC()
	observations.mu.Lock()
	defer observations.mu.Unlock()
	entry, ok := observations.entries[key]
	if !ok {
		return CircuitObservationState(CircuitObservationStale)
	}
	return observations.stateAt(entry, at)
}

// RecordSuccess closes the observation after a dispatched successful attempt.
func (observations *CircuitObservations) RecordSuccess(key CircuitObservationKey, at time.Time) {
	observations.record(key, at, false)
}

// RecordRetryableFailure records only a failure from the executor's closed
// retry/fallback condition vocabulary. Policy, quota, configuration, protocol,
// persistence, and client-cancellation failures must not call this method.
func (observations *CircuitObservations) RecordRetryableFailure(key CircuitObservationKey, at time.Time) {
	observations.record(key, at, true)
}

func (observations *CircuitObservations) record(key CircuitObservationKey, at time.Time, failure bool) {
	if observations == nil || !validCircuitObservationKey(key) || at.IsZero() {
		return
	}
	at = at.UTC()
	observations.mu.Lock()
	defer observations.mu.Unlock()
	entry, exists := observations.entries[key]
	if exists && at.Before(entry.lastObservedAt) {
		// A wall-clock regression or delayed observation must not rewrite a newer
		// state transition. Equal timestamps remain ordered by the mutex so tests
		// and coarse clocks can still record consecutive attempts.
		return
	}
	if exists && at.Sub(entry.lastObservedAt) >= observations.staleAfter {
		// Once history is stale, the next outcome starts a fresh observation
		// window. Retaining the old counter would let one new failure reopen a
		// circuit based on failures that State already declared expired.
		entry = circuitObservationEntry{}
	}
	if !exists {
		observations.makeRoom(at)
	}
	if failure {
		if entry.consecutiveFailures < observations.failureThreshold {
			entry.consecutiveFailures++
		}
		if entry.consecutiveFailures >= observations.failureThreshold {
			entry.openedAt = at
		}
	} else {
		entry.consecutiveFailures = 0
		entry.openedAt = time.Time{}
	}
	entry.lastObservedAt = at
	observations.entries[key] = entry
}

func (observations *CircuitObservations) stateAt(entry circuitObservationEntry, at time.Time) CircuitObservationState {
	if entry.lastObservedAt.IsZero() || at.Before(entry.lastObservedAt) ||
		at.Sub(entry.lastObservedAt) >= observations.staleAfter {
		return CircuitObservationState(CircuitObservationStale)
	}
	if entry.consecutiveFailures < observations.failureThreshold {
		return CircuitObservationState(CircuitObservationClosed)
	}
	if entry.openedAt.IsZero() || at.Before(entry.openedAt) {
		return CircuitObservationState(CircuitObservationStale)
	}
	if at.Sub(entry.openedAt) < observations.openInterval {
		return CircuitObservationState(CircuitObservationOpen)
	}
	return CircuitObservationState(CircuitObservationHalfOpen)
}

func (observations *CircuitObservations) makeRoom(at time.Time) {
	if len(observations.entries) < observations.maximumEntries {
		return
	}
	for key, entry := range observations.entries {
		if !at.Before(entry.lastObservedAt) && at.Sub(entry.lastObservedAt) >= observations.staleAfter {
			delete(observations.entries, key)
		}
	}
	if len(observations.entries) < observations.maximumEntries {
		return
	}
	var oldestKey CircuitObservationKey
	var oldestAt time.Time
	haveOldest := false
	for key, entry := range observations.entries {
		if !haveOldest || entry.lastObservedAt.Before(oldestAt) ||
			(entry.lastObservedAt.Equal(oldestAt) && circuitObservationKeyLess(key, oldestKey)) {
			oldestKey, oldestAt, haveOldest = key, entry.lastObservedAt, true
		}
	}
	if haveOldest {
		delete(observations.entries, oldestKey)
	}
}

func validCircuitObservationKey(key CircuitObservationKey) bool {
	for _, part := range [...]string{key.EnvironmentID, key.RevisionID, key.RouteID, key.UpstreamID, key.ModelID} {
		if strings.TrimSpace(part) != part || part == "" || len(part) > maximumCircuitObservationKeyPartBytes {
			return false
		}
	}
	return true
}

func circuitObservationKeyLess(left, right CircuitObservationKey) bool {
	leftParts := [...]string{left.EnvironmentID, left.RevisionID, left.RouteID, left.UpstreamID, left.ModelID}
	rightParts := [...]string{right.EnvironmentID, right.RevisionID, right.RouteID, right.UpstreamID, right.ModelID}
	for index := range leftParts {
		if leftParts[index] != rightParts[index] {
			return leftParts[index] < rightParts[index]
		}
	}
	return false
}
