// Package mockupstream provides a deterministic, bounded AI upstream used by
// Latchway conformance and integration tests.
package mockupstream

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

const (
	// ScenarioHeader is understood only by this test handler. Production proxy
	// code must never forward it to arbitrary upstreams.
	ScenarioHeader = "X-Latchway-Mock-Upstream-Scenario"
	// CostHeader exposes the deterministic fixture cost without relying on a
	// provider-specific extension to a successful response body.
	CostHeader = "X-Latchway-Mock-Cost-Nano-USD"

	defaultMaxRequestBodyBytes = int64(1 << 20)
	maximumRequestBodyBytes    = int64(4 << 20)
	defaultMaxOutputBytes      = 512 << 10
	maximumOutputBytes         = 2 << 20
	minimumOutputBytes         = 4 << 10
	defaultOversizedEventBytes = 256 << 10
	minimumOversizedEventBytes = 1 << 10
	outputEnvelopeAllowance    = 512
	maximumFirstByteDelay      = 2 * time.Second
	maximumCancellationWait    = 5 * time.Second
)

// Scenario selects deterministic response behavior.
type Scenario string

const (
	ScenarioDefault             Scenario = "default"
	ScenarioStream              Scenario = "stream"
	ScenarioDelayedFirstByte    Scenario = "delayed-first-byte"
	ScenarioMidStreamDisconnect Scenario = "mid-stream-disconnect"
	ScenarioHTTP408             Scenario = "http-408"
	ScenarioHTTP429             Scenario = "http-429"
	ScenarioHTTP500             Scenario = "http-500"
	ScenarioMalformedJSON       Scenario = "malformed-json"
	ScenarioMalformedSSE        Scenario = "malformed-sse"
	ScenarioMissingUsage        Scenario = "missing-usage"
	ScenarioOversizedEvent      Scenario = "oversized-event"
	ScenarioToolCall            Scenario = "tool-call"
	ScenarioClientCancellation  Scenario = "client-cancellation"
)

var supportedScenarios = []Scenario{
	ScenarioDefault,
	ScenarioStream,
	ScenarioDelayedFirstByte,
	ScenarioMidStreamDisconnect,
	ScenarioHTTP408,
	ScenarioHTTP429,
	ScenarioHTTP500,
	ScenarioMalformedJSON,
	ScenarioMalformedSSE,
	ScenarioMissingUsage,
	ScenarioOversizedEvent,
	ScenarioToolCall,
	ScenarioClientCancellation,
}

// Usage is the deterministic token accounting returned by successful fixtures.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// TotalTokens returns input plus output tokens.
func (u Usage) TotalTokens() int {
	return u.InputTokens + u.OutputTokens
}

// Config controls one mock-upstream handler. Zero-valued fields receive safe,
// bounded defaults. Scenario-header overrides are disabled unless explicitly
// enabled by the conformance harness.
type Config struct {
	Scenario            Scenario
	AllowScenarioHeader bool
	FirstByteDelay      time.Duration
	CancellationWait    time.Duration
	MaxRequestBodyBytes int64
	MaxOutputBytes      int
	OversizedEventBytes int
	FixedUsage          Usage
	FixedCostNanoUSD    int64
}

type normalizedConfig struct {
	scenario            Scenario
	allowScenarioHeader bool
	firstByteDelay      time.Duration
	cancellationWait    time.Duration
	maxRequestBodyBytes int64
	maxOutputBytes      int
	oversizedEventBytes int
	fixedUsage          Usage
	fixedCostNanoUSD    int64
}

// Observation captures bounded request/response facts without retaining request
// bodies, credentials, or generated content. StatusCode is zero when a client
// canceled before any response was started.
type Observation struct {
	Sequence          uint64
	Method            string
	Path              string
	Scenario          Scenario
	RequestBytes      int
	StatusCode        int
	ResponseBytes     int64
	ResponseStarted   bool
	Canceled          bool
	ConnectionAborted bool
}

// Handler implements the deterministic upstream and records cancellation-safe
// request observations.
type Handler struct {
	cfg normalizedConfig

	mu           sync.Mutex
	nextSequence uint64
	active       int
	observations []Observation
}

// DefaultConfig returns the fixture values used across conformance suites.
func DefaultConfig() Config {
	return Config{
		Scenario:            ScenarioDefault,
		FirstByteDelay:      25 * time.Millisecond,
		CancellationWait:    time.Second,
		MaxRequestBodyBytes: defaultMaxRequestBodyBytes,
		MaxOutputBytes:      defaultMaxOutputBytes,
		OversizedEventBytes: defaultOversizedEventBytes,
		FixedUsage:          Usage{InputTokens: 11, OutputTokens: 7},
		FixedCostNanoUSD:    123_456,
	}
}

// New constructs a validated mock upstream.
func New(cfg Config) (*Handler, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{cfg: normalized}, nil
}

// SupportedScenarios returns a sorted copy of every accepted scenario name.
func SupportedScenarios() []Scenario {
	result := slices.Clone(supportedScenarios)
	slices.Sort(result)
	return result
}

// Observations returns a snapshot ordered by request completion.
func (h *Handler) Observations() []Observation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.observations)
}

// ActiveRequests returns the number of requests currently inside the handler.
func (h *Handler) ActiveRequests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active
}

// ResetObservations discards completed observations. Active requests are not
// affected and will be recorded when they finish.
func (h *Handler) ResetObservations() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observations = nil
}

func normalizeConfig(cfg Config) (normalizedConfig, error) {
	defaults := DefaultConfig()
	if cfg.Scenario == "" {
		cfg.Scenario = defaults.Scenario
	}
	if !isSupportedScenario(cfg.Scenario) {
		return normalizedConfig{}, fmt.Errorf("unsupported mock upstream scenario %q", cfg.Scenario)
	}
	if cfg.FirstByteDelay == 0 {
		cfg.FirstByteDelay = defaults.FirstByteDelay
	}
	if cfg.FirstByteDelay < 0 || cfg.FirstByteDelay > maximumFirstByteDelay {
		return normalizedConfig{}, fmt.Errorf("first byte delay must be between zero and %s", maximumFirstByteDelay)
	}
	if cfg.CancellationWait == 0 {
		cfg.CancellationWait = defaults.CancellationWait
	}
	if cfg.CancellationWait < 0 || cfg.CancellationWait > maximumCancellationWait {
		return normalizedConfig{}, fmt.Errorf("cancellation wait must be between zero and %s", maximumCancellationWait)
	}
	if cfg.MaxRequestBodyBytes == 0 {
		cfg.MaxRequestBodyBytes = defaults.MaxRequestBodyBytes
	}
	if cfg.MaxRequestBodyBytes < 1 || cfg.MaxRequestBodyBytes > maximumRequestBodyBytes {
		return normalizedConfig{}, fmt.Errorf("request body limit must be between 1 and %d bytes", maximumRequestBodyBytes)
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = defaults.MaxOutputBytes
	}
	if cfg.MaxOutputBytes < minimumOutputBytes || cfg.MaxOutputBytes > maximumOutputBytes {
		return normalizedConfig{}, fmt.Errorf("output limit must be between %d and %d bytes", minimumOutputBytes, maximumOutputBytes)
	}
	if cfg.OversizedEventBytes == 0 {
		cfg.OversizedEventBytes = min(defaults.OversizedEventBytes, cfg.MaxOutputBytes-outputEnvelopeAllowance)
	}
	if cfg.OversizedEventBytes < minimumOversizedEventBytes || cfg.OversizedEventBytes+outputEnvelopeAllowance > cfg.MaxOutputBytes {
		return normalizedConfig{}, fmt.Errorf("oversized event must fit inside the configured output limit with %d bytes of envelope allowance", outputEnvelopeAllowance)
	}
	if cfg.FixedUsage == (Usage{}) {
		cfg.FixedUsage = defaults.FixedUsage
	}
	if cfg.FixedUsage.InputTokens < 0 || cfg.FixedUsage.OutputTokens < 0 {
		return normalizedConfig{}, fmt.Errorf("fixed token usage cannot be negative")
	}
	if cfg.FixedCostNanoUSD == 0 {
		cfg.FixedCostNanoUSD = defaults.FixedCostNanoUSD
	}
	if cfg.FixedCostNanoUSD < 0 {
		return normalizedConfig{}, fmt.Errorf("fixed cost cannot be negative")
	}

	return normalizedConfig{
		scenario:            cfg.Scenario,
		allowScenarioHeader: cfg.AllowScenarioHeader,
		firstByteDelay:      cfg.FirstByteDelay,
		cancellationWait:    cfg.CancellationWait,
		maxRequestBodyBytes: cfg.MaxRequestBodyBytes,
		maxOutputBytes:      cfg.MaxOutputBytes,
		oversizedEventBytes: cfg.OversizedEventBytes,
		fixedUsage:          cfg.FixedUsage,
		fixedCostNanoUSD:    cfg.FixedCostNanoUSD,
	}, nil
}

func isSupportedScenario(scenario Scenario) bool {
	return slices.Contains(supportedScenarios, scenario)
}

func (h *Handler) beginObservation(method, requestPath string) Observation {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextSequence++
	h.active++
	return Observation{
		Sequence: h.nextSequence,
		Method:   method,
		Path:     requestPath,
		Scenario: h.cfg.scenario,
	}
}

func (h *Handler) finishObservation(observation Observation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active--
	h.observations = append(h.observations, observation)
}
