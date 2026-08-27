package worker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRuntimeRunsImmediatelyAndBoundsEachPass(t *testing.T) {
	t.Parallel()

	ticker := newManualTicker()
	quota := &fakeQuotaExpirer{results: []batchResult{{count: 2}, {count: 2}, {count: 2}, {count: 0}}}
	replay := &fakeReplayCleaner{results: []batchResult{{count: 3}, {count: 1}, {count: 0}}}
	now := time.Date(2026, time.August, 28, 4, 5, 6, 0, time.UTC)
	runtime := newTestRuntime(t, Config{
		Quotas: quota, Replays: replay, QuotaBatchSize: 2, ReplayBatchSize: 3,
		MaxBatches: 2, Now: func() time.Time { return now },
		NewTicker: func(time.Duration) Ticker { return ticker },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	quota.waitCalls(t, 2)
	replay.waitCalls(t, 2)
	if got := quota.callCount(); got != 2 {
		t.Fatalf("immediate quota calls = %d, want bounded 2", got)
	}
	if got := replay.beforeValues(); len(got) != 2 || !got[0].Equal(now) || !got[1].Equal(now) {
		t.Fatalf("replay cutoffs = %v, want one stable cutoff %v", got, now)
	}

	ticker.tick(now.Add(time.Minute))
	quota.waitCalls(t, 4)
	replay.waitCalls(t, 3)
	cancel()
	if err := waitRuntime(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !ticker.wasStopped() {
		t.Fatal("ticker was not stopped")
	}
}

func TestRuntimeRetriesErrorsWithoutLoggingDependencyDetails(t *testing.T) {
	t.Parallel()

	const sensitiveDetail = "postgres error includes tenant-id-and-secret"
	var logs bytes.Buffer
	ticker := newManualTicker()
	tickerReady := make(chan struct{})
	quota := &fakeQuotaExpirer{results: []batchResult{{err: errors.New(sensitiveDetail)}, {count: 0}}}
	replay := &fakeReplayCleaner{results: []batchResult{{count: 0}, {count: 0}}}
	runtime, err := New(Config{
		Quotas: quota, Replays: replay,
		Logger:   slog.New(slog.NewJSONHandler(&logs, nil)),
		Interval: time.Minute, RunTimeout: time.Second,
		QuotaBatchSize: 2, ReplayBatchSize: 2, MaxBatches: 1,
		Now: time.Now, NewTicker: func(time.Duration) Ticker {
			close(tickerReady)
			return ticker
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	quota.waitCalls(t, 1)
	replay.waitCalls(t, 1)
	waitChannel(t, tickerReady, "ticker creation after immediate pass")
	if got := logs.String(); !strings.Contains(got, `"error_code":"job_failed"`) || strings.Contains(got, sensitiveDetail) {
		t.Fatalf("unsafe or incomplete worker log = %s", got)
	}

	ticker.tick(time.Now())
	quota.waitCalls(t, 2)
	replay.waitCalls(t, 2)
	cancel()
	if err := waitRuntime(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRuntimeCancellationStopsAnActiveJobAndSkipsRemainingWork(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	quota := quotaExpirerFunc(func(ctx context.Context, _ int) (int64, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	})
	replay := &fakeReplayCleaner{}
	runtime := newTestRuntime(t, Config{
		Quotas: quota, Replays: replay,
		NewTicker: func(time.Duration) Ticker { return newManualTicker() },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("immediate maintenance job did not start")
	}
	cancel()
	if err := waitRuntime(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := replay.callCount(); got != 0 {
		t.Fatalf("replay cleanup calls after cancellation = %d, want 0", got)
	}
}

func TestRuntimeTimesOutAJobAndContinuesToTheIndependentJob(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	quota := quotaExpirerFunc(func(ctx context.Context, _ int) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	replay := &fakeReplayCleaner{results: []batchResult{{count: 0}}}
	runtime, err := New(Config{
		Quotas: quota, Replays: replay,
		Logger:   slog.New(slog.NewJSONHandler(&logs, nil)),
		Interval: time.Hour, RunTimeout: 10 * time.Millisecond,
		QuotaBatchSize: 1, ReplayBatchSize: 1, MaxBatches: 1,
		Now: time.Now, NewTicker: func(time.Duration) Ticker { return newManualTicker() },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	replay.waitCalls(t, 1)
	cancel()
	if err := waitRuntime(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(logs.String(), `"error_code":"run_timeout"`) {
		t.Fatalf("timeout log = %s", logs.String())
	}
}

func TestNewRejectsInvalidDependenciesAndBounds(t *testing.T) {
	t.Parallel()

	valid := Config{Quotas: &fakeQuotaExpirer{}, Replays: &fakeReplayCleaner{}}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "quota", mutate: func(config *Config) { config.Quotas = nil }},
		{name: "replay", mutate: func(config *Config) { config.Replays = nil }},
		{name: "interval", mutate: func(config *Config) { config.Interval = -time.Second }},
		{name: "timeout", mutate: func(config *Config) { config.RunTimeout = -time.Second }},
		{name: "quota batch", mutate: func(config *Config) { config.QuotaBatchSize = 501 }},
		{name: "replay batch", mutate: func(config *Config) { config.ReplayBatchSize = 10_001 }},
		{name: "batches", mutate: func(config *Config) { config.MaxBatches = 101 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if runtime, err := New(config); err == nil || runtime != nil {
				t.Fatalf("New() = %#v, %v; want rejection", runtime, err)
			}
		})
	}
}

func newTestRuntime(t *testing.T, config Config) *Runtime {
	t.Helper()
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	}
	if config.Interval == 0 {
		config.Interval = time.Hour
	}
	if config.RunTimeout == 0 {
		config.RunTimeout = time.Second
	}
	if config.QuotaBatchSize == 0 {
		config.QuotaBatchSize = 2
	}
	if config.ReplayBatchSize == 0 {
		config.ReplayBatchSize = 2
	}
	if config.MaxBatches == 0 {
		config.MaxBatches = 2
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	runtime, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return runtime
}

func waitRuntime(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("worker runtime did not stop")
		return nil
	}
}

func waitChannel(t *testing.T, channel <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

type batchResult struct {
	count int64
	err   error
}

type fakeQuotaExpirer struct {
	mu      sync.Mutex
	results []batchResult
	calls   int
	notify  chan struct{}
}

func (fake *fakeQuotaExpirer) ExpirePendingBatch(_ context.Context, _ int) (int64, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls++
	fake.signal()
	if len(fake.results) == 0 {
		return 0, nil
	}
	result := fake.results[0]
	fake.results = fake.results[1:]
	return result.count, result.err
}

func (fake *fakeQuotaExpirer) callCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.calls
}

func (fake *fakeQuotaExpirer) waitCalls(t *testing.T, want int) {
	t.Helper()
	waitCalls(t, want, fake.callCount, func() <-chan struct{} {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.notify == nil {
			fake.notify = make(chan struct{}, 1)
		}
		return fake.notify
	})
}

func (fake *fakeQuotaExpirer) signal() {
	if fake.notify == nil {
		fake.notify = make(chan struct{}, 1)
	}
	select {
	case fake.notify <- struct{}{}:
	default:
	}
}

type fakeReplayCleaner struct {
	mu      sync.Mutex
	results []batchResult
	calls   int
	before  []time.Time
	notify  chan struct{}
}

func (fake *fakeReplayCleaner) DeleteExpired(_ context.Context, before time.Time, _ int) (int64, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls++
	fake.before = append(fake.before, before)
	fake.signal()
	if len(fake.results) == 0 {
		return 0, nil
	}
	result := fake.results[0]
	fake.results = fake.results[1:]
	return result.count, result.err
}

func (fake *fakeReplayCleaner) callCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.calls
}

func (fake *fakeReplayCleaner) beforeValues() []time.Time {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]time.Time(nil), fake.before...)
}

func (fake *fakeReplayCleaner) waitCalls(t *testing.T, want int) {
	t.Helper()
	waitCalls(t, want, fake.callCount, func() <-chan struct{} {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.notify == nil {
			fake.notify = make(chan struct{}, 1)
		}
		return fake.notify
	})
}

func (fake *fakeReplayCleaner) signal() {
	if fake.notify == nil {
		fake.notify = make(chan struct{}, 1)
	}
	select {
	case fake.notify <- struct{}{}:
	default:
	}
}

func waitCalls(t *testing.T, want int, current func() int, notify func() <-chan struct{}) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for current() < want {
		select {
		case <-notify():
		case <-deadline.C:
			t.Fatalf("calls = %d, want at least %d", current(), want)
		}
	}
}

type quotaExpirerFunc func(context.Context, int) (int64, error)

func (function quotaExpirerFunc) ExpirePendingBatch(ctx context.Context, limit int) (int64, error) {
	return function(ctx, limit)
}

type manualTicker struct {
	channel chan time.Time
	mu      sync.Mutex
	stopped bool
}

func newManualTicker() *manualTicker {
	return &manualTicker{channel: make(chan time.Time, 1)}
}

func (ticker *manualTicker) C() <-chan time.Time { return ticker.channel }

func (ticker *manualTicker) Stop() {
	ticker.mu.Lock()
	defer ticker.mu.Unlock()
	ticker.stopped = true
}

func (ticker *manualTicker) tick(at time.Time) {
	ticker.channel <- at
}

func (ticker *manualTicker) wasStopped() bool {
	ticker.mu.Lock()
	defer ticker.mu.Unlock()
	return ticker.stopped
}
