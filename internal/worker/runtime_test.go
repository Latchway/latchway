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
	attestation := &fakeAttestationCleaner{results: []batchResult{{count: 2}, {count: 2}, {count: 0}}}
	now := time.Date(2026, time.August, 28, 4, 5, 6, 0, time.UTC)
	runtime := newTestRuntime(t, Config{
		Quotas: quota, Replays: replay, Attestations: attestation,
		QuotaBatchSize: 2, ReplayBatchSize: 3, AttestationBatchSize: 2,
		MaxBatches: 2, Now: func() time.Time { return now },
		NewTicker: func(time.Duration) Ticker { return ticker },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	quota.waitCalls(t, 2)
	replay.waitCalls(t, 2)
	attestation.waitCalls(t, 2)
	if got := quota.callCount(); got != 2 {
		t.Fatalf("immediate quota calls = %d, want bounded 2", got)
	}
	if got := replay.beforeValues(); len(got) != 2 || !got[0].Equal(now) || !got[1].Equal(now) {
		t.Fatalf("replay cutoffs = %v, want one stable cutoff %v", got, now)
	}
	if got := attestation.beforeValues(); len(got) != 2 || !got[0].Equal(now) || !got[1].Equal(now) {
		t.Fatalf("attestation cutoffs = %v, want one stable cutoff %v", got, now)
	}
	if got := attestation.limitValues(); len(got) != 2 || got[0] != 2 || got[1] != 2 {
		t.Fatalf("attestation limits = %v, want [2 2]", got)
	}

	ticker.tick(now.Add(time.Minute))
	quota.waitCalls(t, 4)
	replay.waitCalls(t, 3)
	attestation.waitCalls(t, 3)
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
	attestation := &fakeAttestationCleaner{results: []batchResult{{count: 0}, {count: 0}}}
	runtime, err := New(Config{
		Quotas: quota, Replays: replay, Attestations: attestation,
		Logger:   slog.New(slog.NewJSONHandler(&logs, nil)),
		Interval: time.Minute, RunTimeout: time.Second,
		QuotaBatchSize: 2, ReplayBatchSize: 2, AttestationBatchSize: 2, MaxBatches: 1,
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
	attestation.waitCalls(t, 1)
	waitChannel(t, tickerReady, "ticker creation after immediate pass")
	if got := logs.String(); !strings.Contains(got, `"error_code":"job_failed"`) || strings.Contains(got, sensitiveDetail) {
		t.Fatalf("unsafe or incomplete worker log = %s", got)
	}

	ticker.tick(time.Now())
	quota.waitCalls(t, 2)
	replay.waitCalls(t, 2)
	attestation.waitCalls(t, 2)
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
	attestation := &fakeAttestationCleaner{}
	runtime := newTestRuntime(t, Config{
		Quotas: quota, Replays: replay, Attestations: attestation,
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
	if got := attestation.callCount(); got != 0 {
		t.Fatalf("attestation cleanup calls after cancellation = %d, want 0", got)
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
	attestation := &fakeAttestationCleaner{results: []batchResult{{count: 0}}}
	runtime, err := New(Config{
		Quotas: quota, Replays: replay, Attestations: attestation,
		Logger:   slog.New(slog.NewJSONHandler(&logs, nil)),
		Interval: time.Hour, RunTimeout: 10 * time.Millisecond,
		QuotaBatchSize: 1, ReplayBatchSize: 1, AttestationBatchSize: 1, MaxBatches: 1,
		Now: time.Now, NewTicker: func(time.Duration) Ticker { return newManualTicker() },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	replay.waitCalls(t, 1)
	attestation.waitCalls(t, 1)
	cancel()
	if err := waitRuntime(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(logs.String(), `"error_code":"run_timeout"`) {
		t.Fatalf("timeout log = %s", logs.String())
	}
}

func TestRuntimeSharesOneUTCCutoffAndOrdersAttestationAfterReplay(t *testing.T) {
	t.Parallel()

	sourceTime := time.Date(2026, time.August, 28, 11, 12, 13, 14, time.FixedZone("test", 7*60*60))
	wantCutoff := sourceTime.UTC()
	nowCalls := 0
	var calls []string
	quota := quotaExpirerFunc(func(context.Context, int) (int64, error) {
		calls = append(calls, "quota")
		return 0, nil
	})
	replay := replayCleanerFunc(func(_ context.Context, before time.Time, _ int) (int64, error) {
		calls = append(calls, "replay")
		if before != wantCutoff || before.Location() != time.UTC {
			t.Fatalf("replay cutoff = %v (%v), want UTC %v", before, before.Location(), wantCutoff)
		}
		return 0, nil
	})
	attestation := attestationCleanerFunc(func(_ context.Context, before time.Time, _ int) (int64, error) {
		calls = append(calls, "attestation")
		if before != wantCutoff || before.Location() != time.UTC {
			t.Fatalf("attestation cutoff = %v (%v), want UTC %v", before, before.Location(), wantCutoff)
		}
		return 0, nil
	})
	runtime := newTestRuntime(t, Config{
		Quotas: quota, Replays: replay, Attestations: attestation,
		Now: func() time.Time {
			nowCalls++
			return sourceTime
		},
	})

	runtime.runPass(context.Background())

	if got := strings.Join(calls, ","); got != "quota,replay,attestation" {
		t.Fatalf("maintenance order = %q, want quota,replay,attestation", got)
	}
	if nowCalls != 1 {
		t.Fatalf("clock calls = %d, want 1 per pass", nowCalls)
	}
}

func TestRuntimeCancellationDuringReplaySkipsAttestation(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	replay := replayCleanerFunc(func(ctx context.Context, _ time.Time, _ int) (int64, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	})
	attestation := &fakeAttestationCleaner{}
	runtime := newTestRuntime(t, Config{
		Quotas: &fakeQuotaExpirer{}, Replays: replay, Attestations: attestation,
		NewTicker: func(time.Duration) Ticker { return newManualTicker() },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitChannel(t, started, "replay cleanup")
	cancel()
	if err := waitRuntime(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := attestation.callCount(); got != 0 {
		t.Fatalf("attestation cleanup calls after replay cancellation = %d, want 0", got)
	}
}

func TestRuntimeReplayTimeoutStillRunsAttestation(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	replay := replayCleanerFunc(func(ctx context.Context, _ time.Time, _ int) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	attestation := &fakeAttestationCleaner{results: []batchResult{{count: 0}}}
	runtime := newTestRuntime(t, Config{
		Quotas: &fakeQuotaExpirer{}, Replays: replay, Attestations: attestation,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)), RunTimeout: 10 * time.Millisecond,
	})

	runtime.runPass(context.Background())

	if got := attestation.callCount(); got != 1 {
		t.Fatalf("attestation calls after replay timeout = %d, want 1", got)
	}
	gotLogs := logs.String()
	if !strings.Contains(gotLogs, `"job":"dpop_replay_cleanup"`) ||
		!strings.Contains(gotLogs, `"error_code":"run_timeout"`) {
		t.Fatalf("replay timeout log = %s", gotLogs)
	}
}

func TestRuntimeAttestationFailureUsesStableRedactedJobCode(t *testing.T) {
	t.Parallel()

	const sensitiveDetail = "app attest key, receipt, and tenant secret"
	var logs bytes.Buffer
	runtime := newTestRuntime(t, Config{
		Quotas: &fakeQuotaExpirer{}, Replays: &fakeReplayCleaner{},
		Attestations: attestationCleanerFunc(func(context.Context, time.Time, int) (int64, error) {
			return 0, errors.New(sensitiveDetail)
		}),
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})

	runtime.runPass(context.Background())

	got := logs.String()
	if !strings.Contains(got, `"job":"attestation_state_cleanup"`) ||
		!strings.Contains(got, `"error_code":"job_failed"`) ||
		strings.Contains(got, sensitiveDetail) {
		t.Fatalf("unsafe or incomplete attestation log = %s", got)
	}
}

func TestRuntimeAttestationCleanupHonorsRunTimeout(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	attestation := attestationCleanerFunc(func(ctx context.Context, _ time.Time, _ int) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	runtime := newTestRuntime(t, Config{
		Quotas: &fakeQuotaExpirer{}, Replays: &fakeReplayCleaner{}, Attestations: attestation,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)), RunTimeout: 10 * time.Millisecond,
	})

	runtime.runPass(context.Background())

	got := logs.String()
	if !strings.Contains(got, `"job":"attestation_state_cleanup"`) ||
		!strings.Contains(got, `"error_code":"run_timeout"`) {
		t.Fatalf("attestation timeout log = %s", got)
	}
}

func TestRuntimeInvalidClockSkipsTimeBasedCleanupWithStableCodes(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	quota := &fakeQuotaExpirer{}
	replay := &fakeReplayCleaner{}
	attestation := &fakeAttestationCleaner{}
	runtime := newTestRuntime(t, Config{
		Quotas: quota, Replays: replay, Attestations: attestation,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)), Now: func() time.Time { return time.Time{} },
	})

	runtime.runPass(context.Background())

	if got := quota.callCount(); got != 1 {
		t.Fatalf("quota calls = %d, want 1", got)
	}
	if got := replay.callCount(); got != 0 {
		t.Fatalf("replay calls with invalid clock = %d, want 0", got)
	}
	if got := attestation.callCount(); got != 0 {
		t.Fatalf("attestation calls with invalid clock = %d, want 0", got)
	}
	gotLogs := logs.String()
	if !strings.Contains(gotLogs, `"job":"dpop_replay_cleanup"`) ||
		!strings.Contains(gotLogs, `"job":"attestation_state_cleanup"`) ||
		strings.Count(gotLogs, `"error_code":"invalid_clock"`) != 2 {
		t.Fatalf("invalid-clock logs = %s", gotLogs)
	}
}

func TestNewRejectsInvalidDependenciesAndBounds(t *testing.T) {
	t.Parallel()

	valid := Config{
		Quotas:       &fakeQuotaExpirer{},
		Replays:      &fakeReplayCleaner{},
		Attestations: &fakeAttestationCleaner{},
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "quota", mutate: func(config *Config) { config.Quotas = nil }},
		{name: "replay", mutate: func(config *Config) { config.Replays = nil }},
		{name: "attestation", mutate: func(config *Config) { config.Attestations = nil }},
		{name: "interval", mutate: func(config *Config) { config.Interval = -time.Second }},
		{name: "timeout", mutate: func(config *Config) { config.RunTimeout = -time.Second }},
		{name: "quota batch", mutate: func(config *Config) { config.QuotaBatchSize = 501 }},
		{name: "replay batch", mutate: func(config *Config) { config.ReplayBatchSize = 10_001 }},
		{name: "attestation batch low", mutate: func(config *Config) { config.AttestationBatchSize = -1 }},
		{name: "attestation batch", mutate: func(config *Config) { config.AttestationBatchSize = 1_001 }},
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

func TestNewUsesConservativeAttestationBatchDefault(t *testing.T) {
	t.Parallel()

	runtime, err := New(Config{
		Quotas: &fakeQuotaExpirer{}, Replays: &fakeReplayCleaner{},
		Attestations: &fakeAttestationCleaner{},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if runtime.attestationBatchSize != 100 {
		t.Fatalf("attestation batch default = %d, want 100", runtime.attestationBatchSize)
	}
}

func TestRuntimeExecutesDurableIdentityKeyRefresh(t *testing.T) {
	t.Parallel()
	maintainer := identityKeyMaintainerFunc(func(context.Context) (int64, error) { return 7, nil })
	runtime := &Runtime{quotas: durableQuotaStub{}, identityKeys: maintainer}
	processed, err := runtime.executeJob(context.Background(), Job{Type: "refresh_jwks"})
	if err != nil || processed != 7 {
		t.Fatalf("identity-key refresh processed=%d err=%v", processed, err)
	}

	const sensitive = "issuer tenant and identity token must stay out of logs"
	runtime.identityKeys = identityKeyMaintainerFunc(func(context.Context) (int64, error) {
		return 0, errors.New(sensitive)
	})
	if _, err := runtime.executeJob(context.Background(), Job{Type: "refresh_jwks"}); err == nil || err.Error() != sensitive {
		t.Fatalf("identity-key refresh failure = %v", err)
	}
}

func TestRuntimeExecutesDistinctBoundedConcurrencyRecoveryLane(t *testing.T) {
	t.Parallel()
	quota := &recordingDurableQuota{concurrencyResults: []batchResult{{count: 3}, {count: 1}}}
	runtime := &Runtime{quotas: quota, maxBatches: 2, quotaBatchSize: 3}
	processed, err := runtime.executeJob(context.Background(), Job{Type: "release_expired_concurrency_leases"})
	if err != nil || processed != 4 {
		t.Fatalf("concurrency recovery processed=%d err=%v, want 4 nil", processed, err)
	}
	if quota.concurrencyCalls != 2 || quota.undispatchedCalls != 0 || quota.reconcileCalls != 0 {
		t.Fatalf("quota lane calls concurrency=%d undispatched=%d reconcile=%d",
			quota.concurrencyCalls, quota.undispatchedCalls, quota.reconcileCalls)
	}
}

func TestScheduledDurableJobInventoryIsClosedAndExecutable(t *testing.T) {
	t.Parallel()
	types := scheduledDurableJobTypes()
	if len(types)+1 != len(supportedJobTypes) {
		t.Fatalf("periodic jobs=%d supported=%d", len(types), len(supportedJobTypes))
	}
	seen := make(map[string]struct{}, len(types))
	for _, jobType := range types {
		if _, duplicate := seen[jobType]; duplicate {
			t.Fatalf("duplicate scheduled job %q", jobType)
		}
		seen[jobType] = struct{}{}
		if _, supported := supportedJobTypes[jobType]; !supported {
			t.Fatalf("scheduled job %q has no executable queue contract", jobType)
		}
	}
	if _, ok := seen["release_expired_concurrency_leases"]; !ok {
		t.Fatal("concurrency recovery lane is absent")
	}
	if _, periodic := seen["run_scheduled_self_test"]; periodic {
		t.Fatal("per-schedule self-test entered the global periodic scheduler")
	}
	if _, supported := supportedJobTypes["run_scheduled_self_test"]; !supported {
		t.Fatal("persistently authorized scheduled self-test is not executable")
	}
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	runtime := &Runtime{
		quotas: durableQuotaStub{},
		replays: replayCleanerFunc(func(context.Context, time.Time, int) (int64, error) {
			return 0, nil
		}),
		attestations: attestationCleanerFunc(func(context.Context, time.Time, int) (int64, error) {
			return 0, nil
		}),
		challenges: challengeCleanerFunc(func(context.Context, time.Time, int) (int64, error) {
			return 0, nil
		}),
		signingKeys: signingKeyMaintainerFunc(func(context.Context) (int64, error) { return 0, nil }),
		identityKeys: identityKeyMaintainerFunc(func(context.Context) (int64, error) {
			return 0, nil
		}),
		operations: operationalJobsStub{}, quotaBatchSize: 1, replayBatchSize: 1,
		attestationBatchSize: 1, maxBatches: 1, now: func() time.Time { return now },
		selfTests: scheduledSelfTestsFunc(func(context.Context, string) (int64, error) { return 1, nil }),
	}
	for _, jobType := range types {
		if _, err := runtime.executeJob(context.Background(), Job{Type: jobType, ScheduledAt: now}); err != nil {
			t.Fatalf("scheduled job %q is not executable: %v", jobType, err)
		}
	}
	if processed, err := runtime.executeJob(context.Background(), Job{Type: "run_scheduled_self_test", ScheduledAt: now}); err != nil || processed != 1 {
		t.Fatalf("scheduled self-test processed=%d err=%v", processed, err)
	}
}

type scheduledSelfTestsFunc func(context.Context, string) (int64, error)

func (run scheduledSelfTestsFunc) ExecuteScheduled(ctx context.Context, jobID string) (int64, error) {
	return run(ctx, jobID)
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
	if config.AttestationBatchSize == 0 {
		config.AttestationBatchSize = 2
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

type durableQuotaStub struct{}

func (durableQuotaStub) ExpirePendingBatch(context.Context, int) (int64, error) { return 0, nil }
func (durableQuotaStub) ReleaseExpiredUndispatchedBatch(context.Context, int) (int64, error) {
	return 0, nil
}
func (durableQuotaStub) ReleaseExpiredConcurrencyLeasesBatch(context.Context, int) (int64, error) {
	return 0, nil
}
func (durableQuotaStub) ReconcilePendingUsageBatch(context.Context, int) (int64, error) {
	return 0, nil
}

type recordingDurableQuota struct {
	concurrencyResults []batchResult
	concurrencyCalls   int
	undispatchedCalls  int
	reconcileCalls     int
}

func (quota *recordingDurableQuota) ExpirePendingBatch(context.Context, int) (int64, error) {
	return 0, nil
}

func (quota *recordingDurableQuota) ReleaseExpiredUndispatchedBatch(context.Context, int) (int64, error) {
	quota.undispatchedCalls++
	return 0, nil
}

func (quota *recordingDurableQuota) ReleaseExpiredConcurrencyLeasesBatch(context.Context, int) (int64, error) {
	quota.concurrencyCalls++
	if len(quota.concurrencyResults) == 0 {
		return 0, nil
	}
	result := quota.concurrencyResults[0]
	quota.concurrencyResults = quota.concurrencyResults[1:]
	return result.count, result.err
}

func (quota *recordingDurableQuota) ReconcilePendingUsageBatch(context.Context, int) (int64, error) {
	quota.reconcileCalls++
	return 0, nil
}

type identityKeyMaintainerFunc func(context.Context) (int64, error)

func (maintainer identityKeyMaintainerFunc) MaintainIdentityKeys(ctx context.Context) (int64, error) {
	return maintainer(ctx)
}

type signingKeyMaintainerFunc func(context.Context) (int64, error)

func (maintainer signingKeyMaintainerFunc) MaintainSigningKeys(ctx context.Context) (int64, error) {
	return maintainer(ctx)
}

type challengeCleanerFunc func(context.Context, time.Time, int) (int64, error)

func (cleaner challengeCleanerFunc) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	return cleaner(ctx, before, limit)
}

type operationalJobsStub struct{}

func (operationalJobsStub) AggregateHourlyUsage(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (operationalJobsStub) AggregateDailyUsage(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (operationalJobsStub) EnforceRetention(context.Context, time.Time, int) (int64, error) {
	return 0, nil
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

type fakeAttestationCleaner struct {
	mu      sync.Mutex
	results []batchResult
	calls   int
	before  []time.Time
	limits  []int
	notify  chan struct{}
}

func (fake *fakeAttestationCleaner) DeleteExpired(_ context.Context, before time.Time, limit int) (int64, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls++
	fake.before = append(fake.before, before)
	fake.limits = append(fake.limits, limit)
	fake.signal()
	if len(fake.results) == 0 {
		return 0, nil
	}
	result := fake.results[0]
	fake.results = fake.results[1:]
	return result.count, result.err
}

func (fake *fakeAttestationCleaner) callCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.calls
}

func (fake *fakeAttestationCleaner) beforeValues() []time.Time {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]time.Time(nil), fake.before...)
}

func (fake *fakeAttestationCleaner) limitValues() []int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]int(nil), fake.limits...)
}

func (fake *fakeAttestationCleaner) waitCalls(t *testing.T, want int) {
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

func (fake *fakeAttestationCleaner) signal() {
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

type replayCleanerFunc func(context.Context, time.Time, int) (int64, error)

func (function replayCleanerFunc) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	return function(ctx, before, limit)
}

type attestationCleanerFunc func(context.Context, time.Time, int) (int64, error)

func (function attestationCleanerFunc) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	return function(ctx, before, limit)
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
