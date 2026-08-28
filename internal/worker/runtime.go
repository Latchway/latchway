// Package worker runs bounded PostgreSQL-backed maintenance jobs.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/latchway/latchway/internal/telemetry"
)

const (
	defaultInterval             = 30 * time.Second
	defaultRunTimeout           = 10 * time.Second
	defaultQuotaBatchSize       = 100
	defaultReplayBatchSize      = 1_000
	defaultAttestationBatchSize = 100
	defaultMaxBatchesPerRun     = 4
)

// QuotaExpirer is the narrow quota-maintenance capability used by Runtime.
type QuotaExpirer interface {
	ExpirePendingBatch(context.Context, int) (int64, error)
}

type operationalQuota interface {
	ReleaseExpiredUndispatchedBatch(context.Context, int) (int64, error)
	ReconcilePendingUsageBatch(context.Context, int) (int64, error)
}

// ReplayCleaner is the narrow DPoP replay-maintenance capability used by
// Runtime.
type ReplayCleaner interface {
	DeleteExpired(context.Context, time.Time, int) (int64, error)
}

// AttestationCleaner is the narrow App Attest state-maintenance capability
// used by Runtime.
type AttestationCleaner interface {
	DeleteExpired(context.Context, time.Time, int) (int64, error)
}

type ChallengeCleaner interface {
	DeleteExpired(context.Context, time.Time, int) (int64, error)
}

type SigningKeyMaintainer interface {
	MaintainSigningKeys(context.Context) (int64, error)
}

type IdentityKeyMaintainer interface {
	MaintainIdentityKeys(context.Context) (int64, error)
}

type OperationalJobs interface {
	AggregateHourlyUsage(context.Context, time.Time) (int64, error)
	AggregateDailyUsage(context.Context, time.Time) (int64, error)
	EnforceRetention(context.Context, time.Time, int) (int64, error)
}

// Ticker is the stoppable clock source used between maintenance runs.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// TickerFactory constructs a Ticker. It is injectable so scheduling can be
// tested without wall-clock sleeps.
type TickerFactory func(time.Duration) Ticker

// Config defines a bounded maintenance runtime. Zero scheduling and batch
// values select conservative production defaults.
type Config struct {
	Quotas       QuotaExpirer
	Replays      ReplayCleaner
	Attestations AttestationCleaner
	Challenges   ChallengeCleaner
	SigningKeys  SigningKeyMaintainer
	IdentityKeys IdentityKeyMaintainer
	Operations   OperationalJobs
	Queue        *Queue
	Telemetry    *telemetry.Registry
	Logger       *slog.Logger

	Interval             time.Duration
	RunTimeout           time.Duration
	QuotaBatchSize       int
	ReplayBatchSize      int
	AttestationBatchSize int
	MaxBatches           int

	Now       func() time.Time
	NewTicker TickerFactory
}

// Runtime continuously recovers abandoned quota reservations and removes
// expired DPoP replay digests and App Attest maintenance state. A job failure
// is non-fatal: it is recorded using a redaction-safe code and retried on the
// next interval. Construction errors and unexpected runtime exits remain fatal
// to the process orchestrator.
type Runtime struct {
	quotas       QuotaExpirer
	replays      ReplayCleaner
	attestations AttestationCleaner
	challenges   ChallengeCleaner
	signingKeys  SigningKeyMaintainer
	identityKeys IdentityKeyMaintainer
	operations   OperationalJobs
	queue        *Queue
	telemetry    *telemetry.Registry
	logger       *slog.Logger

	interval             time.Duration
	runTimeout           time.Duration
	quotaBatchSize       int
	replayBatchSize      int
	attestationBatchSize int
	maxBatches           int

	now       func() time.Time
	newTicker TickerFactory
}

// New constructs a production maintenance runtime.
func New(config Config) (*Runtime, error) {
	if config.Quotas == nil {
		return nil, errors.New("worker quota expirer is nil")
	}
	if config.Replays == nil {
		return nil, errors.New("worker replay cleaner is nil")
	}
	if config.Attestations == nil {
		return nil, errors.New("worker attestation cleaner is nil")
	}
	if config.Queue != nil {
		if _, ok := config.Quotas.(operationalQuota); !ok || config.Challenges == nil || config.SigningKeys == nil || config.IdentityKeys == nil || config.Operations == nil {
			return nil, errors.New("durable worker job dependency is nil")
		}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Interval == 0 {
		config.Interval = defaultInterval
	}
	if config.RunTimeout == 0 {
		config.RunTimeout = defaultRunTimeout
	}
	if config.QuotaBatchSize == 0 {
		config.QuotaBatchSize = defaultQuotaBatchSize
	}
	if config.ReplayBatchSize == 0 {
		config.ReplayBatchSize = defaultReplayBatchSize
	}
	if config.AttestationBatchSize == 0 {
		config.AttestationBatchSize = defaultAttestationBatchSize
	}
	if config.MaxBatches == 0 {
		config.MaxBatches = defaultMaxBatchesPerRun
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewTicker == nil {
		config.NewTicker = newRealTicker
	}
	if config.Interval <= 0 || config.RunTimeout <= 0 ||
		config.QuotaBatchSize < 1 || config.QuotaBatchSize > 500 ||
		config.ReplayBatchSize < 1 || config.ReplayBatchSize > 10_000 ||
		config.AttestationBatchSize < 1 || config.AttestationBatchSize > 1_000 ||
		config.MaxBatches < 1 || config.MaxBatches > 100 {
		return nil, errors.New("worker scheduling or batch configuration is invalid")
	}

	return &Runtime{
		quotas: config.Quotas, replays: config.Replays,
		attestations: config.Attestations, challenges: config.Challenges,
		signingKeys: config.SigningKeys, identityKeys: config.IdentityKeys, operations: config.Operations,
		queue: config.Queue, telemetry: config.Telemetry, logger: config.Logger,
		interval: config.Interval, runTimeout: config.RunTimeout,
		quotaBatchSize: config.QuotaBatchSize, replayBatchSize: config.ReplayBatchSize,
		attestationBatchSize: config.AttestationBatchSize,
		maxBatches:           config.MaxBatches, now: config.Now, newTicker: config.NewTicker,
	}, nil
}

// Run performs one maintenance pass immediately and then repeats at the
// configured interval until ctx is canceled. It starts no subordinate
// goroutines, so returning guarantees that all worker activity has stopped.
func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return errors.New("worker runtime is invalid")
	}
	if ctx.Err() != nil {
		return nil
	}

	runtime.runPass(ctx)
	if ctx.Err() != nil {
		return nil
	}

	ticker := runtime.newTicker(runtime.interval)
	if ticker == nil {
		return errors.New("worker ticker is invalid")
	}
	ticks := ticker.C()
	if ticks == nil {
		ticker.Stop()
		return errors.New("worker ticker is invalid")
	}
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return errors.New("worker ticker stopped unexpectedly")
			}
			runtime.runPass(ctx)
		}
	}
}

func (runtime *Runtime) runPass(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if runtime.queue != nil {
		runtime.runDurablePass(ctx)
		return
	}
	before := runtime.now().UTC()
	runtime.runQuotaExpiry(ctx)
	if ctx.Err() != nil {
		return
	}
	runtime.runReplayCleanup(ctx, before)
	if ctx.Err() != nil {
		return
	}
	runtime.runAttestationCleanup(ctx, before)
}

func (runtime *Runtime) runDurablePass(ctx context.Context) {
	now := runtime.now().UTC()
	if now.IsZero() {
		runtime.logFailure(ctx, "worker_heartbeat", 0, 0, "invalid_clock")
		return
	}
	heartbeatCtx, heartbeatCancel := context.WithTimeout(ctx, runtime.runTimeout)
	err := runtime.queue.Heartbeat(heartbeatCtx)
	heartbeatCancel()
	if err != nil {
		runtime.logFailure(ctx, "worker_heartbeat", 0, 0, "job_failed")
		if runtime.telemetry != nil {
			runtime.telemetry.RecordWorkerJob(ctx, "worker_heartbeat", "failed", 0)
		}
		return
	}
	jobTypes := []string{
		"release_expired_reservations", "prune_dpop_replays", "prune_challenges",
		"rotate_signing_keys", "refresh_jwks", "aggregate_hourly_usage", "aggregate_daily_usage",
		"enforce_retention", "reconcile_pending_usage",
	}
	scheduleCtx, scheduleCancel := context.WithTimeout(ctx, runtime.runTimeout)
	err = runtime.queue.Schedule(scheduleCtx, now, jobTypes)
	scheduleCancel()
	if err != nil {
		runtime.logFailure(ctx, "worker_heartbeat", 0, 0, "schedule_failed")
		return
	}
	for range len(jobTypes) {
		if ctx.Err() != nil {
			return
		}
		claimCtx, claimCancel := context.WithTimeout(ctx, runtime.runTimeout)
		job, found, claimErr := runtime.queue.Claim(claimCtx, defaultWorkerStaleAfter)
		claimCancel()
		if claimErr != nil {
			runtime.logFailure(ctx, "worker_heartbeat", 0, 0, "claim_failed")
			return
		}
		if !found {
			break
		}
		runtime.executeDurableJob(ctx, job)
	}
	finalCtx, finalCancel := context.WithTimeout(ctx, runtime.runTimeout)
	_ = runtime.queue.Heartbeat(finalCtx)
	finalCancel()
}

func (runtime *Runtime) executeDurableJob(ctx context.Context, job Job) {
	started := runtime.now()
	runCtx, cancel := context.WithTimeout(ctx, runtime.runTimeout)
	processed, err := runtime.executeJob(runCtx, job)
	cancel()
	duration := runtime.now().Sub(started)
	if duration < 0 {
		duration = 0
	}
	finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer finalizeCancel()
	if err == nil {
		err = runtime.queue.Complete(finalizeCtx, job)
		if err == nil {
			runtime.logger.InfoContext(ctx, "maintenance job completed",
				"job", job.Type, "processed", processed, "attempt", job.AttemptCount,
			)
			if runtime.telemetry != nil {
				runtime.telemetry.RecordWorkerJob(ctx, job.Type, "succeeded", duration)
				if job.Type == "release_expired_reservations" || job.Type == "reconcile_pending_usage" {
					runtime.telemetry.RecordReservationsReclaimed(ctx, telemetry.Labels{Outcome: "reclaimed"}, processed)
				}
			}
			return
		}
	}
	code := "job_failed"
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		code = "run_timeout"
	}
	_ = runtime.queue.Fail(finalizeCtx, job, code)
	runtime.logFailure(ctx, job.Type, processed, job.AttemptCount, code)
	if runtime.telemetry != nil {
		runtime.telemetry.RecordWorkerJob(ctx, job.Type, "failed", duration)
	}
}

func (runtime *Runtime) executeJob(ctx context.Context, job Job) (int64, error) {
	quotaJobs := runtime.quotas.(operationalQuota)
	switch job.Type {
	case "release_expired_reservations":
		return runBoundedBatches(ctx, runtime.maxBatches, runtime.quotaBatchSize, func() (int64, error) {
			return quotaJobs.ReleaseExpiredUndispatchedBatch(ctx, runtime.quotaBatchSize)
		})
	case "reconcile_pending_usage":
		return runBoundedBatches(ctx, runtime.maxBatches, runtime.quotaBatchSize, func() (int64, error) {
			return quotaJobs.ReconcilePendingUsageBatch(ctx, runtime.quotaBatchSize)
		})
	case "prune_dpop_replays":
		return runBoundedBatches(ctx, runtime.maxBatches, runtime.replayBatchSize, func() (int64, error) {
			return runtime.replays.DeleteExpired(ctx, runtime.now().UTC(), runtime.replayBatchSize)
		})
	case "prune_challenges":
		return runBoundedBatches(ctx, runtime.maxBatches, runtime.replayBatchSize, func() (int64, error) {
			return runtime.challenges.DeleteExpired(ctx, runtime.now().UTC(), runtime.replayBatchSize)
		})
	case "rotate_signing_keys":
		return runtime.signingKeys.MaintainSigningKeys(ctx)
	case "refresh_jwks":
		return runtime.identityKeys.MaintainIdentityKeys(ctx)
	case "aggregate_hourly_usage":
		return runtime.operations.AggregateHourlyUsage(ctx, job.ScheduledAt)
	case "aggregate_daily_usage":
		return runtime.operations.AggregateDailyUsage(ctx, job.ScheduledAt)
	case "enforce_retention":
		processed, err := runtime.operations.EnforceRetention(ctx, job.ScheduledAt, runtime.replayBatchSize)
		if err != nil {
			return processed, err
		}
		attestation, err := runBoundedBatches(ctx, runtime.maxBatches, runtime.attestationBatchSize, func() (int64, error) {
			return runtime.attestations.DeleteExpired(ctx, runtime.now().UTC(), runtime.attestationBatchSize)
		})
		return processed + attestation, err
	default:
		return 0, errors.New("unsupported durable worker job")
	}
}

func runBoundedBatches(ctx context.Context, maxBatches, batchSize int, run func() (int64, error)) (int64, error) {
	var processed int64
	for range maxBatches {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		count, err := run()
		if err != nil {
			return processed, err
		}
		if count < 0 || count > int64(batchSize) {
			return processed, errors.New("maintenance job returned invalid count")
		}
		processed += count
		if count < int64(batchSize) {
			break
		}
	}
	return processed, nil
}

func (runtime *Runtime) runQuotaExpiry(ctx context.Context) {
	runtime.runBatches(ctx, "quota_pending_expiry", runtime.quotaBatchSize, func(runCtx context.Context) (int64, error) {
		return runtime.quotas.ExpirePendingBatch(runCtx, runtime.quotaBatchSize)
	})
}

func (runtime *Runtime) runReplayCleanup(ctx context.Context, before time.Time) {
	if before.IsZero() {
		runtime.logFailure(ctx, "dpop_replay_cleanup", 0, 0, "invalid_clock")
		return
	}
	runtime.runBatches(ctx, "dpop_replay_cleanup", runtime.replayBatchSize, func(runCtx context.Context) (int64, error) {
		return runtime.replays.DeleteExpired(runCtx, before, runtime.replayBatchSize)
	})
}

func (runtime *Runtime) runAttestationCleanup(ctx context.Context, before time.Time) {
	if before.IsZero() {
		runtime.logFailure(ctx, "attestation_state_cleanup", 0, 0, "invalid_clock")
		return
	}
	runtime.runBatches(ctx, "attestation_state_cleanup", runtime.attestationBatchSize, func(runCtx context.Context) (int64, error) {
		return runtime.attestations.DeleteExpired(runCtx, before, runtime.attestationBatchSize)
	})
}

func (runtime *Runtime) runBatches(
	ctx context.Context,
	name string,
	batchSize int,
	runBatch func(context.Context) (int64, error),
) {
	runCtx, cancel := context.WithTimeout(ctx, runtime.runTimeout)
	defer cancel()

	var processed int64
	var batches int
	bounded := false
	for batches < runtime.maxBatches {
		count, err := runBatch(runCtx)
		batches++
		if count >= 0 && count <= int64(batchSize) {
			processed += count
		}
		if err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return
			}
			code := "job_failed"
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				code = "run_timeout"
			}
			runtime.logFailure(ctx, name, processed, batches, code)
			return
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			runtime.logFailure(ctx, name, processed, batches, "run_timeout")
			return
		}
		if ctx.Err() != nil {
			return
		}
		if count < 0 || count > int64(batchSize) {
			runtime.logFailure(ctx, name, processed, batches, "invalid_count")
			return
		}
		if count < int64(batchSize) {
			break
		}
		bounded = batches == runtime.maxBatches
	}
	runtime.logger.InfoContext(ctx, "maintenance job completed",
		"job", name,
		"processed", processed,
		"batches", batches,
		"bounded", bounded,
	)
}

func (runtime *Runtime) logFailure(ctx context.Context, name string, processed int64, batches int, code string) {
	// Do not log the underlying error: database and dependency errors are not a
	// safe channel for tenant identifiers, credentials, or provider material.
	runtime.logger.ErrorContext(ctx, "maintenance job failed",
		"job", name,
		"processed", processed,
		"batches", batches,
		"error_code", code,
	)
}

type realTicker struct {
	*time.Ticker
}

func newRealTicker(interval time.Duration) Ticker {
	return realTicker{Ticker: time.NewTicker(interval)}
}

func (ticker realTicker) C() <-chan time.Time {
	return ticker.Ticker.C
}
