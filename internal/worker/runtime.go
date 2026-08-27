// Package worker runs bounded PostgreSQL-backed maintenance jobs.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const (
	defaultInterval         = 30 * time.Second
	defaultRunTimeout       = 10 * time.Second
	defaultQuotaBatchSize   = 100
	defaultReplayBatchSize  = 1_000
	defaultMaxBatchesPerRun = 4
)

// QuotaExpirer is the narrow quota-maintenance capability used by Runtime.
type QuotaExpirer interface {
	ExpirePendingBatch(context.Context, int) (int64, error)
}

// ReplayCleaner is the narrow DPoP replay-maintenance capability used by
// Runtime.
type ReplayCleaner interface {
	DeleteExpired(context.Context, time.Time, int) (int64, error)
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
	Quotas  QuotaExpirer
	Replays ReplayCleaner
	Logger  *slog.Logger

	Interval        time.Duration
	RunTimeout      time.Duration
	QuotaBatchSize  int
	ReplayBatchSize int
	MaxBatches      int

	Now       func() time.Time
	NewTicker TickerFactory
}

// Runtime continuously recovers abandoned quota reservations and removes
// expired DPoP replay digests. A job failure is non-fatal: it is recorded using
// a redaction-safe code and retried on the next interval. Construction errors
// and unexpected runtime exits remain fatal to the process orchestrator.
type Runtime struct {
	quotas  QuotaExpirer
	replays ReplayCleaner
	logger  *slog.Logger

	interval        time.Duration
	runTimeout      time.Duration
	quotaBatchSize  int
	replayBatchSize int
	maxBatches      int

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
		config.MaxBatches < 1 || config.MaxBatches > 100 {
		return nil, errors.New("worker scheduling or batch configuration is invalid")
	}

	return &Runtime{
		quotas: config.Quotas, replays: config.Replays, logger: config.Logger,
		interval: config.Interval, runTimeout: config.RunTimeout,
		quotaBatchSize: config.QuotaBatchSize, replayBatchSize: config.ReplayBatchSize,
		maxBatches: config.MaxBatches, now: config.Now, newTicker: config.NewTicker,
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
	runtime.runQuotaExpiry(ctx)
	if ctx.Err() != nil {
		return
	}
	runtime.runReplayCleanup(ctx)
}

func (runtime *Runtime) runQuotaExpiry(ctx context.Context) {
	runtime.runBatches(ctx, "quota_pending_expiry", runtime.quotaBatchSize, func(runCtx context.Context) (int64, error) {
		return runtime.quotas.ExpirePendingBatch(runCtx, runtime.quotaBatchSize)
	})
}

func (runtime *Runtime) runReplayCleanup(ctx context.Context) {
	before := runtime.now().UTC()
	if before.IsZero() {
		runtime.logFailure(ctx, "dpop_replay_cleanup", 0, 0, "invalid_clock")
		return
	}
	runtime.runBatches(ctx, "dpop_replay_cleanup", runtime.replayBatchSize, func(runCtx context.Context) (int64, error) {
		return runtime.replays.DeleteExpired(runCtx, before, runtime.replayBatchSize)
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
