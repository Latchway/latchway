package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HealthSampleInterval is how often the worker records the self-check.
const HealthSampleInterval = 5 * time.Minute

// HealthSampleRetention is how long samples are kept.
const HealthSampleRetention = 30 * 24 * time.Hour

// Sampler records a compact summary of the self-check for health history.
type Sampler struct {
	pool         *pgxpool.Pool
	role         string
	dependencies Dependencies
}

// NewSampler returns a sampler for a worker or all-in-one process.
func NewSampler(pool *pgxpool.Pool, role string, dependencies Dependencies) (*Sampler, error) {
	if pool == nil || (role != "worker" && role != "all") {
		return nil, errors.New("health sampler configuration is invalid")
	}
	return &Sampler{pool: pool, role: role, dependencies: dependencies}, nil
}

// HealthSample is one recorded self-check summary. Only check identifiers are
// kept; summaries and facts stay in the live report.
type HealthSample struct {
	SampledAt     time.Time    `json:"sampled_at"`
	OverallState  OverallState `json:"overall_state"`
	FailedChecks  []string     `json:"failed_checks"`
	WarningChecks []string     `json:"warning_checks"`
}

// Summarize reduces a report to a sample at sampledAt.
func Summarize(report Report, sampledAt time.Time) HealthSample {
	sample := HealthSample{
		SampledAt: sampledAt.UTC(), OverallState: report.OverallState,
		FailedChecks: make([]string, 0), WarningChecks: make([]string, 0),
	}
	for _, check := range report.Checks {
		switch check.State {
		case CheckFailed:
			sample.FailedChecks = append(sample.FailedChecks, check.ID)
		case CheckWarning:
			sample.WarningChecks = append(sample.WarningChecks, check.ID)
		}
	}
	slices.Sort(sample.FailedChecks)
	slices.Sort(sample.WarningChecks)
	if len(sample.FailedChecks) > 64 {
		sample.FailedChecks = sample.FailedChecks[:64]
	}
	if len(sample.WarningChecks) > 64 {
		sample.WarningChecks = sample.WarningChecks[:64]
	}
	return sample
}

// RecordHealthSample runs the self-check and stores its summary for the
// sampling slot that contains scheduledAt. A slot already recorded by another
// replica is left as it is.
func (sampler *Sampler) RecordHealthSample(ctx context.Context, scheduledAt time.Time) error {
	if sampler == nil || ctx == nil || scheduledAt.IsZero() {
		return errors.New("health sampler is unavailable")
	}
	report := Run(ctx, sampler.pool, sampler.role, sampler.dependencies)
	sample := Summarize(report, scheduledAt.UTC().Truncate(HealthSampleInterval))
	if _, err := sampler.pool.Exec(ctx, `
		INSERT INTO system_health_samples (sampled_at, overall_state, failed_checks, warning_checks, recorded_by_role)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (sampled_at) DO NOTHING
	`, sample.SampledAt, string(sample.OverallState), sample.FailedChecks, sample.WarningChecks, sampler.role); err != nil {
		return fmt.Errorf("record health sample: %w", err)
	}
	return nil
}
