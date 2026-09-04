package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
)

type poolPingFunc func(context.Context) error

func (ping poolPingFunc) Ping(ctx context.Context) error { return ping(ctx) }

func TestUnavailableReportAndSupportBundleAreStructurallyRedacted(t *testing.T) {
	t.Parallel()
	report := Run(context.Background(), nil, "api", Dependencies{})
	if report.Status != "error" || report.Database != "unreachable" || report.OverallState != OverallUnhealthy {
		t.Fatalf("report = %+v", report)
	}
	if err := Validate(report); err != nil {
		t.Fatal(err)
	}
	bundle := Bundle(report, "admin_api")
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, `"by_status":null`) || strings.Contains(text, `"fresh_by_role":null`) {
		t.Fatalf("support bundle emitted null collection: %s", text)
	}
	for _, forbidden := range []string{
		"provider-secret-value", "identity-token-value", "raw-prompt-value", "attestation-evidence-value",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("support bundle contained forbidden value %q", forbidden)
		}
	}
	for _, exclusion := range []string{"provider_credentials", "raw_attestation_evidence", "request_content", "secret_values"} {
		if !strings.Contains(text, exclusion) {
			t.Errorf("support bundle omitted exclusion %q", exclusion)
		}
	}
}

func TestOverallStateDoesNotTreatSkippedAsFailure(t *testing.T) {
	t.Parallel()
	if state := overall([]Check{passedCheck("a", "A"), skippedCheck("b", "B")}); state != OverallHealthy {
		t.Fatalf("overall = %q", state)
	}
	if state := overall([]Check{warningCheck("a", "A", "R")}); state != OverallDegraded {
		t.Fatalf("overall = %q", state)
	}
}

func TestPoolFactsAggregateDistinctCompletionReserve(t *testing.T) {
	t.Parallel()

	newPool := func(maximum int32) *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig("postgres://diagnostics:secret@127.0.0.1/latchway?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		cfg.MaxConns = maximum
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	regular := newPool(24)
	completion := newPool(8)
	facts := DatabaseFacts{}
	completionUtilization, separate := collectPoolFacts(regular, completion, &facts)
	if !separate || completionUtilization != 0 || facts.PoolMaximum != 32 ||
		facts.PoolTotal != 0 || facts.PoolAcquired != 0 || facts.PoolIdle != 0 ||
		facts.PoolUtilizationPPM != 0 {
		t.Fatalf("aggregate pool facts = %+v, completion=%d separate=%t", facts, completionUtilization, separate)
	}

	singleFacts := DatabaseFacts{}
	if utilization, gotSeparate := collectPoolFacts(regular, regular, &singleFacts); gotSeparate ||
		utilization != 0 || singleFacts.PoolMaximum != 24 {
		t.Fatalf("single pool facts = %+v, completion=%d separate=%t", singleFacts, utilization, gotSeparate)
	}
}

func TestCompletionPoolCheckUsesIndependentSaturationThreshold(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		utilization int64
		want        CheckState
	}{
		{utilization: 749_999, want: CheckPassed},
		{utilization: 750_000, want: CheckWarning},
		{utilization: 900_000, want: CheckFailed},
	} {
		report := Report{}
		appendCompletionPoolCheck(&report, test.utilization, true)
		if got := checkStateByID(t, report.Checks, "quota_completion_pool_saturation"); got != test.want {
			t.Fatalf("completion utilization %d check = %q, want %q", test.utilization, got, test.want)
		}
	}
	report := Report{}
	appendCompletionPoolCheck(&report, 0, false)
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_saturation"); got != CheckFailed {
		t.Fatalf("unreachable completion pool saturation check = %q, want %q", got, CheckFailed)
	}
}

func TestCompletionPoolConnectivityProbeIsBoundedAndRedacted(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		probe  poolPingFunc
		failed bool
	}{
		{
			name:  "available",
			probe: func(context.Context) error { return nil },
		},
		{
			name:   "closed",
			probe:  func(context.Context) error { return errors.New("private database address and closed-pool detail") },
			failed: true,
		},
		{
			name: "fully acquired",
			probe: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
			failed: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := time.Now()
			err := probeCompletionPool(context.Background(), test.probe, 10*time.Millisecond)
			if test.failed != (err != nil) {
				t.Fatalf("probe error = %v, failed=%t", err, test.failed)
			}
			if time.Since(started) > time.Second {
				t.Fatal("completion-pool probe exceeded its independent bound")
			}

			report := Report{}
			appendCompletionPoolConnectivityCheck(&report, err)
			want := CheckPassed
			if test.failed {
				want = CheckFailed
			}
			if got := checkStateByID(t, report.Checks, "quota_completion_pool_connectivity"); got != want {
				t.Fatalf("connectivity check = %q, want %q", got, want)
			}
			encoded, marshalErr := json.Marshal(report.Checks)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if strings.Contains(string(encoded), "private database") || strings.Contains(string(encoded), "closed-pool detail") {
				t.Fatalf("completion-pool check disclosed dependency error: %s", encoded)
			}
		})
	}
}

func TestConfigurationCacheCheckUsesOnlyBoundedProcessFacts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	report := Report{}
	collectConfigurationCache(now, Dependencies{ConfigurationCache: func(got time.Time) configuration.ActiveSnapshotCacheStatus {
		if !got.Equal(now) {
			t.Fatalf("cache observation instant = %s", got)
		}
		return configuration.ActiveSnapshotCacheStatus{
			Available: true, Entries: 2, FreshEntries: 2, EstimatedBytes: 32 << 10,
			MaximumEntries: 1024, MaximumEstimatedBytes: 24 << 20,
			ReconciliationIntervalSeconds: 30,
		}
	}}, &report)
	if state := checkStateByID(t, report.Checks, "configuration_cache_state"); state != CheckPassed {
		t.Fatalf("cache check = %q", state)
	}
	if report.Facts.Configuration.Cache.Entries != 2 {
		t.Fatalf("cache facts = %+v", report.Facts.Configuration.Cache)
	}
}

func TestCriticalJobChecksRequireFreshDurableObservations(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(48 * time.Hour)
	last := now.Add(-time.Minute)
	report := Report{Facts: Facts{
		Replicas: ReplicaFacts{FreshWorkers: 1},
		Security: SecurityFacts{
			ActiveSigningKeys: 1, SigningKeyExpiresAt: &expiresAt,
			ConfiguredExternalJWKSProviders: 1,
		},
		Jobs: JobFacts{
			LastUsageRollupAt: &last, LastRetentionAt: &last,
			LastUsageReconciliationAt: &last, LastSigningKeyRotationAt: &last,
			LastExternalJWKSRefreshAt: &last,
		},
	}}
	appendCriticalJobChecks(now, &report)
	for _, id := range []string{
		"usage_rollup_freshness", "retention_job_freshness", "usage_reconciliation_freshness",
		"usage_settlement_backlog", "signing_key_rotation", "external_jwks_reachability",
	} {
		if state := checkStateByID(t, report.Checks, id); state != CheckPassed {
			t.Errorf("%s = %q", id, state)
		}
	}

	missing := Report{Facts: Facts{Security: SecurityFacts{
		ActiveSigningKeys: 1, SigningKeyExpiresAt: &expiresAt,
		ConfiguredExternalJWKSProviders: 1,
	}}}
	appendCriticalJobChecks(now, &missing)
	if state := checkStateByID(t, missing.Checks, "external_jwks_reachability"); state != CheckWarning {
		t.Fatalf("unobserved JWKS reachability = %q", state)
	}
	if state := checkStateByID(t, missing.Checks, "signing_key_rotation"); state != CheckWarning {
		t.Fatalf("rotation without worker = %q", state)
	}
}

func TestRuntimeCompatibilityIsExplicitlyEmbeddedNotRemote(t *testing.T) {
	t.Parallel()
	runtime := runtimeFacts("api")
	if runtime.LatestCompatibleVersion != runtime.ServerVersion || runtime.CompatibilitySource != "embedded_self" {
		t.Fatalf("runtime compatibility = %+v", runtime)
	}
}

func checkStateByID(t *testing.T, checks []Check, id string) CheckState {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check.State
		}
	}
	t.Fatalf("check %q was not emitted", id)
	return ""
}
