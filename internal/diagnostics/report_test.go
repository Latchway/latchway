package diagnostics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
)

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
