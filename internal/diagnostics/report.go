// Package diagnostics owns the redaction-safe operational report shared by
// the CLI, Admin API, and embedded console.
package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
)

const (
	ReportSchemaVersion        = 1
	defaultTimeout             = 5 * time.Second
	completionPoolProbeTimeout = 500 * time.Millisecond
)

type poolPinger interface {
	Ping(context.Context) error
}

type CheckState string

const (
	CheckPassed  CheckState = "passed"
	CheckWarning CheckState = "warning"
	CheckFailed  CheckState = "failed"
	CheckSkipped CheckState = "skipped"
)

type OverallState string

const (
	OverallHealthy   OverallState = "healthy"
	OverallDegraded  OverallState = "degraded"
	OverallUnhealthy OverallState = "unhealthy"
)

type Check struct {
	ID          string     `json:"id"`
	State       CheckState `json:"state"`
	Summary     string     `json:"summary"`
	Remediation string     `json:"remediation,omitempty"`
}

type DatabaseFacts struct {
	Reachable          bool  `json:"reachable"`
	LatencyMS          int64 `json:"latency_ms"`
	SchemaCurrent      int64 `json:"schema_current"`
	SchemaAvailable    int64 `json:"schema_available"`
	PoolMaximum        int32 `json:"pool_maximum"`
	PoolTotal          int32 `json:"pool_total"`
	PoolAcquired       int32 `json:"pool_acquired"`
	PoolIdle           int32 `json:"pool_idle"`
	PoolUtilizationPPM int64 `json:"pool_utilization_ppm"`
	SizeBytes          int64 `json:"size_bytes"`
}

type ConfigurationFacts struct {
	ActiveEnvironments         int64                                   `json:"active_environments"`
	ActiveConfigurations       int64                                   `json:"active_configurations"`
	MissingActiveConfiguration int64                                   `json:"missing_active_configuration"`
	Revisions                  int64                                   `json:"revisions"`
	DraftRevisions             int64                                   `json:"draft_revisions"`
	InvalidRevisions           int64                                   `json:"invalid_revisions"`
	HighestRevisionNumber      int64                                   `json:"highest_revision_number"`
	Cache                      configuration.ActiveSnapshotCacheStatus `json:"cache"`
}

type VerificationDependencyFacts struct {
	ConfiguredSelections       int64 `json:"configured_selections"`
	RequiredSelections         int64 `json:"required_selections"`
	ExternalNetworkSelections  int64 `json:"external_network_selections"`
	CredentialBackedSelections int64 `json:"credential_backed_selections"`
	ResolvedCredentialRecords  int64 `json:"resolved_credential_records"`
	RegisteredActiveKeys       int64 `json:"registered_active_keys"`
}

type SecurityFacts struct {
	ActiveSecretRecords             int64                       `json:"active_secret_records"`
	ActiveSigningKeys               int64                       `json:"active_signing_keys"`
	PendingSigningKeys              int64                       `json:"pending_signing_keys"`
	RetiringSigningKeys             int64                       `json:"retiring_signing_keys"`
	SigningKeyExpiresAt             *time.Time                  `json:"signing_key_expires_at,omitempty"`
	ConfiguredExternalJWKSProviders int64                       `json:"configured_external_jwks_providers"`
	IdentityProviders               int64                       `json:"identity_providers"`
	IdentityProviderErrors          int64                       `json:"identity_provider_errors"`
	StaleIdentityProviderJWKS       int64                       `json:"stale_identity_provider_jwks"`
	AppleVerification               VerificationDependencyFacts `json:"apple_verification"`
	GoogleVerification              VerificationDependencyFacts `json:"google_verification"`
}

type JobStatusCount struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

type JobFacts struct {
	ByStatus                  []JobStatusCount `json:"by_status"`
	OldestPendingAt           *time.Time       `json:"oldest_pending_at,omitempty"`
	ExpiredLocks              int64            `json:"expired_locks"`
	RecentSelfTests           int64            `json:"recent_self_tests"`
	FailedSelfTests           int64            `json:"failed_self_tests"`
	UsageSettlementBacklog    int64            `json:"usage_settlement_backlog"`
	LastUsageRollupAt         *time.Time       `json:"last_usage_rollup_at,omitempty"`
	LastRetentionAt           *time.Time       `json:"last_retention_at,omitempty"`
	LastUsageReconciliationAt *time.Time       `json:"last_usage_reconciliation_at,omitempty"`
	LastSigningKeyRotationAt  *time.Time       `json:"last_signing_key_rotation_at,omitempty"`
	LastExternalJWKSRefreshAt *time.Time       `json:"last_external_jwks_refresh_at,omitempty"`
}

type RetentionFacts struct {
	PolicyMode                    string     `json:"policy_mode"`
	AdminSessionRetentionHours    int64      `json:"admin_session_retention_hours"`
	JobHistoryRetentionHours      int64      `json:"job_history_retention_hours"`
	RuntimeInstanceRetentionHours int64      `json:"runtime_instance_retention_hours"`
	OldestRequestAt               *time.Time `json:"oldest_request_at,omitempty"`
	OldestUsageAt                 *time.Time `json:"oldest_usage_at,omitempty"`
	OldestAuditAt                 *time.Time `json:"oldest_audit_at,omitempty"`
}

type ReplicaRoleCount struct {
	Role  string `json:"role"`
	Count int64  `json:"count"`
}

type ReplicaFacts struct {
	FreshByRole       []ReplicaRoleCount `json:"fresh_by_role"`
	FreshAPIs         int64              `json:"fresh_apis"`
	FreshWorkers      int64              `json:"fresh_workers"`
	StaleReplicas     int64              `json:"stale_replicas"`
	NewestHeartbeatAt *time.Time         `json:"newest_heartbeat_at,omitempty"`
}

type RuntimeFacts struct {
	ServerVersion           string `json:"server_version"`
	LatestCompatibleVersion string `json:"latest_compatible_version"`
	CompatibilitySource     string `json:"compatibility_source"`
	Commit                  string `json:"commit"`
	BuildDate               string `json:"build_date"`
	ContractVersion         string `json:"contract_version"`
	ProtocolVersions        []int  `json:"protocol_versions"`
	Role                    string `json:"role"`
	ClockOffsetMS           int64  `json:"clock_offset_ms"`
}

type Facts struct {
	Runtime                  RuntimeFacts       `json:"runtime"`
	Database                 DatabaseFacts      `json:"database"`
	Configuration            ConfigurationFacts `json:"configuration"`
	Security                 SecurityFacts      `json:"security"`
	Jobs                     JobFacts           `json:"jobs"`
	Replicas                 ReplicaFacts       `json:"replicas"`
	Retention                RetentionFacts     `json:"retention"`
	ExpiredQuotaReservations int64              `json:"expired_quota_reservations"`
}

// Report retains the four original doctor keys for deployment-evidence
// compatibility while adding the canonical structured contract.
type Report struct {
	Status        string       `json:"status"`
	Database      string       `json:"database"`
	SchemaVersion int64        `json:"schema_version"`
	Role          string       `json:"role"`
	Schema        int          `json:"report_schema"`
	GeneratedAt   time.Time    `json:"generated_at"`
	OverallState  OverallState `json:"overall_state"`
	Checks        []Check      `json:"checks"`
	Facts         Facts        `json:"facts"`
}

type RedactionContract struct {
	Mode     string   `json:"mode"`
	Excluded []string `json:"excluded"`
}

type SupportBundle struct {
	BundleSchema int               `json:"bundle_schema"`
	GeneratedAt  time.Time         `json:"generated_at"`
	Source       string            `json:"source"`
	Report       Report            `json:"report"`
	Redaction    RedactionContract `json:"redaction"`
}

type Dependencies struct {
	MasterKey          func(context.Context) error
	ConfigurationCache func(time.Time) configuration.ActiveSnapshotCacheStatus
	// CompletionPool is the separately reserved quota-lifecycle pool. When it
	// is present, the existing database pool facts remain aggregate totals so
	// operators cannot accidentally treat DB_MAX_CONNECTIONS as a per-pool
	// allowance. Separate checks surface completion-pool connectivity and
	// saturation.
	CompletionPool *pgxpool.Pool
	Now            func() time.Time
}

// Run executes bounded, body-free checks. Database/provider errors are
// normalized into fixed summaries and never copied into the report.
func Run(parent context.Context, pool *pgxpool.Pool, role string, dependencies Dependencies) Report {
	now := time.Now
	if dependencies.Now != nil {
		now = dependencies.Now
	}
	generatedAt := now().UTC()
	report := Report{
		Status: "error", Database: "unreachable", Role: role,
		Schema: ReportSchemaVersion, GeneratedAt: generatedAt,
		OverallState: OverallUnhealthy,
		Facts: Facts{
			Runtime: runtimeFacts(role), Retention: retentionPolicyFacts(),
			Jobs:     JobFacts{ByStatus: make([]JobStatusCount, 0)},
			Replicas: ReplicaFacts{FreshByRole: make([]ReplicaRoleCount, 0)},
		},
	}
	if pool == nil || parent == nil {
		report.Checks = []Check{failedCheck("database_connectivity", "PostgreSQL is unavailable.", "Verify the configured database URL and network path.")}
		return report
	}
	ctx, cancel := context.WithTimeout(parent, defaultTimeout)
	defer cancel()

	pingStarted := time.Now()
	if err := pool.Ping(ctx); err != nil {
		report.Checks = []Check{failedCheck("database_connectivity", "PostgreSQL is unavailable.", "Verify the configured database URL and network path.")}
		return report
	}
	report.Database = "reachable"
	report.Facts.Database.Reachable = true
	report.Facts.Database.LatencyMS = maxInt64(0, time.Since(pingStarted).Milliseconds())
	report.Checks = append(report.Checks, passedCheck("database_connectivity", "PostgreSQL accepted a bounded probe."))
	separateCompletionPool := dependencies.CompletionPool != nil && dependencies.CompletionPool != pool
	completionPoolReachable := false
	if separateCompletionPool {
		completionProbeErr := probeCompletionPool(ctx, dependencies.CompletionPool, completionPoolProbeTimeout)
		appendCompletionPoolConnectivityCheck(
			&report,
			completionProbeErr,
		)
		completionPoolReachable = completionProbeErr == nil
	}
	completionUtilization, _ := collectPoolFacts(
		pool, dependencies.CompletionPool, &report.Facts.Database,
	)

	current, available, migrationErr := database.NewMigrator(pool).Status(ctx)
	report.SchemaVersion = current
	report.Facts.Database.SchemaCurrent = current
	report.Facts.Database.SchemaAvailable = available
	if migrationErr != nil || current != available {
		report.Checks = append(report.Checks, failedCheck("migration_status", "The database schema is not compatible with this binary.", "Run latchway migrate status, review the upgrade guide, then apply the matching forward migrations."))
	} else {
		report.Status = "ok"
		report.Checks = append(report.Checks, passedCheck("migration_status", "The database schema matches this binary."))
	}

	if err := collectDatabaseClock(ctx, pool, generatedAt, &report); err != nil {
		report.Checks = append(report.Checks, warningCheck("clock_skew", "Database clock comparison is unavailable.", "Verify database and host time synchronization."))
	}
	if err := collectDatabaseSize(ctx, pool, &report); err != nil {
		report.Checks = append(report.Checks, warningCheck("database_storage_visibility", "Database storage size is unavailable.", "Verify PostgreSQL monitoring and retention outside Latchway."))
	} else {
		report.Checks = append(report.Checks, passedCheck("database_storage_visibility", "PostgreSQL reported its current database size; capacity remains an infrastructure responsibility."))
	}
	collectConfiguration(ctx, pool, &report)
	collectConfigurationCache(generatedAt, dependencies, &report)
	collectSecurity(ctx, pool, generatedAt, dependencies, &report)
	collectReplicas(ctx, pool, generatedAt, &report)
	collectJobs(ctx, pool, generatedAt, &report)
	collectRetention(ctx, pool, &report)
	collectQuota(ctx, pool, &report)
	appendCompatibilityCheck(&report)
	appendPoolCheck(&report)
	if separateCompletionPool {
		appendCompletionPoolCheck(&report, completionUtilization, completionPoolReachable)
	}
	report.OverallState = overall(report.Checks)
	return report
}

// collectPoolFacts preserves the public v1 diagnostic shape while treating
// DB_MAX_CONNECTIONS as the aggregate per-process budget. The completion pool
// is counted only when it is a distinct pool, which keeps single-pool CLI and
// test callers source-compatible.
func collectPoolFacts(primary, completion *pgxpool.Pool, facts *DatabaseFacts) (int64, bool) {
	if primary == nil || facts == nil {
		return 0, false
	}
	pools := []*pgxpool.Pool{primary}
	separateCompletionPool := completion != nil && completion != primary
	if separateCompletionPool {
		pools = append(pools, completion)
	}
	completionUtilization := int64(0)
	for index, candidate := range pools {
		stats := candidate.Stat()
		facts.PoolMaximum += stats.MaxConns()
		facts.PoolTotal += stats.TotalConns()
		facts.PoolAcquired += stats.AcquiredConns()
		facts.PoolIdle += stats.IdleConns()
		if index == 1 && stats.MaxConns() > 0 {
			completionUtilization = int64(stats.AcquiredConns()) * 1_000_000 / int64(stats.MaxConns())
		}
	}
	if facts.PoolMaximum > 0 {
		facts.PoolUtilizationPPM = int64(facts.PoolAcquired) * 1_000_000 / int64(facts.PoolMaximum)
	}
	return completionUtilization, separateCompletionPool
}

func Bundle(report Report, source string) SupportBundle {
	if source != "admin_api" && source != "local_cli" {
		source = "unknown"
	}
	return SupportBundle{
		BundleSchema: 1,
		GeneratedAt:  report.GeneratedAt,
		Source:       source,
		Report:       report,
		Redaction: RedactionContract{
			Mode: "structural_allowlist",
			Excluded: []string{
				"access_tokens", "admin_sessions", "api_tokens", "authorization_headers",
				"cookies", "dpop_proofs", "identity_tokens", "master_key", "provider_credentials",
				"raw_attestation_evidence", "request_content", "response_content", "secret_values",
			},
		},
	}
}

func runtimeFacts(role string) RuntimeFacts {
	build := buildinfo.Current()
	return RuntimeFacts{
		ServerVersion: build.Version, LatestCompatibleVersion: build.Version,
		CompatibilitySource: "embedded_self", Commit: build.Commit, BuildDate: build.BuildDate,
		ContractVersion: build.ContractVersion, ProtocolVersions: buildinfo.SupportedProtocolVersions(), Role: role,
	}
}

func collectDatabaseClock(ctx context.Context, pool *pgxpool.Pool, now time.Time, report *Report) error {
	var databaseNow time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return err
	}
	offset := databaseNow.UTC().Sub(now).Milliseconds()
	report.Facts.Runtime.ClockOffsetMS = offset
	abs := offset
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs > 30_000:
		report.Checks = append(report.Checks, failedCheck("clock_skew", "Database and process clocks differ by more than 30 seconds.", "Restore NTP synchronization before issuing or validating sessions."))
	case abs > 5_000:
		report.Checks = append(report.Checks, warningCheck("clock_skew", "Database and process clocks differ by more than 5 seconds.", "Inspect host and database time synchronization."))
	default:
		report.Checks = append(report.Checks, passedCheck("clock_skew", "Database and process clocks are within the allowed diagnostic window."))
	}
	return nil
}

func collectDatabaseSize(ctx context.Context, pool *pgxpool.Pool, report *Report) error {
	return pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&report.Facts.Database.SizeBytes)
}

func collectConfiguration(ctx context.Context, pool *pgxpool.Pool, report *Report) {
	err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE environment.status = 'active'),
			count(active.environment_id) FILTER (WHERE environment.status = 'active'),
			count(*) FILTER (WHERE environment.status = 'active' AND active.environment_id IS NULL),
			(SELECT count(*) FROM config_revisions),
			(SELECT count(*) FROM config_revisions WHERE status = 'draft'),
			(SELECT count(*) FROM config_revisions WHERE status = 'invalid'),
			(SELECT COALESCE(max(revision_number), 0) FROM config_revisions)
		FROM environments AS environment
		LEFT JOIN active_config_revisions AS active
		  ON active.organization_id = environment.organization_id
		 AND active.application_id = environment.application_id
		 AND active.environment_id = environment.environment_id
	`).Scan(
		&report.Facts.Configuration.ActiveEnvironments,
		&report.Facts.Configuration.ActiveConfigurations,
		&report.Facts.Configuration.MissingActiveConfiguration,
		&report.Facts.Configuration.Revisions,
		&report.Facts.Configuration.DraftRevisions,
		&report.Facts.Configuration.InvalidRevisions,
		&report.Facts.Configuration.HighestRevisionNumber,
	)
	if err != nil {
		report.Checks = append(report.Checks, failedCheck("active_configuration", "Configuration state could not be inspected.", "Check the migration state and PostgreSQL permissions."))
		return
	}
	if report.Facts.Configuration.MissingActiveConfiguration > 0 {
		report.Checks = append(report.Checks, failedCheck("active_configuration", "At least one active environment has no active configuration.", "Validate and activate a configuration revision for every active environment."))
	} else if report.Facts.Configuration.ActiveEnvironments == 0 {
		report.Checks = append(report.Checks, warningCheck("active_configuration", "No active environment exists yet.", "Complete the resumable first-run setup before sending client traffic."))
	} else {
		report.Checks = append(report.Checks, passedCheck("active_configuration", "Every active environment has an active configuration revision."))
	}
}

func collectConfigurationCache(now time.Time, dependencies Dependencies, report *Report) {
	if dependencies.ConfigurationCache == nil {
		report.Checks = append(report.Checks, skippedCheck(
			"configuration_cache_state",
			"Process-local configuration-cache inspection is unavailable on this diagnostic surface.",
		))
		return
	}
	status := dependencies.ConfigurationCache(now)
	report.Facts.Configuration.Cache = status
	if !status.Available || status.MaximumEntries <= 0 || status.MaximumEstimatedBytes <= 0 ||
		status.ReconciliationIntervalSeconds <= 0 || status.Entries < 0 || status.FreshEntries < 0 ||
		status.StaleEntries < 0 || status.RefreshesInFlight < 0 || status.EstimatedBytes < 0 ||
		status.Entries != status.FreshEntries+status.StaleEntries ||
		status.Entries > status.MaximumEntries || status.EstimatedBytes > status.MaximumEstimatedBytes {
		report.Checks = append(report.Checks, failedCheck(
			"configuration_cache_state",
			"The process-local configuration cache returned an invalid bounded state.",
			"Restart the API replica and inspect configuration-cache limits before serving traffic.",
		))
		return
	}
	if status.StaleEntries > 0 {
		report.Checks = append(report.Checks, warningCheck(
			"configuration_cache_state",
			"The process-local configuration cache contains entries beyond its reconciliation interval.",
			"Verify PostgreSQL reachability and configuration refresh latency on this API replica.",
		))
		return
	}
	report.Checks = append(report.Checks, passedCheck(
		"configuration_cache_state",
		"The process-local configuration cache is bounded and contains no stale entry.",
	))
}

func collectSecurity(ctx context.Context, pool *pgxpool.Pool, now time.Time, dependencies Dependencies, report *Report) {
	var expiresAt *time.Time
	err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM secret_records WHERE rotated_at IS NULL AND destroyed_at IS NULL),
			(SELECT count(*) FROM gateway_signing_keys WHERE status = 'active' AND not_before <= clock_timestamp() AND not_after > clock_timestamp()),
			(SELECT count(*) FROM gateway_signing_keys WHERE status = 'pending'),
			(SELECT count(*) FROM gateway_signing_keys WHERE status = 'retiring' AND not_after > clock_timestamp()),
			(SELECT min(not_after) FROM gateway_signing_keys WHERE status = 'active' AND not_after > clock_timestamp()),
			(SELECT count(*) FROM identity_provider_states),
			(SELECT count(*) FROM identity_provider_states WHERE last_error_code IS NOT NULL),
			(SELECT count(*) FROM identity_provider_states
			 WHERE provider_type IN ('oidc', 'firebase', 'supabase', 'clerk')
			   AND (jwks_refreshed_at IS NULL OR jwks_refreshed_at < clock_timestamp() - interval '24 hours')),
			(SELECT count(*) FROM attestation_keys WHERE provider = 'app_attest' AND status = 'active')
	`).Scan(
		&report.Facts.Security.ActiveSecretRecords,
		&report.Facts.Security.ActiveSigningKeys,
		&report.Facts.Security.PendingSigningKeys,
		&report.Facts.Security.RetiringSigningKeys,
		&expiresAt,
		&report.Facts.Security.IdentityProviders,
		&report.Facts.Security.IdentityProviderErrors,
		&report.Facts.Security.StaleIdentityProviderJWKS,
		&report.Facts.Security.AppleVerification.RegisteredActiveKeys,
	)
	if err != nil {
		report.Checks = append(report.Checks, failedCheck("signing_key_availability", "Signing-key state could not be inspected.", "Check PostgreSQL permissions and the signing-key migration."))
	} else {
		report.Facts.Security.SigningKeyExpiresAt = expiresAt
		if report.Facts.Security.ActiveSigningKeys == 0 {
			report.Checks = append(report.Checks, failedCheck("signing_key_availability", "No currently valid active session-signing key exists.", "Run the signing-key rotation worker before serving client sessions."))
		} else {
			report.Checks = append(report.Checks, passedCheck("signing_key_availability", "A currently valid active session-signing key exists."))
		}
	}
	collectVerificationDependencies(ctx, pool, report)
	if dependencies.MasterKey == nil {
		report.Checks = append(report.Checks, skippedCheck("master_key_availability", "Runtime master-key verification was not supplied to this diagnostic surface."))
	} else if err := dependencies.MasterKey(ctx); err != nil {
		report.Checks = append(report.Checks, failedCheck("master_key_availability", "The runtime master-key identifier does not match the persisted secret inventory.", "Restore the exact configured master key before rotating or using provider credentials."))
	} else {
		report.Checks = append(report.Checks, passedCheck("master_key_availability", "The runtime master-key identifier matches the persisted secret inventory."))
	}
}

func collectVerificationDependencies(ctx context.Context, pool *pgxpool.Pool, report *Report) {
	err := pool.QueryRow(ctx, `
		WITH active_documents AS (
			SELECT active.environment_id, revision.compiled_document
			FROM active_config_revisions AS active
			JOIN config_revisions AS revision
			  ON revision.organization_id = active.organization_id
			 AND revision.application_id = active.application_id
			 AND revision.environment_id = active.environment_id
			 AND revision.config_revision_id = active.config_revision_id
			WHERE revision.compiled_document IS NOT NULL
		), selections AS (
			SELECT document.environment_id, platform.value AS selection
			FROM active_documents AS document
			CROSS JOIN LATERAL jsonb_array_elements(
				COALESCE(document.compiled_document #> '{spec,attestationPolicies}', '[]'::jsonb)
			) AS policy(value)
			CROSS JOIN LATERAL jsonb_each(COALESCE(policy.value -> 'platforms', '{}'::jsonb)) AS platform(key, value)
		), providers AS (
			SELECT provider.value AS provider
			FROM active_documents AS document
			CROSS JOIN LATERAL jsonb_array_elements(
				COALESCE(document.compiled_document #> '{spec,identityProviders}', '[]'::jsonb)
			) AS provider(value)
		)
		SELECT
			(SELECT count(*) FROM providers
			 WHERE provider ->> 'type' IN ('firebase', 'supabase', 'clerk')
			    OR provider ? 'jwksUrl'),
			(SELECT count(*) FROM selections WHERE selection ->> 'provider' = 'app_attest'),
			(SELECT count(*) FROM selections WHERE selection ->> 'provider' = 'app_attest' AND selection ->> 'mode' = 'required'),
			(SELECT count(*) FROM selections WHERE selection ->> 'provider' IN ('play_integrity', 'firebase_app_check')),
			(SELECT count(*) FROM selections WHERE selection ->> 'provider' IN ('play_integrity', 'firebase_app_check') AND selection ->> 'mode' = 'required'),
			(SELECT count(*) FROM selections WHERE selection ->> 'provider' IN ('play_integrity', 'firebase_app_check')),
			(SELECT count(*) FROM selections
			 WHERE selection ->> 'provider' = 'play_integrity'
			   AND selection #>> '{playIntegrity,credentialSource}' = 'service_account'),
			(SELECT count(*) FROM selections AS selection
			 WHERE selection.selection ->> 'provider' = 'play_integrity'
			   AND selection.selection #>> '{playIntegrity,credentialSource}' = 'service_account'
			   AND EXISTS (
				 SELECT 1 FROM secret_records AS secret
				 WHERE secret.environment_id = selection.environment_id
				   AND secret.name = regexp_replace(selection.selection ->> 'secretRef', '^secret/', '')
				   AND secret.rotated_at IS NULL AND secret.destroyed_at IS NULL
			   ))
	`).Scan(
		&report.Facts.Security.ConfiguredExternalJWKSProviders,
		&report.Facts.Security.AppleVerification.ConfiguredSelections,
		&report.Facts.Security.AppleVerification.RequiredSelections,
		&report.Facts.Security.GoogleVerification.ConfiguredSelections,
		&report.Facts.Security.GoogleVerification.RequiredSelections,
		&report.Facts.Security.GoogleVerification.ExternalNetworkSelections,
		&report.Facts.Security.GoogleVerification.CredentialBackedSelections,
		&report.Facts.Security.GoogleVerification.ResolvedCredentialRecords,
	)
	if err != nil {
		report.Checks = append(report.Checks,
			warningCheck("apple_verification_dependencies", "Apple verification configuration dependencies could not be inspected.", "Check active configuration documents and App Attest persistence migrations."),
			warningCheck("google_verification_dependencies", "Google verification configuration dependencies could not be inspected.", "Check active configuration documents and server-owned credential references."),
		)
		return
	}
	apple := report.Facts.Security.AppleVerification
	if apple.ConfiguredSelections == 0 {
		report.Checks = append(report.Checks, skippedCheck("apple_verification_dependencies", "No active App Attest selection is configured."))
	} else if apple.RequiredSelections > apple.ConfiguredSelections {
		report.Checks = append(report.Checks, failedCheck("apple_verification_dependencies", "The active App Attest dependency inventory is inconsistent.", "Validate and reactivate the affected configuration revision."))
	} else {
		report.Checks = append(report.Checks, passedCheck("apple_verification_dependencies", "App Attest selections are compiled and the PostgreSQL-backed key store is available; registered-key counts contain no key material."))
	}
	google := report.Facts.Security.GoogleVerification
	if google.ConfiguredSelections == 0 {
		report.Checks = append(report.Checks, skippedCheck("google_verification_dependencies", "No active Play Integrity or Firebase App Check selection is configured."))
	} else if google.ResolvedCredentialRecords != google.CredentialBackedSelections {
		report.Checks = append(report.Checks, failedCheck("google_verification_dependencies", "At least one credential-backed Google verifier has no active server-owned credential record.", "Restore the referenced credential and reactivate the configuration before accepting Google-attested clients."))
	} else {
		report.Checks = append(report.Checks, passedCheck("google_verification_dependencies", "Play Integrity and Firebase App Check selections are compiled and every credential-backed verifier resolves to an active server-owned record."))
	}
}

func collectReplicas(ctx context.Context, pool *pgxpool.Pool, _ time.Time, report *Report) {
	rows, err := pool.Query(ctx, `
		SELECT role, count(*)
		FROM runtime_instances
		WHERE heartbeat_at >= clock_timestamp() - interval '90 seconds'
		GROUP BY role
		ORDER BY role
	`)
	if err != nil {
		report.Checks = append(report.Checks, warningCheck("worker_heartbeat", "Replica heartbeats could not be inspected.", "Check runtime-instance migrations and PostgreSQL permissions."))
		return
	}
	defer rows.Close()
	for rows.Next() {
		var item ReplicaRoleCount
		if err := rows.Scan(&item.Role, &item.Count); err != nil {
			report.Checks = append(report.Checks, warningCheck("worker_heartbeat", "Replica heartbeat results were invalid.", "Inspect runtime instance persistence."))
			return
		}
		report.Facts.Replicas.FreshByRole = append(report.Facts.Replicas.FreshByRole, item)
		if item.Role == "api" || item.Role == "all" {
			report.Facts.Replicas.FreshAPIs += item.Count
		}
		if item.Role == "worker" || item.Role == "all" {
			report.Facts.Replicas.FreshWorkers += item.Count
		}
	}
	if rows.Err() != nil {
		report.Checks = append(report.Checks, warningCheck("worker_heartbeat", "Replica heartbeat iteration failed.", "Inspect PostgreSQL connectivity."))
		return
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE heartbeat_at < clock_timestamp() - interval '90 seconds'), max(heartbeat_at) FROM runtime_instances`).Scan(
		&report.Facts.Replicas.StaleReplicas, &report.Facts.Replicas.NewestHeartbeatAt,
	); err != nil {
		report.Checks = append(report.Checks, warningCheck("worker_heartbeat", "Replica heartbeat summary was unavailable.", "Inspect runtime instance persistence and PostgreSQL connectivity."))
		return
	}
	if report.Facts.Replicas.FreshWorkers == 0 {
		report.Checks = append(report.Checks, warningCheck("worker_heartbeat", "No worker heartbeat was observed in the last 90 seconds.", "Start an all or worker role before relying on cleanup, rotation, refresh, and rollup jobs."))
	} else {
		report.Checks = append(report.Checks, passedCheck("worker_heartbeat", "A worker heartbeat was observed in the last 90 seconds."))
	}
	if report.Role == "worker" {
		report.Checks = append(report.Checks, skippedCheck("replica_coverage", "A worker-only diagnostic cannot prove API replica coverage."))
	} else if report.Facts.Replicas.FreshWorkers == 0 {
		report.Checks = append(report.Checks, warningCheck("replica_coverage", "The current API surface has no fresh durable worker coverage.", "Start a worker or all-role replica and verify its heartbeat before relying on operational jobs."))
	} else if report.Role == "all" && report.Facts.Replicas.FreshAPIs == 0 {
		report.Checks = append(report.Checks, warningCheck("replica_coverage", "The all-role process has no fresh durable all-role heartbeat.", "Inspect the local worker runtime and runtime-instance persistence."))
	} else if report.Facts.Replicas.StaleReplicas > 0 {
		report.Checks = append(report.Checks, warningCheck("replica_coverage", "Fresh API and worker coverage exists, but stale replica records remain.", "Verify retired replicas and allow the bounded retention job to prune stale runtime records."))
	} else {
		report.Checks = append(report.Checks, passedCheck("replica_coverage", "The diagnostic API surface and durable worker heartbeats provide the required role coverage."))
	}
}

func collectJobs(ctx context.Context, pool *pgxpool.Pool, now time.Time, report *Report) {
	rows, err := pool.Query(ctx, `SELECT status, count(*) FROM jobs GROUP BY status ORDER BY status`)
	if err != nil {
		report.Checks = append(report.Checks, warningCheck("job_backlog", "Background-job state could not be inspected.", "Check the job migration and PostgreSQL permissions."))
		return
	}
	for rows.Next() {
		var item JobStatusCount
		if err := rows.Scan(&item.Status, &item.Count); err != nil {
			rows.Close()
			report.Checks = append(report.Checks, warningCheck("job_backlog", "Background-job results were invalid.", "Inspect the durable job queue."))
			return
		}
		report.Facts.Jobs.ByStatus = append(report.Facts.Jobs.ByStatus, item)
	}
	rows.Close()
	if rows.Err() != nil {
		report.Checks = append(report.Checks, warningCheck("job_backlog", "Background-job iteration failed.", "Inspect PostgreSQL connectivity."))
		return
	}
	err = pool.QueryRow(ctx, `
		SELECT
			min(created_at) FILTER (WHERE status = 'pending'),
			count(*) FILTER (WHERE status = 'running' AND locked_at < clock_timestamp() - interval '5 minutes'),
			count(*) FILTER (WHERE job_type = 'run_scheduled_self_test' AND updated_at >= clock_timestamp() - interval '24 hours'),
			count(*) FILTER (WHERE job_type = 'run_scheduled_self_test' AND status IN ('failed', 'dead') AND updated_at >= clock_timestamp() - interval '24 hours'),
			(SELECT count(*) FROM quota_reservations AS reservation
			 WHERE reservation.status = 'pending' AND reservation.expires_at <= clock_timestamp()
			   AND EXISTS (
				 SELECT 1 FROM upstream_attempts AS attempt
				 WHERE attempt.environment_id = reservation.environment_id
				   AND attempt.logical_request_id = reservation.logical_request_id
			   )),
			max(completed_at) FILTER (WHERE job_type = 'aggregate_hourly_usage' AND status = 'succeeded'),
			max(completed_at) FILTER (WHERE job_type = 'enforce_retention' AND status = 'succeeded'),
			max(completed_at) FILTER (WHERE job_type = 'reconcile_pending_usage' AND status = 'succeeded'),
			max(completed_at) FILTER (WHERE job_type = 'rotate_signing_keys' AND status = 'succeeded'),
			max(completed_at) FILTER (WHERE job_type = 'refresh_jwks' AND status = 'succeeded')
		FROM jobs
	`).Scan(
		&report.Facts.Jobs.OldestPendingAt,
		&report.Facts.Jobs.ExpiredLocks,
		&report.Facts.Jobs.RecentSelfTests,
		&report.Facts.Jobs.FailedSelfTests,
		&report.Facts.Jobs.UsageSettlementBacklog,
		&report.Facts.Jobs.LastUsageRollupAt,
		&report.Facts.Jobs.LastRetentionAt,
		&report.Facts.Jobs.LastUsageReconciliationAt,
		&report.Facts.Jobs.LastSigningKeyRotationAt,
		&report.Facts.Jobs.LastExternalJWKSRefreshAt,
	)
	if err != nil {
		report.Checks = append(report.Checks, warningCheck("job_backlog", "Background-job age could not be inspected.", "Inspect the durable job queue."))
		return
	}
	dead := countJobStatus(report.Facts.Jobs.ByStatus, "dead")
	failed := countJobStatus(report.Facts.Jobs.ByStatus, "failed")
	if dead > 0 || report.Facts.Jobs.ExpiredLocks > 0 {
		report.Checks = append(report.Checks, failedCheck("job_backlog", "The queue contains dead jobs or expired running locks.", "Inspect job error codes, restore worker heartbeats, and retry only idempotent jobs."))
	} else if failed > 0 || (report.Facts.Jobs.OldestPendingAt != nil && now.Sub(*report.Facts.Jobs.OldestPendingAt) > 5*time.Minute) {
		report.Checks = append(report.Checks, warningCheck("job_backlog", "The queue contains failed or delayed work.", "Inspect bounded job error codes and worker capacity."))
	} else {
		report.Checks = append(report.Checks, passedCheck("job_backlog", "No dead, expired-lock, or delayed job backlog was detected."))
	}
	if report.Facts.Jobs.RecentSelfTests == 0 {
		report.Checks = append(report.Checks, skippedCheck("ai_connection_health", "No scheduled AI connection self-test ran in the last 24 hours."))
	} else if report.Facts.Jobs.FailedSelfTests > 0 {
		report.Checks = append(report.Checks, warningCheck("ai_connection_health", "At least one recent scheduled AI connection self-test failed.", "Open the redacted self-test result and verify the configured connection."))
	} else {
		report.Checks = append(report.Checks, passedCheck("ai_connection_health", "Recent scheduled AI connection self-tests have no durable queue failure."))
	}
	appendCriticalJobChecks(now, report)
}

func appendCriticalJobChecks(now time.Time, report *Report) {
	if report.Facts.Replicas.FreshWorkers == 0 {
		report.Checks = append(report.Checks,
			skippedCheck("usage_rollup_freshness", "Usage-rollup freshness requires a fresh worker heartbeat."),
			skippedCheck("retention_job_freshness", "Retention-job freshness requires a fresh worker heartbeat."),
			skippedCheck("usage_reconciliation_freshness", "Usage-reconciliation freshness requires a fresh worker heartbeat."),
		)
	} else {
		report.Checks = append(report.Checks,
			freshnessCheck("usage_rollup_freshness", "hourly usage rollup", report.Facts.Jobs.LastUsageRollupAt, now, 2*time.Hour),
			freshnessCheck("retention_job_freshness", "operational retention", report.Facts.Jobs.LastRetentionAt, now, 2*time.Hour),
			freshnessCheck("usage_reconciliation_freshness", "usage reconciliation", report.Facts.Jobs.LastUsageReconciliationAt, now, 5*time.Minute),
		)
	}
	if report.Facts.Jobs.UsageSettlementBacklog > 0 {
		report.Checks = append(report.Checks, warningCheck(
			"usage_settlement_backlog",
			"Expired dispatched reservations are awaiting conservative usage settlement.",
			"Verify the reconciliation worker, then inspect only redaction-safe request and quota metadata.",
		))
	} else {
		report.Checks = append(report.Checks, passedCheck("usage_settlement_backlog", "No expired dispatched reservation is awaiting usage settlement."))
	}
	appendSigningRotationCheck(now, report)
	appendExternalJWKSCheck(now, report)
}

func freshnessCheck(id, label string, last *time.Time, now time.Time, maximumAge time.Duration) Check {
	if last == nil {
		return warningCheck(id, "No successful "+label+" job is retained.", "Verify the worker heartbeat and durable job scheduler.")
	}
	age := now.Sub(last.UTC())
	if age < 0 || age > maximumAge {
		return warningCheck(id, "The latest successful "+label+" job is outside its expected freshness window.", "Inspect the durable job queue and worker capacity.")
	}
	return passedCheck(id, "The latest successful "+label+" job is within its expected freshness window.")
}

func appendSigningRotationCheck(now time.Time, report *Report) {
	expiresAt := report.Facts.Security.SigningKeyExpiresAt
	last := report.Facts.Jobs.LastSigningKeyRotationAt
	if report.Facts.Security.ActiveSigningKeys == 0 || expiresAt == nil {
		report.Checks = append(report.Checks, failedCheck("signing_key_rotation", "Signing-key rotation has no currently valid active key to maintain.", "Restore master-key access and run the rotation worker."))
		return
	}
	if expiresAt.Sub(now) < 24*time.Hour {
		report.Checks = append(report.Checks, warningCheck("signing_key_rotation", "The active signing key expires within 24 hours.", "Verify a fresh rotation job and confirm that a replacement active key is published."))
		return
	}
	if report.Facts.Replicas.FreshWorkers == 0 {
		report.Checks = append(report.Checks, warningCheck("signing_key_rotation", "The active signing key is valid, but no fresh worker can maintain rotation.", "Start a worker or all-role replica."))
		return
	}
	if last == nil || now.Sub(last.UTC()) < 0 || now.Sub(last.UTC()) > 5*time.Minute {
		report.Checks = append(report.Checks, warningCheck("signing_key_rotation", "The active signing key is valid, but rotation-job freshness is outside the expected window.", "Inspect the durable rotate_signing_keys job and worker capacity."))
		return
	}
	report.Checks = append(report.Checks, passedCheck("signing_key_rotation", "A valid active signing key and a fresh successful rotation job are present."))
}

func appendExternalJWKSCheck(now time.Time, report *Report) {
	configured := report.Facts.Security.ConfiguredExternalJWKSProviders
	if configured == 0 {
		report.Checks = append(report.Checks, skippedCheck("external_jwks_reachability", "No active identity provider requires external JWKS refresh."))
		return
	}
	if report.Facts.Security.IdentityProviderErrors > 0 || report.Facts.Security.StaleIdentityProviderJWKS > 0 {
		report.Checks = append(report.Checks, warningCheck("external_jwks_reachability", "The last-known external JWKS refresh state is stale or reports a bounded error.", "Verify provider DNS/TLS reachability and run the JWKS refresh worker."))
		return
	}
	last := report.Facts.Jobs.LastExternalJWKSRefreshAt
	if last == nil || now.Sub(last.UTC()) < 0 || now.Sub(last.UTC()) > 15*time.Minute {
		report.Checks = append(report.Checks, warningCheck("external_jwks_reachability", "External JWKS reachability has no recent successful durable refresh observation.", "Run the JWKS refresh worker and verify provider reachability."))
		return
	}
	report.Checks = append(report.Checks, passedCheck("external_jwks_reachability", "A recent successful durable JWKS refresh provides last-known external reachability evidence."))
}

func collectQuota(ctx context.Context, pool *pgxpool.Pool, report *Report) {
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM quota_reservations WHERE status = 'pending' AND expires_at <= clock_timestamp()`).Scan(&report.Facts.ExpiredQuotaReservations); err != nil {
		report.Checks = append(report.Checks, warningCheck("expired_quota_reservations", "Expired quota reservations could not be inspected.", "Check the quota migration and cleanup worker."))
	} else if report.Facts.ExpiredQuotaReservations > 0 {
		report.Checks = append(report.Checks, warningCheck("expired_quota_reservations", "Expired quota reservations are awaiting reclamation.", "Verify the reservation-release job and worker heartbeat."))
	} else {
		report.Checks = append(report.Checks, passedCheck("expired_quota_reservations", "No expired pending quota reservation was detected."))
	}
}

func collectRetention(ctx context.Context, pool *pgxpool.Pool, report *Report) {
	report.Facts.Retention = retentionPolicyFacts()
	err := pool.QueryRow(ctx, `
		SELECT
			(SELECT min(requested_at) FROM logical_requests),
			(SELECT min(recorded_at) FROM usage_records),
			(SELECT min(occurred_at) FROM audit_events)
	`).Scan(
		&report.Facts.Retention.OldestRequestAt,
		&report.Facts.Retention.OldestUsageAt,
		&report.Facts.Retention.OldestAuditAt,
	)
	if err != nil {
		report.Checks = append(report.Checks, warningCheck(
			"storage_retention",
			"Retention horizons and oldest retained tenant records could not be inspected.",
			"Check PostgreSQL permissions and the retention worker migration.",
		))
		return
	}
	last := report.Facts.Jobs.LastRetentionAt
	if report.Facts.Replicas.FreshWorkers == 0 {
		report.Checks = append(report.Checks, warningCheck(
			"storage_retention",
			"Retention policy is explicit, but no fresh worker can enforce fixed operational horizons.",
			"Start a worker or all-role replica; tenant request, usage, and audit retention remains operator-owned.",
		))
	} else if last == nil || report.GeneratedAt.Sub(last.UTC()) < 0 || report.GeneratedAt.Sub(last.UTC()) > 2*time.Hour {
		report.Checks = append(report.Checks, warningCheck(
			"storage_retention",
			"Retention policy is explicit, but no recent successful operational-retention job is retained.",
			"Inspect the durable retention job; configure tenant request, usage, and audit retention according to deployment policy.",
		))
	} else {
		report.Checks = append(report.Checks, passedCheck(
			"storage_retention",
			"Fixed operational retention is fresh; oldest tenant request, usage, and audit timestamps are reported without content and remain operator-policy owned.",
		))
	}
}

func retentionPolicyFacts() RetentionFacts {
	return RetentionFacts{
		PolicyMode:                    "fixed_operational_operator_tenant_data",
		AdminSessionRetentionHours:    7 * 24,
		JobHistoryRetentionHours:      30 * 24,
		RuntimeInstanceRetentionHours: 24,
	}
}

func appendCompatibilityCheck(report *Report) {
	if report.Facts.Runtime.ServerVersion == "" || report.Facts.Runtime.LatestCompatibleVersion == "" ||
		report.Facts.Runtime.CompatibilitySource != "embedded_self" ||
		report.Facts.Runtime.ContractVersion == "" || len(report.Facts.Runtime.ProtocolVersions) == 0 {
		report.Checks = append(report.Checks, failedCheck("sdk_compatibility", "Protocol compatibility metadata is unavailable.", "Use a complete release build with embedded contracts."))
		return
	}
	report.Checks = append(report.Checks, passedCheck("sdk_compatibility", fmt.Sprintf(
		"Contract %s advertises %d supported protocol versions; %s is the latest compatible version embedded in this binary, not a remote update claim.",
		report.Facts.Runtime.ContractVersion,
		len(report.Facts.Runtime.ProtocolVersions),
		report.Facts.Runtime.LatestCompatibleVersion,
	)))
}

func appendPoolCheck(report *Report) {
	utilization := report.Facts.Database.PoolUtilizationPPM
	if utilization >= 900_000 {
		report.Checks = append(report.Checks, failedCheck("connection_pool_saturation", "The aggregate PostgreSQL connection budget is at least 90% acquired.", "Reduce request pressure or review the bounded per-process pool budget and database capacity."))
	} else if utilization >= 750_000 {
		report.Checks = append(report.Checks, warningCheck("connection_pool_saturation", "The aggregate PostgreSQL connection budget is at least 75% acquired.", "Review sustained concurrency before raising the per-process pool budget."))
	} else {
		report.Checks = append(report.Checks, passedCheck("connection_pool_saturation", "The aggregate PostgreSQL connection budget is below the diagnostic saturation threshold."))
	}
}

func appendCompletionPoolCheck(report *Report, utilization int64, reachable bool) {
	if !reachable {
		report.Checks = append(report.Checks, failedCheck("quota_completion_pool_saturation", "Reserved quota-completion pool pressure could not be measured because its connectivity probe failed.", "Restore completion-pool connectivity before interpreting its saturation."))
		return
	}
	if utilization >= 900_000 {
		report.Checks = append(report.Checks, failedCheck("quota_completion_pool_saturation", "The reserved quota-completion pool is at least 90% acquired.", "Reduce request pressure and inspect quota settlement latency before changing the aggregate database budget."))
	} else if utilization >= 750_000 {
		report.Checks = append(report.Checks, warningCheck("quota_completion_pool_saturation", "The reserved quota-completion pool is at least 75% acquired.", "Inspect sustained settlement latency and PostgreSQL lock pressure."))
	} else {
		report.Checks = append(report.Checks, passedCheck("quota_completion_pool_saturation", "The reserved quota-completion pool is below the diagnostic saturation threshold."))
	}
}

func probeCompletionPool(parent context.Context, pool poolPinger, timeout time.Duration) error {
	if parent == nil || pool == nil || timeout <= 0 {
		return errors.New("completion pool probe is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return pool.Ping(ctx)
}

func appendCompletionPoolConnectivityCheck(report *Report, err error) {
	if err != nil {
		report.Checks = append(report.Checks, failedCheck(
			"quota_completion_pool_connectivity",
			"The reserved quota-completion pool did not accept a bounded probe.",
			"Inspect PostgreSQL connectivity and terminal quota-settlement pressure before accepting traffic.",
		))
		return
	}
	report.Checks = append(report.Checks, passedCheck(
		"quota_completion_pool_connectivity",
		"The reserved quota-completion pool accepted a bounded probe.",
	))
}

func countJobStatus(items []JobStatusCount, status string) int64 {
	for _, item := range items {
		if item.Status == status {
			return item.Count
		}
	}
	return 0
}

func overall(checks []Check) OverallState {
	state := OverallHealthy
	for _, check := range checks {
		if check.State == CheckFailed {
			return OverallUnhealthy
		}
		if check.State == CheckWarning {
			state = OverallDegraded
		}
	}
	return state
}

func passedCheck(id, summary string) Check {
	return Check{ID: id, State: CheckPassed, Summary: summary}
}
func skippedCheck(id, summary string) Check {
	return Check{ID: id, State: CheckSkipped, Summary: summary}
}
func warningCheck(id, summary, remediation string) Check {
	return Check{ID: id, State: CheckWarning, Summary: summary, Remediation: remediation}
}
func failedCheck(id, summary, remediation string) Check {
	return Check{ID: id, State: CheckFailed, Summary: summary, Remediation: remediation}
}
func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func Validate(report Report) error {
	if report.Schema != ReportSchemaVersion || report.GeneratedAt.IsZero() ||
		(report.Role != "all" && report.Role != "api" && report.Role != "worker") || len(report.Checks) == 0 {
		return errors.New("diagnostic report is invalid")
	}
	seen := make(map[string]struct{}, len(report.Checks))
	for _, check := range report.Checks {
		if check.ID == "" || check.Summary == "" {
			return errors.New("diagnostic check is invalid")
		}
		if _, exists := seen[check.ID]; exists {
			return errors.New("diagnostic check is duplicated")
		}
		seen[check.ID] = struct{}{}
	}
	if !sort.SliceIsSorted(report.Facts.Replicas.FreshByRole, func(i, j int) bool {
		return report.Facts.Replicas.FreshByRole[i].Role < report.Facts.Replicas.FreshByRole[j].Role
	}) {
		return errors.New("diagnostic replica facts are not deterministic")
	}
	return nil
}
