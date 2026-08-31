package localverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	defaultTimeout = 2 * time.Minute
	maximumTimeout = 5 * time.Minute

	nonStreamingRequestID = "local-verify-non-streaming"
	streamingRequestID    = "local-verify-streaming"
)

type Config struct {
	DatabaseURL string
	Timeout     time.Duration
}

type plannedCheck struct {
	name   string
	detail string
	run    func(context.Context, *fixture) error
}

// Run executes one bounded, destructive verification against an isolated
// schema. The caller's application schema is never migrated or seeded, and the
// generated schema is dropped even after a failed check or canceled context.
func Run(parent context.Context, config Config) (report Report) {
	report = newReport()
	if parent == nil || strings.TrimSpace(config.DatabaseURL) == "" {
		report.add("database_connectivity", "failed", "A PostgreSQL database URL supplied through an environment variable is required.")
		report.cause = errors.New("local verification database configuration is invalid")
		return report
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 10*time.Second || timeout > maximumTimeout {
		report.add("database_connectivity", "failed", "The verification timeout must be between 10 seconds and 5 minutes.")
		report.cause = errors.New("local verification timeout is invalid")
		return report
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	f := &fixture{databaseURL: config.DatabaseURL}
	checks := verificationPlan(f)
	completed := 0
	defer func() {
		cleanupErr := f.cleanup()
		if cleanupErr != nil {
			report.add("ephemeral_cleanup", "failed", "The isolated verification resources could not be fully deleted.")
			if report.cause == nil {
				report.cause = cleanupErr
			}
		} else if f.schema == "" {
			report.add("ephemeral_cleanup", "skipped", "No isolated schema was created.")
		} else {
			report.add("ephemeral_cleanup", "passed", "The isolated schema, tenant, secrets, sessions, requests, and usage were deleted.")
		}
	}()
	for index, check := range checks {
		if err := check.run(ctx, f); err != nil {
			report.add(check.name, "failed", failedDetail(check.name))
			// The underlying error can contain database coordinates, generated
			// identifiers, or provider request material. Keep the public command
			// failure useful but deliberately collapse it to one stable category.
			report.cause = fmt.Errorf("%s: %s", check.name, failedDetail(check.name))
			completed = index + 1
			break
		}
		report.add(check.name, "passed", check.detail)
		completed = index + 1
	}
	if completed < len(checks) {
		for _, check := range checks[completed:] {
			report.add(check.name, "skipped", "A prerequisite verification check failed.")
		}
	}
	return report
}

func verificationPlan(f *fixture) []plannedCheck {
	return []plannedCheck{
		{name: "database_connectivity", detail: "PostgreSQL accepted a bounded connection.", run: func(ctx context.Context, f *fixture) error { return f.connect(ctx) }},
		{name: "isolated_migrations", detail: "Every embedded migration applied in a generated isolated schema.", run: func(ctx context.Context, f *fixture) error { return f.isolateAndMigrate(ctx) }},
		{name: "ephemeral_tenant", detail: "An isolated organization, application, development environment, and owner were created.", run: func(ctx context.Context, f *fixture) error { return f.seedTenant(ctx) }},
		{name: "mock_services", detail: "Bounded mock OIDC and three deterministic private upstreams started.", run: func(context.Context, *fixture) error {
			if err := f.prepareCryptography(); err != nil {
				return err
			}
			return f.startMockServices()
		}},
		{name: "configuration_activation", detail: "A production-shaped identity, trust, route, pricing, and quota revision validated and activated.", run: func(ctx context.Context, f *fixture) error {
			if err := f.seedVerificationSecrets(ctx); err != nil {
				return err
			}
			return f.activateConfiguration(ctx)
		}},
		{name: "runtime_composition", detail: "The canonical client API, policy, quota, secret, session, and data-plane implementations composed.", run: func(ctx context.Context, f *fixture) error { return f.composeRuntime(ctx) }},
		{name: "oidc_debug_dpop_session", detail: "Mock OIDC, debug attestation, a generated P-256 key, challenge binding, and DPoP session exchange passed.", run: func(ctx context.Context, f *fixture) error { return f.exchangeSession(ctx) }},
		{name: "non_streaming", detail: "A DPoP-authorized non-streaming Chat request completed through the deterministic upstream.", run: func(ctx context.Context, f *fixture) error { return f.verifyNonStreaming(ctx) }},
		{name: "streaming", detail: "An SSE response streamed complete events and terminal provider usage without whole-response buffering.", run: func(ctx context.Context, f *fixture) error { return f.verifyStreaming(ctx) }},
		{name: "usage_accounting", detail: "Trusted input preflight and provider-reported input, output, total, request, and cost records settled durably.", run: func(ctx context.Context, f *fixture) error { return f.verifyUsageAccounting(ctx) }},
		{name: "dpop_replay", detail: "An identical protected DPoP proof was rejected before a second upstream dispatch.", run: func(ctx context.Context, f *fixture) error { return f.verifyDPoPReplay(ctx) }},
		{name: "request_quota", detail: "The third logical request was atomically denied after a two-request hard calendar limit.", run: func(ctx context.Context, f *fixture) error { return f.verifyRequestExhaustion(ctx) }},
		{name: "output_quota_and_clamp", detail: "The provider request was clamped to seven output tokens and the settled window denied the next request.", run: func(ctx context.Context, f *fixture) error { return f.verifyOutputExhaustion(ctx) }},
		{name: "token_bucket_refill", detail: "A depleted rolling token bucket denied, accrued one exact token, and accepted the next request.", run: func(ctx context.Context, f *fixture) error { return f.verifyTokenBucketRefill(ctx) }},
		{name: "concurrency", detail: "A live stream held the only lease, a competitor was denied, and completion released the lease.", run: func(ctx context.Context, f *fixture) error { return f.verifyConcurrency(ctx) }},
		{name: "fallback_attempt_accounting", detail: "A configured status-500 fallback produced two durable attempts and one logical request settlement.", run: func(ctx context.Context, f *fixture) error { return f.verifyFallback(ctx) }},
		{name: "crash_reclaim", detail: "Abandoned pre-dispatch capacity was released and dispatched capacity was conservatively settled by recovery.", run: func(ctx context.Context, f *fixture) error { return f.verifyCrashRecovery(ctx) }},
		{name: "credential_header_stripping", detail: "Client credentials and forwarding/control headers were stripped; only the server-held bearer secret crossed.", run: func(ctx context.Context, f *fixture) error { return f.verifyHeaderBoundary(ctx) }},
		{name: "ssrf_defense", detail: "Loopback, link-local metadata, and private destinations were rejected by the production target policy.", run: func(ctx context.Context, f *fixture) error { return f.verifySSRF(ctx) }},
		{name: "configuration_rollback", detail: "A second immutable revision activated and rollback restored the exact first compiled revision.", run: func(ctx context.Context, f *fixture) error { return f.verifyConfigurationRollback(ctx) }},
	}
}

func failedDetail(name string) string {
	details := map[string]string{
		"database_connectivity":       "PostgreSQL connectivity failed.",
		"isolated_migrations":         "The isolated schema or embedded migrations failed.",
		"ephemeral_tenant":            "Ephemeral tenant creation failed.",
		"mock_services":               "A bounded mock service could not start.",
		"configuration_activation":    "The local verification configuration did not validate and activate.",
		"runtime_composition":         "A production runtime dependency could not be composed.",
		"oidc_debug_dpop_session":     "OIDC, debug attestation, or P-256 DPoP session exchange failed.",
		"non_streaming":               "The authenticated non-streaming vertical failed.",
		"streaming":                   "The authenticated SSE vertical failed.",
		"usage_accounting":            "Trusted preflight or durable usage settlement failed.",
		"dpop_replay":                 "DPoP replay denial failed.",
		"request_quota":               "Request-count exhaustion failed.",
		"output_quota_and_clamp":      "Output clamp or output-window exhaustion failed.",
		"token_bucket_refill":         "Token-bucket denial or refill failed.",
		"concurrency":                 "Concurrent-stream lease enforcement failed.",
		"fallback_attempt_accounting": "Configured fallback or attempt accounting failed.",
		"crash_reclaim":               "Expired reservation recovery failed.",
		"credential_header_stripping": "The provider credential boundary failed.",
		"ssrf_defense":                "A prohibited upstream destination was accepted.",
		"configuration_rollback":      "Configuration activation or rollback failed.",
	}
	if detail := details[name]; detail != "" {
		return detail
	}
	return "The verification check failed."
}

func chatBody(prompt string, streaming bool) map[string]any {
	body := map[string]any{
		"model":                 "untrusted-client-model",
		"messages":              []any{map[string]any{"role": "user", "content": prompt}},
		"max_completion_tokens": int64(9999),
	}
	if streaming {
		body["stream"] = true
	}
	return body
}

func (f *fixture) sendFeature(feature, clientRequestID, prompt string, streaming bool, label string) (*deadlineRecorder, string, error) {
	target, err := parseURL(f.origin() + protocol.OpenAIChatPublicPath)
	if err != nil {
		return nil, "", err
	}
	proof, err := signDPoP(f.dpopKey, http.MethodPost, target, f.now, label, f.accessToken)
	if err != nil {
		return nil, "", err
	}
	response, err := postFeature(f.dataHandler, f.accessToken, proof, feature, clientRequestID, chatBody(prompt, streaming))
	return response, proof, err
}

func (f *fixture) verifyNonStreaming(context.Context) error {
	response, proof, err := f.sendFeature("assistant", nonStreamingRequestID, "local-verify-non-stream", false, "non-stream")
	if err != nil {
		return err
	}
	if err := requireStatus(response.ResponseRecorder, http.StatusOK); err != nil {
		return err
	}
	if err := decodeUsageBody(response.ResponseRecorder); err != nil {
		return err
	}
	f.nonStreamingProof = proof
	return nil
}

func (f *fixture) verifyStreaming(context.Context) error {
	response, _, err := f.sendFeature("assistant", streamingRequestID, "local-verify-stream", true, "stream")
	if err != nil {
		return err
	}
	if err := requireStatus(response.ResponseRecorder, http.StatusOK); err != nil {
		return err
	}
	if !response.Flushed || !containsFinalSSEUsage(response.ResponseRecorder) {
		return errors.New("streaming response omitted complete final usage")
	}
	return nil
}

func (f *fixture) verifyUsageAccounting(ctx context.Context) error {
	for _, clientRequestID := range []string{nonStreamingRequestID, streamingRequestID} {
		var logicalStatus, reservationStatus, attemptStatus, method string
		var httpStatus int
		var inputBound, outputBound, totalBound int64
		if err := f.pool.QueryRow(ctx, `
			SELECT request.status, reservation.status, attempt.status, attempt.http_status,
			       attempt.input_accounting_method, attempt.input_token_bound,
			       attempt.output_token_bound, attempt.total_token_bound
			FROM logical_requests AS request
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN upstream_attempts AS attempt USING (logical_request_id)
			WHERE request.client_request_id = $1
		`, clientRequestID).Scan(
			&logicalStatus, &reservationStatus, &attemptStatus, &httpStatus,
			&method, &inputBound, &outputBound, &totalBound,
		); err != nil {
			return err
		}
		if logicalStatus != "succeeded" || reservationStatus != "settled" ||
			attemptStatus != quota.AttemptSucceeded || httpStatus != http.StatusOK ||
			method != quota.UTF8ByteBPEDeclaredFramingV1 || inputBound <= 0 ||
			outputBound != 8 || totalBound != inputBound+outputBound {
			return errors.New("trusted attempt accounting is inconsistent")
		}
		rows, err := f.pool.Query(ctx, `
			SELECT usage.metric, usage.units, usage.confidence, usage.provenance_key
			FROM usage_records AS usage
			JOIN logical_requests AS request USING (logical_request_id)
			WHERE request.client_request_id = $1
		`, clientRequestID)
		if err != nil {
			return err
		}
		expected := map[string]int64{
			quota.LogicalRequestsMetric: 1, quota.InputTokensMetric: 11,
			quota.OutputTokensMetric: 7, quota.TotalTokensMetric: 18,
			quota.CostNanoUSDMetric: 0,
		}
		seen := make(map[string]bool, len(expected))
		for rows.Next() {
			var metric, confidence, provenance string
			var units int64
			if err := rows.Scan(&metric, &units, &confidence, &provenance); err != nil {
				rows.Close()
				return err
			}
			want, relevant := expected[metric]
			if !relevant {
				continue
			}
			validAttribution := confidence != "" && provenance != ""
			switch metric {
			case quota.LogicalRequestsMetric:
				validAttribution = validAttribution && confidence == "calculated" && strings.HasPrefix(provenance, "logical-request:")
			case quota.CostNanoUSDMetric:
				validAttribution = validAttribution && confidence == quota.CalculatedCostConfidence && strings.HasPrefix(provenance, "configured_flat_rate:")
			default:
				validAttribution = validAttribution && confidence == "reported" && strings.HasPrefix(provenance, quota.ProviderReportedProvenance+":")
			}
			if units != want || !validAttribution {
				rows.Close()
				return errors.New("persisted usage record is inconsistent")
			}
			seen[metric] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(seen) != len(expected) {
			return errors.New("persisted usage metrics are incomplete")
		}
	}
	return nil
}

func (f *fixture) verifyDPoPReplay(context.Context) error {
	before, err := f.providerCapture.snapshot()
	if err != nil {
		return err
	}
	response, err := postFeature(
		f.dataHandler, f.accessToken, f.nonStreamingProof, "assistant",
		nonStreamingRequestID, chatBody("local-verify-non-stream", false),
	)
	if err != nil {
		return err
	}
	code, decodeErr := problemCode(response.ResponseRecorder)
	if decodeErr != nil || response.Code != http.StatusUnauthorized || code != "dpop_replayed" {
		return errors.New("replayed DPoP proof was not rejected")
	}
	after, err := f.providerCapture.snapshot()
	if err != nil || len(after) != len(before) {
		return errors.New("replayed DPoP proof reached the upstream")
	}
	return nil
}

func (f *fixture) verifyRequestExhaustion(context.Context) error {
	before, err := f.providerCapture.snapshot()
	if err != nil {
		return err
	}
	response, _, err := f.sendFeature("assistant", "local-verify-request-denied", "request-denied", false, "request-denied")
	if err != nil {
		return err
	}
	code, decodeErr := problemCode(response.ResponseRecorder)
	if decodeErr != nil || response.Code != http.StatusTooManyRequests || code != "quota_exceeded" ||
		response.Header().Get("Retry-After") == "" {
		return errors.New("request quota did not deny atomically")
	}
	after, err := f.providerCapture.snapshot()
	if err != nil || len(after) != len(before) {
		return errors.New("request quota denial reached the upstream")
	}
	return nil
}

func (f *fixture) verifyOutputExhaustion(context.Context) error {
	before, err := f.providerCapture.snapshot()
	if err != nil {
		return err
	}
	first, _, err := f.sendFeature("output_guard", "local-verify-output-first", "output-first", false, "output-first")
	if err != nil || first.Code != http.StatusOK {
		return errors.New("first output-budget request failed")
	}
	afterFirst, err := f.providerCapture.snapshot()
	if err != nil || len(afterFirst) != len(before)+1 {
		return errors.New("first output-budget request did not dispatch once")
	}
	maximum, model, err := outputMaximum(afterFirst[len(afterFirst)-1].Body)
	if err != nil || maximum != 7 || model != providerModel {
		return errors.New("provider request did not apply the exact output clamp and model rewrite")
	}
	second, _, err := f.sendFeature("output_guard", "local-verify-output-denied", "output-denied", false, "output-denied")
	if err != nil {
		return err
	}
	code, decodeErr := problemCode(second.ResponseRecorder)
	if decodeErr != nil || second.Code != http.StatusTooManyRequests || code != "quota_exceeded" {
		return errors.New("settled output-token budget did not deny the next request")
	}
	afterSecond, err := f.providerCapture.snapshot()
	if err != nil || len(afterSecond) != len(afterFirst) {
		return errors.New("output-token denial reached the upstream")
	}
	return nil
}

func (f *fixture) verifyTokenBucketRefill(ctx context.Context) error {
	first, _, err := f.sendFeature("request_pacer", "local-verify-pace-first", "pace-first", false, "pace-first")
	if err != nil || first.Code != http.StatusOK {
		return errors.New("first token-bucket request failed")
	}
	denied, _, err := f.sendFeature("request_pacer", "local-verify-pace-denied", "pace-denied", false, "pace-denied")
	if err != nil {
		return err
	}
	code, decodeErr := problemCode(denied.ResponseRecorder)
	if decodeErr != nil || denied.Code != http.StatusTooManyRequests || code != "quota_exceeded" {
		return errors.New("depleted token bucket did not deny")
	}
	command, err := f.pool.Exec(ctx, `
		UPDATE quota_buckets SET refilled_at = refilled_at - interval '100 seconds'
		WHERE limit_plan_key = $1 AND metric = $2 AND algorithm = $3 AND window_key = 'rolling'
	`, pacePlan, quota.LogicalRequestsMetric, quota.TokenBucketAlgorithm)
	if err != nil || command.RowsAffected() != 1 {
		return errors.New("token-bucket refill cursor could not be advanced")
	}
	refilled, _, err := f.sendFeature("request_pacer", "local-verify-pace-refilled", "pace-refilled", false, "pace-refilled")
	if err != nil || refilled.Code != http.StatusOK {
		return errors.New("refilled token bucket did not accept one exact request")
	}
	var available, reserved int64
	if err := f.pool.QueryRow(ctx, `
		SELECT available_units, reserved_units FROM quota_buckets
		WHERE limit_plan_key = $1 AND metric = $2 AND algorithm = $3
	`, pacePlan, quota.LogicalRequestsMetric, quota.TokenBucketAlgorithm).Scan(&available, &reserved); err != nil {
		return err
	}
	if available < 0 || available >= 1_000_000_000_000 || reserved != 0 {
		return errors.New("refilled token bucket has invalid terminal occupancy")
	}
	return nil
}

func (f *fixture) verifyConcurrency(ctx context.Context) error {
	target, err := parseURL(f.origin() + protocol.OpenAIChatPublicPath)
	if err != nil {
		return err
	}
	holdProof, err := signDPoP(f.dpopKey, http.MethodPost, target, f.now, "concurrency-hold", f.accessToken)
	if err != nil {
		return err
	}
	holdRequest, holdResponse, err := newFeatureRequest(
		f.accessToken, holdProof, "stream_guard", "local-verify-concurrency-hold",
		chatBody(blockedPrompt, true),
	)
	if err != nil {
		return err
	}
	holdDone := make(chan struct{})
	go func() {
		f.dataHandler.ServeHTTP(holdResponse, holdRequest)
		close(holdDone)
	}()
	select {
	case <-f.providerCapture.blockStarted:
	case <-holdDone:
		return errors.New("held stream completed before acquiring a lease")
	case <-ctx.Done():
		return ctx.Err()
	}
	denied, _, err := f.sendFeature(
		"stream_guard", "local-verify-concurrency-denied", "concurrency-denied", true, "concurrency-denied",
	)
	if err != nil {
		return err
	}
	code, decodeErr := problemCode(denied.ResponseRecorder)
	if decodeErr != nil || denied.Code != http.StatusTooManyRequests || code != "concurrency_exceeded" {
		return errors.New("competing stream was not denied")
	}
	var active int64
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM concurrency_leases WHERE released_at IS NULL`).Scan(&active); err != nil {
		return err
	}
	if active != 1 {
		return errors.New("concurrency lease was not durably active")
	}
	f.providerCapture.release()
	select {
	case <-holdDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if holdResponse.Code != http.StatusOK || !containsFinalSSEUsage(holdResponse.ResponseRecorder) {
		return errors.New("held stream did not complete successfully")
	}
	var total, released int64
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE released_at IS NOT NULL)
		FROM concurrency_leases
	`).Scan(&total, &released); err != nil {
		return err
	}
	if total != 1 || released != 1 {
		return errors.New("concurrency lease was not released")
	}
	return nil
}

func (f *fixture) verifyFallback(ctx context.Context) error {
	response, _, err := f.sendFeature("fallback", "local-verify-fallback", "fallback", false, "fallback")
	if err != nil || response.Code != http.StatusOK {
		return errors.New("configured fallback request failed")
	}
	failures, failureErr := f.failureCapture.snapshot()
	successes, successErr := f.fallbackCapture.snapshot()
	if failureErr != nil || successErr != nil || len(failures) != 1 || len(successes) != 1 {
		return errors.New("fallback did not dispatch exactly one primary and one secondary attempt")
	}
	rows, err := f.pool.Query(ctx, `
		SELECT attempt.attempt_number, attempt.status, attempt.http_status,
		       attempt.upstream_key, attempt.model_key
		FROM upstream_attempts AS attempt
		JOIN logical_requests AS request USING (logical_request_id)
		WHERE request.client_request_id = 'local-verify-fallback'
		ORDER BY attempt.attempt_number
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type attemptState struct {
		number          int32
		state           string
		status          int
		upstream, model string
	}
	var attempts []attemptState
	for rows.Next() {
		var item attemptState
		if err := rows.Scan(&item.number, &item.state, &item.status, &item.upstream, &item.model); err != nil {
			return err
		}
		attempts = append(attempts, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(attempts) != 2 || attempts[0] != (attemptState{1, quota.AttemptFailed, 500, "failure", "fallback_primary"}) ||
		attempts[1] != (attemptState{2, quota.AttemptSucceeded, 200, "fallback", "fallback_secondary"}) {
		return errors.New("durable fallback attempt ledger is inconsistent")
	}
	var logicalCount, requestUsage int64
	if err := f.pool.QueryRow(ctx, `
		SELECT count(DISTINCT request.logical_request_id),
		       count(*) FILTER (WHERE usage.metric = $1)
		FROM logical_requests AS request
		LEFT JOIN usage_records AS usage USING (logical_request_id)
		WHERE request.client_request_id = 'local-verify-fallback'
	`, quota.LogicalRequestsMetric).Scan(&logicalCount, &requestUsage); err != nil {
		return err
	}
	if logicalCount != 1 || requestUsage != 1 {
		return errors.New("fallback double-counted the logical request")
	}
	return nil
}

func logicalIdentity(ctx context.Context) (requestidentity.LogicalID, error) {
	requestCtx, err := requestidentity.NewContext(ctx)
	if err != nil {
		return requestidentity.LogicalID{}, err
	}
	logicalID, ok := requestidentity.FromContext(requestCtx)
	if !ok {
		return requestidentity.LogicalID{}, errors.New("logical request identity was not generated")
	}
	return logicalID, nil
}

func (f *fixture) crashReserveInput(ctx context.Context, suffix string) (quota.ReserveInput, error) {
	logicalID, err := logicalIdentity(ctx)
	if err != nil {
		return quota.ReserveInput{}, err
	}
	return quota.ReserveInput{
		LogicalRequestID: logicalID,
		OrganizationID:   f.tenant.organizationID, ApplicationID: f.tenant.applicationID,
		EnvironmentID: f.tenant.environmentID, ApplicationUserID: f.applicationUserID,
		InstallationID: f.installationID, SessionGrantID: f.sessionGrantID,
		ConfigRevisionID: f.quotaRevisionID, FeatureKey: "crash_guard",
		Protocol: protocol.OpenAIChatID, ClientRequestID: "local-verify-crash-" + suffix,
		LimitPlanKey: "crash_limits", RouteKey: "primary", UpstreamKey: "primary",
		ModelKey: "chat", PhysicalModel: providerModel,
		Rules: []quota.Rule{{
			Metric: quota.LogicalRequestsMetric, Algorithm: quota.CalendarAlgorithm,
			Scope: []string{"feature", "user"}, Window: "1d", Maximum: 10, Hard: true,
		}},
	}, nil
}

func (f *fixture) verifyCrashRecovery(ctx context.Context) error {
	dispatchedInput, err := f.crashReserveInput(ctx, "dispatched")
	if err != nil {
		return err
	}
	dispatched, err := f.quotaStore.Reserve(ctx, dispatchedInput)
	if err != nil {
		return err
	}
	attempt, owner, err := f.quotaStore.BeginAttempt(ctx, dispatched)
	if err != nil || !owner || attempt.ID() == "" {
		return errors.New("crash drill could not durably begin dispatch")
	}
	undispatchedInput, err := f.crashReserveInput(ctx, "undispatched")
	if err != nil {
		return err
	}
	undispatched, err := f.quotaStore.Reserve(ctx, undispatchedInput)
	if err != nil {
		return err
	}
	command, err := f.pool.Exec(ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = ANY($1::text[])
	`, []string{dispatched.ID(), undispatched.ID()})
	if err != nil || command.RowsAffected() != 2 {
		return errors.New("crash drill reservations could not be expired")
	}
	processed, err := f.quotaStore.ExpirePendingBatch(ctx, 2)
	if err != nil || processed != 2 {
		return errors.New("recovery did not claim both abandoned reservations")
	}
	var dispatchedReservation, attemptStatus, attemptFailure string
	if err := f.pool.QueryRow(ctx, `
		SELECT reservation.status, attempt.status, attempt.failure_code
		FROM quota_reservations AS reservation
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		WHERE reservation.quota_reservation_id = $1
	`, dispatched.ID()).Scan(&dispatchedReservation, &attemptStatus, &attemptFailure); err != nil {
		return err
	}
	var undispatchedReservation, logicalStatus, logicalFailure string
	if err := f.pool.QueryRow(ctx, `
		SELECT reservation.status, request.status, request.failure_code
		FROM quota_reservations AS reservation
		JOIN logical_requests AS request USING (logical_request_id)
		WHERE reservation.quota_reservation_id = $1
	`, undispatched.ID()).Scan(&undispatchedReservation, &logicalStatus, &logicalFailure); err != nil {
		return err
	}
	if dispatchedReservation != "settled" || attemptStatus != quota.AttemptTimedOut || attemptFailure == "" ||
		undispatchedReservation != "expired" || logicalStatus != "failed" || logicalFailure == "" {
		return errors.New("abandoned reservation recovery states are inconsistent")
	}
	var reserved int64
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(sum(reserved_units), 0) FROM quota_buckets WHERE limit_plan_key = 'crash_limits'
	`).Scan(&reserved); err != nil {
		return err
	}
	if reserved != 0 {
		return errors.New("recovery retained quota capacity")
	}
	return nil
}

func (f *fixture) verifyHeaderBoundary(context.Context) error {
	requests, err := f.providerCapture.snapshot()
	if err != nil || len(requests) == 0 {
		return errors.New("no provider request was captured")
	}
	for _, request := range requests {
		if containsForbiddenProviderHeaders(request.Headers) || !canonicalBearer(request.Headers, f.providerCredential) {
			return errors.New("a captured provider request violated the credential boundary")
		}
	}
	return nil
}

func (f *fixture) verifySSRF(context.Context) error {
	blocked := []string{
		"http://127.0.0.1:8080/v1", "http://169.254.169.254/latest/meta-data",
		"http://10.0.0.8/v1", "http://[::1]:8080/v1",
	}
	for _, destination := range blocked {
		if err := upstream.ValidateDestination(destination, upstream.DestinationPolicy{}); err == nil {
			return errors.New("blocked destination passed target validation")
		}
	}
	return nil
}
