package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/diagnostics"
	"github.com/latchway/latchway/internal/id"
)

const (
	maximumHealthHistoryRange = 7 * 24 * time.Hour
	maximumConnectionRange    = 90 * 24 * time.Hour
	maximumHourlySeriesRange  = 14 * 24 * time.Hour
	maximumListedConnections  = 200
)

type healthHistoryDocument struct {
	Start           time.Time                  `json:"start"`
	End             time.Time                  `json:"end"`
	IntervalSeconds int64                      `json:"interval_seconds"`
	Samples         []diagnostics.HealthSample `json:"samples"`
}

func (store *operationalStore) healthHistory(ctx context.Context, start, end time.Time) (healthHistoryDocument, error) {
	if !start.Before(end) || end.Sub(start) > maximumHealthHistoryRange {
		return healthHistoryDocument{}, errOperationalInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT sampled_at, overall_state, failed_checks, warning_checks
		FROM system_health_samples
		WHERE sampled_at >= $1 AND sampled_at < $2
		ORDER BY sampled_at
	`, start, end)
	if err != nil {
		return healthHistoryDocument{}, fmt.Errorf("read health history: %w", err)
	}
	defer rows.Close()
	document := healthHistoryDocument{
		Start: start.UTC(), End: end.UTC(), IntervalSeconds: int64(diagnostics.HealthSampleInterval / time.Second),
		Samples: make([]diagnostics.HealthSample, 0),
	}
	for rows.Next() {
		var sample diagnostics.HealthSample
		var state string
		if err := rows.Scan(&sample.SampledAt, &state, &sample.FailedChecks, &sample.WarningChecks); err != nil {
			return healthHistoryDocument{}, fmt.Errorf("scan health sample: %w", err)
		}
		sample.SampledAt, sample.OverallState = sample.SampledAt.UTC(), diagnostics.OverallState(state)
		document.Samples = append(document.Samples, sample)
	}
	if err := rows.Err(); err != nil {
		return healthHistoryDocument{}, fmt.Errorf("iterate health history: %w", err)
	}
	return document, nil
}

func (api *API) systemHealthHistory(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "start", "end") {
		api.writeProblem(w, r, invalidRequest("The health-history query is invalid."))
		return
	}
	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour)
	for name, target := range map[string]*time.Time{"start": &start, "end": &end} {
		raw, ok := optionalQueryValue(r, name)
		if !ok {
			api.writeProblem(w, r, invalidRequest("The health-history range is invalid."))
			return
		}
		if raw == "" {
			continue
		}
		parsed, err := parseRequestFilterTime(raw)
		if err != nil {
			api.writeProblem(w, r, invalidRequest("The health-history range is invalid."))
			return
		}
		*target = parsed
	}
	document, err := api.operations.healthHistory(r.Context(), start, end)
	if errors.Is(err, errOperationalInvalid) {
		api.writeProblem(w, r, invalidRequest("The health-history range must start before it ends and span at most 7 days."))
		return
	}
	if err != nil {
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

type connectionFailure struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

type connectionHealth struct {
	Upstream     string              `json:"upstream"`
	Attempts     int64               `json:"attempts"`
	Succeeded    int64               `json:"succeeded"`
	Failed       int64               `json:"failed"`
	Canceled     int64               `json:"canceled"`
	RateLimited  int64               `json:"rate_limited"`
	ServerErrors int64               `json:"server_errors"`
	FellBack     int64               `json:"fell_back"`
	Failures     []connectionFailure `json:"failures"`
	FirstByte    usageDistribution   `json:"first_byte"`
	Duration     usageDistribution   `json:"duration"`
	Usage        usageValues         `json:"usage"`
}

type connectionPoint struct {
	Upstream  string    `json:"upstream"`
	Timestamp time.Time `json:"timestamp"`
	Attempts  int64     `json:"attempts"`
	Failed    int64     `json:"failed"`
}

type connectionHealthDocument struct {
	EnvironmentID string             `json:"environment_id"`
	Start         time.Time          `json:"start"`
	End           time.Time          `json:"end"`
	Interval      string             `json:"interval,omitempty"`
	Connections   []connectionHealth `json:"connections"`
	Truncated     bool               `json:"truncated"`
	Series        []connectionPoint  `json:"series,omitempty"`
}

// connectionHealth summarizes upstream attempts per AI connection: outcomes,
// public failure categories, how often a failure moved to another attempt,
// time to first byte and total duration, and recorded usage. It reads only
// what requests recorded; nothing probes the providers.
func (store *operationalStore) connectionHealth(ctx context.Context, principal adminauth.Principal, environmentID string, start, end time.Time, interval string) (connectionHealthDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || !start.Before(end) || end.Sub(start) > maximumConnectionRange ||
		(interval != "" && interval != "hour" && interval != "day") || (interval == "hour" && end.Sub(start) > maximumHourlySeriesRange) {
		return connectionHealthDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return connectionHealthDocument{}, errOperationalForbidden
	}
	if err := store.ensureEnvironment(ctx, principal.OrganizationID, environmentID); err != nil {
		return connectionHealthDocument{}, err
	}
	document := connectionHealthDocument{
		EnvironmentID: environmentID, Start: start.UTC(), End: end.UTC(), Interval: interval,
		Connections: make([]connectionHealth, 0),
	}
	rows, err := store.pool.Query(ctx, `
		SELECT attempt.upstream_key,
		       count(*)::bigint,
		       count(*) FILTER (WHERE attempt.status = 'succeeded')::bigint,
		       count(*) FILTER (WHERE attempt.status IN ('failed', 'timed_out'))::bigint,
		       count(*) FILTER (WHERE attempt.status = 'cancelled')::bigint,
		       count(*) FILTER (WHERE attempt.http_status = 429)::bigint,
		       count(*) FILTER (WHERE attempt.http_status >= 500)::bigint,
		       count(*) FILTER (WHERE attempt.status IN ('failed', 'timed_out') AND EXISTS (
		           SELECT 1 FROM upstream_attempts AS next
		           WHERE next.logical_request_id = attempt.logical_request_id
		             AND next.attempt_number = attempt.attempt_number + 1
		       ))::bigint,
		       count(attempt.first_byte_at)::bigint,
		       COALESCE(percentile_disc(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM attempt.first_byte_at - attempt.started_at) * 1000) FILTER (WHERE attempt.first_byte_at IS NOT NULL), 0)::bigint,
		       COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM attempt.first_byte_at - attempt.started_at) * 1000) FILTER (WHERE attempt.first_byte_at IS NOT NULL), 0)::bigint,
		       COALESCE(percentile_disc(0.99) WITHIN GROUP (ORDER BY extract(epoch FROM attempt.first_byte_at - attempt.started_at) * 1000) FILTER (WHERE attempt.first_byte_at IS NOT NULL), 0)::bigint,
		       count(attempt.completed_at)::bigint,
		       COALESCE(percentile_disc(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM attempt.completed_at - attempt.started_at) * 1000) FILTER (WHERE attempt.completed_at IS NOT NULL), 0)::bigint,
		       COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM attempt.completed_at - attempt.started_at) * 1000) FILTER (WHERE attempt.completed_at IS NOT NULL), 0)::bigint,
		       COALESCE(percentile_disc(0.99) WITHIN GROUP (ORDER BY extract(epoch FROM attempt.completed_at - attempt.started_at) * 1000) FILTER (WHERE attempt.completed_at IS NOT NULL), 0)::bigint
		FROM upstream_attempts AS attempt
		WHERE attempt.organization_id = $1 AND attempt.environment_id = $2
		  AND attempt.started_at >= $3 AND attempt.started_at < $4
		GROUP BY attempt.upstream_key
		ORDER BY count(*) DESC, attempt.upstream_key
		LIMIT $5
	`, principal.OrganizationID, environmentID, start, end, maximumListedConnections+1)
	if err != nil {
		return connectionHealthDocument{}, fmt.Errorf("summarize connection health: %w", err)
	}
	index := make(map[string]int)
	for rows.Next() {
		var item connectionHealth
		if err := rows.Scan(&item.Upstream, &item.Attempts, &item.Succeeded, &item.Failed, &item.Canceled,
			&item.RateLimited, &item.ServerErrors, &item.FellBack,
			&item.FirstByte.Samples, &item.FirstByte.P50MS, &item.FirstByte.P95MS, &item.FirstByte.P99MS,
			&item.Duration.Samples, &item.Duration.P50MS, &item.Duration.P95MS, &item.Duration.P99MS); err != nil {
			rows.Close()
			return connectionHealthDocument{}, fmt.Errorf("scan connection health: %w", err)
		}
		if !operationalIdentifierPattern.MatchString(item.Upstream) {
			rows.Close()
			return connectionHealthDocument{}, errOperationalCorrupt
		}
		item.Failures = make([]connectionFailure, 0)
		index[item.Upstream] = len(document.Connections)
		document.Connections = append(document.Connections, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return connectionHealthDocument{}, fmt.Errorf("iterate connection health: %w", err)
	}
	if len(document.Connections) > maximumListedConnections {
		dropped := document.Connections[maximumListedConnections].Upstream
		delete(index, dropped)
		document.Connections, document.Truncated = document.Connections[:maximumListedConnections], true
	}
	if len(document.Connections) == 0 {
		return document, nil
	}
	if err := store.connectionFailures(ctx, principal.OrganizationID, environmentID, start, end, index, &document); err != nil {
		return connectionHealthDocument{}, err
	}
	if err := store.connectionUsage(ctx, principal.OrganizationID, environmentID, start, end, index, &document); err != nil {
		return connectionHealthDocument{}, err
	}
	if interval != "" {
		if err := store.connectionSeries(ctx, principal.OrganizationID, environmentID, start, end, interval, index, &document); err != nil {
			return connectionHealthDocument{}, err
		}
	}
	return document, nil
}

func (store *operationalStore) connectionFailures(ctx context.Context, organizationID, environmentID string, start, end time.Time, index map[string]int, document *connectionHealthDocument) error {
	rows, err := store.pool.Query(ctx, `
		SELECT attempt.upstream_key, `+publicAttemptFailureSQL("attempt.failure_code")+` AS failure, count(*)::bigint
		FROM upstream_attempts AS attempt
		WHERE attempt.organization_id = $1 AND attempt.environment_id = $2
		  AND attempt.started_at >= $3 AND attempt.started_at < $4
		  AND attempt.status IN ('failed', 'timed_out', 'cancelled')
		GROUP BY 1, 2
		ORDER BY 1, 3 DESC, 2
	`, organizationID, environmentID, start, end)
	if err != nil {
		return fmt.Errorf("count connection failures: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var upstream string
		var code *string
		var count int64
		if err := rows.Scan(&upstream, &code, &count); err != nil {
			return fmt.Errorf("scan connection failure: %w", err)
		}
		position, kept := index[upstream]
		if !kept {
			continue
		}
		failure := "unknown"
		if code != nil {
			failure = *code
		}
		document.Connections[position].Failures = append(document.Connections[position].Failures, connectionFailure{Code: failure, Count: count})
	}
	return rows.Err()
}

func (store *operationalStore) connectionUsage(ctx context.Context, organizationID, environmentID string, start, end time.Time, index map[string]int, document *connectionHealthDocument) error {
	rows, err := store.pool.Query(ctx, `
		SELECT attempt.upstream_key,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'input_tokens'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'output_tokens'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'total_tokens'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'cost_nano_usd'), 0)::bigint,
		       count(DISTINCT attempt.logical_request_id) FILTER (WHERE attempt.status = 'succeeded')::bigint
		FROM upstream_attempts AS attempt
		LEFT JOIN usage_records AS usage
		  ON usage.upstream_attempt_id = attempt.upstream_attempt_id
		 AND usage.organization_id = attempt.organization_id
		WHERE attempt.organization_id = $1 AND attempt.environment_id = $2
		  AND attempt.started_at >= $3 AND attempt.started_at < $4
		GROUP BY attempt.upstream_key
	`, organizationID, environmentID, start, end)
	if err != nil {
		return fmt.Errorf("sum connection usage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var upstream string
		var values usageValues
		if err := rows.Scan(&upstream, &values.InputTokens, &values.OutputTokens, &values.TotalTokens, &values.CostNanoUSD, &values.LogicalRequests); err != nil {
			return fmt.Errorf("scan connection usage: %w", err)
		}
		if position, kept := index[upstream]; kept {
			document.Connections[position].Usage = values
		}
	}
	return rows.Err()
}

func (store *operationalStore) connectionSeries(ctx context.Context, organizationID, environmentID string, start, end time.Time, interval string, index map[string]int, document *connectionHealthDocument) error {
	rows, err := store.pool.Query(ctx, `
		SELECT attempt.upstream_key, date_trunc($5, attempt.started_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
		       count(*)::bigint, count(*) FILTER (WHERE attempt.status IN ('failed', 'timed_out'))::bigint
		FROM upstream_attempts AS attempt
		WHERE attempt.organization_id = $1 AND attempt.environment_id = $2
		  AND attempt.started_at >= $3 AND attempt.started_at < $4
		GROUP BY 1, 2
		ORDER BY 1, 2
	`, organizationID, environmentID, start, end, interval)
	if err != nil {
		return fmt.Errorf("read connection series: %w", err)
	}
	defer rows.Close()
	document.Series = make([]connectionPoint, 0)
	for rows.Next() {
		var point connectionPoint
		if err := rows.Scan(&point.Upstream, &point.Timestamp, &point.Attempts, &point.Failed); err != nil {
			return fmt.Errorf("scan connection series: %w", err)
		}
		if _, kept := index[point.Upstream]; kept {
			point.Timestamp = point.Timestamp.UTC()
			document.Series = append(document.Series, point)
		}
	}
	return rows.Err()
}

func (api *API) usageConnections(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "start", "end", "interval") {
		api.writeProblem(w, r, invalidRequest("The connection-health query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	start, end, ok := parseUsageRange(r)
	interval, intervalOK := optionalQueryValue(r, "interval")
	if !ok || !intervalOK {
		api.writeProblem(w, r, invalidRequest("The connection-health range is invalid."))
		return
	}
	document, err := api.operations.connectionHealth(r.Context(), mustPrincipal(r.Context()), environmentID, start, end, interval)
	if err != nil {
		if errors.Is(err, errOperationalInvalid) {
			api.writeProblem(w, r, invalidRequest("The connection-health range is at most 90 days, and hourly series at most 14 days."))
			return
		}
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

type selfTestFilter struct {
	scheduleID string
	state      string
	page       operationalPage
}

// listSelfTests lists recent self-test runs for an environment, newest first,
// from the job records the worker keeps for the job-history retention window.
func (store *operationalStore) listSelfTests(ctx context.Context, principal adminauth.Principal, environmentID string, filter selfTestFilter) ([]selfTestDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || filter.page.validate(id.SelfTest) != nil ||
		(filter.scheduleID != "" && id.Validate(filter.scheduleID, id.SelfTestSchedule) != nil) {
		return nil, errOperationalInvalid
	}
	if allowed, err := store.allowedInEnvironment(ctx, principal, adminauth.RunSelfTests, environmentID); err != nil {
		return nil, err
	} else if !allowed {
		return nil, errOperationalForbidden
	}
	var after, afterID any
	if !filter.page.after.IsZero() {
		after, afterID = filter.page.after, filter.page.afterID
	}
	rows, err := store.pool.Query(ctx, `
		SELECT payload
		FROM jobs
		WHERE organization_id = $1 AND job_type = 'run_scheduled_self_test' AND environment_id = $2
		  AND ($3 = '' OR payload->>'schedule_id' = $3)
		  AND ($4 = '' OR payload->>'state' = $4)
		  AND ($5::timestamptz IS NULL OR ((payload->>'created_at')::timestamptz, payload->>'id') < ($5, $6::text))
		ORDER BY (payload->>'created_at')::timestamptz DESC, payload->>'id' DESC
		LIMIT $7
	`, principal.OrganizationID, environmentID, filter.scheduleID, filter.state, after, afterID, filter.page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list self-tests: %w", err)
	}
	defer rows.Close()
	items := make([]selfTestDocument, 0, filter.page.size+1)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan self-test: %w", err)
		}
		var run selfTestDocument
		if len(payload) == 0 || len(payload) > 64<<10 || json.Unmarshal(payload, &run) != nil ||
			run.EnvironmentID != environmentID || !validStoredSelfTest(run) {
			return nil, errOperationalCorrupt
		}
		items = append(items, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate self-tests: %w", err)
	}
	return items, nil
}

var selfTestStates = []string{"queued", "running", "passed", "failed", "canceled"}

func (api *API) selfTests(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "schedule_id", "state", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The self-test list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	var filter selfTestFilter
	scheduleID, scheduleOK := optionalQueryValue(r, "schedule_id")
	state, stateOK := optionalQueryValue(r, "state")
	if !scheduleOK || !stateOK || (state != "" && !slices.Contains(selfTestStates, state)) {
		api.writeProblem(w, r, invalidRequest("The self-test filters are invalid."))
		return
	}
	filter.scheduleID, filter.state = scheduleID, state
	page, err := parseOperationalPage(r, id.SelfTest)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	filter.page = page
	items, err := api.operations.listSelfTests(r.Context(), mustPrincipal(r.Context()), environmentID, filter)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item selfTestDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

type renameRequest struct {
	DisplayName string `json:"display_name"`
}

func (api *API) renameOrganization(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[renameRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The organization rename is invalid."))
		return
	}
	item, err := api.control.RenameOrganization(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "organizationID"), request.DisplayName)
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) renameApplication(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[renameRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The application rename is invalid."))
		return
	}
	item, err := api.control.RenameApplication(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "applicationID"), request.DisplayName)
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) renameEnvironment(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[renameRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The environment rename is invalid."))
		return
	}
	item, err := api.control.RenameEnvironment(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "environmentID"), request.DisplayName)
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
