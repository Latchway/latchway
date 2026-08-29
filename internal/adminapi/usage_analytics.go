package adminapi

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/latchway/latchway/internal/adminauth"
)

const (
	defaultUsageBreakdownLimit = 50
	maximumUsageBreakdownLimit = 200
)

type usageFraction struct {
	Numerator   int64 `json:"numerator"`
	Denominator int64 `json:"denominator"`
}

type usageRate struct {
	Numerator       int64 `json:"numerator"`
	Denominator     int64 `json:"denominator"`
	PartsPerMillion int64 `json:"parts_per_million"`
}

type usageDistribution struct {
	Samples int64 `json:"samples"`
	P50MS   int64 `json:"p50_ms"`
	P95MS   int64 `json:"p95_ms"`
	P99MS   int64 `json:"p99_ms"`
}

type usageBreakdownItem struct {
	Key          string      `json:"key"`
	ActiveUsers  int64       `json:"active_users"`
	RequestCount int64       `json:"request_count"`
	Values       usageValues `json:"values"`
}

type usageBreakdown struct {
	Items     []usageBreakdownItem `json:"items"`
	Truncated bool                 `json:"truncated"`
	Limit     int                  `json:"limit"`
}

type usageProvenanceItem struct {
	Provenance string      `json:"provenance"`
	Values     usageValues `json:"values"`
}

type usageAnalyticsDocument struct {
	ActiveUsers              int64                 `json:"active_users"`
	RequestCount             int64                 `json:"request_count"`
	RequestsPerActiveUser    usageFraction         `json:"requests_per_active_user"`
	CostPerActiveUserNanoUSD usageFraction         `json:"cost_per_active_user_nano_usd"`
	ByFeature                usageBreakdown        `json:"by_feature"`
	ByModel                  usageBreakdown        `json:"by_model"`
	BySelectedPlan           usageBreakdown        `json:"by_selected_plan"`
	RequestLatency           usageDistribution     `json:"request_latency"`
	TimeToFirstToken         usageDistribution     `json:"time_to_first_token"`
	FailureRate              usageRate             `json:"failure_rate"`
	QuotaDenialRate          usageRate             `json:"quota_denial_rate"`
	AttestationFailureRate   usageRate             `json:"attestation_failure_rate"`
	FallbackRate             usageRate             `json:"fallback_rate"`
	UsageByProvenance        []usageProvenanceItem `json:"usage_by_provenance"`
}

func (store *operationalStore) usageAnalytics(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	start time.Time,
	end time.Time,
	values usageValues,
	breakdownLimit int,
) (usageAnalyticsDocument, error) {
	if breakdownLimit < 1 || breakdownLimit > maximumUsageBreakdownLimit {
		return usageAnalyticsDocument{}, errOperationalInvalid
	}
	activeUsers, requestCount, err := store.usageAudience(
		ctx, principal.OrganizationID, environmentID, start, end,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	feature, err := store.usageDimensionBreakdown(
		ctx, principal.OrganizationID, environmentID, start, end, "feature", breakdownLimit,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	model, err := store.usageDimensionBreakdown(
		ctx, principal.OrganizationID, environmentID, start, end, "model", breakdownLimit,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	plan, err := store.usageDimensionBreakdown(
		ctx, principal.OrganizationID, environmentID, start, end, "selected_plan", breakdownLimit,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	requestLatency, ttft, err := store.usageLatency(
		ctx, principal.OrganizationID, environmentID, start, end,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	failure, quotaDenial, attestationFailure, fallback, err := store.usageRates(
		ctx, principal.OrganizationID, environmentID, start, end,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	provenance, err := store.usageProvenanceBreakdown(
		ctx, principal.OrganizationID, environmentID, start, end,
	)
	if err != nil {
		return usageAnalyticsDocument{}, err
	}
	return usageAnalyticsDocument{
		ActiveUsers: activeUsers, RequestCount: requestCount,
		RequestsPerActiveUser:    usageFraction{Numerator: requestCount, Denominator: activeUsers},
		CostPerActiveUserNanoUSD: usageFraction{Numerator: values.CostNanoUSD, Denominator: activeUsers},
		ByFeature:                feature, ByModel: model, BySelectedPlan: plan,
		RequestLatency: requestLatency, TimeToFirstToken: ttft,
		FailureRate: failure, QuotaDenialRate: quotaDenial,
		AttestationFailureRate: attestationFailure, FallbackRate: fallback,
		UsageByProvenance: provenance,
	}, nil
}

func (store *operationalStore) usageAudience(
	ctx context.Context, organizationID, environmentID string, start, end time.Time,
) (int64, int64, error) {
	var activeUsers, requests int64
	err := store.pool.QueryRow(ctx, `
		SELECT count(DISTINCT application_user_id)::bigint, count(*)::bigint
		FROM logical_requests
		WHERE organization_id = $1 AND environment_id = $2
		  AND requested_at >= $3 AND requested_at < $4
	`, organizationID, environmentID, start.UTC(), end.UTC()).Scan(&activeUsers, &requests)
	if err != nil {
		return 0, 0, fmt.Errorf("aggregate usage audience: %w", err)
	}
	return activeUsers, requests, nil
}

func (store *operationalStore) usageDimensionBreakdown(
	ctx context.Context,
	organizationID string,
	environmentID string,
	start time.Time,
	end time.Time,
	dimension string,
	limit int,
) (usageBreakdown, error) {
	requestSource, requestKey, usageJoins, usageKey := "logical_requests request", "request.feature_key", "JOIN logical_requests request ON request.organization_id = usage.organization_id AND request.environment_id = usage.environment_id AND request.logical_request_id = usage.logical_request_id", "request.feature_key"
	switch dimension {
	case "feature":
	case "selected_plan":
		requestKey, usageKey = "request.selected_limit_plan_key", "request.selected_limit_plan_key"
	case "model":
		requestSource = "upstream_attempts attempt JOIN logical_requests request ON request.organization_id = attempt.organization_id AND request.environment_id = attempt.environment_id AND request.logical_request_id = attempt.logical_request_id"
		requestKey = "COALESCE(attempt.model_key, 'legacy_unknown')"
		usageJoins = "JOIN upstream_attempts attempt ON attempt.organization_id = usage.organization_id AND attempt.environment_id = usage.environment_id AND attempt.upstream_attempt_id = usage.upstream_attempt_id JOIN logical_requests request ON request.organization_id = attempt.organization_id AND request.environment_id = attempt.environment_id AND request.logical_request_id = attempt.logical_request_id"
		usageKey = "COALESCE(attempt.model_key, 'legacy_unknown')"
	default:
		return usageBreakdown{}, errOperationalInvalid
	}
	query := fmt.Sprintf(`
		WITH request_aggregate AS (
			SELECT %s AS dimension_key,
			       count(DISTINCT request.logical_request_id)::bigint AS request_count,
			       count(DISTINCT request.application_user_id)::bigint AS active_users
			FROM %s
			WHERE request.organization_id = $1 AND request.environment_id = $2
			  AND request.requested_at >= $3 AND request.requested_at < $4
			GROUP BY %s
		), usage_aggregate AS (
			SELECT %s AS dimension_key,
			       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'logical_requests'), 0)::bigint AS logical_requests,
			       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'input_tokens'), 0)::bigint AS input_tokens,
			       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'output_tokens'), 0)::bigint AS output_tokens,
			       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'total_tokens'), 0)::bigint AS total_tokens,
			       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'cost_nano_usd'), 0)::bigint AS cost_nano_usd
			FROM usage_records usage
			%s
			WHERE usage.organization_id = $1 AND usage.environment_id = $2
			  AND usage.recorded_at >= $3 AND usage.recorded_at < $4
			GROUP BY %s
		)
		SELECT COALESCE(request_aggregate.dimension_key, usage_aggregate.dimension_key),
		       COALESCE(request_aggregate.active_users, 0)::bigint,
		       COALESCE(request_aggregate.request_count, 0)::bigint,
		       COALESCE(usage_aggregate.logical_requests, 0)::bigint,
		       COALESCE(usage_aggregate.input_tokens, 0)::bigint,
		       COALESCE(usage_aggregate.output_tokens, 0)::bigint,
		       COALESCE(usage_aggregate.total_tokens, 0)::bigint,
		       COALESCE(usage_aggregate.cost_nano_usd, 0)::bigint
		FROM request_aggregate
		FULL OUTER JOIN usage_aggregate USING (dimension_key)
		WHERE COALESCE(request_aggregate.dimension_key, usage_aggregate.dimension_key) IS NOT NULL
		ORDER BY COALESCE(request_aggregate.request_count, 0) DESC,
		         COALESCE(usage_aggregate.cost_nano_usd, 0) DESC,
		         COALESCE(request_aggregate.dimension_key, usage_aggregate.dimension_key)
		LIMIT $5
	`, requestKey, requestSource, requestKey, usageKey, usageJoins, usageKey)
	rows, err := store.pool.Query(
		ctx, query, organizationID, environmentID, start.UTC(), end.UTC(), limit+1,
	)
	if err != nil {
		return usageBreakdown{}, fmt.Errorf("query %s usage breakdown: %w", dimension, err)
	}
	defer rows.Close()
	items := make([]usageBreakdownItem, 0, limit+1)
	for rows.Next() {
		var item usageBreakdownItem
		if err := rows.Scan(
			&item.Key, &item.ActiveUsers, &item.RequestCount,
			&item.Values.LogicalRequests, &item.Values.InputTokens, &item.Values.OutputTokens,
			&item.Values.TotalTokens, &item.Values.CostNanoUSD,
		); err != nil {
			return usageBreakdown{}, fmt.Errorf("scan %s usage breakdown: %w", dimension, err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return usageBreakdown{}, fmt.Errorf("iterate %s usage breakdown: %w", dimension, err)
	}
	truncated := len(items) > limit
	if truncated {
		items = items[:limit]
	}
	return usageBreakdown{Items: items, Truncated: truncated, Limit: limit}, nil
}

func (store *operationalStore) usageLatency(
	ctx context.Context, organizationID, environmentID string, start, end time.Time,
) (usageDistribution, usageDistribution, error) {
	var request, ttft usageDistribution
	err := store.pool.QueryRow(ctx, `
		WITH request_latency AS (
			SELECT floor(extract(epoch FROM (completed_at - requested_at)) * 1000)::bigint AS value
			FROM logical_requests
			WHERE organization_id = $1 AND environment_id = $2
			  AND requested_at >= $3 AND requested_at < $4 AND completed_at IS NOT NULL
		), first_tokens AS (
			SELECT request.logical_request_id,
			       floor(extract(epoch FROM (min(attempt.first_byte_at) - request.requested_at)) * 1000)::bigint AS value
			FROM logical_requests request
			JOIN upstream_attempts attempt
			  ON attempt.organization_id = request.organization_id
			 AND attempt.environment_id = request.environment_id
			 AND attempt.logical_request_id = request.logical_request_id
			WHERE request.organization_id = $1 AND request.environment_id = $2
			  AND request.requested_at >= $3 AND request.requested_at < $4
			  AND attempt.first_byte_at IS NOT NULL
			GROUP BY request.logical_request_id, request.requested_at
		)
		SELECT
			(SELECT count(*)::bigint FROM request_latency),
			COALESCE((SELECT percentile_disc(0.50) WITHIN GROUP (ORDER BY value) FROM request_latency), 0)::bigint,
			COALESCE((SELECT percentile_disc(0.95) WITHIN GROUP (ORDER BY value) FROM request_latency), 0)::bigint,
			COALESCE((SELECT percentile_disc(0.99) WITHIN GROUP (ORDER BY value) FROM request_latency), 0)::bigint,
			(SELECT count(*)::bigint FROM first_tokens),
			COALESCE((SELECT percentile_disc(0.50) WITHIN GROUP (ORDER BY value) FROM first_tokens), 0)::bigint,
			COALESCE((SELECT percentile_disc(0.95) WITHIN GROUP (ORDER BY value) FROM first_tokens), 0)::bigint,
			COALESCE((SELECT percentile_disc(0.99) WITHIN GROUP (ORDER BY value) FROM first_tokens), 0)::bigint
	`, organizationID, environmentID, start.UTC(), end.UTC()).Scan(
		&request.Samples, &request.P50MS, &request.P95MS, &request.P99MS,
		&ttft.Samples, &ttft.P50MS, &ttft.P95MS, &ttft.P99MS,
	)
	if err != nil {
		return usageDistribution{}, usageDistribution{}, fmt.Errorf("aggregate usage latency: %w", err)
	}
	return request, ttft, nil
}

func (store *operationalStore) usageRates(
	ctx context.Context, organizationID, environmentID string, start, end time.Time,
) (usageRate, usageRate, usageRate, usageRate, error) {
	var totalRequests, failures, quotaDenials, attemptedRequests, fallbackRequests int64
	var attestationEvents, attestationFailures int64
	err := store.pool.QueryRow(ctx, `
		WITH selected_requests AS (
			SELECT logical_request_id, status, failure_code
			FROM logical_requests
			WHERE organization_id = $1 AND environment_id = $2
			  AND requested_at >= $3 AND requested_at < $4
		), request_counts AS (
			SELECT count(*)::bigint AS total,
			       count(*) FILTER (WHERE status = 'failed')::bigint AS failures,
			       count(*) FILTER (WHERE status = 'denied' AND failure_code = 'quota_exceeded')::bigint AS quota_denials
			FROM selected_requests
		), attempt_counts AS (
			SELECT count(*)::bigint AS attempted,
			       count(*) FILTER (WHERE distinct_routes > 1)::bigint AS fallback
			FROM (
				SELECT selected_requests.logical_request_id, count(DISTINCT attempt.route_key) AS distinct_routes
				FROM selected_requests
				JOIN upstream_attempts attempt
				  ON attempt.organization_id = $1 AND attempt.environment_id = $2
				 AND attempt.logical_request_id = selected_requests.logical_request_id
				GROUP BY selected_requests.logical_request_id
			) attempted
		), attestation_counts AS (
			SELECT count(*)::bigint AS total,
			       count(*) FILTER (WHERE outcome IN ('rejected', 'error'))::bigint AS failures
			FROM attestation_events
			WHERE organization_id = $1 AND environment_id = $2
			  AND occurred_at >= $3 AND occurred_at < $4
		)
		SELECT request_counts.total, request_counts.failures, request_counts.quota_denials,
		       attempt_counts.attempted, attempt_counts.fallback,
		       attestation_counts.total, attestation_counts.failures
		FROM request_counts CROSS JOIN attempt_counts CROSS JOIN attestation_counts
	`, organizationID, environmentID, start.UTC(), end.UTC()).Scan(
		&totalRequests, &failures, &quotaDenials, &attemptedRequests, &fallbackRequests,
		&attestationEvents, &attestationFailures,
	)
	if err != nil {
		return usageRate{}, usageRate{}, usageRate{}, usageRate{}, fmt.Errorf("aggregate usage rates: %w", err)
	}
	return newUsageRate(failures, totalRequests), newUsageRate(quotaDenials, totalRequests),
		newUsageRate(attestationFailures, attestationEvents),
		newUsageRate(fallbackRequests, attemptedRequests), nil
}

func (store *operationalStore) usageProvenanceBreakdown(
	ctx context.Context, organizationID, environmentID string, start, end time.Time,
) ([]usageProvenanceItem, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT confidence, metric, COALESCE(sum(units), 0)::bigint
		FROM usage_records
		WHERE organization_id = $1 AND environment_id = $2
		  AND recorded_at >= $3 AND recorded_at < $4
		GROUP BY confidence, metric
	`, organizationID, environmentID, start.UTC(), end.UTC())
	if err != nil {
		return nil, fmt.Errorf("query usage provenance: %w", err)
	}
	defer rows.Close()
	values := map[string]usageValues{
		"upstream_reported": {}, "calculated": {}, "estimated": {}, "unknown": {},
	}
	for rows.Next() {
		var confidence, metric string
		var units int64
		if err := rows.Scan(&confidence, &metric, &units); err != nil {
			return nil, fmt.Errorf("scan usage provenance: %w", err)
		}
		provenance := publicUsageProvenance(confidence)
		current := values[provenance]
		if !addUsageMetric(&current, metric, units) {
			return nil, errOperationalCorrupt
		}
		values[provenance] = current
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate usage provenance: %w", err)
	}
	order := []string{"upstream_reported", "calculated", "estimated", "unknown"}
	result := make([]usageProvenanceItem, 0, len(order))
	for _, provenance := range order {
		result = append(result, usageProvenanceItem{Provenance: provenance, Values: values[provenance]})
	}
	return result, nil
}

func addUsageMetric(values *usageValues, metric string, units int64) bool {
	if values == nil || units < 0 {
		return false
	}
	var destination *int64
	switch metric {
	case "logical_requests":
		destination = &values.LogicalRequests
	case "input_tokens":
		destination = &values.InputTokens
	case "output_tokens":
		destination = &values.OutputTokens
	case "total_tokens":
		destination = &values.TotalTokens
	case "cost_nano_usd":
		destination = &values.CostNanoUSD
	default:
		return false
	}
	if *destination > math.MaxInt64-units {
		return false
	}
	*destination += units
	return true
}

func newUsageRate(numerator, denominator int64) usageRate {
	rate := usageRate{Numerator: numerator, Denominator: denominator}
	if numerator < 0 || denominator <= 0 || numerator > denominator {
		return rate
	}
	product := new(big.Int).Mul(big.NewInt(numerator), big.NewInt(1_000_000))
	product.Quo(product, big.NewInt(denominator))
	if product.IsInt64() {
		rate.PartsPerMillion = product.Int64()
	}
	return rate
}
