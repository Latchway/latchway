package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/useroverride"
)

const (
	maximumDistributionRange   = 90 * 24 * time.Hour
	maximumDistributionPeriods = 2_000
)

// distributionMetrics are the usage-record metrics a per-subject distribution
// can sum. Concurrency and byte metrics have no per-window total.
var distributionMetrics = []string{
	"logical_requests", "upstream_attempts", "input_tokens", "output_tokens", "total_tokens",
	"reasoning_tokens", "cached_input_tokens", "cache_write_tokens", "cost_nano_usd",
}

// distributionScopes are the limit scope dimensions a distribution can group
// by, in canonical order.
var distributionScopes = []string{"user", "feature", "installation"}

// distributionEdges are 1-2-5 bucket boundaries for peak usage per window.
var distributionEdges = func() []int64 {
	edges := []int64{1}
	for edges[len(edges)-1] < 1_000_000_000_000_000 {
		last := edges[len(edges)-1]
		switch last / pow10(digits(last)-1) {
		case 1:
			edges = append(edges, last*2)
		case 2:
			edges = append(edges, last/2*5)
		default:
			edges = append(edges, last*2)
		}
	}
	return edges
}()

func digits(value int64) int {
	count := 1
	for value >= 10 {
		value /= 10
		count++
	}
	return count
}

func pow10(exponent int) int64 {
	result := int64(1)
	for range exponent {
		result *= 10
	}
	return result
}

type usageDistributionQuery struct {
	EnvironmentID string
	Metric        string
	Window        string
	Timezone      string
	Start, End    time.Time
	Feature       string
	LimitPlan     string
	Scope         []string
	Maximum       *int64
}

type distributionBucket struct {
	From     int64  `json:"from"`
	To       *int64 `json:"to,omitempty"`
	Subjects int64  `json:"subjects"`
}

type distributionPeaks struct {
	P50 int64 `json:"p50"`
	P90 int64 `json:"p90"`
	P99 int64 `json:"p99"`
	Max int64 `json:"max"`
}

type usageDistributionDocument struct {
	EnvironmentID string               `json:"environment_id"`
	Metric        string               `json:"metric"`
	Window        string               `json:"window"`
	Timezone      string               `json:"timezone"`
	Start         time.Time            `json:"start"`
	End           time.Time            `json:"end"`
	Feature       string               `json:"feature,omitempty"`
	LimitPlan     string               `json:"limit_plan,omitempty"`
	Scope         []string             `json:"scope"`
	Periods       int                  `json:"periods"`
	Subjects      int64                `json:"subjects"`
	Users         int64                `json:"users"`
	Peaks         distributionPeaks    `json:"peaks"`
	Histogram     []distributionBucket `json:"histogram"`
	Maximum       *int64               `json:"maximum,omitempty"`
	OverSubjects  *int64               `json:"over_subjects,omitempty"`
	OverUsers     *int64               `json:"over_users,omitempty"`
}

func parseUsageDistributionQuery(r *http.Request) (usageDistributionQuery, bool) {
	if !onlyQueryKeys(r, "environment_id", "metric", "window", "timezone", "start", "end", "feature", "limit_plan", "scope", "maximum") {
		return usageDistributionQuery{}, false
	}
	values := make(map[string]string, 10)
	for _, name := range []string{"environment_id", "metric", "window", "timezone", "start", "end", "feature", "limit_plan", "scope", "maximum"} {
		value, ok := optionalQueryValue(r, name)
		if !ok {
			return usageDistributionQuery{}, false
		}
		values[name] = value
	}
	query := usageDistributionQuery{
		EnvironmentID: values["environment_id"], Metric: values["metric"], Window: values["window"],
		Timezone: values["timezone"], Feature: values["feature"], LimitPlan: values["limit_plan"],
	}
	if query.Timezone == "" {
		query.Timezone = "UTC"
	}
	var err error
	if query.Start, err = parseRequestFilterTime(values["start"]); err != nil {
		return usageDistributionQuery{}, false
	}
	if query.End, err = parseRequestFilterTime(values["end"]); err != nil {
		return usageDistributionQuery{}, false
	}
	scope := values["scope"]
	if scope == "" {
		scope = "user"
	}
	for _, dimension := range strings.Split(scope, ",") {
		if !slices.Contains(distributionScopes, dimension) || slices.Contains(query.Scope, dimension) {
			return usageDistributionQuery{}, false
		}
		query.Scope = append(query.Scope, dimension)
	}
	slices.SortFunc(query.Scope, func(left, right string) int {
		return slices.Index(distributionScopes, left) - slices.Index(distributionScopes, right)
	})
	if raw := values["maximum"]; raw != "" {
		maximum, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || maximum < 0 {
			return usageDistributionQuery{}, false
		}
		query.Maximum = &maximum
	}
	return query, id.Validate(query.EnvironmentID, id.Environment) == nil &&
		slices.Contains(distributionMetrics, query.Metric) &&
		query.Start.Before(query.End) && query.End.Sub(query.Start) <= maximumDistributionRange &&
		(query.Feature == "" || operationalIdentifierPattern.MatchString(query.Feature)) &&
		(query.LimitPlan == "" || operationalIdentifierPattern.MatchString(query.LimitPlan))
}

// usageDistribution sums usage per subject (the scope's dimensions) in each
// calendar window of the limit's window and timezone, and describes each
// subject's busiest window: how many subjects there are, peak percentiles, a
// 1-2-5 histogram, and how many would have exceeded maximum. No subject
// identifiers leave the server.
func (store *operationalStore) usageDistribution(ctx context.Context, principal adminauth.Principal, query usageDistributionQuery) (usageDistributionDocument, error) {
	if !validOperationalRead(principal) {
		return usageDistributionDocument{}, errOperationalForbidden
	}
	periods, err := quota.CalendarPeriods(query.Window, query.Timezone, query.Start, query.End, maximumDistributionPeriods)
	if err != nil {
		return usageDistributionDocument{}, errOperationalInvalid
	}
	if err := store.ensureEnvironment(ctx, principal.OrganizationID, query.EnvironmentID); err != nil {
		return usageDistributionDocument{}, err
	}
	starts := make([]time.Time, len(periods))
	ends := make([]time.Time, len(periods))
	for index, period := range periods {
		starts[index], ends[index] = period.Start, period.End
	}
	subject := make([]string, 0, len(query.Scope))
	for _, dimension := range query.Scope {
		switch dimension {
		case "user":
			subject = append(subject, "request.application_user_id")
		case "feature":
			subject = append(subject, "request.feature_key")
		case "installation":
			subject = append(subject, "request.installation_id")
		}
	}
	maximum := int64(-1)
	if query.Maximum != nil {
		maximum = *query.Maximum
	}
	document := usageDistributionDocument{
		EnvironmentID: query.EnvironmentID, Metric: query.Metric, Window: query.Window, Timezone: query.Timezone,
		Start: query.Start, End: query.End, Feature: query.Feature, LimitPlan: query.LimitPlan,
		Scope: query.Scope, Periods: len(periods), Maximum: query.Maximum, Histogram: make([]distributionBucket, 0),
	}
	// The subject expression is built from closed column names only; every
	// value is bound.
	rows, err := store.pool.Query(ctx, fmt.Sprintf(`
		WITH periods AS (
			SELECT * FROM unnest($4::timestamptz[], $5::timestamptz[]) AS period(starts_at, ends_at)
		), measured AS (
			SELECT concat_ws('|', %s) AS subject, request.application_user_id AS user_id,
			       period.starts_at, sum(usage.units) AS used
			FROM usage_records AS usage
			JOIN logical_requests AS request ON request.logical_request_id = usage.logical_request_id
			JOIN periods AS period ON request.requested_at >= period.starts_at AND request.requested_at < period.ends_at
			WHERE usage.organization_id = $1 AND usage.environment_id = $2 AND usage.metric = $3
			  AND request.organization_id = $1 AND request.environment_id = $2
			  AND ($6 = '' OR request.feature_key = $6)
			  AND ($7 = '' OR request.selected_limit_plan_key = $7)
			GROUP BY 1, 2, 3
		), peaks AS (
			SELECT subject, min(user_id) AS user_id, max(used) AS peak FROM measured GROUP BY subject
		)
		SELECT 'summary' AS kind, count(*)::bigint, count(DISTINCT user_id)::bigint,
		       COALESCE(percentile_disc(0.5) WITHIN GROUP (ORDER BY peak), 0)::bigint,
		       COALESCE(percentile_disc(0.9) WITHIN GROUP (ORDER BY peak), 0)::bigint,
		       COALESCE(percentile_disc(0.99) WITHIN GROUP (ORDER BY peak), 0)::bigint,
		       COALESCE(max(peak), 0)::bigint,
		       count(*) FILTER (WHERE $8 >= 0 AND peak > $8)::bigint,
		       count(DISTINCT user_id) FILTER (WHERE $8 >= 0 AND peak > $8)::bigint
		FROM peaks
		UNION ALL
		SELECT 'bucket', width_bucket(peak::bigint, $9::bigint[])::bigint, count(*)::bigint, 0, 0, 0, 0, 0, 0
		FROM peaks GROUP BY 2
		ORDER BY 1 DESC, 2
	`, strings.Join(subject, ", ")),
		principal.OrganizationID, query.EnvironmentID, query.Metric, starts, ends,
		query.Feature, query.LimitPlan, maximum, distributionEdges)
	if err != nil {
		return usageDistributionDocument{}, fmt.Errorf("query usage distribution: %w", err)
	}
	defer rows.Close()
	var overSubjects, overUsers int64
	for rows.Next() {
		var kind string
		var first, second, p50, p90, p99, peak, over, overUserCount int64
		if err := rows.Scan(&kind, &first, &second, &p50, &p90, &p99, &peak, &over, &overUserCount); err != nil {
			return usageDistributionDocument{}, fmt.Errorf("scan usage distribution: %w", err)
		}
		if kind == "summary" {
			document.Subjects, document.Users = first, second
			document.Peaks = distributionPeaks{P50: p50, P90: p90, P99: p99, Max: peak}
			overSubjects, overUsers = over, overUserCount
			continue
		}
		// width_bucket returns 0 below the first edge and len(edges) at or
		// above the last.
		bucket := distributionBucket{Subjects: second}
		if first > 0 {
			bucket.From = distributionEdges[first-1]
		}
		if first < int64(len(distributionEdges)) {
			to := distributionEdges[first]
			bucket.To = &to
		}
		document.Histogram = append(document.Histogram, bucket)
	}
	if err := rows.Err(); err != nil {
		return usageDistributionDocument{}, fmt.Errorf("iterate usage distribution: %w", err)
	}
	if query.Maximum != nil {
		document.OverSubjects, document.OverUsers = &overSubjects, &overUsers
	}
	return document, nil
}

func (api *API) usageDistribution(w http.ResponseWriter, r *http.Request) {
	query, ok := parseUsageDistributionQuery(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The usage-distribution query is invalid: it needs an environment, a metric, a calendar window, and a range of at most 90 days."))
		return
	}
	document, err := api.operations.usageDistribution(r.Context(), mustPrincipal(r.Context()), query)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

// userOverrideDocument is one limit-plan override, current or ended.
type userOverrideDocument struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	LimitPlan string     `json:"limit_plan"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type userOverrideFilter struct {
	status    string
	limitPlan string
	userID    string
	page      operationalPage
}

// listUserOverrides lists limit-plan overrides newest first. "active" is
// unrevoked and unexpired, "ended" is revoked or expired.
func (store *operationalStore) listUserOverrides(ctx context.Context, principal adminauth.Principal, environmentID string, filter userOverrideFilter) ([]userOverrideDocument, error) {
	if !validOperationalRead(principal) {
		return nil, errOperationalForbidden
	}
	if id.Validate(environmentID, id.Environment) != nil || filter.page.validate(id.UserOverride) != nil {
		return nil, errOperationalInvalid
	}
	if err := store.ensureEnvironment(ctx, principal.OrganizationID, environmentID); err != nil {
		return nil, err
	}
	var after any
	var afterID any
	if !filter.page.after.IsZero() {
		after, afterID = filter.page.after, filter.page.afterID
	}
	rows, err := store.pool.Query(ctx, `
		SELECT override.user_override_id, override.application_user_id, override.override_document,
		       override.reason, override.created_by_admin_user_id, override.created_at,
		       override.expires_at, override.revoked_at,
		       CASE
		           WHEN override.revoked_at IS NOT NULL THEN 'revoked'
		           WHEN override.expires_at IS NOT NULL AND override.expires_at <= statement_timestamp() THEN 'expired'
		           ELSE 'active'
		       END
		FROM user_overrides AS override
		WHERE override.organization_id = $1 AND override.environment_id = $2
		  AND ($3 = '' OR ($3 = 'active') = (override.revoked_at IS NULL AND (override.expires_at IS NULL OR override.expires_at > statement_timestamp())))
		  AND ($4 = '' OR override.override_document ->> 'limit_plan' = $4)
		  AND ($5 = '' OR override.application_user_id = $5)
		  AND ($6::timestamptz IS NULL OR (override.created_at, override.user_override_id) < ($6, $7::text))
		ORDER BY override.created_at DESC, override.user_override_id DESC
		LIMIT $8
	`, principal.OrganizationID, environmentID, filter.status, filter.limitPlan, filter.userID, after, afterID, filter.page.size+1)
	if err != nil {
		return nil, fmt.Errorf("list user overrides: %w", err)
	}
	defer rows.Close()
	items := make([]userOverrideDocument, 0, filter.page.size+1)
	for rows.Next() {
		var item userOverrideDocument
		var document []byte
		if err := rows.Scan(&item.ID, &item.UserID, &document, &item.Reason, &item.CreatedBy, &item.CreatedAt,
			&item.ExpiresAt, &item.RevokedAt, &item.Status); err != nil {
			return nil, fmt.Errorf("scan user override: %w", err)
		}
		decoded, err := useroverride.Decode(document)
		if err != nil {
			return nil, errOperationalCorrupt
		}
		item.LimitPlan = decoded.LimitPlan
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user overrides: %w", err)
	}
	return items, nil
}

func (api *API) userOverrides(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "status", "limit_plan", "user_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The user-override query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	var filter userOverrideFilter
	for name, target := range map[string]*string{"status": &filter.status, "limit_plan": &filter.limitPlan, "user_id": &filter.userID} {
		value, valueOK := optionalQueryValue(r, name)
		if !valueOK {
			api.writeProblem(w, r, invalidRequest("The user-override filters are invalid."))
			return
		}
		*target = value
	}
	if (filter.status != "" && filter.status != "active" && filter.status != "ended") ||
		(filter.limitPlan != "" && !operationalIdentifierPattern.MatchString(filter.limitPlan)) ||
		(filter.userID != "" && id.Validate(filter.userID, id.ApplicationUser) != nil) {
		api.writeProblem(w, r, invalidRequest("The user-override filters are invalid: status is active or ended."))
		return
	}
	page, err := parseOperationalPage(r, id.UserOverride)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	filter.page = page
	items, err := api.operations.listUserOverrides(r.Context(), mustPrincipal(r.Context()), environmentID, filter)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item userOverrideDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}
