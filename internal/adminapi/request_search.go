package adminapi

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

const (
	requestTotalCap            = 100_000
	maximumRequestFacetRange   = 90 * 24 * time.Hour
	defaultRequestFacetLimit   = 20
	maximumRequestFacetLimit   = 100
	maximumRequestFacetGrouped = 1_000
)

// requestFacetNames lists the facets in response order. Each one matches a
// request-list filter of the same name.
var requestFacetNames = [...]string{
	"status", "feature", "error_code", "upstream", "model", "route",
	"platform", "component_kind", "trust_source", "limit_plan",
}

type requestFacetValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type requestFacetDocument struct {
	Values    []requestFacetValue `json:"values"`
	Truncated bool                `json:"truncated"`
}

type requestFacetsDocument struct {
	EnvironmentID string                          `json:"environment_id"`
	Feature       string                          `json:"feature,omitempty"`
	Start         time.Time                       `json:"start"`
	End           time.Time                       `json:"end"`
	Requests      int64                           `json:"requests"`
	Facets        map[string]requestFacetDocument `json:"facets"`
}

// countRequests counts the requests a filter matches, up to requestTotalCap.
func (store *operationalStore) countRequests(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
	filter requestListFilter,
) (int64, bool, error) {
	if id.Validate(environmentID, id.Environment) != nil || filter.validate() != nil {
		return 0, false, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return 0, false, errOperationalForbidden
	}
	where, arguments := requestListConditions(principal.OrganizationID, environmentID, filter)
	arguments = append(arguments, requestTotalCap+1)
	var count int64
	if err := store.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT count(*) FROM (
			SELECT 1 FROM logical_requests AS request WHERE %s LIMIT $%d
		) AS matched
	`, strings.Join(where, " AND "), len(arguments)), arguments...).Scan(&count); err != nil {
		return 0, false, fmt.Errorf("count logical requests: %w", err)
	}
	if count > requestTotalCap {
		return requestTotalCap, true, nil
	}
	return count, false, nil
}

// requestFacets counts requests started in [start, end) by each filterable
// value. Statuses and failure codes use their public names, so every value
// is one the request-list filters accept.
func (store *operationalStore) requestFacets(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID, feature string,
	start time.Time,
	end time.Time,
	limit int,
) (requestFacetsDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || !start.Before(end) ||
		(feature != "" && !operationalIdentifierPattern.MatchString(feature)) ||
		end.Sub(start) > maximumRequestFacetRange || limit < 1 || limit > maximumRequestFacetLimit {
		return requestFacetsDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return requestFacetsDocument{}, errOperationalForbidden
	}
	if err := store.ensureEnvironment(ctx, principal.OrganizationID, environmentID); err != nil {
		return requestFacetsDocument{}, err
	}
	rows, err := store.pool.Query(ctx, `
		WITH scoped AS MATERIALIZED (
			SELECT request.status, request.feature_key, request.failure_code,
			       request.selected_upstream_key, request.selected_model_key,
			       request.selected_route_key, request.component_kind, request.trust_source,
			       request.selected_limit_plan_key,
			       (
			           SELECT installation.platform FROM installations AS installation
			           WHERE installation.installation_id = request.installation_id
			             AND installation.organization_id = request.organization_id
			       ) AS platform
			FROM logical_requests AS request
			WHERE request.organization_id = $1 AND request.environment_id = $2
			  AND request.requested_at >= $3 AND request.requested_at < $4
			  AND ($6 = '' OR request.feature_key = $6)
		), grouped AS (
			SELECT 'status' AS facet, status AS value, count(*) AS matched FROM scoped GROUP BY status
			UNION ALL
			SELECT 'feature', feature_key, count(*) FROM scoped GROUP BY feature_key
			UNION ALL
			SELECT 'error_code', failure_code, count(*) FROM scoped
			WHERE failure_code IS NOT NULL GROUP BY failure_code
			UNION ALL
			SELECT 'upstream', selected_upstream_key, count(*) FROM scoped
			WHERE selected_upstream_key IS NOT NULL GROUP BY selected_upstream_key
			UNION ALL
			SELECT 'model', selected_model_key, count(*) FROM scoped
			WHERE selected_model_key IS NOT NULL GROUP BY selected_model_key
			UNION ALL
			SELECT 'route', selected_route_key, count(*) FROM scoped
			WHERE selected_route_key IS NOT NULL GROUP BY selected_route_key
			UNION ALL
			SELECT 'platform', platform, count(*) FROM scoped
			WHERE platform IS NOT NULL GROUP BY platform
			UNION ALL
			SELECT 'component_kind', component_kind, count(*) FROM scoped
			WHERE component_kind IS NOT NULL GROUP BY component_kind
			UNION ALL
			SELECT 'trust_source', trust_source, count(*) FROM scoped
			WHERE trust_source IS NOT NULL GROUP BY trust_source
			UNION ALL
			SELECT 'limit_plan', selected_limit_plan_key, count(*) FROM scoped GROUP BY selected_limit_plan_key
		)
		SELECT facet, value, matched,
		       (SELECT count(*) FROM scoped) AS requests,
		       count(*) OVER (PARTITION BY facet) AS distinct_values
		FROM (
			SELECT facet, value, matched,
			       row_number() OVER (PARTITION BY facet ORDER BY matched DESC, value) AS position
			FROM grouped
		) AS ranked
		WHERE position <= $5
		ORDER BY facet, matched DESC, value
	`, principal.OrganizationID, environmentID, start, end, maximumRequestFacetGrouped, feature)
	if err != nil {
		return requestFacetsDocument{}, fmt.Errorf("count request facets: %w", err)
	}
	defer rows.Close()
	merged := make(map[string]map[string]int64, len(requestFacetNames))
	overflow := make(map[string]bool, len(requestFacetNames))
	document := requestFacetsDocument{
		EnvironmentID: environmentID, Feature: feature, Start: start.UTC(), End: end.UTC(),
		Facets: make(map[string]requestFacetDocument, len(requestFacetNames)),
	}
	for rows.Next() {
		var facet, value string
		var matched, distinct int64
		if err := rows.Scan(&facet, &value, &matched, &document.Requests, &distinct); err != nil {
			return requestFacetsDocument{}, fmt.Errorf("scan request facet: %w", err)
		}
		switch facet {
		case "status":
			value = publicLogicalRequestStatus(value)
		case "error_code":
			value = *publicLogicalFailureCode(&value)
		case "model":
			if !validOperationalText(value, 512) {
				return requestFacetsDocument{}, errOperationalCorrupt
			}
		default:
			if !operationalIdentifierPattern.MatchString(value) {
				return requestFacetsDocument{}, errOperationalCorrupt
			}
		}
		if merged[facet] == nil {
			merged[facet] = make(map[string]int64)
		}
		merged[facet][value] += matched
		overflow[facet] = overflow[facet] || distinct > maximumRequestFacetGrouped
	}
	if err := rows.Err(); err != nil {
		return requestFacetsDocument{}, fmt.Errorf("iterate request facets: %w", err)
	}
	for _, facet := range requestFacetNames {
		values := make([]requestFacetValue, 0, len(merged[facet]))
		for value, count := range merged[facet] {
			values = append(values, requestFacetValue{Value: value, Count: count})
		}
		slices.SortFunc(values, func(left, right requestFacetValue) int {
			return cmp.Or(cmp.Compare(right.Count, left.Count), strings.Compare(left.Value, right.Value))
		})
		truncated := overflow[facet] || len(values) > limit
		if len(values) > limit {
			values = values[:limit]
		}
		document.Facets[facet] = requestFacetDocument{Values: values, Truncated: truncated}
	}
	return document, nil
}

func (api *API) requestFacets(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "start", "end", "limit", "feature") {
		api.writeProblem(w, r, invalidRequest("The request-facets query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	rawStart, startOK := requiredQueryValue(r, "start")
	rawEnd, endOK := requiredQueryValue(r, "end")
	if !startOK || !endOK {
		api.writeProblem(w, r, invalidRequest("The request-facets range needs a start and an end."))
		return
	}
	start, startErr := parseRequestFilterTime(rawStart)
	end, endErr := parseRequestFilterTime(rawEnd)
	if startErr != nil || endErr != nil || !start.Before(end) || end.Sub(start) > maximumRequestFacetRange {
		api.writeProblem(w, r, invalidRequest("The request-facets range must be RFC 3339 times, start before end, at most 90 days apart."))
		return
	}
	feature, ok := optionalQueryValue(r, "feature")
	if !ok || (feature != "" && !operationalIdentifierPattern.MatchString(feature)) {
		api.writeProblem(w, r, invalidRequest("The request-facets feature is invalid."))
		return
	}
	limit := defaultRequestFacetLimit
	if raw, ok := optionalQueryValue(r, "limit"); !ok {
		api.writeProblem(w, r, invalidRequest("The request-facets limit is invalid."))
		return
	} else if raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maximumRequestFacetLimit {
			api.writeProblem(w, r, invalidRequest("The request-facets limit must be between 1 and 100."))
			return
		}
		limit = parsed
	}
	document, err := api.operations.requestFacets(r.Context(), mustPrincipal(r.Context()), environmentID, feature, start, end, limit)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}
