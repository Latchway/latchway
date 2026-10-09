package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

// userUsageDocument is one user's usage for requests started in a range.
type userUsageDocument struct {
	UserID     string      `json:"user_id"`
	Start      time.Time   `json:"start"`
	End        time.Time   `json:"end"`
	Requests   int64       `json:"request_count"`
	Values     usageValues `json:"values"`
	Provenance []string    `json:"provenance"`
}

func (api *API) userUsage(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "start", "end") {
		api.writeProblem(w, r, invalidRequest("The user-usage query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	start, end, ok := parseUsageRange(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The usage time range is invalid."))
		return
	}
	document, err := api.operations.userUsage(r.Context(), mustPrincipal(r.Context()), environmentID, chi.URLParam(r, "userID"), start, end)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (store *operationalStore) userUsage(ctx context.Context, principal adminauth.Principal, environmentID, userID string, start, end time.Time) (userUsageDocument, error) {
	if id.Validate(environmentID, id.Environment) != nil || id.Validate(userID, id.ApplicationUser) != nil || !validUsageRange(start, end, maximumSummaryRange) {
		return userUsageDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return userUsageDocument{}, errOperationalForbidden
	}
	if _, err := queryApplicationUser(ctx, store.pool, principal.OrganizationID, environmentID, userID); err != nil {
		return userUsageDocument{}, err
	}
	document := userUsageDocument{UserID: userID, Start: start.UTC(), End: end.UTC()}
	var confidences []string
	var detailsJSON []byte
	if err := store.pool.QueryRow(ctx, `
		SELECT count(DISTINCT request.logical_request_id)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'logical_requests'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'input_tokens'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'output_tokens'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'total_tokens'), 0)::bigint,
		       COALESCE(sum(usage.units) FILTER (WHERE usage.metric = 'cost_nano_usd'), 0)::bigint,
		       COALESCE(array_agg(DISTINCT usage.confidence) FILTER (WHERE usage.confidence IS NOT NULL), ARRAY[]::text[]),
		       `+usageDetailsSQL("usage.")+`
		FROM logical_requests AS request
		LEFT JOIN usage_records AS usage
		  ON usage.organization_id = request.organization_id
		 AND usage.environment_id = request.environment_id
		 AND usage.logical_request_id = request.logical_request_id
		WHERE request.organization_id = $1 AND request.environment_id = $2
		  AND request.application_user_id = $3
		  AND request.requested_at >= $4 AND request.requested_at < $5
	`, principal.OrganizationID, environmentID, userID, start.UTC(), end.UTC()).Scan(
		&document.Requests, &document.Values.LogicalRequests, &document.Values.InputTokens, &document.Values.OutputTokens,
		&document.Values.TotalTokens, &document.Values.CostNanoUSD, &confidences, &detailsJSON,
	); err != nil {
		return userUsageDocument{}, fmt.Errorf("aggregate user usage: %w", err)
	}
	details, err := decodeUsageDetails(detailsJSON)
	if err != nil {
		return userUsageDocument{}, err
	}
	document.Values.Details = details
	document.Provenance = normalizeProvenance(confidences)
	return document, nil
}

// operationImpactCounts are the credentials an installation or component
// action ends now.
type operationImpactCounts struct {
	ActiveComponents     int64      `json:"active_components"`
	ActiveSessions       int64      `json:"active_sessions"`
	ActiveRefreshTokens  int64      `json:"active_refresh_tokens"`
	DelegatedComponents  int64      `json:"delegated_components"`
	RequestsLast24Hours  int64      `json:"requests_last_24_hours"`
	RequestsLast24Capped bool       `json:"requests_last_24_hours_capped"`
	LastSeenAt           *time.Time `json:"last_seen_at,omitempty"`
}

// operationImpactDocument previews an installation or component action. It
// changes nothing; the action itself re-checks state.
type operationImpactDocument struct {
	Action     string                `json:"action"`
	Applicable bool                  `json:"applicable"`
	Status     string                `json:"current_status"`
	Summary    string                `json:"summary"`
	Counts     operationImpactCounts `json:"counts"`
}

const impactRequestCap = 10_000

func (api *API) installationFamilyImpact(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "action") {
		api.writeProblem(w, r, invalidRequest("The installation impact query is invalid."))
		return
	}
	action, ok := requiredQueryValue(r, "action")
	if !ok || (action != "revoke" && action != "require_renewal") {
		api.writeProblem(w, r, invalidRequest("The action is revoke or require_renewal."))
		return
	}
	document, err := api.operations.familyImpact(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "familyID"), action)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (api *API) clientComponentImpact(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "action") {
		api.writeProblem(w, r, invalidRequest("The component impact query is invalid."))
		return
	}
	action, ok := requiredQueryValue(r, "action")
	if !ok || (action != "revoke" && action != "require_reattestation") {
		api.writeProblem(w, r, invalidRequest("The action is revoke or require_reattestation."))
		return
	}
	document, err := api.operations.componentImpact(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "componentID"), action)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

// impactScope counts what a family or component action would end. With
// componentID empty it covers the whole family.
func (store *operationalStore) impactScope(ctx context.Context, organizationID, familyID, componentID string) (operationImpactCounts, error) {
	var counts operationImpactCounts
	err := store.pool.QueryRow(ctx, `
		WITH RECURSIVE scope AS (
		    SELECT component.client_component_id, component.status, component.last_seen_at
		    FROM client_components AS component
		    WHERE component.organization_id = $1 AND component.installation_family_id = $2
		      AND ($3::text IS NULL OR component.client_component_id = $3)
		    UNION
		    SELECT child.client_component_id, child.status, child.last_seen_at
		    FROM client_components AS child
		    JOIN scope ON child.trust_parent_component_id = scope.client_component_id
		    WHERE child.organization_id = $1 AND child.installation_family_id = $2
		)
		SELECT
		  (SELECT count(*) FROM scope WHERE status = 'active'),
		  (SELECT count(*) FROM component_session_families AS session_family
		   JOIN scope ON scope.client_component_id = session_family.client_component_id
		   WHERE session_family.status = 'active'),
		  (SELECT count(*) FROM component_refresh_tokens AS token
		   JOIN scope ON scope.client_component_id = token.client_component_id
		   WHERE token.status IN ('staged', 'active')),
		  (SELECT count(*) FROM scope WHERE $3::text IS NOT NULL AND client_component_id <> $3 AND status = 'active'),
		  (SELECT count(*) FROM (
		       SELECT 1 FROM logical_requests AS request
		       WHERE request.organization_id = $1 AND request.installation_family_id = $2
		         AND ($3::text IS NULL OR request.client_component_id IN (SELECT client_component_id FROM scope))
		         AND request.requested_at > transaction_timestamp() - interval '24 hours'
		       LIMIT $4) AS recent),
		  (SELECT max(last_seen_at) FROM scope)
	`, organizationID, familyID, nullableString(componentID), impactRequestCap+1).Scan(
		&counts.ActiveComponents, &counts.ActiveSessions, &counts.ActiveRefreshTokens,
		&counts.DelegatedComponents, &counts.RequestsLast24Hours, &counts.LastSeenAt,
	)
	if err != nil {
		return operationImpactCounts{}, fmt.Errorf("count operation impact: %w", err)
	}
	if counts.RequestsLast24Hours > impactRequestCap {
		counts.RequestsLast24Hours, counts.RequestsLast24Capped = impactRequestCap, true
	}
	return counts, nil
}

func (store *operationalStore) familyImpact(ctx context.Context, principal adminauth.Principal, familyID, action string) (operationImpactDocument, error) {
	if id.Validate(familyID, id.InstallationFamily) != nil {
		return operationImpactDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return operationImpactDocument{}, errOperationalForbidden
	}
	var applicationID, status string
	err := store.pool.QueryRow(ctx, `
		SELECT application_id, status FROM installation_families WHERE organization_id = $1 AND installation_family_id = $2
	`, principal.OrganizationID, familyID).Scan(&applicationID, &status)
	if err != nil {
		return operationImpactDocument{}, mapImpactLookup(err)
	}
	if !principal.AllowsIn(adminauth.RevokeInstallations, applicationID, adminauth.AuthorizationContext{}) {
		return operationImpactDocument{}, errOperationalForbidden
	}
	counts, err := store.impactScope(ctx, principal.OrganizationID, familyID, "")
	if err != nil {
		return operationImpactDocument{}, err
	}
	document := operationImpactDocument{Action: action, Applicable: status == "active", Status: status, Counts: counts}
	switch {
	case !document.Applicable:
		document.Summary = "This installation is already revoked."
	case action == "revoke":
		document.Summary = fmt.Sprintf("Ends %d active parts, %d sessions and %d refresh tokens now. The app has to verify as a new installation to keep working.", counts.ActiveComponents, counts.ActiveSessions, counts.ActiveRefreshTokens)
	default:
		document.Summary = fmt.Sprintf("Ends %d sessions and %d refresh tokens now; the app renews its trust on its next request and keeps its installation.", counts.ActiveSessions, counts.ActiveRefreshTokens)
	}
	return document, nil
}

func (store *operationalStore) componentImpact(ctx context.Context, principal adminauth.Principal, componentID, action string) (operationImpactDocument, error) {
	if id.Validate(componentID, id.ClientComponent) != nil {
		return operationImpactDocument{}, errOperationalInvalid
	}
	if !validOperationalRead(principal) {
		return operationImpactDocument{}, errOperationalForbidden
	}
	var applicationID, familyID, status string
	var root bool
	err := store.pool.QueryRow(ctx, `
		SELECT application_id, installation_family_id, status, is_root FROM client_components WHERE organization_id = $1 AND client_component_id = $2
	`, principal.OrganizationID, componentID).Scan(&applicationID, &familyID, &status, &root)
	if err != nil {
		return operationImpactDocument{}, mapImpactLookup(err)
	}
	if !principal.AllowsIn(adminauth.RevokeInstallations, applicationID, adminauth.AuthorizationContext{}) {
		return operationImpactDocument{}, errOperationalForbidden
	}
	counts, err := store.impactScope(ctx, principal.OrganizationID, familyID, componentID)
	if err != nil {
		return operationImpactDocument{}, err
	}
	document := operationImpactDocument{Action: action, Applicable: status == "active" && !(root && action == "revoke"), Status: status, Counts: counts}
	switch {
	case status != "active":
		document.Summary = "This part is no longer active."
	case root && action == "revoke":
		document.Summary = "This is the installation's root part; revoke the installation instead."
	case action == "revoke":
		document.Summary = fmt.Sprintf("Ends this part and the %d parts it delegated to, with %d sessions and %d refresh tokens, now.", counts.DelegatedComponents, counts.ActiveSessions, counts.ActiveRefreshTokens)
	default:
		document.Summary = fmt.Sprintf("Ends %d sessions and %d refresh tokens for this part now; it attests again on its next request.", counts.ActiveSessions, counts.ActiveRefreshTokens)
	}
	return document, nil
}

func mapImpactLookup(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errOperationalNotFound
	}
	return fmt.Errorf("read operation target: %w", err)
}

// maximumUserBatch bounds how many users one batch request covers.
const maximumUserBatch = 100

type userBatchImpactRequest struct {
	Action  string   `json:"action"`
	UserIDs []string `json:"user_ids"`
}

type userBatchImpactItem struct {
	UserID  string               `json:"user_id"`
	Impact  *userOperationImpact `json:"impact,omitempty"`
	Outcome string               `json:"outcome,omitempty"`
}

func validUserBatch(action string, userIDs []string) bool {
	if !validUserOperation(action) || len(userIDs) < 1 || len(userIDs) > maximumUserBatch {
		return false
	}
	seen := make(map[string]bool, len(userIDs))
	for _, userID := range userIDs {
		if id.Validate(userID, id.ApplicationUser) != nil || seen[userID] {
			return false
		}
		seen[userID] = true
	}
	return true
}

// batchOutcome names what happened to one user in a batch.
func batchOutcome(err error) string {
	switch {
	case errors.Is(err, errOperationalConflict):
		return "changed"
	case errors.Is(err, errOperationalNotFound):
		return "not_found"
	case errors.Is(err, errOperationalForbidden):
		return "forbidden"
	default:
		return "failed"
	}
}

// userBatchImpact previews one action for many users. Each applicable user's
// impact token must come back with the batch, so a user whose state changed
// in between is skipped rather than acted on blindly.
func (api *API) userBatchImpact(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id") {
		api.writeProblem(w, r, invalidRequest("The batch impact query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	request, err := decodeJSON[userBatchImpactRequest](r)
	if err != nil || !validUserBatch(request.Action, request.UserIDs) {
		api.writeProblem(w, r, invalidRequest("Send an action and 1 to 100 distinct user IDs."))
		return
	}
	principal := mustPrincipal(r.Context())
	items := make([]userBatchImpactItem, 0, len(request.UserIDs))
	var totals userOperationCounts
	applicable := 0
	for _, userID := range request.UserIDs {
		impact, err := api.operations.previewUserOperation(r.Context(), principal, environmentID, userID, request.Action)
		if err != nil {
			outcome := batchOutcome(err)
			if outcome == "failed" || outcome == "forbidden" {
				api.handleOperationalError(w, r, err, "")
				return
			}
			items = append(items, userBatchImpactItem{UserID: userID, Outcome: outcome})
			continue
		}
		if impact.Applicable {
			applicable++
			totals.ActiveSessionGrants += impact.Counts.ActiveSessionGrants
			totals.ActiveRefreshTokens += impact.Counts.ActiveRefreshTokens
			totals.ActiveComponentSessions += impact.Counts.ActiveComponentSessions
			totals.ActiveComponentRefreshTokens += impact.Counts.ActiveComponentRefreshTokens
			totals.ActiveInstallationFamilies += impact.Counts.ActiveInstallationFamilies
			totals.ActiveClientComponents += impact.Counts.ActiveClientComponents
		}
		items = append(items, userBatchImpactItem{UserID: userID, Impact: &impact})
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": request.Action, "items": items, "applicable": applicable, "totals": totals})
}

type userBatchItem struct {
	UserID      string `json:"user_id"`
	ImpactToken string `json:"impact_token"`
}

type userBatchRequest struct {
	Action                     string          `json:"action"`
	Reason                     string          `json:"reason"`
	AcknowledgeImmediateEffect bool            `json:"acknowledge_immediate_effect"`
	Items                      []userBatchItem `json:"items"`
}

type userBatchResult struct {
	UserID      string `json:"user_id"`
	Outcome     string `json:"outcome"`
	OperationID string `json:"operation_id,omitempty"`
}

// userBatch applies one confirmed action to many users, each in its own
// transaction and audit event, and reports each outcome.
func (api *API) userBatch(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id") {
		api.writeProblem(w, r, invalidRequest("The batch query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	request, err := decodeJSON[userBatchRequest](r)
	userIDs := make([]string, 0, len(request.Items))
	for _, item := range request.Items {
		userIDs = append(userIDs, item.UserID)
	}
	confirmation := confirmedUserOperationRequest{Reason: request.Reason, AcknowledgeImmediateEffect: request.AcknowledgeImmediateEffect}
	if err != nil || !validUserBatch(request.Action, userIDs) || !validConfirmation(confirmation) {
		api.writeProblem(w, r, invalidRequest("Send an action, a reason of up to 500 characters, the acknowledgement, and 1 to 100 users with the impact tokens from the batch preview."))
		return
	}
	if _, err := newMutationOperationID(r.Context()); err != nil {
		api.internal(w, r, err)
		return
	}
	principal := mustPrincipal(r.Context())
	results := make([]userBatchResult, 0, len(request.Items))
	done := 0
	for _, item := range request.Items {
		confirmation.ImpactToken = item.ImpactToken
		if len(item.ImpactToken) != 43 || !operationalTokenPattern(item.ImpactToken) {
			results = append(results, userBatchResult{UserID: item.UserID, Outcome: "changed"})
			continue
		}
		operationID, err := id.New(id.AdminRequest)
		if err != nil {
			api.internal(w, r, err)
			return
		}
		switch request.Action {
		case userOperationBlock, userOperationUnblock:
			_, err = api.operations.setUserBlocked(r.Context(), principal, environmentID, item.UserID, request.Action == userOperationBlock, confirmation, operationID)
		default:
			_, err = api.operations.performConfirmedUserOperation(r.Context(), principal, environmentID, item.UserID, request.Action, confirmation, operationID)
		}
		if err != nil {
			outcome := batchOutcome(err)
			if outcome == "failed" {
				api.logger.ErrorContext(r.Context(), "batch user operation failed", "error_class", fmt.Sprintf("%T", err))
			}
			results = append(results, userBatchResult{UserID: item.UserID, Outcome: outcome})
			continue
		}
		done++
		results = append(results, userBatchResult{UserID: item.UserID, Outcome: "done", OperationID: operationID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": request.Action, "done": done, "results": results})
}
