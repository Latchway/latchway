package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/useroverride"
)

func (api *API) users(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The user-list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	page, err := parseOperationalPage(r, id.ApplicationUser)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listUsers(r.Context(), mustPrincipal(r.Context()), environmentID, page)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item useroverride.ApplicationUser) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) user(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id") {
		api.writeProblem(w, r, invalidRequest("The user query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	item, err := api.operations.getUser(
		r.Context(), mustPrincipal(r.Context()), environmentID, chi.URLParam(r, "userID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) blockUser(w http.ResponseWriter, r *http.Request) {
	api.setUserBlocked(w, r, true)
}

func (api *API) unblockUser(w http.ResponseWriter, r *http.Request) {
	api.setUserBlocked(w, r, false)
}

func (api *API) setUserBlocked(w http.ResponseWriter, r *http.Request, blocked bool) {
	if !onlyQueryKeys(r, "environment_id") {
		api.writeProblem(w, r, invalidRequest("The user mutation query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.setUserBlocked(
		r.Context(), mustPrincipal(r.Context()), environmentID,
		chi.URLParam(r, "userID"), blocked, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) installations(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The installation-list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	page, err := parseOperationalPage(r, id.Installation)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listInstallations(r.Context(), mustPrincipal(r.Context()), environmentID, page)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item installationDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) installation(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The installation query is invalid."))
		return
	}
	item, err := api.operations.getInstallation(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "installationID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type revokeInstallationRequest struct {
	Reason string `json:"reason"`
}

func (api *API) revokeInstallation(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The installation revocation query is invalid."))
		return
	}
	var request revokeInstallationRequest
	var err error
	if r.ContentLength != 0 {
		request, err = decodeJSON[revokeInstallationRequest](r)
		if err != nil {
			api.writeProblem(w, r, invalidRequest("The installation revocation request is invalid."))
			return
		}
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.revokeInstallation(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "installationID"),
		request.Reason, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) requests(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The request-list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	page, err := parseOperationalPage(r, id.LogicalRequest)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listRequests(r.Context(), mustPrincipal(r.Context()), environmentID, page)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item logicalRequestDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.StartedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) request(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The request query is invalid."))
		return
	}
	item, err := api.operations.getRequest(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "requestID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) usageSummary(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "start", "end") {
		api.writeProblem(w, r, invalidRequest("The usage-summary query is invalid."))
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
	document, err := api.operations.usageSummary(
		r.Context(), mustPrincipal(r.Context()), environmentID, start, end,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (api *API) usageTimeseries(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "start", "end", "interval") {
		api.writeProblem(w, r, invalidRequest("The usage-timeseries query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	interval, ok := requiredQueryValue(r, "interval")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The usage interval is required."))
		return
	}
	start, end, ok := parseUsageRange(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The usage time range is invalid."))
		return
	}
	document, err := api.operations.usageTimeseries(
		r.Context(), mustPrincipal(r.Context()), environmentID, start, end, interval,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (api *API) auditEvents(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "organization_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The audit-event query is invalid."))
		return
	}
	organizationID, ok := optionalQueryValue(r, "organization_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The organization filter is invalid."))
		return
	}
	page, err := parseOperationalPage(r, id.AuditEvent)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listAuditEvents(
		r.Context(), mustPrincipal(r.Context()), organizationID, page,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item auditEventDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.Timestamp, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

type startSelfTestRequest struct {
	Kind           string `json:"kind"`
	EnvironmentID  string `json:"environment_id"`
	Upstream       string `json:"upstream"`
	Model          string `json:"model"`
	MaxCostNanoUSD int64  `json:"max_cost_nano_usd"`
}

func (api *API) startSelfTest(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The self-test query is invalid."))
		return
	}
	request, err := decodeJSON[startSelfTestRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The self-test request is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	run, err := api.operations.startSelfTest(r.Context(), mustPrincipal(r.Context()), startSelfTestInput{
		Kind: request.Kind, Environment: request.EnvironmentID, Upstream: request.Upstream,
		Model: request.Model, MaxCost: request.MaxCostNanoUSD, RequestID: operationID,
	})
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (api *API) selfTest(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The self-test query is invalid."))
		return
	}
	run, err := api.operations.getSelfTest(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "selfTestID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (api *API) systemStatus(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The system-status query is invalid."))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	ready := true
	databaseVersion := "unknown"
	if err := api.operations.pool.Ping(ctx); err != nil {
		ready = false
	} else {
		current, available, err := database.NewMigrator(api.operations.pool).Status(ctx)
		if err != nil {
			ready = false
		} else {
			databaseVersion = strconv.FormatInt(current, 10)
			ready = current == available
		}
	}
	build := buildinfo.Current()
	writeJSON(w, http.StatusOK, map[string]any{
		"server_version": build.Version, "contract_version": build.ContractVersion,
		"protocol_versions": []int{1}, "role": api.role,
		"database_schema_version": databaseVersion, "ready": ready,
	})
}

func parseOperationalPage(r *http.Request, prefix id.Prefix) (operationalPage, error) {
	if values := r.URL.Query()["cursor"]; len(values) > 1 {
		return operationalPage{}, errOperationalInvalid
	}
	if values := r.URL.Query()["page_size"]; len(values) > 1 {
		return operationalPage{}, errOperationalInvalid
	}
	parsed, err := parsePageRequest(r, prefix)
	if err != nil {
		return operationalPage{}, err
	}
	return operationalPage{after: parsed.After, afterID: parsed.AfterID, size: parsed.Size}, nil
}

func parseUsageRange(r *http.Request) (time.Time, time.Time, bool) {
	startText, startOK := requiredQueryValue(r, "start")
	endText, endOK := requiredQueryValue(r, "end")
	if !startOK || !endOK || len(startText) > 64 || len(endText) > 64 {
		return time.Time{}, time.Time{}, false
	}
	start, startErr := time.Parse(time.RFC3339, startText)
	end, endErr := time.Parse(time.RFC3339, endText)
	if startErr != nil || endErr != nil || !start.Before(end) {
		return time.Time{}, time.Time{}, false
	}
	return start.UTC(), end.UTC(), true
}

func requiredQueryValue(r *http.Request, name string) (string, bool) {
	values, exists := r.URL.Query()[name]
	returnValue, ok := exactQueryValue(values, exists)
	return returnValue, ok && returnValue != ""
}

func optionalQueryValue(r *http.Request, name string) (string, bool) {
	values, exists := r.URL.Query()[name]
	if !exists {
		return "", true
	}
	value, ok := exactQueryValue(values, true)
	return value, ok && value != ""
}

func exactQueryValue(values []string, exists bool) (string, bool) {
	if !exists || len(values) != 1 || len(values[0]) > 2048 {
		return "", false
	}
	return values[0], true
}

func onlyQueryKeys(r *http.Request, allowed ...string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		set[key] = struct{}{}
	}
	for key := range r.URL.Query() {
		if _, ok := set[key]; !ok {
			return false
		}
	}
	return true
}

func (api *API) handleOperationalError(w http.ResponseWriter, r *http.Request, err error, operationID string) {
	switch {
	case errors.Is(err, errOperationalInvalid):
		api.writeProblem(w, r, invalidRequest("The administrative operation is invalid."))
	case errors.Is(err, errOperationalForbidden):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot perform this operation."})
	case errors.Is(err, errOperationalNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The requested tenant-scoped resource was not found."})
	case errors.Is(err, errOperationalIndeterminate):
		if id.Validate(operationID, id.AdminRequest) != nil {
			api.internal(w, r, errors.New("indeterminate operational mutation has no correlation ID"))
			return
		}
		markMutationIndeterminate(r.Context())
		api.writeProblem(w, r, problem.Error{
			Code: "operation_indeterminate", OperationID: operationID,
			Detail: "The database commit outcome is unknown. Preserve the operation ID and reconcile it against the audit log before retrying.",
		})
	default:
		api.internal(w, r, err)
	}
}
