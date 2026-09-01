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
	confirmation, ok := decodeConfirmedUserOperation(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The confirmed user operation is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.setUserBlocked(
		r.Context(), mustPrincipal(r.Context()), environmentID,
		chi.URLParam(r, "userID"), blocked, confirmation, operationID,
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
	if !onlyQueryKeys(
		r, "environment_id", "cursor", "page_size", "status", "feature", "user_id",
		"platform", "component_kind", "trust_source", "route", "upstream", "model",
		"error_code", "request_id", "start", "end", "latency_min_ms", "latency_max_ms",
		"tokens_min", "tokens_max", "cost_min_nano_usd", "cost_max_nano_usd", "sort",
	) {
		api.writeProblem(w, r, invalidRequest("The request-list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	filter, ok := parseRequestListFilter(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The request-list filters or pagination cursor are invalid."))
		return
	}
	items, err := api.operations.listRequests(r.Context(), mustPrincipal(r.Context()), environmentID, filter)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(filter.page.size), func(item logicalRequestDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.StartedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func parseRequestListFilter(r *http.Request) (requestListFilter, bool) {
	page, err := parseOperationalPage(r, id.LogicalRequest)
	if err != nil {
		return requestListFilter{}, false
	}
	values := make(map[string]string, 14)
	for _, name := range []string{
		"status", "feature", "user_id", "platform", "component_kind", "trust_source",
		"route", "upstream", "model", "error_code", "request_id", "start", "end", "sort",
	} {
		value, ok := optionalQueryValue(r, name)
		if !ok {
			return requestListFilter{}, false
		}
		values[name] = value
	}
	filter := requestListFilter{
		page: page, status: values["status"], feature: values["feature"], userID: values["user_id"],
		platform: values["platform"], componentKind: values["component_kind"], trustSource: values["trust_source"],
		route: values["route"], upstream: values["upstream"], model: values["model"],
		errorCode: values["error_code"], requestID: values["request_id"], sort: values["sort"],
	}
	if filter.sort == "" {
		filter.sort = "started_at_desc"
	}
	if values["start"] != "" {
		filter.start, err = parseRequestFilterTime(values["start"])
		if err != nil {
			return requestListFilter{}, false
		}
	}
	if values["end"] != "" {
		filter.end, err = parseRequestFilterTime(values["end"])
		if err != nil {
			return requestListFilter{}, false
		}
	}
	for name, target := range map[string]**int64{
		"latency_min_ms":    &filter.minimumLatencyMS,
		"latency_max_ms":    &filter.maximumLatencyMS,
		"tokens_min":        &filter.minimumTokens,
		"tokens_max":        &filter.maximumTokens,
		"cost_min_nano_usd": &filter.minimumCost,
		"cost_max_nano_usd": &filter.maximumCost,
	} {
		parsed, ok := parseOptionalRequestInteger(r, name)
		if !ok {
			return requestListFilter{}, false
		}
		*target = parsed
	}
	return filter, filter.validate() == nil
}

func parseRequestFilterTime(value string) (time.Time, error) {
	if len(value) > 64 {
		return time.Time{}, errOperationalInvalid
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errOperationalInvalid
	}
	return parsed.UTC(), nil
}

func parseOptionalRequestInteger(r *http.Request, name string) (*int64, bool) {
	value, ok := optionalQueryValue(r, name)
	if !ok {
		return nil, false
	}
	if value == "" {
		return nil, true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return nil, false
	}
	return &parsed, true
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
	if !onlyQueryKeys(r, "environment_id", "start", "end", "breakdown_limit") {
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
	breakdownLimit := defaultUsageBreakdownLimit
	if raw := r.URL.Query().Get("breakdown_limit"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > maximumUsageBreakdownLimit {
			api.writeProblem(w, r, invalidRequest("The usage breakdown limit must be between 1 and 200."))
			return
		}
		breakdownLimit = parsed
	}
	document, err := api.operations.usageSummary(
		r.Context(), mustPrincipal(r.Context()), environmentID, start, end, breakdownLimit,
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
	if !onlyQueryKeys(r, "organization_id", "environment_id", "actor_kind", "actor_id", "action", "resource_type", "resource_id", "source", "reason", "result", "start", "end", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The audit-event query is invalid."))
		return
	}
	filter, ok := parseAuditFilter(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The audit-event filters are invalid."))
		return
	}
	page, err := parseOperationalPage(r, id.AuditEvent)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listAuditEvents(
		r.Context(), mustPrincipal(r.Context()), filter, page,
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

func (api *API) auditEvent(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The audit-event detail query is invalid."))
		return
	}
	item, err := api.operations.getAuditEvent(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "auditEventID"))
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func parseAuditFilter(r *http.Request) (auditFilter, bool) {
	values := make(map[string]string, 12)
	for _, name := range []string{"organization_id", "environment_id", "actor_kind", "actor_id", "action", "resource_type", "resource_id", "source", "reason", "result", "start", "end"} {
		value, ok := optionalQueryValue(r, name)
		if !ok {
			return auditFilter{}, false
		}
		values[name] = value
	}
	filter := auditFilter{
		OrganizationID: values["organization_id"], EnvironmentID: values["environment_id"],
		ActorKind: values["actor_kind"], ActorID: values["actor_id"], Action: values["action"],
		ResourceType: values["resource_type"], ResourceID: values["resource_id"],
		Source: values["source"], Reason: values["reason"], Result: values["result"],
	}
	var err error
	if values["start"] != "" {
		filter.Start, err = time.Parse(time.RFC3339, values["start"])
		if err != nil {
			return auditFilter{}, false
		}
		filter.Start = filter.Start.UTC()
	}
	if values["end"] != "" {
		filter.End, err = time.Parse(time.RFC3339, values["end"])
		if err != nil {
			return auditFilter{}, false
		}
		filter.End = filter.End.UTC()
	}
	return filter, true
}

type createSelfTestScheduleRequest struct {
	Kind                  string `json:"kind"`
	EnvironmentID         string `json:"environment_id"`
	Upstream              string `json:"upstream"`
	Model                 string `json:"model"`
	MaxCostNanoUSD        int64  `json:"max_cost_nano_usd"`
	DailyCostLimitNanoUSD int64  `json:"daily_cost_limit_nano_usd"`
	IntervalSeconds       int64  `json:"interval_seconds"`
}

func (api *API) selfTestSchedules(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The self-test schedule query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	page, err := parseOperationalPage(r, id.SelfTestSchedule)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listSelfTestSchedules(
		r.Context(), mustPrincipal(r.Context()), environmentID, page,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item selfTestScheduleDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) createSelfTestSchedule(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The self-test schedule query is invalid."))
		return
	}
	request, err := decodeJSON[createSelfTestScheduleRequest](r)
	if err != nil || request.IntervalSeconds < int64(minimumSelfTestScheduleInterval/time.Second) ||
		request.IntervalSeconds > int64(maximumSelfTestScheduleInterval/time.Second) {
		api.writeProblem(w, r, invalidRequest("The self-test schedule request is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	schedule, err := api.operations.createSelfTestSchedule(
		r.Context(), mustPrincipal(r.Context()), createSelfTestScheduleInput{
			Kind: request.Kind, Environment: request.EnvironmentID, Upstream: request.Upstream,
			Model: request.Model, MaxCost: request.MaxCostNanoUSD,
			DailyCostLimit: request.DailyCostLimitNanoUSD,
			Interval:       time.Duration(request.IntervalSeconds) * time.Second,
			RequestID:      operationID,
		},
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusCreated, schedule)
}

func (api *API) selfTestSchedule(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The self-test schedule query is invalid."))
		return
	}
	schedule, err := api.operations.getSelfTestSchedule(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "scheduleID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, schedule)
}

func (api *API) disableSelfTestSchedule(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The self-test schedule query is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	schedule, err := api.operations.disableSelfTestSchedule(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "scheduleID"), operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, schedule)
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
	var ready bool
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
		"protocol_versions": buildinfo.SupportedProtocolVersions(), "role": api.role,
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
	case errors.Is(err, errOperationalConflict):
		api.writeProblem(w, r, problem.Error{
			Code:   "conflict",
			Detail: "The user state changed after the reviewed impact. Load the impact again before retrying.",
		})
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
