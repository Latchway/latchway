package adminapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/id"
)

var familySignals = map[string]bool{
	"any": true, signalDebugTrust: true, signalTrustExpiring: true, signalTokenReuse: true,
	signalWeakKeyStorage: true, signalFailedSessions: true,
}

func parseFamilyListFilter(r *http.Request) (familyListFilter, bool) {
	query := r.URL.Query()
	for _, key := range []string{"status", "platform", "signal", "sort", "include_total"} {
		if len(query[key]) > 1 {
			return familyListFilter{}, false
		}
	}
	filter := familyListFilter{status: query.Get("status"), platform: query.Get("platform"), signal: query.Get("signal"), sort: query.Get("sort")}
	if filter.status != "" && filter.status != "active" && filter.status != "suspended" && filter.status != "revoked" {
		return familyListFilter{}, false
	}
	if filter.platform != "" && !operationalIdentifierPattern.MatchString(filter.platform) {
		return familyListFilter{}, false
	}
	if filter.signal != "" && !familySignals[filter.signal] {
		return familyListFilter{}, false
	}
	if _, _, ok := familyOrdering(filter.sort); !ok {
		return familyListFilter{}, false
	}
	if value := query.Get("include_total"); value != "" && value != "true" {
		return familyListFilter{}, false
	}
	return filter, true
}

func (api *API) installationFamilies(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "user_id", "cursor", "page_size", "status", "platform", "signal", "sort", "include_total") {
		api.writeProblem(w, r, invalidRequest("The installation-family list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	userID, ok := optionalQueryValue(r, "user_id")
	if !ok || (userID != "" && id.Validate(userID, id.ApplicationUser) != nil) {
		api.writeProblem(w, r, invalidRequest("The application-user filter is invalid."))
		return
	}
	filter, ok := parseFamilyListFilter(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The installation filters are invalid: status is active or revoked, signal is any or a signal name, and sort is oldest, newest or recently_seen."))
		return
	}
	page, err := parseOperationalPage(r, id.InstallationFamily)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listInstallationFamilies(
		r.Context(), mustPrincipal(r.Context()), environmentID, userID, filter, page,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item installationFamilyDocument) cursorDocument {
		return cursorDocument{CreatedAt: familySortKey(filter.sort, item), ID: item.ID}
	})
	document := map[string]any{"items": items, "page": pageDocument}
	if r.URL.Query().Get("include_total") == "true" {
		count, capped, err := api.operations.countInstallationFamilies(r.Context(), mustPrincipal(r.Context()), environmentID, userID, filter)
		if err != nil {
			api.handleOperationalError(w, r, err, "")
			return
		}
		document["total"] = map[string]any{"count": count, "capped": capped}
	}
	writeJSON(w, http.StatusOK, document)
}

func (api *API) installationFamily(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The installation-family query is invalid."))
		return
	}
	item, err := api.operations.getInstallationFamily(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "familyID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) revokeInstallationFamily(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The installation-family revocation query is invalid."))
		return
	}
	reason, ok := decodeOperationalRevocationRequest(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The installation-family revocation request is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.revokeInstallationFamily(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "familyID"), reason, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) requireInstallationFamilyRenewal(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The containing-app renewal query is invalid."))
		return
	}
	reason, ok := decodeOperationalRevocationRequest(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The containing-app renewal request is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.requireInstallationFamilyRenewal(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "familyID"), reason, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) clientComponents(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id", "installation_family_id", "cursor", "page_size") {
		api.writeProblem(w, r, invalidRequest("The client-component list query is invalid."))
		return
	}
	environmentID, ok := requiredQueryValue(r, "environment_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The environment identifier is required."))
		return
	}
	familyID, ok := optionalQueryValue(r, "installation_family_id")
	if !ok {
		api.writeProblem(w, r, invalidRequest("The installation-family filter is invalid."))
		return
	}
	page, err := parseOperationalPage(r, id.ClientComponent)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.operations.listClientComponents(
		r.Context(), mustPrincipal(r.Context()), environmentID, familyID, page,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	items, pageDocument := buildPage(items, int(page.size), func(item clientComponentDocument) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) clientComponent(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The client-component query is invalid."))
		return
	}
	item, err := api.operations.getClientComponent(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "componentID"),
	)
	if err != nil {
		api.handleOperationalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) revokeClientComponent(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The client-component revocation query is invalid."))
		return
	}
	reason, ok := decodeOperationalRevocationRequest(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The client-component revocation request is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.revokeClientComponent(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "componentID"), reason, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) requireClientComponentReattestation(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The component re-attestation query is invalid."))
		return
	}
	reason, ok := decodeOperationalRevocationRequest(r)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The component re-attestation request is invalid."))
		return
	}
	operationID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.operations.requireClientComponentReattestation(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "componentID"), reason, operationID,
	)
	if err != nil {
		api.handleOperationalError(w, r, err, operationID)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func decodeOperationalRevocationRequest(r *http.Request) (string, bool) {
	if r.ContentLength == 0 {
		return "", true
	}
	request, err := decodeJSON[revokeInstallationRequest](r)
	if err != nil {
		return "", false
	}
	return request.Reason, true
}
