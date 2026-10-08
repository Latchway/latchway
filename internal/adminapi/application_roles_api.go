package adminapi

import (
	"errors"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/problem"
)

type applicationRoleDocument struct {
	ApplicationID string         `json:"application_id"`
	Role          adminauth.Role `json:"role"`
}

// applicationRolesDocument lists a principal's raised application roles, sorted.
func applicationRolesDocument(principal adminauth.Principal) []applicationRoleDocument {
	roles := principal.ApplicationRoles()
	items := make([]applicationRoleDocument, 0, len(roles))
	for applicationID, role := range roles {
		items = append(items, applicationRoleDocument{ApplicationID: applicationID, Role: role})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ApplicationID < items[j].ApplicationID })
	return items
}

func (api *API) handleApplicationRoleError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, adminauth.ErrRoleNotRaised) {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "That role isn't higher than the member's organization role, so it would change nothing. Owners already have every role."})
		return
	}
	api.handleAdminAuthError(w, r, err)
}

func (api *API) listApplicationRoles(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The application role query is invalid."))
		return
	}
	items, err := api.auth.ListApplicationRoles(r.Context(), mustPrincipal(r.Context()))
	if err != nil {
		api.handleApplicationRoleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type applicationRoleRequest struct {
	Role string `json:"role"`
}

func (api *API) setApplicationRole(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[applicationRoleRequest](r)
	role := adminauth.Role(request.Role)
	if err != nil || (role != adminauth.RoleAdmin && role != adminauth.RoleOperator) {
		api.writeProblem(w, r, invalidRequest("An application role is admin or operator."))
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	grant, err := api.auth.SetApplicationRole(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "adminUserID"), chi.URLParam(r, "applicationID"), role, requestID)
	if err != nil {
		api.handleApplicationRoleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (api *API) removeApplicationRole(w http.ResponseWriter, r *http.Request) {
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.RemoveApplicationRole(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "adminUserID"), chi.URLParam(r, "applicationID"), requestID); err != nil {
		api.handleApplicationRoleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
