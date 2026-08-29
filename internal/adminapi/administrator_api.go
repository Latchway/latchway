package adminapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/controlplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
)

type createAdministratorRequest struct {
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name"`
	Password    string         `json:"password"`
	Role        adminauth.Role `json:"role"`
}

type changeAdministratorRoleRequest struct {
	Role adminauth.Role `json:"role"`
}

type resetAdministratorPasswordRequest struct {
	Password string `json:"password"`
}

func (api *API) administrators(w http.ResponseWriter, r *http.Request) {
	page, err := parsePageRequest(r, id.AdminUser)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The administrator pagination cursor is invalid."))
		return
	}
	items, err := api.auth.ListAdministrators(r.Context(), mustPrincipal(r.Context()), adminauth.AdministratorPageRequest{
		After: page.After, AfterID: page.AfterID, Size: page.Size,
	})
	if err != nil {
		api.handleAdministratorError(w, r, err)
		return
	}
	items, pageDocument := buildPage(items, int(page.Size), func(item adminauth.Administrator) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) createAdministrator(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[createAdministratorRequest](r)
	if err != nil || len(request.Password) < 12 {
		api.writeProblem(w, r, invalidRequest("The administrator account request is invalid."))
		return
	}
	password := []byte(request.Password)
	hash, err := api.hasher.Hash(password)
	clear(password)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The administrator password is invalid."))
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.auth.CreateAdministrator(r.Context(), mustPrincipal(r.Context()), adminauth.CreateAdministratorInput{
		Email: request.Email, DisplayName: request.DisplayName, PasswordHash: hash,
		Role: request.Role, RequestID: auditRequestID,
	})
	if err != nil {
		api.handleAdministratorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (api *API) changeAdministratorRole(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[changeAdministratorRoleRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The administrator role request is invalid."))
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.auth.ChangeAdministratorRole(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "adminUserID"), request.Role, auditRequestID,
	)
	if err != nil {
		api.handleAdministratorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) disableAdministrator(w http.ResponseWriter, r *http.Request) {
	api.setAdministratorEnabled(w, r, false)
}

func (api *API) enableAdministrator(w http.ResponseWriter, r *http.Request) {
	api.setAdministratorEnabled(w, r, true)
}

func (api *API) setAdministratorEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.auth.SetAdministratorEnabled(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "adminUserID"), enabled, auditRequestID,
	)
	if err != nil {
		api.handleAdministratorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) resetAdministratorPassword(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[resetAdministratorPasswordRequest](r)
	if err != nil || len(request.Password) < 12 {
		api.writeProblem(w, r, invalidRequest("The administrator password-reset request is invalid."))
		return
	}
	password := []byte(request.Password)
	hash, err := api.hasher.Hash(password)
	clear(password)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The administrator password is invalid."))
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	item, err := api.auth.ResetAdministratorPassword(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "adminUserID"), hash, auditRequestID,
	)
	if err != nil {
		api.handleAdministratorError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (api *API) handleAdministratorError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminauth.ErrInvalidAdminInput):
		api.writeProblem(w, r, invalidRequest("The administrator lifecycle request is invalid."))
	case errors.Is(err, adminauth.ErrAdminAuthentication):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only an active owner can manage administrators."})
	case errors.Is(err, adminauth.ErrAdminNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The administrator membership was not found."})
	case errors.Is(err, adminauth.ErrLastActiveOwner):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The final active owner cannot be demoted or disabled."})
	case errors.Is(err, adminauth.ErrAdminConflict):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The administrator account conflicts with an existing account or tenant membership."})
	case errors.Is(err, controlplane.ErrInvalid):
		api.writeProblem(w, r, invalidRequest("The administrator pagination request is invalid."))
	default:
		api.internal(w, r, err)
	}
}
