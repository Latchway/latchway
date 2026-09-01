package adminapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

func (api *API) adminSessions(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "cursor", "page_size") ||
		len(r.URL.Query()["cursor"]) > 1 || len(r.URL.Query()["page_size"]) > 1 {
		api.writeProblem(w, r, invalidRequest("The administrator-session query is invalid."))
		return
	}
	page, err := parsePageRequest(r, id.AdminSession)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The administrator-session pagination cursor is invalid."))
		return
	}
	items, err := api.auth.ListAdminSessions(r.Context(), mustPrincipal(r.Context()), adminauth.AdminSessionPageRequest{
		After: page.After, AfterID: page.AfterID, Size: page.Size,
	})
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	items, pageDocument := buildPage(items, int(page.Size), func(item adminauth.AdminSessionMetadata) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": pageDocument})
}

func (api *API) revokeManagedAdminSession(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	sessionID := chi.URLParam(r, "adminSessionID")
	if err := api.auth.RevokeManagedAdminSession(r.Context(), principal, sessionID, requestID); err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	if principal.Method == adminauth.AuthenticationSession && principal.CredentialID == sessionID {
		api.clearSession(w)
	}
	w.WriteHeader(http.StatusNoContent)
}
