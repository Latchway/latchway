package adminapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/secrets"
)

// A JSON string may use a six-byte escape for one decoded byte. Keep that
// worst case reachable while still bounding the write-only request before it
// is decoded. The allowance covers the containing object and field names.
const maxSecretJSONBody = (6 * secrets.MaxValueBytes) + (16 << 10)

type secretManager interface {
	List(context.Context, adminauth.Principal, string, secrets.PageRequest) ([]secrets.Metadata, error)
	Create(context.Context, adminauth.Principal, secrets.CreateInput) (secrets.Metadata, error)
	Rotate(context.Context, adminauth.Principal, secrets.RotateInput) (secrets.Metadata, error)
	Destroy(context.Context, adminauth.Principal, secrets.DestroyInput) error
}

type writeSecretRequest struct {
	EnvironmentID string `json:"environment_id"`
	Name          string `json:"name"`
	Value         string `json:"value"`
}

type rotateSecretRequest struct {
	Value string `json:"value"`
}

func (api *API) secrets(w http.ResponseWriter, r *http.Request) {
	if api.secretManager == nil {
		api.internal(w, r, errors.New("secret manager is unavailable"))
		return
	}
	if !api.canManageSecrets(w, r) {
		return
	}
	parsed, err := parsePageRequest(r, id.SecretRecord)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.secretManager.List(
		r.Context(), mustPrincipal(r.Context()), r.URL.Query().Get("environment_id"),
		secrets.PageRequest{Before: parsed.After, BeforeID: parsed.AfterID, Size: parsed.Size},
	)
	if err != nil {
		api.handleSecretError(w, r, err, "")
		return
	}
	items, page := buildPage(items, int(parsed.Size), func(item secrets.Metadata) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}

func (api *API) createSecret(w http.ResponseWriter, r *http.Request) {
	if api.secretManager == nil {
		api.internal(w, r, errors.New("secret manager is unavailable"))
		return
	}
	if !api.canManageSecrets(w, r) {
		return
	}
	request, err := decodeJSONLimited[writeSecretRequest](r, maxSecretJSONBody)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The secret request is invalid."))
		return
	}
	value := []byte(request.Value)
	request.Value = ""
	defer clear(value)
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	metadata, err := api.secretManager.Create(r.Context(), mustPrincipal(r.Context()), secrets.CreateInput{
		EnvironmentID: request.EnvironmentID,
		Name:          request.Name,
		Value:         value,
		RequestID:     requestID,
	})
	if err != nil {
		api.handleSecretError(w, r, err, requestID)
		return
	}
	writeJSON(w, http.StatusCreated, metadata)
}

func (api *API) rotateSecret(w http.ResponseWriter, r *http.Request) {
	if api.secretManager == nil {
		api.internal(w, r, errors.New("secret manager is unavailable"))
		return
	}
	if !api.canManageSecrets(w, r) {
		return
	}
	request, err := decodeJSONLimited[rotateSecretRequest](r, maxSecretJSONBody)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The secret rotation request is invalid."))
		return
	}
	value := []byte(request.Value)
	request.Value = ""
	defer clear(value)
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	metadata, err := api.secretManager.Rotate(r.Context(), mustPrincipal(r.Context()), secrets.RotateInput{
		SecretID:  chi.URLParam(r, "secretID"),
		Value:     value,
		RequestID: requestID,
	})
	if err != nil {
		api.handleSecretError(w, r, err, requestID)
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (api *API) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if api.secretManager == nil {
		api.internal(w, r, errors.New("secret manager is unavailable"))
		return
	}
	if !api.canManageSecrets(w, r) {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.secretManager.Destroy(r.Context(), mustPrincipal(r.Context()), secrets.DestroyInput{
		SecretID: chi.URLParam(r, "secretID"), RequestID: requestID,
	}); err != nil {
		api.handleSecretError(w, r, err, requestID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) canManageSecrets(w http.ResponseWriter, r *http.Request) bool {
	if mustPrincipal(r.Context()).Allows(adminauth.ManageSecrets, adminauth.AuthorizationContext{}) {
		return true
	}
	api.handleSecretError(w, r, secrets.ErrForbidden, "")
	return false
}

func (api *API) handleSecretError(w http.ResponseWriter, r *http.Request, err error, operationID string) {
	switch {
	case errors.Is(err, secrets.ErrInvalid):
		api.writeProblem(w, r, invalidRequest("The secret operation is invalid."))
	case errors.Is(err, secrets.ErrForbidden):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot manage secrets."})
	case errors.Is(err, secrets.ErrNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The requested secret was not found."})
	case errors.Is(err, secrets.ErrConflict):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The secret operation conflicts with the current version."})
	case errors.Is(err, secrets.ErrReferenced):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The secret is referenced by a deployable configuration revision."})
	case errors.Is(err, secrets.ErrIndeterminate):
		if id.Validate(operationID, id.AdminRequest) != nil {
			api.internal(w, r, errors.New("indeterminate secret operation has no correlation ID"))
			return
		}
		markMutationIndeterminate(r.Context())
		api.writeProblem(w, r, problem.Error{
			Code: "operation_indeterminate", OperationID: operationID,
			Detail: "The database commit outcome is unknown. Preserve the operation ID; only a correlated succeeded audit event proves that this request committed. Follow the documented reconciliation path before retrying.",
		})
	default:
		api.internal(w, r, err)
	}
}
