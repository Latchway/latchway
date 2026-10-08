package adminapi

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/problem"
)

// handleDraftLifecycleError maps the draft-lifecycle refusals that need more
// specific guidance than the shared configuration errors.
func (api *API) handleDraftLifecycleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, configuration.ErrDraftPending):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The environment already has an unpublished draft. Publish or discard it first."})
	case errors.Is(err, configuration.ErrMergeConflict):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "Both the draft and the live configuration changed the same paths. Choose a side for every conflict."})
	default:
		api.handleConfigurationError(w, r, err)
	}
}

func (api *API) configurationRevisionEdits(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The configuration edit-history query is invalid."))
		return
	}
	edits, err := api.configurations.ListRevisionEdits(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"))
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, edits)
}

func (api *API) discardConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	etag, ok := api.requireETag(w, r)
	if !ok {
		return
	}
	revision, err := api.configurations.DiscardRevision(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"), etag)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

func (api *API) configurationRebasePreview(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The rebase-preview query is invalid."))
		return
	}
	preview, err := api.configurations.RebasePreview(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"))
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

type rebaseConfigurationRequest struct {
	LiveRevisionID string            `json:"live_revision_id"`
	Resolutions    map[string]string `json:"resolutions"`
}

func (api *API) rebaseConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	etag, ok := api.requireETag(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[rebaseConfigurationRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The rebase request is invalid."))
		return
	}
	revision, err := api.configurations.Rebase(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"), etag,
		request.LiveRevisionID, request.Resolutions,
	)
	if err != nil {
		api.handleDraftLifecycleError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

type promoteConfigurationRequest struct {
	SourceEnvironmentID string `json:"source_environment_id"`
	Description         string `json:"description"`
}

func (api *API) promoteConfiguration(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[promoteConfigurationRequest](r)
	if err != nil || !utf8.ValidString(request.Description) {
		api.writeProblem(w, r, invalidRequest("The promotion request is invalid."))
		return
	}
	revision, report, err := api.configurations.Promote(r.Context(), mustPrincipal(r.Context()), configuration.PromoteInput{
		TargetEnvironmentID: chi.URLParam(r, "environmentID"), SourceEnvironmentID: request.SourceEnvironmentID,
		Description: request.Description,
	})
	if err != nil {
		api.handleDraftLifecycleError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusCreated, map[string]any{"revision": revision, "promotion": report})
}

type activateConfigurationRequest struct {
	Note string `json:"note"`
}

// activationOptions reads the optional activation body. Clients that send no
// body (older consoles and the CLI) activate without a note.
func activationOptions(r *http.Request) ([]configuration.ActivationOption, bool) {
	if r.ContentLength == 0 || (r.ContentLength < 0 && strings.TrimSpace(r.Header.Get("Content-Type")) == "") {
		return nil, true
	}
	request, err := decodeJSON[activateConfigurationRequest](r)
	if err != nil {
		return nil, false
	}
	if request.Note == "" {
		return nil, true
	}
	if !configuration.ValidActivationNote(request.Note) {
		return nil, false
	}
	return []configuration.ActivationOption{configuration.WithActivationNote(request.Note)}, true
}
