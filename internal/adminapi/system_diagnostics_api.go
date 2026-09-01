package adminapi

import (
	"errors"
	"net/http"

	"github.com/latchway/latchway/internal/diagnostics"
)

func (api *API) systemDoctor(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The system-doctor query is invalid."))
		return
	}
	report := diagnostics.Run(r.Context(), api.operations.pool, api.role, api.diagnostics)
	if err := diagnostics.Validate(report); err != nil {
		api.internal(w, r, errors.New("system diagnostic report failed validation"))
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (api *API) systemSupportBundle(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The support-bundle query is invalid."))
		return
	}
	report := diagnostics.Run(r.Context(), api.operations.pool, api.role, api.diagnostics)
	if err := diagnostics.Validate(report); err != nil {
		api.internal(w, r, errors.New("system diagnostic report failed validation"))
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="latchway-support-bundle.json"`)
	writeJSON(w, http.StatusOK, diagnostics.Bundle(report, "admin_api"))
}
