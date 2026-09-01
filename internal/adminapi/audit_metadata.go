package adminapi

import (
	"net/http"
	"strings"

	"github.com/latchway/latchway/internal/adminauth"
)

const (
	adminSourceHeader = "X-Latchway-Admin-Source"
	auditReasonHeader = "X-Latchway-Audit-Reason"
)

func (api *API) auditMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This header is a bounded client claim, not an authentication fact.
		// authenticate resolves sessions to Console and prevents bearer callers
		// from claiming the Console surface.
		source := adminauth.AuditSource(strings.TrimSpace(r.Header.Get(adminSourceHeader)))
		if source == "" {
			source = adminauth.AuditSourceAPI
		}
		ctx, err := adminauth.WithAuditMetadata(r.Context(), source, r.Header.Get(auditReasonHeader))
		if err != nil {
			api.writeProblem(w, r, invalidRequest("The administrative audit attribution is invalid."))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
