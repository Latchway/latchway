// Package adminapi implements the canonical HTTP control plane used by both
// the embedded console and administrative CLI clients.
package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/controlplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/useroverride"
)

const (
	adminCookieName = "__Host-latchway_admin"
	csrfCookieName  = "__Host-latchway_csrf"
	csrfHeader      = "X-CSRF-Token"
	maxAdminBody    = 1 << 20
)

type principalContextKey struct{}

type API struct {
	auth            *adminauth.Store
	control         *controlplane.Store
	configurations  *configuration.Store
	overrides       *useroverride.Store
	secretManager   secretManager
	hasher          *adminauth.PasswordHasher
	dummyHash       adminauth.PasswordHash
	publicOrigin    string
	sessionLifetime time.Duration
	logger          *slog.Logger
	loginLimiter    *failureLimiter
	operations      *operationalStore
	policyResolver  *policy.Resolver
	role            string
}

// Option supplies process facts that are not persisted in PostgreSQL.
type Option func(*API) error

// WithRole records the process role exposed by the authenticated system-status
// endpoint. The default remains "all" for embedded callers and tests.
func WithRole(role string) Option {
	return func(api *API) error {
		switch role {
		case "all", "api", "worker":
			api.role = role
			return nil
		default:
			return errors.New("admin API process role is invalid")
		}
	}
}

// WithConfigurationStore shares the process configuration store with the
// control plane. In api/all roles this keeps activation cache warming and its
// memory budget unified with session and data-plane reads.
func WithConfigurationStore(store *configuration.Store) Option {
	return func(api *API) error {
		if store == nil {
			return errors.New("admin API configuration store is nil")
		}
		api.configurations = store
		return nil
	}
}

func New(pool *pgxpool.Pool, publicOrigin string, sessionLifetime time.Duration, logger *slog.Logger, manager secretManager, options ...Option) (*API, error) {
	if manager == nil {
		return nil, errors.New("admin API secret manager is nil")
	}
	auth, err := adminauth.NewStore(pool)
	if err != nil {
		return nil, err
	}
	control, err := controlplane.NewStore(pool)
	if err != nil {
		return nil, err
	}
	configurations, err := configuration.NewStore(pool)
	if err != nil {
		return nil, err
	}
	policyResolver, err := policy.NewResolver()
	if err != nil {
		return nil, err
	}
	overrides, err := useroverride.NewStore(pool)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		return nil, errors.New("admin API logger is nil")
	}
	hasher := adminauth.NewDefaultPasswordHasher()
	dummyHash, err := hasher.Hash([]byte("latchway-login-equalization-only"))
	if err != nil {
		return nil, fmt.Errorf("create login equalization hash: %w", err)
	}
	api := &API{
		auth: auth, control: control, configurations: configurations, overrides: overrides,
		secretManager: manager,
		hasher:        hasher, dummyHash: dummyHash,
		publicOrigin: strings.TrimSuffix(publicOrigin, "/"), sessionLifetime: sessionLifetime,
		logger: logger, loginLimiter: newFailureLimiter(5, 5*time.Minute),
		operations: newOperationalStore(pool), policyResolver: policyResolver, role: "all",
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("admin API option is nil")
		}
		if err := option(api); err != nil {
			return nil, err
		}
	}
	if api.operations == nil {
		return nil, errors.New("admin API operational store is nil")
	}
	if api.policyResolver == nil {
		return nil, errors.New("admin API policy resolver is nil")
	}
	return api, nil
}

// InitializeBootstrap installs the configured one-time secret. A consumed
// token never prevents startup; its continued presence is logged as a warning.
func (api *API) InitializeBootstrap(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	err := api.auth.InitializeBootstrapToken(ctx, token, nil)
	if errors.Is(err, adminauth.ErrBootstrapDisabled) {
		api.logger.Warn("administrative bootstrap is disabled but LATCHWAY_ADMIN_BOOTSTRAP_TOKEN remains configured")
		return nil
	}
	if err != nil {
		return fmt.Errorf("initialize administrative bootstrap: %w", err)
	}
	return nil
}

func (api *API) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(noStore)
	router.Use(api.auditRejectedMutation)
	router.Post("/auth/bootstrap", api.bootstrap)
	router.Post("/auth/login", api.login)
	router.Group(func(protected chi.Router) {
		protected.Use(api.authenticate)
		protected.Get("/auth/session", api.session)
		protected.With(api.mutationProtection).Post("/auth/logout", api.logout)
		protected.Get("/organizations", api.organizations)
		protected.With(api.mutationProtection).Post("/organizations", api.createOrganization)
		protected.Get("/applications", api.applications)
		protected.With(api.mutationProtection).Post("/applications", api.createApplication)
		protected.Get("/applications/{applicationID}/environments", api.environments)
		protected.With(api.mutationProtection).Post("/applications/{applicationID}/environments", api.createEnvironment)
		protected.Get("/environments/{environmentID}/config", api.activeConfiguration)
		protected.Get("/environments/{environmentID}/config-revisions", api.configurationRevisions)
		protected.With(api.mutationProtection).Post("/environments/{environmentID}/config-revisions", api.createConfigurationRevision)
		protected.Get("/config-revisions/{revisionID}", api.configurationRevision)
		protected.With(api.mutationProtection).Patch("/config-revisions/{revisionID}", api.replaceDraftConfiguration)
		protected.With(api.mutationProtection).Post("/config-revisions/{revisionID}/validate", api.validateConfigurationRevision)
		protected.With(api.mutationProtection).Post("/config-revisions/{revisionID}/plan", api.planConfigurationRevision)
		protected.With(api.mutationProtection).Post("/config-revisions/{revisionID}/simulate", api.simulateConfigurationRevision)
		protected.With(api.mutationProtection).Post("/config-revisions/{revisionID}/activate", api.activateConfigurationRevision)
		protected.With(api.mutationProtection).Post("/environments/{environmentID}/rollback", api.rollbackEnvironmentConfiguration)
		protected.Get("/secrets", api.secrets)
		protected.With(api.mutationProtection).Post("/secrets", api.createSecret)
		protected.With(api.mutationProtection).Post("/secrets/{secretID}/rotate", api.rotateSecret)
		protected.With(api.mutationProtection).Delete("/secrets/{secretID}", api.deleteSecret)
		protected.Get("/api-tokens", api.apiTokens)
		protected.With(api.mutationProtection).Post("/api-tokens", api.createAPIToken)
		protected.With(api.mutationProtection).Delete("/api-tokens/{tokenID}", api.revokeAPIToken)
		protected.Get("/administrators", api.administrators)
		protected.With(api.mutationProtection).Post("/administrators", api.createAdministrator)
		protected.With(api.mutationProtection).Put("/administrators/{adminUserID}/role", api.changeAdministratorRole)
		protected.With(api.mutationProtection).Post("/administrators/{adminUserID}/disable", api.disableAdministrator)
		protected.With(api.mutationProtection).Post("/administrators/{adminUserID}/enable", api.enableAdministrator)
		protected.With(api.mutationProtection).Post("/administrators/{adminUserID}/reset-password", api.resetAdministratorPassword)
		protected.Get("/users", api.users)
		protected.Get("/users/{userID}", api.user)
		protected.With(api.mutationProtection).Post("/users/{userID}/block", api.blockUser)
		protected.With(api.mutationProtection).Post("/users/{userID}/unblock", api.unblockUser)
		protected.With(api.mutationProtection).Put("/users/{userID}/limit-override", api.replaceUserLimitOverride)
		protected.With(api.mutationProtection).Delete("/users/{userID}/limit-override", api.clearUserLimitOverride)
		protected.Get("/installations", api.installations)
		protected.Get("/installations/{installationID}", api.installation)
		protected.With(api.mutationProtection).Post("/installations/{installationID}/revoke", api.revokeInstallation)
		protected.Get("/requests", api.requests)
		protected.Get("/requests/{requestID}", api.request)
		protected.Get("/usage/summary", api.usageSummary)
		protected.Get("/usage/timeseries", api.usageTimeseries)
		protected.Get("/audit-events", api.auditEvents)
		protected.With(api.mutationProtection).Post("/self-tests", api.startSelfTest)
		protected.Get("/self-tests/{selfTestID}", api.selfTest)
		protected.Get("/system", api.systemStatus)
	})
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The administrative endpoint was not found."})
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		api.writeProblem(w, r, problem.Error{Code: "request_invalid", Detail: "The HTTP method is not supported by this administrative endpoint."})
	})
	return router
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type bootstrapRequest struct {
	BootstrapToken   string `json:"bootstrap_token"`
	OrganizationSlug string `json:"organization_slug"`
	OrganizationName string `json:"organization_name"`
	Email            string `json:"email"`
	DisplayName      string `json:"display_name"`
	Password         string `json:"password"`
}

func (api *API) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	request, err := decodeJSON[bootstrapRequest](r)
	if err != nil || len(request.Password) < 12 {
		api.writeProblem(w, r, invalidRequest("The bootstrap request is invalid."))
		return
	}
	if err := api.auth.ValidateBootstrapToken(r.Context(), request.BootstrapToken); err != nil {
		api.handleBootstrapError(w, r, err)
		return
	}
	password := []byte(request.Password)
	hash, err := api.hasher.Hash(password)
	clear(password)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The bootstrap password is invalid."))
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	result, issued, err := api.auth.BootstrapOwnerAndSession(r.Context(), request.BootstrapToken, adminauth.BootstrapOwnerInput{
		OrganizationSlug: request.OrganizationSlug, OrganizationName: request.OrganizationName,
		Email: request.Email, DisplayName: request.DisplayName, PasswordHash: hash, RequestID: auditRequestID,
	}, api.sessionLifetime)
	if err != nil {
		api.handleBootstrapError(w, r, err)
		return
	}
	api.setSession(w, issued)
	view, err := api.control.AdminView(r.Context(), result.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, api.sessionDocument(view, principalFromIssued(result, issued)))
}

func (api *API) handleBootstrapError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminauth.ErrBootstrapDisabled), errors.Is(err, adminauth.ErrBootstrapAlreadyInitialized):
		api.writeProblem(w, r, problem.Error{Code: "bootstrap_disabled", Detail: "First-owner setup is permanently unavailable."})
	case errors.Is(err, adminauth.ErrBootstrapTokenInvalid), errors.Is(err, adminauth.ErrBootstrapTokenExpired):
		api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "The bootstrap credential is invalid."})
	case errors.Is(err, adminauth.ErrInvalidAdminInput):
		api.writeProblem(w, r, invalidRequest("The bootstrap request is invalid."))
	default:
		api.internal(w, r, err)
	}
}

type loginRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	OrganizationID string `json:"organization_id"`
}

func (api *API) login(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	request, err := decodeJSON[loginRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The login request is invalid."))
		return
	}
	key := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(request.Email))))
	if !api.loginLimiter.allow(key, time.Now()) {
		api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many failed login attempts.", RetryAfterSeconds: 300})
		return
	}
	adminUserID, stored, credentialErr := api.auth.PasswordCredentialByEmail(r.Context(), request.Email)
	if credentialErr != nil {
		stored = api.dummyHash
	}
	password := []byte(request.Password)
	verification, verifyErr := api.hasher.Verify(password, stored)
	clear(password)
	if credentialErr != nil || verifyErr != nil || !verification.Match {
		if credentialErr != nil && !errors.Is(credentialErr, adminauth.ErrAdminAuthentication) {
			api.internal(w, r, credentialErr)
			return
		}
		api.loginLimiter.failure(key, time.Now())
		api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "The administrator credentials are invalid."})
		return
	}
	view, err := api.control.AdminView(r.Context(), adminUserID)
	if err != nil || len(view.Memberships) == 0 {
		if err == nil {
			err = errors.New("authenticated administrator has no active membership")
		}
		api.internal(w, r, err)
		return
	}
	membership, ok := selectMembership(view.Memberships, request.OrganizationID)
	if !ok {
		api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "The administrator credentials are invalid."})
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	issued, err := api.auth.CreateSession(r.Context(), adminauth.CreateSessionInput{
		OrganizationID: membership.OrganizationID, AdminUserID: adminUserID,
		Lifetime: api.sessionLifetime, RequestID: auditRequestID,
	})
	if err != nil {
		api.internal(w, r, err)
		return
	}
	api.loginLimiter.success(key)
	api.setSession(w, issued)
	writeJSON(w, http.StatusOK, api.sessionDocument(view, adminauth.Principal{
		OrganizationID: membership.OrganizationID, AdminUserID: adminUserID,
		Role: membership.Role, Method: adminauth.AuthenticationSession,
		CredentialID: issued.SessionID, CredentialExpiresAt: &issued.ExpiresAt,
	}))
}

func (api *API) session(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	view, err := api.control.AdminView(r.Context(), principal.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, api.sessionDocument(view, principal))
}

func (api *API) logout(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	var actor adminauth.AuditActor
	if principal.Method == adminauth.AuthenticationAPIToken {
		actor, err = adminauth.NewAPITokenActor(principal.CredentialID)
		if err == nil {
			err = api.auth.RevokeAPIToken(r.Context(), principal.CredentialID, actor, auditRequestID, "logout")
		}
	} else {
		actor, err = adminauth.NewAdminUserActor(principal.AdminUserID)
		if err == nil {
			err = api.auth.RevokeSession(r.Context(), principal.CredentialID, actor, auditRequestID, "logout")
		}
		api.clearSession(w)
	}
	if err != nil {
		api.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) organizations(w http.ResponseWriter, r *http.Request) {
	pageRequest, err := parsePageRequest(r, id.Organization)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.control.ListOrganizations(r.Context(), mustPrincipal(r.Context()), pageRequest)
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	items, page := buildPage(items, int(pageRequest.Size), func(item controlplane.Organization) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}

func (api *API) createOrganization(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[controlplane.NamedInput](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The organization is invalid."))
		return
	}
	item, err := api.control.CreateOrganization(r.Context(), mustPrincipal(r.Context()), request)
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (api *API) applications(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	organizationID := r.URL.Query().Get("organization_id")
	if organizationID == "" {
		organizationID = principal.OrganizationID
	}
	pageRequest, err := parsePageRequest(r, id.Application)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	items, err := api.control.ListApplications(r.Context(), principal, organizationID, pageRequest)
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	items, page := buildPage(items, int(pageRequest.Size), func(item controlplane.Application) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}

type applicationRequest struct {
	OrganizationID string `json:"organization_id"`
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name"`
}

func (api *API) createApplication(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[applicationRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The application is invalid."))
		return
	}
	item, err := api.control.CreateApplication(r.Context(), mustPrincipal(r.Context()), controlplane.ApplicationInput{
		OrganizationID: request.OrganizationID, NamedInput: controlplane.NamedInput{Slug: request.Slug, DisplayName: request.DisplayName},
	})
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (api *API) environments(w http.ResponseWriter, r *http.Request) {
	items, err := api.control.ListEnvironments(r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "applicationID"))
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type environmentRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
}

func (api *API) createEnvironment(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[environmentRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The environment is invalid."))
		return
	}
	item, err := api.control.CreateEnvironment(r.Context(), mustPrincipal(r.Context()), controlplane.EnvironmentInput{
		ApplicationID: chi.URLParam(r, "applicationID"), Kind: request.Kind,
		NamedInput: controlplane.NamedInput{Slug: request.Slug, DisplayName: request.DisplayName},
	})
	if err != nil {
		api.handleControlError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (api *API) activeConfiguration(w http.ResponseWriter, r *http.Request) {
	revision, err := api.configurations.GetActiveRevision(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "environmentID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

func (api *API) configurationRevisions(w http.ResponseWriter, r *http.Request) {
	parsed, err := parsePageRequest(r, id.ConfigRevision)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The pagination cursor is invalid."))
		return
	}
	pageRequest := configuration.PageRequest{
		Before: parsed.After, BeforeID: parsed.AfterID, Size: parsed.Size,
	}
	items, err := api.configurations.ListRevisions(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "environmentID"), pageRequest,
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	items, page := buildPage(items, int(pageRequest.Size), func(item configuration.Revision) cursorDocument {
		return cursorDocument{CreatedAt: item.CreatedAt, ID: item.ID}
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": page})
}

type createConfigurationRevisionRequest struct {
	BaseRevisionID string          `json:"base_revision_id"`
	Document       json.RawMessage `json:"document"`
	Description    string          `json:"description"`
}

func (api *API) createConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[createConfigurationRevisionRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The configuration draft request is invalid."))
		return
	}
	revision, err := api.configurations.CreateRevision(r.Context(), mustPrincipal(r.Context()), configuration.CreateInput{
		EnvironmentID: chi.URLParam(r, "environmentID"), BaseRevisionID: request.BaseRevisionID,
		Document: request.Document, Description: request.Description,
	})
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusCreated, revision)
}

func (api *API) configurationRevision(w http.ResponseWriter, r *http.Request) {
	revision, err := api.configurations.GetRevision(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

func (api *API) replaceDraftConfiguration(w http.ResponseWriter, r *http.Request) {
	etag, ok := api.requireETag(w, r)
	if !ok {
		return
	}
	document, err := decodeJSON[json.RawMessage](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The configuration document is invalid."))
		return
	}
	revision, err := api.configurations.ReplaceDraft(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"), etag, document,
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

func (api *API) validateConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	report, err := api.configurations.ValidateRevision(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (api *API) planConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	plan, err := api.configurations.PlanRevision(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"),
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (api *API) activateConfigurationRevision(w http.ResponseWriter, r *http.Request) {
	etag, ok := api.requireETag(w, r)
	if !ok {
		return
	}
	revision, err := api.configurations.ActivateRevision(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "revisionID"), etag,
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

type rollbackConfigurationRequest struct {
	RevisionID string `json:"revision_id"`
}

func (api *API) rollbackEnvironmentConfiguration(w http.ResponseWriter, r *http.Request) {
	etag, ok := api.requireETag(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[rollbackConfigurationRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The rollback request is invalid."))
		return
	}
	revision, err := api.configurations.Rollback(
		r.Context(), mustPrincipal(r.Context()), chi.URLParam(r, "environmentID"), request.RevisionID, etag,
	)
	if err != nil {
		api.handleConfigurationError(w, r, err)
		return
	}
	w.Header().Set("ETag", revision.ETag)
	writeJSON(w, http.StatusOK, revision)
}

func (api *API) requireETag(w http.ResponseWriter, r *http.Request) (string, bool) {
	etag := strings.TrimSpace(r.Header.Get("If-Match"))
	if etag == "" {
		api.writeProblem(w, r, problem.Error{Code: "etag_required", Detail: "The mutation requires the current strong ETag."})
		return "", false
	}
	if len(etag) < 3 || len(etag) > 256 || strings.HasPrefix(etag, "W/") || etag[0] != '"' || etag[len(etag)-1] != '"' || strings.ContainsAny(etag, "\r\n,") {
		api.writeProblem(w, r, invalidRequest("The If-Match header must contain one strong ETag."))
		return "", false
	}
	return etag, true
}

func (api *API) apiTokens(w http.ResponseWriter, r *http.Request) {
	items, err := api.auth.ListAPITokens(r.Context(), mustPrincipal(r.Context()))
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type apiTokenRequest struct {
	Name      string                 `json:"name"`
	Scopes    []adminauth.Capability `json:"scopes"`
	ExpiresAt *time.Time             `json:"expires_at"`
}

func (api *API) createAPIToken(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[apiTokenRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The API token request is invalid."))
		return
	}
	scope, err := adminauth.NewCapabilitySet(request.Scopes...)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The API token scope is invalid."))
		return
	}
	principal := mustPrincipal(r.Context())
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	issued, err := api.auth.CreateAPIToken(r.Context(), adminauth.CreateAPITokenInput{
		OrganizationID: principal.OrganizationID, AdminUserID: principal.AdminUserID,
		CreatedByAdminUserID: principal.AdminUserID, Name: request.Name, Scope: scope,
		ExpiresAt: request.ExpiresAt, RequestID: auditRequestID,
	})
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	metadata := adminauth.APITokenMetadata{
		ID: issued.APITokenID, Name: strings.TrimSpace(request.Name), Scopes: capabilityStrings(scope),
		CreatedAt: issued.CreatedAt, ExpiresAt: issued.ExpiresAt, Revoked: false,
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": issued.Token.Reveal(), "metadata": metadata})
}

func (api *API) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	var actor adminauth.AuditActor
	var err error
	if principal.Method == adminauth.AuthenticationAPIToken {
		actor, err = adminauth.NewAPITokenActor(principal.CredentialID)
	} else {
		actor, err = adminauth.NewAdminUserActor(principal.AdminUserID)
	}
	if err != nil {
		api.internal(w, r, err)
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.RevokeAPIToken(r.Context(), chi.URLParam(r, "tokenID"), actor, auditRequestID, "administrative revocation"); err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type userLimitOverrideRequest struct {
	LimitPlan string          `json:"limit_plan"`
	Reason    string          `json:"reason"`
	ExpiresAt json.RawMessage `json:"expires_at"`
}

func (api *API) replaceUserLimitOverride(w http.ResponseWriter, r *http.Request) {
	request, err := decodeJSON[userLimitOverrideRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The user limit override request is invalid."))
		return
	}
	expiresAt, err := optionalUserOverrideExpiry(request.ExpiresAt)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The user limit override request is invalid."))
		return
	}
	scope, ok := api.userOverrideScope(w, r)
	if !ok {
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	user, err := api.overrides.Replace(r.Context(), mustPrincipal(r.Context()), useroverride.ReplaceInput{
		Scope: scope, LimitPlan: request.LimitPlan, Reason: request.Reason,
		ExpiresAt: expiresAt, RequestID: auditRequestID,
	})
	if err != nil {
		api.handleUserOverrideError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func optionalUserOverrideExpiry(encoded json.RawMessage) (*time.Time, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var instant time.Time
	if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) || json.Unmarshal(encoded, &instant) != nil {
		return nil, errors.New("invalid user override expiry")
	}
	instant = instant.UTC()
	return &instant, nil
}

func (api *API) clearUserLimitOverride(w http.ResponseWriter, r *http.Request) {
	scope, ok := api.userOverrideScope(w, r)
	if !ok {
		return
	}
	auditRequestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	err = api.overrides.Clear(r.Context(), mustPrincipal(r.Context()), scope, auditRequestID)
	if err != nil {
		api.handleUserOverrideError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) userOverrideScope(w http.ResponseWriter, r *http.Request) (useroverride.AdminScope, bool) {
	principal := mustPrincipal(r.Context())
	scope := useroverride.AdminScope{
		OrganizationID: principal.OrganizationID, EnvironmentID: r.URL.Query().Get("environment_id"),
		ApplicationUserID: chi.URLParam(r, "userID"),
	}
	if id.Validate(scope.EnvironmentID, id.Environment) != nil || id.Validate(scope.ApplicationUserID, id.ApplicationUser) != nil {
		api.writeProblem(w, r, invalidRequest("The user and environment identifiers are invalid."))
		return useroverride.AdminScope{}, false
	}
	return scope, true
}

func capabilityStrings(scope adminauth.CapabilitySet) []string {
	values := scope.Values()
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func (api *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimSpace(r.Header.Get("Authorization"))
		cookie, cookieErr := r.Cookie(adminCookieName)
		if bearer != "" && cookieErr == nil {
			api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "Ambiguous administrator credentials are not accepted."})
			return
		}
		var principal adminauth.Principal
		var err error
		switch {
		case strings.HasPrefix(bearer, "Bearer "):
			principal, err = api.auth.AuthenticateAPIToken(r.Context(), strings.TrimPrefix(bearer, "Bearer "))
		case cookieErr == nil:
			principal, err = api.auth.AuthenticateSession(r.Context(), cookie.Value)
		default:
			err = adminauth.ErrAdminAuthentication
		}
		if err != nil {
			api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "Administrator authentication is required."})
			return
		}
		if auditState, ok := r.Context().Value(rejectedMutationAuditContextKey{}).(*rejectedMutationAuditState); ok {
			principalCopy := principal
			auditState.principal = &principalCopy
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal)))
	})
}

func (api *API) mutationProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := mustPrincipal(r.Context())
		if principal.Method == adminauth.AuthenticationSession {
			if r.Header.Get("Origin") != api.publicOrigin {
				api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
				return
			}
			if err := api.auth.ValidateSessionCSRF(r.Context(), principal.CredentialID, r.Header.Get(csrfHeader)); err != nil {
				api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The CSRF credential is invalid."})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (api *API) optionalOriginValid(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || origin == api.publicOrigin
}

func (api *API) setSession(w http.ResponseWriter, session adminauth.IssuedSession) {
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: session.Token.Reveal(), Path: "/", Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: session.CSRFToken.Reveal(), Path: "/", Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds()), Secure: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set(csrfHeader, session.CSRFToken.Reveal())
	w.Header().Set("Cache-Control", "no-store")
}

func (api *API) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (api *API) sessionDocument(view controlplane.AdminView, principal adminauth.Principal) map[string]any {
	var expiresAt any
	if principal.CredentialExpiresAt != nil {
		expiresAt = principal.CredentialExpiresAt.UTC()
	}
	capabilities := make([]string, 0)
	for _, capability := range []adminauth.Capability{adminauth.ManageOwners, adminauth.ManageSecrets, adminauth.ActivateConfiguration, adminauth.RunSelfTests, adminauth.InspectUsers, adminauth.RevokeInstallations, adminauth.ViewPromptBodies} {
		if principal.Allows(capability, adminauth.AuthorizationContext{}) {
			capabilities = append(capabilities, string(capability))
		}
	}
	return map[string]any{
		"administrator":   map[string]any{"id": view.ID, "email": view.Email, "enabled": true},
		"organization_id": principal.OrganizationID, "memberships": view.Memberships,
		"capabilities": capabilities, "expires_at": expiresAt,
	}
}

func selectMembership(memberships []controlplane.Membership, organizationID string) (controlplane.Membership, bool) {
	if organizationID == "" && len(memberships) > 0 {
		return memberships[0], true
	}
	for _, membership := range memberships {
		if membership.OrganizationID == organizationID {
			return membership, true
		}
	}
	return controlplane.Membership{}, false
}

type cursorDocument struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func parsePageRequest(r *http.Request, prefix id.Prefix) (controlplane.PageRequest, error) {
	size := 50
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			return controlplane.PageRequest{}, controlplane.ErrInvalid
		}
		size = parsed
	}
	page := controlplane.PageRequest{Size: int32(size)}
	rawCursor := r.URL.Query().Get("cursor")
	if rawCursor == "" {
		return page, nil
	}
	if len(rawCursor) > 2048 {
		return controlplane.PageRequest{}, controlplane.ErrInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawCursor)
	if err != nil {
		return controlplane.PageRequest{}, controlplane.ErrInvalid
	}
	value, err := jsonsafe.DecodeReader(bytes.NewReader(decoded), 4096)
	if err != nil {
		return controlplane.PageRequest{}, controlplane.ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return controlplane.PageRequest{}, controlplane.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var cursor cursorDocument
	if err := decoder.Decode(&cursor); err != nil || cursor.CreatedAt.IsZero() || id.Validate(cursor.ID, prefix) != nil {
		return controlplane.PageRequest{}, controlplane.ErrInvalid
	}
	page.After = cursor.CreatedAt.UTC()
	page.AfterID = cursor.ID
	return page, nil
}

func buildPage[T any](items []T, size int, cursorFor func(T) cursorDocument) ([]T, map[string]any) {
	hasMore := len(items) > size
	if hasMore {
		items = items[:size]
	}
	page := map[string]any{"has_more": hasMore}
	if hasMore && len(items) > 0 {
		encoded, err := json.Marshal(cursorFor(items[len(items)-1]))
		if err == nil {
			page["next_cursor"] = base64.RawURLEncoding.EncodeToString(encoded)
		}
	}
	return items, page
}

func principalFromIssued(result adminauth.BootstrapResult, issued adminauth.IssuedSession) adminauth.Principal {
	return adminauth.Principal{OrganizationID: result.OrganizationID, AdminUserID: result.AdminUserID, Role: adminauth.RoleOwner, Method: adminauth.AuthenticationSession, CredentialID: issued.SessionID, CredentialExpiresAt: &issued.ExpiresAt}
}

func decodeJSON[T any](r *http.Request) (T, error) {
	return decodeJSONLimited[T](r, maxAdminBody)
}

func decodeJSONLimited[T any](r *http.Request, maximumBytes int64) (T, error) {
	var zero T
	if maximumBytes < 1 {
		return zero, errors.New("JSON body limit is invalid")
	}
	if media := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); media != "application/json" {
		return zero, errors.New("content type must be application/json")
	}
	value, err := jsonsafe.DecodeReader(r.Body, maximumBytes)
	if err != nil {
		return zero, err
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return zero, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical.Bytes()))
	decoder.DisallowUnknownFields()
	var result T
	if err := decoder.Decode(&result); err != nil {
		return zero, err
	}
	return result, nil
}

func mustPrincipal(ctx context.Context) adminauth.Principal {
	principal, ok := ctx.Value(principalContextKey{}).(adminauth.Principal)
	if !ok {
		panic("admin principal middleware invariant violated")
	}
	return principal
}

func invalidRequest(detail string) problem.Error {
	return problem.Error{Code: "request_invalid", Detail: detail}
}

func (api *API) handleControlError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, controlplane.ErrInvalid):
		api.writeProblem(w, r, invalidRequest("The administrative resource is invalid."))
	case errors.Is(err, controlplane.ErrForbidden):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot perform this operation."})
	case errors.Is(err, controlplane.ErrConflict):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "A resource with the same identifier already exists."})
	case errors.Is(err, controlplane.ErrNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The requested resource was not found."})
	default:
		api.internal(w, r, err)
	}
}

func (api *API) handleConfigurationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, configuration.ErrInvalid):
		api.writeProblem(w, r, invalidRequest("The configuration operation is invalid."))
	case errors.Is(err, configuration.ErrForbidden):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot perform this configuration operation."})
	case errors.Is(err, configuration.ErrNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The requested configuration revision was not found."})
	case errors.Is(err, configuration.ErrETagMismatch):
		api.writeProblem(w, r, problem.Error{Code: "etag_mismatch", Detail: "The configuration changed after the supplied ETag was issued."})
	case errors.Is(err, configuration.ErrConflict):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "The configuration operation conflicts with the current active revision."})
	case errors.Is(err, configuration.ErrConfigurationInvalid):
		issues := make([]problem.ValidationIssue, 0)
		var failure *configuration.ValidationFailure
		if errors.As(err, &failure) {
			for _, issue := range failure.Issues {
				if issue.Severity == "error" {
					issues = append(issues, problem.ValidationIssue{Severity: issue.Severity, Code: issue.Code, Path: issue.Path, Message: issue.Message})
				}
			}
		}
		api.writeProblem(w, r, problem.Error{Code: "configuration_invalid", Detail: "The configuration has validation errors and cannot be used.", ValidationIssues: issues})
	default:
		api.internal(w, r, err)
	}
}

func (api *API) handleUserOverrideError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, useroverride.ErrInvalid):
		api.writeProblem(w, r, invalidRequest("The user limit override is invalid."))
	case errors.Is(err, useroverride.ErrForbidden):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot manage user limit overrides."})
	case errors.Is(err, useroverride.ErrNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The requested user or environment was not found."})
	case errors.Is(err, useroverride.ErrConfiguration):
		api.writeProblem(w, r, invalidRequest("The limit plan is not available in the active environment configuration."))
	default:
		api.internal(w, r, err)
	}
}

func (api *API) handleAdminAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminauth.ErrInvalidAdminInput), errors.Is(err, adminauth.ErrEmptyTokenScope), errors.Is(err, adminauth.ErrInvalidCapability):
		api.writeProblem(w, r, invalidRequest("The administrative credential request is invalid."))
	case errors.Is(err, adminauth.ErrAdminAuthentication):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The administrator cannot perform this credential operation."})
	case errors.Is(err, adminauth.ErrAdminNotFound):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The administrative credential was not found."})
	default:
		api.internal(w, r, err)
	}
}

func (api *API) writeProblem(w http.ResponseWriter, r *http.Request, value problem.Error) {
	problem.Write(w, requestID(r.Context()), value)
}

func (api *API) internal(w http.ResponseWriter, r *http.Request, err error) {
	api.logger.ErrorContext(r.Context(), "admin API operation failed", "request_id", requestID(r.Context()), "error_class", fmt.Sprintf("%T", err))
	api.writeProblem(w, r, problem.Error{Code: "internal_error", Detail: "The administrative operation could not be completed."})
}

func requestID(ctx context.Context) string {
	value := middleware.GetReqID(ctx)
	if value != "" {
		return value
	}
	generated, err := id.New(id.LogicalRequest)
	if err != nil {
		return "request_unknown"
	}
	return generated
}

type rejectedMutationAuditState struct {
	principal     *adminauth.Principal
	operationID   string
	indeterminate bool
}

type rejectedMutationAuditContextKey struct{}

func (api *API) recordRejectedMutation(
	ctx context.Context,
	action string,
	resourceType string,
	principal *adminauth.Principal,
	outcome adminauth.AuditOutcome,
	operationID string,
) error {
	eventID, eventErr := id.New(id.AuditEvent)
	requestID := operationID
	var requestErr error
	if id.Validate(requestID, id.AdminRequest) != nil {
		requestID, requestErr = id.New(id.AdminRequest)
	}
	change, changeErr := adminauth.NewSensitiveAuditChange("credential", adminauth.AuditSet)
	if eventErr != nil || requestErr != nil || changeErr != nil {
		return errors.New("construct rejected mutation audit")
	}
	actor := adminauth.SystemActor()
	organizationID := ""
	if principal != nil {
		organizationID = principal.OrganizationID
		var actorErr error
		if principal.Method == adminauth.AuthenticationAPIToken {
			actor, actorErr = adminauth.NewAPITokenActor(principal.CredentialID)
		} else {
			actor, actorErr = adminauth.NewAdminUserActor(principal.AdminUserID)
		}
		if actorErr != nil {
			return actorErr
		}
	}
	mutation, err := adminauth.NewAuditMutation(
		eventID, organizationID, "", actor, action, resourceType,
		requestID, outcome, requestID, time.Now().UTC(),
		[]adminauth.AuditChange{change},
	)
	if err != nil {
		return err
	}
	return api.auth.RecordAuditMutation(ctx, mutation)
}

func (api *API) auditRejectedMutation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}
		state := &rejectedMutationAuditState{}
		r = r.WithContext(context.WithValue(
			r.Context(), rejectedMutationAuditContextKey{}, state,
		))
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrapped, r)
		if wrapped.Status() >= http.StatusBadRequest {
			action, resourceType := rejectedMutationDescriptor(r.Method, r.URL.Path)
			outcome := rejectedMutationOutcome(wrapped.Status(), state.indeterminate)
			auditContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
			defer cancel()
			if err := api.recordRejectedMutation(
				auditContext, action, resourceType, state.principal, outcome, state.operationID,
			); err != nil {
				api.logger.ErrorContext(
					r.Context(), "record rejected Admin API mutation",
					"action", action, "error_class", fmt.Sprintf("%T", err),
				)
			}
		}
	})
}

func rejectedMutationOutcome(status int, indeterminate bool) adminauth.AuditOutcome {
	if indeterminate {
		return adminauth.AuditIndeterminate
	}
	if status >= http.StatusInternalServerError {
		return adminauth.AuditFailed
	}
	return adminauth.AuditDenied
}

func newMutationOperationID(ctx context.Context) (string, error) {
	operationID, err := id.New(id.AdminRequest)
	if err != nil {
		return "", err
	}
	if state, ok := ctx.Value(rejectedMutationAuditContextKey{}).(*rejectedMutationAuditState); ok {
		state.operationID = operationID
	}
	return operationID, nil
}

func markMutationIndeterminate(ctx context.Context) {
	if state, ok := ctx.Value(rejectedMutationAuditContextKey{}).(*rejectedMutationAuditState); ok {
		state.indeterminate = true
	}
}

func rejectedMutationDescriptor(method, path string) (string, string) {
	switch {
	case strings.HasSuffix(path, "/auth/bootstrap"):
		return "admin.bootstrap_owner", "admin_request"
	case strings.HasSuffix(path, "/auth/login"):
		return "admin.login", "admin_request"
	case strings.HasSuffix(path, "/auth/logout"):
		return "admin.logout", "admin_request"
	case strings.HasSuffix(path, "/organizations"):
		return "admin.organization_create", "admin_request"
	case strings.HasSuffix(path, "/applications"):
		return "admin.application_create", "admin_request"
	case strings.HasSuffix(path, "/environments"):
		return "admin.environment_create", "admin_request"
	case strings.HasSuffix(path, "/config-revisions") && method == http.MethodPost:
		return "admin.configuration_revision_create", "admin_request"
	case strings.Contains(path, "/config-revisions/") && method == http.MethodPatch:
		return "admin.configuration_revision_update", "admin_request"
	case strings.HasSuffix(path, "/validate"):
		return "admin.configuration_revision_validate", "admin_request"
	case strings.HasSuffix(path, "/plan"):
		return "admin.configuration_plan", "admin_request"
	case strings.HasSuffix(path, "/activate"):
		return "admin.configuration_activate", "admin_request"
	case strings.HasSuffix(path, "/rollback"):
		return "admin.configuration_rollback", "admin_request"
	case strings.HasSuffix(path, "/secrets") && method == http.MethodPost:
		return "admin.secret_create", "admin_request"
	case strings.HasSuffix(path, "/rotate") && strings.Contains(path, "/secrets/"):
		return "admin.secret_rotate", "admin_request"
	case strings.Contains(path, "/secrets/") && method == http.MethodDelete:
		return "admin.secret_delete", "admin_request"
	case strings.Contains(path, "/api-tokens") && method == http.MethodPost:
		return "admin.api_token_create", "admin_request"
	case strings.Contains(path, "/api-tokens") && method == http.MethodDelete:
		return "admin.api_token_revoke", "admin_request"
	case strings.HasSuffix(path, "/limit-override") && method == http.MethodPut:
		return "admin.user_limit_override_replace", "admin_request"
	case strings.HasSuffix(path, "/limit-override") && method == http.MethodDelete:
		return "admin.user_limit_override_clear", "admin_request"
	case strings.HasSuffix(path, "/block") && strings.Contains(path, "/users/"):
		return "admin.user_block", "admin_request"
	case strings.HasSuffix(path, "/unblock") && strings.Contains(path, "/users/"):
		return "admin.user_unblock", "admin_request"
	case strings.HasSuffix(path, "/revoke") && strings.Contains(path, "/installations/"):
		return "admin.installation_revoke", "admin_request"
	case strings.HasSuffix(path, "/self-tests") && method == http.MethodPost:
		return "admin.self_test_run", "admin_request"
	default:
		return "admin.request_rejected", "admin_request"
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type failureLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	failures map[[sha256.Size]byte][]time.Time
}

func newFailureLimiter(limit int, window time.Duration) *failureLimiter {
	return &failureLimiter{limit: limit, window: window, failures: make(map[[sha256.Size]byte][]time.Time)}
}

func (limiter *failureLimiter) allow(key [sha256.Size]byte, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.prune(key, now)
	return len(limiter.failures[key]) < limiter.limit
}

func (limiter *failureLimiter) failure(key [sha256.Size]byte, now time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.prune(key, now)
	limiter.failures[key] = append(limiter.failures[key], now)
}

func (limiter *failureLimiter) success(key [sha256.Size]byte) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	delete(limiter.failures, key)
}

func (limiter *failureLimiter) prune(key [sha256.Size]byte, now time.Time) {
	cutoff := now.Add(-limiter.window)
	values := limiter.failures[key]
	first := 0
	for first < len(values) && values[first].Before(cutoff) {
		first++
	}
	if first == len(values) {
		delete(limiter.failures, key)
		return
	}
	limiter.failures[key] = values[first:]
}
