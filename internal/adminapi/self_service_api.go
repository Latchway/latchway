package adminapi

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
)

// minimumAdministratorPasswordLength matches bootstrap and administrator creation.
const minimumAdministratorPasswordLength = 12

// sessionEndProblems explains an ended console session to the holder of its cookie.
var sessionEndProblems = map[adminauth.SessionEndReason]problem.Error{
	adminauth.SessionEndExpired:            {Code: "session_expired", Detail: "Your console session expired."},
	adminauth.SessionEndSignedOut:          {Code: "session_revoked", Detail: "This session was signed out."},
	adminauth.SessionEndSignedOutElsewhere: {Code: "session_revoked", Detail: "You signed this session out from another session of your account."},
	adminauth.SessionEndRevokedByOwner:     {Code: "session_revoked", Detail: "An owner signed this session out."},
	adminauth.SessionEndPasswordReset:      {Code: "session_revoked", Detail: "An owner reset your password. Sign in with the new password."},
	adminauth.SessionEndPasswordChanged:    {Code: "session_revoked", Detail: "Your password was changed, which signed out your other sessions."},
	adminauth.SessionEndOrganizationSwitch: {Code: "session_revoked", Detail: "This session was replaced when you switched organization."},
	adminauth.SessionEndAccessDisabled:     {Code: "session_revoked", Detail: "Your account or membership in this organization was disabled."},
	adminauth.SessionEndTwoFactorReset:     {Code: "session_revoked", Detail: "An owner reset your two-factor sign-in. Sign in with your password and set it up again if your organization requires it."},
	adminauth.SessionEndSSOChanged:         {Code: "session_revoked", Detail: "An owner changed your organization's single sign-on. Sign in again."},
	adminauth.SessionEndOther:              {Code: "session_revoked", Detail: "This session ended."},
}

// sessionFailureProblem keeps unknown credentials generic and tells a known
// session's holder why it stopped working.
func (api *API) sessionFailureProblem(r *http.Request, cookieValue string) problem.Error {
	generic := problem.Error{Code: "authentication_required", Detail: "Administrator authentication is required."}
	reason, found, err := api.auth.EndedSessionReason(r.Context(), cookieValue)
	if err != nil {
		api.logger.Warn("administrator session end reason unavailable", "error", err)
		return generic
	}
	if !found {
		return generic
	}
	return sessionEndProblems[reason]
}

// passwordChangeAllows lists what a session that must choose a new password may still do.
func passwordChangeAllows(r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/admin/v1")
	switch {
	case r.Method == http.MethodGet && (path == "/auth/session" || path == "/system"):
		return true
	case r.Method == http.MethodPost && (path == "/auth/password" || path == "/auth/logout"):
		return true
	default:
		return false
	}
}

func (api *API) authInfo(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The sign-in information query is invalid."))
		return
	}
	open, err := api.auth.BootstrapOpen(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	methods := api.signInMethods()
	if sso, err := api.auth.AnySSOEnabled(r.Context()); err != nil {
		api.internal(w, r, err)
		return
	} else if sso && api.factors != nil {
		methods = append(methods, "sso")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"contract_version":  buildinfo.ContractVersion,
		"protocol_versions": buildinfo.SupportedProtocolVersions(),
		"setup_open":        open,
		"sign_in_methods":   methods,
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (api *API) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can change its own password."})
		return
	}
	request, err := decodeJSON[changePasswordRequest](r)
	if err != nil || request.CurrentPassword == "" || len(request.NewPassword) < minimumAdministratorPasswordLength || len(request.NewPassword) > 1024 {
		api.writeProblem(w, r, invalidRequest("Enter your current password and a new password of at least 12 characters."))
		return
	}
	key := sha256.Sum256([]byte("password-change:" + principal.AdminUserID))
	if !api.loginLimiter.allow(key, time.Now()) {
		api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many incorrect current passwords.", RetryAfterSeconds: 300})
		return
	}
	stored, err := api.auth.PasswordCredentialByAdminUserID(r.Context(), principal.AdminUserID)
	if errors.Is(err, adminauth.ErrAdminNotFound) {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "Your account has no password because it was created by single sign-on. An owner can set one for you."})
		return
	}
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	current := []byte(request.CurrentPassword)
	verification, verifyErr := api.hasher.Verify(current, stored)
	clear(current)
	if verifyErr != nil || !verification.Match {
		api.loginLimiter.failure(key, time.Now())
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The current password is incorrect."})
		return
	}
	api.loginLimiter.success(key)
	next := []byte(request.NewPassword)
	defer clear(next)
	if same, sameErr := api.hasher.Verify(next, stored); sameErr == nil && same.Match {
		api.writeProblem(w, r, invalidRequest("Choose a password different from the current one."))
		return
	}
	hash, err := api.hasher.Hash(next)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The new password is invalid."))
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	ended, err := api.auth.ChangeOwnPassword(r.Context(), principal, hash, requestID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed_out_sessions": ended})
}

type switchOrganizationRequest struct {
	OrganizationID string `json:"organization_id"`
}

func (api *API) switchOrganization(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can switch organization."})
		return
	}
	request, err := decodeJSON[switchOrganizationRequest](r)
	if err != nil || id.Validate(request.OrganizationID, id.Organization) != nil {
		api.writeProblem(w, r, invalidRequest("The organization switch request is invalid."))
		return
	}
	view, err := api.control.AdminView(r.Context(), principal.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	membership, ok := selectMembership(view.Memberships, request.OrganizationID)
	if !ok || request.OrganizationID == "" {
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "You are not an active member of that organization."})
		return
	}
	if membership.OrganizationID == principal.OrganizationID {
		api.writeProblem(w, r, invalidRequest("This session already uses that organization."))
		return
	}
	if principal.SignInMethod == adminauth.SignInSSO {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "A single sign-on session stays in the organization it signed in to. Sign out and sign in to the other organization."})
		return
	}
	if api.refuseWhenSSORequired(w, r, membership.OrganizationID, membership.Role) {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	issued, err := api.auth.SwitchSessionOrganization(
		r.Context(), principal, membership.OrganizationID, api.sessionLifetime,
		adminauth.DeviceSummaryFromUserAgent(r.UserAgent()), requestID,
	)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	switched := adminauth.Principal{
		OrganizationID: membership.OrganizationID, AdminUserID: principal.AdminUserID,
		Role: membership.Role, Method: adminauth.AuthenticationSession,
		CredentialID: issued.SessionID, CredentialExpiresAt: &issued.ExpiresAt, SignInMethod: principal.SignInMethod,
	}
	if err := api.fillSessionFlags(r, &switched); err != nil {
		api.internal(w, r, err)
		return
	}
	api.setSession(w, issued)
	writeJSON(w, http.StatusOK, api.sessionDocument(view, switched))
}

func (api *API) ownSessions(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The session query is invalid."))
		return
	}
	items, err := api.auth.ListOwnSessions(r.Context(), mustPrincipal(r.Context()))
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (api *API) revokeOwnSession(w http.ResponseWriter, r *http.Request) {
	api.revokeOwnSessions(w, r, chi.URLParam(r, "adminSessionID"))
}

func (api *API) revokeOtherOwnSessions(w http.ResponseWriter, r *http.Request) {
	api.revokeOwnSessions(w, r, "")
}

func (api *API) revokeOwnSessions(w http.ResponseWriter, r *http.Request, sessionID string) {
	principal := mustPrincipal(r.Context())
	if sessionID == "" && principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can sign out its other sessions."})
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	ended, err := api.auth.RevokeOwnSessions(r.Context(), principal, sessionID, requestID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	if sessionID != "" && principal.Method == adminauth.AuthenticationSession && principal.CredentialID == sessionID {
		api.clearSession(w)
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed_out_sessions": ended})
}
