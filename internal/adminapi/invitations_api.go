package adminapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/mail"
	"github.com/latchway/latchway/internal/problem"
)

// invitationLifetime is how long an invitation link works.
const invitationLifetime = 7 * 24 * time.Hour

// WithMailer lets owners have invitations emailed through the configured relay.
func WithMailer(sender mail.Sender) Option {
	return func(api *API) error {
		if sender == nil {
			return errors.New("mail sender is nil")
		}
		api.mailer = sender
		return nil
	}
}

// invitationURL is the console link that carries the token. The token sits in
// the fragment, which browsers never send to the server or in referrers.
func (api *API) invitationURL(token string) string {
	return api.publicOrigin + "/invitation#" + token
}

func (api *API) handleInvitationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminauth.ErrInvitationInvalid):
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "This invitation was used, revoked, replaced or has expired. Ask an owner for a new one."})
	case errors.Is(err, adminauth.ErrAlreadyMember):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "That address already belongs to this organization."})
	case errors.Is(err, adminauth.ErrInvitationAccount):
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "That address already has a Latchway account. Sign in to it to accept the invitation."})
	case errors.Is(err, adminauth.ErrInvitationEmail):
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "This invitation is for a different email address than the account you're signed in to."})
	default:
		api.handleAdminAuthError(w, r, err)
	}
}

func (api *API) listInvitations(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	items, err := api.auth.ListInvitations(r.Context(), principal)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "email_delivery": api.mailer != nil})
}

type createInvitationRequest struct {
	Email       string `json:"email"`
	Role        string `json:"role"`
	DisplayName string `json:"display_name"`
	SendEmail   bool   `json:"send_email"`
}

// deliverInvitation emails the link when asked and possible, and records the result.
func (api *API) deliverInvitation(r *http.Request, principal adminauth.Principal, invitation adminauth.Invitation, link string, send bool) adminauth.Invitation {
	if !send || api.mailer == nil {
		return invitation
	}
	organization := principal.OrganizationID
	if name, err := api.auth.OrganizationName(r.Context(), principal.OrganizationID); err == nil {
		organization = name
	}
	body := fmt.Sprintf("%s invited you to join %s on Latchway as %s.\n\nAccept the invitation:\n%s\n\nThe link works once and expires on %s. If you weren't expecting this, you can ignore this email.\n",
		invitation.InvitedBy, organization, invitation.Role, link, invitation.ExpiresAt.UTC().Format("2 January 2006 at 15:04 UTC"))
	err := api.mailer.Send(r.Context(), mail.Message{To: invitation.Email, Subject: "You're invited to " + organization + " on Latchway", Body: body})
	if err != nil {
		api.logger.WarnContext(r.Context(), "invitation email failed", "admin_invitation_id", invitation.ID, "error_class", fmt.Sprintf("%T", err))
	}
	if recordErr := api.auth.RecordInvitationEmail(r.Context(), principal.OrganizationID, invitation.ID, err == nil); recordErr != nil {
		api.logger.WarnContext(r.Context(), "invitation email status unrecorded", "admin_invitation_id", invitation.ID)
		return invitation
	}
	now := time.Now().UTC()
	if err == nil {
		invitation.EmailStatus, invitation.EmailSentAt = "sent", &now
	} else {
		invitation.EmailStatus = "failed"
	}
	return invitation
}

func (api *API) createInvitation(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[createInvitationRequest](r)
	role := adminauth.Role(request.Role)
	if err != nil || role.Validate() != nil || len(request.DisplayName) > 200 {
		api.writeProblem(w, r, invalidRequest("Send an email address, a role, and optionally a name of up to 200 characters."))
		return
	}
	if _, err := adminauth.NormalizeEmail(request.Email); err != nil {
		api.writeProblem(w, r, invalidRequest("Enter a valid email address."))
		return
	}
	if request.SendEmail && api.mailer == nil {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "This server can't send email. Share the invitation link instead."})
		return
	}
	if required, err := api.auth.SSORequiredFor(r.Context(), principal.OrganizationID, role); err != nil {
		api.internal(w, r, err)
		return
	} else if required {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "This organization requires single sign-on, so members other than owners join by signing in with SSO."})
		return
	}
	token, hash, err := adminauth.NewInvitationToken()
	if err != nil {
		api.internal(w, r, err)
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	invitation, err := api.auth.CreateInvitation(r.Context(), principal, adminauth.CreateInvitationInput{
		Email: request.Email, DisplayName: strings.TrimSpace(request.DisplayName), Role: role,
		TokenHash: hash, Lifetime: invitationLifetime, RequestID: requestID,
	})
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	link := api.invitationURL(token)
	invitation = api.deliverInvitation(r, principal, invitation, link, request.SendEmail)
	writeJSON(w, http.StatusCreated, map[string]any{"invitation": invitation, "url": link})
}

func (api *API) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	invitation, err := api.auth.RevokeInvitation(r.Context(), principal, chi.URLParam(r, "invitationID"), requestID)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, invitation)
}

type renewInvitationRequest struct {
	SendEmail bool `json:"send_email"`
}

func (api *API) renewInvitation(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[renewInvitationRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The renewal request is invalid."))
		return
	}
	if request.SendEmail && api.mailer == nil {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "This server can't send email. Share the invitation link instead."})
		return
	}
	token, hash, err := adminauth.NewInvitationToken()
	if err != nil {
		api.internal(w, r, err)
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	invitation, err := api.auth.RenewInvitation(r.Context(), principal, chi.URLParam(r, "invitationID"), hash, invitationLifetime, requestID)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	link := api.invitationURL(token)
	invitation = api.deliverInvitation(r, principal, invitation, link, request.SendEmail)
	writeJSON(w, http.StatusOK, map[string]any{"invitation": invitation, "url": link})
}

type invitationTokenRequest struct {
	Token string `json:"token"`
}

// previewInvitation tells the holder of a link what they're invited to.
func (api *API) previewInvitation(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	request, err := decodeJSON[invitationTokenRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("Send the invitation token."))
		return
	}
	preview, err := api.auth.PreviewInvitation(r.Context(), request.Token)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

type acceptInvitationRequest struct {
	Token       string `json:"token"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// acceptInvitation creates the invited account with the password its holder
// chooses and signs it in. An address that already has an account claims the
// invitation after signing in instead.
func (api *API) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	request, err := decodeJSON[acceptInvitationRequest](r)
	name := strings.TrimSpace(request.DisplayName)
	if err != nil || name == "" || len(name) > 200 || len(request.Password) < minimumAdministratorPasswordLength || len(request.Password) > 1024 {
		api.writeProblem(w, r, invalidRequest("Enter your name and a password of at least 12 characters."))
		return
	}
	preview, err := api.auth.PreviewInvitation(r.Context(), request.Token)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	if preview.AccountExists {
		api.handleInvitationError(w, r, adminauth.ErrInvitationAccount)
		return
	}
	if api.refuseWhenSSORequired(w, r, preview.OrganizationID, preview.Role) {
		return
	}
	password := []byte(request.Password)
	hash, err := api.hasher.Hash(password)
	clear(password)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The password is invalid."))
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	accepted, err := api.auth.AcceptInvitationWithNewAccount(r.Context(), request.Token, name, hash, requestID)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	view, err := api.control.AdminView(r.Context(), accepted.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	membership, ok := selectMembership(view.Memberships, accepted.OrganizationID)
	if !ok {
		api.internal(w, r, errors.New("accepted invitation has no membership"))
		return
	}
	api.issueSignInSession(w, r, view, membership, adminauth.DeviceSummaryFromUserAgent(r.UserAgent()), requestID, adminauth.SignInPassword)
}

// claimInvitation adds the signed-in administrator to the invited
// organization. The console then moves the session there.
func (api *API) claimInvitation(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can accept an invitation."})
		return
	}
	request, err := decodeJSON[invitationTokenRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("Send the invitation token."))
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	accepted, err := api.auth.ClaimInvitation(r.Context(), principal, request.Token, requestID)
	if err != nil {
		api.handleInvitationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organization_id": accepted.OrganizationID, "role": accepted.Role})
}
