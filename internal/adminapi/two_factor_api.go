package adminapi

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/controlplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/secrets"
)

// signInChallengeLifetime bounds the gap between a correct password and the second factor.
const signInChallengeLifetime = 5 * time.Minute

// factorSealer seals administrator sign-in secrets with the master key:
// second-factor keys and single sign-on client secrets.
type factorSealer interface {
	SealAdministratorFactor(plaintext []byte, adminUserID string) (secrets.Envelope, error)
	OpenAdministratorFactor(envelope secrets.Envelope, adminUserID string) ([]byte, error)
	SealOrganizationSSOSecret(plaintext []byte, organizationID string) (secrets.Envelope, error)
	OpenOrganizationSSOSecret(envelope secrets.Envelope, organizationID string) ([]byte, error)
}

// WithFactorSealer enables two-factor sign-in with the master key that seals authenticator keys.
func WithFactorSealer(sealer factorSealer) Option {
	return func(api *API) error {
		if sealer == nil {
			return errors.New("administrator factor sealer is nil")
		}
		api.factors = sealer
		return nil
	}
}

func (api *API) openTOTP(adminUserID string, sealed adminauth.SealedFactor) (adminauth.TOTPSecret, error) {
	if api.factors == nil {
		return adminauth.TOTPSecret{}, errors.New("two-factor sign-in is unavailable")
	}
	raw, err := api.factors.OpenAdministratorFactor(secrets.Envelope{
		FormatVersion: 1, Algorithm: "AES-256-GCM", KeyID: sealed.KeyID, Nonce: sealed.Nonce, Ciphertext: sealed.Ciphertext,
	}, adminUserID)
	if err != nil {
		return adminauth.TOTPSecret{}, err
	}
	return adminauth.TOTPSecretFromBytes(raw), nil
}

// verifyTOTP checks a code against the administrator's key and spends its time step.
func (api *API) verifyTOTP(r *http.Request, adminUserID, code string, wantConfirmed bool) (int64, bool, error) {
	sealed, confirmed, err := api.auth.TOTPFactor(r.Context(), adminUserID)
	if errors.Is(err, adminauth.ErrAdminNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if confirmed != wantConfirmed {
		return 0, false, nil
	}
	secret, err := api.openTOTP(adminUserID, sealed)
	if err != nil {
		return 0, false, err
	}
	defer clear(secret.Bytes())
	step, ok := adminauth.MatchTOTP(secret, code, time.Now())
	if !ok {
		return 0, false, nil
	}
	if !wantConfirmed {
		return step, true, nil
	}
	used, err := api.auth.UseTOTPStep(r.Context(), adminUserID, step)
	return step, used, err
}

func (api *API) secondFactorLimiterKey(adminUserID string) [sha256.Size]byte {
	return sha256.Sum256([]byte("second-factor:" + adminUserID))
}

type loginSecondFactorRequest struct {
	Challenge    string               `json:"challenge"`
	Code         string               `json:"code"`
	RecoveryCode string               `json:"recovery_code"`
	Passkey      *assertionCredential `json:"passkey"`
}

func (request loginSecondFactorRequest) methods() int {
	count := 0
	for _, present := range []bool{request.Code != "", request.RecoveryCode != "", request.Passkey != nil} {
		if present {
			count++
		}
	}
	return count
}

// loginSecondFactor finishes a sign-in that a correct password started.
func (api *API) loginSecondFactor(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	request, err := decodeJSON[loginSecondFactorRequest](r)
	if err != nil || request.Challenge == "" || request.methods() != 1 {
		api.writeProblem(w, r, invalidRequest("Send the sign-in challenge with exactly one of a verification code, a recovery code or a passkey."))
		return
	}
	challenge, err := api.auth.PendingSignInChallenge(r.Context(), request.Challenge)
	if err != nil {
		if errors.Is(err, adminauth.ErrSignInChallengeInvalid) {
			api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "This sign-in attempt expired or was used up. Sign in again."})
			return
		}
		api.internal(w, r, err)
		return
	}
	key := api.secondFactorLimiterKey(challenge.AdminUserID)
	if !api.loginLimiter.allow(key, time.Now()) {
		api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many incorrect verification codes.", RetryAfterSeconds: 300})
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	var verified bool
	switch {
	case request.Code != "":
		_, verified, err = api.verifyTOTP(r, challenge.AdminUserID, request.Code, true)
	case request.Passkey != nil:
		verified, err = api.verifySecondFactorPasskey(r, request.Challenge, challenge.AdminUserID, request.Passkey)
	default:
		verified, err = api.auth.UseRecoveryCode(r.Context(), challenge.AdminUserID, challenge.OrganizationID, adminauth.HashRecoveryCode(request.RecoveryCode), requestID)
	}
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if !verified {
		api.loginLimiter.failure(key, time.Now())
		if failErr := api.auth.FailSignInChallenge(r.Context(), request.Challenge); failErr != nil {
			api.internal(w, r, failErr)
			return
		}
		api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "The verification code is incorrect."})
		return
	}
	api.loginLimiter.success(key)
	if err := api.auth.ConsumeSignInChallenge(r.Context(), request.Challenge); err != nil {
		api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "This sign-in attempt expired or was used up. Sign in again."})
		return
	}
	view, err := api.control.AdminView(r.Context(), challenge.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	membership, ok := selectMembership(view.Memberships, challenge.OrganizationID)
	if !ok {
		api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "The administrator credentials are invalid."})
		return
	}
	api.issueSignInSession(w, r, view, membership, challenge.DeviceSummary, requestID, adminauth.SignInPassword)
}

// createSignInSession creates the console session that ends a successful
// sign-in and sets its cookies.
func (api *API) createSignInSession(w http.ResponseWriter, r *http.Request, membership controlplane.Membership, adminUserID, deviceSummary, requestID string, method adminauth.SignInMethod) (adminauth.Principal, error) {
	issued, err := api.auth.CreateSession(r.Context(), adminauth.CreateSessionInput{
		OrganizationID: membership.OrganizationID, AdminUserID: adminUserID,
		Lifetime: api.sessionLifetime, RequestID: requestID, DeviceSummary: deviceSummary, SignInMethod: method,
	})
	if err != nil {
		return adminauth.Principal{}, err
	}
	principal := adminauth.Principal{
		OrganizationID: membership.OrganizationID, AdminUserID: adminUserID,
		Role: membership.Role, Method: adminauth.AuthenticationSession,
		CredentialID: issued.SessionID, CredentialExpiresAt: &issued.ExpiresAt, SignInMethod: method,
	}
	if err := api.fillSessionFlags(r, &principal); err != nil {
		return adminauth.Principal{}, err
	}
	api.setSession(w, issued)
	return principal, nil
}

// issueSignInSession creates the session and answers with its document.
func (api *API) issueSignInSession(w http.ResponseWriter, r *http.Request, view controlplane.AdminView, membership controlplane.Membership, deviceSummary, requestID string, method adminauth.SignInMethod) {
	principal, err := api.createSignInSession(w, r, membership, view.ID, deviceSummary, requestID, method)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, api.sessionDocument(view, principal))
}

// fillSessionFlags reads the restrictions a fresh session starts with.
func (api *API) fillSessionFlags(r *http.Request, principal *adminauth.Principal) error {
	state, err := api.auth.SignInState(r.Context(), principal.AdminUserID)
	if err != nil {
		return err
	}
	status, err := api.auth.TwoFactorStatus(r.Context(), principal.AdminUserID, principal.OrganizationID)
	if err != nil {
		return err
	}
	roles, err := api.auth.ApplicationRolesFor(r.Context(), principal.OrganizationID, principal.AdminUserID)
	if err != nil {
		return err
	}
	*principal = principal.WithApplicationRoles(roles)
	// A single sign-on session relies on the identity provider for further factors and needs no password.
	sso := principal.SignInMethod == adminauth.SignInSSO
	principal.PasswordResetRequired = state.PasswordResetRequired && !sso
	principal.TwoFactorEnrollmentRequired = status.RequiredByOrganization && !status.Enabled && !sso
	return nil
}

func (api *API) twoFactorStatus(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	status, err := api.auth.TwoFactorStatus(r.Context(), principal.AdminUserID, principal.OrganizationID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (api *API) startTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can set up two-factor sign-in."})
		return
	}
	if api.factors == nil {
		api.writeProblem(w, r, problem.Error{Code: "server_not_ready", Detail: "Two-factor sign-in is unavailable on this server."})
		return
	}
	secret, err := adminauth.NewTOTPSecret(rand.Reader)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	defer clear(secret.Bytes())
	envelope, err := api.factors.SealAdministratorFactor(secret.Bytes(), principal.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.SaveTOTPEnrollment(r.Context(), principal.AdminUserID, adminauth.SealedFactor{
		KeyID: envelope.KeyID, Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext,
	}); err != nil {
		if errors.Is(err, adminauth.ErrAdminConflict) {
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "Two-factor sign-in is already on. Turn it off before setting up another authenticator."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	view, err := api.control.AdminView(r.Context(), principal.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret.Base32(),
		"uri":    secret.URI(api.totpIssuer(), view.Email),
	})
}

// totpIssuer names this server in authenticator apps, e.g. "Latchway (console.example.com)".
func (api *API) totpIssuer() string {
	if parsed, err := url.Parse(api.publicOrigin); err == nil && parsed.Host != "" {
		return "Latchway (" + parsed.Host + ")"
	}
	return "Latchway"
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

type recoveryCodesRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

func (api *API) newRecoveryCodes(w http.ResponseWriter, r *http.Request) ([]string, [][sha256.Size]byte, bool) {
	codes, err := adminauth.NewRecoveryCodes(rand.Reader)
	if err != nil {
		api.internal(w, r, err)
		return nil, nil, false
	}
	hashes := make([][sha256.Size]byte, 0, len(codes))
	for _, code := range codes {
		hashes = append(hashes, adminauth.HashRecoveryCode(code))
	}
	return codes, hashes, true
}

func (api *API) confirmTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can set up two-factor sign-in."})
		return
	}
	request, err := decodeJSON[totpCodeRequest](r)
	if err != nil || request.Code == "" {
		api.writeProblem(w, r, invalidRequest("Enter the six-digit code from your authenticator."))
		return
	}
	key := api.secondFactorLimiterKey(principal.AdminUserID)
	if !api.loginLimiter.allow(key, time.Now()) {
		api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many incorrect verification codes.", RetryAfterSeconds: 300})
		return
	}
	step, ok, err := api.verifyTOTP(r, principal.AdminUserID, request.Code, false)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if !ok {
		api.loginLimiter.failure(key, time.Now())
		api.writeProblem(w, r, invalidRequest("That code doesn't match. Check the authenticator's clock and try the newest code."))
		return
	}
	api.loginLimiter.success(key)
	codes, hashes, ok := api.newRecoveryCodes(w, r)
	if !ok {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.ConfirmTOTP(r.Context(), principal, step, hashes, requestID); err != nil {
		if errors.Is(err, adminauth.ErrAdminConflict) {
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "There's no authenticator waiting to be confirmed. Start the setup again."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (api *API) replaceRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can replace recovery codes."})
		return
	}
	request, err := decodeJSON[recoveryCodesRequest](r)
	if err != nil || (request.Code == "") == (request.Password == "") {
		api.writeProblem(w, r, invalidRequest("Enter a current code from your authenticator app, or your password."))
		return
	}
	if request.Code != "" && !api.checkCurrentTOTP(w, r, principal.AdminUserID, request.Code) {
		return
	}
	if request.Password != "" && !api.confirmOwnPassword(w, r, principal, request.Password) {
		return
	}
	codes, hashes, ok := api.newRecoveryCodes(w, r)
	if !ok {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.ReplaceRecoveryCodes(r.Context(), principal, hashes, requestID); err != nil {
		if errors.Is(err, adminauth.ErrAdminConflict) {
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "Set up an authenticator app or a passkey before creating recovery codes."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// checkCurrentTOTP verifies a code for a confirmed key under the second-factor limiter.
func (api *API) checkCurrentTOTP(w http.ResponseWriter, r *http.Request, adminUserID, code string) bool {
	key := api.secondFactorLimiterKey(adminUserID)
	if !api.loginLimiter.allow(key, time.Now()) {
		api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many incorrect verification codes.", RetryAfterSeconds: 300})
		return false
	}
	_, ok, err := api.verifyTOTP(r, adminUserID, code, true)
	if err != nil {
		api.internal(w, r, err)
		return false
	}
	if !ok {
		api.loginLimiter.failure(key, time.Now())
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The verification code is incorrect."})
		return false
	}
	api.loginLimiter.success(key)
	return true
}

type disableTwoFactorRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (api *API) disableTwoFactor(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can remove its authenticator app."})
		return
	}
	request, err := decodeJSON[disableTwoFactorRequest](r)
	if err != nil || request.Password == "" || request.Code == "" {
		api.writeProblem(w, r, invalidRequest("Enter your password and a current authenticator code."))
		return
	}
	stored, err := api.auth.PasswordCredentialByAdminUserID(r.Context(), principal.AdminUserID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	password := []byte(request.Password)
	verification, verifyErr := api.hasher.Verify(password, stored)
	clear(password)
	if verifyErr != nil || !verification.Match {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The password is incorrect."})
		return
	}
	if !api.checkCurrentTOTP(w, r, principal.AdminUserID, request.Code) {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.DisableTwoFactor(r.Context(), principal, requestID); err != nil {
		if errors.Is(err, adminauth.ErrTwoFactorRequired) {
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "An organization you belong to requires two-factor sign-in. Add a passkey before removing your authenticator app."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) resetAdministratorTwoFactor(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	updated, err := api.auth.ResetAdministratorTwoFactor(r.Context(), principal, chi.URLParam(r, "adminUserID"), requestID)
	if err != nil {
		if errors.Is(err, adminauth.ErrAdminConflict) {
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "This administrator also belongs to another organization. Their second factor is shared across organizations, so it can't be reset from one of them."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

type twoFactorRequirementRequest struct {
	Required *bool `json:"required"`
}

func (api *API) setTwoFactorRequirement(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if chi.URLParam(r, "organizationID") != principal.OrganizationID {
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The organization was not found."})
		return
	}
	request, err := decodeJSON[twoFactorRequirementRequest](r)
	if err != nil || request.Required == nil {
		api.writeProblem(w, r, invalidRequest("Send required as true or false."))
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.SetOrganizationTwoFactorRequirement(r.Context(), principal, *request.Required, requestID); err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"required": *request.Required})
}

// twoFactorEnrollmentAllows lists what a session that must set up a second factor may still do.
func twoFactorEnrollmentAllows(r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/admin/v1")
	if passwordChangeAllows(r) {
		return true
	}
	switch {
	case r.Method == http.MethodGet && (path == "/auth/two-factor" || path == "/auth/passkeys"):
		return true
	case r.Method == http.MethodPost && (path == "/auth/two-factor/totp" || path == "/auth/two-factor/totp/confirm"):
		return true
	case r.Method == http.MethodPost && (path == "/auth/passkeys/registration-options" || path == "/auth/passkeys"):
		return true
	default:
		return false
	}
}
