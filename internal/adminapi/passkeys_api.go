package adminapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/webauthn"
)

// passkeyCeremonyLifetime bounds how long a browser may take over a passkey prompt.
const passkeyCeremonyLifetime = 5 * time.Minute

var b64url = base64.RawURLEncoding

// relyingParty is this server as passkeys see it. Passkeys need the console
// on a domain name over HTTPS (or localhost), because browsers refuse IP
// addresses as relying party IDs.
func (api *API) relyingParty() (webauthn.RelyingParty, bool) {
	parsed, err := url.Parse(api.publicOrigin)
	if err != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil {
		return webauthn.RelyingParty{}, false
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" {
		return webauthn.RelyingParty{}, false
	}
	return webauthn.RelyingParty{ID: parsed.Hostname(), Origin: api.publicOrigin}, true
}

func (api *API) requireRelyingParty(w http.ResponseWriter, r *http.Request) (webauthn.RelyingParty, bool) {
	rp, ok := api.relyingParty()
	if !ok {
		api.writeProblem(w, r, problem.Error{Code: "server_not_ready", Detail: "Passkeys need the console to be served from a domain name over HTTPS."})
	}
	return rp, ok
}

// signInMethods lists how administrators can sign in to this deployment.
func (api *API) signInMethods() []string {
	if _, ok := api.relyingParty(); ok {
		return []string{"password", "passkey"}
	}
	return []string{"password"}
}

type passkeyDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func passkeyDescriptors(credentialIDs [][]byte) []passkeyDescriptor {
	descriptors := make([]passkeyDescriptor, 0, len(credentialIDs))
	for _, credentialID := range credentialIDs {
		descriptors = append(descriptors, passkeyDescriptor{Type: "public-key", ID: b64url.EncodeToString(credentialID)})
	}
	return descriptors
}

// passkeyRequestOptions follows the WebAuthn Level 3 JSON encoding of
// PublicKeyCredentialRequestOptions.
func passkeyRequestOptions(rp webauthn.RelyingParty, challenge []byte, allow [][]byte) map[string]any {
	return map[string]any{"public_key": map[string]any{
		"challenge":        b64url.EncodeToString(challenge),
		"rpId":             rp.ID,
		"timeout":          passkeyCeremonyLifetime.Milliseconds(),
		"userVerification": "required",
		"allowCredentials": passkeyDescriptors(allow),
	}}
}

// The credential documents follow the WebAuthn Level 3 JSON encoding that
// PublicKeyCredential.toJSON() produces.
type registrationCredential struct {
	ID                      string                     `json:"id"`
	RawID                   string                     `json:"rawId"`
	Type                    string                     `json:"type"`
	AuthenticatorAttachment string                     `json:"authenticatorAttachment"`
	ClientExtensionResults  map[string]json.RawMessage `json:"clientExtensionResults"`
	Response                struct {
		ClientDataJSON     string   `json:"clientDataJSON"`
		AttestationObject  string   `json:"attestationObject"`
		AuthenticatorData  string   `json:"authenticatorData"`
		Transports         []string `json:"transports"`
		PublicKey          string   `json:"publicKey"`
		PublicKeyAlgorithm int      `json:"publicKeyAlgorithm"`
	} `json:"response"`
}

type assertionCredential struct {
	ID                      string                     `json:"id"`
	RawID                   string                     `json:"rawId"`
	Type                    string                     `json:"type"`
	AuthenticatorAttachment string                     `json:"authenticatorAttachment"`
	ClientExtensionResults  map[string]json.RawMessage `json:"clientExtensionResults"`
	Response                struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

// decodedAssertion is an assertion with its binary fields decoded.
type decodedAssertion struct {
	credentialID      []byte
	clientDataJSON    []byte
	challenge         []byte
	authenticatorData []byte
	signature         []byte
	userHandle        []byte
}

func decodeAssertion(credential *assertionCredential) (decodedAssertion, bool) {
	if credential == nil || credential.Type != "public-key" || credential.ID != credential.RawID {
		return decodedAssertion{}, false
	}
	var decoded decodedAssertion
	var err error
	if decoded.credentialID, err = b64url.DecodeString(credential.RawID); err != nil || len(decoded.credentialID) == 0 {
		return decodedAssertion{}, false
	}
	if decoded.clientDataJSON, err = b64url.DecodeString(credential.Response.ClientDataJSON); err != nil {
		return decodedAssertion{}, false
	}
	if _, decoded.challenge, err = webauthn.ParseClientData(decoded.clientDataJSON); err != nil {
		return decodedAssertion{}, false
	}
	if decoded.authenticatorData, err = b64url.DecodeString(credential.Response.AuthenticatorData); err != nil {
		return decodedAssertion{}, false
	}
	if decoded.signature, err = b64url.DecodeString(credential.Response.Signature); err != nil {
		return decodedAssertion{}, false
	}
	if decoded.userHandle, err = b64url.DecodeString(credential.Response.UserHandle); err != nil {
		return decodedAssertion{}, false
	}
	return decoded, true
}

// verifyPasskeyAssertion checks an assertion whose challenge was already
// consumed. It returns false for any credential, signature or counter problem.
func (api *API) verifyPasskeyAssertion(r *http.Request, rp webauthn.RelyingParty, assertion decodedAssertion, wantAdminUserID string) (string, bool, error) {
	stored, err := api.auth.PasskeyByCredentialID(r.Context(), assertion.credentialID)
	if errors.Is(err, adminauth.ErrAdminNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if wantAdminUserID != "" && stored.AdminUserID != wantAdminUserID {
		return "", false, nil
	}
	if len(assertion.userHandle) != 0 {
		handle, err := api.auth.WebAuthnUserHandle(r.Context(), stored.AdminUserID)
		if err != nil {
			return "", false, err
		}
		if subtle.ConstantTimeCompare(handle, assertion.userHandle) != 1 {
			return "", false, nil
		}
	}
	publicKey, err := webauthn.PublicKeyFromCoordinates(stored.X, stored.Y)
	if err != nil {
		return "", false, err
	}
	result, err := webauthn.VerifyAssertion(rp, assertion.challenge, assertion.clientDataJSON, assertion.authenticatorData, assertion.signature, publicKey)
	if err != nil {
		return "", false, nil
	}
	if err := api.auth.RecordPasskeyUse(r.Context(), stored.ID, result.SignCount, result.BackupState); err != nil {
		if errors.Is(err, adminauth.ErrPasskeyCounter) {
			api.logger.Warn("passkey signature counter did not advance", "admin_passkey_id", stored.ID)
			return "", false, nil
		}
		return "", false, err
	}
	return stored.AdminUserID, true, nil
}

func (api *API) listPasskeys(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r) {
		api.writeProblem(w, r, invalidRequest("The passkey query is invalid."))
		return
	}
	items, err := api.auth.ListPasskeys(r.Context(), mustPrincipal(r.Context()).AdminUserID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type passwordConfirmationRequest struct {
	Password string `json:"password"`
}

// confirmOwnPassword re-checks a console session's password under the
// password-change limiter before a sensitive change.
func (api *API) confirmOwnPassword(w http.ResponseWriter, r *http.Request, principal adminauth.Principal, password string) bool {
	if password == "" || len(password) > 1024 {
		api.writeProblem(w, r, invalidRequest("Enter your password."))
		return false
	}
	key := sha256.Sum256([]byte("password-change:" + principal.AdminUserID))
	if !api.loginLimiter.allow(key, time.Now()) {
		api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many incorrect passwords.", RetryAfterSeconds: 300})
		return false
	}
	stored, err := api.auth.PasswordCredentialByAdminUserID(r.Context(), principal.AdminUserID)
	if errors.Is(err, adminauth.ErrAdminNotFound) {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "Your account has no password because it was created by single sign-on. An owner can set one for you."})
		return false
	}
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return false
	}
	plaintext := []byte(password)
	verification, verifyErr := api.hasher.Verify(plaintext, stored)
	clear(plaintext)
	if verifyErr != nil || !verification.Match {
		api.loginLimiter.failure(key, time.Now())
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The password is incorrect."})
		return false
	}
	api.loginLimiter.success(key)
	return true
}

func (api *API) passkeyRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can add a passkey."})
		return
	}
	rp, ok := api.requireRelyingParty(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[passwordConfirmationRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("Enter your password."))
		return
	}
	if !api.confirmOwnPassword(w, r, principal, request.Password) {
		return
	}
	view, err := api.control.AdminView(r.Context(), principal.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	handle, err := api.auth.WebAuthnUserHandle(r.Context(), principal.AdminUserID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	existing, err := api.auth.PasskeyCredentialIDs(r.Context(), principal.AdminUserID)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	challenge, err := api.auth.CreateWebAuthnChallenge(r.Context(), adminauth.WebAuthnRegister, principal.AdminUserID, "", passkeyCeremonyLifetime)
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	displayName := view.DisplayName
	if displayName == "" {
		displayName = view.Email
	}
	writeJSON(w, http.StatusOK, map[string]any{"public_key": map[string]any{
		"rp":                 map[string]string{"id": rp.ID, "name": api.totpIssuer()},
		"user":               map[string]string{"id": b64url.EncodeToString(handle), "name": view.Email, "displayName": displayName},
		"challenge":          b64url.EncodeToString(challenge),
		"pubKeyCredParams":   []map[string]any{{"type": "public-key", "alg": webauthn.AlgorithmES256}},
		"timeout":            passkeyCeremonyLifetime.Milliseconds(),
		"excludeCredentials": passkeyDescriptors(existing),
		"authenticatorSelection": map[string]any{
			"residentKey": "required", "requireResidentKey": true, "userVerification": "required",
		},
		"attestation": "none",
	}})
}

type addPasskeyRequest struct {
	Name       string                  `json:"name"`
	Credential *registrationCredential `json:"credential"`
}

func (api *API) addPasskey(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can add a passkey."})
		return
	}
	rp, ok := api.requireRelyingParty(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[addPasskeyRequest](r)
	name := strings.TrimSpace(request.Name)
	if err != nil || request.Credential == nil || request.Credential.Type != "public-key" || name == "" || len(name) > 64 {
		api.writeProblem(w, r, invalidRequest("Name the passkey (up to 64 characters) and send the browser's registration response."))
		return
	}
	clientDataJSON, clientErr := b64url.DecodeString(request.Credential.Response.ClientDataJSON)
	attestationObject, attestationErr := b64url.DecodeString(request.Credential.Response.AttestationObject)
	_, challenge, parseErr := webauthn.ParseClientData(clientDataJSON)
	if clientErr != nil || attestationErr != nil || parseErr != nil {
		api.writeProblem(w, r, invalidRequest("The passkey registration response is malformed."))
		return
	}
	owner, err := api.auth.ConsumeWebAuthnChallenge(r.Context(), challenge, adminauth.WebAuthnRegister, "")
	if err != nil || owner != principal.AdminUserID {
		if err != nil && !errors.Is(err, adminauth.ErrWebAuthnChallengeInvalid) {
			api.internal(w, r, err)
			return
		}
		api.writeProblem(w, r, invalidRequest("The passkey prompt expired. Start again."))
		return
	}
	credential, err := webauthn.VerifyRegistration(rp, challenge, clientDataJSON, attestationObject)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The passkey couldn't be verified. Use a passkey that supports user verification and ES256."))
		return
	}
	if b64url.EncodeToString(credential.ID) != request.Credential.RawID {
		api.writeProblem(w, r, invalidRequest("The passkey registration response is inconsistent."))
		return
	}
	x, y, err := webauthn.Coordinates(credential.PublicKey)
	if err != nil {
		api.internal(w, r, err)
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
	added, issued, err := api.auth.AddPasskey(r.Context(), principal, adminauth.NewPasskey{
		CredentialID: credential.ID, X: x, Y: y, SignCount: credential.SignCount, AAGUID: credential.AAGUID,
		BackupEligible: credential.BackupEligible, BackupState: credential.BackupState, Name: name,
	}, hashes, requestID)
	if err != nil {
		if errors.Is(err, adminauth.ErrAdminConflict) {
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "This passkey is already registered."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	document := map[string]any{"passkey": added}
	if issued {
		document["recovery_codes"] = codes
	}
	writeJSON(w, http.StatusCreated, document)
}

func (api *API) removePasskey(w http.ResponseWriter, r *http.Request) {
	principal := mustPrincipal(r.Context())
	if principal.Method != adminauth.AuthenticationSession {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only a console session can remove a passkey."})
		return
	}
	request, err := decodeJSON[passwordConfirmationRequest](r)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("Enter your password."))
		return
	}
	passkeyID := chi.URLParam(r, "adminPasskeyID")
	if id.Validate(passkeyID, id.AdminPasskey) != nil {
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The passkey was not found."})
		return
	}
	if !api.confirmOwnPassword(w, r, principal, request.Password) {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.RemovePasskey(r.Context(), principal, passkeyID, requestID); err != nil {
		switch {
		case errors.Is(err, adminauth.ErrTwoFactorRequired):
			api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "An organization you belong to requires two-factor sign-in, and this is your last second factor."})
		case errors.Is(err, adminauth.ErrAdminNotFound):
			api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The passkey was not found."})
		default:
			api.handleAdminAuthError(w, r, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *API) passkeySignInOptions(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	rp, ok := api.requireRelyingParty(w, r)
	if !ok {
		return
	}
	challenge, err := api.auth.CreateWebAuthnChallenge(r.Context(), adminauth.WebAuthnSignIn, "", "", passkeyCeremonyLifetime)
	if err != nil {
		if errors.Is(err, adminauth.ErrWebAuthnBusy) {
			api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many passkey sign-ins are in progress. Try again shortly, or sign in with your password.", RetryAfterSeconds: 60})
			return
		}
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyRequestOptions(rp, challenge, nil))
}

type passkeySignInRequest struct {
	Credential     *assertionCredential `json:"credential"`
	OrganizationID string               `json:"organization_id"`
}

// passkeySignIn signs in with a passkey alone. User verification on the
// authenticator stands in for both the password and the second factor.
func (api *API) passkeySignIn(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	rp, ok := api.requireRelyingParty(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[passkeySignInRequest](r)
	if err != nil || (request.OrganizationID != "" && id.Validate(request.OrganizationID, id.Organization) != nil) {
		api.writeProblem(w, r, invalidRequest("The passkey sign-in request is invalid."))
		return
	}
	assertion, ok := decodeAssertion(request.Credential)
	if !ok {
		api.writeProblem(w, r, invalidRequest("The passkey response is malformed."))
		return
	}
	failed := problem.Error{Code: "authentication_required", Detail: "That passkey couldn't sign you in. Try again, or sign in with your password."}
	if _, err := api.auth.ConsumeWebAuthnChallenge(r.Context(), assertion.challenge, adminauth.WebAuthnSignIn, ""); err != nil {
		if errors.Is(err, adminauth.ErrWebAuthnChallengeInvalid) {
			api.writeProblem(w, r, failed)
			return
		}
		api.internal(w, r, err)
		return
	}
	if len(assertion.userHandle) == 0 {
		api.writeProblem(w, r, failed)
		return
	}
	adminUserID, verified, err := api.verifyPasskeyAssertion(r, rp, assertion, "")
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if !verified {
		api.writeProblem(w, r, failed)
		return
	}
	view, err := api.control.AdminView(r.Context(), adminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	requested := request.OrganizationID
	if requested == "" {
		signIn, err := api.auth.SignInState(r.Context(), adminUserID)
		if err != nil {
			api.internal(w, r, err)
			return
		}
		if _, ok := selectMembership(view.Memberships, signIn.LastOrganizationID); ok {
			requested = signIn.LastOrganizationID
		}
	}
	membership, ok := selectMembership(view.Memberships, requested)
	if !ok {
		api.writeProblem(w, r, failed)
		return
	}
	if api.refuseWhenSSORequired(w, r, membership.OrganizationID, membership.Role) {
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	api.issueSignInSession(w, r, view, membership, adminauth.DeviceSummaryFromUserAgent(r.UserAgent()), requestID, adminauth.SignInPasskey)
}

type secondFactorPasskeyOptionsRequest struct {
	Challenge string `json:"challenge"`
}

// secondFactorPasskeyOptions starts a passkey prompt for a sign-in whose
// password was already correct.
func (api *API) secondFactorPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	rp, ok := api.requireRelyingParty(w, r)
	if !ok {
		return
	}
	request, err := decodeJSON[secondFactorPasskeyOptionsRequest](r)
	if err != nil || request.Challenge == "" {
		api.writeProblem(w, r, invalidRequest("Send the sign-in challenge."))
		return
	}
	pending, err := api.auth.PendingSignInChallenge(r.Context(), request.Challenge)
	if err != nil {
		if errors.Is(err, adminauth.ErrSignInChallengeInvalid) {
			api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "This sign-in attempt expired or was used up. Sign in again."})
			return
		}
		api.internal(w, r, err)
		return
	}
	allowed, err := api.auth.PasskeyCredentialIDs(r.Context(), pending.AdminUserID)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if len(allowed) == 0 {
		api.writeProblem(w, r, problem.Error{Code: "conflict", Detail: "This account has no passkey. Use your authenticator app or a recovery code."})
		return
	}
	challenge, err := api.auth.CreateWebAuthnChallenge(r.Context(), adminauth.WebAuthnSecondFactor, pending.AdminUserID, request.Challenge, passkeyCeremonyLifetime)
	if err != nil {
		api.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyRequestOptions(rp, challenge, allowed))
}

// verifySecondFactorPasskey checks a passkey assertion for a pending
// password sign-in. It returns false for any failure the caller counts.
func (api *API) verifySecondFactorPasskey(r *http.Request, signInChallenge, adminUserID string, credential *assertionCredential) (bool, error) {
	rp, ok := api.relyingParty()
	if !ok {
		return false, nil
	}
	assertion, ok := decodeAssertion(credential)
	if !ok {
		return false, nil
	}
	owner, err := api.auth.ConsumeWebAuthnChallenge(r.Context(), assertion.challenge, adminauth.WebAuthnSecondFactor, signInChallenge)
	if errors.Is(err, adminauth.ErrWebAuthnChallengeInvalid) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if owner != adminUserID {
		return false, nil
	}
	_, verified, err := api.verifyPasskeyAssertion(r, rp, assertion, adminUserID)
	return verified, err
}
