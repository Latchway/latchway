package adminapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/oidc"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/secrets"
)

const (
	// ssoLoginLifetime bounds the time a sign-in may spend at the identity provider.
	ssoLoginLifetime = 10 * time.Minute
	// ssoBrowserCookie binds a pending login to the browser that started it. It
	// is Lax because the provider's redirect back is a cross-site navigation.
	ssoBrowserCookie = "__Host-latchway_sso"
	ssoCallbackPath  = "/admin/v1/auth/sso/callback"
)

// WithOIDCClient replaces the OpenID Connect client; tests use it with an
// in-memory provider.
func WithOIDCClient(client *oidc.Client) Option {
	return func(api *API) error {
		if client == nil {
			return errors.New("OpenID Connect client is nil")
		}
		api.oidc = client
		return nil
	}
}

func (api *API) ssoRedirectURI() string {
	return api.publicOrigin + ssoCallbackPath
}

type ssoProviderRequest struct {
	Issuer              string   `json:"issuer"`
	ClientID            string   `json:"client_id"`
	ClientSecret        *string  `json:"client_secret"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	ProvisionRole       *string  `json:"provision_role"`
	Enabled             *bool    `json:"enabled"`
	RequireSSO          *bool    `json:"require_sso"`
}

func (api *API) ssoConfigurationDocument(provider *adminauth.SSOProvider) map[string]any {
	return map[string]any{"redirect_uri": api.ssoRedirectURI(), "provider": provider}
}

func (api *API) ownOrganization(w http.ResponseWriter, r *http.Request) (adminauth.Principal, bool) {
	principal := mustPrincipal(r.Context())
	if chi.URLParam(r, "organizationID") != principal.OrganizationID {
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "The organization was not found."})
		return principal, false
	}
	if !principal.Allows(adminauth.ManageOwners, adminauth.AuthorizationContext{}) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "Only an owner can manage single sign-on."})
		return principal, false
	}
	return principal, true
}

func (api *API) getSSOProvider(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	stored, err := api.auth.OrganizationSSOProvider(r.Context(), principal.OrganizationID)
	if errors.Is(err, adminauth.ErrSSONotConfigured) {
		writeJSON(w, http.StatusOK, api.ssoConfigurationDocument(nil))
		return
	}
	if err != nil {
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ssoConfigurationDocument(&stored.SSOProvider))
}

func (api *API) putSSOProvider(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	if api.factors == nil {
		api.writeProblem(w, r, problem.Error{Code: "server_not_ready", Detail: "Single sign-on needs the master key, which this server doesn't have."})
		return
	}
	request, err := decodeJSON[ssoProviderRequest](r)
	if err != nil || request.Enabled == nil || request.RequireSSO == nil || strings.TrimSpace(request.ClientID) == "" ||
		len(request.ClientID) > 512 || (request.ClientSecret != nil && (*request.ClientSecret == "" || len(*request.ClientSecret) > 1024)) {
		api.writeProblem(w, r, invalidRequest("Send the issuer, client ID, enabled and require_sso, and a client secret of up to 1024 characters when setting one."))
		return
	}
	domains, err := adminauth.NormalizeEmailDomains(request.AllowedEmailDomains)
	if err != nil {
		api.writeProblem(w, r, invalidRequest("Allowed email domains must be up to 20 domain names, like example.com."))
		return
	}
	var role *adminauth.Role
	if request.ProvisionRole != nil {
		value := adminauth.Role(*request.ProvisionRole)
		if value == adminauth.RoleOwner || value.Validate() != nil {
			api.writeProblem(w, r, invalidRequest("New accounts can be created as admin, operator or viewer, never owner."))
			return
		}
		role = &value
	}
	if *request.RequireSSO && !*request.Enabled {
		api.writeProblem(w, r, invalidRequest("Single sign-on must be enabled to require it."))
		return
	}
	issuer, err := oidc.CanonicalIssuer(strings.TrimSpace(request.Issuer))
	if err != nil {
		api.writeProblem(w, r, invalidRequest("The issuer must be the identity provider's https URL, without a query or fragment."))
		return
	}
	discovered, err := api.oidc.Discover(r.Context(), issuer)
	if err != nil {
		api.writeProblem(w, r, problem.Error{Code: "configuration_invalid", Detail: "The identity provider couldn't be used: " + strings.TrimPrefix(err.Error(), oidc.ErrDiscovery.Error()+": ") + "."})
		return
	}
	input := adminauth.SaveSSOProviderInput{
		Issuer: discovered.Issuer, ClientID: request.ClientID, AuthorizationEndpoint: discovered.AuthorizationEndpoint,
		TokenEndpoint: discovered.TokenEndpoint, JWKSURI: discovered.JWKSURI, AllowedEmailDomains: domains,
		ProvisionRole: role, Enabled: *request.Enabled, RequireSSO: *request.RequireSSO,
	}
	if request.ClientSecret != nil {
		plaintext := []byte(*request.ClientSecret)
		envelope, sealErr := api.factors.SealOrganizationSSOSecret(plaintext, principal.OrganizationID)
		clear(plaintext)
		if sealErr != nil {
			api.internal(w, r, sealErr)
			return
		}
		input.Secret = &adminauth.SealedFactor{KeyID: envelope.KeyID, Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext}
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	saved, err := api.auth.SaveSSOProvider(r.Context(), principal, input, requestID)
	if err != nil {
		if errors.Is(err, adminauth.ErrSSONotConfigured) {
			api.writeProblem(w, r, invalidRequest("Send the client secret when setting up single sign-on."))
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, api.ssoConfigurationDocument(&saved))
}

func (api *API) removeSSOProvider(w http.ResponseWriter, r *http.Request) {
	principal, ok := api.ownOrganization(w, r)
	if !ok {
		return
	}
	requestID, err := newMutationOperationID(r.Context())
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.RemoveSSOProvider(r.Context(), principal, requestID); err != nil {
		if errors.Is(err, adminauth.ErrSSONotConfigured) {
			api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "Single sign-on isn't set up."})
			return
		}
		api.handleAdminAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type ssoStartRequest struct {
	OrganizationSlug string `json:"organization_slug"`
}

func randomValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// startSSO begins a sign-in at the organization's identity provider. The
// console navigates to the returned URL.
func (api *API) startSSO(w http.ResponseWriter, r *http.Request) {
	if !api.optionalOriginValid(r) {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "The request origin is not allowed."})
		return
	}
	request, err := decodeJSON[ssoStartRequest](r)
	if err != nil || strings.TrimSpace(request.OrganizationSlug) == "" {
		api.writeProblem(w, r, invalidRequest("Enter your organization's sign-in name."))
		return
	}
	if api.factors == nil {
		api.writeProblem(w, r, problem.Error{Code: "server_not_ready", Detail: "Single sign-on is unavailable on this server."})
		return
	}
	provider, err := api.auth.EnabledSSOProviderBySlug(r.Context(), request.OrganizationSlug)
	if errors.Is(err, adminauth.ErrSSONotConfigured) {
		api.writeProblem(w, r, problem.Error{Code: "resource_not_found", Detail: "Single sign-on isn't set up for that organization. Check the name, or sign in with your email."})
		return
	}
	if err != nil {
		api.internal(w, r, err)
		return
	}
	state, nonce, verifier, err := oidc.NewLogin()
	if err != nil {
		api.internal(w, r, err)
		return
	}
	binding, err := randomValue()
	if err != nil {
		api.internal(w, r, err)
		return
	}
	if err := api.auth.CreateSSOState(r.Context(), state, binding, adminauth.SSOLoginState{
		OrganizationID: provider.OrganizationID, Nonce: nonce, CodeVerifier: verifier,
	}, ssoLoginLifetime); err != nil {
		if errors.Is(err, adminauth.ErrSSOBusy) {
			api.writeProblem(w, r, problem.Error{Code: "rate_limited", Detail: "Too many single sign-on attempts are in progress for this organization. Try again shortly.", RetryAfterSeconds: 60})
			return
		}
		api.internal(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: ssoBrowserCookie, Value: binding, Path: "/", MaxAge: int(ssoLoginLifetime.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{
		"authorization_url": oidc.AuthorizationURL(oidc.Provider{
			Issuer: provider.Issuer, AuthorizationEndpoint: provider.AuthorizationEndpoint,
		}, provider.ClientID, api.ssoRedirectURI(), state, nonce, verifier),
	})
}

// ssoFailure sends the browser back to the console with a stable reason it
// explains; nothing about the identity is put in the URL.
func (api *API) ssoFailure(w http.ResponseWriter, r *http.Request, reason string, err error) {
	if err != nil {
		// Only the OpenID Connect errors are worded for logs; others may carry stored values.
		detail := fmt.Sprintf("%T", err)
		if errors.Is(err, oidc.ErrExchange) || errors.Is(err, oidc.ErrIDToken) || errors.Is(err, oidc.ErrDiscovery) {
			detail = err.Error()
		}
		api.logger.WarnContext(r.Context(), "administrator single sign-on failed", "reason", reason, "error", detail)
	}
	http.Redirect(w, r, "/?sso_error="+url.QueryEscape(reason), http.StatusSeeOther)
}

// ssoCallback finishes a sign-in when the identity provider redirects back.
func (api *API) ssoCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	http.SetCookie(w, &http.Cookie{Name: ssoBrowserCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	binding := ""
	if cookie, err := r.Cookie(ssoBrowserCookie); err == nil {
		binding = cookie.Value
	}
	login, err := api.auth.ConsumeSSOState(r.Context(), query.Get("state"), binding)
	if err != nil {
		api.ssoFailure(w, r, "expired", nil)
		return
	}
	if code := query.Get("error"); code != "" {
		api.ssoFailure(w, r, "denied", errors.New(oidc.AuthorizationError(code)))
		return
	}
	provider, err := api.auth.OrganizationSSOProvider(r.Context(), login.OrganizationID)
	if err != nil || !provider.Enabled || api.factors == nil {
		api.ssoFailure(w, r, "unavailable", err)
		return
	}
	secret, err := api.factors.OpenOrganizationSSOSecret(secrets.Envelope{
		FormatVersion: 1, Algorithm: "AES-256-GCM", KeyID: provider.Secret.KeyID, Nonce: provider.Secret.Nonce, Ciphertext: provider.Secret.Ciphertext,
	}, provider.OrganizationID)
	if err != nil {
		api.ssoFailure(w, r, "unavailable", err)
		return
	}
	endpoints := oidc.Provider{Issuer: provider.Issuer, AuthorizationEndpoint: provider.AuthorizationEndpoint, TokenEndpoint: provider.TokenEndpoint, JWKSURI: provider.JWKSURI}
	idToken, err := api.oidc.Exchange(r.Context(), endpoints, provider.ClientID, string(secret), api.ssoRedirectURI(), query.Get("code"), login.CodeVerifier)
	clear(secret)
	if err != nil {
		api.ssoFailure(w, r, "failed", err)
		return
	}
	claims, err := api.oidc.VerifyIDToken(r.Context(), endpoints, provider.ClientID, idToken, login.Nonce)
	if err != nil {
		api.ssoFailure(w, r, "failed", err)
		return
	}
	requestID, err := id.New(id.AdminRequest)
	if err != nil {
		api.ssoFailure(w, r, "failed", err)
		return
	}
	resolution, err := api.auth.ResolveSSOIdentity(r.Context(), provider, adminauth.SSOIdentity{
		Issuer: provider.Issuer, Subject: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified, Name: claims.Name,
	}, requestID)
	switch {
	case errors.Is(err, adminauth.ErrSSONoAccount):
		api.ssoFailure(w, r, "no_account", nil)
		return
	case errors.Is(err, adminauth.ErrSSOEmailUnverified):
		api.ssoFailure(w, r, "unverified_email", nil)
		return
	case errors.Is(err, adminauth.ErrSSODomain):
		api.ssoFailure(w, r, "domain", nil)
		return
	case errors.Is(err, adminauth.ErrAdminConflict):
		api.ssoFailure(w, r, "conflict", nil)
		return
	case err != nil:
		api.ssoFailure(w, r, "failed", err)
		return
	}
	view, err := api.control.AdminView(r.Context(), resolution.AdminUserID)
	if err != nil {
		api.ssoFailure(w, r, "failed", err)
		return
	}
	membership, ok := selectMembership(view.Memberships, provider.OrganizationID)
	if !ok || membership.OrganizationID != provider.OrganizationID {
		api.ssoFailure(w, r, "no_account", nil)
		return
	}
	if _, err := api.createSignInSession(w, r, membership, view.ID, adminauth.DeviceSummaryFromUserAgent(r.UserAgent()), requestID, adminauth.SignInSSO); err != nil {
		api.ssoFailure(w, r, "failed", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// refuseWhenSSORequired answers a password or passkey sign-in into an
// organization that requires single sign-on for the member's role.
func (api *API) refuseWhenSSORequired(w http.ResponseWriter, r *http.Request, organizationID string, role adminauth.Role) bool {
	required, err := api.auth.SSORequiredFor(r.Context(), organizationID, role)
	if err != nil {
		api.internal(w, r, err)
		return true
	}
	if required {
		api.writeProblem(w, r, problem.Error{Code: "permission_denied", Detail: "This organization requires single sign-on. Use Sign in with SSO."})
		return true
	}
	return false
}
