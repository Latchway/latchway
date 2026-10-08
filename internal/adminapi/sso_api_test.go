package adminapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/oidc"
	"github.com/latchway/latchway/internal/oidc/oidctest"
)

const ssoIssuer = "https://idp.example.test"

type ssoHarness struct {
	t        *testing.T
	handler  http.Handler
	provider *oidctest.Provider
}

// signIn starts a sign-in for the organization, has the provider approve it
// for an account with claims, and returns the callback response.
func (harness ssoHarness) signIn(slug string, claims map[string]any) *http.Response {
	harness.t.Helper()
	started := performJSON(harness.t, harness.handler, http.MethodPost, "/admin/v1/auth/sso/start", map[string]string{"organization_slug": slug}, nil, "", selfServiceOrigin)
	if started.Code != http.StatusOK {
		harness.t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}
	var document struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	decodeResponse(harness.t, started, &document)
	binding := started.Result().Cookies()[0]
	if binding.Name != ssoBrowserCookie || !binding.HttpOnly || binding.SameSite != http.SameSiteLaxMode {
		harness.t.Fatalf("binding cookie=%+v", binding)
	}
	code, state, err := harness.provider.Authorize(document.AuthorizationURL, claims)
	if err != nil {
		harness.t.Fatal(err)
	}
	return harness.callback(url.Values{"code": {code}, "state": {state}}, binding).Result()
}

func (harness ssoHarness) callback(query url.Values, binding *http.Cookie) *httptest.ResponseRecorder {
	return performGET(harness.handler, "/admin/v1/auth/sso/callback?"+query.Encode(), binding)
}

func sessionFromRedirect(t *testing.T, response *http.Response) selfServiceSession {
	t.Helper()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" {
		t.Fatalf("callback status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	session := selfServiceSession{}
	for _, cookie := range response.Cookies() {
		switch cookie.Name {
		case adminCookieName:
			session.cookie = cookie
		case csrfCookieName:
			session.csrf = cookie.Value
		}
	}
	if session.cookie == nil {
		t.Fatal("callback set no session cookie")
	}
	return session
}

func ssoFailure(t *testing.T, response *http.Response, reason string) {
	t.Helper()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/?sso_error="+reason {
		t.Fatalf("want failure %q, got status=%d location=%q", reason, response.StatusCode, response.Header.Get("Location"))
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == adminCookieName && cookie.MaxAge >= 0 {
			t.Fatal("a failed sign-in set a session cookie")
		}
	}
}

func TestAdministratorSingleSignOnPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	manager := testAdminSecretManager(t, pool)
	provider, err := oidctest.New(ssoIssuer, "latchway-console", "test-only-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), manager,
		WithFactorSealer(testFactorSealer(t)), WithOIDCClient(&oidc.Client{HTTP: provider.Client()}))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("sso-bootstrap-token-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := withUserAgent(router)
	harness := ssoHarness{t: t, handler: handler, provider: provider}
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "acme", "organization_name": "Acme",
		"email": "owner@example.test", "display_name": "Owner", "password": "initial owner password",
	}, nil, "", selfServiceOrigin)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var organization struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &organization)
	owner := selfServiceSession{cookie: bootstrap.Result().Cookies()[0], csrf: bootstrap.Header().Get(csrfHeader)}
	configPath := "/admin/v1/organizations/" + organization.OrganizationID + "/sso"

	if before := performGET(handler, configPath, owner.cookie); before.Code != http.StatusOK ||
		!bytes.Contains(before.Body.Bytes(), []byte(`"provider":null`)) || !bytes.Contains(before.Body.Bytes(), []byte(`"redirect_uri":"https://console.example.test/admin/v1/auth/sso/callback"`)) {
		t.Fatalf("unconfigured status=%d body=%s", before.Code, before.Body.String())
	}
	if info := performGET(handler, "/admin/v1/auth/info", nil); bytes.Contains(info.Body.Bytes(), []byte(`"sso"`)) {
		t.Fatalf("sso offered before setup: %s", info.Body.String())
	}
	configuration := map[string]any{
		"issuer": ssoIssuer, "client_id": "latchway-console", "allowed_email_domains": []string{"Example.TEST"},
		"provision_role": "viewer", "enabled": true, "require_sso": false,
	}
	if missing := performJSON(t, handler, http.MethodPut, configPath, configuration, owner.cookie, owner.csrf, selfServiceOrigin); missing.Code != http.StatusBadRequest {
		t.Fatalf("new provider without secret status=%d body=%s", missing.Code, missing.Body.String())
	}
	configuration["client_secret"] = "test-only-client-secret"
	saved := performJSON(t, handler, http.MethodPut, configPath, configuration, owner.cookie, owner.csrf, selfServiceOrigin)
	if saved.Code != http.StatusOK || bytes.Contains(saved.Body.Bytes(), []byte("test-only-client-secret")) ||
		!bytes.Contains(saved.Body.Bytes(), []byte(`"token_endpoint":"https://idp.example.test/token"`)) || !bytes.Contains(saved.Body.Bytes(), []byte(`"allowed_email_domains":["example.test"]`)) {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if badIssuer := performJSON(t, handler, http.MethodPut, configPath, map[string]any{
		"issuer": "https://unknown.example.test", "client_id": "x", "enabled": true, "require_sso": false,
	}, owner.cookie, owner.csrf, selfServiceOrigin); badIssuer.Code != http.StatusUnprocessableEntity {
		t.Fatalf("undiscoverable issuer status=%d body=%s", badIssuer.Code, badIssuer.Body.String())
	}
	if info := performGET(handler, "/admin/v1/auth/info", nil); !bytes.Contains(info.Body.Bytes(), []byte(`"sso"`)) {
		t.Fatalf("sso not offered after setup: %s", info.Body.String())
	}
	if unknown := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/sso/start", map[string]string{"organization_slug": "nobody"}, nil, "", selfServiceOrigin); unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown organization status=%d", unknown.Code)
	}

	// The owner's verified email links their account; the session records how it signed in.
	ownerSSO := sessionFromRedirect(t, harness.signIn("acme", map[string]any{"sub": "owner-subject", "email": "OWNER@example.test", "email_verified": true}))
	session := performGET(handler, "/admin/v1/auth/session", ownerSSO.cookie)
	if session.Code != http.StatusOK || !bytes.Contains(session.Body.Bytes(), []byte(`"sign_in_method":"sso"`)) {
		t.Fatalf("sso session status=%d body=%s", session.Code, session.Body.String())
	}
	if members := performGET(handler, "/admin/v1/administrators", owner.cookie); !bytes.Contains(members.Body.Bytes(), []byte(`"sso_linked":true`)) {
		t.Fatalf("members body=%s", members.Body.String())
	}
	// Once linked, the subject signs in even if the provider's email changes.
	sessionFromRedirect(t, harness.signIn("acme", map[string]any{"sub": "owner-subject", "email": "renamed@example.test", "email_verified": false}))

	// A new verified address in an allowed domain gets a viewer account with no password.
	newcomer := sessionFromRedirect(t, harness.signIn("acme", map[string]any{"sub": "new-subject", "email": "newcomer@example.test", "email_verified": true, "name": "New Comer"}))
	if session := performGET(handler, "/admin/v1/auth/session", newcomer.cookie); !bytes.Contains(session.Body.Bytes(), []byte(`"role":"viewer"`)) ||
		!bytes.Contains(session.Body.Bytes(), []byte(`"display_name":"New Comer"`)) {
		t.Fatalf("provisioned session body=%s", session.Body.String())
	}
	if password := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{"email": "newcomer@example.test", "password": "anything at all"}, nil, "", selfServiceOrigin); password.Code != http.StatusUnauthorized {
		t.Fatalf("password sign-in for a provisioned account status=%d", password.Code)
	}

	// Refusals come back to the console as stable reasons, without a session.
	ssoFailure(t, harness.signIn("acme", map[string]any{"sub": "other-domain", "email": "someone@other.test", "email_verified": true}), "domain")
	ssoFailure(t, harness.signIn("acme", map[string]any{"sub": "unverified", "email": "unverified@example.test", "email_verified": false}), "unverified_email")
	started := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/sso/start", map[string]string{"organization_slug": "acme"}, nil, "", selfServiceOrigin)
	var document struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	decodeResponse(t, started, &document)
	binding := started.Result().Cookies()[0]
	code, state, err := provider.Authorize(document.AuthorizationURL, map[string]any{"sub": "owner-subject"})
	if err != nil {
		t.Fatal(err)
	}
	// Another browser can't finish it, and doesn't spend it either; the right browser can, once.
	ssoFailure(t, harness.callback(url.Values{"code": {code}, "state": {state}}, nil).Result(), "expired")
	sessionFromRedirect(t, harness.callback(url.Values{"code": {code}, "state": {state}}, binding).Result())
	ssoFailure(t, harness.callback(url.Values{"code": {code}, "state": {state}}, binding).Result(), "expired")
	started = performJSON(t, handler, http.MethodPost, "/admin/v1/auth/sso/start", map[string]string{"organization_slug": "acme"}, nil, "", selfServiceOrigin)
	decodeResponse(t, started, &document)
	_, state, err = provider.Authorize(document.AuthorizationURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ssoFailure(t, harness.callback(url.Values{"error": {"access_denied"}, "state": {state}}, started.Result().Cookies()[0]).Result(), "denied")

	// Requiring single sign-on refuses other methods for members, never owners.
	created := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "operator@example.test", "display_name": "Operator", "password": "initial operator password", "role": "operator",
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	if created.Code != http.StatusCreated {
		t.Fatalf("create operator status=%d body=%s", created.Code, created.Body.String())
	}
	operator, _ := selfServiceLogin(t, handler, "operator@example.test", "initial operator password", "")
	configuration["require_sso"] = true
	delete(configuration, "client_secret")
	if required := performJSON(t, handler, http.MethodPut, configPath, configuration, owner.cookie, owner.csrf, selfServiceOrigin); required.Code != http.StatusOK {
		t.Fatalf("require sso status=%d body=%s", required.Code, required.Body.String())
	}
	expectEndedSession(t, handler, operator, "session_revoked", "changed your organization's single sign-on")
	if kept := performGET(handler, "/admin/v1/auth/session", newcomer.cookie); kept.Code != http.StatusOK {
		t.Fatalf("an sso session ended when sso became required: %d", kept.Code)
	}
	if refused := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{"email": "operator@example.test", "password": "initial operator password"}, nil, "", selfServiceOrigin); refused.Code != http.StatusForbidden ||
		!bytes.Contains(refused.Body.Bytes(), []byte("requires single sign-on")) {
		t.Fatalf("member password sign-in under require_sso status=%d body=%s", refused.Code, refused.Body.String())
	}
	if _, body := selfServiceLogin(t, handler, "owner@example.test", "initial owner password", ""); !bytes.Contains(body, []byte(`"sign_in_method":"password"`)) {
		t.Fatalf("owner break-glass sign-in body=%s", body)
	}

	// A single sign-on session isn't held to the two-factor requirement and can't switch organization.
	if required := performJSON(t, handler, http.MethodPut, "/admin/v1/organizations/"+organization.OrganizationID+"/two-factor-requirement",
		map[string]bool{"required": true}, owner.cookie, owner.csrf, selfServiceOrigin); required.Code != http.StatusOK {
		t.Fatalf("require two-factor status=%d", required.Code)
	}
	if session := performGET(handler, "/admin/v1/auth/session", newcomer.cookie); !bytes.Contains(session.Body.Bytes(), []byte(`"two_factor_enrollment_required":false`)) {
		t.Fatalf("sso session under two-factor requirement body=%s", session.Body.String())
	}
	if restricted := performGET(handler, "/admin/v1/auth/session", owner.cookie); !bytes.Contains(restricted.Body.Bytes(), []byte(`"two_factor_enrollment_required":true`)) {
		t.Fatalf("password session under two-factor requirement body=%s", restricted.Body.String())
	}
	second := performJSON(t, handler, http.MethodPost, "/admin/v1/organizations", map[string]string{"slug": "second", "display_name": "Second"}, ownerSSO.cookie, ownerSSO.csrf, selfServiceOrigin)
	if second.Code != http.StatusCreated {
		t.Fatalf("second organization status=%d body=%s", second.Code, second.Body.String())
	}
	var secondOrganization struct {
		ID string `json:"id"`
	}
	decodeResponse(t, second, &secondOrganization)
	if switched := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/organization", map[string]string{"organization_id": secondOrganization.ID}, ownerSSO.cookie, ownerSSO.csrf, selfServiceOrigin); switched.Code != http.StatusConflict {
		t.Fatalf("sso session switch status=%d body=%s", switched.Code, switched.Body.String())
	}

	// Removing the provider ends single sign-on for the organization.
	if removed := performJSON(t, handler, http.MethodDelete, configPath, nil, ownerSSO.cookie, ownerSSO.csrf, selfServiceOrigin); removed.Code != http.StatusNoContent {
		t.Fatalf("remove status=%d body=%s", removed.Code, removed.Body.String())
	}
	expectEndedSession(t, handler, newcomer, "session_revoked", "changed your organization's single sign-on")
	if acting := performGET(handler, "/admin/v1/auth/session", ownerSSO.cookie); acting.Code != http.StatusOK {
		t.Fatalf("the owner's own session ended with the removal: %d", acting.Code)
	}
	if after := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/sso/start", map[string]string{"organization_slug": "acme"}, nil, "", selfServiceOrigin); after.Code != http.StatusNotFound {
		t.Fatalf("start after removal status=%d", after.Code)
	}
	if members := performGET(handler, "/admin/v1/administrators", ownerSSO.cookie); bytes.Contains(members.Body.Bytes(), []byte(`"sso_linked":true`)) {
		t.Fatalf("identities survived removal: %s", members.Body.String())
	}
}
