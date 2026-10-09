package adminapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestApplicationRolesRaiseOneApplicationPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	manager := testAdminSecretManager(t, pool)
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), manager, WithFactorSealer(testFactorSealer(t)))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("app-role-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := withUserAgent(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "acme", "organization_name": "Acme",
		"email": "owner@example.test", "display_name": "Owner", "password": "initial owner password",
	}, nil, "", selfServiceOrigin)
	var organization struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &organization)
	owner := selfServiceSession{cookie: bootstrap.Result().Cookies()[0], csrf: bootstrap.Header().Get(csrfHeader)}
	createApp := func(slug string) (string, string) {
		t.Helper()
		created := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", map[string]string{"organization_id": organization.OrganizationID, "slug": slug, "display_name": slug}, owner.cookie, owner.csrf, selfServiceOrigin)
		var application struct {
			ID string `json:"id"`
		}
		decodeResponse(t, created, &application)
		environment := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{"slug": "production", "display_name": "Production", "kind": "production"}, owner.cookie, owner.csrf, selfServiceOrigin)
		var created2 struct {
			ID string `json:"id"`
		}
		decodeResponse(t, environment, &created2)
		return application.ID, created2.ID
	}
	mobile, mobileProduction := createApp("mobile")
	web, webProduction := createApp("web")
	created := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "viewer@example.test", "display_name": "Viewer", "password": "initial viewer password", "role": "viewer",
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	var viewerRecord struct {
		ID string `json:"id"`
	}
	decodeResponse(t, created, &viewerRecord)
	viewer, _ := selfServiceLogin(t, handler, "viewer@example.test", "initial viewer password", "")
	if changed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/password", map[string]string{"current_password": "initial viewer password", "new_password": "viewer picked password"}, viewer.cookie, viewer.csrf, selfServiceOrigin); changed.Code != http.StatusOK {
		t.Fatalf("viewer password change status=%d", changed.Code)
	}
	newEnvironment := func(session selfServiceSession, applicationID, slug string) int {
		return performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+applicationID+"/environments", map[string]string{"slug": slug, "display_name": slug, "kind": "staging"}, session.cookie, session.csrf, selfServiceOrigin).Code
	}
	if code := newEnvironment(viewer, mobile, "staging"); code != http.StatusForbidden {
		t.Fatalf("viewer environment create status=%d", code)
	}

	// An owner raises the viewer to Admin in one application only.
	grantPath := "/admin/v1/administrators/" + viewerRecord.ID + "/application-roles/" + mobile
	if bad := performJSON(t, handler, http.MethodPut, grantPath, map[string]string{"role": "owner"}, owner.cookie, owner.csrf, selfServiceOrigin); bad.Code != http.StatusBadRequest {
		t.Fatalf("owner application role status=%d", bad.Code)
	}
	if self := performJSON(t, handler, http.MethodPut, "/admin/v1/administrators/"+viewerRecord.ID+"/application-roles/"+mobile, map[string]string{"role": "admin"}, viewer.cookie, viewer.csrf, selfServiceOrigin); self.Code != http.StatusForbidden {
		t.Fatalf("viewer granting itself status=%d", self.Code)
	}
	granted := performJSON(t, handler, http.MethodPut, grantPath, map[string]string{"role": "admin"}, owner.cookie, owner.csrf, selfServiceOrigin)
	if granted.Code != http.StatusOK || !bytes.Contains(granted.Body.Bytes(), []byte(`"role":"admin"`)) {
		t.Fatalf("grant status=%d body=%s", granted.Code, granted.Body.String())
	}
	if session := performGET(handler, "/admin/v1/auth/session", viewer.cookie); !bytes.Contains(session.Body.Bytes(), []byte(`"application_roles":[{"application_id":"`+mobile+`","role":"admin"}]`)) {
		t.Fatalf("viewer session body=%s", session.Body.String())
	}
	if code := newEnvironment(viewer, mobile, "staging"); code != http.StatusCreated {
		t.Fatalf("raised environment create status=%d", code)
	}
	if code := newEnvironment(viewer, web, "staging"); code != http.StatusForbidden {
		t.Fatalf("environment create in another application status=%d", code)
	}
	if code := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", map[string]string{"organization_id": organization.OrganizationID, "slug": "third", "display_name": "Third"}, viewer.cookie, viewer.csrf, selfServiceOrigin).Code; code != http.StatusForbidden {
		t.Fatalf("organization-wide application create status=%d", code)
	}
	draft := func(environmentID string) int {
		return performConfigurationJSON(t, handler, http.MethodPost, "/admin/v1/environments/"+environmentID+"/config-revisions",
			map[string]any{"document": configurationObjectForAPI(t, "draft"), "description": "draft"}, viewer.cookie, viewer.csrf, "").Code
	}
	if code := draft(mobileProduction); code != http.StatusCreated {
		t.Fatalf("raised configuration draft status=%d", code)
	}
	if code := draft(webProduction); code != http.StatusForbidden {
		t.Fatalf("configuration draft in another application status=%d", code)
	}

	// A token the viewer creates may carry the raised capability, and is held to the same application.
	tokenResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{"name": "mobile-ci", "scopes": []string{"activate_configuration"}}, viewer.cookie, viewer.csrf, selfServiceOrigin)
	if tokenResponse.Code != http.StatusCreated {
		t.Fatalf("raised token status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var issued struct {
		Token string `json:"token"`
	}
	decodeResponse(t, tokenResponse, &issued)
	byToken := func(applicationID string) int {
		request := performBearerJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+applicationID+"/environments", map[string]string{"slug": "token-env", "display_name": "Token", "kind": "development"}, issued.Token)
		return request.Code
	}
	if code := byToken(mobile); code != http.StatusCreated {
		t.Fatalf("token in raised application status=%d", code)
	}
	if code := byToken(web); code != http.StatusForbidden {
		t.Fatalf("token in another application status=%d", code)
	}

	// The grant is listed for owners; removing it, or promoting the member past it, ends the raise.
	if listed := performGET(handler, "/admin/v1/application-roles", owner.cookie); !bytes.Contains(listed.Body.Bytes(), []byte(`"granted_by":"Owner"`)) {
		t.Fatalf("grants body=%s", listed.Body.String())
	}
	if removed := performJSON(t, handler, http.MethodDelete, grantPath, nil, owner.cookie, owner.csrf, selfServiceOrigin); removed.Code != http.StatusNoContent {
		t.Fatalf("remove status=%d", removed.Code)
	}
	if code := newEnvironment(viewer, mobile, "qa"); code != http.StatusForbidden {
		t.Fatalf("environment create after removal status=%d", code)
	}
	performJSON(t, handler, http.MethodPut, grantPath, map[string]string{"role": "operator"}, owner.cookie, owner.csrf, selfServiceOrigin)
	if promoted := performJSON(t, handler, http.MethodPut, "/admin/v1/administrators/"+viewerRecord.ID+"/role", map[string]string{"role": "admin"}, owner.cookie, owner.csrf, selfServiceOrigin); promoted.Code != http.StatusOK {
		t.Fatalf("promote status=%d body=%s", promoted.Code, promoted.Body.String())
	}
	if listed := performGET(handler, "/admin/v1/application-roles", owner.cookie); bytes.Contains(listed.Body.Bytes(), []byte(viewerRecord.ID)) {
		t.Fatalf("superseded grant kept: %s", listed.Body.String())
	}
	if notRaised := performJSON(t, handler, http.MethodPut, grantPath, map[string]string{"role": "operator"}, owner.cookie, owner.csrf, selfServiceOrigin); notRaised.Code != http.StatusConflict {
		t.Fatalf("grant below organization role status=%d", notRaised.Code)
	}
}
