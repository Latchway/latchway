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

const (
	selfServiceOrigin    = "https://console.example.test"
	selfServiceUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

// withUserAgent gives every test request a browser User-Agent unless it set one.
func withUserAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			r.Header.Set("User-Agent", selfServiceUserAgent)
		}
		next.ServeHTTP(w, r)
	})
}

type selfServiceSession struct {
	cookie *http.Cookie
	csrf   string
}

func selfServiceLogin(t *testing.T, handler http.Handler, email, password, organizationID string) (selfServiceSession, []byte) {
	t.Helper()
	body := map[string]string{"email": email, "password": password}
	if organizationID != "" {
		body["organization_id"] = organizationID
	}
	response := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", body, nil, "", selfServiceOrigin)
	if response.Code != http.StatusOK {
		t.Fatalf("login %s status=%d body=%s", email, response.Code, response.Body.String())
	}
	return selfServiceSession{cookie: response.Result().Cookies()[0], csrf: response.Header().Get(csrfHeader)}, response.Body.Bytes()
}

func expectEndedSession(t *testing.T, handler http.Handler, session selfServiceSession, code, detail string) {
	t.Helper()
	response := performGET(handler, "/admin/v1/auth/session", session.cookie)
	if response.Code != http.StatusUnauthorized ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"code":"`+code+`"`)) ||
		!bytes.Contains(response.Body.Bytes(), []byte(detail)) {
		t.Fatalf("ended session status=%d body=%s, want %s %q", response.Code, response.Body.String(), code, detail)
	}
}

func TestAdministratorSelfServicePostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := withUserAgent(router)

	if info := performGET(handler, "/admin/v1/auth/info", nil); info.Code != http.StatusOK ||
		!bytes.Contains(info.Body.Bytes(), []byte(`"setup_open":false`)) ||
		!bytes.Contains(info.Body.Bytes(), []byte(`"contract_version":"1.1.0"`)) {
		t.Fatalf("info without a bootstrap token status=%d body=%s", info.Code, info.Body.String())
	}
	bootstrapToken := strings.Repeat("self-service-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	if info := performGET(handler, "/admin/v1/auth/info", nil); !bytes.Contains(info.Body.Bytes(), []byte(`"setup_open":true`)) {
		t.Fatalf("info with an open bootstrap body=%s", info.Body.String())
	}
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "self-service",
		"organization_name": "Self Service", "email": "owner@example.test",
		"display_name": "Owner", "password": "initial owner password",
	}, nil, "", selfServiceOrigin)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	if info := performGET(handler, "/admin/v1/auth/info", nil); !bytes.Contains(info.Body.Bytes(), []byte(`"setup_open":false`)) {
		t.Fatalf("info after bootstrap body=%s", info.Body.String())
	}
	var first struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &first)
	owner := selfServiceSession{cookie: bootstrap.Result().Cookies()[0], csrf: bootstrap.Header().Get(csrfHeader)}

	secondResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/organizations", map[string]string{
		"slug": "self-service-two", "display_name": "Self Service Two",
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("second organization status=%d body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	var second struct {
		ID string `json:"id"`
	}
	decodeResponse(t, secondResponse, &second)

	// Switching organization replaces the session without a password and the old cookie explains why it ended.
	switched := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/organization", map[string]string{
		"organization_id": second.ID,
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	if switched.Code != http.StatusOK || !bytes.Contains(switched.Body.Bytes(), []byte(`"organization_id":"`+second.ID+`"`)) {
		t.Fatalf("switch status=%d body=%s", switched.Code, switched.Body.String())
	}
	expectEndedSession(t, handler, owner, "session_revoked", "switched organization")
	owner = selfServiceSession{cookie: switched.Result().Cookies()[0], csrf: switched.Header().Get(csrfHeader)}
	if same := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/organization", map[string]string{
		"organization_id": second.ID,
	}, owner.cookie, owner.csrf, selfServiceOrigin); same.Code != http.StatusBadRequest {
		t.Fatalf("switch to the same organization status=%d body=%s", same.Code, same.Body.String())
	}

	// A sign-in that names no organization returns to the last one used.
	other, body := selfServiceLogin(t, handler, "owner@example.test", "initial owner password", "")
	if !bytes.Contains(body, []byte(`"organization_id":"`+second.ID+`"`)) {
		t.Fatalf("default sign-in organization body=%s, want last organization %s", body, second.ID)
	}

	// Your own sessions carry a coarse device summary and can be signed out from another session.
	listed := performGET(handler, "/admin/v1/auth/sessions", owner.cookie)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(`"device_summary":"Chrome on macOS"`)) ||
		!bytes.Contains(listed.Body.Bytes(), []byte(`"end_reason":"organization_switch"`)) ||
		bytes.Contains(listed.Body.Bytes(), []byte("Mozilla")) {
		t.Fatalf("own sessions status=%d body=%s", listed.Code, listed.Body.String())
	}
	ownerSessions := performGET(handler, "/admin/v1/admin-sessions", owner.cookie)
	if ownerSessions.Code != http.StatusOK || !bytes.Contains(ownerSessions.Body.Bytes(), []byte(`"device_summary":"Chrome on macOS"`)) {
		t.Fatalf("owner session list status=%d body=%s", ownerSessions.Code, ownerSessions.Body.String())
	}
	revoked := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/sessions/revoke-others", nil, owner.cookie, owner.csrf, selfServiceOrigin)
	if revoked.Code != http.StatusOK || !bytes.Contains(revoked.Body.Bytes(), []byte(`"signed_out_sessions":1`)) {
		t.Fatalf("revoke others status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	expectEndedSession(t, handler, other, "session_revoked", "another session of your account")
	if current := performGET(handler, "/admin/v1/auth/session", owner.cookie); current.Code != http.StatusOK {
		t.Fatalf("current session after revoke-others status=%d", current.Code)
	}

	// Changing your password checks the current one, refuses reuse and signs out your other sessions.
	other, _ = selfServiceLogin(t, handler, "owner@example.test", "initial owner password", first.OrganizationID)
	if wrong := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/password", map[string]string{
		"current_password": "not the password", "new_password": "a brand new owner password",
	}, owner.cookie, owner.csrf, selfServiceOrigin); wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong current password status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	if reused := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/password", map[string]string{
		"current_password": "initial owner password", "new_password": "initial owner password",
	}, owner.cookie, owner.csrf, selfServiceOrigin); reused.Code != http.StatusBadRequest {
		t.Fatalf("reused password status=%d body=%s", reused.Code, reused.Body.String())
	}
	changed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/password", map[string]string{
		"current_password": "initial owner password", "new_password": "a brand new owner password",
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	if changed.Code != http.StatusOK || bytes.Contains(changed.Body.Bytes(), []byte("brand new")) {
		t.Fatalf("password change status=%d body=%s", changed.Code, changed.Body.String())
	}
	expectEndedSession(t, handler, other, "session_revoked", "Your password was changed")
	if current := performGET(handler, "/admin/v1/auth/session", owner.cookie); current.Code != http.StatusOK {
		t.Fatalf("changing session status=%d, want it kept", current.Code)
	}
	selfServiceLogin(t, handler, "owner@example.test", "a brand new owner password", "")

	// Owners can list every administrator's API tokens with their last use; others cannot.
	operator := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "operator@example.test", "display_name": "Operator",
		"password": "initial operator password", "role": "operator",
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	if operator.Code != http.StatusCreated || !bytes.Contains(operator.Body.Bytes(), []byte(`"password_reset_required":true`)) {
		t.Fatalf("create operator status=%d body=%s", operator.Code, operator.Body.String())
	}
	operatorSession, operatorBody := selfServiceLogin(t, handler, "operator@example.test", "initial operator password", second.ID)
	if !bytes.Contains(operatorBody, []byte(`"password_reset_required":true`)) {
		t.Fatalf("operator session must require a password change: %s", operatorBody)
	}
	if blocked := performGET(handler, "/admin/v1/applications?organization_id="+second.ID, operatorSession.cookie); blocked.Code != http.StatusForbidden ||
		!bytes.Contains(blocked.Body.Bytes(), []byte("Choose a new password")) {
		t.Fatalf("restricted read status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	if allowed := performGET(handler, "/admin/v1/auth/session", operatorSession.cookie); allowed.Code != http.StatusOK {
		t.Fatalf("restricted session read status=%d", allowed.Code)
	}
	if changed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/password", map[string]string{
		"current_password": "initial operator password", "new_password": "operator picked password",
	}, operatorSession.cookie, operatorSession.csrf, selfServiceOrigin); changed.Code != http.StatusOK {
		t.Fatalf("operator password change status=%d body=%s", changed.Code, changed.Body.String())
	}
	if session := performGET(handler, "/admin/v1/auth/session", operatorSession.cookie); !bytes.Contains(session.Body.Bytes(), []byte(`"password_reset_required":false`)) {
		t.Fatalf("session after change body=%s", session.Body.String())
	}
	tokenResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{
		"name": "operator-automation", "scopes": []string{"inspect_users"},
	}, operatorSession.cookie, operatorSession.csrf, selfServiceOrigin)
	if tokenResponse.Code != http.StatusCreated {
		t.Fatalf("operator token status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var token struct {
		Token string `json:"token"`
	}
	decodeResponse(t, tokenResponse, &token)
	if used := performBearerGET(handler, "/admin/v1/auth/session", token.Token); used.Code != http.StatusOK {
		t.Fatalf("token use status=%d", used.Code)
	}
	everyone := performGET(handler, "/admin/v1/api-tokens?scope=organization", owner.cookie)
	if everyone.Code != http.StatusOK || !bytes.Contains(everyone.Body.Bytes(), []byte(`"email":"operator@example.test"`)) ||
		!bytes.Contains(everyone.Body.Bytes(), []byte(`"last_used_at"`)) {
		t.Fatalf("organization tokens status=%d body=%s", everyone.Code, everyone.Body.String())
	}
	if denied := performGET(handler, "/admin/v1/api-tokens?scope=organization", operatorSession.cookie); denied.Code != http.StatusForbidden {
		t.Fatalf("operator organization token list status=%d", denied.Code)
	}
	if invalid := performGET(handler, "/admin/v1/api-tokens?scope=everything", owner.cookie); invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid token scope status=%d", invalid.Code)
	}

	// Signing out explains itself to the old cookie; an unknown cookie stays generic.
	if logout := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/logout", nil, operatorSession.cookie, operatorSession.csrf, selfServiceOrigin); logout.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d", logout.Code)
	}
	expectEndedSession(t, handler, operatorSession, "session_revoked", "This session was signed out.")
	unknown := &http.Cookie{Name: adminCookieName, Value: "not-a-session"}
	if response := performGET(handler, "/admin/v1/auth/session", unknown); response.Code != http.StatusUnauthorized ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"code":"authentication_required"`)) {
		t.Fatalf("unknown cookie status=%d body=%s", response.Code, response.Body.String())
	}
}
