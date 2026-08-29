package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

func TestAdministratorLifecyclePostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(
		pool, "https://console.example.test", 12*time.Hour,
		slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool),
	)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("administrator-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)

	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "administrator-test",
		"organization_name": "Administrator Test", "email": "owner@example.test",
		"display_name": "Owner", "password": "initial owner password",
	}, nil, "", "https://console.example.test")
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	ownerCookie := bootstrap.Result().Cookies()[0]
	ownerCSRF := bootstrap.Header().Get(csrfHeader)
	var bootstrapSession struct {
		Administrator struct {
			ID string `json:"id"`
		} `json:"administrator"`
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &bootstrapSession)

	created := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "operator@example.test", "display_name": "Operator",
		"password": "initial operator password", "role": "viewer",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if created.Code != http.StatusCreated || bytes.Contains(created.Body.Bytes(), []byte("initial operator password")) {
		t.Fatalf("create administrator status=%d body=%s", created.Code, created.Body.String())
	}
	var operator adminauth.Administrator
	decodeResponse(t, created, &operator)
	if operator.ID == "" || operator.Role != adminauth.RoleViewer || operator.Status != "active" {
		t.Fatalf("created administrator=%+v", operator)
	}

	duplicate := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "OPERATOR@example.test", "display_name": "Duplicate",
		"password": "different secure password", "role": "viewer",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate administrator status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	listed := performGET(handler, "/admin/v1/administrators?page_size=1", ownerCookie)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(`"has_more":true`)) {
		t.Fatalf("administrator page status=%d body=%s", listed.Code, listed.Body.String())
	}

	operatorLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": "operator@example.test", "password": "initial operator password",
		"organization_id": bootstrapSession.OrganizationID,
	}, nil, "", "https://console.example.test")
	if operatorLogin.Code != http.StatusOK {
		t.Fatalf("operator login status=%d body=%s", operatorLogin.Code, operatorLogin.Body.String())
	}
	operatorCookie := operatorLogin.Result().Cookies()[0]
	operatorCSRF := operatorLogin.Header().Get(csrfHeader)
	operatorTokenResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/api-tokens", map[string]any{
		"name": "operator-token", "scopes": []string{"inspect_users"},
	}, operatorCookie, operatorCSRF, "https://console.example.test")
	if operatorTokenResponse.Code != http.StatusCreated {
		t.Fatalf("operator token status=%d body=%s", operatorTokenResponse.Code, operatorTokenResponse.Body.String())
	}
	var operatorToken struct {
		Token string `json:"token"`
	}
	decodeResponse(t, operatorTokenResponse, &operatorToken)
	if response := performGET(handler, "/admin/v1/administrators", operatorCookie); response.Code != http.StatusForbidden {
		t.Fatalf("viewer administrator list status=%d, want 403", response.Code)
	}
	if response := performBearerGET(handler, "/admin/v1/administrators", operatorToken.Token); response.Code != http.StatusForbidden {
		t.Fatalf("unscoped administrator list status=%d, want 403", response.Code)
	}

	secondaryOrganizationResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/organizations", map[string]string{
		"slug": "administrator-secondary", "display_name": "Administrator Secondary",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if secondaryOrganizationResponse.Code != http.StatusCreated {
		t.Fatalf("secondary organization status=%d body=%s", secondaryOrganizationResponse.Code, secondaryOrganizationResponse.Body.String())
	}
	var secondaryOrganization struct {
		ID string `json:"id"`
	}
	decodeResponse(t, secondaryOrganizationResponse, &secondaryOrganization)
	secondaryOwnerLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": "owner@example.test", "password": "initial owner password",
		"organization_id": secondaryOrganization.ID,
	}, nil, "", "https://console.example.test")
	if secondaryOwnerLogin.Code != http.StatusOK {
		t.Fatalf("secondary owner login status=%d body=%s", secondaryOwnerLogin.Code, secondaryOwnerLogin.Body.String())
	}
	secondaryOwnerCookie := secondaryOwnerLogin.Result().Cookies()[0]
	secondaryOwnerCSRF := secondaryOwnerLogin.Header().Get(csrfHeader)
	secondaryAdministratorResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "secondary@example.test", "display_name": "Secondary",
		"password": "initial secondary password", "role": "viewer",
	}, secondaryOwnerCookie, secondaryOwnerCSRF, "https://console.example.test")
	if secondaryAdministratorResponse.Code != http.StatusCreated {
		t.Fatalf("secondary administrator status=%d body=%s", secondaryAdministratorResponse.Code, secondaryAdministratorResponse.Body.String())
	}
	var secondaryAdministrator adminauth.Administrator
	decodeResponse(t, secondaryAdministratorResponse, &secondaryAdministrator)
	crossTenantRole := performJSON(t, handler, http.MethodPut, "/admin/v1/administrators/"+secondaryAdministrator.ID+"/role", map[string]string{
		"role": "operator",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if crossTenantRole.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant role status=%d body=%s", crossTenantRole.Code, crossTenantRole.Body.String())
	}
	crossTenantPassword := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators/"+bootstrapSession.Administrator.ID+"/reset-password", map[string]string{
		"password": "replacement owner password",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if crossTenantPassword.Code != http.StatusConflict {
		t.Fatalf("cross-tenant password reset status=%d body=%s", crossTenantPassword.Code, crossTenantPassword.Body.String())
	}
	if response := performGET(handler, "/admin/v1/administrators", ownerCookie); response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte("secondary@example.test")) {
		t.Fatalf("tenant-isolated list status=%d body=%s", response.Code, response.Body.String())
	}

	reset := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators/"+operator.ID+"/reset-password", map[string]string{
		"password": "replacement operator password",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if reset.Code != http.StatusOK || bytes.Contains(reset.Body.Bytes(), []byte("replacement operator password")) {
		t.Fatalf("reset password status=%d body=%s", reset.Code, reset.Body.String())
	}
	if response := performGET(handler, "/admin/v1/auth/session", operatorCookie); response.Code != http.StatusUnauthorized {
		t.Fatalf("reset session status=%d, want 401", response.Code)
	}
	if response := performBearerGET(handler, "/admin/v1/auth/session", operatorToken.Token); response.Code != http.StatusUnauthorized {
		t.Fatalf("reset API token status=%d, want 401", response.Code)
	}
	oldLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": "operator@example.test", "password": "initial operator password",
		"organization_id": bootstrapSession.OrganizationID,
	}, nil, "", "https://console.example.test")
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password login status=%d body=%s", oldLogin.Code, oldLogin.Body.String())
	}
	newLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": "operator@example.test", "password": "replacement operator password",
		"organization_id": bootstrapSession.OrganizationID,
	}, nil, "", "https://console.example.test")
	if newLogin.Code != http.StatusOK {
		t.Fatalf("replacement password login status=%d body=%s", newLogin.Code, newLogin.Body.String())
	}
	newOperatorCookie := newLogin.Result().Cookies()[0]
	disabled := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators/"+operator.ID+"/disable", nil,
		ownerCookie, ownerCSRF, "https://console.example.test")
	if disabled.Code != http.StatusOK || !bytes.Contains(disabled.Body.Bytes(), []byte(`"status":"disabled"`)) {
		t.Fatalf("disable administrator status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	if response := performGET(handler, "/admin/v1/auth/session", newOperatorCookie); response.Code != http.StatusUnauthorized {
		t.Fatalf("disabled session status=%d, want 401", response.Code)
	}
	enabled := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators/"+operator.ID+"/enable", nil,
		ownerCookie, ownerCSRF, "https://console.example.test")
	if enabled.Code != http.StatusOK || !bytes.Contains(enabled.Body.Bytes(), []byte(`"status":"active"`)) {
		t.Fatalf("enable administrator status=%d body=%s", enabled.Code, enabled.Body.String())
	}
	reenabledLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": "operator@example.test", "password": "replacement operator password",
		"organization_id": bootstrapSession.OrganizationID,
	}, nil, "", "https://console.example.test")
	if reenabledLogin.Code != http.StatusOK {
		t.Fatalf("re-enabled login status=%d body=%s", reenabledLogin.Code, reenabledLogin.Body.String())
	}

	role := performJSON(t, handler, http.MethodPut, "/admin/v1/administrators/"+operator.ID+"/role", map[string]string{
		"role": "owner",
	}, ownerCookie, ownerCSRF, "https://console.example.test")
	if role.Code != http.StatusOK || !bytes.Contains(role.Body.Bytes(), []byte(`"role":"owner"`)) {
		t.Fatalf("role change status=%d body=%s", role.Code, role.Body.String())
	}

	ownerPrincipal := adminauth.Principal{
		OrganizationID: bootstrapSession.OrganizationID, AdminUserID: bootstrapSession.Administrator.ID,
		Role: adminauth.RoleOwner,
	}
	operatorPrincipal := adminauth.Principal{
		OrganizationID: bootstrapSession.OrganizationID, AdminUserID: operator.ID,
		Role: adminauth.RoleOwner,
	}
	type outcome struct {
		target string
		err    error
	}
	requestIDs := []string{mustAdminRequestID(t), mustAdminRequestID(t)}
	outcomes := make(chan outcome, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, attempt := range []struct {
		principal adminauth.Principal
		target    string
	}{{ownerPrincipal, operator.ID}, {operatorPrincipal, bootstrapSession.Administrator.ID}} {
		wait.Add(1)
		go func(attempt struct {
			principal adminauth.Principal
			target    string
		}, requestID string) {
			defer wait.Done()
			<-start
			_, mutationErr := api.auth.SetAdministratorEnabled(
				ctx, attempt.principal, attempt.target, false, requestID,
			)
			outcomes <- outcome{target: attempt.target, err: mutationErr}
		}(attempt, requestIDs[index])
	}
	close(start)
	wait.Wait()
	close(outcomes)
	succeeded := 0
	rejected := 0
	for result := range outcomes {
		switch {
		case result.err == nil:
			succeeded++
		case errors.Is(result.err, adminauth.ErrLastActiveOwner), errors.Is(result.err, adminauth.ErrAdminAuthentication):
			rejected++
		default:
			t.Fatalf("concurrent owner disable target=%s error=%v", result.target, result.err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent owner disable outcomes succeeded=%d rejected=%d", succeeded, rejected)
	}
	var activeOwners int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM admin_memberships AS m
		JOIN admin_users AS u ON u.admin_user_id = m.admin_user_id
		WHERE m.organization_id = $1 AND m.role = 'owner'
		  AND m.status = 'active' AND u.status = 'active'
	`, bootstrapSession.OrganizationID).Scan(&activeOwners); err != nil {
		t.Fatal(err)
	}
	if activeOwners != 1 {
		t.Fatalf("active owners=%d, want 1", activeOwners)
	}

	var passwordAuditClassification string
	if err := pool.QueryRow(ctx, `
		SELECT change.classification
		FROM audit_events AS event
		JOIN audit_event_changes AS change USING (audit_event_id)
		WHERE event.action = 'admin.administrator_password_reset'
		  AND change.field_name = 'password_hash'
	`).Scan(&passwordAuditClassification); err != nil {
		t.Fatal(err)
	}
	if passwordAuditClassification != "sensitive" {
		t.Fatalf("password audit classification=%q", passwordAuditClassification)
	}
}

func mustAdminRequestID(t *testing.T) string {
	t.Helper()
	value, err := id.New(id.AdminRequest)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestAdministratorRequestsRejectUnknownFields(t *testing.T) {
	var request createAdministratorRequest
	encoded, _ := json.Marshal(map[string]any{
		"email": "owner@example.test", "display_name": "Owner", "password": "secure password",
		"role": "owner", "plaintext_password_copy": "must-not-be-accepted",
	})
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err == nil {
		t.Fatal("administrator request accepted an unknown credential field")
	}
}
