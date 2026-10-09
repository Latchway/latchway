package adminapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/mail"
)

type recordingMailer struct {
	mu       sync.Mutex
	messages []mail.Message
	fail     bool
}

func (mailer *recordingMailer) Send(_ context.Context, message mail.Message) error {
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	if mailer.fail {
		return errors.New("relay refused")
	}
	mailer.messages = append(mailer.messages, message)
	return nil
}

type invitationDocument struct {
	Invitation struct {
		ID          string `json:"id"`
		Status      string `json:"status"`
		EmailStatus string `json:"email_status"`
		InvitedBy   string `json:"invited_by"`
	} `json:"invitation"`
	URL string `json:"url"`
}

func invitationToken(t *testing.T, link string) string {
	t.Helper()
	prefix := selfServiceOrigin + "/invitation#"
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("invitation url=%q", link)
	}
	return strings.TrimPrefix(link, prefix)
}

func TestAdministratorInvitationsPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	manager := testAdminSecretManager(t, pool)
	mailer := &recordingMailer{}
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), manager,
		WithFactorSealer(testFactorSealer(t)), WithMailer(mailer))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("invitation-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := withUserAgent(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "acme", "organization_name": "Acme",
		"email": "owner@example.test", "display_name": "Olivia Owner", "password": "initial owner password",
	}, nil, "", selfServiceOrigin)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var organization struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &organization)
	owner := selfServiceSession{cookie: bootstrap.Result().Cookies()[0], csrf: bootstrap.Header().Get(csrfHeader)}
	invitations := "/admin/v1/organizations/" + organization.OrganizationID + "/invitations"

	// An owner invites by email; the link carries the token only in its fragment.
	created := performJSON(t, handler, http.MethodPost, invitations, map[string]any{"email": "Newcomer@Example.test", "role": "operator", "send_email": true}, owner.cookie, owner.csrf, selfServiceOrigin)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var first invitationDocument
	decodeResponse(t, created, &first)
	firstToken := invitationToken(t, first.URL)
	if first.Invitation.Status != "pending" || first.Invitation.EmailStatus != "sent" || first.Invitation.InvitedBy != "Olivia Owner" {
		t.Fatalf("invitation=%+v", first.Invitation)
	}
	if len(mailer.messages) != 1 || mailer.messages[0].To != "Newcomer@Example.test" || !strings.Contains(mailer.messages[0].Body, first.URL) ||
		mailer.messages[0].Subject != "You're invited to Acme on Latchway" {
		t.Fatalf("messages=%+v", mailer.messages)
	}
	listed := performGET(handler, invitations, owner.cookie)
	if !bytes.Contains(listed.Body.Bytes(), []byte(`"email_delivery":true`)) || bytes.Contains(listed.Body.Bytes(), []byte(firstToken)) {
		t.Fatalf("list body=%s", listed.Body.String())
	}
	if member := performJSON(t, handler, http.MethodPost, invitations, map[string]any{"email": "owner@example.test", "role": "viewer"}, owner.cookie, owner.csrf, selfServiceOrigin); member.Code != http.StatusConflict {
		t.Fatalf("inviting a member status=%d", member.Code)
	}

	// A renewed link replaces the first; a new invitation for the same address replaces both.
	renewed := performJSON(t, handler, http.MethodPost, invitations+"/"+first.Invitation.ID+"/renew", map[string]any{"send_email": false}, owner.cookie, owner.csrf, selfServiceOrigin)
	var second invitationDocument
	decodeResponse(t, renewed, &second)
	secondToken := invitationToken(t, second.URL)
	if renewed.Code != http.StatusOK || secondToken == firstToken || second.Invitation.EmailStatus != "not_requested" {
		t.Fatalf("renew status=%d body=%s", renewed.Code, renewed.Body.String())
	}
	if stale := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/preview", map[string]string{"token": firstToken}, nil, "", selfServiceOrigin); stale.Code != http.StatusNotFound {
		t.Fatalf("replaced link status=%d", stale.Code)
	}
	preview := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/preview", map[string]string{"token": secondToken}, nil, "", selfServiceOrigin)
	if preview.Code != http.StatusOK || !bytes.Contains(preview.Body.Bytes(), []byte(`"organization_name":"Acme"`)) || !bytes.Contains(preview.Body.Bytes(), []byte(`"account_exists":false`)) {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}

	// Accepting creates the account with the chosen password and signs it in, once.
	if short := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/accept", map[string]string{"token": secondToken, "display_name": "New Comer", "password": "short"}, nil, "", selfServiceOrigin); short.Code != http.StatusBadRequest {
		t.Fatalf("short password status=%d", short.Code)
	}
	accepted := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/accept", map[string]string{"token": secondToken, "display_name": "New Comer", "password": "newcomer chosen password"}, nil, "", selfServiceOrigin)
	if accepted.Code != http.StatusOK || !bytes.Contains(accepted.Body.Bytes(), []byte(`"role":"operator"`)) || !bytes.Contains(accepted.Body.Bytes(), []byte(`"password_reset_required":false`)) {
		t.Fatalf("accept status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	if again := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/accept", map[string]string{"token": secondToken, "display_name": "Someone Else", "password": "another chosen password"}, nil, "", selfServiceOrigin); again.Code != http.StatusNotFound {
		t.Fatalf("reused invitation status=%d", again.Code)
	}
	if _, body := selfServiceLogin(t, handler, "newcomer@example.test", "newcomer chosen password", ""); !bytes.Contains(body, []byte(`"organization_id":"`+organization.OrganizationID+`"`)) {
		t.Fatalf("newcomer sign-in body=%s", body)
	}

	// An existing account claims an invitation to another organization after signing in, as itself only.
	second2 := performJSON(t, handler, http.MethodPost, "/admin/v1/organizations", map[string]string{"slug": "beta", "display_name": "Beta"}, owner.cookie, owner.csrf, selfServiceOrigin)
	var beta struct {
		ID string `json:"id"`
	}
	decodeResponse(t, second2, &beta)
	betaOwner := selfServiceSession{}
	switched := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/organization", map[string]string{"organization_id": beta.ID}, owner.cookie, owner.csrf, selfServiceOrigin)
	if switched.Code != http.StatusOK {
		t.Fatalf("switch to beta status=%d body=%s", switched.Code, switched.Body.String())
	}
	betaOwner.cookie, betaOwner.csrf = switched.Result().Cookies()[0], switched.Header().Get(csrfHeader)
	invited := performJSON(t, handler, http.MethodPost, "/admin/v1/organizations/"+beta.ID+"/invitations", map[string]any{"email": "newcomer@example.test", "role": "viewer"}, betaOwner.cookie, betaOwner.csrf, selfServiceOrigin)
	var claim invitationDocument
	decodeResponse(t, invited, &claim)
	claimToken := invitationToken(t, claim.URL)
	if claim.Invitation.EmailStatus != "not_requested" {
		t.Fatalf("unrequested email status=%q", claim.Invitation.EmailStatus)
	}
	if existing := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/accept", map[string]string{"token": claimToken, "display_name": "Imposter", "password": "imposter chosen password"}, nil, "", selfServiceOrigin); existing.Code != http.StatusConflict {
		t.Fatalf("accept for an existing account status=%d body=%s", existing.Code, existing.Body.String())
	}
	if wrong := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/claim", map[string]string{"token": claimToken}, betaOwner.cookie, betaOwner.csrf, selfServiceOrigin); wrong.Code != http.StatusForbidden {
		t.Fatalf("claim by another account status=%d", wrong.Code)
	}
	newcomer, _ := selfServiceLogin(t, handler, "newcomer@example.test", "newcomer chosen password", "")
	claimed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/claim", map[string]string{"token": claimToken}, newcomer.cookie, newcomer.csrf, selfServiceOrigin)
	if claimed.Code != http.StatusOK || !bytes.Contains(claimed.Body.Bytes(), []byte(beta.ID)) {
		t.Fatalf("claim status=%d body=%s", claimed.Code, claimed.Body.String())
	}
	if session := performGET(handler, "/admin/v1/auth/session", newcomer.cookie); !bytes.Contains(session.Body.Bytes(), []byte(beta.ID)) {
		t.Fatalf("newcomer memberships body=%s", session.Body.String())
	}

	// Revoked invitations stop working; a failed email is recorded rather than hiding the link.
	owner, _ = selfServiceLogin(t, handler, "owner@example.test", "initial owner password", organization.OrganizationID)
	revocable := performJSON(t, handler, http.MethodPost, invitations, map[string]any{"email": "later@example.test", "role": "viewer"}, owner.cookie, owner.csrf, selfServiceOrigin)
	var third invitationDocument
	decodeResponse(t, revocable, &third)
	if revoked := performJSON(t, handler, http.MethodPost, invitations+"/"+third.Invitation.ID+"/revoke", nil, owner.cookie, owner.csrf, selfServiceOrigin); revoked.Code != http.StatusOK || !bytes.Contains(revoked.Body.Bytes(), []byte(`"status":"revoked"`)) {
		t.Fatalf("revoke status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	if gone := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/preview", map[string]string{"token": invitationToken(t, third.URL)}, nil, "", selfServiceOrigin); gone.Code != http.StatusNotFound {
		t.Fatalf("revoked link status=%d", gone.Code)
	}
	if again := performJSON(t, handler, http.MethodPost, invitations+"/"+third.Invitation.ID+"/revoke", nil, owner.cookie, owner.csrf, selfServiceOrigin); again.Code != http.StatusNotFound {
		t.Fatalf("second revoke status=%d", again.Code)
	}
	mailer.fail = true
	failed := performJSON(t, handler, http.MethodPost, invitations, map[string]any{"email": "bounce@example.test", "role": "viewer", "send_email": true}, owner.cookie, owner.csrf, selfServiceOrigin)
	var fourth invitationDocument
	decodeResponse(t, failed, &fourth)
	if failed.Code != http.StatusCreated || fourth.Invitation.EmailStatus != "failed" || fourth.URL == "" {
		t.Fatalf("failed email status=%d body=%s", failed.Code, failed.Body.String())
	}
	if junk := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/invitations/preview", map[string]string{"token": "lwinv_" + strings.Repeat("A", 43)}, nil, "", selfServiceOrigin); junk.Code != http.StatusNotFound {
		t.Fatalf("unknown token status=%d", junk.Code)
	}
}
