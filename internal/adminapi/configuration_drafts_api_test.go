package adminapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
)

func TestConfigurationDraftLifecycleAdminAPIPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(pool, "https://console.example.test", 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("draft-lifecycle-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "example",
		"organization_name": "Example", "email": "owner-drafts@example.test",
		"display_name": "Owner", "password": "correct horse battery staple",
	}, nil, "", "https://console.example.test")
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var session struct {
		OrganizationID string `json:"organization_id"`
		Administrator  struct {
			ID string `json:"id"`
		} `json:"administrator"`
	}
	decodeResponse(t, bootstrap, &session)
	cookie := bootstrap.Result().Cookies()[0]
	csrf := bootstrap.Header().Get(csrfHeader)
	request := func(method, path string, body any, etag string) *httptest.ResponseRecorder {
		t.Helper()
		return performConfigurationJSON(t, handler, method, path, body, cookie, csrf, etag)
	}
	created := request(http.MethodPost, "/admin/v1/applications", map[string]string{
		"organization_id": session.OrganizationID, "slug": "habits", "display_name": "Habits",
	}, "")
	var application struct {
		ID string `json:"id"`
	}
	decodeResponse(t, created, &application)
	environmentID := func(slug, kind string) string {
		t.Helper()
		response := request(http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{
			"slug": slug, "display_name": slug, "kind": kind,
		}, "")
		if response.Code != http.StatusCreated {
			t.Fatalf("environment %s status=%d body=%s", slug, response.Code, response.Body.String())
		}
		var environment struct {
			ID string `json:"id"`
		}
		decodeResponse(t, response, &environment)
		return environment.ID
	}
	production := environmentID("production", "production")
	staging := environmentID("staging", "staging")

	createDraft := func(body map[string]any) (configuration.Revision, string) {
		t.Helper()
		response := request(http.MethodPost, "/admin/v1/environments/"+production+"/config-revisions", body, "")
		if response.Code != http.StatusCreated {
			t.Fatalf("create draft status=%d body=%s", response.Code, response.Body.String())
		}
		var revision configuration.Revision
		decodeResponse(t, response, &revision)
		return revision, response.Header().Get("ETag")
	}
	validate := func(revisionID string) string {
		t.Helper()
		response := request(http.MethodPost, "/admin/v1/config-revisions/"+revisionID+"/validate", nil, "")
		if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"valid":true`)) {
			t.Fatalf("validate status=%d body=%s", response.Code, response.Body.String())
		}
		current := performGET(handler, "/admin/v1/config-revisions/"+revisionID, cookie)
		return current.Header().Get("ETag")
	}

	initial, _ := createDraft(map[string]any{"document": configurationObjectForAPI(t, "initial"), "description": "initial"})
	initialETag := validate(initial.ID)
	badNote := request(http.MethodPost, "/admin/v1/config-revisions/"+initial.ID+"/activate", map[string]string{"note": "bell\a"}, initialETag)
	unknownField := request(http.MethodPost, "/admin/v1/config-revisions/"+initial.ID+"/activate", map[string]string{"comment": "x"}, initialETag)
	if badNote.Code != http.StatusBadRequest || unknownField.Code != http.StatusBadRequest {
		t.Fatalf("invalid activation bodies status=%d/%d", badNote.Code, unknownField.Code)
	}
	activated := request(http.MethodPost, "/admin/v1/config-revisions/"+initial.ID+"/activate", map[string]string{"note": "First release."}, initialETag)
	if activated.Code != http.StatusOK || !bytes.Contains(activated.Body.Bytes(), []byte(`"activation_note":"First release."`)) {
		t.Fatalf("activate with note status=%d body=%s", activated.Code, activated.Body.String())
	}
	if count := auditActionCount(t, ctx, pool, "admin.configuration_activate"); count != 1 {
		t.Fatalf("activation audit events = %d", count)
	}

	// The console's second save: a validated draft is edited again.
	draft, draftETag := createDraft(map[string]any{"base_revision_id": initial.ID, "description": "Admin console draft"})
	if draft.BaseRevisionID != initial.ID || draft.Description != "Admin console draft" || draft.UpdatedBy != session.Administrator.ID {
		t.Fatalf("draft document base=%q description=%q updated_by=%q", draft.BaseRevisionID, draft.Description, draft.UpdatedBy)
	}
	draftETag = validate(draft.ID)
	secondSave := request(http.MethodPatch, "/admin/v1/config-revisions/"+draft.ID, configurationObjectForAPI(t, "second save"), draftETag)
	if secondSave.Code != http.StatusOK || !bytes.Contains(secondSave.Body.Bytes(), []byte(`"state":"draft"`)) {
		t.Fatalf("edit after validation status=%d body=%s", secondSave.Code, secondSave.Body.String())
	}
	edits := performGET(handler, "/admin/v1/config-revisions/"+draft.ID+"/edits", cookie)
	var history configuration.RevisionEdits
	decodeResponse(t, edits, &history)
	if edits.Code != http.StatusOK || len(history.Items) != 2 || history.Items[0].Kind != "edited" ||
		history.Items[0].EditedBy != session.Administrator.ID || history.Items[0].ChangeCount == 0 ||
		strings.Contains(edits.Body.String(), "second save") {
		t.Fatalf("edit history status=%d body=%s", edits.Code, edits.Body.String())
	}
	if unexpected := performGET(handler, "/admin/v1/config-revisions/"+draft.ID+"/edits?page_size=1", cookie); unexpected.Code != http.StatusBadRequest {
		t.Fatalf("edit history with a query status=%d", unexpected.Code)
	}
	if missingETag := request(http.MethodPost, "/admin/v1/config-revisions/"+draft.ID+"/discard", nil, ""); missingETag.Code != http.StatusPreconditionRequired {
		t.Fatalf("discard without If-Match status=%d body=%s", missingETag.Code, missingETag.Body.String())
	}
	discarded := request(http.MethodPost, "/admin/v1/config-revisions/"+draft.ID+"/discard", nil, secondSave.Header().Get("ETag"))
	if discarded.Code != http.StatusOK || !bytes.Contains(discarded.Body.Bytes(), []byte(`"state":"discarded"`)) ||
		!bytes.Contains(discarded.Body.Bytes(), []byte(`"discarded_by":"`+session.Administrator.ID+`"`)) {
		t.Fatalf("discard status=%d body=%s", discarded.Code, discarded.Body.String())
	}
	if again := request(http.MethodPost, "/admin/v1/config-revisions/"+draft.ID+"/discard", nil, discarded.Header().Get("ETag")); again.Code != http.StatusConflict {
		t.Fatalf("second discard status=%d body=%s", again.Code, again.Body.String())
	}
	if count := auditActionCount(t, ctx, pool, "admin.configuration_revision_discard"); count != 1 {
		t.Fatalf("discard audit events = %d", count)
	}

	// A stale draft is brought up to date by an explicit merge.
	stale, staleETag := createDraft(map[string]any{"document": configurationObjectForAPI(t, "draft side")})
	competing, _ := createDraft(map[string]any{"document": configurationObjectForAPI(t, "live side")})
	competingETag := validate(competing.ID)
	if response := request(http.MethodPost, "/admin/v1/config-revisions/"+competing.ID+"/activate", nil, competingETag); response.Code != http.StatusOK {
		t.Fatalf("activate competing status=%d body=%s", response.Code, response.Body.String())
	}
	preview := performGET(handler, "/admin/v1/config-revisions/"+stale.ID+"/rebase-preview", cookie)
	var mergePreview configuration.MergePreview
	decodeResponse(t, preview, &mergePreview)
	if preview.Code != http.StatusOK || mergePreview.UpToDate || mergePreview.LiveRevisionID != competing.ID ||
		len(mergePreview.Conflicts) != 1 || mergePreview.Conflicts[0] != "/metadata/description" ||
		strings.Contains(preview.Body.String(), "draft side") || strings.Contains(preview.Body.String(), "live side") {
		t.Fatalf("rebase preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	unresolved := request(http.MethodPost, "/admin/v1/config-revisions/"+stale.ID+"/rebase", map[string]any{"live_revision_id": competing.ID}, staleETag)
	if unresolved.Code != http.StatusConflict || !strings.Contains(unresolved.Body.String(), "Choose a side") {
		t.Fatalf("unresolved rebase status=%d body=%s", unresolved.Code, unresolved.Body.String())
	}
	badSide := request(http.MethodPost, "/admin/v1/config-revisions/"+stale.ID+"/rebase", map[string]any{
		"live_revision_id": competing.ID, "resolutions": map[string]string{"/metadata/description": "both"},
	}, staleETag)
	if badSide.Code != http.StatusBadRequest {
		t.Fatalf("rebase with an unknown side status=%d body=%s", badSide.Code, badSide.Body.String())
	}
	rebased := request(http.MethodPost, "/admin/v1/config-revisions/"+stale.ID+"/rebase", map[string]any{
		"live_revision_id": competing.ID, "resolutions": map[string]string{"/metadata/description": "draft"},
	}, staleETag)
	if rebased.Code != http.StatusOK || !bytes.Contains(rebased.Body.Bytes(), []byte(`"base_revision_id":"`+competing.ID+`"`)) ||
		!bytes.Contains(rebased.Body.Bytes(), []byte(`"description":"draft side"`)) {
		t.Fatalf("rebase status=%d body=%s", rebased.Code, rebased.Body.String())
	}

	// Promotion copies production's live configuration into staging's draft.
	promoted := request(http.MethodPost, "/admin/v1/environments/"+staging+"/config-revisions/promote", map[string]string{
		"source_environment_id": production, "description": "From production",
	}, "")
	if promoted.Code != http.StatusCreated || promoted.Header().Get("ETag") == "" ||
		!bytes.Contains(promoted.Body.Bytes(), []byte(`"environment":"staging"`)) ||
		!bytes.Contains(promoted.Body.Bytes(), []byte(`"review":["/spec/identityProviders/firebase"`)) {
		t.Fatalf("promotion status=%d body=%s", promoted.Code, promoted.Body.String())
	}
	if pending := request(http.MethodPost, "/admin/v1/environments/"+staging+"/config-revisions/promote", map[string]string{
		"source_environment_id": production,
	}, ""); pending.Code != http.StatusConflict || !strings.Contains(pending.Body.String(), "unpublished draft") {
		t.Fatalf("promotion over a pending draft status=%d body=%s", pending.Code, pending.Body.String())
	}
	if unknown := request(http.MethodPost, "/admin/v1/environments/"+staging+"/config-revisions/promote", map[string]string{
		"source_environment_id": production, "note": "x",
	}, ""); unknown.Code != http.StatusBadRequest {
		t.Fatalf("promotion with an unknown field status=%d", unknown.Code)
	}
}

// auditActionCount counts succeeded audit events with one action.
func auditActionCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, action string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = 'succeeded'`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
