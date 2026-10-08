package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/id"
)

func TestUsersAndInstallsInsightsPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("insights-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "insights", "organization_name": "Insights",
		"email": "owner@example.test", "display_name": "Owner", "password": "initial owner password",
	}, nil, "", selfServiceOrigin)
	var session struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &session)
	cookie, csrf := bootstrap.Result().Cookies()[0], bootstrap.Header().Get(csrfHeader)
	created := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", map[string]string{"organization_id": session.OrganizationID, "slug": "mobile", "display_name": "Mobile"}, cookie, csrf, selfServiceOrigin)
	var application struct {
		ID string `json:"id"`
	}
	decodeResponse(t, created, &application)
	environmentResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{"slug": "production", "display_name": "Production", "kind": "production"}, cookie, csrf, selfServiceOrigin)
	var environment struct {
		ID string `json:"id"`
	}
	decodeResponse(t, environmentResponse, &environment)
	fixture := seedOperationalFixture(t, ctx, pool, session.OrganizationID, application.ID, environment.ID)
	scope := "environment_id=" + url.QueryEscape(environment.ID)

	// Two more users: one blocked with a pro plan seen just now, one never seen and created first.
	blocked, quiet := id.Must(id.ApplicationUser), id.Must(id.ApplicationUser)
	now := time.Now().UTC()
	for _, row := range []struct {
		userID, status, claims string
		created                time.Time
		seen                   *time.Time
	}{
		{blocked, "blocked", `{"tier":"pro"}`, now.Add(-30 * time.Minute), &now},
		{quiet, "active", `{}`, now.Add(-200 * time.Minute), nil},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO application_users (application_user_id, organization_id, application_id, status, normalized_claims, created_at, updated_at, last_seen_at, blocked_at)
			VALUES ($1, $2, $3, $4::text, $5::jsonb, $6::timestamptz, $6::timestamptz, $7, CASE WHEN $4::text = 'blocked' THEN $6::timestamptz END)
		`, row.userID, session.OrganizationID, application.ID, row.status, row.claims, row.created, row.seen); err != nil {
			t.Fatal(err)
		}
		issuer, subject := sha256.Sum256([]byte("issuer:"+row.userID)), sha256.Sum256([]byte("subject:"+row.userID))
		if _, err := pool.Exec(ctx, `
			INSERT INTO external_identities (external_identity_id, organization_id, application_id, application_user_id, provider_key, issuer_hash, subject_hmac, selected_claims, created_at, last_verified_at)
			VALUES ($1, $2, $3, $4, 'supabase', $5, $6, '{}'::jsonb, $7, $7)
		`, id.Must(id.ExternalIdentity), session.OrganizationID, application.ID, row.userID, issuer[:], subject[:], row.created); err != nil {
			t.Fatal(err)
		}
	}
	listUsers := func(query string) []string {
		t.Helper()
		response := performGET(handler, "/admin/v1/users?"+scope+query, cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("users%s status=%d body=%s", query, response.Code, response.Body.String())
		}
		var document struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		decodeResponse(t, response, &document)
		ids := make([]string, 0, len(document.Items))
		for _, item := range document.Items {
			ids = append(ids, item.ID)
		}
		return ids
	}
	if got := strings.Join(listUsers(""), ","); got != strings.Join([]string{quiet, fixture.userID, blocked}, ",") {
		t.Fatalf("oldest-first users=%s", got)
	}
	if got := strings.Join(listUsers("&sort=newest"), ","); got != strings.Join([]string{blocked, fixture.userID, quiet}, ",") {
		t.Fatalf("newest-first users=%s", got)
	}
	if got := strings.Join(listUsers("&sort=recently_seen"), ","); got != strings.Join([]string{blocked, fixture.userID, quiet}, ",") {
		t.Fatalf("recently seen users=%s", got)
	}
	if got := listUsers("&status=blocked"); len(got) != 1 || got[0] != blocked {
		t.Fatalf("blocked users=%v", got)
	}
	if got := listUsers("&claim=tier:paid&provider=firebase"); len(got) != 1 || got[0] != fixture.userID {
		t.Fatalf("claim and provider users=%v", got)
	}
	if got := listUsers("&has_override=true"); len(got) != 0 {
		t.Fatalf("override users=%v", got)
	}
	// Pages follow the chosen order.
	first := performGET(handler, "/admin/v1/users?"+scope+"&sort=newest&page_size=1&include_total=true", cookie)
	var paged struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Page struct {
			NextCursor string `json:"next_cursor"`
		} `json:"page"`
		Total struct {
			Count  int64 `json:"count"`
			Capped bool  `json:"capped"`
		} `json:"total"`
	}
	decodeResponse(t, first, &paged)
	if len(paged.Items) != 1 || paged.Items[0].ID != blocked || paged.Total.Count != 3 || paged.Total.Capped || paged.Page.NextCursor == "" {
		t.Fatalf("first page body=%s", first.Body.String())
	}
	if got := listUsers("&sort=newest&page_size=1&cursor=" + paged.Page.NextCursor); len(got) != 1 || got[0] != fixture.userID {
		t.Fatalf("second page=%v", got)
	}
	for _, bad := range []string{"&status=deleted", "&claim=tier", "&claim=Tier:paid", "&sort=random", "&has_override=yes", "&include_total=1", "&status=active&status=blocked"} {
		if response := performGET(handler, "/admin/v1/users?"+scope+bad, cookie); response.Code != http.StatusBadRequest {
			t.Fatalf("filter %q status=%d", bad, response.Code)
		}
	}

	// A user's usage is summed from their requests in the range.
	usage := performGET(handler, "/admin/v1/users/"+fixture.userID+"/usage?"+scope+"&start="+url.QueryEscape(now.Add(-24*time.Hour).Format(time.RFC3339))+"&end="+url.QueryEscape(now.Add(time.Hour).Format(time.RFC3339)), cookie)
	var usageDocument struct {
		Requests int64 `json:"request_count"`
		Values   struct {
			CostNanoUSD int64 `json:"cost_nano_usd"`
		} `json:"values"`
	}
	decodeResponse(t, usage, &usageDocument)
	if usage.Code != http.StatusOK || usageDocument.Requests < 1 || usageDocument.Values.CostNanoUSD <= 0 {
		t.Fatalf("user usage status=%d body=%s", usage.Code, usage.Body.String())
	}
	if none := performGET(handler, "/admin/v1/users/"+quiet+"/usage?"+scope+"&start="+url.QueryEscape(now.Add(-24*time.Hour).Format(time.RFC3339))+"&end="+url.QueryEscape(now.Add(time.Hour).Format(time.RFC3339)), cookie); !bytes.Contains(none.Body.Bytes(), []byte(`"request_count":0`)) {
		t.Fatalf("idle user usage body=%s", none.Body.String())
	}

	// Installations carry server-side signals and can be filtered by them.
	families := performGET(handler, "/admin/v1/installation-families?"+scope+"&signal=any&include_total=true", cookie)
	if families.Code != http.StatusOK || !bytes.Contains(families.Body.Bytes(), []byte(`"signals":["debug_trust","trust_expiring"]`)) ||
		!bytes.Contains(families.Body.Bytes(), []byte(`"total":{"capped":false,"count":1}`)) {
		t.Fatalf("signal families status=%d body=%s", families.Code, families.Body.String())
	}
	if none := performGET(handler, "/admin/v1/installation-families?"+scope+"&signal=token_reuse", cookie); !bytes.Contains(none.Body.Bytes(), []byte(`"items":[]`)) {
		t.Fatalf("token reuse families body=%s", none.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE client_components SET key_storage_claim = 'software' WHERE client_component_id = $1`, fixture.componentID); err != nil {
		t.Fatal(err)
	}
	if weak := performGET(handler, "/admin/v1/installation-families/"+fixture.familyID, cookie); !bytes.Contains(weak.Body.Bytes(), []byte(`"weak_key_storage"`)) {
		t.Fatalf("family detail body=%s", weak.Body.String())
	}
	if bad := performGET(handler, "/admin/v1/installation-families?"+scope+"&signal=spooky", cookie); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown signal status=%d", bad.Code)
	}

	// Impact previews count what an action would end, without changing anything.
	impact := performGET(handler, "/admin/v1/installation-families/"+fixture.familyID+"/operation-impact?action=revoke", cookie)
	var familyImpact operationImpactDocument
	decodeResponse(t, impact, &familyImpact)
	if impact.Code != http.StatusOK || !familyImpact.Applicable || familyImpact.Counts.ActiveComponents != 1 || familyImpact.Counts.RequestsLast24Hours < 1 {
		t.Fatalf("family impact status=%d body=%s", impact.Code, impact.Body.String())
	}
	rootRevoke := performGET(handler, "/admin/v1/client-components/"+fixture.componentID+"/operation-impact?action=revoke", cookie)
	if !bytes.Contains(rootRevoke.Body.Bytes(), []byte(`"applicable":false`)) {
		t.Fatalf("root component revoke impact body=%s", rootRevoke.Body.String())
	}
	if reattest := performGET(handler, "/admin/v1/client-components/"+fixture.componentID+"/operation-impact?action=require_reattestation", cookie); !bytes.Contains(reattest.Body.Bytes(), []byte(`"applicable":true`)) {
		t.Fatalf("reattestation impact body=%s", reattest.Body.String())
	}

	// A batch applies one action to many users, skipping any whose state changed since the preview.
	unknown := id.Must(id.ApplicationUser)
	preview := performJSON(t, handler, http.MethodPost, "/admin/v1/users/batch-impact?"+scope, map[string]any{"action": "block", "user_ids": []string{fixture.userID, quiet, unknown}}, cookie, csrf, selfServiceOrigin)
	var previewDocument struct {
		Applicable int `json:"applicable"`
		Items      []struct {
			UserID  string `json:"user_id"`
			Outcome string `json:"outcome"`
			Impact  *struct {
				ImpactToken string `json:"impact_token"`
			} `json:"impact"`
		} `json:"items"`
	}
	decodeResponse(t, preview, &previewDocument)
	if preview.Code != http.StatusOK || previewDocument.Applicable != 2 || len(previewDocument.Items) != 3 || previewDocument.Items[2].Outcome != "not_found" {
		t.Fatalf("batch preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	items := []map[string]string{}
	for _, item := range previewDocument.Items[:2] {
		items = append(items, map[string]string{"user_id": item.UserID, "impact_token": item.Impact.ImpactToken})
	}
	batch := map[string]any{"action": "block", "reason": "abuse wave", "acknowledge_immediate_effect": true, "items": items}
	applied := performJSON(t, handler, http.MethodPost, "/admin/v1/users/batch?"+scope, batch, cookie, csrf, selfServiceOrigin)
	if applied.Code != http.StatusOK || !bytes.Contains(applied.Body.Bytes(), []byte(`"done":2`)) {
		t.Fatalf("batch status=%d body=%s", applied.Code, applied.Body.String())
	}
	if got := listUsers("&status=blocked"); len(got) != 3 {
		t.Fatalf("blocked after batch=%v", got)
	}
	again := performJSON(t, handler, http.MethodPost, "/admin/v1/users/batch?"+scope, batch, cookie, csrf, selfServiceOrigin)
	var replay struct {
		Done    int `json:"done"`
		Results []struct {
			Outcome string `json:"outcome"`
		} `json:"results"`
	}
	decodeResponse(t, again, &replay)
	if replay.Done != 0 || replay.Results[0].Outcome != "changed" || replay.Results[1].Outcome != "changed" {
		t.Fatalf("replayed batch body=%s", again.Body.String())
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action = 'admin.user_block'`, session.OrganizationID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 2 {
		t.Fatalf("user block audit events=%d", audits)
	}
	if missing := performJSON(t, handler, http.MethodPost, "/admin/v1/users/batch?"+scope, map[string]any{"action": "block", "reason": "x", "acknowledge_immediate_effect": false, "items": items}, cookie, csrf, selfServiceOrigin); missing.Code != http.StatusBadRequest {
		t.Fatalf("unacknowledged batch status=%d", missing.Code)
	}
}
