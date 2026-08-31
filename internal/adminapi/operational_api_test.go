package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/latchway/latchway/internal/id"
)

func TestOperationalDatabaseErrorClassification(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		code string
		want error
	}{
		{code: "23503", want: errOperationalNotFound},
		{code: "23505", want: errOperationalInvalid},
		{code: "23514", want: errOperationalInvalid},
		{code: "22001", want: errOperationalInvalid},
		{code: "22P02", want: errOperationalInvalid},
	} {
		test := test
		t.Run(test.code, func(t *testing.T) {
			t.Parallel()
			got := mapOperationalDatabase("classify", &pgconn.PgError{Code: test.code})
			if !errors.Is(got, test.want) {
				t.Fatalf("mapOperationalDatabase(%s)=%v, want %v", test.code, got, test.want)
			}
		})
	}
	transportFailure := errors.New("database commit acknowledgement lost")
	if got := mapOperationalCommit("commit", transportFailure); !errors.Is(got, errOperationalIndeterminate) {
		t.Fatalf("transport commit error=%v, want indeterminate", got)
	}
	constraintFailure := mapOperationalCommit("commit", &pgconn.PgError{Code: "23514"})
	if !errors.Is(constraintFailure, errOperationalInvalid) || errors.Is(constraintFailure, errOperationalIndeterminate) {
		t.Fatalf("constraint commit error=%v, want definite invalid", constraintFailure)
	}
	rollbackFailure := mapOperationalCommit("commit", pgx.ErrTxCommitRollback)
	if errors.Is(rollbackFailure, errOperationalIndeterminate) {
		t.Fatalf("commit rollback error=%v, want definite failure", rollbackFailure)
	}
}

func TestOperationalAdminAPIPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	api, err := New(
		pool, "https://console.example.test", 12*time.Hour,
		slog.New(slog.NewJSONHandler(io.Discard, nil)), testAdminSecretManager(t, pool),
		WithRole("api"),
	)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("operational-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "operations",
		"organization_name": "Operations", "email": "owner-operations@example.test",
		"display_name": "Operations Owner", "password": "correct horse battery staple",
	}, nil, "", "https://console.example.test")
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var session struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &session)
	cookie := bootstrap.Result().Cookies()[0]
	csrf := bootstrap.Header().Get(csrfHeader)
	applicationResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", map[string]string{
		"organization_id": session.OrganizationID, "slug": "mobile", "display_name": "Mobile",
	}, cookie, csrf, "https://console.example.test")
	if applicationResponse.Code != http.StatusCreated {
		t.Fatalf("create application status=%d body=%s", applicationResponse.Code, applicationResponse.Body.String())
	}
	var application struct {
		ID string `json:"id"`
	}
	decodeResponse(t, applicationResponse, &application)
	environmentResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{
		"slug": "production", "display_name": "Production", "kind": "production",
	}, cookie, csrf, "https://console.example.test")
	if environmentResponse.Code != http.StatusCreated {
		t.Fatalf("create environment status=%d body=%s", environmentResponse.Code, environmentResponse.Body.String())
	}
	var environment struct {
		ID string `json:"id"`
	}
	decodeResponse(t, environmentResponse, &environment)
	fixture := seedOperationalFixture(t, ctx, pool, session.OrganizationID, application.ID, environment.ID)

	baseQuery := "?environment_id=" + url.QueryEscape(environment.ID)
	userList := performGET(handler, "/admin/v1/users"+baseQuery+"&page_size=1", cookie)
	if userList.Code != http.StatusOK || !bytes.Contains(userList.Body.Bytes(), []byte(fixture.userID)) ||
		bytes.Contains(userList.Body.Bytes(), fixture.subjectHMAC) {
		t.Fatalf("user list status/body=%d %s", userList.Code, userList.Body.String())
	}
	userGet := performGET(handler, "/admin/v1/users/"+fixture.userID+baseQuery, cookie)
	if userGet.Code != http.StatusOK || !bytes.Contains(userGet.Body.Bytes(), []byte(`"identity_providers":["firebase"]`)) {
		t.Fatalf("user get status/body=%d %s", userGet.Code, userGet.Body.String())
	}
	duplicateEnvironment := performGET(handler, "/admin/v1/users"+baseQuery+"&environment_id="+url.QueryEscape(environment.ID), cookie)
	if duplicateEnvironment.Code != http.StatusBadRequest {
		t.Fatalf("duplicate environment status=%d body=%s", duplicateEnvironment.Code, duplicateEnvironment.Body.String())
	}

	installationList := performGET(handler, "/admin/v1/installations"+baseQuery, cookie)
	if installationList.Code != http.StatusOK || !bytes.Contains(installationList.Body.Bytes(), []byte(fixture.installationID)) ||
		!bytes.Contains(installationList.Body.Bytes(), []byte(`"attestation_provider":"debug"`)) {
		principal, authenticationErr := api.auth.AuthenticateSession(ctx, cookie.Value)
		_, directErr := api.operations.listInstallations(ctx, principal, environment.ID, operationalPage{size: 50})
		t.Fatalf("installation list status/body=%d %s auth=%v direct=%v", installationList.Code, installationList.Body.String(), authenticationErr, directErr)
	}
	installationGet := performGET(handler, "/admin/v1/installations/"+fixture.installationID, cookie)
	if installationGet.Code != http.StatusOK || bytes.Contains(installationGet.Body.Bytes(), fixture.refreshHash) {
		t.Fatalf("installation get status/body=%d %s", installationGet.Code, installationGet.Body.String())
	}
	familyList := performGET(handler, "/admin/v1/installation-families"+baseQuery, cookie)
	if familyList.Code != http.StatusOK ||
		!bytes.Contains(familyList.Body.Bytes(), []byte(fixture.familyID)) ||
		!bytes.Contains(familyList.Body.Bytes(), []byte(`"component_count":1`)) ||
		!bytes.Contains(familyList.Body.Bytes(), []byte(`"cost_nano_usd":123`)) {
		t.Fatalf("installation-family list status/body=%d %s", familyList.Code, familyList.Body.String())
	}
	filteredFamilyList := performGET(handler, "/admin/v1/installation-families"+baseQuery+
		"&user_id="+url.QueryEscape(fixture.userID), cookie)
	if filteredFamilyList.Code != http.StatusOK ||
		!bytes.Contains(filteredFamilyList.Body.Bytes(), []byte(fixture.familyID)) {
		t.Fatalf("filtered installation-family list status/body=%d %s",
			filteredFamilyList.Code, filteredFamilyList.Body.String())
	}
	otherUserFamilyList := performGET(handler, "/admin/v1/installation-families"+baseQuery+
		"&user_id="+url.QueryEscape(id.Must(id.ApplicationUser)), cookie)
	if otherUserFamilyList.Code != http.StatusOK ||
		bytes.Contains(otherUserFamilyList.Body.Bytes(), []byte(fixture.familyID)) {
		t.Fatalf("other-user installation-family list status/body=%d %s",
			otherUserFamilyList.Code, otherUserFamilyList.Body.String())
	}
	familyGet := performGET(handler, "/admin/v1/installation-families/"+fixture.familyID, cookie)
	if familyGet.Code != http.StatusOK ||
		!bytes.Contains(familyGet.Body.Bytes(), []byte(fixture.componentID)) ||
		!bytes.Contains(familyGet.Body.Bytes(), []byte(`"root_trust_source":"debug"`)) ||
		bytes.Contains(familyGet.Body.Bytes(), fixture.refreshHash) {
		t.Fatalf("installation-family detail status/body=%d %s", familyGet.Code, familyGet.Body.String())
	}
	componentList := performGET(handler, "/admin/v1/client-components"+baseQuery+
		"&installation_family_id="+url.QueryEscape(fixture.familyID), cookie)
	if componentList.Code != http.StatusOK ||
		!bytes.Contains(componentList.Body.Bytes(), []byte(fixture.componentID)) ||
		!bytes.Contains(componentList.Body.Bytes(), []byte(`"granted_features":["assistant"]`)) {
		t.Fatalf("client-component list status/body=%d %s", componentList.Code, componentList.Body.String())
	}
	componentGet := performGET(handler, "/admin/v1/client-components/"+fixture.componentID, cookie)
	if componentGet.Code != http.StatusOK ||
		!bytes.Contains(componentGet.Body.Bytes(), []byte(`"session_status":"active"`)) ||
		!bytes.Contains(componentGet.Body.Bytes(), []byte(`"session_failure_count":0`)) ||
		!bytes.Contains(componentGet.Body.Bytes(), []byte(`"request_count":1`)) ||
		bytes.Contains(componentGet.Body.Bytes(), fixture.refreshHash) {
		t.Fatalf("client-component detail status/body=%d %s", componentGet.Code, componentGet.Body.String())
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO usage_records (
		    usage_record_id, organization_id, application_id, environment_id,
		    logical_request_id, metric, units, confidence, provenance_key, recorded_at
		)
		SELECT 'usg_0' || lpad(generated.value::text, 25, '0'),
		       $1, $2, $3, $4, 'input_tokens', 1, 'estimated',
		       'admin-bulk-usage-' || lpad(generated.value::text, 12, '0'), $5
		FROM generate_series(1, 257) AS generated(value)
	`, session.OrganizationID, application.ID, environment.ID, fixture.requestID, fixture.recordedAt); err != nil {
		t.Fatalf("seed bounded request-usage aggregation: %v", err)
	}
	requestList := performGET(handler, "/admin/v1/requests"+baseQuery, cookie)
	if requestList.Code != http.StatusOK || !bytes.Contains(requestList.Body.Bytes(), []byte(fixture.requestID)) ||
		!bytes.Contains(requestList.Body.Bytes(), []byte(`"cost_nano_usd":123`)) ||
		!bytes.Contains(requestList.Body.Bytes(), []byte(`"input_tokens":262`)) ||
		!bytes.Contains(requestList.Body.Bytes(), []byte(`"client_component_id":"`+fixture.componentID+`"`)) ||
		!bytes.Contains(requestList.Body.Bytes(), []byte(`"framework":"swift-openai"`)) ||
		!bytes.Contains(requestList.Body.Bytes(), []byte(`"framework_version":"4.6.0"`)) ||
		requestList.Body.Len() > 16<<10 {
		t.Fatalf("request list status/body=%d %s", requestList.Code, requestList.Body.String())
	}
	requestGet := performGET(handler, "/admin/v1/requests/"+fixture.requestID, cookie)
	if requestGet.Code != http.StatusOK || !bytes.Contains(requestGet.Body.Bytes(), []byte(fixture.attemptID)) ||
		!bytes.Contains(requestGet.Body.Bytes(), []byte(fixture.secondAttemptID)) ||
		!bytes.Contains(requestGet.Body.Bytes(), []byte(`"usage_provenance":"upstream_reported"`)) ||
		!bytes.Contains(requestGet.Body.Bytes(), []byte(`"cost_provenance":"upstream_reported"`)) ||
		!bytes.Contains(requestGet.Body.Bytes(), []byte(`"cost_source":"openrouter_usage_cost"`)) {
		t.Fatalf("request get status/body=%d %s", requestGet.Code, requestGet.Body.String())
	}
	var requestDocument logicalRequestDocument
	decodeResponse(t, requestGet, &requestDocument)
	if len(requestDocument.Attempts) != 2 ||
		requestDocument.Attempts[0].AttemptNumber != 1 || requestDocument.Attempts[0].Route != "primary" ||
		requestDocument.Attempts[0].HTTPStatus == nil || *requestDocument.Attempts[0].HTTPStatus != 504 ||
		requestDocument.Attempts[0].FailureCode == nil || *requestDocument.Attempts[0].FailureCode != "timeout" ||
		requestDocument.Attempts[0].FirstByteAt != nil ||
		requestDocument.Attempts[1].AttemptNumber != 2 || requestDocument.Attempts[1].Route != "fallback" ||
		requestDocument.Attempts[1].FirstByteAt == nil || requestDocument.Attempts[1].FirstTokenAt == nil ||
		requestDocument.Attempts[1].FailureCode != nil {
		t.Fatalf("request attempt detail/order = %#v", requestDocument.Attempts)
	}
	if bytes.Contains(requestGet.Body.Bytes(), []byte(`upstream_timeout`)) {
		t.Fatalf("request detail exposed internal failure code: %s", requestGet.Body.String())
	}

	start := fixture.recordedAt.Add(-time.Hour).Format(time.RFC3339)
	end := fixture.recordedAt.Add(time.Hour).Format(time.RFC3339)
	usageQuery := baseQuery + "&start=" + url.QueryEscape(start) + "&end=" + url.QueryEscape(end)
	summary := performGET(handler, "/admin/v1/usage/summary"+usageQuery, cookie)
	if summary.Code != http.StatusOK || !bytes.Contains(summary.Body.Bytes(), []byte(`"logical_requests":1`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"total_tokens":12`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"active_users":1`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"request_count":1`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"key":"assistant"`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"key":"legacy_unknown"`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"p50_ms":60000`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"provenance":"upstream_reported"`)) ||
		!bytes.Contains(summary.Body.Bytes(), []byte(`"cost_source":"openrouter_usage_cost"`)) {
		t.Fatalf("usage summary status/body=%d %s", summary.Code, summary.Body.String())
	}
	var summaryDocument usageSummaryDocument
	decodeResponse(t, summary, &summaryDocument)
	if summaryDocument.Analytics.TimeToFirstToken != (usageDistribution{
		Samples: 1, P50MS: 40_000, P95MS: 40_000, P99MS: 40_000,
	}) {
		t.Fatalf("time-to-first-token distribution = %#v", summaryDocument.Analytics.TimeToFirstToken)
	}
	invalidBreakdown := performGET(handler, "/admin/v1/usage/summary"+usageQuery+"&breakdown_limit=201", cookie)
	if invalidBreakdown.Code != http.StatusBadRequest {
		t.Fatalf("invalid usage breakdown status/body=%d %s", invalidBreakdown.Code, invalidBreakdown.Body.String())
	}
	timeseries := performGET(handler, "/admin/v1/usage/timeseries"+usageQuery+"&interval=hour", cookie)
	if timeseries.Code != http.StatusOK || !bytes.Contains(timeseries.Body.Bytes(), []byte(`"cost_nano_usd":123`)) {
		t.Fatalf("usage timeseries status/body=%d %s", timeseries.Code, timeseries.Body.String())
	}
	oversizedSummary := performGET(handler, "/admin/v1/usage/summary"+baseQuery+
		"&start=2024-01-01T00%3A00%3A00Z&end=2026-01-01T00%3A00%3A00Z", cookie)
	if oversizedSummary.Code != http.StatusBadRequest {
		t.Fatalf("oversized summary status=%d body=%s", oversizedSummary.Code, oversizedSummary.Body.String())
	}
	oversizedTimeseries := performGET(handler, "/admin/v1/usage/timeseries"+baseQuery+
		"&start=2024-01-01T00%3A00%3A00Z&end=2026-01-01T00%3A00%3A00Z&interval=hour", cookie)
	if oversizedTimeseries.Code != http.StatusBadRequest {
		t.Fatalf("oversized timeseries status=%d body=%s", oversizedTimeseries.Code, oversizedTimeseries.Body.String())
	}
	inspectToken := createUserOverrideAPIToken(t, handler, cookie, csrf, "operational-read", []string{"inspect_users"})
	if inspected := performBearerGET(handler, "/admin/v1/requests"+baseQuery, inspectToken); inspected.Code != http.StatusOK {
		t.Fatalf("inspect-token request list status=%d body=%s", inspected.Code, inspected.Body.String())
	}
	inspectMutation := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/users/"+fixture.userID+"/block"+baseQuery, nil, inspectToken)
	if inspectMutation.Code != http.StatusForbidden {
		t.Fatalf("inspect-token mutation status=%d body=%s", inspectMutation.Code, inspectMutation.Body.String())
	}
	revokeToken := createUserOverrideAPIToken(t, handler, cookie, csrf, "operational-revoke", []string{"revoke_installations"})
	invalidReattestation := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/client-components/"+fixture.componentID+"/require-reattestation",
		map[string]string{"reason": strings.Repeat("r", 101)}, revokeToken)
	if invalidReattestation.Code != http.StatusBadRequest {
		t.Fatalf("invalid component re-attestation status/body=%d %s",
			invalidReattestation.Code, invalidReattestation.Body.String())
	}
	requiredReattestation := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/client-components/"+fixture.componentID+"/require-reattestation",
		map[string]string{"reason": "operator-reattestation"}, revokeToken)
	if requiredReattestation.Code != http.StatusOK ||
		!bytes.Contains(requiredReattestation.Body.Bytes(), []byte(`"status":"active"`)) ||
		!bytes.Contains(requiredReattestation.Body.Bytes(), []byte(`"trust_expires_at":`)) {
		t.Fatalf("require component re-attestation status/body=%d %s",
			requiredReattestation.Code, requiredReattestation.Body.String())
	}
	var preBlockGrantRevoked bool
	var renewalComponentRefreshStatus, legacyRefreshStatus string
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM session_grants WHERE session_grant_id = $1`,
		fixture.grantID).Scan(&preBlockGrantRevoked); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT status FROM component_refresh_tokens WHERE component_refresh_token_id = $1`,
		fixture.componentRefreshID).Scan(&renewalComponentRefreshStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT status FROM refresh_tokens WHERE refresh_token_id = $1`,
		fixture.refreshID).Scan(&legacyRefreshStatus); err != nil {
		t.Fatal(err)
	}
	if preBlockGrantRevoked || renewalComponentRefreshStatus != "revoked" || legacyRefreshStatus != "revoked" {
		t.Fatalf("re-attestation credentials grant_revoked=%t component_refresh=%q legacy_refresh=%q",
			preBlockGrantRevoked, renewalComponentRefreshStatus, legacyRefreshStatus)
	}
	requiredRenewal := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/installation-families/"+fixture.familyID+"/require-renewal",
		map[string]string{"reason": "operator-renewal"}, revokeToken)
	if requiredRenewal.Code != http.StatusOK ||
		!bytes.Contains(requiredRenewal.Body.Bytes(), []byte(`"status":"active"`)) ||
		!bytes.Contains(requiredRenewal.Body.Bytes(), []byte(`"root_trust_expires_at":`)) {
		t.Fatalf("require installation-family renewal status/body=%d %s",
			requiredRenewal.Code, requiredRenewal.Body.String())
	}

	blocked := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/users/"+fixture.userID+"/block"+baseQuery, nil, revokeToken)
	if blocked.Code != http.StatusOK || !bytes.Contains(blocked.Body.Bytes(), []byte(`"status":"blocked"`)) {
		t.Fatalf("block user status/body=%d %s", blocked.Code, blocked.Body.String())
	}
	unblocked := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/users/"+fixture.userID+"/unblock"+baseQuery, nil, revokeToken)
	if unblocked.Code != http.StatusOK || !bytes.Contains(unblocked.Body.Bytes(), []byte(`"status":"active"`)) {
		t.Fatalf("unblock user status/body=%d %s", unblocked.Code, unblocked.Body.String())
	}
	var grantRevoked bool
	var refreshStatus string
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM session_grants WHERE session_grant_id = $1`, fixture.grantID).Scan(&grantRevoked); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM refresh_tokens WHERE refresh_token_id = $1`, fixture.refreshID).Scan(&refreshStatus); err != nil {
		t.Fatal(err)
	}
	if !grantRevoked || refreshStatus != "revoked" {
		t.Fatalf("blocked-user credentials grant_revoked=%t refresh_status=%q", grantRevoked, refreshStatus)
	}

	invalidComponentRevocation := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/client-components/"+fixture.componentID+"/revoke",
		map[string]string{"reason": strings.Repeat("r", 101)}, revokeToken)
	if invalidComponentRevocation.Code != http.StatusBadRequest {
		t.Fatalf("invalid component revocation status/body=%d %s",
			invalidComponentRevocation.Code, invalidComponentRevocation.Body.String())
	}
	componentRevoked := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/client-components/"+fixture.componentID+"/revoke",
		map[string]string{"reason": "root-compromised"}, revokeToken)
	if componentRevoked.Code != http.StatusOK ||
		!bytes.Contains(componentRevoked.Body.Bytes(), []byte(`"status":"revoked"`)) ||
		!bytes.Contains(componentRevoked.Body.Bytes(), []byte(`"session_failure_count":1`)) {
		t.Fatalf("revoke root component status/body=%d %s",
			componentRevoked.Code, componentRevoked.Body.String())
	}
	var familyStatus, componentKeyStatus, componentSessionStatus, componentRefreshStatus string
	if err := pool.QueryRow(ctx, `
		SELECT family.status, component_key.status, component_session.status,
		       component_refresh.status
		FROM installation_families AS family
		JOIN client_components AS component
		  ON component.client_component_id = family.root_component_id
		JOIN component_keys AS component_key
		  ON component_key.component_key_id = component.current_component_key_id
		JOIN component_session_families AS component_session
		  ON component_session.client_component_id = component.client_component_id
		JOIN component_refresh_tokens AS component_refresh
		  ON component_refresh.component_session_family_id = component_session.component_session_family_id
		WHERE family.installation_family_id = $1
	`, fixture.familyID).Scan(
		&familyStatus, &componentKeyStatus, &componentSessionStatus, &componentRefreshStatus,
	); err != nil {
		t.Fatal(err)
	}
	if familyStatus != "revoked" || componentKeyStatus != "revoked" ||
		componentSessionStatus != "revoked" || componentRefreshStatus != "revoked" {
		t.Fatalf("root revocation family/key/session/refresh = %q/%q/%q/%q",
			familyStatus, componentKeyStatus, componentSessionStatus, componentRefreshStatus)
	}
	familyRevoked := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/installation-families/"+fixture.familyID+"/revoke",
		map[string]string{"reason": "operator-family-confirmation"}, revokeToken)
	if familyRevoked.Code != http.StatusOK ||
		!bytes.Contains(familyRevoked.Body.Bytes(), []byte(`"status":"revoked"`)) {
		t.Fatalf("idempotent family revocation status/body=%d %s",
			familyRevoked.Code, familyRevoked.Body.String())
	}

	invalidRevocation := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/installations/"+fixture.installationID+"/revoke",
		map[string]string{"reason": strings.Repeat("r", 101)}, revokeToken)
	if invalidRevocation.Code != http.StatusBadRequest {
		t.Fatalf("invalid installation revocation status/body=%d %s", invalidRevocation.Code, invalidRevocation.Body.String())
	}
	revoked := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/installations/"+fixture.installationID+"/revoke",
		map[string]string{"reason": "operator-requested"}, revokeToken)
	if revoked.Code != http.StatusOK || !bytes.Contains(revoked.Body.Bytes(), []byte(`"status":"revoked"`)) {
		t.Fatalf("revoke installation status/body=%d %s", revoked.Code, revoked.Body.String())
	}

	selfTest := performJSON(t, handler, http.MethodPost, "/admin/v1/self-tests", map[string]any{
		"kind": "local", "environment_id": environment.ID,
	}, cookie, csrf, "https://console.example.test")
	if selfTest.Code != http.StatusAccepted || !bytes.Contains(selfTest.Body.Bytes(), []byte(`"state":"passed"`)) {
		t.Fatalf("self-test status/body=%d %s", selfTest.Code, selfTest.Body.String())
	}
	var selfTestDocument struct {
		ID string `json:"id"`
	}
	decodeResponse(t, selfTest, &selfTestDocument)
	selfTestGet := performGET(handler, "/admin/v1/self-tests/"+selfTestDocument.ID, cookie)
	if selfTestGet.Code != http.StatusOK || !bytes.Contains(selfTestGet.Body.Bytes(), []byte(`"active_configuration"`)) {
		t.Fatalf("self-test get status/body=%d %s", selfTestGet.Code, selfTestGet.Body.String())
	}
	unsupportedSelfTest := performJSON(t, handler, http.MethodPost, "/admin/v1/self-tests", map[string]any{
		"kind": "openrouter", "environment_id": environment.ID,
	}, cookie, csrf, "https://console.example.test")
	if unsupportedSelfTest.Code != http.StatusBadRequest {
		t.Fatalf("unsupported self-test status/body=%d %s", unsupportedSelfTest.Code, unsupportedSelfTest.Body.String())
	}
	api.operations.selfTests = credentialSelfTestRunnerFixture(func(
		_ context.Context,
		input credentialSelfTestInput,
	) credentialSelfTestResult {
		if input.Scope.OrganizationID != session.OrganizationID || input.Scope.ApplicationID != application.ID ||
			input.Scope.EnvironmentID != environment.ID || input.Kind != "upstream" ||
			input.UpstreamID != "primary" || input.ModelID != "canary" || input.MaxCostNano != 1_000_000 {
			return failedCredentialSelfTest(nil, "fixture", "The test runner received the wrong tenant-scoped input.")
		}
		return credentialSelfTestResult{State: "passed", Checks: []selfTestCheck{
			passedSelfTestCheck("fixture", "The credential-aware fixture completed."),
		}}
	})
	credentialSelfTest := performJSON(t, handler, http.MethodPost, "/admin/v1/self-tests", map[string]any{
		"kind": "upstream", "environment_id": environment.ID,
		"upstream": "primary", "model": "canary", "max_cost_nano_usd": 1_000_000,
	}, cookie, csrf, "https://console.example.test")
	if credentialSelfTest.Code != http.StatusAccepted ||
		!bytes.Contains(credentialSelfTest.Body.Bytes(), []byte(`"state":"passed"`)) {
		t.Fatalf("credential self-test status/body=%d %s", credentialSelfTest.Code, credentialSelfTest.Body.String())
	}
	var credentialSelfTestDocument struct {
		ID string `json:"id"`
	}
	decodeResponse(t, credentialSelfTest, &credentialSelfTestDocument)
	credentialSelfTestGet := performGET(handler, "/admin/v1/self-tests/"+credentialSelfTestDocument.ID, cookie)
	if credentialSelfTestGet.Code != http.StatusOK ||
		!bytes.Contains(credentialSelfTestGet.Body.Bytes(), []byte(`"kind":"upstream"`)) ||
		!bytes.Contains(credentialSelfTestGet.Body.Bytes(), []byte(`credential-aware fixture completed`)) {
		t.Fatalf("credential self-test get status/body=%d %s", credentialSelfTestGet.Code, credentialSelfTestGet.Body.String())
	}
	api.operations.selfSchedules = scheduledSelfTestServiceFixture{revisionID: fixture.revisionID}
	scheduleBody := map[string]any{
		"kind": "upstream", "environment_id": environment.ID,
		"upstream": "primary", "model": "canary", "max_cost_nano_usd": 1_000_000,
		"daily_cost_limit_nano_usd": 24_000_000, "interval_seconds": 3600,
	}
	sessionSchedule := performJSON(t, handler, http.MethodPost, "/admin/v1/self-test-schedules",
		scheduleBody, cookie, csrf, "https://console.example.test")
	if sessionSchedule.Code != http.StatusForbidden {
		t.Fatalf("session-backed schedule status/body=%d %s", sessionSchedule.Code, sessionSchedule.Body.String())
	}
	sessionSubstitutionBody := make(map[string]any, len(scheduleBody)+1)
	for key, value := range scheduleBody {
		sessionSubstitutionBody[key] = value
	}
	sessionSubstitutionBody["authorization_credential_id"] = id.Must(id.AdminAPIToken)
	sessionSubstitution := performJSON(t, handler, http.MethodPost, "/admin/v1/self-test-schedules",
		sessionSubstitutionBody, cookie, csrf, "https://console.example.test")
	if sessionSubstitution.Code != http.StatusBadRequest {
		t.Fatalf("session credential substitution status/body=%d %s", sessionSubstitution.Code, sessionSubstitution.Body.String())
	}
	scheduleToken := createUserOverrideAPIToken(t, handler, cookie, csrf,
		"self-test-scheduler", []string{"run_self_tests"})
	var scheduleTokenID string
	if err := pool.QueryRow(ctx, `
		SELECT admin_api_token_id FROM admin_api_tokens
		WHERE organization_id = $1 AND name = 'self-test-scheduler'
	`, session.OrganizationID).Scan(&scheduleTokenID); err != nil {
		t.Fatal(err)
	}
	createdSchedule := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/self-test-schedules", scheduleBody, scheduleToken)
	if createdSchedule.Code != http.StatusCreated ||
		!bytes.Contains(createdSchedule.Body.Bytes(), []byte(`"status":"active"`)) ||
		!bytes.Contains(createdSchedule.Body.Bytes(), []byte(`"authorization_credential_id":"`+scheduleTokenID+`"`)) {
		t.Fatalf("create schedule status/body=%d %s", createdSchedule.Code, createdSchedule.Body.String())
	}
	var scheduleDocument struct {
		ID string `json:"id"`
	}
	decodeResponse(t, createdSchedule, &scheduleDocument)
	if id.Validate(scheduleDocument.ID, id.SelfTestSchedule) != nil {
		t.Fatalf("created invalid schedule ID %q", scheduleDocument.ID)
	}
	duplicateSchedule := performBearerJSON(t, handler, http.MethodPost,
		"/admin/v1/self-test-schedules", scheduleBody, scheduleToken)
	if duplicateSchedule.Code != http.StatusBadRequest {
		t.Fatalf("duplicate schedule status/body=%d %s", duplicateSchedule.Code, duplicateSchedule.Body.String())
	}
	listedSchedules := performGET(handler, "/admin/v1/self-test-schedules?environment_id="+
		url.QueryEscape(environment.ID), cookie)
	if listedSchedules.Code != http.StatusOK ||
		!bytes.Contains(listedSchedules.Body.Bytes(), []byte(scheduleDocument.ID)) {
		t.Fatalf("list schedules status/body=%d %s", listedSchedules.Code, listedSchedules.Body.String())
	}
	readSchedule := performGET(handler, "/admin/v1/self-test-schedules/"+scheduleDocument.ID, cookie)
	if readSchedule.Code != http.StatusOK ||
		!bytes.Contains(readSchedule.Body.Bytes(), []byte(fixture.revisionID)) {
		t.Fatalf("read schedule status/body=%d %s", readSchedule.Code, readSchedule.Body.String())
	}
	disabledSchedule := performJSON(t, handler, http.MethodDelete,
		"/admin/v1/self-test-schedules/"+scheduleDocument.ID, nil, cookie, csrf, "https://console.example.test")
	if disabledSchedule.Code != http.StatusOK ||
		!bytes.Contains(disabledSchedule.Body.Bytes(), []byte(`"status":"disabled"`)) ||
		!bytes.Contains(disabledSchedule.Body.Bytes(), []byte(`"disabled_reason_code":"operator_disabled"`)) {
		t.Fatalf("disable schedule status/body=%d %s", disabledSchedule.Code, disabledSchedule.Body.String())
	}
	selfTestWithUnknownQuery := performJSON(t, handler, http.MethodPost, "/admin/v1/self-tests?unexpected=true", map[string]any{
		"kind": "local", "environment_id": environment.ID,
	}, cookie, csrf, "https://console.example.test")
	if selfTestWithUnknownQuery.Code != http.StatusBadRequest {
		t.Fatalf("self-test unknown query status/body=%d %s", selfTestWithUnknownQuery.Code, selfTestWithUnknownQuery.Body.String())
	}
	secondOrganization := performJSON(t, handler, http.MethodPost, "/admin/v1/organizations", map[string]string{
		"slug": "other-operations", "display_name": "Other Operations",
	}, cookie, csrf, "https://console.example.test")
	if secondOrganization.Code != http.StatusCreated {
		t.Fatalf("second organization status/body=%d %s", secondOrganization.Code, secondOrganization.Body.String())
	}
	var secondOrganizationDocument struct {
		ID string `json:"id"`
	}
	decodeResponse(t, secondOrganization, &secondOrganizationDocument)
	secondLogin := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{
		"email": "owner-operations@example.test", "password": "correct horse battery staple",
		"organization_id": secondOrganizationDocument.ID,
	}, nil, "", "https://console.example.test")
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("second organization login status=%d body=%s", secondLogin.Code, secondLogin.Body.String())
	}
	secondCookie := secondLogin.Result().Cookies()[0]
	secondCSRF := secondLogin.Header().Get(csrfHeader)
	secondApplicationResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications", map[string]string{
		"organization_id": secondOrganizationDocument.ID, "slug": "secondary-mobile", "display_name": "Secondary Mobile",
	}, secondCookie, secondCSRF, "https://console.example.test")
	if secondApplicationResponse.Code != http.StatusCreated {
		t.Fatalf("second application status=%d body=%s", secondApplicationResponse.Code, secondApplicationResponse.Body.String())
	}
	var secondApplication struct {
		ID string `json:"id"`
	}
	decodeResponse(t, secondApplicationResponse, &secondApplication)
	secondEnvironmentResponse := performJSON(t, handler, http.MethodPost,
		"/admin/v1/applications/"+secondApplication.ID+"/environments", map[string]string{
			"slug": "production", "display_name": "Production", "kind": "production",
		}, secondCookie, secondCSRF, "https://console.example.test")
	if secondEnvironmentResponse.Code != http.StatusCreated {
		t.Fatalf("second environment status=%d body=%s", secondEnvironmentResponse.Code, secondEnvironmentResponse.Body.String())
	}
	var secondEnvironment struct {
		ID string `json:"id"`
	}
	decodeResponse(t, secondEnvironmentResponse, &secondEnvironment)
	secondFixture := seedOperationalFixture(
		t, ctx, pool, secondOrganizationDocument.ID, secondApplication.ID, secondEnvironment.ID,
	)
	crossTenantRequest := performGET(handler, "/admin/v1/requests/"+secondFixture.requestID, cookie)
	if crossTenantRequest.Code != http.StatusNotFound ||
		bytes.Contains(crossTenantRequest.Body.Bytes(), []byte(secondFixture.attemptID)) ||
		bytes.Contains(crossTenantRequest.Body.Bytes(), []byte(secondFixture.secondAttemptID)) {
		t.Fatalf("cross-tenant request status/body=%d %s", crossTenantRequest.Code, crossTenantRequest.Body.String())
	}
	secondTenantRequest := performGET(handler, "/admin/v1/requests/"+secondFixture.requestID, secondCookie)
	if secondTenantRequest.Code != http.StatusOK ||
		!bytes.Contains(secondTenantRequest.Body.Bytes(), []byte(secondFixture.secondAttemptID)) {
		t.Fatalf("same-tenant request status/body=%d %s", secondTenantRequest.Code, secondTenantRequest.Body.String())
	}
	if _, err := pool.Exec(ctx, `
		UPDATE upstream_attempts SET failure_code = 'provider_body_secret_text'
		WHERE upstream_attempt_id = $1
	`, secondFixture.attemptID); err != nil {
		t.Fatalf("seed unrecognized attempt failure: %v", err)
	}
	unknownFailure := performGET(handler, "/admin/v1/requests/"+secondFixture.requestID, secondCookie)
	if unknownFailure.Code != http.StatusOK ||
		!bytes.Contains(unknownFailure.Body.Bytes(), []byte(`"failure_code":"unknown"`)) ||
		bytes.Contains(unknownFailure.Body.Bytes(), []byte("provider_body_secret_text")) {
		t.Fatalf("unknown failure mapping status/body=%d %s", unknownFailure.Code, unknownFailure.Body.String())
	}
	if _, err := pool.Exec(ctx, `
		UPDATE upstream_attempts SET failure_code = 'upstream_timeout'
		WHERE upstream_attempt_id = $1
	`, secondFixture.attemptID); err != nil {
		t.Fatalf("restore recognized attempt failure: %v", err)
	}
	assertCorruptAttempt := func(name, mutation, restore string) {
		t.Helper()
		if _, err := pool.Exec(ctx, mutation, secondFixture.secondAttemptID); err != nil {
			t.Fatalf("%s mutation: %v", name, err)
		}
		response := performGET(handler, "/admin/v1/requests/"+secondFixture.requestID, secondCookie)
		if response.Code != http.StatusInternalServerError ||
			bytes.Contains(response.Body.Bytes(), []byte("corrupt")) ||
			bytes.Contains(response.Body.Bytes(), []byte("Invalid Route")) {
			t.Fatalf("%s corrupt-row response status/body=%d %s", name, response.Code, response.Body.String())
		}
		if _, err := pool.Exec(ctx, restore, secondFixture.secondAttemptID); err != nil {
			t.Fatalf("%s restore: %v", name, err)
		}
	}
	assertCorruptAttempt("timestamp order",
		`UPDATE upstream_attempts SET first_token_at = NULL, first_byte_at = completed_at + interval '1 second' WHERE upstream_attempt_id = $1`,
		`UPDATE upstream_attempts SET first_byte_at = completed_at - interval '30 seconds', first_token_at = completed_at - interval '20 seconds' WHERE upstream_attempt_id = $1`)
	assertCorruptAttempt("attempt-number gap",
		`UPDATE upstream_attempts SET attempt_number = 3 WHERE upstream_attempt_id = $1`,
		`UPDATE upstream_attempts SET attempt_number = 2 WHERE upstream_attempt_id = $1`)
	assertCorruptAttempt("noncanonical route",
		`UPDATE upstream_attempts SET route_key = 'Invalid Route' WHERE upstream_attempt_id = $1`,
		`UPDATE upstream_attempts SET route_key = 'fallback' WHERE upstream_attempt_id = $1`)
	assertCorruptAttempt("started terminal fields",
		`UPDATE upstream_attempts SET status = 'started' WHERE upstream_attempt_id = $1`,
		`UPDATE upstream_attempts SET status = 'succeeded' WHERE upstream_attempt_id = $1`)
	crossTenantAudit := performGET(handler, "/admin/v1/audit-events?organization_id="+
		url.QueryEscape(secondOrganizationDocument.ID), cookie)
	if crossTenantAudit.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant audit status/body=%d %s", crossTenantAudit.Code, crossTenantAudit.Body.String())
	}

	audit := performGET(handler, "/admin/v1/audit-events?page_size=200", cookie)
	for _, action := range []string{
		"admin.user_block", "admin.user_unblock", "admin.client_component_require_reattestation",
		"admin.installation_family_require_renewal", "admin.client_component_revoke",
		"admin.installation_family_revoke", "admin.installation_revoke", "admin.self_test_run",
		"admin.self_test_schedule_create", "admin.self_test_schedule_disable",
	} {
		if audit.Code != http.StatusOK || !bytes.Contains(audit.Body.Bytes(), []byte(action)) {
			t.Fatalf("audit event %q missing: status=%d body=%s", action, audit.Code, audit.Body.String())
		}
	}
	if bytes.Contains(audit.Body.Bytes(), []byte("operator-requested")) || bytes.Contains(audit.Body.Bytes(), fixture.refreshHash) {
		t.Fatalf("audit response leaked mutation or credential material: %s", audit.Body.String())
	}
	auditFirstPage := performGET(handler, "/admin/v1/audit-events?page_size=1", cookie)
	var auditFirst struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Page struct {
			HasMore    bool   `json:"has_more"`
			NextCursor string `json:"next_cursor"`
		} `json:"page"`
	}
	decodeResponse(t, auditFirstPage, &auditFirst)
	if auditFirstPage.Code != http.StatusOK || len(auditFirst.Items) != 1 ||
		!auditFirst.Page.HasMore || auditFirst.Page.NextCursor == "" {
		t.Fatalf("first audit page status/body=%d %s", auditFirstPage.Code, auditFirstPage.Body.String())
	}
	auditSecondPage := performGET(handler, "/admin/v1/audit-events?page_size=1&cursor="+
		url.QueryEscape(auditFirst.Page.NextCursor), cookie)
	var auditSecond struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	decodeResponse(t, auditSecondPage, &auditSecond)
	if auditSecondPage.Code != http.StatusOK || len(auditSecond.Items) != 1 ||
		auditSecond.Items[0].ID == auditFirst.Items[0].ID {
		t.Fatalf("second audit page status/body=%d %s", auditSecondPage.Code, auditSecondPage.Body.String())
	}

	system := performGET(handler, "/admin/v1/system", cookie)
	if system.Code != http.StatusOK || !bytes.Contains(system.Body.Bytes(), []byte(`"role":"api"`)) ||
		!bytes.Contains(system.Body.Bytes(), []byte(`"ready":true`)) {
		t.Fatalf("system status/body=%d %s", system.Code, system.Body.String())
	}
}

type operationalFixture struct {
	revisionID         string
	userID             string
	installationID     string
	familyID           string
	componentID        string
	componentKeyID     string
	componentSessionID string
	componentRefreshID string
	grantID            string
	refreshID          string
	requestID          string
	attemptID          string
	secondAttemptID    string
	recordedAt         time.Time
	subjectHMAC        []byte
	refreshHash        []byte
}

func seedOperationalFixture(
	t *testing.T,
	ctx context.Context,
	pool pgxExecutor,
	organizationID string,
	applicationID string,
	environmentID string,
) operationalFixture {
	t.Helper()
	var ownerID string
	if err := pool.QueryRow(ctx, `
		SELECT admin_user_id FROM admin_memberships
		WHERE organization_id = $1 AND role = 'owner' AND status = 'active'
	`, organizationID).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixtureBytes := func(label string) []byte {
		digest := sha256.Sum256([]byte(label + ":" + organizationID + ":" + applicationID + ":" + environmentID))
		return append([]byte(nil), digest[:]...)
	}
	revisionID := id.Must(id.ConfigRevision)
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
		    config_revision_id, organization_id, application_id, environment_id,
		    revision_number, etag, status, document, compiled_document, validation_report,
		    created_by_admin_user_id, created_at, validated_at, activated_at
		) VALUES ($1, $2, $3, $4, 1, $5, 'valid', '{}'::jsonb, '{}'::jsonb,
		          '{"valid":true,"issues":[]}'::jsonb, $6, $7, $7, $7)
	`, revisionID, organizationID, applicationID, environmentID,
		`"operational-fixture-etag"`, ownerID, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO active_config_revisions (
		    organization_id, application_id, environment_id, config_revision_id,
		    revision_status, activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, 'valid', $5, $6)
	`, organizationID, applicationID, environmentID, revisionID, ownerID, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	fixture := operationalFixture{
		revisionID: revisionID,
		userID:     id.Must(id.ApplicationUser), installationID: id.Must(id.Installation),
		familyID: id.Must(id.InstallationFamily), componentID: id.Must(id.ClientComponent),
		componentKeyID: id.Must(id.ComponentKey), componentSessionID: id.Must(id.ComponentSession),
		componentRefreshID: id.Must(id.ComponentRefresh),
		grantID:            id.Must(id.SessionGrant), refreshID: id.Must(id.RefreshToken),
		requestID: id.Must(id.LogicalRequest), attemptID: id.Must(id.UpstreamAttempt),
		secondAttemptID: id.Must(id.UpstreamAttempt),
		recordedAt:      now.Add(-10 * time.Minute), subjectHMAC: fixtureBytes("subject"),
		refreshHash: fixtureBytes("refresh-token"),
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
		    application_user_id, organization_id, application_id, status,
		    normalized_claims, created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, 'active', '{"tier":"paid"}'::jsonb, $4, $4, $5)
	`, fixture.userID, organizationID, applicationID, now.Add(-90*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO external_identities (
		    external_identity_id, organization_id, application_id, application_user_id,
		    provider_key, issuer_hash, subject_hmac, selected_claims, created_at, last_verified_at
		) VALUES ($1, $2, $3, $4, 'firebase', $5, $6, '{}'::jsonb, $7, $7)
	`, id.Must(id.ExternalIdentity), organizationID, applicationID, fixture.userID,
		bytes.Repeat([]byte{0x4c}, 32), fixture.subjectHMAC, now.Add(-90*time.Minute)); err != nil {
		t.Fatal(err)
	}
	dpopJKT := strings.Repeat("A", 43)
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
		    installation_id, organization_id, application_id, environment_id,
		    application_user_id, platform, dpop_jkt, dpop_public_jwk,
		    key_storage, trust_level, status, created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, 'ios', $6, '{}'::jsonb,
		          'secure_enclave', 'app_verified', 'active', $7, $7, $8)
	`, fixture.installationID, organizationID, applicationID, environmentID,
		fixture.userID, dpopJKT, now.Add(-80*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_definitions (
		    environment_id, config_revision_id, component_definition_id,
		    platform, component_kind, family_role, definition, created_at
		) VALUES (
		    $1, $2, 'ios-main', 'ios', 'main_app', 'root',
		    '{"id":"ios-main","platform":"ios","kind":"main_app","familyRole":"root","allowedFeatures":["assistant"]}'::jsonb,
		    $3
		)
	`, environmentID, revisionID, now.Add(-80*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installation_families (
		    installation_family_id, organization_id, application_id, environment_id,
		    application_user_id, platform, status, root_installation_id,
		    created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, 'ios', 'active', $6, $7, $7, $8)
	`, fixture.familyID, organizationID, applicationID, environmentID,
		fixture.userID, fixture.installationID, now.Add(-80*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO client_components (
		    client_component_id, organization_id, application_id, environment_id,
		    application_user_id, installation_family_id, component_definition_id,
		    component_kind, platform, is_root, status, trust_source,
		    trust_attestation_provider, trust_verified_at, trust_expires_at,
		    trust_signals, granted_features, key_storage_claim, app_version, sdk_version,
		    created_at, updated_at, last_seen_at
		) VALUES (
		    $1, $2, $3, $4, $5, $6, 'ios-main', 'main_app', 'ios', true,
		    'active', 'debug', 'debug', $7, $8, '{"fixture":true}'::jsonb,
		    '["assistant"]'::jsonb, 'secure_enclave', '1.0.0', '1.0.0-rc.1',
		    $9, $9, $10
		)
	`, fixture.componentID, organizationID, applicationID, environmentID,
		fixture.userID, fixture.familyID, now.Add(-60*time.Minute), now.Add(time.Hour),
		now.Add(-80*time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_keys (
		    component_key_id, organization_id, application_id, environment_id,
		    installation_family_id, client_component_id, dpop_jkt, public_jwk,
		    status, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, '{}'::jsonb, 'active', $8)
	`, fixture.componentKeyID, organizationID, applicationID, environmentID,
		fixture.familyID, fixture.componentID, dpopJKT, now.Add(-80*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE client_components SET current_component_key_id = $2
		WHERE client_component_id = $1;
		UPDATE installation_families SET root_component_id = $1
		WHERE installation_family_id = $3
	`, pgx.QueryExecModeSimpleProtocol, fixture.componentID, fixture.componentKeyID, fixture.familyID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_session_families (
		    component_session_family_id, organization_id, application_id, environment_id,
		    application_user_id, installation_family_id, client_component_id,
		    component_key_id, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $9)
	`, fixture.componentSessionID, organizationID, applicationID, environmentID,
		fixture.userID, fixture.familyID, fixture.componentID, fixture.componentKeyID,
		now.Add(-40*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO attestation_events (
		    attestation_event_id, organization_id, application_id, environment_id,
		    installation_id, provider, outcome, trust_level, normalized_signals, occurred_at,
		    installation_family_id, client_component_id, trust_source
		) VALUES ($1, $2, $3, $4, $5, 'debug', 'accepted', 'app_verified',
		          '{}'::jsonb, $6, $7, $8, 'debug')
	`, id.Must(id.AttestationEvent), organizationID, applicationID, environmentID,
		fixture.installationID, now.Add(-60*time.Minute), fixture.familyID, fixture.componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
		    session_grant_id, organization_id, application_id, environment_id,
		    application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
		    policy_revision_id, trust_level, identity_verified_at, attested_at,
		    attestation_provider, attestation_expires_at, issued_at, expires_at,
		    installation_family_id, client_component_id, component_definition_id,
		    component_kind, component_is_root, trust_source, component_session_family_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
		          'app_verified', $10, $10, 'debug', $12, $11, $12,
		          $13, $14, 'ios-main', 'main_app', true, 'debug', $15)
	`, fixture.grantID, organizationID, applicationID, environmentID, fixture.userID,
		fixture.installationID, fixtureBytes("access-token-jti"), dpopJKT, revisionID,
		now.Add(-45*time.Minute), now.Add(-40*time.Minute), now.Add(time.Hour),
		fixture.familyID, fixture.componentID, fixture.componentSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO refresh_tokens (
		    refresh_token_id, family_id, organization_id, application_id, environment_id,
		    application_user_id, installation_id, session_grant_id, token_hash,
		    status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11)
	`, fixture.refreshID, id.Must(id.RefreshTokenFamily), organizationID, applicationID,
		environmentID, fixture.userID, fixture.installationID, fixture.grantID,
		fixture.refreshHash, now.Add(-40*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_refresh_tokens (
		    component_refresh_token_id, component_session_family_id,
		    client_component_id, component_key_id, session_grant_id,
		    grant_kind, token_hash, status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 'session', $6, 'active', $7, $8)
	`, fixture.componentRefreshID, fixture.componentSessionID, fixture.componentID,
		fixture.componentKeyID, fixture.grantID, fixture.refreshHash,
		now.Add(-40*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO logical_requests (
		    logical_request_id, organization_id, application_id, environment_id,
		    application_user_id, installation_id, session_grant_id, config_revision_id,
		    feature_key, protocol, status, requested_at, dispatched_at, completed_at,
		    installation_family_id, client_component_id, component_definition_id,
		    component_kind, trust_source, framework, framework_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
		          'assistant', 'openai_chat', 'succeeded', $9, $10, $11,
		          $12, $13, 'ios-main', 'main_app', 'debug', 'swift-openai', '4.6.0')
	`, fixture.requestID, organizationID, applicationID, environmentID, fixture.userID,
		fixture.installationID, fixture.grantID, revisionID, fixture.recordedAt.Add(-time.Minute),
		fixture.recordedAt.Add(-50*time.Second), fixture.recordedAt,
		fixture.familyID, fixture.componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_reservations (
		    quota_reservation_id, organization_id, application_id, environment_id,
		    logical_request_id, idempotency_key, status, created_at, expires_at, settled_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'settled', $7, $8, $9)
	`, id.Must(id.QuotaReservation), organizationID, applicationID, environmentID,
		fixture.requestID, "operational-fixture-reservation", fixture.recordedAt.Add(-55*time.Second),
		fixture.recordedAt.Add(time.Hour), fixture.recordedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO upstream_attempts (
		    upstream_attempt_id, organization_id, application_id, environment_id,
		    logical_request_id, attempt_number, route_key, upstream_key, physical_model,
		    status, started_at, completed_at, http_status, failure_code, billed_cost_nano_usd,
		    currency, price_revision, pricing_source, cost_confidence
		) VALUES ($1, $2, $3, $4, $5, 1, 'primary', 'openai', 'gpt-test',
		          'timed_out', $6, $7, 504, 'upstream_timeout', 123,
		          'USD', 'fixture', 'configuration', 'reported')
	`, fixture.attemptID, organizationID, applicationID, environmentID, fixture.requestID,
		fixture.recordedAt.Add(-50*time.Second), fixture.recordedAt.Add(-40*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO upstream_attempts (
		    upstream_attempt_id, organization_id, application_id, environment_id,
		    logical_request_id, attempt_number, route_key, upstream_key, physical_model,
		    model_key, attempt_decision_binding_version, attempt_decision_sha256,
		    input_accounting_binding_version,
		    status, started_at, first_byte_at, first_token_at, completed_at, http_status
		) VALUES ($1, $2, $3, $4, $5, 2, 'fallback', 'anthropic', 'claude-test',
		          'assistant_fallback', 1, decode(repeat('42', 32), 'hex'), 1,
		          'succeeded', $6, $7, $8, $9, 200)
	`, fixture.secondAttemptID, organizationID, applicationID, environmentID, fixture.requestID,
		fixture.recordedAt.Add(-39*time.Second), fixture.recordedAt.Add(-30*time.Second),
		fixture.recordedAt.Add(-20*time.Second), fixture.recordedAt); err != nil {
		t.Fatal(err)
	}
	usage := []struct {
		metric     string
		units      int64
		attemptID  any
		confidence string
	}{
		{metric: "logical_requests", units: 1, confidence: "calculated"},
		{metric: "input_tokens", units: 5, attemptID: fixture.attemptID, confidence: "reported"},
		{metric: "output_tokens", units: 7, attemptID: fixture.attemptID, confidence: "reported"},
		{metric: "total_tokens", units: 12, attemptID: fixture.attemptID, confidence: "reported"},
		{metric: "cost_nano_usd", units: 123, attemptID: fixture.attemptID, confidence: "reported"},
	}
	for index, record := range usage {
		var cost, currency, revision, source any
		if record.metric == "cost_nano_usd" {
			cost, currency, source = int64(123), "USD", "openrouter_usage_cost"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO usage_records (
			    usage_record_id, organization_id, application_id, environment_id,
			    logical_request_id, upstream_attempt_id, metric, units,
			    cost_nano_usd, currency, price_revision, pricing_source,
			    confidence, provenance_key, recorded_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		`, id.Must(id.UsageRecord), organizationID, applicationID, environmentID,
			fixture.requestID, record.attemptID, record.metric, record.units,
			cost, currency, revision, source, record.confidence,
			"operational-fixture-"+strconv.Itoa(index), fixture.recordedAt); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

type pgxExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type credentialSelfTestRunnerFixture func(context.Context, credentialSelfTestInput) credentialSelfTestResult

func (fixture credentialSelfTestRunnerFixture) Run(
	ctx context.Context,
	input credentialSelfTestInput,
) credentialSelfTestResult {
	return fixture(ctx, input)
}

type scheduledSelfTestServiceFixture struct {
	revisionID string
}

func (fixture scheduledSelfTestServiceFixture) Prepare(
	_ context.Context,
	input credentialSelfTestInput,
) (preparedScheduledSelfTest, error) {
	return preparedScheduledSelfTest{
		Scope: input.Scope, RevisionID: fixture.revisionID, Kind: input.Kind,
		UpstreamID: input.UpstreamID, ModelID: input.ModelID,
		MaxCostNanoUSD: input.MaxCostNano,
	}, nil
}

func (scheduledSelfTestServiceFixture) RunBound(
	context.Context,
	preparedScheduledSelfTest,
) credentialSelfTestResult {
	return credentialSelfTestResult{State: "passed", Checks: []selfTestCheck{
		passedSelfTestCheck("fixture", "The scheduled fixture completed."),
	}}
}
