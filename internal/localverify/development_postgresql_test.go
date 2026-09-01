package localverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

func TestRunDevelopmentServesConsoleHelpersAndCleansPostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("LATCHWAY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	testContext, testCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer testCancel()
	adminPool, err := database.Open(testContext, databaseURL, 2)
	if err != nil {
		t.Fatal("open test database")
	}
	defer adminPool.Close()
	countSchemas := func() int64 {
		var count int64
		if err := adminPool.QueryRow(testContext, `
			SELECT count(*)
			FROM pg_namespace
			WHERE nspname ~ '^latchway_verify_[0-9a-f]{24}$'
		`).Scan(&count); err != nil {
			t.Fatal("count isolated schemas")
		}
		return count
	}
	baselineSchemas := countSchemas()

	runContext, stop := context.WithCancel(testContext)
	ready := make(chan DevelopmentInfo, 1)
	result := make(chan error, 1)
	resultConsumed := false
	defer func() {
		stop()
		if resultConsumed {
			return
		}
		select {
		case <-result:
		case <-time.After(15 * time.Second):
		}
	}()
	go func() {
		result <- RunDevelopment(runContext, DevelopmentConfig{
			DatabaseURL: databaseURL, ListenAddress: "127.0.0.1:0",
			BrowserOrigin: "http://localhost:5173",
			OnReady: func(info DevelopmentInfo) error {
				ready <- info
				return nil
			},
		})
	}()
	var info DevelopmentInfo
	select {
	case info = <-ready:
	case runErr := <-result:
		resultConsumed = true
		stop()
		t.Fatalf("local development exited before ready: %v", runErr)
	case <-testContext.Done():
		stop()
		t.Fatal("local development did not become ready")
	}
	if id.Validate(info.ApplicationID, id.Application) != nil || info.GatewayURL == "" ||
		info.IdentityTokenURL != info.GatewayURL+"/development/v1/identity-token" ||
		info.AttestationEvidenceURL != info.GatewayURL+"/development/v1/attestation-evidence" ||
		info.SampleRequestURL != info.GatewayURL+"/development/v1/sample-request" ||
		info.ConsoleURL != info.GatewayURL || info.BrowserOrigin != "http://localhost:5173" ||
		info.ConsoleEmail != developmentConsoleEmail || len(info.ConsolePassword) < 32 ||
		info.Environment != "development" || info.Feature != developmentFeature || info.Model != developmentModel {
		stop()
		t.Fatal("local development ready contract is incomplete")
	}

	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	request := func(method, target string, body []byte) *http.Response {
		t.Helper()
		httpRequest, err := http.NewRequestWithContext(testContext, method, target, bytes.NewReader(body))
		if err != nil {
			t.Fatal("construct local development request")
		}
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatal("perform local development request")
		}
		return response
	}

	health := request(http.MethodGet, info.GatewayURL+"/healthz", nil)
	if closeErr := health.Body.Close(); closeErr != nil || health.StatusCode != http.StatusOK {
		stop()
		t.Fatalf("local development health status=%d close_error=%v", health.StatusCode, closeErr)
	}
	identityRequest, err := http.NewRequestWithContext(testContext, http.MethodGet, info.IdentityTokenURL, nil)
	if err != nil {
		stop()
		t.Fatal("construct local identity request")
	}
	identityRequest.Header.Set("Origin", info.BrowserOrigin)
	identity, err := client.Do(identityRequest)
	if err != nil {
		stop()
		t.Fatal("perform local identity request")
	}
	var identityDocument map[string]string
	decodeErr := json.NewDecoder(identity.Body).Decode(&identityDocument)
	closeErr := identity.Body.Close()
	if identity.StatusCode != http.StatusOK || identity.Header.Get("Access-Control-Allow-Origin") != info.BrowserOrigin ||
		decodeErr != nil || closeErr != nil || len(identityDocument["identity_token"]) < 64 {
		stop()
		t.Fatal("local identity helper contract failed")
	}

	console := request(http.MethodGet, info.ConsoleURL+"/", nil)
	if closeErr := console.Body.Close(); closeErr != nil || console.StatusCode != http.StatusOK ||
		!strings.HasPrefix(console.Header.Get("Content-Type"), "text/html") {
		stop()
		t.Fatal("embedded local Console is unavailable")
	}
	loginBody, err := json.Marshal(map[string]string{
		"email": info.ConsoleEmail, "password": info.ConsolePassword,
	})
	if err != nil {
		stop()
		t.Fatal("encode local Console login")
	}
	loginRequest, err := http.NewRequestWithContext(
		testContext, http.MethodPost, info.GatewayURL+"/admin/v1/auth/login", bytes.NewReader(loginBody),
	)
	if err != nil {
		stop()
		t.Fatal("construct local Console login")
	}
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("Origin", info.GatewayURL)
	login, err := client.Do(loginRequest)
	if err != nil {
		stop()
		t.Fatal("perform local Console login")
	}
	if closeErr := login.Body.Close(); closeErr != nil || login.StatusCode != http.StatusOK {
		stop()
		t.Fatal("local Console credential was rejected")
	}
	var adminCookie *http.Cookie
	for _, cookie := range login.Cookies() {
		if cookie.Name == "__Host-latchway_admin" {
			adminCookie = cookie
			break
		}
	}
	if adminCookie == nil || !adminCookie.HttpOnly || !adminCookie.Secure || adminCookie.Path != "/" {
		stop()
		t.Fatal("local Console login did not issue the protected session cookie")
	}
	authenticatedGET := func(target string) *http.Response {
		t.Helper()
		adminRequest, err := http.NewRequestWithContext(testContext, http.MethodGet, target, nil)
		if err != nil {
			t.Fatal("construct authenticated local Console request")
		}
		adminRequest.AddCookie(adminCookie)
		response, err := client.Do(adminRequest)
		if err != nil {
			t.Fatal("perform authenticated local Console request")
		}
		return response
	}
	applicationsResponse := authenticatedGET(info.GatewayURL + "/admin/v1/applications")
	var applications struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	decodeErr = json.NewDecoder(applicationsResponse.Body).Decode(&applications)
	closeErr = applicationsResponse.Body.Close()
	if applicationsResponse.StatusCode != http.StatusOK || decodeErr != nil || closeErr != nil ||
		len(applications.Items) != 1 || applications.Items[0].ID != info.ApplicationID {
		stop()
		t.Fatal("authenticated local application view is unavailable")
	}
	environmentsResponse := authenticatedGET(
		info.GatewayURL + "/admin/v1/applications/" + applications.Items[0].ID + "/environments",
	)
	var environments struct {
		Items []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"items"`
	}
	decodeErr = json.NewDecoder(environmentsResponse.Body).Decode(&environments)
	closeErr = environmentsResponse.Body.Close()
	if environmentsResponse.StatusCode != http.StatusOK || decodeErr != nil || closeErr != nil ||
		len(environments.Items) != 1 || environments.Items[0].Slug != "development" {
		stop()
		t.Fatal("authenticated local environment view is unavailable")
	}
	sampleRequest, err := http.NewRequestWithContext(
		testContext, http.MethodPost, info.SampleRequestURL, strings.NewReader(`{}`),
	)
	if err != nil {
		stop()
		t.Fatal("construct local development sample request")
	}
	sampleRequest.Header.Set("Content-Type", "application/json")
	sampleRequest.Header.Set("Origin", info.GatewayURL)
	sampleResponse, err := client.Do(sampleRequest)
	if err != nil {
		stop()
		t.Fatal("perform local development sample request")
	}
	var sample developmentSampleResult
	decodeErr = json.NewDecoder(sampleResponse.Body).Decode(&sample)
	closeErr = sampleResponse.Body.Close()
	if sampleResponse.StatusCode != http.StatusCreated || decodeErr != nil || closeErr != nil ||
		id.Validate(sample.RequestID, id.LogicalRequest) != nil || sample.Feature != info.Feature ||
		sample.Protocol != "openai_responses" || sample.Status != "succeeded" || sample.Model != providerModel {
		stop()
		t.Fatalf("local development sample failed: status=%d result=%+v", sampleResponse.StatusCode, sample)
	}
	requestResponse := authenticatedGET(info.GatewayURL + "/admin/v1/requests/" + sample.RequestID)
	var durableSample struct {
		ID       string `json:"id"`
		Feature  string `json:"feature"`
		Protocol string `json:"protocol"`
		Status   string `json:"status"`
	}
	decodeErr = json.NewDecoder(requestResponse.Body).Decode(&durableSample)
	closeErr = requestResponse.Body.Close()
	if requestResponse.StatusCode != http.StatusOK || decodeErr != nil || closeErr != nil ||
		durableSample.ID != sample.RequestID || durableSample.Feature != sample.Feature ||
		durableSample.Protocol != sample.Protocol || durableSample.Status != sample.Status {
		stop()
		t.Fatalf("durable development sample mismatch: status=%d result=%+v", requestResponse.StatusCode, durableSample)
	}
	requestsResponse := authenticatedGET(
		info.GatewayURL + "/admin/v1/requests?environment_id=" + environments.Items[0].ID,
	)
	if closeErr := requestsResponse.Body.Close(); closeErr != nil || requestsResponse.StatusCode != http.StatusOK {
		stop()
		t.Fatalf("authenticated local request view status=%d close_error=%v", requestsResponse.StatusCode, closeErr)
	}

	stop()
	select {
	case runErr := <-result:
		resultConsumed = true
		if runErr != nil {
			t.Fatalf("local development shutdown: %v", runErr)
		}
	case <-testContext.Done():
		t.Fatal("local development did not shut down")
	}
	if leaked := countSchemas(); leaked != baselineSchemas {
		t.Fatalf("isolated schema count after shutdown = %d, want %d", leaked, baselineSchemas)
	}
}

func TestDevelopmentEvidenceSignsOnlyExactLiveChallengeBindingPostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("LATCHWAY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture := &fixture{
		databaseURL: databaseURL, publicOrigin: "http://127.0.0.1:38080",
		browserOrigin: "http://localhost:5173", nowFunction: time.Now,
	}
	t.Cleanup(func() {
		if err := fixture.cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	for _, setup := range []struct {
		name string
		step func(context.Context) error
	}{
		{name: "connect", step: fixture.connect},
		{name: "migrate", step: fixture.isolateAndMigrate},
		{name: "tenant", step: fixture.seedTenant},
	} {
		if err := setup.step(ctx); err != nil {
			t.Fatalf("%s: %v", setup.name, err)
		}
	}
	if err := fixture.prepareCryptography(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.startMockServices(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.seedVerificationSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fixture.activateConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fixture.composeRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	developmentHandler, err := fixture.developmentHandler()
	if err != nil {
		t.Fatal(err)
	}
	aliasResponse := httptest.NewRecorder()
	developmentHandler.ServeHTTP(
		aliasResponse, httptest.NewRequest(http.MethodGet, "/identity-token", nil),
	)
	if aliasResponse.Code != http.StatusNotFound {
		t.Fatalf("unmounted helper alias status = %d, want %d", aliasResponse.Code, http.StatusNotFound)
	}

	identityToken, err := fixture.oidc.token(fixture.clock())
	if err != nil {
		t.Fatal(err)
	}
	challengeTarget, err := parseURL(fixture.origin() + "/client/v1/session-challenges")
	if err != nil {
		t.Fatal(err)
	}
	challengeProof, err := signDPoP(fixture.dpopKey, http.MethodPost, challengeTarget, fixture.clock(), "development-challenge", "")
	if err != nil {
		t.Fatal(err)
	}
	challengeResponse, err := postJSON(fixture.clientHandler, "/client/v1/session-challenges", challengeProof, map[string]any{
		"application_id": fixture.tenant.applicationID, "environment": "development",
		"identity_provider": "mock_oidc", "identity_token": identityToken,
		"platform": "react_native_ios", "sdk_version": "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireStatus(challengeResponse, http.StatusCreated); err != nil {
		t.Fatalf("challenge: %v: %s", err, challengeResponse.Body.String())
	}
	var challenge challengeDocument
	if err := decodeJSON(challengeResponse, &challenge); err != nil {
		t.Fatal(err)
	}
	input := developmentEvidenceRequest{
		ChallengeID: challenge.ChallengeID, BindingHash: challenge.Attestation.ClientDataHash,
		ApplicationID: fixture.tenant.applicationID, Environment: "development",
		DPoPJKT: fixture.dpopJKT, Platform: "react_native_ios",
	}

	evidenceResponse := requestDevelopmentEvidence(t, fixture, input)
	if evidenceResponse.Code != http.StatusOK {
		t.Fatalf("authorized evidence: status=%d body=%s", evidenceResponse.Code, evidenceResponse.Body.String())
	}
	var evidence struct {
		KeyID       string `json:"key_id"`
		BindingHash string `json:"binding_hash"`
		ExpiresAt   int64  `json:"expires_at"`
		Signature   string `json:"signature"`
	}
	if err := json.Unmarshal(evidenceResponse.Body.Bytes(), &evidence); err != nil {
		t.Fatal(err)
	}
	bindingBytes, err := base64.RawURLEncoding.Strict().DecodeString(input.BindingHash)
	if err != nil || len(bindingBytes) != 32 {
		t.Fatalf("challenge binding is invalid: length=%d error=%v", len(bindingBytes), err)
	}
	var bindingHash [32]byte
	copy(bindingHash[:], bindingBytes)
	signature, err := base64.RawURLEncoding.Strict().DecodeString(evidence.Signature)
	if err != nil || evidence.KeyID != debugKeyID || evidence.BindingHash != input.BindingHash ||
		!ed25519.Verify(fixture.debugKey.Public().(ed25519.PublicKey), attestation.DebugSigningMessage(bindingHash, evidence.ExpiresAt), signature) {
		t.Fatalf("evidence signature contract is invalid: evidence=%+v signature_error=%v", evidence, err)
	}

	unknownChallengeID, err := id.New(id.SessionChallenge)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*developmentEvidenceRequest)
	}{
		{name: "different challenge", mutate: func(value *developmentEvidenceRequest) { value.ChallengeID = unknownChallengeID }},
		{name: "different binding", mutate: func(value *developmentEvidenceRequest) {
			value.BindingHash = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		}},
		{name: "different DPoP key", mutate: func(value *developmentEvidenceRequest) {
			value.DPoPJKT = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
		}},
		{name: "different platform", mutate: func(value *developmentEvidenceRequest) { value.Platform = "android" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := input
			test.mutate(&mutated)
			response := requestDevelopmentEvidence(t, fixture, mutated)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "development_evidence_not_authorized") {
				t.Fatalf("mismatched binding response: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if _, err := fixture.pool.Exec(ctx, `
		DELETE FROM active_config_revisions
		WHERE environment_id = $1
	`, fixture.tenant.environmentID); err != nil {
		t.Fatal(err)
	}
	inactiveConfiguration := requestDevelopmentEvidence(t, fixture, input)
	if inactiveConfiguration.Code != http.StatusForbidden {
		t.Fatalf("inactive configuration response: status=%d body=%s", inactiveConfiguration.Code, inactiveConfiguration.Body.String())
	}
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO active_config_revisions (
			organization_id, application_id, environment_id, config_revision_id,
			activated_by_admin_user_id, activated_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, fixture.tenant.organizationID, fixture.tenant.applicationID, fixture.tenant.environmentID,
		fixture.quotaRevisionID, fixture.tenant.adminUserID, fixture.clock()); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.pool.Exec(ctx, `
		UPDATE session_challenges
		SET created_at = $2, expires_at = $3
		WHERE session_challenge_id = $1
	`, challenge.ChallengeID, fixture.clock().Add(-2*time.Minute), fixture.clock().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	expired := requestDevelopmentEvidence(t, fixture, input)
	if expired.Code != http.StatusForbidden {
		t.Fatalf("expired challenge response: status=%d body=%s", expired.Code, expired.Body.String())
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE session_challenges
		SET expires_at = $2
		WHERE session_challenge_id = $1
	`, challenge.ChallengeID, fixture.clock().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO session_challenge_consumptions (
			organization_id, application_id, environment_id, session_challenge_id, consumed_at
		)
		SELECT organization_id, application_id, environment_id, session_challenge_id, $2
		FROM session_challenges
		WHERE session_challenge_id = $1
	`, challenge.ChallengeID, fixture.clock()); err != nil {
		t.Fatal(err)
	}
	consumed := requestDevelopmentEvidence(t, fixture, input)
	if consumed.Code != http.StatusForbidden {
		t.Fatalf("consumed challenge response: status=%d body=%s", consumed.Code, consumed.Body.String())
	}
}

func requestDevelopmentEvidence(t *testing.T, fixture *fixture, input developmentEvidenceRequest) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/development/v1/attestation-evidence", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", fixture.browserOrigin)
	response := httptest.NewRecorder()
	handler, err := fixture.developmentHandler()
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(response, request)
	return response
}
