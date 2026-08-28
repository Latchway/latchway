package adminapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	secretstore "github.com/latchway/latchway/internal/secrets"
)

func TestSecretAdminAPIPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	if databaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	provider, err := secretstore.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := secretstore.NewManager(secretstore.ManagerConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(pool, "https://console.example.test", 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), manager)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("secret-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := http.Handler(router)

	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "example",
		"organization_name": "Example", "email": "owner-secrets@example.test",
		"display_name": "Owner", "password": "correct horse battery staple",
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
		"organization_id": session.OrganizationID, "slug": "habits", "display_name": "Habits",
	}, cookie, csrf, "https://console.example.test")
	if applicationResponse.Code != http.StatusCreated {
		t.Fatalf("application status=%d body=%s", applicationResponse.Code, applicationResponse.Body.String())
	}
	var application struct {
		ID string `json:"id"`
	}
	decodeResponse(t, applicationResponse, &application)
	environmentResponse := performJSON(t, handler, http.MethodPost, "/admin/v1/applications/"+application.ID+"/environments", map[string]string{
		"slug": "production", "display_name": "Production", "kind": "production",
	}, cookie, csrf, "https://console.example.test")
	if environmentResponse.Code != http.StatusCreated {
		t.Fatalf("environment status=%d body=%s", environmentResponse.Code, environmentResponse.Body.String())
	}
	var environment struct {
		ID string `json:"id"`
	}
	decodeResponse(t, environmentResponse, &environment)

	firstValue := strings.Repeat("first-provider-key-material-", 4)
	missingCSRF := performJSON(t, handler, http.MethodPost, "/admin/v1/secrets", map[string]string{
		"environment_id": environment.ID, "name": "openrouter", "value": firstValue,
	}, cookie, "", "https://console.example.test")
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}
	created := performJSON(t, handler, http.MethodPost, "/admin/v1/secrets", map[string]string{
		"environment_id": environment.ID, "name": "openrouter", "value": firstValue,
	}, cookie, csrf, "https://console.example.test")
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), firstValue) {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var first secretstore.Metadata
	decodeResponse(t, created, &first)
	if first.EnvironmentID != environment.ID || first.Name != "openrouter" || first.Version != 1 || first.ID == "" {
		t.Fatalf("create metadata=%+v", first)
	}
	assertEncryptedSecretRow(t, ctx, pool, first.ID, []byte(firstValue))
	assertRuntimeSecret(t, ctx, pool, provider, secretstore.Scope{
		OrganizationID: session.OrganizationID, ApplicationID: application.ID, EnvironmentID: environment.ID,
	}, "secret/openrouter", firstValue)

	listed := performGET(handler, "/admin/v1/secrets?environment_id="+url.QueryEscape(environment.ID), cookie)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), firstValue) || strings.Contains(listed.Body.String(), "ciphertext") || strings.Contains(listed.Body.String(), "nonce") {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	var page struct {
		Items []secretstore.Metadata `json:"items"`
	}
	decodeResponse(t, listed, &page)
	if len(page.Items) != 1 || page.Items[0].ID != first.ID {
		t.Fatalf("secret page=%+v", page)
	}

	manageToken := createUserOverrideAPIToken(t, handler, cookie, csrf, "secret-automation", []string{"manage_secrets"})
	inspectToken := createUserOverrideAPIToken(t, handler, cookie, csrf, "secret-inspection", []string{"inspect_users"})
	denied := performBearerJSON(t, handler, http.MethodPost, "/admin/v1/secrets", map[string]string{
		"environment_id": environment.ID, "name": "denied", "value": "must-not-persist",
	}, inspectToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unscoped token status=%d body=%s", denied.Code, denied.Body.String())
	}

	secondValue := strings.Repeat("rotated-provider-key-material-", 4)
	rotated := performBearerJSON(t, handler, http.MethodPost, "/admin/v1/secrets/"+first.ID+"/rotate", map[string]string{
		"value": secondValue,
	}, manageToken)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), secondValue) {
		t.Fatalf("rotate status=%d body=%s", rotated.Code, rotated.Body.String())
	}
	var second secretstore.Metadata
	decodeResponse(t, rotated, &second)
	if second.ID == first.ID || second.Name != first.Name || second.Version != 2 {
		t.Fatalf("rotated metadata=%+v", second)
	}
	assertEncryptedSecretRow(t, ctx, pool, second.ID, []byte(secondValue))
	assertRuntimeSecret(t, ctx, pool, provider, secretstore.Scope{
		OrganizationID: session.OrganizationID, ApplicationID: application.ID, EnvironmentID: environment.ID,
	}, "secret/openrouter", secondValue)

	document := configurationObjectForAPI(t, "secret reference")
	upstream := document["spec"].(map[string]any)["upstreams"].([]any)[0].(map[string]any)
	upstream["authentication"] = map[string]any{"type": "bearer", "secretRef": "secret/openrouter"}
	revisionResponse := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/environments/"+environment.ID+"/config-revisions",
		map[string]any{"document": document}, cookie, csrf, "")
	if revisionResponse.Code != http.StatusCreated {
		t.Fatalf("create referenced config status=%d body=%s", revisionResponse.Code, revisionResponse.Body.String())
	}
	var revision configuration.Revision
	decodeResponse(t, revisionResponse, &revision)
	validated := performConfigurationJSON(t, handler, http.MethodPost,
		"/admin/v1/config-revisions/"+revision.ID+"/validate", nil, cookie, csrf, "")
	if validated.Code != http.StatusOK {
		t.Fatalf("validate referenced config status=%d body=%s", validated.Code, validated.Body.String())
	}
	staleDelete := performBearerJSON(t, handler, http.MethodDelete, "/admin/v1/secrets/"+first.ID, nil, manageToken)
	if staleDelete.Code != http.StatusConflict {
		t.Fatalf("stale delete status=%d body=%s", staleDelete.Code, staleDelete.Body.String())
	}
	referencedDelete := performBearerJSON(t, handler, http.MethodDelete, "/admin/v1/secrets/"+second.ID, nil, manageToken)
	if referencedDelete.Code != http.StatusConflict {
		t.Fatalf("referenced delete status=%d body=%s", referencedDelete.Code, referencedDelete.Body.String())
	}

	unusedValue := strings.Repeat("unused-provider-key-material-", 4)
	unusedCreate := performBearerJSON(t, handler, http.MethodPost, "/admin/v1/secrets", map[string]string{
		"environment_id": environment.ID, "name": "a", "value": unusedValue,
	}, manageToken)
	if unusedCreate.Code != http.StatusCreated {
		t.Fatalf("unused create status=%d body=%s", unusedCreate.Code, unusedCreate.Body.String())
	}
	var unused secretstore.Metadata
	decodeResponse(t, unusedCreate, &unused)
	deleted := performBearerJSON(t, handler, http.MethodDelete, "/admin/v1/secrets/"+unused.ID, nil, manageToken)
	if deleted.Code != http.StatusNoContent || deleted.Body.Len() != 0 {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	deletedAgain := performBearerJSON(t, handler, http.MethodDelete, "/admin/v1/secrets/"+unused.ID, nil, manageToken)
	if deletedAgain.Code != http.StatusNoContent || deletedAgain.Body.Len() != 0 {
		t.Fatalf("repeated delete status=%d body=%s", deletedAgain.Code, deletedAgain.Body.String())
	}
	runtimeStore, err := secretstore.NewStore(secretstore.StoreConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeStore.Use(ctx, secretstore.Scope{
		OrganizationID: session.OrganizationID, ApplicationID: application.ID, EnvironmentID: environment.ID,
	}, "secret/a", func([]byte) error { return nil }); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("destroyed secret use error=%v", err)
	}
	assertSecretAuditRedaction(t, ctx, pool, firstValue, secondValue, unusedValue, "must-not-persist")
}

func TestSecretAdminAPIInternalFailureDoesNotReflectPlaintext(t *testing.T) {
	t.Parallel()
	plaintext := strings.Repeat("reflection-sensitive-value-", 3)
	var logs bytes.Buffer
	api := &API{
		secretManager: secretErrorManager{err: errors.New("provider failure containing " + plaintext)},
		logger:        slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	request := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(`{"environment_id":"env_00000000000000000000000000","name":"provider","value":"`+plaintext+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleOwner,
		Method:         adminauth.AuthenticationSession,
		CredentialID:   "ase_00000000000000000000000000",
	}))
	recorder := httptest.NewRecorder()
	api.createSecret(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), plaintext) || strings.Contains(logs.String(), plaintext) {
		t.Fatalf("secret appeared in response or logs: body=%q logs=%q", recorder.Body.String(), logs.String())
	}
}

func TestSecretAdminAPIRejectsUnauthorizedMutationBeforeReadingBody(t *testing.T) {
	t.Parallel()
	api := &API{
		secretManager: secretErrorManager{err: errors.New("manager must not be called")},
		logger:        slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	body := &failOnReadSecretBody{}
	request := httptest.NewRequest(http.MethodPost, "/secrets", body)
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleViewer,
		Method:         adminauth.AuthenticationSession,
		CredentialID:   "ase_00000000000000000000000000",
	}))
	recorder := httptest.NewRecorder()
	api.createSecret(recorder, request)
	if recorder.Code != http.StatusForbidden || body.read {
		t.Fatalf("status=%d body_read=%t response=%s", recorder.Code, body.read, recorder.Body.String())
	}
}

func TestSecretAdminAPIReportsIndeterminateCommitWithCorrelatedOperationID(t *testing.T) {
	t.Parallel()
	manager := &secretIndeterminateManager{}
	api := &API{
		secretManager: manager,
		logger:        slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	state := &rejectedMutationAuditState{}
	request := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(
		`{"environment_id":"env_00000000000000000000000000","name":"provider","value":"safe-fixture"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), rejectedMutationAuditContextKey{}, state))
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleOwner,
		Method:         adminauth.AuthenticationSession,
		CredentialID:   "ase_00000000000000000000000000",
	}))
	recorder := httptest.NewRecorder()
	api.createSecret(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !state.indeterminate {
		t.Fatalf("status=%d indeterminate=%t body=%s", recorder.Code, state.indeterminate, recorder.Body.String())
	}
	var document struct {
		Code        string `json:"code"`
		OperationID string `json:"operation_id"`
		Retryable   bool   `json:"retryable"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Code != "operation_indeterminate" || !document.Retryable ||
		document.OperationID == "" || document.OperationID != manager.operationID || document.OperationID != state.operationID {
		t.Fatalf("problem=%+v manager_operation_id=%q state=%+v", document, manager.operationID, state)
	}
	if got := rejectedMutationOutcome(recorder.Code, state.indeterminate); got != adminauth.AuditIndeterminate {
		t.Fatalf("audit outcome=%q", got)
	}
}

type failOnReadSecretBody struct {
	read bool
}

func (body *failOnReadSecretBody) Read([]byte) (int, error) {
	body.read = true
	return 0, errors.New("unauthorized request body was read")
}

func assertEncryptedSecretRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, secretID string, plaintext []byte) {
	t.Helper()
	var ciphertext, nonce []byte
	if err := pool.QueryRow(ctx, `
		SELECT ciphertext, nonce FROM secret_records WHERE secret_record_id = $1
	`, secretID).Scan(&ciphertext, &nonce); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) < 17 || len(nonce) != 12 || bytes.Contains(ciphertext, plaintext) {
		t.Fatal("secret record was not stored as a valid redaction-safe envelope")
	}
}

func assertRuntimeSecret(t *testing.T, ctx context.Context, pool *pgxpool.Pool, provider secretstore.Provider, scope secretstore.Scope, reference, expected string) {
	t.Helper()
	store, err := secretstore.NewStore(secretstore.StoreConfig{Pool: pool, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	var observed []byte
	if err := store.Use(ctx, scope, reference, func(value []byte) error {
		observed = append(observed, value...)
		return nil
	}); err != nil {
		t.Fatalf("resolve runtime secret: %v", err)
	}
	defer clear(observed)
	if string(observed) != expected {
		t.Fatal("runtime secret did not resolve the expected active version")
	}
}

type secretErrorManager struct {
	err error
}

type secretIndeterminateManager struct {
	operationID string
}

func (*secretIndeterminateManager) List(context.Context, adminauth.Principal, string, secretstore.PageRequest) ([]secretstore.Metadata, error) {
	return nil, errors.New("not used")
}

func (manager *secretIndeterminateManager) Create(_ context.Context, _ adminauth.Principal, input secretstore.CreateInput) (secretstore.Metadata, error) {
	manager.operationID = input.RequestID
	return secretstore.Metadata{}, secretstore.ErrIndeterminate
}

func (*secretIndeterminateManager) Rotate(context.Context, adminauth.Principal, secretstore.RotateInput) (secretstore.Metadata, error) {
	return secretstore.Metadata{}, errors.New("not used")
}

func (*secretIndeterminateManager) Destroy(context.Context, adminauth.Principal, secretstore.DestroyInput) error {
	return errors.New("not used")
}

func (manager secretErrorManager) List(context.Context, adminauth.Principal, string, secretstore.PageRequest) ([]secretstore.Metadata, error) {
	return nil, manager.err
}

func (manager secretErrorManager) Create(context.Context, adminauth.Principal, secretstore.CreateInput) (secretstore.Metadata, error) {
	return secretstore.Metadata{}, manager.err
}

func (manager secretErrorManager) Rotate(context.Context, adminauth.Principal, secretstore.RotateInput) (secretstore.Metadata, error) {
	return secretstore.Metadata{}, manager.err
}

func (manager secretErrorManager) Destroy(context.Context, adminauth.Principal, secretstore.DestroyInput) error {
	return manager.err
}

func assertSecretAuditRedaction(t *testing.T, ctx context.Context, pool *pgxpool.Pool, plaintexts ...string) {
	t.Helper()
	var creates, rotations, deletions int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE action = 'admin.secret_create' AND outcome = 'succeeded'),
		       count(*) FILTER (WHERE action = 'admin.secret_rotate' AND outcome = 'succeeded'),
		       count(*) FILTER (WHERE action = 'admin.secret_delete' AND outcome = 'succeeded')
		FROM audit_events
	`).Scan(&creates, &rotations, &deletions); err != nil {
		t.Fatal(err)
	}
	if creates != 2 || rotations != 1 || deletions != 2 {
		t.Fatalf("secret audit counts create=%d rotate=%d delete=%d", creates, rotations, deletions)
	}
	var representation string
	if err := pool.QueryRow(ctx, `
		SELECT coalesce(jsonb_agg(to_jsonb(audit_event) || jsonb_build_object(
			'changes', coalesce(changes.items, '[]'::jsonb)
		))::text, '[]')
		FROM audit_events AS audit_event
		LEFT JOIN LATERAL (
			SELECT jsonb_agg(to_jsonb(change)) AS items
			FROM audit_event_changes AS change
			WHERE change.audit_event_id = audit_event.audit_event_id
		) AS changes ON true
		WHERE audit_event.action LIKE 'admin.secret_%'
	`).Scan(&representation); err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range plaintexts {
		if strings.Contains(representation, plaintext) {
			t.Fatalf("secret audit representation disclosed plaintext %q", plaintext)
		}
	}
}
