package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

var readinessSchemaPattern = regexp.MustCompile(`^latchway_readiness_test_[0-9]+$`)

func TestReadinessChecksSchemaConfigurationKeysAndWorkerPostgreSQL(t *testing.T) {
	pool, ctx := isolatedReadinessPool(t)
	calls := map[string]int{}
	checks := ReadinessChecks{
		MasterKey:       func(context.Context) error { calls["master_key"]++; return nil },
		SigningKey:      func(context.Context) error { calls["signing_key"]++; return nil },
		WorkerHeartbeat: func(context.Context) error { calls["worker_heartbeat"]++; return nil },
	}
	status, body := serveReadiness(t, pool, checks)
	if status != http.StatusOK || body["status"] != "ready" {
		t.Fatalf("initial readiness status=%d body=%v", status, body)
	}
	if readinessCheck(body, "quota_completion_pool") != "ok" {
		t.Fatalf("single-pool completion readiness = %v", body)
	}
	for _, name := range []string{"master_key", "signing_key", "worker_heartbeat"} {
		if calls[name] != 1 {
			t.Fatalf("%s calls=%d want 1", name, calls[name])
		}
	}

	organizationID, applicationID, environmentID := mustReadinessID(t, id.Organization), mustReadinessID(t, id.Application), mustReadinessID(t, id.Environment)
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (organization_id,slug,display_name,created_at,updated_at) VALUES ($1,'ready-org','Ready Org',$2,$2)`, organizationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO applications (application_id,organization_id,slug,display_name,created_at,updated_at) VALUES ($1,$2,'ready-app','Ready App',$3,$3)`, applicationID, organizationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO environments (environment_id,organization_id,application_id,slug,display_name,kind,created_at,updated_at) VALUES ($1,$2,$3,'production','Production','production',$4,$4)`, environmentID, organizationID, applicationID, now); err != nil {
		t.Fatal(err)
	}
	status, body = serveReadiness(t, pool, checks)
	if status != http.StatusServiceUnavailable || readinessCheck(body, "active_configuration") != "unavailable" {
		t.Fatalf("missing active config status=%d body=%v", status, body)
	}

	failing := ReadinessChecks{
		QuotaCompletionPool: func(context.Context) error { return errors.New("private completion pool detail") },
		MasterKey:           func(context.Context) error { return errors.New("secret plaintext must not appear") },
		SigningKey:          func(context.Context) error { return errors.New("private signing bytes") },
		WorkerHeartbeat:     func(context.Context) error { return errors.New("worker host detail") },
	}
	status, body = serveReadiness(t, pool, failing)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("dependency failure status=%d", status)
	}
	for _, name := range []string{"quota_completion_pool", "master_key", "signing_key", "worker_heartbeat"} {
		if readinessCheck(body, name) != "unavailable" {
			t.Fatalf("%s check=%v", name, body)
		}
	}
	encoded, _ := json.Marshal(body)
	for _, private := range []string{"private completion", "secret plaintext", "private signing", "worker host"} {
		if regexp.MustCompile(private).Match(encoded) {
			t.Fatalf("readiness disclosed dependency detail: %s", encoded)
		}
	}

	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = (SELECT max(version) FROM schema_migrations)`); err != nil {
		t.Fatal(err)
	}
	status, body = serveReadiness(t, pool, checks)
	if status != http.StatusServiceUnavailable || readinessCheck(body, "schema") != "incompatible" {
		t.Fatalf("schema mismatch status=%d body=%v", status, body)
	}
}

func TestReadinessChecksDistinctCompletionPoolAvailableClosedAndFullyAcquiredPostgreSQL(t *testing.T) {
	pool, ctx := isolatedReadinessPool(t)
	baseChecks := ReadinessChecks{
		MasterKey:       func(context.Context) error { return nil },
		SigningKey:      func(context.Context) error { return nil },
		WorkerHeartbeat: func(context.Context) error { return nil },
	}

	available := newReadinessCompletionPool(t, ctx, pool)
	checks := baseChecks
	checks.QuotaCompletionPool = available.Ping
	status, body := serveReadiness(t, pool, checks)
	if status != http.StatusOK || body["status"] != "ready" ||
		readinessCheck(body, "quota_completion_pool") != "ok" {
		t.Fatalf("available completion pool status=%d body=%v", status, body)
	}

	available.Close()
	status, body = serveReadiness(t, pool, checks)
	if status != http.StatusServiceUnavailable || body["status"] != "not_ready" ||
		readinessCheck(body, "quota_completion_pool") != "unavailable" {
		t.Fatalf("closed completion pool status=%d body=%v", status, body)
	}
	closedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?i)closed|private completion`).Match(closedBody) {
		t.Fatalf("closed completion readiness disclosed dependency detail: %s", closedBody)
	}

	full := newReadinessCompletionPool(t, ctx, pool)
	held, err := full.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(held.Release)
	checks = baseChecks
	checks.QuotaCompletionPool = full.Ping
	status, body = serveReadiness(t, pool, checks)
	if status != http.StatusServiceUnavailable || body["status"] != "not_ready" ||
		readinessCheck(body, "quota_completion_pool") != "unavailable" {
		t.Fatalf("fully acquired completion pool status=%d body=%v", status, body)
	}
	for _, name := range []string{"database", "schema", "active_configuration", "master_key", "signing_key", "worker_heartbeat"} {
		if readinessCheck(body, name) != "ok" {
			t.Fatalf("fully acquired completion pool cascaded into %s: %v", name, body)
		}
	}
}

func serveReadiness(t *testing.T, pool *pgxpool.Pool, checks ReadinessChecks) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	readinessHandler(pool, checks).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return recorder.Code, body
}

func readinessCheck(body map[string]any, name string) string {
	checks, _ := body["checks"].(map[string]any)
	value, _ := checks[name].(string)
	return value
}

func newReadinessCompletionPool(t *testing.T, ctx context.Context, primary *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	config := primary.Config()
	config.MaxConns = 1
	config.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func isolatedReadinessPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("latchway_readiness_test_%d", time.Now().UnixNano())
	if !readinessSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsed.String(), 6)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func mustReadinessID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
