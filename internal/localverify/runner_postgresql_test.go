package localverify

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/database"
)

func TestRunPostgreSQLV1Vertical(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("LATCHWAY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report := Run(ctx, Config{DatabaseURL: databaseURL, Timeout: 90 * time.Second})
	if err := report.Error(); err != nil {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		t.Fatalf("Run() error = %v\n%s", err, encoded)
	}

	wantNames := []string{
		"database_connectivity",
		"isolated_migrations",
		"ephemeral_tenant",
		"mock_services",
		"configuration_activation",
		"runtime_composition",
		"oidc_debug_dpop_session",
		"non_streaming",
		"streaming",
		"usage_accounting",
		"dpop_replay",
		"request_quota",
		"output_quota_and_clamp",
		"token_bucket_refill",
		"concurrency",
		"fallback_attempt_accounting",
		"crash_reclaim",
		"credential_header_stripping",
		"ssrf_defense",
		"configuration_rollback",
		"ephemeral_cleanup",
	}
	gotNames := make([]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		gotNames = append(gotNames, check.Name)
		if check.State != "passed" {
			t.Fatalf("check %q state = %q, want passed", check.Name, check.State)
		}
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("check names = %v, want %v", gotNames, wantNames)
	}
	first, err := report.MarshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	second, err := report.MarshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("JUnit evidence changed for one immutable report")
	}
}

func TestCleanupPostgreSQLDropsPartiallyInitializedSchema(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("LATCHWAY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := &fixture{databaseURL: databaseURL}
	defer func() { _ = f.cleanup() }()
	if err := f.connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.isolateAndMigrate(ctx); err != nil {
		t.Fatal(err)
	}
	checkPool, err := database.Open(ctx, databaseURL, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer checkPool.Close()
	var exists bool
	if err := checkPool.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
		f.schema,
	).Scan(&exists); err != nil || !exists {
		t.Fatalf("isolated schema existence = %t, error = %v", exists, err)
	}
	if err := f.cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := checkPool.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
		f.schema,
	).Scan(&exists); err != nil || exists {
		t.Fatalf("isolated schema existence after cleanup = %t, error = %v", exists, err)
	}
}
