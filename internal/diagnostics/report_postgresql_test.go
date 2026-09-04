package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
)

var completionDiagnosticSchemaPattern = regexp.MustCompile(`^latchway_diagnostic_completion_[0-9]+$`)

func TestDoctorProbesDistinctCompletionPoolAvailableClosedAndFullyAcquiredPostgreSQL(t *testing.T) {
	regular, ctx := isolatedCompletionDiagnosticPool(t)

	available := newCompletionDiagnosticPool(t, ctx, regular)
	report := Run(ctx, regular, "all", Dependencies{CompletionPool: available})
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_connectivity"); got != CheckPassed {
		t.Fatalf("available completion connectivity = %q", got)
	}
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_saturation"); got != CheckPassed {
		t.Fatalf("available completion saturation = %q", got)
	}
	if report.Facts.Database.PoolMaximum != 7 {
		t.Fatalf("aggregate pool maximum = %d, want 7", report.Facts.Database.PoolMaximum)
	}

	available.Close()
	report = Run(ctx, regular, "all", Dependencies{CompletionPool: available})
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_connectivity"); got != CheckFailed {
		t.Fatalf("closed completion connectivity = %q", got)
	}
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_saturation"); got != CheckFailed {
		t.Fatalf("closed completion saturation = %q", got)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "closed") {
		t.Fatalf("doctor disclosed closed-pool dependency detail: %s", encoded)
	}

	full := newCompletionDiagnosticPool(t, ctx, regular)
	held, err := full.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(held.Release)
	report = Run(ctx, regular, "all", Dependencies{CompletionPool: full})
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_connectivity"); got != CheckFailed {
		t.Fatalf("fully acquired completion connectivity = %q", got)
	}
	if got := checkStateByID(t, report.Checks, "quota_completion_pool_saturation"); got != CheckFailed {
		t.Fatalf("fully acquired completion saturation = %q", got)
	}
	if got := checkStateByID(t, report.Checks, "database_connectivity"); got != CheckPassed {
		t.Fatalf("completion saturation cascaded into regular connectivity = %q", got)
	}
}

func isolatedCompletionDiagnosticPool(t *testing.T) (*pgxpool.Pool, context.Context) {
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
	schema := fmt.Sprintf("latchway_diagnostic_completion_%d", time.Now().UnixNano())
	if !completionDiagnosticSchemaPattern.MatchString(schema) {
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

func newCompletionDiagnosticPool(t *testing.T, ctx context.Context, primary *pgxpool.Pool) *pgxpool.Pool {
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
