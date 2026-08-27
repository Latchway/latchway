package database

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var integrationSchemaPattern = regexp.MustCompile(`\Alatchway_test_[0-9]+\z`)

func TestMigratorPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer adminPool.Close()

	schema := fmt.Sprintf("latchway_test_%d", time.Now().UnixNano())
	if !integrationSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	pool, err := Open(ctx, parsed.String(), 4)
	if err != nil {
		t.Fatalf("open isolated pool: %v", err)
	}
	defer pool.Close()

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("idempotent migration run: %v", err)
	}
	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatalf("migration status: %v", err)
	}
	if current != available || available == 0 {
		t.Fatalf("schema versions current=%d available=%d", current, available)
	}
}
