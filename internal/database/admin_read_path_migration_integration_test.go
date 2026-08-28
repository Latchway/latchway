package database

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigratorPostgreSQLUpgradeV13AdminReadPathIndexes(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 13)

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("upgrade through Admin read-path indexes: %v", err)
	}
	current, available, err := migrator.Status(ctx)
	if err != nil || current != 15 || available != 15 {
		t.Fatalf("migration status current=%d available=%d err=%v", current, available, err)
	}

	for _, index := range []string{
		"installations_admin_list_idx",
		"logical_requests_admin_list_idx",
		"upstream_attempts_admin_request_idx",
		"usage_records_admin_request_idx",
		"usage_records_admin_time_idx",
		"audit_events_admin_list_idx",
		"jobs_admin_self_test_result_idx",
	} {
		assertAdminReadPathIndex(t, ctx, pool, index)
	}
}

func assertAdminReadPathIndex(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	indexName string,
) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_indexes
			WHERE schemaname = current_schema() AND indexname = $1
		)
	`, indexName).Scan(&exists); err != nil {
		t.Fatalf("read index %s: %v", indexName, err)
	}
	if !exists {
		t.Errorf("Admin read-path index %s was not created", indexName)
	}
}
