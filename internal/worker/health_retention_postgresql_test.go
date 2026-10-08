package worker

import (
	"testing"
	"time"
)

func TestRetentionDeletesOnlyExpiredHealthSamplesPostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	now := time.Now().UTC().Truncate(5 * time.Minute)
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_health_samples (sampled_at, overall_state, failed_checks, warning_checks, recorded_by_role)
		VALUES ($1, 'healthy', '{}', '{}', 'worker'), ($2, 'degraded', '{}', '{database_latency}', 'worker')
	`, now.Add(-31*24*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	operations, err := NewPostgreSQLOperations(pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operations.EnforceRetention(ctx, now, 10); err != nil {
		t.Fatal(err)
	}
	var remaining []time.Time
	rows, err := pool.Query(ctx, `SELECT sampled_at FROM system_health_samples ORDER BY sampled_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var sampledAt time.Time
		if err := rows.Scan(&sampledAt); err != nil {
			t.Fatal(err)
		}
		remaining = append(remaining, sampledAt)
	}
	if len(remaining) != 1 || !remaining[0].Equal(now.Add(-time.Hour)) {
		t.Fatalf("remaining health samples = %v", remaining)
	}
}
