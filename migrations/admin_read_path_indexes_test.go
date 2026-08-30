package migrations

import (
	"strings"
	"testing"
)

func TestAdminReadPathIndexesMigrationIsAdditiveAndTransactionCompatible(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000014_admin_read_path_indexes.sql")
	if err != nil {
		t.Fatalf("read Admin read-path migration: %v", err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"create index installations_admin_list_idx",
		"on installations (organization_id, environment_id, created_at, installation_id)",
		"create index logical_requests_admin_list_idx",
		"on logical_requests (organization_id, environment_id, requested_at, logical_request_id)",
		"create index upstream_attempts_admin_request_idx",
		"on upstream_attempts (organization_id, logical_request_id, attempt_number)",
		"create index usage_records_admin_request_idx",
		"on usage_records (organization_id, logical_request_id, recorded_at, usage_record_id)",
		"create index usage_records_admin_time_idx",
		"on usage_records (organization_id, environment_id, recorded_at, usage_record_id)",
		"create index audit_events_admin_list_idx",
		"on audit_events (organization_id, occurred_at desc, audit_event_id desc)",
		"create index jobs_admin_self_test_result_idx",
		"where job_type = 'run_scheduled_self_test'",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("Admin read-path migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"create index concurrently",
		"drop table",
		"drop index",
		"delete from",
		"truncate",
		"alter table",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("Admin read-path migration contains forbidden operation %q", forbidden)
		}
	}
}
