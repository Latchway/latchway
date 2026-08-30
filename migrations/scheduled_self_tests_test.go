package migrations

import (
	"strings"
	"testing"
)

func TestScheduledSelfTestsMigrationPinsAuthorizationTargetsAndBudgets(t *testing.T) {
	contents, err := Files.ReadFile("000019_scheduled_self_tests.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, required := range []string{
		"CREATE TABLE self_test_schedules",
		"authorization_method text NOT NULL CHECK (authorization_method = 'api_token')",
		"authorization_credential_id text NOT NULL",
		"config_revision_id text NOT NULL",
		"daily_cost_limit_nano_usd bigint NOT NULL",
		"interval_seconds BETWEEN 3600 AND 2592000",
		"CREATE TABLE self_test_schedule_secret_bindings",
		"secret_record_id text NOT NULL",
		"secret_version bigint NOT NULL",
		"FOREIGN KEY (self_test_schedule_id, organization_id, application_id, environment_id)",
		"CREATE TABLE scheduled_self_test_runs",
		"status text NOT NULL CHECK (status IN ('dispatching', 'completed'))",
		"scheduled_self_test_runs_budget_idx",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("scheduled self-test migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{"DROP TABLE", "DROP COLUMN", "DELETE FROM", "UPDATE jobs"} {
		if strings.Contains(strings.ToUpper(sql), forbidden) {
			t.Errorf("scheduled self-test migration contains backward-incompatible operation %q", forbidden)
		}
	}
}
