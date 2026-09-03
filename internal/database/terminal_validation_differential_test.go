package database

import (
	"context"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/migrations"
)

// These tiny isolated tables exercise the function's exact relational/NULL
// semantics, including defensive branches unreachable through current CHECKs.
// They do not replace the real-schema migration and quota integration suites,
// and no production constraint or trigger is disabled to create a test case.
const terminalValidationTables = `
CREATE TABLE logical_requests (
    organization_id text, application_id text, environment_id text,
    logical_request_id text PRIMARY KEY, status text
);
CREATE TABLE quota_reservations (
    organization_id text, application_id text, environment_id text,
    logical_request_id text, quota_reservation_id text PRIMARY KEY, status text,
    UNIQUE (organization_id, application_id, environment_id, logical_request_id)
);
CREATE TABLE quota_buckets (
    organization_id text, application_id text, environment_id text,
    quota_bucket_id text PRIMARY KEY, metric text
);
CREATE TABLE quota_reservation_entries (
    organization_id text, application_id text, environment_id text,
    quota_reservation_id text, quota_reservation_entry_id text,
    quota_bucket_id text, origin_attempt_number integer,
    initial_reserved_units bigint, settled_units bigint, released_units bigint
);
CREATE TABLE upstream_attempt_quota_entries (
    organization_id text, application_id text, environment_id text,
    logical_request_id text, upstream_attempt_id text, quota_reservation_id text,
    quota_reservation_entry_id text, quota_bucket_id text, metric text,
    allocated_units bigint, charged_units bigint, released_units bigint, settled_at timestamptz,
    PRIMARY KEY (environment_id, upstream_attempt_id, quota_reservation_entry_id)
);
CREATE TABLE upstream_attempts (
    organization_id text, application_id text, environment_id text,
    logical_request_id text, upstream_attempt_id text PRIMARY KEY,
    attempt_number integer, attempt_decision_binding_version integer,
    status text, completed_at timestamptz
);
`

const terminalValidationSeed = `
INSERT INTO logical_requests VALUES ('o','a','e','request','succeeded');
INSERT INTO quota_reservations VALUES ('o','a','e','request','reservation','settled');
INSERT INTO quota_buckets VALUES ('o','a','e','bucket','output_tokens');
INSERT INTO quota_reservation_entries VALUES ('o','a','e','reservation','entry','bucket',1,7,5,2);
INSERT INTO upstream_attempt_quota_entries VALUES
    ('o','a','e','request','attempt','reservation','entry','bucket','output_tokens',7,5,2,'2026-09-03T00:00:00Z');
INSERT INTO upstream_attempts VALUES ('o','a','e','request','attempt',1,2,'started',NULL);
`

const terminalValidationSecondEntry = `
INSERT INTO quota_buckets VALUES ('o','a','e','bucket2','input_tokens');
INSERT INTO quota_reservation_entries VALUES ('o','a','e','reservation','entry2','bucket2',1,7,5,2);
`

const terminalValidationSecondLedger = `
INSERT INTO upstream_attempt_quota_entries VALUES
    ('o','a','e','request','attempt','reservation','entry2','bucket2','input_tokens',7,5,2,'2026-09-03T00:00:00Z');
`

const terminalValidationUnsettled = `
UPDATE upstream_attempt_quota_entries SET charged_units=NULL,released_units=NULL,settled_at=NULL;
`

const terminalValidationForeignRows = `
INSERT INTO quota_reservations VALUES ('foreign','a','e','request','foreign-reservation','pending');
INSERT INTO quota_buckets VALUES ('foreign','a','e','foreign-bucket','output_tokens');
INSERT INTO quota_reservation_entries VALUES ('foreign','a','e','foreign-reservation','foreign-entry','foreign-bucket',1,99,1,98);
INSERT INTO upstream_attempt_quota_entries VALUES
    ('foreign','a','e','request','attempt','foreign-reservation','foreign-entry','foreign-bucket','output_tokens',99,1,98,'2026-09-02T00:00:00Z'),
    ('o','a','e','foreign-request','attempt','reservation','foreign-request-entry','bucket','input_tokens',88,2,86,'2026-09-02T00:00:00Z'),
    ('o','a','e','request','foreign-attempt','reservation','foreign-attempt-entry','bucket','input_tokens',77,3,74,'2026-09-02T00:00:00Z');
`

type terminalValidationCase struct {
	nullEventTime                                   bool
	name, mutation, status, afterEvent, wantMessage string
	wantRows                                        int
}

func terminalValidationCases() []terminalValidationCase {
	const incomplete = "legacy terminal attempt ledger is incomplete"
	const binding = "legacy terminal attempt ledger has invalid allocation binding"
	const lifecycle = "settled legacy attempt has incoherent aggregate lifecycle"
	const disagreement = "legacy terminal attempt ledger disagrees with reservation"
	const legacy = "legacy terminal attempt requires coherent terminal reservation"
	return []terminalValidationCase{
		{name: "one modern settled allocation", wantRows: 1},
		{name: "multiple modern settled allocations", mutation: terminalValidationSecondEntry + terminalValidationSecondLedger, wantRows: 2},
		{name: "zero ledger coherent", mutation: "DELETE FROM upstream_attempt_quota_entries; DELETE FROM quota_reservation_entries;", wantRows: 0},
		{name: "zero ledger incoherent", mutation: "DELETE FROM upstream_attempt_quota_entries; DELETE FROM quota_reservation_entries; UPDATE logical_requests SET status='failed';", wantMessage: lifecycle},
		{name: "missing ledger", mutation: "DELETE FROM upstream_attempt_quota_entries;", wantMessage: incomplete},
		{name: "surplus noneligible ledger", mutation: terminalValidationSecondEntry + terminalValidationSecondLedger + "UPDATE quota_buckets SET metric='logical_requests' WHERE quota_bucket_id='bucket2';", wantMessage: incomplete},
		{name: "mixed settled and unsettled", mutation: terminalValidationSecondEntry + terminalValidationSecondLedger + "UPDATE upstream_attempt_quota_entries SET charged_units=NULL,released_units=NULL,settled_at=NULL WHERE quota_reservation_entry_id='entry2';", wantMessage: incomplete},
		{name: "wrong metric", mutation: "UPDATE upstream_attempt_quota_entries SET metric='input_tokens';", wantMessage: binding},
		{name: "wrong initial allocation", mutation: "UPDATE quota_reservation_entries SET initial_reserved_units=8;", wantMessage: binding},
		{name: "wrong origin with balanced counts", mutation: "UPDATE quota_reservation_entries SET origin_attempt_number=2;" + terminalValidationSecondEntry, wantMessage: binding},
		{name: "excluded nonledger entry", mutation: terminalValidationSecondEntry + "UPDATE quota_buckets SET metric='logical_requests' WHERE quota_bucket_id='bucket2';", wantRows: 1},
		{name: "excluded retry origin entry", mutation: terminalValidationSecondEntry + "UPDATE quota_reservation_entries SET origin_attempt_number=2 WHERE quota_reservation_entry_id='entry2';", wantRows: 1},
		{name: "zero valued cost", mutation: "UPDATE quota_buckets SET metric='cost_nano_usd'; UPDATE quota_reservation_entries SET initial_reserved_units=0,settled_units=0,released_units=0; UPDATE upstream_attempt_quota_entries SET metric='cost_nano_usd',allocated_units=0,charged_units=0,released_units=0;", wantRows: 1},
		{name: "internally derived attempt metric", mutation: "UPDATE quota_buckets SET metric='upstream_attempts'; UPDATE upstream_attempt_quota_entries SET metric='upstream_attempts';", wantRows: 1},
		{name: "charged mismatch", mutation: "UPDATE quota_reservation_entries SET settled_units=4;", wantMessage: disagreement},
		{name: "released mismatch", mutation: "UPDATE quota_reservation_entries SET released_units=1;", wantMessage: disagreement},
		{name: "timestamp mismatch", mutation: "UPDATE upstream_attempt_quota_entries SET settled_at=settled_at+interval '1 second';", wantMessage: disagreement},
		{name: "nullable settled units retain SQL unknown", mutation: "UPDATE quota_reservation_entries SET settled_units=NULL;", wantRows: 1},
		{name: "nullable released units retain SQL unknown", mutation: "UPDATE quota_reservation_entries SET released_units=NULL;", wantRows: 1},
		{name: "nullable initial units retain SQL unknown", mutation: "UPDATE quota_reservation_entries SET initial_reserved_units=NULL;", wantRows: 1},
		{name: "missing aggregate status", mutation: "DELETE FROM logical_requests;", wantMessage: lifecycle},
		{name: "null aggregate status", mutation: "UPDATE logical_requests SET status=NULL;", wantMessage: lifecycle},
		{name: "pending failed attempt", status: "failed", mutation: "UPDATE quota_reservations SET status='pending'; UPDATE logical_requests SET status='dispatched';", wantRows: 1},
		{name: "pending timed out attempt", status: "timed_out", mutation: "UPDATE quota_reservations SET status='pending'; UPDATE logical_requests SET status='streaming';", wantRows: 1},
		{name: "pending success rejected", mutation: "UPDATE quota_reservations SET status='pending'; UPDATE logical_requests SET status='streaming';", wantMessage: lifecycle},
		{name: "settled failed attempt", status: "failed", mutation: "UPDATE logical_requests SET status='failed';", wantRows: 1},
		{name: "settled timed out attempt", status: "timed_out", mutation: "UPDATE logical_requests SET status='failed';", wantRows: 1},
		{name: "settled cancelled attempt", status: "cancelled", mutation: "UPDATE logical_requests SET status='cancelled';", wantRows: 1},
		{name: "legacy all unsettled repair", mutation: terminalValidationUnsettled, wantRows: 1},
		{name: "legacy multiple repair", mutation: terminalValidationSecondEntry + terminalValidationSecondLedger + terminalValidationUnsettled, wantRows: 2},
		{name: "legacy incoherent aggregate", mutation: terminalValidationUnsettled + "UPDATE logical_requests SET status='failed';", wantMessage: legacy},
		{name: "legacy partial row actual update count", mutation: "UPDATE upstream_attempt_quota_entries SET charged_units=NULL;", wantMessage: "legacy terminal attempt ledger update is incomplete"},
		{name: "legacy suppressed update actual rowcount", mutation: terminalValidationUnsettled + `
CREATE FUNCTION terminal_test_skip_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
CREATE TRIGGER terminal_test_skip BEFORE UPDATE ON upstream_attempt_quota_entries FOR EACH ROW EXECUTE FUNCTION terminal_test_skip_update();
`, wantMessage: "legacy terminal attempt ledger update is incomplete"},
		{name: "topology precedes binding", mutation: terminalValidationSecondEntry + "UPDATE upstream_attempt_quota_entries SET metric='input_tokens';", wantMessage: incomplete},
		{name: "binding precedes lifecycle", mutation: "UPDATE upstream_attempt_quota_entries SET metric='input_tokens'; UPDATE logical_requests SET status='failed';", wantMessage: binding},
		{name: "lifecycle precedes settlement mismatch", mutation: "UPDATE logical_requests SET status='failed'; UPDATE quota_reservation_entries SET settled_units=4;", wantMessage: lifecycle},
		{name: "deferred event timestamp not current row", afterEvent: "UPDATE upstream_attempts SET completed_at=completed_at+interval '1 second';", wantRows: 1},
		{name: "deferred trigger legacy v0", mutation: "UPDATE upstream_attempts SET attempt_decision_binding_version=0;" + terminalValidationUnsettled, wantRows: 1},
		{name: "missing bucket still checks settlement", mutation: "DELETE FROM quota_buckets;" + terminalValidationSecondEntry + "UPDATE quota_reservation_entries SET settled_units=4 WHERE quota_reservation_entry_id='entry';", wantMessage: disagreement},
		{name: "missing bucket binding join stays excluded", mutation: "DELETE FROM quota_buckets;" + terminalValidationSecondEntry, wantRows: 1},
		{name: "missing bucket excludes mismatched allocation binding", mutation: "DELETE FROM quota_buckets;" + terminalValidationSecondEntry + "UPDATE upstream_attempt_quota_entries SET allocated_units=99;", wantRows: 1},
		{name: "duplicate synthetic expected join", mutation: "INSERT INTO quota_reservation_entries SELECT * FROM quota_reservation_entries;", wantMessage: incomplete},
		{name: "duplicate synthetic binding join with balanced counts", mutation: "INSERT INTO quota_reservation_entries SELECT organization_id,application_id,environment_id,quota_reservation_id,quota_reservation_entry_id,quota_bucket_id,2,initial_reserved_units,settled_units,released_units FROM quota_reservation_entries;", wantMessage: binding},
		{name: "zero ledger absent aggregate", mutation: "DELETE FROM upstream_attempt_quota_entries; DELETE FROM quota_reservation_entries; DELETE FROM quota_reservations;", wantMessage: lifecycle},
		{name: "null event time retains distinct comparison", nullEventTime: true, wantMessage: disagreement},
		{name: "modern later attempt firing scope unchanged", mutation: "UPDATE upstream_attempts SET attempt_number=2; UPDATE upstream_attempt_quota_entries SET metric='input_tokens';", wantRows: 1},
		{name: "foreign tenant request and attempt rows ignored", mutation: terminalValidationForeignRows, wantRows: 4},
		{name: "legacy repair preserves foreign rows", mutation: terminalValidationUnsettled + terminalValidationForeignRows, wantRows: 4},
	}
}

func terminalValidationSources(t *testing.T) (string, string, string) {
	t.Helper()
	read := func(name string) string {
		t.Helper()
		contents, err := migrations.Files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(contents)
	}
	original := read("000028_attempt_quota_policy.sql")
	start := strings.Index(original, "CREATE OR REPLACE FUNCTION latchway_schema12_attempt_terminal_compat()")
	if start < 0 {
		t.Fatal("missing original terminal function")
	}
	original = original[start:]
	end := strings.Index(original, "$$;")
	if end < 0 {
		t.Fatal("missing original function terminator")
	}
	original = original[:end+3]
	trigger := read("000012_upstream_attempt_accounting.sql")
	start = strings.Index(trigger, "CREATE CONSTRAINT TRIGGER upstream_attempts_schema11_terminal_compat")
	if start < 0 {
		t.Fatal("missing original terminal trigger")
	}
	return original, read("000029_attempt_terminal_validation.sql"), trigger[start:]
}

type terminalLedgerProjection struct {
	Metric            string
	Allocated         int64
	Charged, Released *int64
	Settled           *time.Time
}

type terminalValidationOutcome struct {
	Code, Message string
	Rows          []terminalLedgerProjection
}

func TestPostgreSQLTerminalValidationDifferential(t *testing.T) {
	if os.Getenv("LATCHWAY_TEST_DATABASE_URL") == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	for _, protocol := range []string{"cache_statement", "simple_protocol"} {
		t.Run(protocol, func(t *testing.T) {
			connection, err := url.Parse(os.Getenv("LATCHWAY_TEST_DATABASE_URL"))
			if err != nil {
				t.Fatal("invalid test database connection")
			}
			query := connection.Query()
			query.Set("default_query_exec_mode", protocol)
			connection.RawQuery = query.Encode()
			t.Setenv("LATCHWAY_TEST_DATABASE_URL", connection.String())
			ctx, pool := newPostgreSQLIntegrationPool(t)
			original, candidate, trigger := terminalValidationSources(t)
			if _, err := pool.Exec(ctx, terminalValidationTables+original+trigger); err != nil {
				t.Fatalf("create isolated semantic fixture: %v", err)
			}
			for _, test := range terminalValidationCases() {
				t.Run(test.name, func(t *testing.T) {
					before := runTerminalValidationCase(t, ctx, pool, original, test, false)
					after := runTerminalValidationCase(t, ctx, pool, candidate, test, false)
					if !reflect.DeepEqual(before, after) {
						t.Fatalf("candidate diverged from original: before=%#v after=%#v", before, after)
					}
				})
			}
			// Real COMMIT, not just SET CONSTRAINTS, proves deferred success,
			// compatibility repair, event NEW semantics, and commit-time rollback.
			for _, name := range []string{"one modern settled allocation", "legacy all unsettled repair", "wrong metric", "deferred event timestamp not current row"} {
				var test terminalValidationCase
				for _, candidate := range terminalValidationCases() {
					if candidate.name == name {
						test = candidate
						break
					}
				}
				if test.name == "" {
					t.Fatalf("missing named COMMIT case %q", name)
				}
				t.Run("commit/"+test.name, func(t *testing.T) {
					before := runTerminalValidationCase(t, ctx, pool, original, test, true)
					after := runTerminalValidationCase(t, ctx, pool, candidate, test, true)
					if !reflect.DeepEqual(before, after) {
						t.Fatal("COMMIT result diverged from original")
					}
				})
			}
		})
	}
}

func runTerminalValidationCase(t *testing.T, ctx context.Context, pool *pgxpool.Pool, function string, test terminalValidationCase, commit bool) terminalValidationOutcome {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("begin terminal validation trial")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	for _, statement := range []string{function, terminalValidationSeed, test.mutation} {
		if statement == "" {
			continue
		}
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare terminal validation trial: %v", err)
		}
	}
	status := test.status
	if status == "" {
		status = "succeeded"
	}
	eventTime := "'2026-09-03T00:00:00Z'"
	if test.nullEventTime {
		eventTime = "NULL"
	}
	if _, err := tx.Exec(ctx, "UPDATE upstream_attempts SET status=$1, completed_at="+eventTime, status); err != nil {
		t.Fatalf("queue deferred terminal event: %v", err)
	}
	if test.afterEvent != "" {
		if _, err := tx.Exec(ctx, test.afterEvent); err != nil {
			t.Fatal("prepare deferred event mutation")
		}
	}
	var deferred bool
	if err := tx.QueryRow(ctx, `SELECT tgdeferrable AND tginitdeferred FROM pg_trigger WHERE tgrelid='upstream_attempts'::regclass AND tgname='upstream_attempts_schema11_terminal_compat'`).Scan(&deferred); err != nil || !deferred {
		t.Fatal("terminal trigger is no longer initially deferred")
	}
	if commit {
		err = tx.Commit(ctx)
	} else {
		_, err = tx.Exec(ctx, "SET CONSTRAINTS upstream_attempts_schema11_terminal_compat IMMEDIATE")
	}
	result := terminalValidationOutcome{}
	if err != nil {
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) {
			t.Fatal("terminal validation did not return a PostgreSQL error")
		}
		result.Code, result.Message = pgError.Code, pgError.Message
	}
	if test.wantMessage != result.Message || (test.wantMessage != "" && result.Code != "23514") {
		t.Fatalf("terminal outcome code=%q message=%q, want 23514/%q (empty means success)", result.Code, result.Message, test.wantMessage)
	}
	if err == nil {
		const projection = `SELECT metric,allocated_units,charged_units,released_units,settled_at FROM upstream_attempt_quota_entries ORDER BY quota_reservation_entry_id`
		var rows pgx.Rows
		if commit {
			rows, err = pool.Query(ctx, projection)
		} else {
			rows, err = tx.Query(ctx, projection)
		}
		if err != nil {
			t.Fatal("read terminal projection")
		}
		for rows.Next() {
			var row terminalLedgerProjection
			if err := rows.Scan(&row.Metric, &row.Allocated, &row.Charged, &row.Released, &row.Settled); err != nil {
				rows.Close()
				t.Fatal("scan terminal projection")
			}
			result.Rows = append(result.Rows, row)
		}
		rows.Close()
		if rows.Err() != nil || len(result.Rows) != test.wantRows {
			t.Fatal("unexpected terminal projection size")
		}
	}
	if !commit {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatal("rollback terminal trial")
		}
	}
	if commit && result.Code == "" {
		// Exact private synthetic tables only; no production schema is used.
		if _, err := pool.Exec(ctx, `TRUNCATE upstream_attempt_quota_entries, upstream_attempts, quota_reservation_entries, quota_buckets, quota_reservations, logical_requests`); err != nil {
			t.Fatal("clear committed semantic trial")
		}
	}
	var remaining int64
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM upstream_attempt_quota_entries)+(SELECT count(*) FROM upstream_attempts)+(SELECT count(*) FROM quota_reservation_entries)+(SELECT count(*) FROM quota_buckets)+(SELECT count(*) FROM quota_reservations)+(SELECT count(*) FROM logical_requests)`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("terminal trial did not roll back/clean up atomically")
	}
	return result
}
