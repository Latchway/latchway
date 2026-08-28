package database

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigratorPostgreSQLEmbeddingsZeroOutputPreflightFreshAndUpgrade(t *testing.T) {
	for _, test := range []struct {
		name    string
		upgrade bool
	}{
		{name: "fresh"},
		{name: "upgrade from 15", upgrade: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, pool := newPostgreSQLIntegrationPool(t)
			if test.upgrade {
				applyMigrationsThrough(t, ctx, pool, 15)
			} else {
				migrator := NewMigrator(pool)
				if err := migrator.Up(ctx); err != nil {
					t.Fatal(err)
				}
			}
			seedQuotaMigrationTenant(t, ctx, pool)
			seedQuotaMigrationRequestDependencies(t, ctx, pool)

			chat := quotaAttemptAccountingIDs(160)
			insertZeroOutputMigrationLogicalRequest(t, ctx, pool, chat.logicalRequestID, "openai_chat")
			insertZeroOutputMigrationAttempt(t, ctx, pool, chat.attemptID, chat.logicalRequestID, 7, 18)

			embeddings := quotaAttemptAccountingIDs(161)
			insertZeroOutputMigrationLogicalRequest(t, ctx, pool, embeddings.logicalRequestID, "openai_embeddings")
			if test.upgrade {
				_, err := pool.Exec(ctx, zeroOutputMigrationAttemptSQL,
					embeddings.attemptID, embeddings.logicalRequestID, int64(0), int64(11))
				expectPostgreSQLConstraintError(
					t, err, "23514", "upstream_attempts_input_accounting_binding_check",
				)
				migrator := NewMigrator(pool)
				if err := migrator.Up(ctx); err != nil {
					t.Fatal(err)
				}
			}
			insertZeroOutputMigrationAttempt(t, ctx, pool,
				embeddings.attemptID, embeddings.logicalRequestID, 0, 11)

			migrator := NewMigrator(pool)
			current, available, err := migrator.Status(ctx)
			if err != nil || current != 16 || available != 16 {
				t.Fatalf("schema current=%d available=%d err=%v", current, available, err)
			}
			var chatOutput, embeddingsOutput, embeddingsTotal int64
			if err := pool.QueryRow(ctx, `
				SELECT
					(SELECT output_token_bound FROM upstream_attempts WHERE upstream_attempt_id = $1),
					(SELECT output_token_bound FROM upstream_attempts WHERE upstream_attempt_id = $2),
					(SELECT total_token_bound FROM upstream_attempts WHERE upstream_attempt_id = $2)
			`, chat.attemptID, embeddings.attemptID).Scan(
				&chatOutput, &embeddingsOutput, &embeddingsTotal,
			); err != nil {
				t.Fatalf("read migrated proof bounds: %v", err)
			}
			if chatOutput != 7 || embeddingsOutput != 0 || embeddingsTotal != 11 {
				t.Fatalf("migrated proof bounds = chat:%d embeddings:%d/%d, want 7 and 0/11",
					chatOutput, embeddingsOutput, embeddingsTotal)
			}

			_, err = pool.Exec(ctx, `
				UPDATE upstream_attempts
				SET output_token_bound = -1, total_token_bound = input_token_bound - 1
				WHERE upstream_attempt_id = $1
			`, embeddings.attemptID)
			expectPostgreSQLConstraintError(
				t, err, "23514", "upstream_attempts_input_accounting_binding_check",
			)
			_, err = pool.Exec(ctx, `
				UPDATE upstream_attempts
				SET total_token_bound = input_token_bound + output_token_bound + 1
				WHERE upstream_attempt_id = $1
			`, embeddings.attemptID)
			expectPostgreSQLConstraintError(
				t, err, "23514", "upstream_attempts_input_accounting_binding_check",
			)
		})
	}
}

func insertZeroOutputMigrationLogicalRequest(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logicalRequestID, protocol string,
) {
	t.Helper()
	if err := insertQuotaMigrationLogicalRequest(ctx, pool, logicalRequestID, "structured-proof"); err != nil {
		t.Fatalf("insert structured-proof logical request: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests SET protocol = $2 WHERE logical_request_id = $1
	`, logicalRequestID, protocol); err != nil {
		t.Fatalf("set structured-proof protocol: %v", err)
	}
}

const zeroOutputMigrationAttemptSQL = `
	INSERT INTO upstream_attempts (
		upstream_attempt_id, organization_id, application_id, environment_id,
		logical_request_id, attempt_number, route_key, upstream_key,
		physical_model, model_key, attempt_decision_binding_version,
		attempt_decision_sha256, input_accounting_binding_version,
		input_accounting_method, input_accounting_profile_id,
		input_accounting_profile_digest, rewritten_body_sha256,
		input_token_bound, output_token_bound, total_token_bound, status
	) VALUES (
		$1, '` + quotaMigrationOrganizationID + `', '` + quotaMigrationApplicationID + `',
		'` + quotaMigrationEnvironmentID + `', $2, 1, 'primary', 'provider',
		'provider/model-v1', 'model-v1', 1, decode(repeat('22', 32), 'hex'), 1,
		'utf8_byte_bpe_declared_framing_v1', 'structured-profile',
		decode(repeat('33', 32), 'hex'), decode(repeat('44', 32), 'hex'),
		11, $3, $4, 'started'
	)
`

func insertZeroOutputMigrationAttempt(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	attemptID, logicalRequestID string,
	outputBound, totalBound int64,
) {
	t.Helper()
	if _, err := pool.Exec(ctx, zeroOutputMigrationAttemptSQL,
		attemptID, logicalRequestID, outputBound, totalBound); err != nil {
		t.Fatalf("insert structured-proof attempt: %v", err)
	}
}
