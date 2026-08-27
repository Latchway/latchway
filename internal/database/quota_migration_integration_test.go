package database

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	quotaMigrationOrganizationID = "org_00000000000000000000000001"
	quotaMigrationApplicationID  = "app_00000000000000000000000001"
	quotaMigrationEnvironmentID  = "env_00000000000000000000000001"
)

func TestMigratorPostgreSQLQuotaIdentityUpgradeFailsClosed(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 7)
	seedQuotaMigrationTenant(t, ctx, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO quota_buckets (
			quota_bucket_id, organization_id, application_id, environment_id,
			metric, scope_type, scope_key, algorithm, window_key, hard_maximum
		) VALUES (
			'qbk_00000000000000000000000001', $1, $2, $3,
			'logical_requests', 'user', 'legacy-user-value', 'calendar', '2026-08-27', 100
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID, quotaMigrationEnvironmentID); err != nil {
		t.Fatalf("insert legacy quota bucket: %v", err)
	}

	migrator := NewMigrator(pool)
	err := migrator.Up(ctx)
	expectPostgreSQLConstraintError(t, err, "23514", "")

	var versionApplied bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 8)
	`).Scan(&versionApplied); err != nil {
		t.Fatalf("read rejected quota migration status: %v", err)
	}
	if versionApplied {
		t.Fatal("quota identity migration was recorded after rejecting legacy buckets")
	}

	var newColumnPresent bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = 'quota_buckets'
			  AND column_name = 'limit_plan_key'
		)
	`).Scan(&newColumnPresent); err != nil {
		t.Fatalf("read rejected quota schema: %v", err)
	}
	if newColumnPresent {
		t.Fatal("quota bucket columns survived the rejected transactional migration")
	}

	var legacyClientIndexUnique bool
	if err := pool.QueryRow(ctx, `
		SELECT index_entry.indisunique
		FROM pg_index AS index_entry
		JOIN pg_class AS index_relation ON index_relation.oid = index_entry.indexrelid
		WHERE index_relation.oid = 'logical_requests_client_request_idx'::regclass
	`).Scan(&legacyClientIndexUnique); err != nil {
		t.Fatalf("read rolled-back client correlation index: %v", err)
	}
	if !legacyClientIndexUnique {
		t.Fatal("client correlation index change survived the rejected transactional migration")
	}

	if _, err := pool.Exec(ctx, `
		DELETE FROM quota_buckets
		WHERE quota_bucket_id = 'qbk_00000000000000000000000001'
	`); err != nil {
		t.Fatalf("remove test legacy bucket before explicit retry: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply quota identity migration after operator repair: %v", err)
	}
	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatalf("read repaired quota migration status: %v", err)
	}
	if current != 9 || available != 9 {
		t.Fatalf("schema versions after repaired upgrade current=%d available=%d", current, available)
	}
}

func TestMigratorPostgreSQLLogicalRequestFingerprintUpgrade(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 8)
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	const legacyRequestID = "req_00000000000000000000000001"
	if err := insertQuotaMigrationLogicalRequest(ctx, pool, legacyRequestID, "chat"); err != nil {
		t.Fatalf("insert legacy logical request: %v", err)
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply logical request fingerprint migration: %v", err)
	}

	var legacyFingerprint *string
	if err := pool.QueryRow(ctx, `
		SELECT trusted_decision_fingerprint
		FROM logical_requests
		WHERE logical_request_id = $1
	`, legacyRequestID).Scan(&legacyFingerprint); err != nil {
		t.Fatalf("read legacy fingerprint: %v", err)
	}
	if legacyFingerprint != nil {
		t.Fatalf("legacy fingerprint = %q, want NULL", *legacyFingerprint)
	}
	var constraintValidated bool
	if err := pool.QueryRow(ctx, `
		SELECT convalidated
		FROM pg_constraint
		WHERE conrelid = 'logical_requests'::regclass
		  AND conname = 'logical_requests_trusted_decision_fingerprint_check'
	`).Scan(&constraintValidated); err != nil {
		t.Fatalf("read fingerprint constraint validation state: %v", err)
	}
	if constraintValidated {
		t.Fatal("fingerprint constraint performed eager legacy-table validation")
	}

	const validFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests
		SET trusted_decision_fingerprint = $2
		WHERE logical_request_id = $1
	`, legacyRequestID, validFingerprint); err != nil {
		t.Fatalf("store bounded fingerprint: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, session_grant_id,
			config_revision_id, feature_key, protocol,
			trusted_decision_fingerprint, status
		) VALUES (
			'req_00000000000000000000000002', $1, $2, $3,
			'usr_00000000000000000000000001',
			'ins_00000000000000000000000001',
			'sgr_00000000000000000000000001',
			'rev_00000000000000000000000001',
			'chat', 'openai_chat', $4, 'reserved'
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID,
		quotaMigrationEnvironmentID, strings.Repeat("x", 42)); err == nil {
		t.Fatal("invalid fingerprint passed NOT VALID constraint on insert")
	} else {
		expectPostgreSQLConstraintError(
			t,
			err,
			"23514",
			"logical_requests_trusted_decision_fingerprint_check",
		)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE logical_requests
		SET trusted_decision_fingerprint = $2
		WHERE logical_request_id = $1
	`, legacyRequestID, strings.Repeat("x", 42)); err == nil {
		t.Fatal("short trusted decision fingerprint passed schema constraint")
	} else {
		expectPostgreSQLConstraintError(
			t,
			err,
			"23514",
			"logical_requests_trusted_decision_fingerprint_check",
		)
	}

	current, available, err := migrator.Status(ctx)
	if err != nil {
		t.Fatalf("read fingerprint migration status: %v", err)
	}
	if current != 9 || available != 9 {
		t.Fatalf("fingerprint schema versions current=%d available=%d", current, available)
	}
}

func TestMigratorPostgreSQLQuotaIdentityConstraints(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	seedQuotaMigrationTenant(t, ctx, pool)

	assertQuotaMigrationCatalog(t, ctx, pool)

	base := quotaBucketFixture{
		ID:              "qbk_00000000000000000000000001",
		LimitPlanKey:    "standard",
		RuleKey:         strings.Repeat("r", 43),
		Metric:          "logical_requests",
		ScopeType:       "user",
		ScopeDimensions: []string{"user"},
		ScopeKey:        strings.Repeat("s", 43),
		Algorithm:       "calendar",
		WindowKey:       "2026-08-27",
		HardMaximum:     100,
	}
	if err := insertQuotaMigrationBucket(ctx, pool, base); err != nil {
		t.Fatalf("insert singular quota bucket: %v", err)
	}

	composite := base
	composite.ID = "qbk_00000000000000000000000002"
	composite.RuleKey = strings.Repeat("c", 43)
	composite.ScopeType = "composite"
	composite.ScopeDimensions = []string{"user", "feature"}
	composite.ScopeKey = strings.Repeat("d", 43)
	if err := insertQuotaMigrationBucket(ctx, pool, composite); err != nil {
		t.Fatalf("insert composite quota bucket: %v", err)
	}

	route := base
	route.ID = "qbk_00000000000000000000000003"
	route.RuleKey = strings.Repeat("e", 43)
	route.ScopeType = "route"
	route.ScopeDimensions = []string{"route"}
	route.ScopeKey = strings.Repeat("f", 43)
	if err := insertQuotaMigrationBucket(ctx, pool, route); err != nil {
		t.Fatalf("insert route-scoped quota bucket: %v", err)
	}

	duplicateIdentity := base
	duplicateIdentity.ID = "qbk_00000000000000000000000004"
	duplicateIdentity.HardMaximum = 200
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, duplicateIdentity),
		"23505",
		"quota_buckets_identity_key",
	)

	invalidPlan := base
	invalidPlan.ID = "qbk_00000000000000000000000005"
	invalidPlan.LimitPlanKey = "Standard"
	invalidPlan.RuleKey = strings.Repeat("g", 43)
	invalidPlan.ScopeKey = strings.Repeat("h", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, invalidPlan),
		"23514",
		"quota_buckets_limit_plan_key_identifier_check",
	)

	invalidRuleHash := base
	invalidRuleHash.ID = "qbk_00000000000000000000000006"
	invalidRuleHash.RuleKey = strings.Repeat("i", 42)
	invalidRuleHash.ScopeKey = strings.Repeat("j", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, invalidRuleHash),
		"23514",
		"quota_buckets_rule_key_hash_check",
	)

	duplicateDimensions := base
	duplicateDimensions.ID = "qbk_00000000000000000000000007"
	duplicateDimensions.RuleKey = strings.Repeat("k", 43)
	duplicateDimensions.ScopeType = "composite"
	duplicateDimensions.ScopeDimensions = []string{"user", "user"}
	duplicateDimensions.ScopeKey = strings.Repeat("m", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, duplicateDimensions),
		"23514",
		"quota_buckets_scope_dimensions_check",
	)

	mismatchedSingularScope := base
	mismatchedSingularScope.ID = "qbk_00000000000000000000000008"
	mismatchedSingularScope.RuleKey = strings.Repeat("n", 43)
	mismatchedSingularScope.ScopeType = "feature"
	mismatchedSingularScope.ScopeDimensions = []string{"user"}
	mismatchedSingularScope.ScopeKey = strings.Repeat("o", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, mismatchedSingularScope),
		"23514",
		"quota_buckets_scope_type_dimensions_check",
	)

	invalidScopeHash := base
	invalidScopeHash.ID = "qbk_00000000000000000000000009"
	invalidScopeHash.RuleKey = strings.Repeat("p", 43)
	invalidScopeHash.ScopeKey = strings.Repeat("q", 42)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, invalidScopeHash),
		"23514",
		"quota_buckets_scope_key_hash_check",
	)

	zeroBasedDimensions := base
	zeroBasedDimensions.ID = "qbk_00000000000000000000000010"
	zeroBasedDimensions.RuleKey = strings.Repeat("t", 43)
	zeroBasedDimensions.ScopeDimensions = pgtype.Array[string]{
		Elements: []string{"user"},
		Dims:     []pgtype.ArrayDimension{{Length: 1, LowerBound: 0}},
		Valid:    true,
	}
	zeroBasedDimensions.ScopeKey = strings.Repeat("u", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, zeroBasedDimensions),
		"23514",
		"quota_buckets_scope_dimensions_check",
	)

	multidimensionalScope := base
	multidimensionalScope.ID = "qbk_00000000000000000000000011"
	multidimensionalScope.RuleKey = strings.Repeat("v", 43)
	multidimensionalScope.ScopeType = "composite"
	multidimensionalScope.ScopeDimensions = pgtype.Array[string]{
		Elements: []string{"user", "feature"},
		Dims: []pgtype.ArrayDimension{
			{Length: 1, LowerBound: 1},
			{Length: 2, LowerBound: 1},
		},
		Valid: true,
	}
	multidimensionalScope.ScopeKey = strings.Repeat("w", 43)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationBucket(ctx, pool, multidimensionalScope),
		"23514",
		"quota_buckets_scope_dimensions_check",
	)
}

func TestMigratorPostgreSQLLogicalRequestFeatureIdentifierBounds(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	seedQuotaMigrationTenant(t, ctx, pool)
	seedQuotaMigrationRequestDependencies(t, ctx, pool)

	var featureConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'logical_requests'::regclass
		  AND conname = 'logical_requests_feature_key_identifier_check'
	`).Scan(&featureConstraint); err != nil {
		t.Fatalf("read logical request feature constraint: %v", err)
	}
	if !strings.Contains(featureConstraint, "{0,62}") {
		t.Fatalf("logical request feature constraint = %q", featureConstraint)
	}

	if err := insertQuotaMigrationLogicalRequest(
		ctx,
		pool,
		"req_00000000000000000000000001",
		"a",
	); err != nil {
		t.Fatalf("insert one-character feature identifier: %v", err)
	}

	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationLogicalRequest(
			ctx,
			pool,
			"req_00000000000000000000000002",
			strings.Repeat("a", 64),
		),
		"23514",
		"logical_requests_feature_key_identifier_check",
	)
	expectPostgreSQLConstraintError(
		t,
		insertQuotaMigrationLogicalRequest(
			ctx,
			pool,
			"req_00000000000000000000000003",
			"Not_Canonical",
		),
		"23514",
		"logical_requests_feature_key_identifier_check",
	)
}

type quotaBucketFixture struct {
	ID              string
	LimitPlanKey    string
	RuleKey         string
	Metric          string
	ScopeType       string
	ScopeDimensions any
	ScopeKey        string
	Algorithm       string
	WindowKey       string
	HardMaximum     int64
}

func insertQuotaMigrationBucket(ctx context.Context, pool *pgxpool.Pool, fixture quotaBucketFixture) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO quota_buckets (
			quota_bucket_id,
			organization_id,
			application_id,
			environment_id,
			limit_plan_key,
			rule_key,
			metric,
			scope_type,
			scope_dimensions,
			scope_key,
			algorithm,
			window_key,
			hard_maximum
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text[], $10, $11, $12, $13)
	`,
		fixture.ID,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		fixture.LimitPlanKey,
		fixture.RuleKey,
		fixture.Metric,
		fixture.ScopeType,
		fixture.ScopeDimensions,
		fixture.ScopeKey,
		fixture.Algorithm,
		fixture.WindowKey,
		fixture.HardMaximum,
	)
	return err
}

func insertQuotaMigrationLogicalRequest(
	ctx context.Context,
	pool *pgxpool.Pool,
	logicalRequestID string,
	featureKey string,
) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO logical_requests (
			logical_request_id,
			organization_id,
			application_id,
			environment_id,
			application_user_id,
			installation_id,
			session_grant_id,
			config_revision_id,
			feature_key,
			protocol,
			status
		) VALUES (
			$1, $2, $3, $4,
			'usr_00000000000000000000000001',
			'ins_00000000000000000000000001',
			'sgr_00000000000000000000000001',
			'rev_00000000000000000000000001',
			$5, 'openai_chat', 'reserved'
		)
	`,
		logicalRequestID,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		featureKey,
	)
	return err
}

func assertQuotaMigrationCatalog(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	var (
		clientRequestUnique    bool
		clientRequestPredicate string
	)
	if err := pool.QueryRow(ctx, `
		SELECT
			index_entry.indisunique,
			pg_get_expr(index_entry.indpred, index_entry.indrelid)
		FROM pg_index AS index_entry
		JOIN pg_class AS index_relation ON index_relation.oid = index_entry.indexrelid
		WHERE index_relation.oid = 'logical_requests_client_request_idx'::regclass
	`).Scan(&clientRequestUnique, &clientRequestPredicate); err != nil {
		t.Fatalf("read client request correlation index: %v", err)
	}
	if clientRequestUnique || !strings.Contains(clientRequestPredicate, "client_request_id IS NOT NULL") {
		t.Fatalf(
			"client correlation index unique=%t predicate=%q",
			clientRequestUnique,
			clientRequestPredicate,
		)
	}

	var reservationConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'quota_reservations'::regclass
		  AND conname = 'quota_reservations_logical_request_key'
	`).Scan(&reservationConstraint); err != nil {
		t.Fatalf("read reservation request identity constraint: %v", err)
	}
	if reservationConstraint != "UNIQUE (environment_id, logical_request_id)" {
		t.Fatalf("reservation request identity constraint = %q", reservationConstraint)
	}

	var bucketIdentityConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'quota_buckets'::regclass
		  AND conname = 'quota_buckets_identity_key'
	`).Scan(&bucketIdentityConstraint); err != nil {
		t.Fatalf("read bucket identity constraint: %v", err)
	}
	if bucketIdentityConstraint != "UNIQUE (environment_id, limit_plan_key, rule_key, metric, algorithm, window_key, scope_key)" {
		t.Fatalf("bucket identity constraint = %q", bucketIdentityConstraint)
	}

	var tenantScopeIndexPresent bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('quota_buckets_tenant_scope_idx') IS NOT NULL
	`).Scan(&tenantScopeIndexPresent); err != nil {
		t.Fatalf("read tenant scope index: %v", err)
	}
	if !tenantScopeIndexPresent {
		t.Fatal("tenant scope lookup index is missing")
	}
}

func seedQuotaMigrationTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name)
		VALUES ($1, 'quota-migration', 'Quota Migration')
	`, quotaMigrationOrganizationID); err != nil {
		t.Fatalf("insert quota migration organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name)
		VALUES ($1, $2, 'quota-app', 'Quota App')
	`, quotaMigrationApplicationID, quotaMigrationOrganizationID); err != nil {
		t.Fatalf("insert quota migration application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind
		) VALUES ($1, $2, $3, 'production', 'Production', 'production')
	`, quotaMigrationEnvironmentID, quotaMigrationOrganizationID, quotaMigrationApplicationID); err != nil {
		t.Fatalf("insert quota migration environment: %v", err)
	}
}

func seedQuotaMigrationRequestDependencies(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name
		) VALUES (
			'adm_00000000000000000000000001',
			'quota@example.test',
			'quota@example.test',
			'Quota Admin'
		)
	`); err != nil {
		t.Fatalf("insert quota migration admin: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role
		) VALUES (
			'amb_00000000000000000000000001',
			$1,
			'adm_00000000000000000000000001',
			'owner'
		)
	`, quotaMigrationOrganizationID); err != nil {
		t.Fatalf("insert quota migration admin membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id,
			organization_id,
			application_id,
			environment_id,
			revision_number,
			etag,
			status,
			document,
			created_by_admin_user_id
		) VALUES (
			'rev_00000000000000000000000001',
			$1, $2, $3, 1, 'feature-etag-001', 'draft', '{}'::jsonb,
			'adm_00000000000000000000000001'
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID, quotaMigrationEnvironmentID); err != nil {
		t.Fatalf("insert quota migration config revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id
		) VALUES (
			'usr_00000000000000000000000001', $1, $2
		)
	`, quotaMigrationOrganizationID, quotaMigrationApplicationID); err != nil {
		t.Fatalf("insert quota migration application user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id,
			organization_id,
			application_id,
			environment_id,
			application_user_id,
			platform,
			dpop_jkt,
			dpop_public_jwk,
			key_storage,
			trust_level
		) VALUES (
			'ins_00000000000000000000000001',
			$1, $2, $3,
			'usr_00000000000000000000000001',
			'ios', $4, '{}'::jsonb, 'unknown', 'debug'
		)
	`,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		strings.Repeat("j", 43),
	); err != nil {
		t.Fatalf("insert quota migration installation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id,
			organization_id,
			application_id,
			environment_id,
			application_user_id,
			installation_id,
			access_token_jti_hash,
			dpop_jkt,
			policy_revision_id,
			trust_level,
			identity_verified_at,
			issued_at,
			expires_at
		) VALUES (
			'sgr_00000000000000000000000001',
			$1, $2, $3,
			'usr_00000000000000000000000001',
			'ins_00000000000000000000000001',
			decode(repeat('11', 32), 'hex'),
			$4,
			'rev_00000000000000000000000001',
			'debug',
			CURRENT_TIMESTAMP - interval '1 minute',
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP + interval '1 hour'
		)
	`,
		quotaMigrationOrganizationID,
		quotaMigrationApplicationID,
		quotaMigrationEnvironmentID,
		strings.Repeat("j", 43),
	); err != nil {
		t.Fatalf("insert quota migration session grant: %v", err)
	}
}

func expectPostgreSQLConstraintError(t *testing.T, err error, code, constraint string) {
	t.Helper()

	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		t.Fatalf("database error = %v, want PostgreSQL %s", err, code)
	}
	if pgError.Code != code {
		t.Fatalf("database error code = %s, want %s: %v", pgError.Code, code, err)
	}
	if constraint != "" && pgError.ConstraintName != constraint {
		t.Fatalf("database constraint = %q, want %q: %v", pgError.ConstraintName, constraint, err)
	}
}
