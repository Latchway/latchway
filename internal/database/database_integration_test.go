package database

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/migrations"
)

var integrationSchemaPattern = regexp.MustCompile(`\Alatchway_test_[0-9]+\z`)

func TestMigratorPostgreSQL(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)

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

func TestMigratorPostgreSQLUpgradeV4SessionsAndReplayScope(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThroughV4(t, ctx, pool)

	const (
		organizationID  = "org_00000000000000000000000001"
		applicationID   = "app_00000000000000000000000001"
		environmentID   = "env_00000000000000000000000001"
		adminUserID     = "adm_00000000000000000000000001"
		membershipID    = "amb_00000000000000000000000001"
		configRevision  = "rev_00000000000000000000000001"
		applicationUser = "usr_00000000000000000000000001"
		installationID  = "ins_00000000000000000000000001"
		sessionGrantID  = "sgr_00000000000000000000000001"
		refreshTokenID  = "rft_00000000000000000000000001"
		refreshFamilyID = "rff_00000000000000000000000001"
		replayEntryID   = "drp_00000000000000000000000001"
		secondGrantID   = "sgr_00000000000000000000000002"
		secondReplayID  = "drp_00000000000000000000000002"
	)
	anchor := time.Now().UTC().Truncate(time.Microsecond)
	dpopJKT := strings.Repeat("j", 43)
	accessTokenHash := bytes.Repeat([]byte{0x11}, 32)
	secondAccessTokenHash := bytes.Repeat([]byte{0x12}, 32)
	refreshTokenHash := bytes.Repeat([]byte{0x21}, 32)
	proofJTIHash := bytes.Repeat([]byte{0x31}, 32)
	httpURIHash := bytes.Repeat([]byte{0x41}, 32)
	identityVerifiedAt := anchor.Add(-30 * time.Minute)
	attestedAt := anchor.Add(-25 * time.Minute)
	issuedAt := anchor.Add(-20 * time.Minute)
	expiresAt := anchor.Add(time.Hour)

	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, 'upgrade-test', 'Upgrade Test', $2, $2)
	`, organizationID, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (
			application_id, organization_id, slug, display_name, created_at, updated_at
		) VALUES ($1, $2, 'upgrade-app', 'Upgrade App', $3, $3)
	`, applicationID, organizationID, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name,
			kind, created_at, updated_at
		) VALUES ($1, $2, $3, 'production', 'Production', 'production', $4, $4)
	`, environmentID, organizationID, applicationID, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy environment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name, created_at, updated_at
		) VALUES ($1, 'upgrade@example.test', 'upgrade@example.test', 'Upgrade Admin', $2, $2)
	`, adminUserID, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy admin: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, created_at, updated_at
		) VALUES ($1, $2, $3, 'owner', $4, $4)
	`, membershipID, organizationID, adminUserID, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy admin membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_errors, validation_report, created_by_admin_user_id,
			created_at, validated_at
		) VALUES (
			$1, $2, $3, $4, 1, 'upgrade-etag-0001', 'valid', '{}'::jsonb,
			'{}'::jsonb, '[]'::jsonb, '{"valid":true}'::jsonb, $5, $6, $7
		)
	`, configRevision, organizationID, applicationID, environmentID, adminUserID,
		anchor.Add(-time.Hour), anchor.Add(-50*time.Minute)); err != nil {
		t.Fatalf("insert legacy configuration revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $4)
	`, applicationUser, organizationID, applicationID, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy application user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id,
			application_user_id, platform, dpop_jkt, dpop_public_jwk, key_storage,
			trust_level, created_at, updated_at, last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5, 'ios', $6, '{"kty":"EC"}'::jsonb,
			'secure_enclave', 'app_verified', $7, $7, $7
		)
	`, installationID, organizationID, applicationID, environmentID, applicationUser,
		dpopJKT, anchor.Add(-time.Hour)); err != nil {
		t.Fatalf("insert legacy installation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
			policy_revision_id, trust_level, identity_verified_at, attested_at,
			issued_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, 'app_verified', $10, $11, $12, $13
		)
	`, sessionGrantID, organizationID, applicationID, environmentID, applicationUser,
		installationID, accessTokenHash, dpopJKT, configRevision, identityVerifiedAt,
		attestedAt, issuedAt, expiresAt); err != nil {
		t.Fatalf("insert active legacy session grant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO refresh_tokens (
			refresh_token_id, family_id, organization_id, application_id,
			environment_id, application_user_id, installation_id, session_grant_id,
			token_hash, status, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11)
	`, refreshTokenID, refreshFamilyID, organizationID, applicationID, environmentID,
		applicationUser, installationID, sessionGrantID, refreshTokenHash, issuedAt,
		expiresAt); err != nil {
		t.Fatalf("insert active legacy refresh credential: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO dpop_replay_entries (
			dpop_replay_entry_id, organization_id, application_id, environment_id,
			session_grant_id, proof_jti_hash, http_method, http_uri_hash,
			observed_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, 'POST', $7, $8, $9)
	`, replayEntryID, organizationID, applicationID, environmentID, sessionGrantID,
		proofJTIHash, httpURIHash, anchor.Add(-time.Minute), anchor.Add(9*time.Minute)); err != nil {
		t.Fatalf("insert legacy replay entry: %v", err)
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("upgrade populated version 4 schema: %v", err)
	}

	var (
		grantRevoked            bool
		grantReason             string
		attestedAtCleared       bool
		identityProviderMissing bool
		identityExpiryMissing   bool
		attestationDataMissing  bool
	)
	if err := pool.QueryRow(ctx, `
		SELECT
			revoked_at IS NOT NULL,
			revoke_reason,
			attested_at IS NULL,
			identity_provider_key IS NULL,
			identity_expires_at IS NULL,
			attestation_provider IS NULL AND attestation_expires_at IS NULL
		FROM session_grants
		WHERE session_grant_id = $1
	`, sessionGrantID).Scan(
		&grantRevoked,
		&grantReason,
		&attestedAtCleared,
		&identityProviderMissing,
		&identityExpiryMissing,
		&attestationDataMissing,
	); err != nil {
		t.Fatalf("read upgraded legacy grant: %v", err)
	}
	if !grantRevoked || grantReason != "schema_upgrade_v5" || !attestedAtCleared ||
		!identityProviderMissing || !identityExpiryMissing || !attestationDataMissing {
		t.Fatalf(
			"legacy grant was not safely invalidated: revoked=%t reason=%q attested_cleared=%t identity_provider_null=%t identity_expiry_null=%t attestation_null=%t",
			grantRevoked,
			grantReason,
			attestedAtCleared,
			identityProviderMissing,
			identityExpiryMissing,
			attestationDataMissing,
		)
	}

	var refreshStatus string
	var refreshRevoked, refreshTimestampValid bool
	if err := pool.QueryRow(ctx, `
		SELECT status, revoked_at IS NOT NULL, revoked_at >= issued_at
		FROM refresh_tokens
		WHERE refresh_token_id = $1
	`, refreshTokenID).Scan(&refreshStatus, &refreshRevoked, &refreshTimestampValid); err != nil {
		t.Fatalf("read upgraded refresh credential: %v", err)
	}
	if refreshStatus != "revoked" || !refreshRevoked || !refreshTimestampValid {
		t.Fatalf(
			"legacy refresh credential was not safely revoked: status=%q revoked=%t timestamp_valid=%t",
			refreshStatus,
			refreshRevoked,
			refreshTimestampValid,
		)
	}

	var replayInstallationID, replayGrantID string
	if err := pool.QueryRow(ctx, `
		SELECT installation_id, session_grant_id
		FROM dpop_replay_entries
		WHERE dpop_replay_entry_id = $1
	`, replayEntryID).Scan(&replayInstallationID, &replayGrantID); err != nil {
		t.Fatalf("read upgraded replay entry: %v", err)
	}
	if replayInstallationID != installationID || replayGrantID != sessionGrantID {
		t.Fatalf(
			"replay scope/correlation mismatch: installation=%q grant=%q",
			replayInstallationID,
			replayGrantID,
		)
	}

	var nullable string
	if err := pool.QueryRow(ctx, `
		SELECT is_nullable
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'dpop_replay_entries'
		  AND column_name = 'installation_id'
	`).Scan(&nullable); err != nil {
		t.Fatalf("read replay installation nullability: %v", err)
	}
	if nullable != "NO" {
		t.Fatalf("replay installation_id nullability = %q, want NO", nullable)
	}

	var installationForeignKey, replayUnique string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'dpop_replay_entries'::regclass
		  AND conname = 'dpop_replay_entries_installation_fkey'
	`).Scan(&installationForeignKey); err != nil {
		t.Fatalf("read replay installation foreign key: %v", err)
	}
	if installationForeignKey != "FOREIGN KEY (organization_id, application_id, environment_id, installation_id) REFERENCES installations(organization_id, application_id, environment_id, installation_id)" {
		t.Fatalf("unexpected replay installation foreign key: %s", installationForeignKey)
	}
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'dpop_replay_entries'::regclass
		  AND conname = 'dpop_replay_entries_installation_proof_jti_key'
	`).Scan(&replayUnique); err != nil {
		t.Fatalf("read replay uniqueness: %v", err)
	}
	if replayUnique != "UNIQUE (installation_id, proof_jti_hash)" {
		t.Fatalf("unexpected replay uniqueness: %s", replayUnique)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
			policy_revision_id, trust_level, identity_verified_at, issued_at,
			expires_at, revoked_at, revoke_reason
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, 'identity_only', $10, $11, $12, $11, 'test_only'
		)
	`, secondGrantID, organizationID, applicationID, environmentID, applicationUser,
		installationID, secondAccessTokenHash, dpopJKT, configRevision, identityVerifiedAt,
		issuedAt, expiresAt); err != nil {
		t.Fatalf("insert second grant for replay uniqueness check: %v", err)
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO dpop_replay_entries (
			dpop_replay_entry_id, organization_id, application_id, environment_id,
			installation_id, session_grant_id, proof_jti_hash, http_method,
			http_uri_hash, observed_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'POST', $8, $9, $10)
	`, secondReplayID, organizationID, applicationID, environmentID, installationID,
		secondGrantID, proofJTIHash, httpURIHash, anchor, anchor.Add(10*time.Minute))
	var constraintError *pgconn.PgError
	if !errors.As(err, &constraintError) || constraintError.Code != "23505" ||
		constraintError.ConstraintName != "dpop_replay_entries_installation_proof_jti_key" {
		t.Fatalf("same-installation replay duplicate error = %v, want installation-scoped unique violation", err)
	}
}

func TestMigratorPostgreSQLUpgradeV5InvalidatesUnboundChallenges(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 5)

	const (
		organizationID  = "org_00000000000000000000000001"
		applicationID   = "app_00000000000000000000000001"
		environmentID   = "env_00000000000000000000000001"
		applicationUser = "usr_00000000000000000000000001"
		challengeID     = "chl_00000000000000000000000001"
	)
	anchor := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name)
		VALUES ($1, 'challenge-upgrade', 'Challenge Upgrade')
	`, organizationID); err != nil {
		t.Fatalf("create version 5 challenge organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name)
		VALUES ($1, $2, 'challenge-upgrade-app', 'Challenge Upgrade App')
	`, applicationID, organizationID); err != nil {
		t.Fatalf("create version 5 challenge application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind
		) VALUES ($1, $2, $3, 'development', 'Development', 'development')
	`, environmentID, organizationID, applicationID); err != nil {
		t.Fatalf("create version 5 challenge environment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id
		) VALUES ($1, $2, $3)
	`, applicationUser, organizationID, applicationID); err != nil {
		t.Fatalf("create version 5 challenge user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_challenges (
			session_challenge_id, organization_id, application_id, environment_id,
			application_user_id, identity_provider_key, platform, dpop_jkt,
			dpop_public_jwk, nonce_hash, binding_hash, created_at, expires_at,
			challenge_nonce, identity_verified_at, identity_expires_at
		) VALUES (
			$1, $2, $3, $4, $5, 'firebase', 'ios', $6, '{"kty":"EC"}'::jsonb,
			$7, $8, $9, $10, $11, $9, $12
		)
	`, challengeID, organizationID, applicationID, environmentID, applicationUser,
		strings.Repeat("j", 43), bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x41}, 32),
		anchor, anchor.Add(5*time.Minute), strings.Repeat("n", 43), anchor.Add(time.Hour)); err != nil {
		t.Fatalf("insert version 5 unbound challenge: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_challenge_consumptions (
			organization_id, application_id, environment_id,
			session_challenge_id, consumed_at
		) VALUES ($1, $2, $3, $4, $5)
	`, organizationID, applicationID, environmentID, challengeID, anchor); err != nil {
		t.Fatalf("consume version 5 unbound challenge: %v", err)
	}

	migrator := NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("upgrade populated version 5 schema: %v", err)
	}
	var challenges, consumptions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM session_challenges`).Scan(&challenges); err != nil {
		t.Fatalf("count upgraded challenges: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM session_challenge_consumptions`).Scan(&consumptions); err != nil {
		t.Fatalf("count upgraded challenge consumptions: %v", err)
	}
	if challenges != 0 || consumptions != 0 {
		t.Fatalf("unbound version 5 challenge state survived upgrade: challenges=%d consumptions=%d", challenges, consumptions)
	}

	requiredColumns := []string{
		"config_revision_id",
		"attestation_policy_id",
		"attestation_provider",
		"attestation_mode",
		"attestation_minimum_trust_level",
		"attestation_maximum_age_milliseconds",
		"challenge_dpop_proof_jti_hash",
		"challenge_dpop_http_method",
		"challenge_dpop_http_uri_hash",
	}
	for _, column := range requiredColumns {
		var nullable string
		if err := pool.QueryRow(ctx, `
			SELECT is_nullable
			FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = 'session_challenges'
			  AND column_name = $1
		`, column).Scan(&nullable); err != nil {
			t.Fatalf("read upgraded challenge column %s: %v", column, err)
		}
		if nullable != "NO" {
			t.Fatalf("upgraded challenge column %s nullability=%q want=NO", column, nullable)
		}
	}
	for _, rawColumn := range []string{"challenge_dpop_proof_jti", "challenge_dpop_http_uri"} {
		var count int
		if err := pool.QueryRow(ctx, `
			SELECT count(*)
			FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = 'session_challenges'
			  AND column_name = $1
		`, rawColumn).Scan(&count); err != nil || count != 0 {
			t.Fatalf("raw challenge DPoP column %s exists: count=%d err=%v", rawColumn, count, err)
		}
	}
	var appVersionCheck string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'installations'::regclass
		  AND conname = 'installations_app_version_length_check'
	`).Scan(&appVersionCheck); err != nil {
		t.Fatalf("read upgraded application-version check: %v", err)
	}
	if !strings.Contains(appVersionCheck, "char_length(app_version) <= 128") {
		t.Fatalf("application-version check does not match locked contract: %s", appVersionCheck)
	}
	var keyStorageCheck string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = 'installations'::regclass
		  AND conname = 'installations_key_storage_check'
	`).Scan(&keyStorageCheck); err != nil {
		t.Fatalf("read upgraded key-storage check: %v", err)
	}
	if !strings.Contains(keyStorageCheck, "'unknown'::text") {
		t.Fatalf("key-storage check lacks conservative unknown value: %s", keyStorageCheck)
	}
}

func TestMigratorPostgreSQLAlignsIdentityProviderIdentifierBounds(t *testing.T) {
	ctx, pool := newPostgreSQLIntegrationPool(t)
	applyMigrationsThrough(t, ctx, pool, 6)

	const (
		organizationID          = "org_00000000000000000000000001"
		applicationID           = "app_00000000000000000000000001"
		environmentID           = "env_00000000000000000000000001"
		adminUserID             = "adm_00000000000000000000000001"
		membershipID            = "amb_00000000000000000000000001"
		configRevisionID        = "rev_00000000000000000000000001"
		applicationUserID       = "usr_00000000000000000000000001"
		providerStateID         = "idp_00000000000000000000000001"
		externalIdentityID      = "xid_00000000000000000000000001"
		installationID          = "ins_00000000000000000000000001"
		sessionChallengeID      = "chl_00000000000000000000000001"
		sessionGrantID          = "sgr_00000000000000000000000001"
		legacyProviderKey       = "aa"
		identityProviderType    = "oidc"
		identityProviderIssuer  = "https://identity.example.test"
		identityProviderState   = "{}"
		attestationPolicyID     = "a"
		attestationProvider     = "debug"
		attestationMode         = "required"
		attestationMinimumTrust = "debug"
	)
	anchor := time.Now().UTC().Truncate(time.Microsecond)
	dpopJKT := strings.Repeat("j", 43)
	legacyMaximumKey := strings.Repeat("a", 64)

	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name)
		VALUES ($1, 'identifier-bounds', 'Identifier Bounds')
	`, organizationID); err != nil {
		t.Fatalf("create identifier-bounds organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name)
		VALUES ($1, $2, 'identifier-bounds-app', 'Identifier Bounds App')
	`, applicationID, organizationID); err != nil {
		t.Fatalf("create identifier-bounds application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind
		) VALUES ($1, $2, $3, 'development', 'Development', 'development')
	`, environmentID, organizationID, applicationID); err != nil {
		t.Fatalf("create identifier-bounds environment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name
		) VALUES ($1, 'bounds@example.test', 'bounds@example.test', 'Bounds Admin')
	`, adminUserID); err != nil {
		t.Fatalf("create identifier-bounds admin: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role
		) VALUES ($1, $2, $3, 'owner')
	`, membershipID, organizationID, adminUserID); err != nil {
		t.Fatalf("create identifier-bounds membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, created_by_admin_user_id
		) VALUES ($1, $2, $3, $4, 1, 'identifier-etag-0001', 'draft', '{}'::jsonb, $5)
	`, configRevisionID, organizationID, applicationID, environmentID, adminUserID); err != nil {
		t.Fatalf("create identifier-bounds configuration revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id
		) VALUES ($1, $2, $3)
	`, applicationUserID, organizationID, applicationID); err != nil {
		t.Fatalf("create identifier-bounds application user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_provider_states (
			identity_provider_state_id, organization_id, application_id,
			environment_id, provider_key, provider_type, issuer, state
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
	`, providerStateID, organizationID, applicationID, environmentID,
		legacyMaximumKey, identityProviderType, identityProviderIssuer, identityProviderState); err != nil {
		t.Fatalf("create legacy 64-character provider state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO external_identities (
			external_identity_id, organization_id, application_id,
			application_user_id, provider_key, issuer_hash, subject_hmac
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, externalIdentityID, organizationID, applicationID, applicationUserID,
		legacyProviderKey, bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x12}, 32)); err != nil {
		t.Fatalf("create legacy external identity: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id,
			application_user_id, platform, dpop_jkt, dpop_public_jwk,
			key_storage, trust_level
		) VALUES (
			$1, $2, $3, $4, $5, 'ios', $6, '{"kty":"EC"}'::jsonb,
			'unknown', 'debug'
		)
	`, installationID, organizationID, applicationID, environmentID,
		applicationUserID, dpopJKT); err != nil {
		t.Fatalf("create identifier-bounds installation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_challenges (
			session_challenge_id, organization_id, application_id, environment_id,
			application_user_id, identity_provider_key, platform, dpop_jkt,
			dpop_public_jwk, nonce_hash, binding_hash, created_at, expires_at,
			challenge_nonce, identity_verified_at, identity_expires_at,
			config_revision_id, attestation_policy_id, attestation_provider,
			attestation_mode, attestation_minimum_trust_level,
			attestation_maximum_age_milliseconds,
			challenge_dpop_proof_jti_hash, challenge_dpop_http_method,
			challenge_dpop_http_uri_hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, 'ios', $7, '{"kty":"EC"}'::jsonb,
			$8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			60000, $20, 'POST', $21
		)
	`, sessionChallengeID, organizationID, applicationID, environmentID,
		applicationUserID, legacyProviderKey, dpopJKT,
		bytes.Repeat([]byte{0x21}, 32), bytes.Repeat([]byte{0x22}, 32),
		anchor, anchor.Add(5*time.Minute), strings.Repeat("n", 43),
		anchor.Add(-time.Minute), anchor.Add(time.Hour), configRevisionID,
		attestationPolicyID, attestationProvider, attestationMode,
		attestationMinimumTrust, bytes.Repeat([]byte{0x23}, 32),
		bytes.Repeat([]byte{0x24}, 32)); err != nil {
		t.Fatalf("create legacy session challenge: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash,
			dpop_jkt, policy_revision_id, trust_level, identity_verified_at,
			attested_at, issued_at, expires_at, identity_provider_key,
			identity_expires_at, attestation_provider, attestation_expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, 'debug', $10, $11,
			$12, $13, $14, $15, 'debug', $16
		)
	`, sessionGrantID, organizationID, applicationID, environmentID,
		applicationUserID, installationID, bytes.Repeat([]byte{0x31}, 32),
		dpopJKT, configRevisionID, anchor.Add(-time.Minute), anchor.Add(-30*time.Second),
		anchor, anchor.Add(15*time.Minute), legacyProviderKey, anchor.Add(time.Hour),
		anchor.Add(time.Hour)); err != nil {
		t.Fatalf("create legacy session grant: %v", err)
	}

	migrator := NewMigrator(pool)
	err := migrator.Up(ctx)
	var constraintError *pgconn.PgError
	if !errors.As(err, &constraintError) || constraintError.Code != "23514" {
		t.Fatalf("migration with invalid legacy identifier error = %v, want check violation", err)
	}
	var migrationApplied bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 7)
	`).Scan(&migrationApplied); err != nil {
		t.Fatalf("read rejected identifier migration status: %v", err)
	}
	if migrationApplied {
		t.Fatal("identifier migration was recorded after rejecting legacy data")
	}
	var oldConstraintPresent bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid = 'identity_provider_states'::regclass
			  AND conname = 'identity_provider_states_provider_key_check'
		)
	`).Scan(&oldConstraintPresent); err != nil {
		t.Fatalf("read legacy provider-state constraint after rejection: %v", err)
	}
	if !oldConstraintPresent {
		t.Fatal("legacy provider-state constraint was removed by rejected migration")
	}
	if _, err := pool.Exec(ctx, `
		UPDATE identity_provider_states SET provider_key = $1
		WHERE identity_provider_state_id = $2
	`, legacyProviderKey, providerStateID); err != nil {
		t.Fatalf("repair legacy provider identifier: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply identifier bounds migration after repair: %v", err)
	}

	targets := []struct {
		tableName     string
		columnName    string
		identifierKey string
		identifier    string
		oldConstraint string
		newConstraint string
	}{
		{
			tableName:     "identity_provider_states",
			columnName:    "provider_key",
			identifierKey: "identity_provider_state_id",
			identifier:    providerStateID,
			oldConstraint: "identity_provider_states_provider_key_check",
			newConstraint: "identity_provider_states_provider_key_identifier_check",
		},
		{
			tableName:     "external_identities",
			columnName:    "provider_key",
			identifierKey: "external_identity_id",
			identifier:    externalIdentityID,
			oldConstraint: "external_identities_provider_key_check",
			newConstraint: "external_identities_provider_key_identifier_check",
		},
		{
			tableName:     "session_challenges",
			columnName:    "identity_provider_key",
			identifierKey: "session_challenge_id",
			identifier:    sessionChallengeID,
			oldConstraint: "session_challenges_identity_provider_key_check",
			newConstraint: "session_challenges_identity_provider_key_identifier_check",
		},
		{
			tableName:     "session_grants",
			columnName:    "identity_provider_key",
			identifierKey: "session_grant_id",
			identifier:    sessionGrantID,
			oldConstraint: "session_grants_identity_provider_key_check",
			newConstraint: "session_grants_identity_provider_key_identifier_check",
		},
	}
	for _, target := range targets {
		t.Run(target.tableName, func(t *testing.T) {
			var oldCount int
			if err := pool.QueryRow(ctx, `
				SELECT count(*) FROM pg_constraint
				WHERE conrelid = $1::regclass AND conname = $2
			`, target.tableName, target.oldConstraint).Scan(&oldCount); err != nil {
				t.Fatalf("read legacy constraint: %v", err)
			}
			if oldCount != 0 {
				t.Fatalf("legacy constraint %q still exists", target.oldConstraint)
			}
			var newDefinition string
			if err := pool.QueryRow(ctx, `
				SELECT pg_get_constraintdef(oid) FROM pg_constraint
				WHERE conrelid = $1::regclass AND conname = $2
			`, target.tableName, target.newConstraint).Scan(&newDefinition); err != nil {
				t.Fatalf("read replacement constraint: %v", err)
			}
			if !strings.Contains(newDefinition, "{0,62}") {
				t.Fatalf("replacement constraint has wrong bounds: %s", newDefinition)
			}

			updateSQL := fmt.Sprintf(
				"UPDATE %s SET %s = $1 WHERE %s = $2",
				target.tableName,
				target.columnName,
				target.identifierKey,
			)
			if _, err := pool.Exec(ctx, updateSQL, "a", target.identifier); err != nil {
				t.Fatalf("one-character identifier rejected: %v", err)
			}
			if _, err := pool.Exec(ctx, updateSQL, strings.Repeat("a", 63), target.identifier); err != nil {
				t.Fatalf("63-character identifier rejected: %v", err)
			}
			_, err := pool.Exec(ctx, updateSQL, strings.Repeat("a", 64), target.identifier)
			constraintError = nil
			if !errors.As(err, &constraintError) || constraintError.Code != "23514" ||
				constraintError.ConstraintName != target.newConstraint {
				t.Fatalf("64-character identifier error = %v, want %s check violation", err, target.newConstraint)
			}
		})
	}
}

func newPostgreSQLIntegrationPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()

	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	t.Cleanup(adminPool.Close)

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
	t.Cleanup(pool.Close)
	return ctx, pool
}

func applyMigrationsThroughV4(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	applyMigrationsThrough(t, ctx, pool, 4)
}

func applyMigrationsThrough(t *testing.T, ctx context.Context, pool *pgxpool.Pool, maximumVersion int64) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatalf("create migration ledger: %v", err)
	}

	for _, migrationFile := range []struct {
		version int64
		name    string
	}{
		{version: 1, name: "000001_runtime.sql"},
		{version: 2, name: "000002_domain_foundation.sql"},
		{version: 3, name: "000003_admin_token_name_length.sql"},
		{version: 4, name: "000004_configuration_revisions.sql"},
		{version: 5, name: "000005_session_challenge_binding.sql"},
		{version: 6, name: "000006_session_challenge_policy.sql"},
	} {
		if migrationFile.version > maximumVersion {
			break
		}
		contents, err := migrations.Files.ReadFile(migrationFile.name)
		if err != nil {
			t.Fatalf("read migration %s: %v", migrationFile.name, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin migration %s: %v", migrationFile.name, err)
		}
		if _, err := tx.Exec(ctx, string(contents)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("execute migration %s: %v", migrationFile.name, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO schema_migrations (version, name) VALUES ($1, $2)
		`, migrationFile.version, migrationFile.name); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("record migration %s: %v", migrationFile.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit migration %s: %v", migrationFile.name, err)
		}
	}
}
