package worker

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/session"
)

func TestComponentMaintenanceIsBoundedIdempotentAndReplicaSafePostgreSQL(t *testing.T) {
	pool, ctx := isolatedWorkerPool(t)
	now := time.Now().UTC().Truncate(time.Second)
	fixture := insertWorkerComponentMaintenanceFixture(t, ctx, pool, now)
	operations, err := NewPostgreSQLOperations(pool)
	if err != nil {
		t.Fatal(err)
	}

	processed := runConcurrentMaintenance(t,
		func() (int64, error) { return operations.EnforceRetention(ctx, now, 1) },
		func() (int64, error) { return operations.EnforceRetention(ctx, now, 1) },
	)
	if processed != 2 {
		t.Fatalf("component credential retention processed %d rows, want 2", processed)
	}
	var refreshStatus, sessionFamilyStatus string
	var refreshRevoked bool
	var rotationResults int
	if err := pool.QueryRow(ctx, `
		SELECT token.status, token.revoked_at IS NOT NULL, family.status,
		       (SELECT count(*) FROM refresh_rotation_results
		        WHERE refresh_rotation_result_id = $3)
		FROM component_refresh_tokens AS token
		JOIN component_session_families AS family
		  ON family.component_session_family_id = token.component_session_family_id
		WHERE token.component_refresh_token_id = $1
		  AND family.component_session_family_id = $2
	`, fixture.refreshTokenID, fixture.sessionFamilyID, fixture.rotationResultID).Scan(
		&refreshStatus, &refreshRevoked, &sessionFamilyStatus, &rotationResults,
	); err != nil {
		t.Fatal(err)
	}
	if refreshStatus != "expired" || !refreshRevoked || sessionFamilyStatus != "active" || rotationResults != 0 {
		t.Fatalf("unexpected first retention state refresh=%q revoked=%t family=%q rotations=%d",
			refreshStatus, refreshRevoked, sessionFamilyStatus, rotationResults)
	}

	challengeMaintenance, err := session.NewChallengeMaintenance(pool)
	if err != nil {
		t.Fatal(err)
	}
	challengeProcessed := runConcurrentMaintenance(t,
		func() (int64, error) { return challengeMaintenance.DeleteExpired(ctx, now, 1) },
		func() (int64, error) { return challengeMaintenance.DeleteExpired(ctx, now, 1) },
	)
	if challengeProcessed != 2 {
		t.Fatalf("component challenge retention processed %d rows, want 2", challengeProcessed)
	}
	var expiredChallenges, liveChallenges int
	if err := pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE component_attestation_challenge_id IN ($1, $2)),
		  count(*) FILTER (WHERE component_attestation_challenge_id = $3)
		FROM component_attestation_challenges
	`, fixture.expiredChallengeID, fixture.secondExpiredChallengeID, fixture.liveChallengeID).Scan(
		&expiredChallenges, &liveChallenges,
	); err != nil {
		t.Fatal(err)
	}
	if expiredChallenges != 0 || liveChallenges != 1 {
		t.Fatalf("component challenge retention expired=%d live=%d", expiredChallenges, liveChallenges)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE session_grants SET expires_at = $2 WHERE session_grant_id = $1
	`, fixture.sessionGrantID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	processed = runConcurrentMaintenance(t,
		func() (int64, error) { return operations.EnforceRetention(ctx, now, 1) },
		func() (int64, error) { return operations.EnforceRetention(ctx, now, 1) },
	)
	if processed != 1 {
		t.Fatalf("component session-family retention processed %d rows, want 1", processed)
	}
	if err := pool.QueryRow(ctx, `
		SELECT status FROM component_session_families
		WHERE component_session_family_id = $1
	`, fixture.sessionFamilyID).Scan(&sessionFamilyStatus); err != nil {
		t.Fatal(err)
	}
	if sessionFamilyStatus != "expired" {
		t.Fatalf("component session family status=%q want=expired", sessionFamilyStatus)
	}
	if count, err := operations.EnforceRetention(ctx, now, 1); err != nil || count != 0 {
		t.Fatalf("idempotent component retention count=%d err=%v", count, err)
	}
	var auditCount int
	var actorKind, action, resourceType, resourceID, outcome, source, reason string
	var occurredAt time.Time
	if err := pool.QueryRow(ctx, `
		SELECT count(*), min(actor_kind), min(action), min(resource_type),
		       min(resource_id), min(outcome), min(source), min(reason),
		       min(occurred_at)
		FROM audit_events
		WHERE action = $1 AND resource_type = 'client_component'
		  AND resource_id = $2
	`, componentSessionFamilyExpiredAction, fixture.componentID).Scan(
		&auditCount, &actorKind, &action, &resourceType, &resourceID, &outcome,
		&source, &reason, &occurredAt,
	); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || actorKind != "system" ||
		action != componentSessionFamilyExpiredAction || resourceType != "client_component" ||
		resourceID != fixture.componentID || outcome != "succeeded" || source != "system" ||
		reason != componentSessionFamilyExpiredReason || !occurredAt.Equal(now) {
		t.Fatalf(
			"unexpected family-expiry audit count=%d actor=%q action=%q resource=%q/%q outcome=%q source=%q reason=%q at=%s",
			auditCount, actorKind, action, resourceType, resourceID, outcome, source, reason,
			occurredAt.Format(time.RFC3339Nano),
		)
	}
	changeRows, err := pool.Query(ctx, `
		SELECT change.field_name, change.operation, change.classification
		FROM audit_event_changes AS change
		JOIN audit_events AS event USING (audit_event_id)
		WHERE event.action = $1 AND event.resource_id = $2
		ORDER BY change.ordinal
	`, componentSessionFamilyExpiredAction, fixture.componentID)
	if err != nil {
		t.Fatal(err)
	}
	var changes []string
	for changeRows.Next() {
		var field, operation, classification string
		if err := changeRows.Scan(&field, &operation, &classification); err != nil {
			changeRows.Close()
			t.Fatal(err)
		}
		changes = append(changes, field+":"+operation+":"+classification)
	}
	if err := changeRows.Err(); err != nil {
		changeRows.Close()
		t.Fatal(err)
	}
	changeRows.Close()
	wantChanges := strings.Join([]string{
		"component_session_family_status:set:public",
		"access_availability:clear:public",
		"refresh_availability:clear:sensitive",
	}, ",")
	if gotChanges := strings.Join(changes, ","); gotChanges != wantChanges {
		t.Fatalf("family-expiry audit changes=%q want=%q", gotChanges, wantChanges)
	}
	if count, err := challengeMaintenance.DeleteExpired(ctx, now, 10); err != nil || count != 0 {
		t.Fatalf("idempotent component challenge retention count=%d err=%v", count, err)
	}
}

type workerComponentMaintenanceFixture struct {
	componentID              string
	refreshTokenID           string
	sessionFamilyID          string
	sessionGrantID           string
	rotationResultID         string
	expiredChallengeID       string
	secondExpiredChallengeID string
	liveChallengeID          string
}

func insertWorkerComponentMaintenanceFixture(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	now time.Time,
) workerComponentMaintenanceFixture {
	t.Helper()
	base := insertWorkerUsageFixture(t, ctx, pool, now)
	newID := func(prefix id.Prefix) string {
		value, err := id.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	var organizationID, applicationID, revisionID string
	if err := pool.QueryRow(ctx, `
		SELECT organization_id, application_id
		FROM environments WHERE environment_id = $1
	`, base.environmentID).Scan(&organizationID, &applicationID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT config_revision_id FROM config_revisions
		WHERE environment_id = $1 ORDER BY revision_number DESC LIMIT 1
	`, base.environmentID).Scan(&revisionID); err != nil {
		t.Fatal(err)
	}

	familyID := newID(id.InstallationFamily)
	componentID := newID(id.ClientComponent)
	componentKeyID := newID(id.ComponentKey)
	sessionFamilyID := newID(id.ComponentSession)
	sessionGrantID := newID(id.SessionGrant)
	refreshTokenID := newID(id.ComponentRefresh)
	rotationResultID := newID(id.RefreshRotation)
	expiredChallengeID := newID(id.SessionChallenge)
	secondExpiredChallengeID := newID(id.SessionChallenge)
	liveChallengeID := newID(id.SessionChallenge)
	componentJKT := strings.Repeat("B", 43)
	createdAt := now.Add(-10 * time.Minute)

	if _, err := pool.Exec(ctx, `
		INSERT INTO installation_families (
			installation_family_id, organization_id, application_id, environment_id,
			application_user_id, platform, status, root_installation_id,
			created_at, updated_at, last_seen_at
		) VALUES ($1,$2,$3,$4,$5,'ios','active',$6,$7,$7,$7)
	`, familyID, organizationID, applicationID, base.environmentID, base.userID,
		base.installationID, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO client_components (
			client_component_id, organization_id, application_id, environment_id,
			application_user_id, installation_family_id, component_definition_id,
			component_kind, platform, is_root, status, trust_source,
			trust_attestation_provider, trust_verified_at, trust_expires_at,
			granted_features, key_storage_claim, created_at, updated_at, last_seen_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,'ios-main','main_app','ios',true,'active',
			'direct_attested','app_attest',$7,$8,'["assistant"]','secure_enclave',$7,$7,$7
		)
	`, componentID, organizationID, applicationID, base.environmentID, base.userID,
		familyID, createdAt, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_keys (
			component_key_id, organization_id, application_id, environment_id,
			installation_family_id, client_component_id, dpop_jkt, public_jwk,
			status, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,'{}','active',$8)
	`, componentKeyID, organizationID, applicationID, base.environmentID, familyID,
		componentID, componentJKT, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE client_components SET current_component_key_id = $2 WHERE client_component_id = $1
	`, componentID, componentKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE installation_families SET root_component_id = $2 WHERE installation_family_id = $1
	`, familyID, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_session_families (
			component_session_family_id, organization_id, application_id, environment_id,
			application_user_id, installation_family_id, client_component_id,
			component_key_id, status, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$9)
	`, sessionFamilyID, organizationID, applicationID, base.environmentID, base.userID,
		familyID, componentID, componentKeyID, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
			policy_revision_id, trust_level, identity_provider_key,
			identity_verified_at, identity_expires_at, attested_at,
			attestation_provider, attestation_expires_at, issued_at, expires_at,
			installation_family_id, client_component_id, component_definition_id,
			component_kind, component_is_root, trust_source, component_session_family_id
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,'app_verified','firebase',
			$10,$11,$10,'app_attest',$11,$12,$13,$14,$15,'ios-main',
			'main_app',true,'direct_attested',$16
		)
	`, sessionGrantID, organizationID, applicationID, base.environmentID, base.userID,
		base.installationID, bytes.Repeat([]byte{0x7d}, 32), componentJKT, revisionID,
		createdAt, now.Add(time.Hour), now.Add(-5*time.Minute), now.Add(5*time.Minute),
		familyID, componentID, sessionFamilyID); err != nil {
		t.Fatal(err)
	}
	refreshHash := bytes.Repeat([]byte{0x4f}, 32)
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_refresh_tokens (
			component_refresh_token_id, component_session_family_id,
			client_component_id, component_key_id, session_grant_id, grant_kind,
			token_hash, status, issued_at, expires_at
		) VALUES ($1,$2,$3,$4,$5,'session',$6,'active',$7,$8)
	`, refreshTokenID, sessionFamilyID, componentID, componentKeyID, sessionGrantID,
		refreshHash, createdAt, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO refresh_rotation_results (
			refresh_rotation_result_id, old_refresh_token_hash, client_component_id,
			component_key_id, dpop_jkt, rotation_response_ciphertext,
			rotation_response_nonce, encryption_format_version,
			encryption_algorithm, master_key_identifier, created_at, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,1,'AES-256-GCM','test-master',$8,$9)
	`, rotationResultID, refreshHash, componentID, componentKeyID, componentJKT,
		bytes.Repeat([]byte{0x51}, 17), bytes.Repeat([]byte{0x52}, 12),
		now.Add(-2*time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	insertChallenge := func(challengeID string, createdAt, expiresAt time.Time, marker byte) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO component_attestation_challenges (
				component_attestation_challenge_id, organization_id, application_id,
				environment_id, application_user_id, installation_family_id,
				client_component_id, component_key_id, config_revision_id,
				platform, dpop_jkt, nonce_hash, binding_hash, challenge_nonce,
				attestation_policy_id, attestation_provider, attestation_mode,
				attestation_minimum_trust_level,
				attestation_maximum_age_milliseconds, created_at, expires_at
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,'ios',$10,$11,$12,$13,
				'native','app_attest','required','app_verified',60000,$14,$15
			)
		`, challengeID, organizationID, applicationID, base.environmentID, base.userID,
			familyID, componentID, componentKeyID, revisionID, componentJKT,
			bytes.Repeat([]byte{marker}, 32), bytes.Repeat([]byte{marker + 1}, 32),
			strings.Repeat(string(rune('C'+marker%20)), 43), createdAt, expiresAt); err != nil {
			t.Fatal(err)
		}
	}
	insertChallenge(expiredChallengeID, now.Add(-2*time.Minute), now.Add(-time.Minute), 0x11)
	insertChallenge(secondExpiredChallengeID, now.Add(-2*time.Minute), now.Add(-time.Minute), 0x21)
	insertChallenge(liveChallengeID, now.Add(-time.Minute), now.Add(5*time.Minute), 0x31)

	return workerComponentMaintenanceFixture{
		componentID: componentID, refreshTokenID: refreshTokenID, sessionFamilyID: sessionFamilyID,
		sessionGrantID: sessionGrantID, rotationResultID: rotationResultID,
		expiredChallengeID:       expiredChallengeID,
		secondExpiredChallengeID: secondExpiredChallengeID,
		liveChallengeID:          liveChallengeID,
	}
}

func runConcurrentMaintenance(t *testing.T, runs ...func() (int64, error)) int64 {
	t.Helper()
	start := make(chan struct{})
	counts := make(chan int64, len(runs))
	errorsChannel := make(chan error, len(runs))
	for _, run := range runs {
		go func(run func() (int64, error)) {
			<-start
			count, err := run()
			counts <- count
			errorsChannel <- err
		}(run)
	}
	close(start)
	var total int64
	for range runs {
		total += <-counts
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
	return total
}
