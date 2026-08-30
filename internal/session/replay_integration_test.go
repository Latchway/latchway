package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/id"
)

func TestReplayInputValidation(t *testing.T) {
	valid := ReplayInput{
		OrganizationID: replayTestID(t, id.Organization),
		ApplicationID:  replayTestID(t, id.Application),
		EnvironmentID:  replayTestID(t, id.Environment),
		InstallationID: replayTestID(t, id.Installation),
		SessionGrantID: replayTestID(t, id.SessionGrant),
		ProofJTI:       "unit-proof-identifier",
		HTTPMethod:     "POST",
		NormalizedURI:  "https://gateway.example.test/v1/responses",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid replay input failed validation: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ReplayInput)
	}{
		{name: "organization ID", mutate: func(input *ReplayInput) { input.OrganizationID = "invalid" }},
		{name: "application ID", mutate: func(input *ReplayInput) { input.ApplicationID = "invalid" }},
		{name: "environment ID", mutate: func(input *ReplayInput) { input.EnvironmentID = "invalid" }},
		{name: "installation ID", mutate: func(input *ReplayInput) { input.InstallationID = "invalid" }},
		{name: "session grant ID", mutate: func(input *ReplayInput) { input.SessionGrantID = "invalid" }},
		{name: "empty proof ID", mutate: func(input *ReplayInput) { input.ProofJTI = "" }},
		{name: "oversized proof ID", mutate: func(input *ReplayInput) { input.ProofJTI = strings.Repeat("a", maximumReplayJTIBytes+1) }},
		{name: "control in proof ID", mutate: func(input *ReplayInput) { input.ProofJTI = "proof\nidentifier" }},
		{name: "lowercase method", mutate: func(input *ReplayInput) { input.HTTPMethod = "post" }},
		{name: "short method", mutate: func(input *ReplayInput) { input.HTTPMethod = "GO" }},
		{name: "long method", mutate: func(input *ReplayInput) { input.HTTPMethod = "VERYLONGHTTP" }},
		{name: "relative URI", mutate: func(input *ReplayInput) { input.NormalizedURI = "/v1/responses" }},
		{name: "query URI", mutate: func(input *ReplayInput) { input.NormalizedURI += "?ignored=true" }},
		{name: "fragment URI", mutate: func(input *ReplayInput) { input.NormalizedURI += "#fragment" }},
		{name: "userinfo URI", mutate: func(input *ReplayInput) { input.NormalizedURI = "https://user@gateway.example.test/v1/responses" }},
		{name: "uppercase host URI", mutate: func(input *ReplayInput) { input.NormalizedURI = "https://GATEWAY.example.test/v1/responses" }},
		{name: "default port URI", mutate: func(input *ReplayInput) { input.NormalizedURI = "https://gateway.example.test:443/v1/responses" }},
		{name: "oversized URI", mutate: func(input *ReplayInput) {
			input.NormalizedURI = "https://gateway.example.test/" + strings.Repeat("a", maximumReplayURIBytes)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			err := input.validate()
			if !errors.Is(err, ErrReplayInvalid) {
				t.Fatalf("invalid replay input returned %v", err)
			}
			if (input.ProofJTI != "" && strings.Contains(err.Error(), input.ProofJTI)) ||
				(input.NormalizedURI != "" && strings.Contains(err.Error(), input.NormalizedURI)) {
				t.Fatal("validation error disclosed a raw proof identifier or URI")
			}
		})
	}
}

func TestReplayStoreConfigurationAndCleanupValidation(t *testing.T) {
	if _, err := NewReplayStore(ReplayStoreConfig{}); err == nil {
		t.Fatal("nil database pool was accepted")
	}
	placeholderPool := new(pgxpool.Pool)
	if _, err := NewReplayStore(ReplayStoreConfig{Pool: placeholderPool, Lifetime: minimumReplayLifetime - time.Nanosecond}); err == nil {
		t.Fatal("unsafe replay lifetime was accepted")
	}
	if _, err := NewReplayStore(ReplayStoreConfig{Pool: placeholderPool, Lifetime: maximumReplayLifetime + time.Nanosecond}); err == nil {
		t.Fatal("excessive replay lifetime was accepted")
	}
	store := &ReplayStore{}
	now := time.Now()
	store.now = func() time.Time { return now }
	for _, input := range []struct {
		before time.Time
		limit  int
	}{
		{before: time.Time{}, limit: 1},
		{before: now.Add(time.Nanosecond), limit: 1},
		{before: now, limit: 0},
		{before: now, limit: maximumCleanupBatch + 1},
	} {
		if _, err := store.DeleteExpired(context.Background(), input.before, input.limit); err == nil {
			t.Fatal("invalid cleanup input was accepted")
		}
	}
}

func TestReplayStorePostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	fixture := createReplayFixture(t, ctx, pool)
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store, err := NewReplayStore(ReplayStoreConfig{
		Pool: pool, Now: func() time.Time { return now }, Lifetime: defaultReplayLifetime,
	})
	if err != nil {
		t.Fatalf("construct replay store: %v", err)
	}
	baseInput := ReplayInput{
		OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
		EnvironmentID: fixture.environmentID, InstallationID: fixture.installationID,
		SessionGrantID: fixture.sessionGrantID,
		ProofJTI:       "proof-identifier-not-for-persistence", HTTPMethod: "POST",
		NormalizedURI: "https://gateway.example.test/v1/responses",
	}

	if err := store.Accept(ctx, baseInput); err != nil {
		t.Fatalf("accept first proof: %v", err)
	}
	if err := store.Accept(ctx, baseInput); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("duplicate proof did not return the stable replay error: %v", err)
	}
	crossGrantReplay := baseInput
	crossGrantReplay.SessionGrantID = fixture.secondSessionGrantID
	if err := store.Accept(ctx, crossGrantReplay); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("same installation proof reused through a second grant was accepted: %v", err)
	}
	assertReplayDigestsOnly(t, ctx, pool, baseInput)

	concurrentInput := baseInput
	concurrentInput.ProofJTI = "concurrent-proof-identifier"
	assertSingleReplayAcceptance(t, ctx, store, concurrentInput)

	var countBeforeScopeChecks int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM dpop_replay_entries").Scan(&countBeforeScopeChecks); err != nil {
		t.Fatalf("count replay entries before scope checks: %v", err)
	}
	unknownGrant := baseInput
	unknownGrant.ProofJTI = "unknown-grant-proof"
	unknownGrant.SessionGrantID = replayTestID(t, id.SessionGrant)
	if err := store.Accept(ctx, unknownGrant); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("unknown session grant did not fail closed: %v", err)
	}
	unknownInstallation := baseInput
	unknownInstallation.ProofJTI = "unknown-installation-proof"
	unknownInstallation.InstallationID = replayTestID(t, id.Installation)
	if err := store.Accept(ctx, unknownInstallation); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("unknown installation did not fail closed: %v", err)
	}
	wrongScope := baseInput
	wrongScope.ProofJTI = "wrong-scope-proof"
	wrongScope.OrganizationID = replayTestID(t, id.Organization)
	if err := store.Accept(ctx, wrongScope); !errors.Is(err, ErrSessionScope) {
		t.Fatalf("mismatched tenant scope did not fail closed: %v", err)
	}
	var countAfterScopeChecks int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM dpop_replay_entries").Scan(&countAfterScopeChecks); err != nil {
		t.Fatalf("count replay entries after scope checks: %v", err)
	}
	if countAfterScopeChecks != countBeforeScopeChecks {
		t.Fatal("failed scope checks persisted replay entries")
	}

	now = now.Add(-2 * time.Hour)
	for index := range 5 {
		cleanupInput := baseInput
		cleanupInput.ProofJTI = fmt.Sprintf("expired-cleanup-proof-%d", index)
		if err := store.Accept(ctx, cleanupInput); err != nil {
			t.Fatalf("seed expired replay digest %d: %v", index, err)
		}
	}
	cleanupBefore := now.Add(2 * time.Hour)
	now = cleanupBefore
	deleted := concurrentReplayCleanup(t, ctx, store, cleanupBefore, 2, 2)
	if deleted != 4 {
		t.Fatalf("concurrent cleanup deleted %d rows, want 4", deleted)
	}
	var expiredRemaining int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM dpop_replay_entries WHERE expires_at <= $1", cleanupBefore).Scan(&expiredRemaining); err != nil {
		t.Fatalf("count expired replay entries: %v", err)
	}
	if expiredRemaining != 1 {
		t.Fatalf("bounded cleanup left %d expired rows, want 1", expiredRemaining)
	}
	finalDeleted, err := store.DeleteExpired(ctx, cleanupBefore, 10)
	if err != nil {
		t.Fatalf("delete final expired replay digest: %v", err)
	}
	if finalDeleted != 1 {
		t.Fatalf("final cleanup deleted %d rows, want 1", finalDeleted)
	}
	var activeRemaining int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM dpop_replay_entries").Scan(&activeRemaining); err != nil {
		t.Fatalf("count active replay entries: %v", err)
	}
	if activeRemaining != 2 {
		t.Fatalf("cleanup removed unexpired entries: remaining=%d want=2", activeRemaining)
	}
}

type replayFixture struct {
	organizationID       string
	applicationID        string
	environmentID        string
	installationID       string
	sessionGrantID       string
	secondSessionGrantID string
}

func createReplayFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) replayFixture {
	t.Helper()
	challengeFixture := createChallengeFixture(t, ctx, pool)
	fixture := replayFixture{
		organizationID:       challengeFixture.organizationID,
		applicationID:        challengeFixture.applicationID,
		environmentID:        challengeFixture.environmentID,
		installationID:       replayTestID(t, id.Installation),
		sessionGrantID:       replayTestID(t, id.SessionGrant),
		secondSessionGrantID: replayTestID(t, id.SessionGrant),
	}
	adminUserID := replayTestID(t, id.AdminUser)
	adminMembershipID := replayTestID(t, id.AdminMembership)
	policyRevisionID := replayTestID(t, id.ConfigRevision)
	dpopJKT := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, sha256.Size))
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name)
		VALUES ($1, 'replay@example.test', 'replay@example.test', 'Replay Test')
	`, adminUserID); err != nil {
		t.Fatalf("create replay admin user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role)
		VALUES ($1, $2, $3, 'owner')
	`, adminMembershipID, fixture.organizationID, adminUserID); err != nil {
		t.Fatalf("create replay admin membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, 1, 'replay-etag-0001', 'draft', '{}'::jsonb, $5, $6)
	`, policyRevisionID, fixture.organizationID, fixture.applicationID, fixture.environmentID, adminUserID, now); err != nil {
		t.Fatalf("create replay policy revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id,
			application_user_id, platform, dpop_jkt, dpop_public_jwk,
			key_storage, trust_level, created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, 'ios', $6, '{"kty":"EC"}'::jsonb,
		          'secure_enclave', 'app_verified', $7, $7, $7)
	`, fixture.installationID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
		challengeFixture.applicationUserID, dpopJKT, now); err != nil {
		t.Fatalf("create replay installation: %v", err)
	}
	for index, sessionGrantID := range []string{fixture.sessionGrantID, fixture.secondSessionGrantID} {
		accessTokenJTIHash := sha256.Sum256([]byte(fmt.Sprintf("replay-fixture-access-token-%d", index)))
		if _, err := pool.Exec(ctx, `
			INSERT INTO session_grants (
				session_grant_id, organization_id, application_id, environment_id,
				application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
				policy_revision_id, trust_level, identity_verified_at, attested_at,
				attestation_provider, attestation_expires_at, issued_at, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'app_verified',
			          $10, $10, 'app_attest', $11, $12, $13)
		`, sessionGrantID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
			challengeFixture.applicationUserID, fixture.installationID, accessTokenJTIHash[:], dpopJKT,
			policyRevisionID, now.Add(-time.Minute), now.Add(10*time.Minute), now, now.Add(time.Hour)); err != nil {
			t.Fatalf("create replay session grant %d: %v", index, err)
		}
	}
	return fixture
}

func assertReplayDigestsOnly(t *testing.T, ctx context.Context, pool *pgxpool.Pool, input ReplayInput) {
	t.Helper()
	expectedJTIHash := sha256.Sum256([]byte(input.ProofJTI))
	expectedURIHash := sha256.Sum256([]byte(input.NormalizedURI))
	var storedJTIHash, storedURIHash []byte
	var storedInstallationID, storedSessionGrantID, storedMethod, serializedRow string
	if err := pool.QueryRow(ctx, `
		SELECT installation_id, session_grant_id, proof_jti_hash, http_uri_hash,
		       http_method, to_jsonb(replay)::text
		FROM dpop_replay_entries AS replay
		WHERE installation_id = $1 AND proof_jti_hash = $2
	`, input.InstallationID, expectedJTIHash[:]).Scan(
		&storedInstallationID, &storedSessionGrantID, &storedJTIHash, &storedURIHash,
		&storedMethod, &serializedRow,
	); err != nil {
		t.Fatalf("read persisted replay digest: %v", err)
	}
	if storedInstallationID != input.InstallationID || storedSessionGrantID != input.SessionGrantID ||
		!bytes.Equal(storedJTIHash, expectedJTIHash[:]) || !bytes.Equal(storedURIHash, expectedURIHash[:]) || storedMethod != input.HTTPMethod {
		t.Fatal("persisted replay binding does not match its digests")
	}
	if strings.Contains(serializedRow, input.ProofJTI) || strings.Contains(serializedRow, input.NormalizedURI) {
		t.Fatal("persisted replay row contains a raw proof identifier or URI")
	}
}

func assertSingleReplayAcceptance(t *testing.T, ctx context.Context, store *ReplayStore, input ReplayInput) {
	t.Helper()
	const workers = 16
	results := make(chan error, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- store.Accept(ctx, input)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var accepted, replayed int
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrDPoPReplayed):
			replayed++
		default:
			t.Fatalf("unexpected concurrent replay result: %v", err)
		}
	}
	if accepted != 1 || replayed != workers-1 {
		t.Fatalf("concurrent replay accepted=%d replayed=%d", accepted, replayed)
	}
}

func concurrentReplayCleanup(t *testing.T, ctx context.Context, store *ReplayStore, before time.Time, workers, limit int) int64 {
	t.Helper()
	results := make(chan int64, workers)
	failures := make(chan error, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			deleted, err := store.DeleteExpired(ctx, before, limit)
			results <- deleted
			failures <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("concurrent replay cleanup: %v", err)
		}
	}
	var deleted int64
	for count := range results {
		deleted += count
	}
	return deleted
}

func replayTestID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate replay fixture ID: %v", err)
	}
	return value
}
