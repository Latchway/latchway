package policy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/session"
)

var policyIntegrationSchemaPattern = regexp.MustCompile(`^latchway_policy_test_[0-9]+$`)

func TestResolveFromDurableSealedAuthorizationPostgreSQL(t *testing.T) {
	pool, ctx := isolatedPolicyPool(t)
	now := time.Now().UTC().Truncate(time.Second)

	organizationID := policyIntegrationID(t, id.Organization)
	applicationID := policyIntegrationID(t, id.Application)
	environmentID := policyIntegrationID(t, id.Environment)
	userID := policyIntegrationID(t, id.ApplicationUser)
	installationID := policyIntegrationID(t, id.Installation)
	grantID := policyIntegrationID(t, id.SessionGrant)
	revisionID := policyIntegrationID(t, id.ConfigRevision)
	adminID := policyIntegrationID(t, id.AdminUser)
	membershipID := policyIntegrationID(t, id.AdminMembership)
	dpopJKT := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))

	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, 'policy-test', 'Policy Test', $2, $2)
	`, organizationID, now); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO applications (application_id, organization_id, slug, display_name, created_at, updated_at)
		VALUES ($1, $2, 'policy-app', 'Policy App', $3, $3)
	`, applicationID, organizationID, now); err != nil {
		t.Fatalf("create application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind, created_at, updated_at
		) VALUES ($1, $2, $3, 'production', 'Production', 'production', $4, $4)
	`, environmentID, organizationID, applicationID, now); err != nil {
		t.Fatalf("create environment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_users (
			admin_user_id, email, email_normalized, display_name, created_at, updated_at
		) VALUES ($1, 'policy@example.test', 'policy@example.test', 'Policy Test', $2, $2)
	`, adminID, now); err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role, created_at, updated_at
		) VALUES ($1, $2, $3, 'owner', $4, $4)
	`, membershipID, organizationID, adminID, now); err != nil {
		t.Fatalf("create admin membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, 1, 'policy-context-0001', 'draft', '{}'::jsonb, $5, $6)
	`, revisionID, organizationID, applicationID, environmentID, adminID, now); err != nil {
		t.Fatalf("create policy revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO application_users (
			application_user_id, organization_id, application_id, normalized_claims,
			created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, '{"plan":"premium","roles":["member"]}'::jsonb, $4, $4, $4)
	`, userID, organizationID, applicationID, now); err != nil {
		t.Fatalf("create application user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id,
			application_user_id, platform, dpop_jkt, dpop_public_jwk,
			key_storage, trust_level, created_at, updated_at, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, 'ios', $6, '{"kty":"EC"}'::jsonb,
		          'secure_enclave', 'device_verified', $7, $7, $7)
	`, installationID, organizationID, applicationID, environmentID, userID, dpopJKT, now); err != nil {
		t.Fatalf("create installation: %v", err)
	}

	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)))
	if err != nil {
		t.Fatalf("construct signing envelope: %v", err)
	}
	keys, err := session.NewSigningKeyManager(session.SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return now },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct signing-key manager: %v", err)
	}
	issuer, err := session.NewAccessTokenIssuer(session.AccessTokenIssuerConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Lifetime: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	issued, err := issuer.Issue(ctx, session.AccessIssueInput{
		OrganizationID: organizationID, ApplicationID: applicationID, EnvironmentID: environmentID,
		ApplicationUserID: userID, InstallationID: installationID, SessionGrantID: grantID,
		IdentityProvider: "firebase", TrustLevel: "device_verified",
		PolicyRevisionID: revisionID, DPoPJKT: dpopJKT,
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	attestedAt := issued.IssuedAt.Add(-time.Minute)
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash, dpop_jkt,
			policy_revision_id, trust_level, identity_verified_at, identity_provider_key,
			identity_expires_at, attested_at, attestation_provider, attestation_expires_at,
			issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'device_verified',
		          $10, 'firebase', $11, $10, 'app_attest', $12, $13, $14)
	`, grantID, organizationID, applicationID, environmentID, userID, installationID,
		issued.JTIHash[:], dpopJKT, revisionID, attestedAt, now.Add(2*time.Hour),
		now.Add(30*time.Minute), issued.IssuedAt, issued.ExpiresAt); err != nil {
		t.Fatalf("create session grant: %v", err)
	}

	verifier, err := session.NewAccessTokenVerifier(session.AccessTokenVerifierConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token verifier: %v", err)
	}
	principal, err := verifier.Verify(ctx, issued.Token)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct configuration store: %v", err)
	}
	sessions, err := session.NewStore(session.StoreConfig{
		Pool: pool, AccessTokens: issuer, Configuration: configurationStore,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct session store: %v", err)
	}
	authorization, err := sessions.Authorize(ctx, principal)
	if err != nil {
		t.Fatalf("load sealed authorization: %v", err)
	}

	requestContext, err := requestidentity.NewContext(ctx)
	if err != nil {
		t.Fatalf("install logical request identity: %v", err)
	}
	logicalID, ok := requestidentity.FromContext(requestContext)
	if !ok {
		t.Fatal("logical request identity missing")
	}
	input, err := NewInput(
		authorization, logicalID,
		ProtocolRequestMetadata{Streaming: true}, EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatalf("build authoritative policy input: %v", err)
	}
	if input.LogicalRequestID() != logicalID.String() || input.ApplicationUserID() != userID || input.InstallationID() != installationID {
		t.Fatalf("authoritative input identity mismatch: %#v", input)
	}

	snapshot := policySnapshot()
	snapshot.revision = revisionID
	snapshot.environment = environmentID
	resolver, err := newResolver(func() time.Time { return now })
	if err != nil {
		t.Fatalf("construct resolver: %v", err)
	}
	decision, err := resolver.Resolve(requestContext, snapshot, "assistant", input)
	if err != nil {
		t.Fatalf("resolve durable authorization: %v", err)
	}
	if decision.LimitPlan.ID != "premium" || decision.Route.ID != "premium-reasoning" || decision.Model.ID != "reasoning" {
		t.Fatalf("durable normalized claims did not drive expected decision: %+v", decision)
	}

	overrideID := policyIntegrationID(t, id.UserOverride)
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_overrides (
			user_override_id, organization_id, application_id, environment_id,
			application_user_id, override_document, reason,
			created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, '{"limit_plan":"free"}'::jsonb,
		          'policy integration override', $6, transaction_timestamp())
	`, overrideID, organizationID, applicationID, environmentID, userID, adminID); err != nil {
		t.Fatalf("create durable user override: %v", err)
	}
	overriddenAuthorization, err := sessions.Authorize(ctx, principal)
	if err != nil {
		t.Fatalf("load overridden sealed authorization: %v", err)
	}
	overriddenInput, err := NewInput(
		overriddenAuthorization, logicalID,
		ProtocolRequestMetadata{Streaming: true}, EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatalf("build overridden policy input: %v", err)
	}
	overriddenDecision, err := resolver.Resolve(requestContext, snapshot, "assistant", overriddenInput)
	if err != nil {
		t.Fatalf("resolve durable user override: %v", err)
	}
	if overriddenAuthorization.UserOverrideID != overrideID ||
		overriddenAuthorization.LimitPlanOverride != "free" ||
		overriddenDecision.LimitPlan.ID != "free" ||
		overriddenDecision.Route.ID != "premium-reasoning" {
		t.Fatalf("durable override did not replace only plan selection: authorization=%+v decision=%+v",
			overriddenAuthorization, overriddenDecision)
	}
	if _, err := newInputAt(
		authorization, logicalID, ProtocolRequestMetadata{Streaming: true}, EnvironmentFacts{Kind: "production"},
		issued.ExpiresAt,
	); !errors.Is(err, session.ErrTokenExpired) {
		t.Fatalf("NewInput access-expiry error = %v, want token expired", err)
	}
	if _, err := newInputAt(
		authorization, logicalID, ProtocolRequestMetadata{Streaming: true}, EnvironmentFacts{Kind: "production"},
		now.Add(30*time.Minute),
	); !errors.Is(err, session.ErrAttestationRefreshNeeded) {
		t.Fatalf("NewInput attestation-expiry error = %v, want refresh needed", err)
	}
}

func isolatedPolicyPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_policy_test_%d", time.Now().UnixNano())
	if !policyIntegrationSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create policy test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsedURL.Query()
	query.Set("search_path", schema)
	parsedURL.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsedURL.String(), 8)
	if err != nil {
		t.Fatalf("open isolated policy database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, ctx
}

func policyIntegrationID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
