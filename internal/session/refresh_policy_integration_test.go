package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

type countedAccessIssuer struct {
	delegate AccessIssuer
	prepares atomic.Int64
	issues   atomic.Int64
}

func (issuer *countedAccessIssuer) Prepare(ctx context.Context) (PreparedAccessIssuer, error) {
	prepared, err := issuer.delegate.Prepare(ctx)
	if err != nil {
		return nil, err
	}
	issuer.prepares.Add(1)
	return &countedPreparedAccessIssuer{delegate: prepared, issues: &issuer.issues}, nil
}

type countedPreparedAccessIssuer struct {
	delegate PreparedAccessIssuer
	issues   *atomic.Int64
}

func (*countedPreparedAccessIssuer) preparedAccessIssuer() {}

func (issuer *countedPreparedAccessIssuer) IssueFor(input AccessIssueInput, lifetime time.Duration) (IssuedAccess, error) {
	issuer.issues.Add(1)
	return issuer.delegate.IssueFor(input, lifetime)
}

type refreshPolicyTestSession struct {
	issued IssuedSession
	key    *ecdsa.PrivateKey
}

type refreshPolicyCounts struct {
	grants  int
	refresh int
	replays int
}

func TestRefreshUsesCurrentActivePolicyPostgreSQL(t *testing.T) {
	pool, ctx := isolatedSessionPool(t)
	issuedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	operationNow := issuedAt.Add(2 * time.Minute)
	currentNow := issuedAt
	fixture := createChallengeFixture(t, ctx, pool)
	initialRevisionID := activateChallengeTestRevision(t, ctx, pool, fixture, issuedAt)
	configurationStore, err := configuration.NewStore(pool)
	if err != nil {
		t.Fatalf("construct refresh-policy configuration store: %v", err)
	}
	challengeStore, err := newChallengeStore(ChallengeStoreConfig{
		Pool: pool, Configuration: configurationStore, Now: func() time.Time { return currentNow },
	})
	if err != nil {
		t.Fatalf("construct refresh-policy challenge store: %v", err)
	}
	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32)))
	if err != nil {
		t.Fatalf("construct refresh-policy signing envelope: %v", err)
	}
	keyManager, err := NewSigningKeyManager(SigningKeyManagerConfig{
		Pool: pool, Envelope: envelope, Now: func() time.Time { return currentNow },
		KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("construct refresh-policy key manager: %v", err)
	}
	accessIssuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keyManager, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return currentNow },
	})
	if err != nil {
		t.Fatalf("construct refresh-policy access issuer: %v", err)
	}
	countedIssuer := &countedAccessIssuer{delegate: accessIssuer}
	store, err := NewStore(StoreConfig{
		Pool: pool, AccessTokens: countedIssuer, Configuration: configurationStore,
		Now: func() time.Time { return currentNow },
	})
	if err != nil {
		t.Fatalf("construct refresh-policy session store: %v", err)
	}

	tests := []struct {
		name                string
		identityProviders   []any
		attestationPolicies []any
		wantErr             error
	}{
		{
			name:                "compatible new revision",
			identityProviders:   refreshIdentityProviders("firebase"),
			attestationPolicies: refreshAttestationPolicies(refreshDebugPolicy("native", "10m", "debug")),
		},
		{
			name:                "minimum trust tightened",
			identityProviders:   refreshIdentityProviders("firebase"),
			attestationPolicies: refreshAttestationPolicies(refreshDebugPolicy("native", "10m", "strong_device_verified")),
			wantErr:             ErrAttestationStepUpRequired,
		},
		{
			name:                "maximum age tightened",
			identityProviders:   refreshIdentityProviders("firebase"),
			attestationPolicies: refreshAttestationPolicies(refreshDebugPolicy("native", "1m", "debug")),
			wantErr:             ErrAttestationStepUpRequired,
		},
		{
			name:                "maximum age boundary reached",
			identityProviders:   refreshIdentityProviders("firebase"),
			attestationPolicies: refreshAttestationPolicies(refreshDebugPolicy("native", "2m", "debug")),
			wantErr:             ErrAttestationStepUpRequired,
		},
		{
			name:              "provider changed",
			identityProviders: refreshIdentityProviders("firebase"),
			attestationPolicies: refreshAttestationPolicies(map[string]any{
				"id": "native", "maxAge": "10m", "platforms": map[string]any{
					"ios": map[string]any{"provider": "app_attest", "mode": "required", "minimumTrustLevel": "app_verified"},
				},
			}),
			wantErr: ErrAttestationStepUpRequired,
		},
		{
			name:                "required policy removed",
			identityProviders:   refreshIdentityProviders("firebase"),
			attestationPolicies: []any{},
			wantErr:             ErrAttestationStepUpRequired,
		},
		{
			name:              "required policy ambiguous",
			identityProviders: refreshIdentityProviders("firebase"),
			attestationPolicies: refreshAttestationPolicies(
				refreshDebugPolicy("native-a", "10m", "debug"),
				refreshDebugPolicy("native-b", "10m", "debug"),
			),
			wantErr: ErrAttestationStepUpRequired,
		},
		{
			name:                "identity provider removed",
			identityProviders:   refreshIdentityProviders("replacement"),
			attestationPolicies: refreshAttestationPolicies(refreshDebugPolicy("native", "10m", "debug")),
			wantErr:             ErrIdentityRefreshRequired,
		},
	}

	challengeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
	exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
	refreshURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions/refresh")
	sessions := make([]refreshPolicyTestSession, len(tests))
	for index := range tests {
		key, jwk, jkt := newChallengeKey(t)
		label := fmt.Sprintf("refresh-policy-%d", index)
		challenge, err := challengeStore.Create(ctx, withChallengeProof(ChallengeInput{
			OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID,
			EnvironmentID: fixture.environmentID, ConfigurationRevisionID: initialRevisionID,
			EnvironmentSlug: "development", ApplicationUserID: fixture.applicationUserID,
			IdentityProvider: "firebase", IdentityVerifiedAt: issuedAt,
			IdentityExpiresAt: issuedAt.Add(time.Hour), Platform: "ios",
			DPoPJKT: jkt, DPoPPublicJWK: jwk,
		}, challengeURI, issuedAt, label+"-challenge"))
		if err != nil {
			t.Fatalf("create %s challenge: %v", tests[index].name, err)
		}
		issued, err := store.Exchange(ctx, ExchangeInput{
			ChallengeID: challenge.ID,
			Attestation: verifiedDebugAttestation(t, challenge.Binding, issuedAt, label+"-exchange"),
			DPoPProof:   signedSessionDPoP(t, key, "POST", exchangeURI, issuedAt, label+"-exchange"),
			HTTPMethod:  "POST", RequestURI: exchangeURI, KeyStorage: "software", AppVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("exchange %s session: %v", tests[index].name, err)
		}
		sessions[index] = refreshPolicyTestSession{issued: issued, key: key}
	}
	if got := countedIssuer.issues.Load(); got != int64(len(tests)) {
		t.Fatalf("initial access token issues=%d want=%d", got, len(tests))
	}
	currentNow = operationNow

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			revisionID := activateRefreshPolicyRevision(t, ctx, pool, fixture, initialRevisionID,
				int64(index+2), operationNow.Add(time.Duration(index)*time.Second),
				test.identityProviders, test.attestationPolicies)
			beforeCounts := loadRefreshPolicyCounts(t, ctx, pool)
			beforePrepares := countedIssuer.prepares.Load()
			beforeIssues := countedIssuer.issues.Load()
			candidate := sessions[index]
			rotated, rotateErr := store.Rotate(ctx, RotateInput{
				RefreshToken: candidate.issued.Refresh,
				DPoPProof: signedSessionDPoP(t, candidate.key, "POST", refreshURI, operationNow,
					fmt.Sprintf("refresh-policy-rotate-%d", index)),
				HTTPMethod: "POST", RequestURI: refreshURI,
			})
			if test.wantErr == nil {
				if rotateErr != nil {
					t.Fatalf("rotate under compatible current policy: %v", rotateErr)
				}
				binding, err := store.InspectRefresh(ctx, rotated.Refresh)
				if err != nil || binding.Status != "active" || binding.PolicyRevisionID != revisionID || binding.AttestationProvider != "debug" || binding.TrustLevel != "debug" {
					t.Fatalf("compatible rotation did not bind current policy: binding=%#v err=%v", binding, err)
				}
				afterCounts := loadRefreshPolicyCounts(t, ctx, pool)
				if afterCounts != (refreshPolicyCounts{grants: beforeCounts.grants + 1, refresh: beforeCounts.refresh + 1, replays: beforeCounts.replays + 1}) ||
					countedIssuer.prepares.Load() != beforePrepares+1 || countedIssuer.issues.Load() != beforeIssues+1 {
					t.Fatalf("compatible rotation mutations=%#v before=%#v prepares=%d issues=%d", afterCounts, beforeCounts, countedIssuer.prepares.Load()-beforePrepares, countedIssuer.issues.Load()-beforeIssues)
				}
				return
			}
			if !errors.Is(rotateErr, test.wantErr) {
				t.Fatalf("rotate error=%v want=%v", rotateErr, test.wantErr)
			}
			if got := loadRefreshPolicyCounts(t, ctx, pool); got != beforeCounts {
				t.Fatalf("rejected rotation mutated session state: before=%#v after=%#v", beforeCounts, got)
			}
			if countedIssuer.prepares.Load() != beforePrepares || countedIssuer.issues.Load() != beforeIssues {
				t.Fatalf("rejected rotation prepared or issued an access token: prepares=%d issues=%d", countedIssuer.prepares.Load()-beforePrepares, countedIssuer.issues.Load()-beforeIssues)
			}
			assertRefreshRemainsUnused(t, ctx, pool, candidate.issued)
		})
	}
}

func refreshIdentityProviders(ids ...string) []any {
	providers := make([]any, 0, len(ids))
	for _, providerID := range ids {
		providers = append(providers, map[string]any{"id": providerID, "type": "firebase"})
	}
	return providers
}

func refreshDebugPolicy(policyID, maximumAge, minimumTrust string) map[string]any {
	return map[string]any{
		"id": policyID, "maxAge": maximumAge, "platforms": map[string]any{
			"ios": map[string]any{
				"provider": "debug", "mode": "required", "minimumTrustLevel": minimumTrust,
				"secretRef": "secret/debug-attestation-public-keys",
			},
		},
	}
}

func refreshAttestationPolicies(policies ...map[string]any) []any {
	result := make([]any, 0, len(policies))
	for _, policy := range policies {
		result = append(result, policy)
	}
	return result
}

func activateRefreshPolicyRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	fixture challengeFixture, previousRevisionID string, revisionNumber int64, activatedAt time.Time,
	identityProviders, attestationPolicies []any) string {
	t.Helper()
	var adminUserID string
	if err := pool.QueryRow(ctx, `
		SELECT created_by_admin_user_id FROM config_revisions WHERE config_revision_id = $1
	`, previousRevisionID).Scan(&adminUserID); err != nil {
		t.Fatalf("resolve refresh-policy revision owner: %v", err)
	}
	compiled, err := json.Marshal(map[string]any{"spec": map[string]any{
		"identityProviders": identityProviders, "attestationPolicies": attestationPolicies,
	}})
	if err != nil {
		t.Fatalf("encode refresh-policy revision: %v", err)
	}
	revisionID := mustSessionID(t, id.ConfigRevision)
	etag := fmt.Sprintf("refresh-policy-etag-%04d", revisionNumber)
	if _, err := pool.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, compiled_document,
			validation_report, created_by_admin_user_id, validated_at, activated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, 'valid', '{}'::jsonb, $9::jsonb,
			'{"valid":true,"checked_at":"2026-08-27T12:00:00Z","issues":[]}'::jsonb,
			$7, $8, $8
		)
	`, revisionID, fixture.organizationID, fixture.applicationID, fixture.environmentID,
		revisionNumber, etag, adminUserID, activatedAt, compiled); err != nil {
		t.Fatalf("create refresh-policy revision: %v", err)
	}
	command, err := pool.Exec(ctx, `
		UPDATE active_config_revisions
		SET config_revision_id = $1, activated_by_admin_user_id = $2, activated_at = $3
		WHERE organization_id = $4 AND application_id = $5 AND environment_id = $6
	`, revisionID, adminUserID, activatedAt, fixture.organizationID, fixture.applicationID, fixture.environmentID)
	if err != nil {
		t.Fatalf("activate refresh-policy revision: %v", err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("activate refresh-policy revision rows=%d want=1", command.RowsAffected())
	}
	return revisionID
}

func loadRefreshPolicyCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) refreshPolicyCounts {
	t.Helper()
	var result refreshPolicyCounts
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM session_grants),
			(SELECT count(*) FROM refresh_tokens),
			(SELECT count(*) FROM dpop_replay_entries)
	`).Scan(&result.grants, &result.refresh, &result.replays); err != nil {
		t.Fatalf("count refresh-policy session state: %v", err)
	}
	return result
}

func assertRefreshRemainsUnused(t *testing.T, ctx context.Context, pool *pgxpool.Pool, issued IssuedSession) {
	t.Helper()
	var status string
	var unused, unlinked, grantLive bool
	if err := pool.QueryRow(ctx, `
		SELECT r.status, r.used_at IS NULL, r.rotated_to_refresh_token_id IS NULL, g.revoked_at IS NULL
		FROM refresh_tokens r
		JOIN session_grants g ON g.session_grant_id = r.session_grant_id
		WHERE r.refresh_token_id = $1 AND r.session_grant_id = $2
	`, issued.RefreshID, issued.GrantID).Scan(&status, &unused, &unlinked, &grantLive); err != nil {
		t.Fatalf("inspect rejected refresh state: %v", err)
	}
	if status != "active" || !unused || !unlinked || !grantLive {
		t.Fatalf("rejected refresh was consumed or revoked: status=%q unused=%t unlinked=%t grant_live=%t", status, unused, unlinked, grantLive)
	}
}
