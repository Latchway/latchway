package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientruntime"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
)

// This decoder stands in for Google's authenticated server-to-server response,
// not the Play verifier. The production verifier still binds and seals every
// result consumed by the database-backed session paths below.
type sessionPlayTestingDecoder struct{ response []byte }

func (*sessionPlayTestingDecoder) CloudProjectNumber() int64 { return 123456789 }
func (decoder *sessionPlayTestingDecoder) DecodeIntegrityToken(ctx context.Context, packageName, token string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if packageName != "com.example.challenge" || token != "test.integrity-token" {
		return nil, errors.New("unexpected Play test decoder request")
	}
	return append([]byte(nil), decoder.response...), nil
}

func verifiedSessionPlayAttestation(t *testing.T, binding attestation.Binding, now time.Time, testingResponse bool) attestation.Result {
	t.Helper()
	hash, err := binding.HashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	certificate := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	payload := map[string]any{
		"requestDetails":  map[string]any{"requestPackageName": "com.example.challenge", "requestHash": hash, "timestampMillis": strconv.FormatInt(now.UnixMilli(), 10)},
		"appIntegrity":    map[string]any{"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": "com.example.challenge", "certificateSha256Digest": []string{certificate}, "versionCode": "42"},
		"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": []string{"MEETS_DEVICE_INTEGRITY"}},
		"accountDetails":  map[string]any{"appLicensingVerdict": "LICENSED"},
	}
	if testingResponse {
		payload["testingDetails"] = map[string]any{"isTestingResponse": true}
	}
	response, err := json.Marshal(map[string]any{"tokenPayloadExternal": payload})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := attestation.NewPlayIntegrityVerifier(attestation.PlayIntegrityConfig{
		ApplicationID: binding.ApplicationID, EnvironmentID: binding.Environment,
		PackageName: "com.example.challenge", CloudProjectNumber: 123456789,
		CertificateSHA256Digests: []string{certificate}, MinimumDeviceIntegrity: "device",
		RequireLicensed: true, AllowTestingResponses: true,
		Decoder: &sessionPlayTestingDecoder{response: response}, Now: nowClock(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := attestation.NewEvidence("play_integrity", map[string]any{"integrity_token": "test.integrity-token"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(context.Background(), evidence, binding)
	if err != nil {
		t.Fatalf("verify trusted Play fixture: %v", err)
	}
	return result
}

func sessionPlayTestingPolicy(platform string, allowTesting, shared bool) []any {
	selection := map[string]any{
		"provider": "play_integrity", "mode": "required", "minimumTrustLevel": "device_verified",
		"playIntegrity": map[string]any{
			"packageName": "com.example.challenge", "cloudProjectNumber": 123456789,
			"certificateSha256Digests": []string{base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))},
			"minimumDeviceIntegrity":   "device", "requireLicensed": true, "allowTestingResponses": allowTesting,
			"minimumVersionCode": 0, "maximumVersionCode": 0, "credentialSource": "metadata",
		},
	}
	if shared {
		selection["sharedNativeCallers"] = []string{"android", "react-native"}
	}
	return []any{map[string]any{"id": "native", "maxAge": "10m", "platforms": map[string]any{platform: selection}}}
}

func activateSessionPlayTestingRevision(t *testing.T, ctx context.Context, pool *pgxpool.Pool, previous string, number int, now time.Time, platform string, allowTesting, shared bool) string {
	t.Helper()
	spec := sessionTestCompiledSpec(refreshIdentityProviders("firebase"), sessionPlayTestingPolicy(platform, allowTesting, shared))
	if shared {
		spec["componentDefinitions"] = json.RawMessage(`[{"id":"android-main","platform":"android","kind":"android_app","familyRole":"root","identifiers":{"packageNames":["com.example.challenge"]},"attestation":{"strategy":"direct","provider":"play_integrity"},"allowedFeatures":["assistant"]}]`)
	}
	compiled, err := json.Marshal(map[string]any{"spec": spec})
	if err != nil {
		t.Fatal(err)
	}
	revision := mustSessionID(t, id.ConfigRevision)
	if _, err := pool.Exec(ctx, `INSERT INTO config_revisions (config_revision_id, organization_id, application_id, environment_id,
		revision_number, etag, status, document, compiled_document, validation_report, created_by_admin_user_id, validated_at, activated_at)
		SELECT $2, organization_id, application_id, environment_id, $3, $4, 'valid', '{}'::jsonb, $5::jsonb,
		validation_report, created_by_admin_user_id, $6, $6 FROM config_revisions WHERE config_revision_id = $1`,
		previous, revision, number, fmt.Sprintf("play-testing-etag-%04d", number), compiled, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE active_config_revisions SET config_revision_id = $2, activated_at = $3 WHERE config_revision_id = $1`, previous, revision, now); err != nil {
		t.Fatal(err)
	}
	return revision
}

func loadPlayTestingSessionCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) [5]int {
	t.Helper()
	var counts [5]int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM session_grants), (SELECT count(*) FROM refresh_tokens),
		(SELECT count(*) FROM component_refresh_tokens), (SELECT count(*) FROM dpop_replay_entries), (SELECT count(*) FROM refresh_rotation_results)`).Scan(
		&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
		t.Fatal(err)
	}
	return counts
}

func TestPlayTestingSessionLifecyclePostgreSQL(t *testing.T) {
	for _, scenario := range []struct {
		name, platform, kind                          string
		allowTesting, testingResponse, shared, denied bool
	}{
		{name: "native-test", platform: "android", kind: "development", allowTesting: true, testingResponse: true},
		{name: "legacy-rn-test", platform: "react_native_android", kind: "development", allowTesting: true, testingResponse: true},
		{name: "shared-rn-test", platform: "android", kind: "development", allowTesting: true, testingResponse: true, shared: true},
		{name: "native-real", platform: "android", kind: "development", allowTesting: true},
		{name: "legacy-rn-real", platform: "react_native_android", kind: "development", allowTesting: true},
		{name: "shared-rn-real", platform: "android", kind: "development", allowTesting: true, shared: true},
		{name: "disabled-test", platform: "android", kind: "development", testingResponse: true, denied: true},
		{name: "production-test", platform: "react_native_android", kind: "production", testingResponse: true, denied: true},
		// A corrupt or historic active document must not bypass the independent
		// authoritative environment guard even if its test flag was enabled.
		{name: "production-forced-opt-in-test", platform: "android", kind: "production", allowTesting: true, testingResponse: true, denied: true},
		{name: "staging-test", platform: "android", kind: "staging", allowTesting: true, testingResponse: true, denied: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			pool, ctx := isolatedSessionPool(t)
			now := time.Now().UTC().Add(5 * time.Second).Truncate(time.Second)
			fixture := createChallengeFixture(t, ctx, pool)
			seedRevision := activateChallengeTestRevision(t, ctx, pool, fixture, now)
			revision := activateSessionPlayTestingRevision(t, ctx, pool, seedRevision, 2, now, scenario.platform, scenario.allowTesting, scenario.shared)
			if _, err := pool.Exec(ctx, `UPDATE environments SET kind = $2 WHERE environment_id = $1`, fixture.environmentID, scenario.kind); err != nil {
				t.Fatal(err)
			}
			config, err := configuration.NewStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			challenges, err := newChallengeStore(ChallengeStoreConfig{Pool: pool, Configuration: config, Now: nowClock(now)})
			if err != nil {
				t.Fatal(err)
			}
			key, jwk, jkt := newChallengeKey(t)
			challengeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/session-challenges")
			exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions")
			refreshURI := mustSessionURL(t, "https://gateway.example.test/client/v1/sessions/refresh")
			accessURI := mustSessionURL(t, "https://gateway.example.test/client/v1/installations/current")
			challenge, err := challenges.Create(ctx, withChallengeProof(ChallengeInput{
				OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID,
				ConfigurationRevisionID: revision, EnvironmentSlug: "development", ApplicationUserID: fixture.applicationUserID,
				IdentityProvider: "firebase", IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
				Platform: scenario.platform, DPoPJKT: jkt, DPoPPublicJWK: jwk,
			}, challengeURI, now, scenario.name+"-challenge"))
			if err != nil {
				t.Fatal(err)
			}
			result := verifiedSessionPlayAttestation(t, challenge.Binding, now, scenario.testingResponse)
			envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x75}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			keys, err := NewSigningKeyManager(SigningKeyManagerConfig{Pool: pool, Envelope: envelope, Now: nowClock(now), KeyLifetime: 48 * time.Hour, RotationLead: 24 * time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane", Now: nowClock(now)})
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane", Now: nowClock(now)})
			if err != nil {
				t.Fatal(err)
			}
			counted := &countedAccessIssuer{delegate: issuer}
			store, err := NewStore(StoreConfig{Pool: pool, AccessTokens: counted, Configuration: config, RotationProtector: envelope, Now: nowClock(now)})
			if err != nil {
				t.Fatal(err)
			}
			before := loadPlayTestingSessionCounts(t, ctx, pool)
			issued, err := store.Exchange(ctx, ExchangeInput{ChallengeID: challenge.ID, Attestation: result,
				DPoPProof: signedSessionDPoP(t, key, "POST", exchangeURI, now, scenario.name+"-exchange"), HTTPMethod: "POST", RequestURI: exchangeURI, KeyStorage: "software", AppVersion: "42"})
			if scenario.denied {
				if !errors.Is(err, ErrSessionInvalid) {
					t.Fatalf("test evidence accepted outside opt-in: %v", err)
				}
				if got := loadPlayTestingSessionCounts(t, ctx, pool); got != before || counted.issues.Load() != 0 {
					t.Fatal("denied exchange mutated session state")
				}
				if _, err := challenges.Get(ctx, challenge.ID); err != nil {
					t.Fatalf("denied exchange consumed challenge: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("exchange verified Play session: %v", err)
			}
			wantTrust := "device_verified"
			if scenario.testingResponse {
				wantTrust = "debug"
			}
			var runtime clientruntime.Declaration
			if scenario.shared {
				runtime = clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "react-native"}
			}
			assertAuthorized := func(issued IssuedSession, label string) {
				t.Helper()
				principal, err := verifier.Verify(ctx, issued.Access.Token)
				if err != nil {
					t.Fatal(err)
				}
				if principal.TrustLevel != wantTrust || (scenario.shared && (principal.AttestationProvider != "play_integrity" || !principal.ComponentIsRoot || principal.ComponentID == "")) {
					t.Fatalf("signed claims lost actual trust/provider: trust=%q provider=%q root=%t", principal.TrustLevel, principal.AttestationProvider, principal.ComponentIsRoot)
				}
				authorized, err := store.AuthorizeAccess(ctx, AccessRequestInput{AccessToken: issued.Access.Token, Principal: principal,
					DPoPProof: signedSessionAccessDPoP(t, key, "GET", accessURI, now, issued.Access.Token.Reveal(), label), HTTPMethod: "GET", RequestURI: accessURI, Runtime: runtime})
				if err != nil || authorized.TrustLevel != wantTrust || authorized.AttestationProvider != "play_integrity" || authorized.EnvironmentKind != scenario.kind {
					t.Fatalf("authorize actual Play trust: %v trust=%q", err, authorized.TrustLevel)
				}
			}
			assertAuthorized(issued, scenario.name+"-access")
			rotated, err := store.Rotate(ctx, RotateInput{RefreshToken: issued.Refresh, DPoPProof: signedSessionDPoP(t, key, "POST", refreshURI, now, scenario.name+"-refresh"), HTTPMethod: "POST", RequestURI: refreshURI, Runtime: runtime})
			if err != nil {
				t.Fatalf("rotate Play session under unchanged policy: %v", err)
			}
			assertAuthorized(rotated, scenario.name+"-rotated-access")
			var eventTrust string
			var testing bool
			if err := pool.QueryRow(ctx, `SELECT trust_level, COALESCE((normalized_signals->>'testing_response')::boolean, false) FROM attestation_events WHERE installation_id = $1`, issued.Installation.ID).Scan(&eventTrust, &testing); err != nil {
				t.Fatal(err)
			}
			if eventTrust != wantTrust || testing != scenario.testingResponse {
				t.Fatal("durable attestation event promoted or lost testing provenance")
			}

			nextRevision := activateSessionPlayTestingRevision(t, ctx, pool, revision, 3, now.Add(time.Second), scenario.platform, false, scenario.shared)
			before = loadPlayTestingSessionCounts(t, ctx, pool)
			beforeIssues, beforePrepares := counted.issues.Load(), counted.prepares.Load()
			_, err = store.Rotate(ctx, RotateInput{RefreshToken: rotated.Refresh, DPoPProof: signedSessionDPoP(t, key, "POST", refreshURI, now, scenario.name+"-after-disable"), HTTPMethod: "POST", RequestURI: refreshURI, Runtime: runtime})
			// Both real and simulated mobile grants re-attest after a revision
			// change; neither may silently carry old provider facts forward.
			if !errors.Is(err, ErrAttestationStepUpRequired) {
				t.Fatalf("new revision did not require fresh mobile attestation: %v", err)
			}
			if got := loadPlayTestingSessionCounts(t, ctx, pool); got != before || counted.issues.Load() != beforeIssues || counted.prepares.Load() != beforePrepares {
				t.Fatal("rejected refresh mutated state or issued tokens")
			}
			if scenario.shared {
				var active, unused, unlinked bool
				if err := pool.QueryRow(ctx, `SELECT status = 'active', used_at IS NULL, rotated_to_component_refresh_token_id IS NULL
					FROM component_refresh_tokens WHERE component_refresh_token_id = $1`, rotated.RefreshID).Scan(&active, &unused, &unlinked); err != nil || !active || !unused || !unlinked {
					t.Fatalf("rejected component rotation mutated existing token: %v", err)
				}
			} else {
				assertRefreshRemainsUnused(t, ctx, pool, rotated)
			}
			freshChallenge, err := challenges.Create(ctx, withChallengeProof(ChallengeInput{
				OrganizationID: fixture.organizationID, ApplicationID: fixture.applicationID, EnvironmentID: fixture.environmentID,
				ConfigurationRevisionID: nextRevision, EnvironmentSlug: "development", ApplicationUserID: fixture.applicationUserID,
				IdentityProvider: "firebase", IdentityVerifiedAt: now, IdentityExpiresAt: now.Add(time.Hour),
				Platform: scenario.platform, DPoPJKT: jkt, DPoPPublicJWK: jwk,
			}, challengeURI, now, scenario.name+"-fresh-challenge"))
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := store.Exchange(ctx, ExchangeInput{ChallengeID: freshChallenge.ID,
				Attestation: verifiedSessionPlayAttestation(t, freshChallenge.Binding, now, false),
				DPoPProof:   signedSessionDPoP(t, key, "POST", exchangeURI, now, scenario.name+"-fresh-exchange"), HTTPMethod: "POST", RequestURI: exchangeURI, KeyStorage: "software", AppVersion: "42"})
			if err != nil {
				t.Fatalf("fresh actual device proof under testing-disabled policy failed: %v", err)
			}
			wantTrust = "device_verified"
			assertAuthorized(fresh, scenario.name+"-fresh-access")
		})
	}
}

var _ attestation.PlayIntegrityTokenDecoder = (*sessionPlayTestingDecoder)(nil)
