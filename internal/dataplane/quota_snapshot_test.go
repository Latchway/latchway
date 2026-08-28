package dataplane

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/session"
)

func TestFeatureQuotaProviderAuthenticatesAndProjectsEffectiveRules(t *testing.T) {
	fixture := newFeatureQuotaFixture(t)
	provider := fixture.provider(t)

	result, err := provider.FeatureQuota(context.Background(), fixture.input)
	if err != nil {
		t.Fatalf("FeatureQuota() error = %v", err)
	}
	if result.Feature != fixture.input.Feature || !result.ObservedAt.Equal(fixture.observedAt) ||
		len(result.Limits) != 3 {
		t.Fatalf("FeatureQuota() = %+v", result)
	}
	if fixture.verifier.calls != 1 || fixture.sessions.calls != 1 ||
		fixture.snapshots.calls != 1 || fixture.policies.calls != 1 || fixture.quotas.calls != 1 {
		t.Fatalf("dependency calls = verifier:%d sessions:%d snapshots:%d policies:%d quotas:%d",
			fixture.verifier.calls, fixture.sessions.calls, fixture.snapshots.calls,
			fixture.policies.calls, fixture.quotas.calls)
	}
	if got := fixture.sessions.input.RequestURI.String(); got != "https://gateway.example/client/v1/features/assistant/quota" {
		t.Fatalf("authorized DPoP target = %q", got)
	}
	if fixture.sessions.input.HTTPMethod != http.MethodGet ||
		fixture.policies.feature != "assistant" ||
		fixture.policies.logicalID.String() != fixture.input.LogicalRequestID.String() ||
		fixture.policies.environment.Kind != "development" {
		t.Fatalf("trusted policy inputs were not preserved")
	}
	wantScope := configuration.TenantScope{
		OrganizationID: fixture.authorization.OrganizationID,
		ApplicationID:  fixture.authorization.ApplicationID,
		EnvironmentID:  fixture.authorization.EnvironmentID,
	}
	if !reflect.DeepEqual(fixture.snapshots.scope, wantScope) {
		t.Fatalf("snapshot scope = %+v, want %+v", fixture.snapshots.scope, wantScope)
	}
	captured := fixture.quotas.input
	if captured.OrganizationID != fixture.authorization.OrganizationID ||
		captured.ApplicationID != fixture.authorization.ApplicationID ||
		captured.EnvironmentID != fixture.authorization.EnvironmentID ||
		captured.ApplicationUserID != fixture.authorization.ApplicationUserID ||
		captured.InstallationID != fixture.authorization.InstallationID ||
		captured.ConfigRevisionID != fixture.authorization.PolicyRevisionID ||
		captured.FeatureKey != "assistant" || captured.LimitPlanKey != "starter" ||
		captured.RouteKey != "" || captured.UpstreamKey != "" || captured.ModelKey != "" ||
		len(captured.Rules) != 3 {
		t.Fatalf("quota snapshot input = %+v", captured)
	}
	for _, rule := range captured.Rules {
		if rule.ReservedUnits != 0 {
			t.Fatalf("snapshot rule reserved units = %d", rule.ReservedUnits)
		}
		if rule.Algorithm == quota.PerRequestAlgorithm && rule.PerRequestMaximum != 32 {
			t.Fatalf("effective per-request maximum = %d, want 32", rule.PerRequestMaximum)
		}
	}

	// Result pointers must not alias the storage dependency's mutable output.
	*fixture.quotas.snapshot.Limits[0].Maximum = 999
	if result.Limits[0].Maximum == nil || *result.Limits[0].Maximum == 999 {
		t.Fatal("result retained a quota-store counter pointer")
	}
}

func TestFeatureQuotaProviderFailsClosedBeforeQuotaRead(t *testing.T) {
	tests := []struct {
		name string
		edit func(*featureQuotaFixture)
		code string
	}{
		{
			name: "forged target",
			edit: func(fixture *featureQuotaFixture) {
				fixture.input.Metadata.TargetURL.Host = "attacker.example"
			},
			code: "server_not_ready",
		},
		{
			name: "SDK installation mismatch",
			edit: func(fixture *featureQuotaFixture) {
				fixture.authorization.InstallationPlatform = "android"
				fixture.sessions.authorization = fixture.authorization
			},
			code: "request_invalid",
		},
		{
			name: "stale active revision",
			edit: func(fixture *featureQuotaFixture) {
				fixture.snapshots.snapshot.RevisionID = id.Must(id.ConfigRevision)
			},
			code: "configuration_invalid",
		},
		{
			name: "streaming-dependent plan",
			edit: func(fixture *featureQuotaFixture) {
				fixture.policies.err = policy.ErrConfiguration
			},
			code: "configuration_invalid",
		},
		{
			name: "physical scope",
			edit: func(fixture *featureQuotaFixture) {
				fixture.policies.projection.LimitPlan.Limits[0].Scope = []string{"user", "model"}
			},
			code: "configuration_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFeatureQuotaFixture(t)
			test.edit(fixture)
			_, err := fixture.provider(t).FeatureQuota(context.Background(), fixture.input)
			var failure *clientapi.DependencyError
			if !errors.As(err, &failure) || failure.Code != test.code {
				t.Fatalf("FeatureQuota() error = %v, want %q", err, test.code)
			}
			if fixture.quotas.calls != 0 {
				t.Fatalf("quota store calls = %d, want zero", fixture.quotas.calls)
			}
		})
	}
}

func TestFeatureQuotaProviderMapsSafeDependencyFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{name: "missing feature", err: policy.ErrFeatureNotFound, code: "feature_not_found"},
		{name: "denied feature", err: policy.ErrFeatureNotAllowed, code: "feature_not_allowed"},
		{name: "revoked installation", err: session.ErrInstallationRevoked, code: "installation_revoked"},
		{name: "replayed proof", err: session.ErrDPoPReplayed, code: "dpop_replayed"},
		{name: "corrupt state", err: quota.ErrInvalidState, code: "server_not_ready"},
		{name: "unknown storage detail", err: errors.New("postgres-secret-detail"), code: "server_not_ready"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := featureQuotaFailure(test.err)
			var safe *clientapi.DependencyError
			if !errors.As(failure, &safe) || safe.Code != test.code ||
				failure.Error() != test.code {
				t.Fatalf("featureQuotaFailure() = %v, want %q", failure, test.code)
			}
		})
	}
}

type featureQuotaFixture struct {
	input         clientapi.FeatureQuotaInput
	authorization session.Authorization
	observedAt    time.Time
	verifier      *fakeAccessVerifier
	sessions      *fakeSessionAuthorizer
	snapshots     *fakeSnapshotLoader
	policies      *fakeFeatureQuotaPolicy
	quotas        *fakeFeatureQuotaStore
}

func newFeatureQuotaFixture(t *testing.T) *featureQuotaFixture {
	t.Helper()
	requestContext, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatalf("create logical request identity: %v", err)
	}
	logicalID, ok := requestidentity.FromContext(requestContext)
	if !ok {
		t.Fatal("logical request identity is missing")
	}
	authorization := session.Authorization{
		OrganizationID: id.Must(id.Organization), ApplicationID: id.Must(id.Application),
		EnvironmentID: id.Must(id.Environment), EnvironmentKind: "development",
		ApplicationUserID: id.Must(id.ApplicationUser), InstallationID: id.Must(id.Installation),
		InstallationPlatform: "ios", SessionGrantID: id.Must(id.SessionGrant),
		PolicyRevisionID: id.Must(id.ConfigRevision),
	}
	projection := policy.QuotaProjection{
		Feature: configuration.Feature{
			ID: "assistant", Protocol: "openai_chat",
			Output: &configuration.OutputPolicy{DefaultMaximumTokens: 128, AbsoluteMaximumTokens: 512},
		},
		LimitPlan: configuration.LimitPlan{ID: "starter", Limits: []configuration.Limit{
			{
				Metric: quota.OutputTokensMetric, Algorithm: quota.PerRequestAlgorithm,
				Scope: []string{"user", "feature"}, PerRequestMaximum: 64, Hard: true,
			},
			{
				Metric: quota.OutputTokensMetric, Algorithm: quota.TokenBucketAlgorithm,
				Scope: []string{"user", "feature"}, Capacity: 32,
				RefillPerSecond: configuration.RefillRate{Numerator: 1, Denominator: 10}, Hard: true,
			},
			{
				Metric: quota.ConcurrentStreamsMetric, Algorithm: quota.ConcurrencyAlgorithm,
				Scope: []string{"environment", "feature"}, Maximum: 3, Hard: true,
			},
		}},
	}
	observedAt := time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC)
	maximum, used, reserved, remaining := int64(3), int64(0), int64(1), int64(2)
	perRequestMaximum, bucketMaximum, bucketUsed, bucketReserved, bucketRemaining :=
		int64(32), int64(32), int64(7), int64(0), int64(25)
	quotaSnapshot := quota.Snapshot{
		Feature: "assistant", ObservedAt: observedAt,
		Limits: []quota.LimitSnapshot{
			{Metric: quota.ConcurrentStreamsMetric, Maximum: &maximum, Used: &used, Reserved: &reserved, Remaining: &remaining, Hard: true},
			{Metric: quota.OutputTokensMetric, Maximum: &perRequestMaximum, Hard: true},
			{Metric: quota.OutputTokensMetric, Maximum: &bucketMaximum, Used: &bucketUsed, Reserved: &bucketReserved, Remaining: &bucketRemaining, Hard: true},
		},
	}
	input := clientapi.FeatureQuotaInput{
		Metadata: clientapi.RequestMetadata{
			RequestID: logicalID.String(), SDK: "ios", SDKVersion: "1.2.3",
			HTTPMethod: http.MethodGet,
			TargetURL:  *mustFeatureQuotaURL(t, "https://gateway.example/client/v1/features/assistant/quota"),
			DPoPProof:  clientapi.NewSensitiveString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.c"),
		},
		LogicalRequestID: logicalID,
		AccessToken:      clientapi.NewSensitiveString("tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt"),
		Feature:          "assistant",
	}
	fixture := &featureQuotaFixture{
		input: input, authorization: authorization, observedAt: observedAt,
		verifier: &fakeAccessVerifier{},
		sessions: &fakeSessionAuthorizer{authorization: authorization},
		snapshots: &fakeSnapshotLoader{snapshot: configuration.ActiveSnapshot{
			RevisionID: authorization.PolicyRevisionID, EnvironmentID: authorization.EnvironmentID,
		}},
		policies: &fakeFeatureQuotaPolicy{projection: projection},
		quotas:   &fakeFeatureQuotaStore{snapshot: quotaSnapshot},
	}
	return fixture
}

func (fixture *featureQuotaFixture) provider(t *testing.T) *FeatureQuotaProvider {
	t.Helper()
	provider, err := NewFeatureQuotaProvider(FeatureQuotaConfig{
		AccessTokens: fixture.verifier, Sessions: fixture.sessions,
		Configuration: fixture.snapshots, Policies: fixture.policies,
		Quotas: fixture.quotas, PublicOrigin: "https://gateway.example",
	})
	if err != nil {
		t.Fatalf("NewFeatureQuotaProvider() error = %v", err)
	}
	return provider
}

func mustFeatureQuotaURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return parsed
}

type fakeFeatureQuotaPolicy struct {
	calls         int
	feature       string
	authorization session.Authorization
	logicalID     requestidentity.LogicalID
	environment   policy.EnvironmentFacts
	projection    policy.QuotaProjection
	err           error
}

func (fake *fakeFeatureQuotaPolicy) ResolveQuota(
	_ context.Context,
	_ policy.Snapshot,
	feature string,
	authorization session.Authorization,
	logicalID requestidentity.LogicalID,
	environment policy.EnvironmentFacts,
) (policy.QuotaProjection, error) {
	fake.calls++
	fake.feature = feature
	fake.authorization = authorization
	fake.logicalID = logicalID
	fake.environment = environment
	return fake.projection, fake.err
}

type fakeFeatureQuotaStore struct {
	calls    int
	input    quota.SnapshotInput
	snapshot quota.Snapshot
	err      error
}

func (fake *fakeFeatureQuotaStore) Snapshot(
	_ context.Context,
	input quota.SnapshotInput,
) (quota.Snapshot, error) {
	fake.calls++
	fake.input = input
	return fake.snapshot, fake.err
}
