package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/session"
)

var policyTestNow = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func TestResolverSelectsAccessPlanAndPriorityRoute(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policySnapshot()
	premium := policyInput("premium")
	decision, err := resolver.Resolve(context.Background(), snapshot, "assistant", premium)
	if err != nil {
		t.Fatal(err)
	}
	if decision.LimitPlan.ID != "premium" || decision.Route.ID != "premium-reasoning" || decision.Model.ID != "reasoning" || decision.Upstream.ID != "primary" {
		t.Fatalf("premium decision = %+v", decision)
	}
	free := policyInput("free")
	decision, err = resolver.Resolve(context.Background(), snapshot, "assistant", free)
	if err != nil {
		t.Fatal(err)
	}
	if decision.LimitPlan.ID != "free" || decision.Route.ID != "fallback-fast" || decision.Model.ID != "fast" {
		t.Fatalf("free decision = %+v", decision)
	}
	denied := policyInput("blocked")
	if _, err = resolver.Resolve(context.Background(), snapshot, "assistant", denied); !errors.Is(err, ErrFeatureNotAllowed) {
		t.Fatalf("denied feature error = %v", err)
	}
	if _, err = resolver.Resolve(context.Background(), snapshot, "missing", premium); !errors.Is(err, ErrFeatureNotFound) {
		t.Fatalf("missing feature error = %v", err)
	}
}

func TestResolverWeightedSelectionIsStableAndDefensive(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policySnapshot()
	feature := snapshot.features["assistant"]
	feature.Routes = []configuration.Route{
		{ID: "canary", When: "true", ModelID: "fast", Priority: 5, Weight: 1, StickyBy: "user", FallbackOn: []string{"status_503"}},
		{ID: "stable", When: "true", ModelID: "reasoning", Priority: 5, Weight: 9, StickyBy: "user", FallbackOn: []string{"status_502"}},
	}
	snapshot.features["assistant"] = feature
	input := policyInput("premium")
	first, err := resolver.Resolve(context.Background(), snapshot, "assistant", input)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 32; index++ {
		next, resolveErr := resolver.Resolve(context.Background(), snapshot, "assistant", input)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		if next.Route.ID != first.Route.ID {
			t.Fatalf("sticky route changed: first=%s next=%s", first.Route.ID, next.Route.ID)
		}
	}
	first.Route.FallbackOn[0] = "changed"
	first.Feature.Routes[0].FallbackOn[0] = "changed-through-feature"
	again, err := resolver.Resolve(context.Background(), snapshot, "assistant", input)
	if err != nil {
		t.Fatal(err)
	}
	if again.Route.FallbackOn[0] == "changed" {
		t.Fatal("returned route mutated the cached policy")
	}
	if again.Route.FallbackOn[0] == "changed-through-feature" {
		t.Fatal("returned feature mutated the cached policy")
	}
}

func TestResolverFailsClosedForAmbiguousOrInvalidRuntimeState(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*fakeSnapshot, *Input)
		want   error
	}{
		{
			name: "mixed sticky modes",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				feature := snapshot.features["assistant"]
				feature.Routes = []configuration.Route{
					{ID: "one", When: "true", ModelID: "fast", Priority: 1, Weight: 1, StickyBy: "user"},
					{ID: "two", When: "true", ModelID: "reasoning", Priority: 1, Weight: 1, StickyBy: "installation"},
				}
				snapshot.features["assistant"] = feature
			},
			want: ErrRouteNotFound,
		},
		{
			name: "selected plan missing",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				delete(snapshot.plans, "premium")
			},
			want: ErrLimitPlanNotFound,
		},
		{
			name: "bounded activation",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.claims["oversized"] = strings.Repeat("x", maximumActivationBytes+1)
			},
			want: ErrInvalidInput,
		},
		{
			name: "missing authoritative user identity",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.userID = ""
			},
			want: ErrInvalidInput,
		},
		{
			name: "missing request selection key",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				feature := snapshot.features["assistant"]
				feature.Routes = []configuration.Route{
					{ID: "one", When: "true", ModelID: "fast", Priority: 1, Weight: 1, StickyBy: "none"},
					{ID: "two", When: "true", ModelID: "reasoning", Priority: 1, Weight: 1, StickyBy: "none"},
				}
				snapshot.features["assistant"] = feature
				input.logicalRequestID = ""
			},
			want: ErrInvalidInput,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := policySnapshot()
			input := policyInput("premium")
			test.mutate(&snapshot, &input)
			if _, resolveErr := resolver.Resolve(context.Background(), snapshot, "assistant", input); !errors.Is(resolveErr, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", resolveErr, test.want)
			}
		})
	}
}

func TestResolverCacheKeyIncludesFeatureFingerprint(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policySnapshot()
	input := policyInput("premium")
	if _, err = resolver.Resolve(context.Background(), snapshot, "assistant", input); err != nil {
		t.Fatal(err)
	}
	feature := snapshot.features["assistant"]
	feature.AccessExpression = "false"
	snapshot.features["assistant"] = feature
	if _, err = resolver.Resolve(context.Background(), snapshot, "assistant", input); !errors.Is(err, ErrFeatureNotAllowed) {
		t.Fatalf("changed feature reused stale program: %v", err)
	}
}

func TestResolverRejectsUnknownPolicyContextKeys(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*configuration.Feature)
		want   error
	}{
		{
			name: "client model absent from access context",
			mutate: func(feature *configuration.Feature) {
				feature.AccessExpression = "request.model == 'client-selected-model'"
			},
			want: ErrFeatureNotAllowed,
		},
		{
			name: "client plan absent from limit context",
			mutate: func(feature *configuration.Feature) {
				feature.LimitPlanExpression = "request.plan"
			},
			want: ErrConfiguration,
		},
		{
			name: "client headers absent from route context",
			mutate: func(feature *configuration.Feature) {
				feature.Routes[0].When = "request.headers != null"
				feature.Routes[1].When = "false"
			},
			want: ErrConfiguration,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := policySnapshot()
			feature := snapshot.features["assistant"]
			test.mutate(&feature)
			snapshot.features["assistant"] = feature
			if _, resolveErr := resolver.Resolve(context.Background(), snapshot, "assistant", policyInput("premium")); !errors.Is(resolveErr, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", resolveErr, test.want)
			}
		})
	}
}

func TestResolverEnforcesFeatureAttestationBeforeCEL(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*fakeSnapshot, *Input)
		want   error
	}{
		{
			name:   "required accepts exact fresh evidence",
			mutate: func(_ *fakeSnapshot, _ *Input) {},
		},
		{
			name: "required rejects grant revision mismatch",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.policyRevisionID = "rev_00000000000000000000000001"
			},
			want: session.ErrAttestationStepUpRequired,
		},
		{
			name:   "missing current platform selection is configuration failure",
			mutate: func(_ *fakeSnapshot, input *Input) { input.authorization.installationPlatform = "android" },
			want:   ErrConfiguration,
		},
		{
			name: "required reports provider mismatch before expired evidence",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.attestationProvider = "firebase_app_check"
				input.authorization.attestationExpiresAt = policyTestNow
			},
			want: session.ErrAttestationStepUpRequired,
		},
		{
			name: "required reports trust mismatch before expired evidence",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.trustLevel = "web_risk_verified"
				input.authorization.attestationExpiresAt = policyTestNow
			},
			want: session.ErrAttestationStepUpRequired,
		},
		{
			name: "required maximum age boundary needs refresh",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.attestedAt = policyTestNow.Add(-10 * time.Minute)
			},
			want: session.ErrAttestationRefreshNeeded,
		},
		{
			name: "required durable evidence expiry needs refresh",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.authorization.attestationExpiresAt = policyTestNow
			},
			want: session.ErrAttestationRefreshNeeded,
		},
		{
			name: "required rejects ambiguous challenge policy",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				snapshot.attestations["other"] = configuration.AttestationPolicy{
					ID: "other", MaxAge: 10 * time.Minute,
					Platforms: map[string]configuration.PlatformAttestation{
						"ios": {Provider: "app_attest", Mode: "required", MinimumTrustLevel: "app_verified"},
					},
				}
			},
			want: ErrConfiguration,
		},
		{
			name: "preferred accepts matching target",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				setPolicyMode(snapshot, "preferred")
			},
		},
		{
			name: "preferred falls back for a different provider",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "preferred")
				input.authorization.attestationProvider = "firebase_app_check"
			},
		},
		{
			name: "preferred falls back for weaker matching evidence",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "preferred")
				input.authorization.trustLevel = "debug"
			},
		},
		{
			name: "preferred falls back when target maximum age is stale",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "preferred")
				input.authorization.attestedAt = policyTestNow.Add(-10 * time.Minute)
			},
		},
		{
			name: "preferred still requires valid sealed evidence",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "preferred")
				input.authorization.attestationProvider = "firebase_app_check"
				input.authorization.attestationExpiresAt = policyTestNow
			},
			want: session.ErrAttestationRefreshNeeded,
		},
		{
			name: "preferred preserves grant revision provenance",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "preferred")
				input.authorization.policyRevisionID = "rev_00000000000000000000000001"
			},
			want: session.ErrAttestationStepUpRequired,
		},
		{
			name: "disabled adds no feature attestation requirement",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "disabled")
				input.authorization.attestationProvider = "firebase_app_check"
				input.authorization.trustLevel = "debug"
			},
		},
		{
			name: "disabled ignores inactive application constraints",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				setPolicyMode(snapshot, "disabled")
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				selection.ApplicationIdentifiers = []string{"TEAMID.com.example.app"}
				policy.Platforms["ios"] = selection
				snapshot.attestations["native"] = policy
			},
		},
		{
			name: "disabled still requires valid sealed evidence",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "disabled")
				input.authorization.attestationExpiresAt = policyTestNow
			},
			want: session.ErrAttestationRefreshNeeded,
		},
		{
			name: "disabled preserves grant revision provenance",
			mutate: func(snapshot *fakeSnapshot, input *Input) {
				setPolicyMode(snapshot, "disabled")
				input.authorization.policyRevisionID = "rev_00000000000000000000000001"
			},
			want: session.ErrAttestationStepUpRequired,
		},
		{
			name: "enabled application constraints are corrupt runtime state",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				selection.ApplicationIdentifiers = []string{"TEAMID.com.example.app"}
				policy.Platforms["ios"] = selection
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "invalid mode fails closed",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				selection.Mode = "future"
				policy.Platforms["ios"] = selection
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "missing policy fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				delete(snapshot.attestations, "native")
			},
			want: ErrConfiguration,
		},
		{
			name: "invalid policy identifier fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				policy.ID = "Native"
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "invalid maximum age fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				policy.MaxAge = 0
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "invalid policy platform fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				delete(policy.Platforms, "ios")
				policy.Platforms["desktop"] = selection
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "invalid platform provider fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				selection.Provider = "play_integrity"
				policy.Platforms["ios"] = selection
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "invalid minimum trust fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				selection.MinimumTrustLevel = "rooted"
				policy.Platforms["ios"] = selection
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
		{
			name: "required none trust fails as configuration",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				policy := snapshot.attestations["native"]
				selection := policy.Platforms["ios"]
				selection.MinimumTrustLevel = "none"
				policy.Platforms["ios"] = selection
				snapshot.attestations["native"] = policy
			},
			want: ErrConfiguration,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := policySnapshot()
			input := policyInput("premium")
			// Prove attestation runs independently before a permissive CEL rule.
			feature := snapshot.features["assistant"]
			feature.AccessExpression = "true"
			snapshot.features["assistant"] = feature
			test.mutate(&snapshot, &input)
			_, resolveErr := resolver.Resolve(context.Background(), snapshot, "assistant", input)
			if test.want == nil {
				if resolveErr != nil {
					t.Fatalf("Resolve() error = %v, want nil", resolveErr)
				}
			} else if !errors.Is(resolveErr, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", resolveErr, test.want)
			}
		})
	}
}

func setPolicyMode(snapshot *fakeSnapshot, mode string) {
	policy := snapshot.attestations["native"]
	selection := policy.Platforms["ios"]
	selection.Mode = mode
	if mode == "disabled" {
		selection.MinimumTrustLevel = "none"
	}
	policy.Platforms["ios"] = selection
	snapshot.attestations["native"] = policy
}

func TestNewInputRejectsUnsealedAuthorization(t *testing.T) {
	t.Parallel()

	if _, err := NewInput(session.Authorization{}, requestidentity.LogicalID{}, ProtocolRequestMetadata{Streaming: true}, EnvironmentFacts{Kind: "production"}); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("NewInput() error = %v, want session invalid", err)
	}
}

func TestInputReusesOpaqueLogicalRequestIdentity(t *testing.T) {
	t.Parallel()

	ctx, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	logicalID, ok := requestidentity.FromContext(ctx)
	if !ok {
		t.Fatal("logical request identity missing")
	}
	authorization := session.Authorization{
		ApplicationUserID: "usr_00000000000000000000000000",
		InstallationID:    "ins_00000000000000000000000000",
		NormalizedClaims:  map[string]any{"plan": "premium"},
	}
	input, err := inputFromAuthorization(
		authorization, logicalID, ProtocolRequestMetadata{Streaming: true}, EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.LogicalRequestID() != logicalID.String() || input.ApplicationUserID() != authorization.ApplicationUserID || input.InstallationID() != authorization.InstallationID {
		t.Fatalf("typed input did not retain authoritative identities: %#v", input)
	}
	authorization.NormalizedClaims["plan"] = "forged"
	if input.authorization.claims["plan"] != "premium" {
		t.Fatal("typed input retained caller-owned normalized claims")
	}
}

func TestResolverPreservesCancellation(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = resolver.Resolve(ctx, policySnapshot(), "assistant", policyInput("premium")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled resolve error = %v", err)
	}
}

type fakeSnapshot struct {
	revision     string
	environment  string
	features     map[string]configuration.Feature
	attestations map[string]configuration.AttestationPolicy
	plans        map[string]configuration.LimitPlan
	models       map[string]configuration.Model
	upstreams    map[string]configuration.Upstream
}

func (snapshot fakeSnapshot) PolicyRevision() string    { return snapshot.revision }
func (snapshot fakeSnapshot) PolicyEnvironment() string { return snapshot.environment }

func (snapshot fakeSnapshot) Feature(identifier string) (configuration.Feature, bool) {
	value, ok := snapshot.features[identifier]
	return value, ok
}

func (snapshot fakeSnapshot) AttestationPolicy(identifier string) (configuration.AttestationPolicy, bool) {
	value, ok := snapshot.attestations[identifier]
	return value, ok
}

func (snapshot fakeSnapshot) RequiredAttestationForPlatform(platform string) (configuration.AttestationPolicy, configuration.PlatformAttestation, bool) {
	var matchedPolicy configuration.AttestationPolicy
	var matchedSelection configuration.PlatformAttestation
	found := false
	for _, policy := range snapshot.attestations {
		selection, ok := policy.Platforms[platform]
		if !ok || selection.Mode != "required" {
			continue
		}
		if found {
			return configuration.AttestationPolicy{}, configuration.PlatformAttestation{}, false
		}
		matchedPolicy = policy
		matchedSelection = selection
		found = true
	}
	return matchedPolicy, matchedSelection, found
}

func (snapshot fakeSnapshot) LimitPlan(identifier string) (configuration.LimitPlan, bool) {
	value, ok := snapshot.plans[identifier]
	return value, ok
}

func (snapshot fakeSnapshot) Model(identifier string) (configuration.Model, bool) {
	value, ok := snapshot.models[identifier]
	return value, ok
}

func (snapshot fakeSnapshot) Upstream(identifier string) (configuration.Upstream, bool) {
	value, ok := snapshot.upstreams[identifier]
	return value, ok
}

func policySnapshot() fakeSnapshot {
	return fakeSnapshot{
		revision: "rev_00000000000000000000000000", environment: "env_00000000000000000000000000",
		features: map[string]configuration.Feature{
			"assistant": {
				ID: "assistant", Protocol: "openai_chat", AttestationPolicyID: "native",
				AccessExpression:    "principal.authenticated && principal.claims.plan in ['free', 'premium']",
				LimitPlanExpression: "principal.claims.plan == 'premium' ? 'premium' : 'free'",
				Output:              &configuration.OutputPolicy{DefaultMaximumTokens: 800, AbsoluteMaximumTokens: 1500},
				Routes: []configuration.Route{
					{ID: "premium-reasoning", When: "principal.claims.plan == 'premium'", ModelID: "reasoning", Priority: 10, Weight: 1, StickyBy: "none"},
					{ID: "fallback-fast", When: "true", ModelID: "fast", Priority: 20, Weight: 1, StickyBy: "none"},
				},
			},
		},
		attestations: map[string]configuration.AttestationPolicy{
			"native": {
				ID: "native", MaxAge: 10 * time.Minute,
				Platforms: map[string]configuration.PlatformAttestation{
					"ios": {Provider: "app_attest", Mode: "required", MinimumTrustLevel: "app_verified"},
				},
			},
		},
		plans: map[string]configuration.LimitPlan{
			"free":    {ID: "free", Limits: []configuration.Limit{{Metric: "logical_requests", Algorithm: "calendar", Window: "1d", Maximum: 5, Hard: true}}},
			"premium": {ID: "premium", Limits: []configuration.Limit{{Metric: "logical_requests", Algorithm: "calendar", Window: "1d", Maximum: 500, Hard: true}}},
		},
		models: map[string]configuration.Model{
			"fast":      {ID: "fast", UpstreamID: "primary", UpstreamModel: "physical-fast", Capabilities: []string{"openai_chat"}},
			"reasoning": {ID: "reasoning", UpstreamID: "primary", UpstreamModel: "physical-reasoning", Capabilities: []string{"openai_chat"}},
		},
		upstreams: map[string]configuration.Upstream{
			"primary": {ID: "primary", Type: "openai_compatible", BaseURL: "https://api.example.test/v1"},
		},
	}
}

func policyInput(plan string) Input {
	return Input{
		authorization: authorizationFacts{
			organizationID:       "org_00000000000000000000000000",
			applicationID:        "app_00000000000000000000000000",
			environmentID:        "env_00000000000000000000000000",
			policyRevisionID:     "rev_00000000000000000000000000",
			userID:               "usr_00000000000000000000000000",
			installationID:       "ins_00000000000000000000000000",
			installationPlatform: "ios", identityProvider: "firebase",
			trustLevel: "device_verified", attestationProvider: "app_attest",
			claims:               map[string]any{"plan": plan},
			identityExpiresAt:    policyTestNow.Add(time.Hour),
			attestedAt:           policyTestNow.Add(-time.Minute),
			attestationExpiresAt: policyTestNow.Add(time.Hour),
			accessExpiresAt:      policyTestNow.Add(10 * time.Minute),
		},
		request:          ProtocolRequestMetadata{Streaming: true},
		environment:      EnvironmentFacts{Kind: "production"},
		logicalRequestID: "req_00000000000000000000000000",
	}
}
