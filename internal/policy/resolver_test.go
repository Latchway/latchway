package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/limitscope"
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

func TestNewSimulationInputUsesTheProductionResolverBoundary(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	facts := SimulationFacts{
		OrganizationID: "org_00000000000000000000000000", ApplicationID: "app_00000000000000000000000000",
		EnvironmentID: "env_00000000000000000000000000", EnvironmentKind: "production",
		PolicyRevisionID:  "rev_00000000000000000000000000",
		ApplicationUserID: "usr_00000000000000000000000000", InstallationID: "ins_00000000000000000000000000",
		LogicalRequestID: "req_00000000000000000000000000", InstallationPlatform: "ios",
		IdentityProvider: "simulator", TrustLevel: "app_verified", AttestationProvider: "app_attest",
		Authenticated: true, NormalizedClaims: map[string]any{"plan": "premium"}, Streaming: true,
		EvaluatedAt: policyTestNow,
	}
	input, err := NewSimulationInput(facts)
	if err != nil {
		t.Fatalf("NewSimulationInput() error = %v", err)
	}
	facts.NormalizedClaims["plan"] = "blocked"
	plan, err := resolver.ResolvePlan(context.Background(), policySnapshot(), "assistant", input)
	if err != nil {
		t.Fatalf("ResolvePlan(simulation) error = %v", err)
	}
	if plan.LimitPlan.ID != "premium" || plan.Candidates[0].Route.ID != "premium-reasoning" {
		t.Fatalf("simulation plan = %+v", plan)
	}

	facts.Authenticated = false
	facts.NormalizedClaims = map[string]any{"plan": "premium"}
	unauthenticated, err := NewSimulationInput(facts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolvePlan(context.Background(), policySnapshot(), "assistant", unauthenticated); !errors.Is(err, ErrFeatureNotAllowed) {
		t.Fatalf("unauthenticated simulation error = %v", err)
	}

	facts.EnvironmentID = "not-an-environment"
	if _, err := NewSimulationInput(facts); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid simulation scope error = %v", err)
	}
	facts.EnvironmentID = "env_00000000000000000000000000"
	facts.NormalizedClaims = map[string]any{"oversized": strings.Repeat("x", maximumActivationBytes+1)}
	if _, err := NewSimulationInput(facts); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized simulation claims error = %v", err)
	}
}

func TestResolverUserOverrideReplacesOnlyLimitPlanSelection(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policySnapshot()

	freePrincipal := policyInput("free")
	freePrincipal.authorization.userOverrideID = "uov_00000000000000000000000000"
	freePrincipal.authorization.limitPlanOverride = "premium"
	decision, err := resolver.Resolve(context.Background(), snapshot, "assistant", freePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if decision.LimitPlan.ID != "premium" || decision.LimitPlan.Limits[0].Maximum != 500 ||
		decision.Route.ID != "fallback-fast" {
		t.Fatalf("free principal override decision = %+v", decision)
	}

	// The compiled feature cache is shared, but the effective override is not.
	premiumPrincipal := policyInput("premium")
	premiumPrincipal.authorization.userID = "usr_00000000000000000000000001"
	premiumPrincipal.authorization.userOverrideID = "uov_00000000000000000000000001"
	premiumPrincipal.authorization.limitPlanOverride = "free"
	decision, err = resolver.Resolve(context.Background(), snapshot, "assistant", premiumPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if decision.LimitPlan.ID != "free" || decision.LimitPlan.Limits[0].Maximum != 5 ||
		decision.Route.ID != "premium-reasoning" {
		t.Fatalf("premium principal override decision = %+v", decision)
	}

	decision.LimitPlan.Limits[0].Maximum = 1
	again, err := resolver.Resolve(context.Background(), snapshot, "assistant", premiumPrincipal)
	if err != nil || again.LimitPlan.Limits[0].Maximum != 5 {
		t.Fatalf("caller mutation reached resolved override plan: %+v, %v", again, err)
	}

	blocked := policyInput("blocked")
	blocked.authorization.userOverrideID = "uov_00000000000000000000000002"
	blocked.authorization.limitPlanOverride = "premium"
	if _, err := resolver.Resolve(context.Background(), snapshot, "assistant", blocked); !errors.Is(err, ErrFeatureNotAllowed) {
		t.Fatalf("override bypassed access policy: %v", err)
	}

	missing := policyInput("free")
	missing.authorization.userOverrideID = "uov_00000000000000000000000003"
	missing.authorization.limitPlanOverride = "missing"
	if _, err := resolver.Resolve(context.Background(), snapshot, "assistant", missing); !errors.Is(err, ErrLimitPlanNotFound) {
		t.Fatalf("missing override plan error = %v", err)
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

func TestCloneRouteDeepCopiesRetryPolicy(t *testing.T) {
	t.Parallel()

	original := configuration.Route{
		ID: "primary", FallbackOn: []string{"status_503"},
		RetryPolicy: &configuration.RetryPolicy{
			MaxAttempts: 3, RetryOn: []string{"connect_error", "status_503"},
		},
	}
	cloned := cloneRoute(original)
	cloned.FallbackOn[0] = "changed"
	cloned.RetryPolicy.RetryOn[0] = "changed"
	cloned.RetryPolicy.MaxAttempts = 8
	if original.FallbackOn[0] != "status_503" || original.RetryPolicy == nil ||
		original.RetryPolicy.RetryOn[0] != "connect_error" || original.RetryPolicy.MaxAttempts != 3 {
		t.Fatalf("route retry policy was not defensively cloned: original=%+v clone=%+v", original, cloned)
	}
}

func TestResolverPlanOrdersEveryMatchedRouteDeterministicallyAndDetached(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policySnapshot()
	feature := snapshot.features["assistant"]
	feature.Routes = []configuration.Route{
		{ID: "priority-canary", When: "true", ModelID: "fast", Priority: 5, Weight: 1, StickyBy: "user", FallbackOn: []string{"status_503"}},
		{ID: "priority-stable", When: "true", ModelID: "reasoning", Priority: 5, Weight: 9, StickyBy: "user", FallbackOn: []string{"status_502"}},
		{ID: "secondary-a", When: "true", ModelID: "fast", Priority: 20, Weight: 3, StickyBy: "none", FallbackOn: []string{"connect_error"}},
		{ID: "secondary-b", When: "true", ModelID: "reasoning", Priority: 20, Weight: 1, StickyBy: "none"},
	}
	snapshot.features["assistant"] = feature
	snapshot.upstreams["primary"] = configuration.Upstream{
		ID: "primary", Type: "openai_compatible", BaseURL: "https://api.example.test/v1",
		DestinationPolicy: configuration.UpstreamDestinationPolicy{AllowedPorts: []int{443}, DNSPinning: true},
		StaticHeaders:     map[string]string{"X-Provider-Tenant": "configured"},
	}
	input := policyInput("premium")

	first, err := resolver.ResolvePlan(context.Background(), snapshot, "assistant", input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := resolver.ResolvePlan(context.Background(), snapshot, "assistant", input)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Candidates) != 4 || len(again.Candidates) != 4 {
		t.Fatalf("candidate counts = %d, %d", len(first.Candidates), len(again.Candidates))
	}
	seen := make(map[string]struct{}, len(first.Candidates))
	for index, candidate := range first.Candidates {
		if candidate.Route.ID != again.Candidates[index].Route.ID {
			t.Fatalf("route order changed: first=%v again=%v", first.Candidates, again.Candidates)
		}
		if _, duplicate := seen[candidate.Route.ID]; duplicate {
			t.Fatalf("route %q appeared more than once", candidate.Route.ID)
		}
		seen[candidate.Route.ID] = struct{}{}
		if index < 2 && candidate.Route.Priority != 5 {
			t.Fatalf("primary priority group candidate %d = %+v", index, candidate.Route)
		}
		if index >= 2 && candidate.Route.Priority != 20 {
			t.Fatalf("secondary priority group candidate %d = %+v", index, candidate.Route)
		}
		if candidate.Model.ID != candidate.Route.ModelID ||
			candidate.Upstream.ID != candidate.Model.UpstreamID {
			t.Fatalf("candidate references do not close: %+v", candidate)
		}
	}
	primary, err := resolver.Resolve(context.Background(), snapshot, "assistant", input)
	if err != nil {
		t.Fatal(err)
	}
	if primary.Route.ID != first.Candidates[0].Route.ID {
		t.Fatalf("Resolve primary %q != plan primary %q", primary.Route.ID, first.Candidates[0].Route.ID)
	}

	// The user-sticky priority group is independent from the logical request
	// identifier used by later non-sticky groups.
	anotherRequest := input
	anotherRequest.logicalRequestID = "req_00000000000000000000000001"
	sticky, err := resolver.ResolvePlan(context.Background(), snapshot, "assistant", anotherRequest)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if sticky.Candidates[index].Route.ID != first.Candidates[index].Route.ID {
			t.Fatalf("user-sticky priority group changed: first=%v next=%v", first.Candidates, sticky.Candidates)
		}
	}

	first.Feature.Routes[0].FallbackOn[0] = "changed-feature"
	first.LimitPlan.Limits[0].Scope = append(first.LimitPlan.Limits[0].Scope, "changed")
	first.Candidates[0].Route.FallbackOn[0] = "changed-route"
	first.Candidates[0].Model.Capabilities[0] = "changed-model"
	first.Candidates[0].Upstream.DestinationPolicy.AllowedPorts[0] = 80
	first.Candidates[0].Upstream.StaticHeaders["X-Provider-Tenant"] = "changed"
	detached, err := resolver.ResolvePlan(context.Background(), snapshot, "assistant", input)
	if err != nil {
		t.Fatal(err)
	}
	if detached.Candidates[0].Route.FallbackOn[0] == "changed-route" ||
		detached.Candidates[0].Model.Capabilities[0] == "changed-model" ||
		detached.Candidates[0].Upstream.DestinationPolicy.AllowedPorts[0] != 443 ||
		detached.Candidates[0].Upstream.StaticHeaders["X-Provider-Tenant"] != "configured" {
		t.Fatalf("caller mutation reached route plan: %+v", detached.Candidates[0])
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
			name: "matched later route model missing",
			mutate: func(snapshot *fakeSnapshot, _ *Input) {
				delete(snapshot.models, "fast")
			},
			want: ErrRouteNotFound,
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

func TestResolverResolveQuotaReturnsStableDetachedProjectionWithoutRouting(t *testing.T) {
	t.Parallel()

	clockCalls := 0
	validationCalls := 0
	resolver, err := newResolver(func() time.Time {
		clockCalls++
		return policyTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.validateAuthorization = func(authorization session.Authorization, at time.Time) (session.Authorization, error) {
		validationCalls++
		if !at.Equal(policyTestNow) {
			t.Fatalf("authorization validation time = %s", at)
		}
		return authorization, nil
	}
	snapshot := policySnapshot()
	feature := snapshot.features["assistant"]
	feature.Routes = []configuration.Route{
		{ID: "one", When: "true", ModelID: "missing-one", Priority: 1, Weight: 0, StickyBy: "user", FallbackOn: []string{"status_503"}},
		{ID: "two", When: "true", ModelID: "missing-two", Priority: 1, Weight: 0, StickyBy: "installation", FallbackOn: []string{"status_502"}},
	}
	feature.OpaqueHTTP = &configuration.OpaqueHTTPPolicy{
		AllowedMethods: []string{"POST"}, PathPrefixes: []string{"/safe"},
		AllowedRequestHeaders: []string{"content-type"},
	}
	snapshot.features["assistant"] = feature
	plan := snapshot.plans["premium"]
	plan.Limits[0].Scope = []string{"user", "feature"}
	snapshot.plans["premium"] = plan
	delete(snapshot.models, "fast")
	delete(snapshot.models, "reasoning")
	delete(snapshot.upstreams, "primary")

	projection, err := resolver.ResolveQuota(
		context.Background(), snapshot, "assistant", quotaAuthorization("premium"),
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if clockCalls != 1 || validationCalls != 1 {
		t.Fatalf("clock/validation calls = %d/%d", clockCalls, validationCalls)
	}
	if projection.Feature.ID != "assistant" || projection.LimitPlan.ID != "premium" ||
		projection.LimitPlan.Limits[0].Maximum != 500 {
		t.Fatalf("quota projection = %+v", projection)
	}

	projection.Feature.Output.AbsoluteMaximumTokens = 1
	projection.Feature.Routes[0].FallbackOn[0] = "changed"
	projection.Feature.OpaqueHTTP.AllowedMethods[0] = "DELETE"
	projection.LimitPlan.Limits[0].Scope[0] = "installation"
	if snapshot.features["assistant"].Output.AbsoluteMaximumTokens != 1500 ||
		snapshot.features["assistant"].Routes[0].FallbackOn[0] != "status_503" ||
		snapshot.features["assistant"].OpaqueHTTP.AllowedMethods[0] != "POST" ||
		snapshot.plans["premium"].Limits[0].Scope[0] != "user" {
		t.Fatal("returned quota projection retained snapshot-owned mutable state")
	}
}

func TestResolverQuotaScopesUseOnlySealedPlatformAndOpaqueClaimDigests(t *testing.T) {
	t.Parallel()

	resolver := quotaResolver(t, func() time.Time { return policyTestNow })
	snapshot := policySnapshot()
	plan := snapshot.plans["premium"]
	plan.Limits[0].Scope = []string{"normalized_claim:region", "platform", "user"}
	snapshot.plans["premium"] = plan
	authorization := quotaAuthorization("premium")
	authorization.InstallationPlatform = "ios"
	authorization.NormalizedClaims["region"] = "eu"

	projection, err := resolver.ResolveQuota(
		context.Background(), snapshot, "assistant", authorization,
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantPresent, ok := limitscope.ClaimDigest("region", "eu", true)
	if !ok || projection.Scopes.Platform != "ios" ||
		projection.Scopes.NormalizedClaims["region"] != wantPresent ||
		strings.Contains(projection.Scopes.NormalizedClaims["region"], "eu") {
		t.Fatalf("sealed quota scopes = %+v", projection.Scopes)
	}
	authorization.InstallationPlatform = "android"
	authorization.NormalizedClaims["region"] = "forged"
	if projection.Scopes.Platform != "ios" ||
		projection.Scopes.NormalizedClaims["region"] != wantPresent {
		t.Fatalf("caller mutation reached detached scope facts: %+v", projection.Scopes)
	}

	missing := quotaAuthorization("premium")
	missing.InstallationPlatform = "ios"
	delete(missing.NormalizedClaims, "region")
	missingProjection, err := resolver.ResolveQuota(
		context.Background(), snapshot, "assistant", missing,
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantMissing, ok := limitscope.ClaimDigest("region", nil, false)
	if !ok || missingProjection.Scopes.NormalizedClaims["region"] != wantMissing ||
		wantMissing == wantPresent {
		t.Fatalf("missing normalized-claim scope = %+v", missingProjection.Scopes)
	}
}

func TestResolverResolveQuotaRejectsRequestDependentPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		access    string
		limitPlan string
		want      error
	}{
		{name: "stream-dependent access", access: "!request.streaming", want: ErrConfiguration},
		{name: "both denied", access: "false", want: ErrFeatureNotAllowed},
		{name: "stream-dependent plan", access: "true", limitPlan: "request.streaming ? 'premium' : 'free'", want: ErrConfiguration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := quotaResolver(t, func() time.Time { return policyTestNow })
			snapshot := policySnapshot()
			feature := snapshot.features["assistant"]
			if test.access != "" {
				feature.AccessExpression = test.access
			}
			if test.limitPlan != "" {
				feature.LimitPlanExpression = test.limitPlan
			}
			snapshot.features["assistant"] = feature
			_, resolveErr := resolver.ResolveQuota(
				context.Background(), snapshot, "assistant", quotaAuthorization("premium"),
				quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
			)
			if !errors.Is(resolveErr, test.want) {
				t.Fatalf("ResolveQuota() error = %v, want %v", resolveErr, test.want)
			}
		})
	}
}

func TestResolverResolveQuotaOverrideStabilizesRequestDependentBasePlan(t *testing.T) {
	t.Parallel()

	resolver := quotaResolver(t, func() time.Time { return policyTestNow })
	snapshot := policySnapshot()
	feature := snapshot.features["assistant"]
	feature.AccessExpression = "true"
	feature.LimitPlanExpression = "request.streaming ? 'premium' : 'free'"
	snapshot.features["assistant"] = feature
	authorization := quotaAuthorization("premium")
	authorization.UserOverrideID = "uov_00000000000000000000000000"
	authorization.LimitPlanOverride = "free"

	projection, err := resolver.ResolveQuota(
		context.Background(), snapshot, "assistant", authorization,
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if projection.LimitPlan.ID != "free" || projection.LimitPlan.Limits[0].Maximum != 5 {
		t.Fatalf("override quota projection = %+v", projection)
	}

	feature.AccessExpression = "!request.streaming"
	snapshot.features["assistant"] = feature
	if _, err := resolver.ResolveQuota(
		context.Background(), snapshot, "assistant", authorization,
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("override stabilized request-dependent access: %v", err)
	}
}

func TestResolverResolveQuotaFailsClosedForMissingAndCorruptSnapshots(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		build   func() Snapshot
		feature string
		want    error
	}{
		{
			name: "missing feature", feature: "missing",
			build: func() Snapshot { snapshot := policySnapshot(); return snapshot },
			want:  ErrFeatureNotFound,
		},
		{
			name: "missing plan",
			build: func() Snapshot {
				snapshot := policySnapshot()
				delete(snapshot.plans, "premium")
				return snapshot
			},
			want: ErrLimitPlanNotFound,
		},
		{
			name: "detached feature identity",
			build: func() Snapshot {
				snapshot := policySnapshot()
				feature := snapshot.features["assistant"]
				feature.ID = "other"
				snapshot.features["assistant"] = feature
				return snapshot
			},
			want: ErrConfiguration,
		},
		{
			name: "detached plan identity",
			build: func() Snapshot {
				snapshot := policySnapshot()
				plan := snapshot.plans["premium"]
				plan.ID = "other"
				snapshot.plans["premium"] = plan
				return snapshot
			},
			want: ErrConfiguration,
		},
		{
			name: "unstable plan content",
			build: func() Snapshot {
				return &alternatingQuotaPlanSnapshot{fakeSnapshot: policySnapshot()}
			},
			want: ErrConfiguration,
		},
		{
			name: "detached revision",
			build: func() Snapshot {
				snapshot := policySnapshot()
				snapshot.revision = "rev_00000000000000000000000001"
				return snapshot
			},
			want: session.ErrAttestationStepUpRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := quotaResolver(t, func() time.Time { return policyTestNow })
			featureID := test.feature
			if featureID == "" {
				featureID = "assistant"
			}
			_, resolveErr := resolver.ResolveQuota(
				context.Background(), test.build(), featureID, quotaAuthorization("premium"),
				quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
			)
			if !errors.Is(resolveErr, test.want) {
				t.Fatalf("ResolveQuota() error = %v, want %v", resolveErr, test.want)
			}
		})
	}

	resolver := quotaResolver(t, func() time.Time { return policyTestNow })
	if _, err := resolver.ResolveQuota(
		context.Background(), nil, "assistant", quotaAuthorization("premium"),
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil snapshot error = %v", err)
	}
}

func TestResolverResolveQuotaPropagatesSessionAndAttestationErrors(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(func() time.Time { return policyTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveQuota(
		context.Background(), policySnapshot(), "assistant", session.Authorization{},
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	); !errors.Is(err, session.ErrSessionInvalid) {
		t.Fatalf("unsealed authorization error = %v", err)
	}

	resolver = quotaResolver(t, func() time.Time { return policyTestNow })
	authorization := quotaAuthorization("premium")
	authorization.AttestationExpiresAt = policyTestNow
	if _, err := resolver.ResolveQuota(
		context.Background(), policySnapshot(), "assistant", authorization,
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	); !errors.Is(err, session.ErrAttestationRefreshNeeded) {
		t.Fatalf("stale attestation error = %v", err)
	}
}

func TestResolverResolveQuotaPreservesCancellationBeforeClockAndValidation(t *testing.T) {
	t.Parallel()

	clockCalls := 0
	validationCalls := 0
	resolver, err := newResolver(func() time.Time {
		clockCalls++
		return policyTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.validateAuthorization = func(authorization session.Authorization, _ time.Time) (session.Authorization, error) {
		validationCalls++
		return authorization, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveQuota(
		ctx, policySnapshot(), "assistant", quotaAuthorization("premium"),
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ResolveQuota() error = %v", err)
	}
	if clockCalls != 0 || validationCalls != 0 {
		t.Fatalf("canceled clock/validation calls = %d/%d", clockCalls, validationCalls)
	}
}

func TestResolverResolveQuotaUsesOneClockAtExpiryBoundary(t *testing.T) {
	t.Parallel()

	clockCalls := 0
	validationCalls := 0
	resolver, err := newResolver(func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return policyTestNow.In(time.FixedZone("boundary", 7*60*60))
		}
		return policyTestNow.Add(time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.validateAuthorization = func(authorization session.Authorization, at time.Time) (session.Authorization, error) {
		validationCalls++
		if at.Location() != time.UTC || !at.Equal(policyTestNow) {
			t.Fatalf("validation instant = %s (%s)", at, at.Location())
		}
		if !authorization.AccessExpiresAt.After(at) {
			return session.Authorization{}, session.ErrTokenExpired
		}
		return authorization, nil
	}
	authorization := quotaAuthorization("premium")
	authorization.AccessExpiresAt = policyTestNow.Add(time.Nanosecond)
	authorization.AttestedAt = policyTestNow.Add(-10*time.Minute + time.Nanosecond)
	if _, err := resolver.ResolveQuota(
		context.Background(), policySnapshot(), "assistant", authorization,
		quotaLogicalID(t), EnvironmentFacts{Kind: "production"},
	); err != nil {
		t.Fatalf("boundary ResolveQuota() error = %v", err)
	}
	if clockCalls != 1 || validationCalls != 1 {
		t.Fatalf("boundary clock/validation calls = %d/%d", clockCalls, validationCalls)
	}
}

type alternatingQuotaPlanSnapshot struct {
	fakeSnapshot
	calls int
}

func (snapshot *alternatingQuotaPlanSnapshot) LimitPlan(identifier string) (configuration.LimitPlan, bool) {
	plan, ok := snapshot.fakeSnapshot.LimitPlan(identifier)
	if !ok {
		return configuration.LimitPlan{}, false
	}
	snapshot.calls++
	plan = cloneLimitPlan(plan)
	if snapshot.calls%2 == 0 {
		plan.Limits[0].Maximum++
	}
	return plan, true
}

func quotaResolver(t *testing.T, now func() time.Time) *Resolver {
	t.Helper()
	resolver, err := newResolver(now)
	if err != nil {
		t.Fatal(err)
	}
	resolver.validateAuthorization = func(authorization session.Authorization, _ time.Time) (session.Authorization, error) {
		return authorization, nil
	}
	return resolver
}

func quotaLogicalID(t *testing.T) requestidentity.LogicalID {
	t.Helper()
	ctx, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	logicalID, ok := requestidentity.FromContext(ctx)
	if !ok {
		t.Fatal("logical request identity missing")
	}
	return logicalID
}

func quotaAuthorization(plan string) session.Authorization {
	input := policyInput(plan)
	return session.Authorization{
		OrganizationID: input.authorization.organizationID, ApplicationID: input.authorization.applicationID,
		EnvironmentID: input.authorization.environmentID, EnvironmentKind: input.environment.Kind,
		ApplicationUserID: input.authorization.userID, InstallationID: input.authorization.installationID,
		InstallationPlatform: input.authorization.installationPlatform,
		SessionGrantID:       "sgr_00000000000000000000000000",
		PolicyRevisionID:     input.authorization.policyRevisionID,
		IdentityProvider:     input.authorization.identityProvider,
		DPoPJKT:              strings.Repeat("A", 43),
		TrustLevel:           input.authorization.trustLevel,
		AttestationProvider:  input.authorization.attestationProvider,
		NormalizedClaims:     cloneClaims(input.authorization.claims),
		IdentityExpiresAt:    input.authorization.identityExpiresAt,
		AttestedAt:           input.authorization.attestedAt,
		AttestationExpiresAt: input.authorization.attestationExpiresAt,
		AccessExpiresAt:      input.authorization.accessExpiresAt,
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
