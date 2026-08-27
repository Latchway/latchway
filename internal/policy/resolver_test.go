package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/configuration"
)

func TestResolverSelectsAccessPlanAndPriorityRoute(t *testing.T) {
	t.Parallel()

	resolver, err := NewResolver()
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

	resolver, err := NewResolver()
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

	resolver, err := NewResolver()
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
				input.Principal["oversized"] = strings.Repeat("x", maximumActivationBytes+1)
			},
			want: ErrInvalidInput,
		},
		{
			name: "missing authoritative user identity",
			mutate: func(_ *fakeSnapshot, input *Input) {
				input.UserID = ""
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
				input.LogicalRequestID = ""
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

	resolver, err := NewResolver()
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

func TestResolverPreservesCancellation(t *testing.T) {
	t.Parallel()

	resolver, err := NewResolver()
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
	revision    string
	environment string
	features    map[string]configuration.Feature
	plans       map[string]configuration.LimitPlan
	models      map[string]configuration.Model
	upstreams   map[string]configuration.Upstream
}

func (snapshot fakeSnapshot) PolicyRevision() string    { return snapshot.revision }
func (snapshot fakeSnapshot) PolicyEnvironment() string { return snapshot.environment }

func (snapshot fakeSnapshot) Feature(identifier string) (configuration.Feature, bool) {
	value, ok := snapshot.features[identifier]
	return value, ok
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
		revision: "rev_test", environment: "env_test",
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
		Principal: map[string]any{
			"authenticated": true,
			"claims":        map[string]any{"plan": plan},
		},
		Installation:     map[string]any{"trust_level": "app_verified"},
		Request:          map[string]any{"streaming": true},
		Environment:      map[string]any{"kind": "production"},
		UserID:           "usr_00000000000000000000000000",
		InstallationID:   "ins_00000000000000000000000000",
		LogicalRequestID: "req_00000000000000000000000000",
	}
}
