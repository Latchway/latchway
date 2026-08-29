package limitmetric

import (
	"slices"
	"testing"
)

func TestDefinitionsCoverInitialPlanRegistryInStableOrder(t *testing.T) {
	t.Parallel()

	want := []string{
		LogicalRequests, UpstreamAttempts, InputTokens, OutputTokens, TotalTokens,
		ReasoningTokens, CachedInputTokens, CacheWriteTokens, CostNanoUSD,
		ConcurrentRequests, ConcurrentStreams, RequestBytes, ResponseBytes,
		ImageUnits, AudioSeconds, ToolCalls,
	}
	definitions := Definitions()
	got := make([]string, 0, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		if definition.Name == "" {
			t.Fatal("registry contains an empty metric name")
		}
		if _, duplicate := seen[definition.Name]; duplicate {
			t.Fatalf("registry contains duplicate metric %q", definition.Name)
		}
		seen[definition.Name] = struct{}{}
		got = append(got, definition.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("metric registry = %#v, want %#v", got, want)
	}
}

func TestRegistryDeclaresExactEnforcementCapabilitiesAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	want := map[string][]string{
		LogicalRequests:    {CalendarAlgorithm, TokenBucketAlgorithm},
		UpstreamAttempts:   nil,
		InputTokens:        {CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm},
		OutputTokens:       {CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm},
		TotalTokens:        {CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm},
		ReasoningTokens:    nil,
		CachedInputTokens:  nil,
		CacheWriteTokens:   nil,
		CostNanoUSD:        {CalendarAlgorithm},
		ConcurrentRequests: {ConcurrencyAlgorithm},
		ConcurrentStreams:  {ConcurrencyAlgorithm},
		RequestBytes:       {PerRequestAlgorithm},
		ResponseBytes:      nil,
		ImageUnits:         {PerRequestAlgorithm},
		AudioSeconds:       nil,
		ToolCalls:          {PerRequestAlgorithm},
	}
	for name, algorithms := range want {
		definition, ok := Lookup(name)
		if !ok || definition.Name != name || !slices.Equal(definition.Algorithms, algorithms) {
			t.Fatalf("Lookup(%q) = %+v, %t; want algorithms %#v", name, definition, ok, algorithms)
		}
		for _, candidate := range []string{
			CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm, ConcurrencyAlgorithm,
		} {
			if got := SupportsEnforcement(name, candidate); got != slices.Contains(algorithms, candidate) {
				t.Fatalf("SupportsEnforcement(%q, %q) = %t", name, candidate, got)
			}
		}
	}
	if _, ok := Lookup("future_client_metric"); ok || SupportsEnforcement("future_client_metric", CalendarAlgorithm) {
		t.Fatal("unknown metric became enforceable")
	}

	definitions := Definitions()
	definitions[0].Name = "mutated"
	definitions[0].Algorithms[0] = "mutated"
	definition, ok := Lookup(LogicalRequests)
	if !ok || definition.Name != LogicalRequests || definition.Algorithms[0] != CalendarAlgorithm {
		t.Fatalf("registry storage was mutable through Definitions: %+v, %t", definition, ok)
	}
	definition.Algorithms[0] = "mutated_again"
	definition, ok = Lookup(LogicalRequests)
	if !ok || definition.Algorithms[0] != CalendarAlgorithm {
		t.Fatalf("registry storage was mutable through Lookup: %+v, %t", definition, ok)
	}
}
