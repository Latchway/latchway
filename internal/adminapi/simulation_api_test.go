package adminapi

import (
	"testing"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/protocol"
)

func TestBaseSimulationResultDescribesProductionCELRequestFacts(t *testing.T) {
	t.Parallel()

	compiled := configuration.SimulationSnapshot{
		Snapshot: configuration.ActiveSnapshot{RevisionID: "rev_00000000000000000000000000"},
		Scope: configuration.TenantScope{
			ApplicationID: "app_00000000000000000000000000",
			EnvironmentID: "env_00000000000000000000000000",
		},
		EnvironmentKind: "production",
	}
	result := baseSimulationResult(compiled, routeSimulationFacts{Feature: "assistant"})
	uses := make(map[string]routeSimulationFactUse, len(result.FactUsage))
	for _, use := range result.FactUsage {
		uses[use.Fact] = use
	}
	for _, fact := range []string{
		"request.feature",
		"request.protocol",
		"request.streaming",
		"request.estimated_input_tokens",
		"request.maximum_output_tokens",
	} {
		use, ok := uses[fact]
		if !ok || !use.AffectsCEL || use.Role != "policy" {
			t.Fatalf("fact usage %q = %+v, present=%t", fact, use, ok)
		}
	}
	if _, legacy := uses["requested_input_tokens"]; legacy {
		t.Fatal("legacy explanatory input estimate remained in fact usage")
	}
}

func TestSimulationRequestTokenFactsUseProductionBound(t *testing.T) {
	t.Parallel()

	valid := routeSimulationRequestFacts{
		RequestedInputTokens: protocol.MaximumPolicyRequestTokens,
		RequestedOutputMax:   protocol.MaximumPolicyRequestTokens,
	}
	if !validSimulationRequestFacts(valid) {
		t.Fatal("production maximum request-token facts were rejected")
	}
	valid.RequestedInputTokens++
	if validSimulationRequestFacts(valid) {
		t.Fatal("unbounded simulated input estimate was accepted")
	}
}
