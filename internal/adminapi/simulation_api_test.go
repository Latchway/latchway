package adminapi

import (
	"testing"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dataplane"
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

func TestSimulationSchemaFactsRemainBoundedAndReachAccounting(t *testing.T) {
	for _, count := range []int64{-1, 4*1024*1024 + 1} {
		if validSimulationRequestFacts(routeSimulationRequestFacts{ExpandedSchemaBytes: count}) {
			t.Fatal("out-of-range expanded schema bytes accepted")
		}
	}
	authenticated := true
	request := routeSimulationRequest{Principal: routeSimulationPrincipal{Authenticated: &authenticated}, Request: routeSimulationRequestFacts{ExpandedSchemaBytes: 268}}
	facts := simulationFacts(configuration.SimulationSnapshot{}, request)
	if facts.ExpandedSchemaBytes != 268 {
		t.Fatal("schema bytes omitted from effective simulation facts")
	}
	result := simulationReservation(dataplane.ReservationProjection{InputAccounting: dataplane.ReservationProjectionInputAccounting{ExpandedSchemaBytes: 268}})
	if result.InputAccounting.ExpandedSchemaBytes != 268 {
		t.Fatal("schema bytes omitted from simulation response")
	}
	base := baseSimulationResult(configuration.SimulationSnapshot{}, facts)
	for _, use := range base.FactUsage {
		if use.Fact == "expanded_schema_bytes" {
			if use.AffectsCEL || use.Role != "reservation" {
				t.Fatal("schema facts must only affect reservation")
			}
			return
		}
	}
	t.Fatal("schema fact usage omitted")
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
