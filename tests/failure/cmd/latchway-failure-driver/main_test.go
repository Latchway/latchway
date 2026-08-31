package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestProtocolClosesSixScenarioPhaseAndAssertionSets(t *testing.T) {
	t.Parallel()
	if len(scenarioOrder) != 6 || len(scenarioPhases) != 6 || len(scenarioAssertions) != 6 {
		t.Fatalf("protocol counts = order:%d phases:%d assertions:%d", len(scenarioOrder), len(scenarioPhases), len(scenarioAssertions))
	}
	for _, scenarioID := range scenarioOrder {
		phases := scenarioPhases[scenarioID]
		assertions := scenarioAssertions[scenarioID]
		if len(phases) < 3 || phases[0] != "prepare" || phases[len(phases)-1] != "verify" || len(assertions) < 5 {
			t.Fatalf("scenario %q has invalid closed protocol", scenarioID)
		}
		for index, phase := range phases {
			if got, err := expectedPhase(scenarioID, index); err != nil || got != phase {
				t.Fatalf("expectedPhase(%q,%d) = %q/%v", scenarioID, index, got, err)
			}
			if _, err := phaseMarker(phase); err != nil {
				t.Fatalf("phaseMarker(%q): %v", phase, err)
			}
		}
	}
}

func TestScenarioAssertionsFailClosed(t *testing.T) {
	t.Parallel()
	run := &scenarioRun{id: scenarioOrder[0], assertions: make(map[string]assertion)}
	if err := run.pass("arbitrary_true", "not a release assertion"); err == nil {
		t.Fatal("arbitrary assertion was accepted")
	}
	for _, name := range scenarioAssertions[run.id] {
		if err := run.pass(name, "machine checked exact disposable state"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := run.verifiedAssertions(); err != nil {
		t.Fatal(err)
	}
	if err := run.pass(scenarioAssertions[run.id][0], "duplicate"); err == nil {
		t.Fatal("duplicate assertion was accepted")
	}
}

func TestDriverRejectsNonPrivateCoordinates(t *testing.T) {
	t.Parallel()
	if _, err := validatePrivateOrigin("http://10.238.1.10:19090", 19090); err != nil {
		t.Fatalf("private origin rejected: %v", err)
	}
	for _, raw := range []string{
		"https://10.238.1.10:19090",
		"http://example.com:19090",
		"http://0.0.0.0:19090",
		"http://10.238.1.10:19091",
	} {
		if _, err := validatePrivateOrigin(raw, 19090); err == nil {
			t.Fatalf("unsafe origin %q was accepted", raw)
		}
	}
}

func TestSSETerminalRequiresDoneAndBoundsLines(t *testing.T) {
	t.Parallel()
	if err := readSSETerminal(bufio.NewReader(strings.NewReader("data: {}\n\ndata: [DONE]\n\n"))); err != nil {
		t.Fatalf("valid terminal event rejected: %v", err)
	}
	if err := readSSETerminal(bufio.NewReader(strings.NewReader("data: {}\n\n"))); err == nil {
		t.Fatal("truncated SSE stream was accepted")
	}
	oversized := "data: " + strings.Repeat("x", 65<<10) + "\n"
	if err := readSSETerminal(bufio.NewReader(strings.NewReader(oversized))); err == nil {
		t.Fatal("oversized SSE line was accepted")
	}
}
