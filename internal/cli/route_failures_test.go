package cli

import (
	"encoding/json"
	"testing"
)

func TestParseSimulationFailures(t *testing.T) {
	t.Parallel()
	parsed, err := parseSimulationFailures([]string{"primary=status_503", "backup=timeout_before_headers:2"})
	encoded, _ := json.Marshal(parsed)
	if err != nil || string(encoded) != `[{"condition":"status_503","route":"primary"},{"attempts":2,"condition":"timeout_before_headers","route":"backup"}]` {
		t.Fatalf("parseSimulationFailures = %s err=%v", encoded, err)
	}
	for _, value := range [][]string{
		{"primary"}, {"primary=status_418"}, {"Primary=status_503"}, {"primary=status_503:0"},
		{"primary=status_503:x"}, {"primary=status_503", "primary=status_429"},
	} {
		if _, err := parseSimulationFailures(value); err == nil {
			t.Fatalf("parseSimulationFailures accepted %v", value)
		}
	}
}
