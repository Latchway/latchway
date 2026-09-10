package openairesponses

import (
	"github.com/latchway/latchway/internal/protocol"
	"testing"
)

func TestFailureTerminalPreservesUsageAndNeverSucceeds(t *testing.T) {
	for _, terminal := range []string{"response.failed", "response.incomplete"} {
		observer := &sseObserver{}
		event := "event: " + terminal + "\ndata: {\"type\":\"" + terminal + "\",\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":3,\"total_tokens\":5}}}\n\n"
		if err := observer.Observe([]byte(event)); err != nil {
			t.Fatal(err)
		}
		usage, err := observer.Finalize()
		if !protocol.IsCode(err, "upstream_protocol_error") || !usage.Known || usage.TotalTokens != 5 {
			t.Fatalf("terminal = %+v, %v", usage, err)
		}
	}
	observer := &sseObserver{}
	if err := observer.Observe([]byte("event: error\ndata: {\"type\":\"error\",\"message\":\"SECRET provider body\"}\n\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Finalize(); !protocol.IsCode(err, "upstream_protocol_error") || err.Error() == "SECRET provider body" {
		t.Fatal(err)
	}
}

func TestCompletedEventCannotDisguiseFailedResponse(t *testing.T) {
	for _, extra := range []string{`"status":"failed",`, `"status":"incomplete",`, `"error":{"message":"secret"},`} {
		observer := &sseObserver{}
		if err := observer.Observe([]byte("data: {\"type\":\"response.completed\",\"response\":{" + extra + "\"usage\":{\"input_tokens\":2,\"output_tokens\":3,\"total_tokens\":5}}}\n\n")); err != nil {
			t.Fatal(err)
		}
		usage, err := observer.Finalize()
		if !protocol.IsCode(err, "upstream_protocol_error") || !usage.Known {
			t.Fatalf("contradictory completion = %+v, %v", usage, err)
		}
	}
}
