package openaichat

import (
	"github.com/latchway/latchway/internal/protocol"
	"strings"
	"testing"
)

func TestErrorEnvelopeCannotBecomeSuccessfulUnknownUsage(t *testing.T) {
	for _, suffix := range []string{"", "data: [DONE]\n\n"} {
		observer := &sseObserver{}
		err := observer.Observe([]byte("data: {\"error\":{\"message\":\"SECRET provider body\"},\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":5}}\n\n" + suffix))
		if err != nil {
			t.Fatal(err)
		}
		usage, err := observer.Finalize()
		if !protocol.IsCode(err, "upstream_protocol_error") || !usage.Known || usage.TotalTokens != 5 || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("terminal = %+v, %v", usage, err)
		}
	}
}
