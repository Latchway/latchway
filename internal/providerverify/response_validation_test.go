package providerverify

import (
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestProbeResponseRequiresARealCompletionEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		streaming bool
		valid     bool
	}{
		{name: "json completion", valid: true, body: `{"choices":[{"index":0,"message":{"role":"assistant","content":"O"},"finish_reason":"length"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`},
		{name: "json usage only", body: `{"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`},
		{name: "json empty content", body: `{"choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"length"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`},
		{name: "json missing finish", body: `{"choices":[{"index":0,"message":{"role":"assistant","content":"O"},"finish_reason":null}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`},
		{name: "stream completion", streaming: true, valid: true, body: "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"O\"},\"finish_reason\":\"length\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1,\"total_tokens\":6}}\n\ndata: [DONE]\n\n"},
		{name: "stream usage only", streaming: true, body: "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1,\"total_tokens\":6}}\n\ndata: [DONE]\n\n"},
		{name: "stream no finish", streaming: true, body: "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"O\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"},
		{name: "stream data after done", streaming: true, body: "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"O\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\ndata: {}\n\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateProbeResponse([]byte(test.body), test.streaming)
			if (err == nil) != test.valid {
				t.Fatalf("validateProbeResponse() error=%v, want valid=%v", err, test.valid)
			}
		})
	}
}

func TestProbeUsageRequiresOneObservedOutputToken(t *testing.T) {
	probe := preparedProbe{InputMaximum: 100, OutputMaximum: 1, TotalMaximum: 101}
	for _, usage := range []protocol.Usage{
		{Known: true, InputTokens: 5, OutputTokens: 0, TotalTokens: 5},
		{Known: true, InputTokens: 5, OutputTokens: 2, TotalTokens: 7},
	} {
		if err := validateUsage(usage, probe); err == nil {
			t.Fatalf("nonconforming usage accepted: %+v", usage)
		}
	}
	if err := validateUsage(protocol.Usage{Known: true, InputTokens: 5, OutputTokens: 1, TotalTokens: 6}, probe); err != nil {
		t.Fatalf("one-token usage rejected: %v", err)
	}
}
