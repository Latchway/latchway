package dataplane

import (
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestProjectedOutputMaximumMatchesProductionClamp(t *testing.T) {
	validated := validatedDecision{defaultOutputTokens: 40, maximumOutputTokens: 100}
	tests := []struct {
		name      string
		protocol  string
		requested int64
		want      int64
		ok        bool
	}{
		{name: "default", protocol: protocol.OpenAIChatID, want: 40, ok: true},
		{name: "requested", protocol: protocol.OpenAIChatID, requested: 80, want: 80, ok: true},
		{name: "clamped", protocol: protocol.OpenAIChatID, requested: 101, want: 100, ok: true},
		{name: "negative", protocol: protocol.OpenAIChatID, requested: -1, ok: false},
		{name: "embeddings zero", protocol: protocol.OpenAIEmbeddingsID, requested: 0, want: 0, ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := projectedOutputMaximum(test.protocol, validated, test.requested)
			if got != test.want || ok != test.ok {
				t.Fatalf("projectedOutputMaximum() = (%d, %t), want (%d, %t)", got, ok, test.want, test.ok)
			}
		})
	}

	zeroOutput := validatedDecision{}
	if got, ok := projectedOutputMaximum(protocol.OpenAIEmbeddingsID, zeroOutput, 0); got != 0 || !ok {
		t.Fatalf("embedding zero-output projection = (%d, %t), want (0, true)", got, ok)
	}
}
