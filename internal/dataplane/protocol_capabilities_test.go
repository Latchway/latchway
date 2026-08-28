package dataplane

import (
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestValidAppliedOutputMaximumBindsAdapterCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		capabilities protocol.Capabilities
		decision     validatedDecision
		applied      int64
		want         bool
	}{
		{
			name:         "generative positive exact bound",
			capabilities: protocol.Capabilities{OutputTokenClamp: true},
			decision:     validatedDecision{defaultOutputTokens: 64, maximumOutputTokens: 128},
			applied:      128, want: true,
		},
		{
			name:         "generative zero rejected",
			capabilities: protocol.Capabilities{OutputTokenClamp: true},
			decision:     validatedDecision{defaultOutputTokens: 64, maximumOutputTokens: 128},
			applied:      0,
		},
		{
			name:     "non-generative zero",
			decision: validatedDecision{}, applied: 0, want: true,
		},
		{
			name:     "non-generative sentinel rejected",
			decision: validatedDecision{}, applied: 1,
		},
		{
			name:     "non-generative output policy rejected",
			decision: validatedDecision{defaultOutputTokens: 1, maximumOutputTokens: 1},
			applied:  0,
		},
		{
			name:     "negative rejected",
			decision: validatedDecision{}, applied: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validAppliedOutputMaximum(test.capabilities, test.decision, test.applied); got != test.want {
				t.Fatalf("validAppliedOutputMaximum() = %t, want %t", got, test.want)
			}
		})
	}
}
