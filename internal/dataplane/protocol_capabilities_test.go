package dataplane

import (
	"testing"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
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

func TestValidateFeatureLimitPlanBindsMetricsToProtocolCapabilities(t *testing.T) {
	t.Parallel()

	logical := configuration.Limit{
		Metric: quota.LogicalRequestsMetric, Algorithm: quota.CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 10, Hard: true,
	}
	output := configuration.Limit{
		Metric: quota.OutputTokensMetric, Algorithm: quota.CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 10, Hard: true,
	}
	input := configuration.Limit{
		Metric: quota.InputTokensMetric, Algorithm: quota.CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 10, Hard: true,
	}
	streams := configuration.Limit{
		Metric: quota.ConcurrentStreamsMetric, Algorithm: quota.ConcurrencyAlgorithm,
		Scope: []string{"user"}, Maximum: 1, Hard: true,
	}
	outputPolicy := &configuration.OutputPolicy{DefaultMaximumTokens: 4, AbsoluteMaximumTokens: 8}
	tests := []struct {
		name     string
		feature  configuration.Feature
		limits   []configuration.Limit
		wantOK   bool
		wantZero bool
	}{
		{
			name: "Embeddings logical requests", wantOK: true, wantZero: true,
			feature: configuration.Feature{ID: "feature", Protocol: protocol.OpenAIEmbeddingsID},
			limits:  []configuration.Limit{logical},
		},
		{
			name:    "Embeddings output policy rejected",
			feature: configuration.Feature{ID: "feature", Protocol: protocol.OpenAIEmbeddingsID, Output: outputPolicy},
			limits:  []configuration.Limit{logical},
		},
		{
			name:    "Embeddings output quota rejected",
			feature: configuration.Feature{ID: "feature", Protocol: protocol.OpenAIEmbeddingsID},
			limits:  []configuration.Limit{output},
		},
		{
			name:    "Embeddings stream concurrency rejected",
			feature: configuration.Feature{ID: "feature", Protocol: protocol.OpenAIEmbeddingsID},
			limits:  []configuration.Limit{streams},
		},
		{
			name:    "Responses input quota rejected",
			feature: configuration.Feature{ID: "feature", Protocol: protocol.OpenAIResponsesID, Output: outputPolicy},
			limits:  []configuration.Limit{input},
		},
		{
			name: "Anthropic output quota", wantOK: true,
			feature: configuration.Feature{ID: "feature", Protocol: protocol.AnthropicMessagesID, Output: outputPolicy},
			limits:  []configuration.Limit{output},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			validated, err := validateFeatureLimitPlan("feature", test.feature, configuration.LimitPlan{
				ID: "plan", Limits: test.limits,
			})
			if (err == nil) != test.wantOK {
				t.Fatalf("validateFeatureLimitPlan() err = %v, wantOK=%t", err, test.wantOK)
			}
			if test.wantZero && (validated.defaultOutputTokens != 0 || validated.maximumOutputTokens != 0) {
				t.Fatalf("non-generative output bounds = %+v", validated)
			}
		})
	}
}
