package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/latchway/latchway/adapters/protocol/anthropicmessages"
	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/adapters/protocol/openaiembeddings"
	"github.com/latchway/latchway/adapters/protocol/openairesponses"
	"github.com/latchway/latchway/internal/protocol"
)

type trustedInputAdapter interface {
	protocol.Adapter
	protocol.InputPreflighter
}

func TestInputAccountingMinimumBodyMatchesStructuredAdapterPreflight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		protocolID    string
		physicalModel string
		outputTokens  int64
		adapter       trustedInputAdapter
	}{
		{
			name: "OpenAI Chat", protocolID: protocol.OpenAIChatID,
			physicalModel: `quote"slash\model`, outputTokens: 17, adapter: openaichat.Adapter{},
		},
		{
			name: "OpenAI Responses", protocolID: protocol.OpenAIResponsesID,
			physicalModel: "responses<>&-模型", outputTokens: 31, adapter: openairesponses.Adapter{},
		},
		{
			name: "OpenAI Embeddings", protocolID: protocol.OpenAIEmbeddingsID,
			physicalModel: "embedding-模型", outputTokens: 0, adapter: openaiembeddings.Adapter{},
		},
		{
			name: "Anthropic Messages", protocolID: protocol.AnthropicMessagesID,
			physicalModel: "claude-model", outputTokens: 23, adapter: anthropicmessages.Adapter{},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configured := InputAccountingProfile{
				ID: "trusted_profile", Protocol: test.protocolID, Method: inputAccountingMethod,
				PhysicalModel:                  test.physicalModel,
				MaximumFramingTokensPerRequest: 8,
				MaximumFramingTokensPerMessage: 4,
			}
			minimalRequest, ok := minimumInputAccountingRequest(configured, test.outputTokens)
			if !ok {
				t.Fatal("configuration has no minimum request for a structured protocol")
			}
			minimalBody, err := json.Marshal(minimalRequest)
			if err != nil {
				t.Fatal(err)
			}
			contextMaximum := int64(len(minimalBody)) + configured.MaximumFramingTokensPerRequest +
				configured.MaximumFramingTokensPerMessage + test.outputTokens
			configured.MaximumContextTokens = contextMaximum
			if !inputAccountingRouteContextPossible(configured, test.outputTokens) {
				t.Fatal("configuration rejected the exact minimal trusted request")
			}
			configured.MaximumContextTokens--
			if inputAccountingRouteContextPossible(configured, test.outputTokens) {
				t.Fatal("configuration accepted one token less than the exact minimum")
			}
			configured.MaximumContextTokens++

			endpoint, ok := protocol.EndpointForProtocol(test.protocolID)
			if !ok {
				t.Fatal("structured protocol endpoint is missing")
			}
			request, err := http.NewRequestWithContext(
				context.Background(), http.MethodPost,
				"https://gateway.example"+endpoint.PublicPath, bytes.NewReader(minimalBody),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			applied, err := test.adapter.ApplyFeature(request.Context(), request, protocol.FeatureDecision{
				PhysicalModel:       test.physicalModel,
				DefaultOutputTokens: test.outputTokens,
				MaximumOutputTokens: test.outputTokens,
			})
			if err != nil || applied != test.outputTokens {
				t.Fatalf("ApplyFeature() output=%d error=%v", applied, err)
			}
			rewritten, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rewritten, minimalBody) {
				t.Fatalf("rewritten minimum = %s, want %s", rewritten, minimalBody)
			}
			request.Body = io.NopCloser(bytes.NewReader(rewritten))
			request.ContentLength = int64(len(rewritten))

			preflight, err := test.adapter.PreflightInput(request.Context(), request, protocol.TrustedInputProfile{
				ID: configured.ID, Protocol: configured.Protocol, Method: configured.Method,
				PhysicalModel:                  configured.PhysicalModel,
				MaximumFramingTokensPerRequest: configured.MaximumFramingTokensPerRequest,
				MaximumFramingTokensPerMessage: configured.MaximumFramingTokensPerMessage,
				MaximumContextTokens:           configured.MaximumContextTokens,
			})
			if err != nil {
				t.Fatalf("PreflightInput() error = %v", err)
			}
			if preflight.RequestBytes != int64(len(minimalBody)) || preflight.MessageCount != 1 ||
				preflight.InputTokenBound != int64(len(minimalBody))+12 ||
				preflight.OutputTokenBound != test.outputTokens || preflight.TotalTokenBound != contextMaximum {
				t.Fatalf("minimal trusted proof = %+v", preflight)
			}
		})
	}
}
