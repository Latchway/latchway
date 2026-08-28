package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/internal/protocol"
)

func TestInputAccountingMinimumBodyMatchesOpenAIChatPreflight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		physicalModel string
		outputTokens  int64
	}{
		{name: "plain one digit", physicalModel: "plain", outputTokens: 9},
		{name: "quote slash two digits", physicalModel: `quote"slash\model`, outputTokens: 10},
		{name: "html escaped three digits", physicalModel: "model<>&", outputTokens: 999},
		{name: "unicode separators four digits", physicalModel: "model\u2028\u2029-模型", outputTokens: 1000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			minimalBody, err := json.Marshal(map[string]any{
				"max_tokens": test.outputTokens,
				"messages": []any{map[string]any{
					"content": "",
					"role":    "user",
				}},
				"model": test.physicalModel,
			})
			if err != nil {
				t.Fatal(err)
			}
			const requestFraming int64 = 8
			const messageFraming int64 = 4
			contextMaximum := requestFraming + messageFraming + int64(len(minimalBody)) + test.outputTokens
			configured := InputAccountingProfile{
				ID: "chat_profile", Protocol: inputAccountingProtocol, Method: inputAccountingMethod,
				PhysicalModel:                  test.physicalModel,
				MaximumFramingTokensPerRequest: requestFraming,
				MaximumFramingTokensPerMessage: messageFraming,
				MaximumContextTokens:           contextMaximum,
			}
			if !inputAccountingRouteContextPossible(configured, test.outputTokens) {
				t.Fatal("configuration rejected the exact minimal trusted Chat body")
			}
			configured.MaximumContextTokens--
			if inputAccountingRouteContextPossible(configured, test.outputTokens) {
				t.Fatal("configuration accepted one token less than the exact minimal trusted Chat body")
			}
			configured.MaximumContextTokens++

			request, err := http.NewRequestWithContext(
				context.Background(), http.MethodPost,
				"https://gateway.example/v1/chat/completions", bytes.NewReader(minimalBody),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			adapter := openaichat.Adapter{}
			applied, err := adapter.ApplyFeature(request.Context(), request, protocol.FeatureDecision{
				PhysicalModel: test.physicalModel, DefaultOutputTokens: test.outputTokens,
				MaximumOutputTokens: test.outputTokens,
			})
			if err != nil || applied != test.outputTokens {
				t.Fatalf("apply minimal trusted Chat request = %d, %v", applied, err)
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

			preflight, err := adapter.PreflightInput(request.Context(), request, protocol.TrustedInputProfile{
				ID: configured.ID, Protocol: configured.Protocol, Method: configured.Method,
				PhysicalModel:                  configured.PhysicalModel,
				MaximumFramingTokensPerRequest: configured.MaximumFramingTokensPerRequest,
				MaximumFramingTokensPerMessage: configured.MaximumFramingTokensPerMessage,
				MaximumContextTokens:           configured.MaximumContextTokens,
			})
			if err != nil {
				t.Fatalf("preflight exact minimal trusted Chat request: %v", err)
			}
			if preflight.RequestBytes != int64(len(minimalBody)) || preflight.MessageCount != 1 ||
				preflight.InputTokenBound != int64(len(minimalBody))+requestFraming+messageFraming ||
				preflight.OutputTokenBound != test.outputTokens || preflight.TotalTokenBound != contextMaximum {
				t.Fatalf("minimal trusted Chat proof = %+v", preflight)
			}
		})
	}
}
