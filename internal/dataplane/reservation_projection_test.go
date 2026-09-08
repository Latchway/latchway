package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/adapters/protocol/openairesponses"
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

func TestReservationProjectionIncludesRealAdapterSchemaExpansion(t *testing.T) {
	for _, test := range []struct {
		protocolID string
		adapter    protocol.InputPreflighter
		body       string
	}{
		{protocol.OpenAIChatID, openaichat.Adapter{}, `{"model":"physical","max_tokens":16,"messages":[{"role":"user","content":"Weather?"}],"tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object","$defs":{"city":{"type":"string"}},"properties":{"city":{"$ref":"#/$defs/city"}}}}}]}`},
		{protocol.OpenAIResponsesID, openairesponses.Adapter{}, `{"model":"physical","max_output_tokens":16,"input":"Weather?","tools":[{"type":"function","name":"weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}]}`},
	} {
		t.Run(test.protocolID, func(t *testing.T) {
			profile := protocol.TrustedInputProfile{ID: "profile", Protocol: test.protocolID, Method: protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
				PhysicalModel: "physical", MaximumFramingTokensPerRequest: 16, MaximumFramingTokensPerMessage: 8, MaximumContextTokens: 100000}
			path := "/v1/chat/completions"
			if test.protocolID == protocol.OpenAIResponsesID {
				path = "/v1/responses"
			}
			request := httptest.NewRequest(http.MethodPost, "https://provider.example"+path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if _, err := test.adapter.(protocol.Adapter).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
				PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 16,
			}); err != nil {
				t.Fatal(err)
			}
			actual, err := test.adapter.PreflightInput(context.Background(), request, profile)
			if err != nil {
				t.Fatal(err)
			}
			if actual.ExpandedSchemaBytes <= 0 || actual.Breakdown == nil || !actual.Breakdown.Matches(profile, actual) {
				t.Fatal("fixture did not produce schema diagnostics")
			}
			input := ReservationProjectionInput{RewrittenRequestBytes: actual.RequestBytes, FramingUnitCount: actual.MessageCount, ExpandedSchemaBytes: actual.ExpandedSchemaBytes}
			projected, err := projectTrustedInputPreflight(profile, input, 16)
			if err != nil || projected.InputTokenBound != actual.InputTokenBound || projected.TotalTokenBound != actual.TotalTokenBound {
				t.Fatalf("simulation disagrees with real adapter: %+v %+v %v", projected, actual, err)
			}
			input.ExpandedSchemaBytes = 0
			withoutSchemas, err := projectTrustedInputPreflight(profile, input, 16)
			if err != nil || projected.InputTokenBound-withoutSchemas.InputTokenBound != actual.ExpandedSchemaBytes {
				t.Fatal("schema expansion is absent from projected bound")
			}
			input.ExpandedSchemaBytes = -1
			if _, err := projectTrustedInputPreflight(profile, input, 16); err == nil {
				t.Fatal("negative schema expansion accepted")
			}
		})
	}
}
