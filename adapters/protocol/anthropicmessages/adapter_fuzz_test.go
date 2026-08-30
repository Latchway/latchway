package anthropicmessages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func FuzzInspectAndApplyFeature(f *testing.F) {
	for _, seed := range []string{
		validRequestBody,
		`{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":true}`,
		`{"model":"client","model":"other","messages":[]}`,
		`{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]}],"tools":[{"name":"x","input_schema":{"type":"object"}}]}`,
		`{"model":"client","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"YQ=="}}]}]}`,
		`{`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		// The configured adapter limit is deliberately small so arbitrary fuzz
		// inputs exercise the bounded read path without retaining large corpora.
		adapter := Adapter{MaximumBodyBytes: 64 << 10}
		request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/messages", bytes.NewReader(input))
		if err != nil {
			t.Skip()
		}
		request.Header.Set("Content-Type", "application/json")
		metadata, err := adapter.InspectRequest(context.Background(), request)
		if err != nil {
			return
		}
		if metadata.ClientModel == "" || metadata.RequestBytes < 0 || metadata.RequestBytes > 64<<10 ||
			metadata.RequestedOutputLimit < 0 || request.GetBody == nil {
			t.Fatalf("successful inspection returned invalid metadata: %+v", metadata)
		}
		inspected, err := request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		inspectedBytes, err := io.ReadAll(inspected)
		_ = inspected.Close()
		if err != nil || !bytes.Equal(inspectedBytes, input) {
			t.Fatalf("successful inspection did not preserve owned body: error=%v", err)
		}

		effective, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
			PhysicalModel: "server-model", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
		})
		if err != nil {
			t.Fatalf("ApplyFeature rejected a successfully inspected request: %v", err)
		}
		if effective <= 0 || effective > 128 || request.GetBody == nil ||
			request.Header.Get("Anthropic-Version") != CanonicalAPIVersion {
			t.Fatalf("successful rewrite violated invariants: effective=%d headers=%v", effective, request.Header)
		}
		measurement, measurementErr := adapter.MeasureRequest(context.Background(), request)
		if measurementErr != nil || measurement.Protocol != ID || measurement.RequestBytes < 0 ||
			measurement.ImageUnits < 0 || measurement.ToolCalls < 0 ||
			!measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
			t.Fatalf("valid rewritten request produced invalid exact measurement: %+v, %v", measurement, measurementErr)
		}
		rewritten := readBodyFactory(t, request)
		if measurement.RequestBytes != int64(len(rewritten)) ||
			measurement.RewrittenBodySHA256 != sha256.Sum256(rewritten) {
			t.Fatalf("measurement does not bind rewritten body: %+v", measurement)
		}
	})
}

func FuzzTrustedInputPreflight(f *testing.F) {
	f.Add(`{"model":"client","messages":[{"role":"user","content":"hello"}]}`)
	f.Add(`{"model":"client","messages":[{"role":"user","content":[{"type":"text","text":"你好 🌉"}]}],"stream":true}`)
	f.Add(`{"model":"client","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGk="}}]}]}`)
	f.Add("not-json")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/messages", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		adapter := Adapter{MaximumBodyBytes: 16 << 10}
		if _, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
			PhysicalModel: "server-model", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
		}); err != nil {
			return
		}
		before := readBodyFactory(t, request)
		profile := protocol.TrustedInputProfile{
			ID: "anthropic_profile", Protocol: ID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "server-model", MaximumFramingTokensPerRequest: 5,
			MaximumFramingTokensPerMessage: 3, MaximumContextTokens: 1_000_000,
		}
		preflight, preflightErr := adapter.PreflightInput(context.Background(), request, profile)
		after := readBody(t, request.Body)
		if string(after) != string(before) {
			t.Fatal("trusted input preflight changed the exact rewritten body")
		}
		if preflightErr != nil {
			if preflight != (protocol.TrustedInputPreflight{}) {
				t.Fatalf("failed preflight returned a partial proof: %+v", preflight)
			}
			return
		}
		if preflight.RewrittenBodySHA256 != sha256.Sum256(before) ||
			preflight.InputTokenBound != int64(len(before))+5+preflight.MessageCount*3 ||
			preflight.OutputTokenBound <= 0 ||
			preflight.TotalTokenBound != preflight.InputTokenBound+preflight.OutputTokenBound {
			t.Fatalf("invalid trusted input proof: %+v", preflight)
		}
	})
}

func FuzzJSONObserver(f *testing.F) {
	for _, seed := range []string{
		`{"type":"message","usage":{"input_tokens":1,"output_tokens":2}}`,
		`{"type":"message","usage":{"input_tokens":9223372036854775807,"output_tokens":1}}`,
		`{"type":"message","usage":{"input_tokens":1,"input_tokens":2,"output_tokens":3}}`,
		`{`,
	} {
		f.Add([]byte(seed), uint8(7))
	}
	f.Fuzz(func(t *testing.T, input []byte, rawChunkSize uint8) {
		if len(input) > int(maximumObservedJSON)+1 {
			return
		}
		observer := &jsonObserver{ctx: context.Background()}
		chunkSize := int(rawChunkSize) + 1
		for offset := 0; offset < len(input); offset += chunkSize {
			end := offset + chunkSize
			if end > len(input) {
				end = len(input)
			}
			if err := observer.Observe(input[offset:end]); err != nil {
				return
			}
		}
		usage, err := observer.Finalize()
		if err != nil {
			return
		}
		assertNormalizedFuzzUsage(t, usage)
	})
}

func FuzzSSEObserver(f *testing.F) {
	valid := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	for _, seed := range []string{
		valid,
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n",
		"data: [DONE]\n\n",
		"event: message_start\ndata: {\"type\":\"message_start\",\"type\":\"message_start\"}\n\n",
	} {
		f.Add([]byte(seed), uint8(3))
	}
	f.Fuzz(func(t *testing.T, input []byte, rawChunkSize uint8) {
		// Event size and event-count limits provide the production bound. This
		// extra corpus cap keeps seed execution proportionate under go test.
		if len(input) > 2*maximumSSEEvent {
			return
		}
		observer := &sseObserver{ctx: context.Background()}
		chunkSize := int(rawChunkSize) + 1
		for offset := 0; offset < len(input); offset += chunkSize {
			end := offset + chunkSize
			if end > len(input) {
				end = len(input)
			}
			if err := observer.Observe(input[offset:end]); err != nil {
				return
			}
		}
		usage, err := observer.Finalize()
		if err != nil {
			return
		}
		assertNormalizedFuzzUsage(t, usage)
	})
}

func assertNormalizedFuzzUsage(t *testing.T, usage protocol.Usage) {
	t.Helper()
	if !usage.Known || usage.Provenance != providerUsageProvenance || usage.InputTokens < 0 ||
		usage.OutputTokens < 0 || usage.TotalTokens < 0 ||
		usage.InputTokens > int64(^uint64(0)>>1)-usage.OutputTokens ||
		usage.TotalTokens != usage.InputTokens+usage.OutputTokens {
		t.Fatalf("observer returned non-normalized usage: %+v", usage)
	}
}
