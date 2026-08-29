package openaichat

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

func FuzzInspectAndRewrite(f *testing.F) {
	f.Add(`{"model":"client","messages":[{"role":"user","content":"hello"}]}`)
	f.Add(`{"model":"client","messages":[{"role":"assistant","content":null,"tool_calls":[]}],"stream":true,"max_completion_tokens":100}`)
	f.Add(`{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":null,"n":null,"max_completion_tokens":null}`)
	f.Add(`{"model":"client","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}]}`)
	f.Add(`{"model":"client","messages":[{"role":"user","content":"hello"}],"model":"duplicate"}`)
	f.Add("not-json")

	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(
			http.MethodPost,
			"https://gateway.example/v1/chat/completions",
			strings.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		adapter := Adapter{MaximumBodyBytes: 16 << 10}
		if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
			return
		}
		if _, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
			PhysicalModel: "server-model", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
		}); err != nil {
			t.Fatalf("valid inspected request could not be rewritten: %v", err)
		}
		measurement, err := adapter.MeasureRequest(context.Background(), request)
		if err != nil || measurement.Protocol != ID || measurement.RequestBytes < 0 ||
			measurement.ImageUnits < 0 || measurement.ToolCalls < 0 ||
			!measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
			t.Fatalf("valid rewritten request produced invalid exact measurement: %+v, %v", measurement, err)
		}
		rewritten, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if measurement.RequestBytes != int64(len(rewritten)) ||
			measurement.RewrittenBodySHA256 != sha256.Sum256(rewritten) {
			t.Fatalf("measurement does not bind rewritten body: %+v", measurement)
		}
		value, err := jsonsafe.Decode(rewritten)
		if err != nil {
			t.Fatalf("rewrite is not strict JSON: %v", err)
		}
		object, ok := value.(map[string]any)
		if !ok || object["model"] != "server-model" {
			t.Fatalf("rewrite did not preserve the server model: %s", rewritten)
		}
		_, hasLegacy := object["max_tokens"]
		_, hasCompletion := object["max_completion_tokens"]
		if hasLegacy == hasCompletion {
			t.Fatalf("rewrite must contain exactly one output limit: %s", rewritten)
		}
	})
}

func FuzzTrustedInputPreflight(f *testing.F) {
	f.Add(`{"model":"client","messages":[{"role":"user","content":"hello"}]}`)
	f.Add(`{"model":"client","messages":[{"role":"developer","content":"brief"},{"role":"user","content":"你好 🌉"}],"stream":true,"n":1}`)
	f.Add(`{"model":"client","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]}]}`)
	f.Add(`{"model":"client","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}],"tools":[{"type":"function","function":{"name":"lookup"}}]}`)
	f.Add("not-json")

	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(
			http.MethodPost,
			"https://gateway.example/v1/chat/completions",
			strings.NewReader(body),
		)
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
		before := requestBodyFromFactory(t, request)
		profile := protocol.TrustedInputProfile{
			ID: "fuzz_profile", Protocol: ID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "server-model", MaximumFramingTokensPerRequest: 5,
			MaximumFramingTokensPerMessage: 3, MaximumContextTokens: 1_000_000,
		}
		preflight, preflightErr := adapter.PreflightInput(context.Background(), request, profile)
		after, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
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
			preflight.RequestBytes != int64(len(before)) ||
			preflight.InputTokenBound != int64(len(before))+5+preflight.MessageCount*3 ||
			preflight.OutputTokenBound <= 0 ||
			preflight.TotalTokenBound != preflight.InputTokenBound+preflight.OutputTokenBound ||
			preflight.ProfileDigest != profile.Digest() || preflight.PhysicalModel != "server-model" {
			t.Fatalf("invalid trusted input proof: %+v", preflight)
		}
	})
}

func FuzzUsageObservers(f *testing.F) {
	f.Add([]byte(`{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`))
	f.Add([]byte("data: [DONE]\n\n"))
	f.Add([]byte("data: {}\n\n"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2<<20 {
			t.Skip()
		}
		jsonObserver := &jsonObserver{}
		if err := jsonObserver.Observe(input); err != nil {
			t.Fatalf("JSON observer Observe returned an error: %v", err)
		}
		_, _ = jsonObserver.Finalize()

		sseObserver := &sseObserver{}
		if err := sseObserver.Observe(input); err == nil {
			_, _ = sseObserver.Finalize()
		}
	})
}

func FuzzSSEChunkPartitionInvariant(f *testing.F) {
	usage := `{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`
	f.Add([]byte("data: {}\n\ndata: "+usage+"\n\ndata: [DONE]\n\n"), []byte{1})
	f.Add([]byte("data: {}\r\rdata: "+usage+"\r\rdata: [DONE]\r\r"), []byte{2, 1, 3})
	f.Add([]byte("data: "+usage+"\r\n\r\ndata: [DONE]\r\n\r\n"), []byte{7, 1})
	f.Add([]byte("data: {}\n\n"), []byte{1})
	f.Add([]byte("data: [DONE]\n\ndata: {}\n\n"), []byte{4, 1, 2})
	f.Add([]byte("data: "+usage+"\n\ndata: "+usage+"\n\ndata: [DONE]\n\n"), []byte{9, 2})

	f.Fuzz(func(t *testing.T, input, partitions []byte) {
		if len(input) > 128<<10 || len(partitions) > 256 {
			t.Skip()
		}
		wholeUsage, wholeErr := observeSSEInChunks(input, len(input)+1)
		partitionedUsage, partitionedErr := observeSSEWithPartitions(input, partitions)
		if wholeUsage != partitionedUsage || errorText(wholeErr) != errorText(partitionedErr) {
			t.Fatalf(
				"chunk-dependent SSE result: whole usage=%+v err=%v; partitioned usage=%+v err=%v; input=%q partitions=%v",
				wholeUsage, wholeErr, partitionedUsage, partitionedErr, input, partitions,
			)
		}
	})
}

func observeSSEWithPartitions(input, partitions []byte) (protocol.Usage, error) {
	observer := &sseObserver{}
	for offset, partitionIndex := 0, 0; offset < len(input); partitionIndex++ {
		chunkSize := 1
		if len(partitions) > 0 {
			chunkSize = int(partitions[partitionIndex%len(partitions)]) + 1
		}
		end := offset + chunkSize
		if end > len(input) {
			end = len(input)
		}
		if err := observer.Observe(input[offset:end]); err != nil {
			return protocol.Usage{}, err
		}
		offset = end
	}
	return observer.Finalize()
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
