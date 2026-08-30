package openairesponses

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
	f.Add(`{"model":"client","input":"hello"}`)
	f.Add(`{"model":"client","input":[{"role":"user","content":"hello"}],"stream":true,"stream_options":{"include_obfuscation":true},"max_output_tokens":100}`)
	f.Add(`{"model":"client","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"result"}],"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]}`)
	f.Add(`{"model":"client","model":"duplicate","input":"hello"}`)
	f.Add(`{"model":"client","input":"hello","background":true}`)
	f.Add("not-json")

	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(
			http.MethodPost,
			"https://gateway.example/v1/responses",
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
		effective, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
			PhysicalModel: "server-model", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
		})
		if err != nil {
			t.Fatalf("valid inspected request could not be rewritten: %v", err)
		}
		if effective <= 0 || effective > 128 {
			t.Fatalf("invalid effective output maximum: %d", effective)
		}
		measurement, measurementErr := adapter.MeasureRequest(context.Background(), request)
		if measurementErr != nil || measurement.Protocol != ID || measurement.RequestBytes < 0 ||
			measurement.ImageUnits != 0 || measurement.ToolCalls < 0 ||
			!measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
			t.Fatalf("valid rewritten request produced invalid exact measurement: %+v, %v", measurement, measurementErr)
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
		if !ok || object["model"] != "server-model" || object["store"] != false {
			t.Fatalf("rewrite did not preserve the server model: %s", rewritten)
		}
		output, err := requestedOutputLimit(object)
		if err != nil || output != effective {
			t.Fatalf("rewrite output maximum=%d error=%v, want %d", output, err, effective)
		}
		first, err := request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		firstBytes, err := io.ReadAll(first)
		closeErr := first.Close()
		if err != nil || closeErr != nil || string(firstBytes) != string(rewritten) {
			t.Fatalf("GetBody is not a stable replay: read=%v close=%v", err, closeErr)
		}
	})
}

func FuzzTrustedInputPreflight(f *testing.F) {
	f.Add(`{"model":"client","input":"hello"}`)
	f.Add(`{"model":"client","input":[{"role":"user","content":"你好 🌉"}],"stream":true}`)
	f.Add(`{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup"}]}`)
	f.Add("not-json")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/responses", strings.NewReader(body))
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
			ID: "responses_profile", Protocol: ID,
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

func FuzzUsageObservers(f *testing.F) {
	f.Add([]byte(`{"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}`))
	f.Add([]byte(`{"usage":{"input_tokens":9223372036854775808,"output_tokens":0,"total_tokens":0}}`))
	f.Add([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}\n\n"))
	f.Add([]byte("data: [DONE]\n\n"))

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
	usage := `{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}`
	f.Add([]byte("data: {\"type\":\"response.created\"}\n\ndata: "+usage+"\n\n"), []byte{1})
	f.Add([]byte("event: response.completed\rdata: "+usage+"\r\r"), []byte{2, 1, 3})
	f.Add([]byte("event: response.completed\r\ndata: "+usage+"\r\n\r\n"), []byte{7, 1})
	f.Add([]byte("data: {\"type\":\"response.created\"}\n\n"), []byte{1})
	f.Add([]byte("data: "+usage+"\n\ndata: {\"type\":\"response.created\"}\n\n"), []byte{4, 1, 2})
	f.Add([]byte("data: "+usage+"\n\ndata: "+usage+"\n\n"), []byte{9, 2})

	f.Fuzz(func(t *testing.T, input, partitions []byte) {
		if len(input) > 128<<10 || len(partitions) > 256 {
			t.Skip()
		}
		wholeUsage, wholeErr := observeSSEWithPartitions(input, []byte{255})
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
		chunkSize := len(input) + 1
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
