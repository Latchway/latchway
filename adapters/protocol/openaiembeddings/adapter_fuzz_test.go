package openaiembeddings

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
	f.Add(`{"model":"client","input":["hello","world"],"encoding_format":"base64","dimensions":256}`)
	f.Add(`{"model":"client","input":[0,1,2]}`)
	f.Add(`{"model":"client","input":[[0,1],[2,3]]}`)
	f.Add(`{"model":"client","model":"duplicate","input":"hello"}`)
	f.Add(`{"model":"client","input":"hello","user":"identity"}`)
	f.Add("not-json")

	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 64<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(
			http.MethodPost,
			"https://gateway.example/v1/embeddings",
			strings.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		adapter := Adapter{MaximumBodyBytes: 128 << 10}
		metadata, err := adapter.InspectRequest(context.Background(), request)
		if err != nil {
			return
		}
		if metadata.Streaming || metadata.RequestedOutputLimit != 0 || metadata.RequestBytes != int64(len(body)) {
			t.Fatalf("invalid inspected metadata: %+v", metadata)
		}
		effective, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server-model"})
		if err != nil {
			t.Fatalf("valid inspected request could not be rewritten: %v", err)
		}
		if effective != 0 {
			t.Fatalf("invalid effective output maximum: %d", effective)
		}
		rewritten, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		value, err := jsonsafe.Decode(rewritten)
		if err != nil {
			t.Fatalf("rewrite is not strict JSON: %v", err)
		}
		object, ok := value.(map[string]any)
		if !ok || object["model"] != "server-model" || !hasOnlyMembers(object, "model", "input", "encoding_format", "dimensions") {
			t.Fatalf("rewrite escaped the v1 request surface: %s", rewritten)
		}
		if _, err := inspectRequestObject(object, rewritten); err != nil {
			t.Fatalf("rewrite no longer passes protocol validation: %v", err)
		}
		first, err := request.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		firstBytes, readErr := io.ReadAll(first)
		closeErr := first.Close()
		if readErr != nil || closeErr != nil || string(firstBytes) != string(rewritten) {
			t.Fatalf("GetBody is not a stable replay: read=%v close=%v", readErr, closeErr)
		}
	})
}

func FuzzTrustedInputPreflight(f *testing.F) {
	f.Add(`{"model":"client","input":"hello"}`)
	f.Add(`{"model":"client","input":["hello","你好 🌉"]}`)
	f.Add(`{"model":"client","input":[1,2,3]}`)
	f.Add("not-json")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8<<10 {
			t.Skip()
		}
		request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/embeddings", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		adapter := Adapter{MaximumBodyBytes: 16 << 10}
		if _, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server-model"}); err != nil {
			return
		}
		before := readBodyFactory(t, request)
		profile := protocol.TrustedInputProfile{
			ID: "embeddings_profile", Protocol: ID,
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
			preflight.OutputTokenBound != 0 || preflight.TotalTokenBound != preflight.InputTokenBound {
			t.Fatalf("invalid trusted input proof: %+v", preflight)
		}
	})
}

func FuzzUsageObserver(f *testing.F) {
	f.Add([]byte(`{"usage":{"prompt_tokens":1,"total_tokens":1}}`))
	f.Add([]byte(`{"usage":{"prompt_tokens":0,"total_tokens":0}}`))
	f.Add([]byte(`{"usage":{"prompt_tokens":9223372036854775808,"total_tokens":0}}`))
	f.Add([]byte(`{"usage":{"prompt_tokens":1,"prompt_tokens":1,"total_tokens":1}}`))
	f.Add([]byte(`{"usage":null}`))
	f.Add([]byte("not-json"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 2<<20 {
			t.Skip()
		}
		for split := 0; split <= len(input); split += len(input)/3 + 1 {
			observer := &jsonObserver{}
			if err := observer.Observe(input[:split]); err != nil {
				t.Fatalf("first Observe() error = %v", err)
			}
			if err := observer.Observe(input[split:]); err != nil {
				t.Fatalf("second Observe() error = %v", err)
			}
			_, _ = observer.Finalize()
		}
	})
}
