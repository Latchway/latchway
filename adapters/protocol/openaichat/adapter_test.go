package openaichat

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

func TestInspectAndApplyFeature(t *testing.T) {
	t.Parallel()

	request, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(`{
		"model":"client-model",
		"messages":[{"role":"user","content":"hello"}],
		"stream":true,
		"max_completion_tokens":2000
	}`))
	request.Header.Set("Content-Type", "application/json")
	adapter := Adapter{}
	metadata, err := adapter.InspectRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.Streaming || metadata.RequestedOutputLimit != 2000 || metadata.ClientModel != "client-model" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel:       "server-model",
		DefaultOutputTokens: 400,
		MaximumOutputTokens: 800,
	}); err != nil {
		t.Fatal(err)
	}
	rewritten, _ := io.ReadAll(request.Body)
	value, err := jsonsafe.Decode(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	object := value.(map[string]any)
	if object["model"] != "server-model" || object["max_completion_tokens"].(interface{ String() string }).String() != "800" {
		t.Fatalf("request not rewritten: %s", rewritten)
	}
	streamOptions := object["stream_options"].(map[string]any)
	if streamOptions["include_usage"] != true {
		t.Fatal("stream usage was not enabled")
	}
}

func TestRejectsAmbiguousOrDuplicateLimits(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"messages":[{}],"max_tokens":1,"max_completion_tokens":2}`,
		`{"messages":[{}],"max_tokens":1,"max_tokens":2}`,
	} {
		request, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "upstream_protocol_error") {
			t.Fatalf("body %s: error = %v", body, err)
		}
	}
}

func TestObservers(t *testing.T) {
	t.Parallel()

	t.Run("json", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14}}`))
		usage, err := observer.Finalize()
		if err != nil || !usage.Known || usage.TotalTokens != 14 {
			t.Fatalf("usage=%+v err=%v", usage, err)
		}
	})

	t.Run("sse chunks", func(t *testing.T) {
		observer := &sseObserver{}
		chunks := []string{
			"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,",
			"\"completion_tokens\":2,\"total_tokens\":7}}\n\ndata: [DONE]\n\n",
		}
		for _, chunk := range chunks {
			if err := observer.Observe([]byte(chunk)); err != nil {
				t.Fatal(err)
			}
		}
		usage, err := observer.Finalize()
		if err != nil || !usage.Known || usage.InputTokens != 5 || usage.OutputTokens != 2 {
			t.Fatalf("usage=%+v err=%v", usage, err)
		}
	})
}
