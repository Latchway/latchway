package openaichat

import (
	"context"
	"errors"
	"fmt"
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
	applied, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel:       "server-model",
		DefaultOutputTokens: 400,
		MaximumOutputTokens: 800,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied != 800 {
		t.Fatalf("applied output maximum = %d, want 800", applied)
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
		`{"model":"client","messages":[{"role":"user","content":"hi"}],"max_tokens":1,"max_completion_tokens":2}`,
		`{"model":"client","messages":[{"role":"user","content":"hi"}],"max_tokens":1,"max_tokens":2}`,
	} {
		request, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
			t.Fatalf("body %s: error = %v", body, err)
		}
	}
}

func TestNullableOptionsUseDefaultsAndOneOutboundLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		options   string
		wantField string
		streaming bool
	}{
		{name: "modern null", options: `"stream":null,"n":null,"max_completion_tokens":null`, wantField: "max_completion_tokens"},
		{name: "legacy null", options: `"max_tokens":null`, wantField: "max_tokens"},
		{name: "both null", options: `"max_tokens":null,"max_completion_tokens":null`, wantField: "max_completion_tokens"},
		{name: "nullable stream options", options: `"stream":true,"stream_options":null`, wantField: "max_completion_tokens", streaming: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"client","messages":[{"role":"user","content":"hello"}],` + test.options + `}`
			request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			adapter := Adapter{}
			metadata, err := adapter.InspectRequest(context.Background(), request)
			if err != nil {
				t.Fatalf("InspectRequest() error = %v", err)
			}
			if metadata.Streaming != test.streaming || metadata.RequestedOutputLimit != 0 {
				t.Fatalf("metadata = %+v", metadata)
			}
			applied, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
				PhysicalModel: "physical", DefaultOutputTokens: 32, MaximumOutputTokens: 64,
			})
			if err != nil {
				t.Fatalf("ApplyFeature() error = %v", err)
			}
			if applied != 32 {
				t.Fatalf("applied output maximum = %d, want 32", applied)
			}
			rewritten, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonsafe.Decode(rewritten)
			if err != nil {
				t.Fatal(err)
			}
			object := value.(map[string]any)
			limit, ok := object[test.wantField].(interface{ String() string })
			if !ok || limit.String() != "32" {
				t.Fatalf("rewritten limit = %s", rewritten)
			}
			otherField := "max_tokens"
			if test.wantField == otherField {
				otherField = "max_completion_tokens"
			}
			if _, exists := object[otherField]; exists {
				t.Fatalf("ambiguous rewritten limits = %s", rewritten)
			}
			if test.streaming {
				options, ok := object["stream_options"].(map[string]any)
				if !ok || options["include_usage"] != true {
					t.Fatalf("stream usage option = %s", rewritten)
				}
			}
		})
	}
}

func TestInspectAcceptsBoundedMessageAndToolShapes(t *testing.T) {
	t.Parallel()

	body := `{
		"model":"client",
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"hello"},
				{"type":"image_url","image_url":{"url":"https://example.test/image.png","detail":"low"}},
				{"type":"input_audio","input_audio":{"data":"AA==","format":"wav"}},
				{"type":"file","file":{"file_id":"file_fixture_01","filename":"fixture.txt"}}
			]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_fixture_01","type":"function","function":{"name":"lookup_weather","arguments":"{\"city\":\"Paris\"}"}}]},
			{"role":"tool","tool_call_id":"call_fixture_01","content":"sunny"},
			{"role":"function","name":"legacy_lookup","content":null},
			{"role":"assistant","content":[{"type":"refusal","refusal":"cannot comply"}]}
		],
		"tools":[
			{"type":"function","function":{"name":"lookup_weather","description":"Lookup weather","parameters":{"type":"object"},"strict":true}},
			{"type":"custom","custom":{"name":"code_exec","description":"Execute code","format":{"type":"grammar","grammar":{"definition":"start: /[a-z]+/","syntax":"lark"}}}}
		]
	}`
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
}

func TestInspectAcceptsCustomToolCalls(t *testing.T) {
	t.Parallel()

	body := `{
		"model":"client",
		"messages":[
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_custom_01","type":"custom","custom":{"name":"code_exec","input":"print(2 + 2)"}}]},
			{"role":"tool","tool_call_id":"call_custom_01","content":"4"}
		],
		"tools":[{"type":"custom","custom":{"name":"code_exec","format":{"type":"text"}}}]
	}`
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
}

func TestMatchRequiresCanonicalQuerylessEndpoint(t *testing.T) {
	t.Parallel()

	adapter := Adapter{}
	for _, target := range []string{
		"https://gateway.example/v1/chat/completions?tenant=client",
		"https://gateway.example/v1%2fchat/completions",
		"https://gateway.example/v1/chat/completions?",
	} {
		request, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if adapter.Match(request) {
			t.Fatalf("non-canonical endpoint matched: %s", target)
		}
	}
}

func TestInspectRejectsUnsafeRequestShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		mutate func(*http.Request)
	}{
		{name: "missing model", body: `{"messages":[{"role":"user","content":"hi"}]}`},
		{name: "missing role", body: `{"model":"client","messages":[{"content":"hi"}]}`},
		{name: "unsupported role", body: `{"model":"client","messages":[{"role":"owner","content":"hi"}]}`},
		{name: "tool without id", body: `{"model":"client","messages":[{"role":"tool","content":"hi"}]}`},
		{name: "ambiguous choices", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"n":2}`},
		{name: "invalid tool", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"browser"}]}`},
		{name: "invalid custom tool format", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","custom":{"name":"code_exec","format":{"type":"grammar","grammar":{"definition":"start: value"}}}}]}`},
		{name: "custom tool call missing input", body: `{"model":"client","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"custom","custom":{"name":"code_exec"}}]}]}`},
		{name: "scalar tool calls", body: `{"model":"client","messages":[{"role":"assistant","tool_calls":false}]}`},
		{name: "empty tool calls", body: `{"model":"client","messages":[{"role":"assistant","content":null,"tool_calls":[]}]}`},
		{name: "tool calls on user", body: `{"model":"client","messages":[{"role":"user","content":"hi","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]}]}`},
		{name: "tool call missing arguments", body: `{"model":"client","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup"}}]}]}`},
		{name: "content part missing payload", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"image_url"}]}]}`},
		{name: "wrong role content part", body: `{"model":"client","messages":[{"role":"system","content":[{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]}]}`},
		{name: "function missing content", body: `{"model":"client","messages":[{"role":"function","name":"lookup"}]}`},
		{name: "duplicate function tools", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}},{"type":"function","function":{"name":"lookup"}}]}`},
		{name: "non-object parameters", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":[]}}]}`},
		{
			name: "encoded body", body: `{"model":"client","messages":[{"role":"user","content":"hi"}]}`,
			mutate: func(request *http.Request) { request.Header.Set("Content-Encoding", "gzip") },
		},
		{
			name: "duplicate content type", body: `{"model":"client","messages":[{"role":"user","content":"hi"}]}`,
			mutate: func(request *http.Request) { request.Header.Add("Content-Type", "application/json") },
		},
		{
			name: "duplicate content type case variants", body: `{"model":"client","messages":[{"role":"user","content":"hi"}]}`,
			mutate: func(request *http.Request) { request.Header["content-type"] = []string{"application/json"} },
		},
		{
			name: "content encoding case variant", body: `{"model":"client","messages":[{"role":"user","content":"hi"}]}`,
			mutate: func(request *http.Request) { request.Header["content-encoding"] = []string{"gzip"} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			if test.mutate != nil {
				test.mutate(request)
			}
			if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestObserveResponseRequiresRequestModeMatchedContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		streaming   bool
		header      http.Header
		wantSSE     bool
		wantErrCode string
	}{
		{name: "JSON", header: http.Header{"Content-Type": {"application/json; charset=utf-8"}}},
		{name: "SSE", streaming: true, header: http.Header{"Content-Type": {"text/event-stream; charset=utf-8"}}, wantSSE: true},
		{name: "missing content type", header: make(http.Header), wantErrCode: "upstream_protocol_error"},
		{name: "unsupported content type", header: http.Header{"Content-Type": {"text/html"}}, wantErrCode: "upstream_protocol_error"},
		{name: "malformed content type", header: http.Header{"Content-Type": {"application/json; charset"}}, wantErrCode: "upstream_protocol_error"},
		{name: "duplicate case variants", header: http.Header{"Content-Type": {"application/json"}, "content-type": {"application/json"}}, wantErrCode: "upstream_protocol_error"},
		{name: "JSON for streaming request", streaming: true, header: http.Header{"Content-Type": {"application/json"}}, wantErrCode: "upstream_protocol_error"},
		{name: "SSE for non-streaming request", header: http.Header{"Content-Type": {"text/event-stream"}}, wantErrCode: "upstream_protocol_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := rewrittenRequestForResponseMode(t, test.streaming)
			response := &http.Response{StatusCode: http.StatusOK, Header: test.header, Request: request}
			observer, err := (Adapter{}).ObserveResponse(context.Background(), response)
			if test.wantErrCode != "" {
				if !protocol.IsCode(err, test.wantErrCode) || observer != nil {
					t.Fatalf("ObserveResponse(): observer=%T error=%v, want %s", observer, err, test.wantErrCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("ObserveResponse() error = %v", err)
			}
			_, isSSE := observer.(*sseObserver)
			if isSSE != test.wantSSE {
				t.Fatalf("observer type = %T, want SSE=%t", observer, test.wantSSE)
			}
		})
	}
}

func TestObserveResponseDefersStreamingProviderErrorToTransportStatus(t *testing.T) {
	t.Parallel()

	request := rewrittenRequestForResponseMode(t, true)
	response := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Request:    request,
	}
	observer, err := (Adapter{}).ObserveResponse(context.Background(), response)
	if err != nil || observer == nil {
		t.Fatalf("ObserveResponse(): observer=%T error=%v", observer, err)
	}
}

func rewrittenRequestForResponseMode(t *testing.T, streaming bool) *http.Request {
	t.Helper()
	stream := "false"
	if streaming {
		stream = "true"
	}
	body := `{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":` + stream + `}`
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "physical", DefaultOutputTokens: 32, MaximumOutputTokens: 64,
	}); err != nil {
		t.Fatalf("ApplyFeature() error = %v", err)
	}
	return request
}

func TestInspectHonorsBodyLimitAndContext(t *testing.T) {
	t.Parallel()

	body := `{"model":"client","messages":[{"role":"user","content":"hello"}]}`
	request, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if _, err := (Adapter{MaximumBodyBytes: 8}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("oversize error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	request, _ = http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if _, err := (Adapter{}).InspectRequest(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestApplyFeatureUsesLegacyLimitWhenRequested(t *testing.T) {
	t.Parallel()

	request, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(
		`{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":200}`,
	))
	request.Header.Set("Content-Type", "application/json")
	applied, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "physical", DefaultOutputTokens: 50, MaximumOutputTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied != 100 {
		t.Fatalf("applied output maximum = %d, want 100", applied)
	}
	rewritten, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonsafe.Decode(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	object := value.(map[string]any)
	if object["max_tokens"].(interface{ String() string }).String() != "100" {
		t.Fatalf("legacy maximum not clamped: %s", rewritten)
	}
	if _, exists := object["max_completion_tokens"]; exists {
		t.Fatalf("legacy maximum unexpectedly changed fields: %s", rewritten)
	}
}

func TestApplyFeatureReturnsExactWrittenOutputMaximum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		field     string
		requested string
		want      int64
	}{
		{name: "missing uses default", field: "max_completion_tokens", want: 50},
		{name: "modern request below cap", field: "max_completion_tokens", requested: `,"max_completion_tokens":40`, want: 40},
		{name: "modern request above cap", field: "max_completion_tokens", requested: `,"max_completion_tokens":200`, want: 100},
		{name: "legacy request below cap", field: "max_tokens", requested: `,"max_tokens":30`, want: 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"client","messages":[{"role":"user","content":"hello"}]` + test.requested + `}`
			request, err := http.NewRequest(
				http.MethodPost,
				"https://gateway.example/v1/chat/completions",
				strings.NewReader(body),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			applied, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
				PhysicalModel: "physical", DefaultOutputTokens: 50, MaximumOutputTokens: 100,
			})
			if err != nil {
				t.Fatalf("ApplyFeature() error = %v", err)
			}
			if applied != test.want {
				t.Fatalf("applied output maximum = %d, want %d", applied, test.want)
			}
			rewritten, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonsafe.Decode(rewritten)
			if err != nil {
				t.Fatal(err)
			}
			object := value.(map[string]any)
			written, ok := object[test.field].(interface{ String() string })
			if !ok || written.String() != fmt.Sprint(test.want) {
				t.Fatalf("rewritten request = %s, want %s=%d", rewritten, test.field, test.want)
			}
		})
	}
}

func TestApplyFeatureClassifiesServerRewriteExpansionAsInternal(t *testing.T) {
	t.Parallel()

	body := `{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":true}`
	adapter := Adapter{MaximumBodyBytes: int64(len(body))}
	request, _ := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
		t.Fatalf("boundary request did not inspect: %v", err)
	}
	_, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "physical-model-that-expands-the-request", DefaultOutputTokens: 50, MaximumOutputTokens: 100,
	})
	if err == nil || protocol.IsCode(err, "request_invalid") {
		t.Fatalf("rewrite expansion error = %v, want non-client failure", err)
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

	t.Run("partial usage is conservative", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"choices":[],"usage":{"prompt_tokens":10,"total_tokens":14}}`))
		usage, err := observer.Finalize()
		if err != nil || usage.Known || usage.Provenance != "unknown" {
			t.Fatalf("usage=%+v err=%v", usage, err)
		}
	})

	t.Run("inconsistent usage fails", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":20}}`))
		if _, err := observer.Finalize(); !protocol.IsCode(err, "upstream_protocol_error") {
			t.Fatalf("error=%v, want upstream_protocol_error", err)
		}
	})

	t.Run("ambiguous usage aliases fail", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"usage":{"prompt_tokens":1,"input_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		if _, err := observer.Finalize(); !protocol.IsCode(err, "upstream_protocol_error") {
			t.Fatalf("error=%v, want upstream_protocol_error", err)
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

	t.Run("many bounded SSE events in one chunk", func(t *testing.T) {
		observer := &sseObserver{}
		chunk := []byte(strings.Repeat("data: {}\n\n", maximumSSEEvent/10+1))
		if len(chunk) <= maximumSSEEvent {
			t.Fatal("test chunk does not exceed the per-event limit")
		}
		if err := observer.Observe(chunk); err != nil {
			t.Fatalf("bounded events rejected because their aggregate chunk was large: %v", err)
		}
		if err := observer.Observe([]byte("data: [DONE]\n\n")); err != nil {
			t.Fatal(err)
		}
		usage, err := observer.Finalize()
		if err != nil || usage.Known {
			t.Fatalf("usage=%+v err=%v", usage, err)
		}
	})

	t.Run("oversized SSE event fails", func(t *testing.T) {
		observer := &sseObserver{}
		event := []byte("data: \"" + strings.Repeat("x", maximumSSEEvent) + "\"\n\n")
		if err := observer.Observe(event); !protocol.IsCode(err, "upstream_protocol_error") {
			t.Fatalf("error=%v, want upstream_protocol_error", err)
		}
	})
}

func TestSSEObserverLifecycleAcrossChunkPartitions(t *testing.T) {
	t.Parallel()

	usageJSON := `{"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`
	tests := []struct {
		name        string
		stream      string
		wantUsage   protocol.Usage
		wantErrCode string
	}{
		{
			name: "LF", stream: "data: {}\n\ndata: " + usageJSON + "\n\ndata: [DONE]\n\n",
			wantUsage: protocol.Usage{InputTokens: 5, OutputTokens: 2, TotalTokens: 7, Known: true, Provenance: "provider_reported"},
		},
		{
			name: "CRLF", stream: "data: {}\r\n\r\ndata: " + usageJSON + "\r\n\r\ndata: [DONE]\r\n\r\n",
			wantUsage: protocol.Usage{InputTokens: 5, OutputTokens: 2, TotalTokens: 7, Known: true, Provenance: "provider_reported"},
		},
		{
			name: "bare CR", stream: "data: {}\r\rdata: " + usageJSON + "\r\rdata: [DONE]\r\r",
			wantUsage: protocol.Usage{InputTokens: 5, OutputTokens: 2, TotalTokens: 7, Known: true, Provenance: "provider_reported"},
		},
		{
			name: "mixed endings and BOM", stream: "\ufeffdata: {}\r\n\ndata: " + usageJSON + "\n\r\ndata: [DONE]\r\r\n",
			wantUsage: protocol.Usage{InputTokens: 5, OutputTokens: 2, TotalTokens: 7, Known: true, Provenance: "provider_reported"},
		},
		{name: "DONE without usage", stream: "data: {}\n\ndata: [DONE]\n\n", wantUsage: protocol.Usage{Known: false, Provenance: "unknown"}},
		{name: "missing DONE", stream: "data: {}\n\n", wantErrCode: "upstream_protocol_error"},
		{name: "incomplete usage event", stream: "data: " + usageJSON, wantErrCode: "upstream_protocol_error"},
		{name: "incomplete DONE event", stream: "data: [DONE]\n", wantErrCode: "upstream_protocol_error"},
		{name: "post DONE data", stream: "data: [DONE]\n\ndata: {}\n\n", wantErrCode: "upstream_protocol_error"},
		{name: "post DONE comment", stream: "data: [DONE]\n\n: keepalive\n\n", wantErrCode: "upstream_protocol_error"},
		{name: "post DONE unknown field", stream: "data: [DONE]\n\nretry: 1000\n\n", wantErrCode: "upstream_protocol_error"},
		{name: "post DONE blank line", stream: "data: [DONE]\n\n\n", wantErrCode: "upstream_protocol_error"},
		{name: "repeated usage", stream: "data: " + usageJSON + "\n\ndata: " + usageJSON + "\n\ndata: [DONE]\n\n", wantErrCode: "upstream_protocol_error"},
		{name: "data after usage", stream: "data: " + usageJSON + "\n\ndata: {}\n\ndata: [DONE]\n\n", wantErrCode: "upstream_protocol_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := []byte(test.stream)
			for chunkSize := 1; chunkSize <= len(input)+1; chunkSize++ {
				usage, err := observeSSEInChunks(input, chunkSize)
				if test.wantErrCode != "" {
					if !protocol.IsCode(err, test.wantErrCode) {
						t.Fatalf("chunk size %d: usage=%+v error=%v, want %s", chunkSize, usage, err, test.wantErrCode)
					}
					continue
				}
				if err != nil || usage != test.wantUsage {
					t.Fatalf("chunk size %d: usage=%+v error=%v, want %+v", chunkSize, usage, err, test.wantUsage)
				}
			}
		})
	}
}

func observeSSEInChunks(input []byte, chunkSize int) (protocol.Usage, error) {
	observer := &sseObserver{}
	for offset := 0; offset < len(input); offset += chunkSize {
		end := offset + chunkSize
		if end > len(input) {
			end = len(input)
		}
		if err := observer.Observe(input[offset:end]); err != nil {
			return protocol.Usage{}, err
		}
	}
	return observer.Finalize()
}
