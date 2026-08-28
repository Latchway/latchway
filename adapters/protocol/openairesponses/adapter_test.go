package openairesponses

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

func TestMatchRequiresCanonicalResponsesEndpoint(t *testing.T) {
	valid := newRequest(t, `{"model":"client","input":"hello"}`)
	if !(Adapter{}).Match(valid) {
		t.Fatal("canonical Responses endpoint did not match")
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "method", mutate: func(request *http.Request) { request.Method = http.MethodGet }},
		{name: "path", mutate: func(request *http.Request) { request.URL.Path = "/responses" }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "forced query", mutate: func(request *http.Request) { request.URL.ForceQuery = true }},
		{name: "encoded raw path", mutate: func(request *http.Request) { request.URL.RawPath = "/v1/%72esponses" }},
		{name: "opaque URL", mutate: func(request *http.Request) { request.URL.Opaque = "//gateway.example/v1/responses" }},
		{name: "fragment", mutate: func(request *http.Request) { request.URL.Fragment = "ignored" }},
		{name: "raw fragment", mutate: func(request *http.Request) { request.URL.RawFragment = "ignored" }},
		{name: "nil URL", mutate: func(request *http.Request) { request.URL = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, `{"model":"client","input":"hello"}`)
			test.mutate(request)
			if (Adapter{}).Match(request) {
				t.Fatal("non-canonical endpoint matched")
			}
		})
	}
	if (Adapter{}).Match(nil) {
		t.Fatal("nil request matched")
	}
}

func TestCapabilitiesAreTruthful(t *testing.T) {
	if (Adapter{}).ID() != protocol.OpenAIResponsesID {
		t.Fatalf("ID = %q", (Adapter{}).ID())
	}
	want := protocol.Capabilities{
		Streaming: true, ModelRewrite: true, OutputTokenClamp: true, ProviderUsage: true,
	}
	if got := (Adapter{}).Capabilities(); got != want {
		t.Fatalf("Capabilities() = %+v, want %+v", got, want)
	}
}

func TestInspectAndApplyFeaturePreserveRelayData(t *testing.T) {
	body := []byte(`{
		"model":"client-model",
		"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],
		"stream":true,
		"stream_options":{"include_obfuscation":false},
		"max_output_tokens":500,
		"tools":[{"type":"function","name":"lookup","description":"relay only","parameters":{"type":"object"}}]
	}`)
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/responses", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header["content-length"] = []string{"untrusted"}
	request.TransferEncoding = []string{"chunked"}

	adapter := Adapter{}
	metadata, err := adapter.InspectRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if metadata.ClientModel != "client-model" || !metadata.Streaming ||
		metadata.RequestedOutputLimit != 500 || metadata.RequestBytes != int64(len(body)) ||
		metadata.EstimatedInputTokens != (int64(len(body))+2)/3 {
		t.Fatalf("metadata = %+v", metadata)
	}

	effective, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "server/model", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
	})
	if err != nil {
		t.Fatalf("ApplyFeature() error = %v", err)
	}
	if effective != 128 {
		t.Fatalf("effective output = %d, want 128", effective)
	}
	rewritten := readBody(t, request.Body)
	value, err := jsonsafe.Decode(rewritten)
	if err != nil {
		t.Fatalf("rewritten body is not strict JSON: %v", err)
	}
	object := value.(map[string]any)
	if object["model"] != "server/model" || mustJSONInt64(t, object["max_output_tokens"]) != 128 || object["store"] != false {
		t.Fatalf("rewritten server fields = %#v", object)
	}
	options := object["stream_options"].(map[string]any)
	if len(options) != 1 || options["include_obfuscation"] != false {
		t.Fatalf("stream_options changed or usage flag injected: %#v", options)
	}
	tools, ok := object["tools"].([]any)
	if !ok || len(tools) != 1 || tools[0].(map[string]any)["name"] != "lookup" {
		t.Fatalf("tools were not relayed as data: %#v", object["tools"])
	}
	input := object["input"].([]any)
	if len(input) != 1 || input[0].(map[string]any)["role"] != "user" {
		t.Fatalf("input was not preserved: %#v", input)
	}
	if request.ContentLength != int64(len(rewritten)) || request.Header.Get("Content-Type") != "application/json" ||
		len(caseInsensitiveHeaderValues(request.Header, "Content-Length")) != 0 || len(request.TransferEncoding) != 0 {
		t.Fatalf("rewritten transport metadata is invalid: length=%d headers=%v transfer=%v", request.ContentLength, request.Header, request.TransferEncoding)
	}

	// Mutating the caller-owned original bytes cannot mutate the installed body.
	for index := range body {
		body[index] = 'x'
	}
	first := readBodyFactory(t, request)
	second := readBodyFactory(t, request)
	if !bytes.Equal(first, rewritten) || !bytes.Equal(second, rewritten) {
		t.Fatal("GetBody did not return stable owned rewritten bytes")
	}
}

func TestApplyFeatureDefaultsPreservesAndClampsOutputLimit(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int64
	}{
		{name: "default", body: `{"model":"client","input":"hello"}`, want: 64},
		{name: "preserve lower", body: `{"model":"client","input":"hello","max_output_tokens":12}`, want: 12},
		{name: "clamp", body: `{"model":"client","input":"hello","max_output_tokens":1000}`, want: 128},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, test.body)
			got, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
				PhysicalModel: "server", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("effective = %d, want %d", got, test.want)
			}
			value, err := jsonsafe.Decode(readBody(t, request.Body))
			if err != nil {
				t.Fatal(err)
			}
			if actual := mustJSONInt64(t, value.(map[string]any)["max_output_tokens"]); actual != test.want {
				t.Fatalf("rewritten max_output_tokens = %d, want %d", actual, test.want)
			}
			if store := value.(map[string]any)["store"]; store != false {
				t.Fatalf("rewritten store = %#v, want false", store)
			}
		})
	}
}

func TestInspectAcceptsOfficialInputFormsAndBackgroundFalse(t *testing.T) {
	for _, body := range []string{
		`{"model":"client","input":"hello","background":false,"store":false,"instructions":"local instructions"}`,
		`{"model":"client","input":[{"role":"user","content":"hello"}]}`,
		`{"model":"client","input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"prior local text"}]},{"role":"user","content":[{"type":"input_text","text":"continue"}]}],"stream":true,"stream_options":{}}`,
		`{"model":"client","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"result"}],"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"},"strict":true}],"tool_choice":"required","parallel_tool_calls":false}`,
		`{"model":"client","input":[{"type":"custom_tool_call","call_id":"call_2","name":"render","input":"circle"},{"type":"custom_tool_call_output","call_id":"call_2","output":"done"}],"tools":[{"type":"custom","name":"render","format":{"type":"grammar","syntax":"regex","definition":"[a-z]+"}}],"tool_choice":"auto"}`,
	} {
		if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); err != nil {
			t.Fatalf("valid request rejected: %s: %v", body, err)
		}
	}
}

func TestInspectRejectsUnsafeRequestShapes(t *testing.T) {
	tooManyItems := make([]string, maximumInputItems+1)
	for index := range tooManyItems {
		tooManyItems[index] = `{"role":"user","content":"x"}`
	}
	tests := []struct {
		name string
		body string
	}{
		{name: "missing model", body: `{"input":"hello"}`},
		{name: "empty model", body: `{"model":"","input":"hello"}`},
		{name: "trimmed model", body: `{"model":" client","input":"hello"}`},
		{name: "control model", body: `{"model":"client\nmodel","input":"hello"}`},
		{name: "missing input", body: `{"model":"client"}`},
		{name: "null input", body: `{"model":"client","input":null}`},
		{name: "empty text input", body: `{"model":"client","input":""}`},
		{name: "NUL text input", body: `{"model":"client","input":"bad\u0000input"}`},
		{name: "empty item input", body: `{"model":"client","input":[]}`},
		{name: "scalar item", body: `{"model":"client","input":["hello"]}`},
		{name: "empty item object", body: `{"model":"client","input":[{}]}`},
		{name: "nested NUL", body: `{"model":"client","input":[{"role":"user","content":"bad\u0000input"}]}`},
		{name: "too many input items", body: `{"model":"client","input":[` + strings.Join(tooManyItems, ",") + `]}`},
		{name: "background true", body: `{"model":"client","input":"hello","background":true}`},
		{name: "background null", body: `{"model":"client","input":"hello","background":null}`},
		{name: "stream null", body: `{"model":"client","input":"hello","stream":null}`},
		{name: "stream string", body: `{"model":"client","input":"hello","stream":"true"}`},
		{name: "stream options without stream", body: `{"model":"client","input":"hello","stream_options":{}}`},
		{name: "chat usage option", body: `{"model":"client","input":"hello","stream":true,"stream_options":{"include_usage":true}}`},
		{name: "bad obfuscation option", body: `{"model":"client","input":"hello","stream":true,"stream_options":{"include_obfuscation":1}}`},
		{name: "nonobject stream options", body: `{"model":"client","input":"hello","stream":true,"stream_options":[]}`},
		{name: "zero output", body: `{"model":"client","input":"hello","max_output_tokens":0}`},
		{name: "negative output", body: `{"model":"client","input":"hello","max_output_tokens":-1}`},
		{name: "fractional output", body: `{"model":"client","input":"hello","max_output_tokens":1.0}`},
		{name: "exponent output", body: `{"model":"client","input":"hello","max_output_tokens":1e1}`},
		{name: "null output", body: `{"model":"client","input":"hello","max_output_tokens":null}`},
		{name: "overflow output", body: `{"model":"client","input":"hello","max_output_tokens":9223372036854775808}`},
		{name: "duplicate member", body: `{"model":"client","model":"other","input":"hello"}`},
		{name: "trailing value", body: `{"model":"client","input":"hello"}{}`},
		{name: "nonobject root", body: `[]`},
		{name: "invalid JSON", body: `{`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, test.body)
			if _, err := (Adapter{MaximumBodyBytes: 256 << 10}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectRejectsProviderStateAndIdentityFields(t *testing.T) {
	tests := []struct {
		name     string
		fragment string
	}{
		{name: "store true", fragment: `"store":true`},
		{name: "store null", fragment: `"store":null`},
		{name: "store nonboolean", fragment: `"store":0`},
		{name: "previous response", fragment: `"previous_response_id":"resp_other_tenant"`},
		{name: "conversation string", fragment: `"conversation":"conv_other_tenant"`},
		{name: "conversation object", fragment: `"conversation":{"id":"conv_other_tenant"}`},
		{name: "reusable prompt", fragment: `"prompt":{"id":"pmpt_other_tenant"}`},
		{name: "context management", fragment: `"context_management":[{"type":"compaction"}]`},
		{name: "hosted include", fragment: `"include":["file_search_call.results"]`},
		{name: "cache key", fragment: `"prompt_cache_key":"shared-user"`},
		{name: "cache options", fragment: `"prompt_cache_options":{"mode":"explicit"}`},
		{name: "cache retention", fragment: `"prompt_cache_retention":"24h"`},
		{name: "deprecated user identity", fragment: `"user":"trusted-user"`},
		{name: "safety identity", fragment: `"safety_identifier":"trusted-user"`},
		{name: "hosted tool call bound", fragment: `"max_tool_calls":1`},
		{name: "audio modality", fragment: `"modalities":["audio"]`},
		{name: "audio output", fragment: `"audio":{"voice":"alloy"}`},
		{name: "nontext instructions", fragment: `"instructions":[{"type":"input_file","file_id":"file_other"}]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"client","input":"hello",` + test.fragment + `}`
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectUsesExactRootAllowlistAndValidatedGenerationControls(t *testing.T) {
	valid := `{
		"model":"client",
		"input":"hello",
		"temperature":0.7,
		"top_p":1,
		"top_logprobs":20,
		"truncation":"disabled",
		"text":{"verbosity":"low","format":{"type":"json_schema","name":"answer","description":"local schema","schema":{"type":"object","properties":{"ok":{"type":"boolean"}}},"strict":true}}
	}`
	if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, valid)); err != nil {
		t.Fatalf("validated generation controls rejected: %v", err)
	}

	tests := []struct {
		name     string
		fragment string
	}{
		{name: "metadata", fragment: `"metadata":{"tenant":"other"}`},
		{name: "service tier", fragment: `"service_tier":"priority"`},
		{name: "reasoning extension", fragment: `"reasoning":{"context":"auto"}`},
		{name: "moderation extension", fragment: `"moderation":{"model":"omni-moderation-latest"}`},
		{name: "future extension", fragment: `"future_provider_state":{"id":"remote"}`},
		{name: "temperature string", fragment: `"temperature":"0.5"`},
		{name: "temperature range", fragment: `"temperature":2.1`},
		{name: "top p range", fragment: `"top_p":-0.1`},
		{name: "top logprobs fraction", fragment: `"top_logprobs":1.0`},
		{name: "top logprobs range", fragment: `"top_logprobs":21`},
		{name: "truncation extension", fragment: `"truncation":"provider_default"`},
		{name: "text nonobject", fragment: `"text":"json"`},
		{name: "text extension", fragment: `"text":{"format":{"type":"text"},"future":true}`},
		{name: "remote text format", fragment: `"text":{"format":{"type":"remote_schema","id":"schema_other"}}`},
		{name: "schema missing body", fragment: `"text":{"format":{"type":"json_schema","name":"answer"}}`},
		{name: "schema extra member", fragment: `"text":{"format":{"type":"json_schema","name":"answer","schema":{},"id":"schema_other"}}`},
		{name: "schema strict nonboolean", fragment: `"text":{"format":{"type":"json_schema","name":"answer","schema":{},"strict":"true"}}`},
		{name: "schema remote reference", fragment: `"text":{"format":{"type":"json_schema","name":"answer","schema":{"$ref":"https://other.example/schema"}}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"client","input":"hello",` + test.fragment + `}`
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectRejectsRemoteToolsAndUnsafeLocalToolShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "web search", body: `{"model":"client","input":"hello","tools":[{"type":"web_search"}]}`},
		{name: "preview web search", body: `{"model":"client","input":"hello","tools":[{"type":"web_search_preview"}]}`},
		{name: "file search", body: `{"model":"client","input":"hello","tools":[{"type":"file_search","vector_store_ids":["vs_other"]}]}`},
		{name: "computer use", body: `{"model":"client","input":"hello","tools":[{"type":"computer_use_preview"}]}`},
		{name: "code interpreter", body: `{"model":"client","input":"hello","tools":[{"type":"code_interpreter","container":{"type":"auto"}}]}`},
		{name: "hosted shell", body: `{"model":"client","input":"hello","tools":[{"type":"shell"}]}`},
		{name: "MCP", body: `{"model":"client","input":"hello","tools":[{"type":"mcp","server_url":"https://other.example"}]}`},
		{name: "image generation", body: `{"model":"client","input":"hello","tools":[{"type":"image_generation"}]}`},
		{name: "tool not array", body: `{"model":"client","input":"hello","tools":{}}`},
		{name: "tool null", body: `{"model":"client","input":"hello","tools":null}`},
		{name: "function extra execution member", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup","parameters":{},"allowed_callers":["direct"]}]}`},
		{name: "function nested Chat shape", body: `{"model":"client","input":"hello","tools":[{"type":"function","function":{"name":"lookup"}}]}`},
		{name: "function bad name", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"bad name"}]}`},
		{name: "function bad parameters", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup","parameters":[]}]}`},
		{name: "function remote schema reference", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup","parameters":{"$ref":"https://other.example/schema"}}]}`},
		{name: "function bad strict", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup","strict":"true"}]}`},
		{name: "duplicate names", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup"},{"type":"custom","name":"lookup"}]}`},
		{name: "custom extra member", body: `{"model":"client","input":"hello","tools":[{"type":"custom","name":"render","defer_loading":true}]}`},
		{name: "custom remote format", body: `{"model":"client","input":"hello","tools":[{"type":"custom","name":"render","format":{"type":"external","url":"https://other.example"}}]}`},
		{name: "object tool choice", body: `{"model":"client","input":"hello","tools":[{"type":"function","name":"lookup"}],"tool_choice":{"type":"function","name":"lookup"}}`},
		{name: "required without tools", body: `{"model":"client","input":"hello","tool_choice":"required"}`},
		{name: "invalid tool choice", body: `{"model":"client","input":"hello","tool_choice":"web_search"}`},
		{name: "parallel null", body: `{"model":"client","input":"hello","parallel_tool_calls":null}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, test.body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectRejectsRemoteAndUnboundInputItems(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "item reference", body: `{"model":"client","input":[{"type":"item_reference","id":"item_other"}]}`},
		{name: "input file", body: `{"model":"client","input":[{"role":"user","content":[{"type":"input_file","file_id":"file_other"}]}]}`},
		{name: "input image URL", body: `{"model":"client","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://other.example/image"}]}]}`},
		{name: "reasoning state", body: `{"model":"client","input":[{"type":"reasoning","encrypted_content":"provider-state"}]}`},
		{name: "computer output", body: `{"model":"client","input":[{"type":"computer_call_output","call_id":"call_1","output":{"type":"computer_screenshot","image_url":"data:image/png;base64,x"}}]}`},
		{name: "MCP output", body: `{"model":"client","input":[{"type":"mcp_call_output","call_id":"call_1","output":"x"}]}`},
		{name: "message remote extra", body: `{"model":"client","input":[{"type":"message","role":"user","content":"hello","id":"msg_other"}]}`},
		{name: "message object content", body: `{"model":"client","input":[{"role":"user","content":{"type":"input_text","text":"hello"}}]}`},
		{name: "assistant input image", body: `{"model":"client","input":[{"role":"assistant","content":[{"type":"input_image","file_id":"file_other"}]}]}`},
		{name: "undeclared function call", body: `{"model":"client","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"}]}`},
		{name: "unbound function output", body: `{"model":"client","input":[{"type":"function_call_output","call_id":"call_1","output":"result"}],"tools":[{"type":"function","name":"lookup"}]}`},
		{name: "function call remote ID", body: `{"model":"client","input":[{"type":"function_call","id":"fc_other","call_id":"call_1","name":"lookup","arguments":"{}"}],"tools":[{"type":"function","name":"lookup"}]}`},
		{name: "tool kind mismatch", body: `{"model":"client","input":[{"type":"custom_tool_call","call_id":"call_1","name":"lookup","input":"x"}],"tools":[{"type":"function","name":"lookup"}]}`},
		{name: "output kind mismatch", body: `{"model":"client","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"custom_tool_call_output","call_id":"call_1","output":"x"}],"tools":[{"type":"function","name":"lookup"}]}`},
		{name: "duplicate calls", body: `{"model":"client","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"}],"tools":[{"type":"function","name":"lookup"}]}`},
		{name: "duplicate outputs", body: `{"model":"client","input":[{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"a"},{"type":"function_call_output","call_id":"call_1","output":"b"}],"tools":[{"type":"function","name":"lookup"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, test.body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectRejectsUnsafeTransportMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "wrong method", mutate: func(request *http.Request) { request.Method = http.MethodPut }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "raw path", mutate: func(request *http.Request) { request.URL.RawPath = "/v1/%72esponses" }},
		{name: "wrong content type", mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }},
		{name: "missing content type", mutate: func(request *http.Request) { request.Header.Del("Content-Type") }},
		{name: "duplicate content type", mutate: func(request *http.Request) { request.Header["content-type"] = []string{"application/json"} }},
		{name: "encoded", mutate: func(request *http.Request) { request.Header["content-encoding"] = []string{"gzip"} }},
		{name: "nil body", mutate: func(request *http.Request) { request.Body = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, `{"model":"client","input":"hello"}`)
			test.mutate(request)
			if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestRequestReadingHonorsLimitsCloseErrorsAndCancellation(t *testing.T) {
	request := newRequest(t, `{"model":"client","input":"hello"}`)
	if _, err := (Adapter{MaximumBodyBytes: 8}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("oversized request error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Adapter{}).InspectRequest(cancelled, newRequest(t, `{"model":"client","input":"hello"}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel error = %v, want context.Canceled", err)
	}

	duringRead, cancelDuringRead := context.WithCancel(context.Background())
	cancelBody := &cancelingBody{reader: strings.NewReader(`{"model":"client","input":"hello"}`), cancel: cancelDuringRead}
	request = requestWithBody(t, cancelBody)
	if _, err := (Adapter{}).InspectRequest(duringRead, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-read cancellation error = %v, want context.Canceled", err)
	}

	request = requestWithBody(t, &errorBody{readErr: errors.New("sensitive read detail")})
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("read error = %v", err)
	}
	request = requestWithBody(t, &errorBody{reader: strings.NewReader(`{"model":"client","input":"hello"}`), closeErr: errors.New("sensitive close detail")})
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("close error = %v", err)
	}
}

func TestApplyFeatureRejectsInvalidDecisionAndRewriteExpansion(t *testing.T) {
	tests := []protocol.FeatureDecision{
		{},
		{PhysicalModel: " bad", DefaultOutputTokens: 1, MaximumOutputTokens: 1},
		{PhysicalModel: "server", DefaultOutputTokens: 0, MaximumOutputTokens: 1},
		{PhysicalModel: "server", DefaultOutputTokens: 2, MaximumOutputTokens: 1},
	}
	for _, decision := range tests {
		if _, err := (Adapter{}).ApplyFeature(context.Background(), newRequest(t, `{"model":"client","input":"hello"}`), decision); err == nil {
			t.Fatalf("invalid decision accepted: %+v", decision)
		}
	}

	body := `{"model":"c","input":"hello"}`
	request := newRequest(t, body)
	if _, err := (Adapter{MaximumBodyBytes: int64(len(body) + 1)}).ApplyFeature(
		context.Background(), request,
		protocol.FeatureDecision{PhysicalModel: strings.Repeat("m", 100), DefaultOutputTokens: 1, MaximumOutputTokens: 1},
	); err == nil || protocol.IsCode(err, "request_invalid") {
		t.Fatalf("rewrite expansion error = %v, want internal configuration failure", err)
	}
}

func TestApplyFeatureHonorsCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Adapter{}).ApplyFeature(
		cancelled,
		newRequest(t, `{"model":"client","input":"hello"}`),
		protocol.FeatureDecision{PhysicalModel: "server", DefaultOutputTokens: 1, MaximumOutputTokens: 1},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("ApplyFeature() error = %v, want context.Canceled", err)
	}
}

func TestObserveResponseRequiresModeMatchedContentType(t *testing.T) {
	tests := []struct {
		name        string
		stream      bool
		status      int
		contentType string
		mutate      func(*http.Response)
		wantSSE     bool
		wantDiscard bool
		wantCode    string
	}{
		{name: "JSON", status: 200, contentType: "application/json; charset=utf-8"},
		{name: "SSE", stream: true, status: 200, contentType: "text/event-stream; charset=utf-8", wantSSE: true},
		{name: "JSON mode with SSE", status: 200, contentType: "text/event-stream", wantCode: "upstream_protocol_error"},
		{name: "SSE mode with JSON", stream: true, status: 200, contentType: "application/json", wantCode: "upstream_protocol_error"},
		{name: "unsupported", status: 200, contentType: "text/plain", wantCode: "upstream_protocol_error"},
		{name: "missing", status: 200, wantCode: "upstream_protocol_error"},
		{name: "duplicate", status: 200, contentType: "application/json", mutate: func(response *http.Response) {
			response.Header["content-type"] = []string{"application/json"}
		}, wantCode: "upstream_protocol_error"},
		{name: "provider error", stream: true, status: 429, contentType: "malformed", wantDiscard: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := appliedRequest(t, test.stream)
			response := &http.Response{StatusCode: test.status, Header: make(http.Header), Request: request}
			if test.contentType != "" {
				response.Header.Set("Content-Type", test.contentType)
			}
			if test.mutate != nil {
				test.mutate(response)
			}
			observer, err := (Adapter{}).ObserveResponse(context.Background(), response)
			if test.wantCode != "" {
				if !protocol.IsCode(err, test.wantCode) || observer != nil {
					t.Fatalf("ObserveResponse() observer=%T error=%v", observer, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := observer.(*sseObserver); ok != test.wantSSE {
				t.Fatalf("observer = %T, wantSSE=%v", observer, test.wantSSE)
			}
			if _, ok := observer.(discardObserver); ok != test.wantDiscard {
				t.Fatalf("observer = %T, wantDiscard=%v", observer, test.wantDiscard)
			}
			if test.wantDiscard {
				_ = observer.Observe([]byte(`{"error":{"message":"provider secret"}}`))
				usage, finalizeErr := observer.Finalize()
				if finalizeErr != nil || usage.Known {
					t.Fatalf("discard observer usage=%+v error=%v", usage, finalizeErr)
				}
			}
		})
	}
}

func TestObserveResponseHonorsContextAndRequiresAppliedMode(t *testing.T) {
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Request: newRequest(t, `{"model":"client","input":"hello"}`)}
	if _, err := (Adapter{}).ObserveResponse(context.Background(), response); err == nil {
		t.Fatal("response without applied request mode accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	response.Request = appliedRequest(t, false)
	if _, err := (Adapter{}).ObserveResponse(cancelled, response); !errors.Is(err, context.Canceled) {
		t.Fatalf("ObserveResponse() error = %v, want context.Canceled", err)
	}
	if _, err := (Adapter{}).ObserveResponse(nil, response); err == nil {
		t.Fatal("nil response context accepted")
	}
	if _, err := (Adapter{}).ObserveResponse(context.Background(), nil); err == nil {
		t.Fatal("nil response accepted")
	}
}

func TestJSONObserverUsageNormalization(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		want      protocol.Usage
		wantCode  string
		wantKnown bool
	}{
		{name: "known", body: `{"id":"resp_1","usage":{"input_tokens":10,"output_tokens":4,"total_tokens":14}}`, want: protocol.Usage{InputTokens: 10, OutputTokens: 4, TotalTokens: 14, Known: true, Provenance: providerUsageProvenance}, wantKnown: true},
		{name: "zero", body: `{"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}`, want: protocol.Usage{Known: true, Provenance: providerUsageProvenance}, wantKnown: true},
		{name: "missing usage", body: `{"id":"resp_1"}`},
		{name: "null usage", body: `{"usage":null}`},
		{name: "partial usage", body: `{"usage":{"input_tokens":10,"total_tokens":10}}`},
		{name: "usage not object", body: `{"usage":1}`, wantCode: "upstream_protocol_error"},
		{name: "wrong value", body: `{"usage":{"input_tokens":"1","output_tokens":2,"total_tokens":3}}`, wantCode: "upstream_protocol_error"},
		{name: "negative", body: `{"usage":{"input_tokens":-1,"output_tokens":2,"total_tokens":1}}`, wantCode: "upstream_protocol_error"},
		{name: "fraction", body: `{"usage":{"input_tokens":1.0,"output_tokens":2,"total_tokens":3}}`, wantCode: "upstream_protocol_error"},
		{name: "exponent", body: `{"usage":{"input_tokens":1e0,"output_tokens":2,"total_tokens":3}}`, wantCode: "upstream_protocol_error"},
		{name: "overflow", body: `{"usage":{"input_tokens":9223372036854775808,"output_tokens":0,"total_tokens":0}}`, wantCode: "upstream_protocol_error"},
		{name: "sum overflow", body: `{"usage":{"input_tokens":9223372036854775807,"output_tokens":1,"total_tokens":9223372036854775807}}`, wantCode: "upstream_protocol_error"},
		{name: "inconsistent total", body: `{"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":4}}`, wantCode: "upstream_protocol_error"},
		{name: "duplicate usage", body: `{"usage":{"input_tokens":1,"input_tokens":2,"output_tokens":2,"total_tokens":3}}`, wantCode: "upstream_protocol_error"},
		{name: "duplicate root", body: `{"usage":null,"usage":null}`, wantCode: "upstream_protocol_error"},
		{name: "nonobject root", body: `[]`, wantCode: "upstream_protocol_error"},
		{name: "malformed JSON", body: `{`, wantCode: "upstream_protocol_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &jsonObserver{}
			for _, chunk := range splitBytes([]byte(test.body), 3) {
				if err := observer.Observe(chunk); err != nil {
					t.Fatal(err)
				}
			}
			usage, err := observer.Finalize()
			if test.wantCode != "" {
				if !protocol.IsCode(err, test.wantCode) {
					t.Fatalf("Finalize() usage=%+v error=%v", usage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.wantKnown {
				if usage != test.want {
					t.Fatalf("usage=%+v, want %+v", usage, test.want)
				}
			} else if usage.Known || usage.Provenance != "unknown" {
				t.Fatalf("usage=%+v, want unknown", usage)
			}
		})
	}
}

func TestJSONObserverBoundsMemoryAndFallsBackToUnknown(t *testing.T) {
	observer := &jsonObserver{}
	chunk := bytes.Repeat([]byte{'x'}, int(maximumObservedJSON)+1)
	if err := observer.Observe(chunk); err != nil {
		t.Fatal(err)
	}
	if observer.buffer.Len() != 0 || !observer.overflow {
		t.Fatalf("overflow state retained bytes: length=%d overflow=%v", observer.buffer.Len(), observer.overflow)
	}
	usage, err := observer.Finalize()
	if err != nil || usage.Known {
		t.Fatalf("Finalize() usage=%+v error=%v", usage, err)
	}
}

func TestSSEObserverExtractsTerminalCompletedUsage(t *testing.T) {
	stream := "event: response.created\n" +
		"data: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\n" +
		": heartbeat\n\n" +
		"event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":37,\"output_tokens\":11,\"total_tokens\":48}}}\n\n"
	observer := &sseObserver{}
	for _, chunk := range splitBytes([]byte(stream), 7) {
		if err := observer.Observe(chunk); err != nil {
			t.Fatalf("Observe() error = %v", err)
		}
	}
	usage, err := observer.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	want := protocol.Usage{InputTokens: 37, OutputTokens: 11, TotalTokens: 48, Known: true, Provenance: providerUsageProvenance}
	if usage != want {
		t.Fatalf("usage=%+v, want %+v", usage, want)
	}
}

func TestSSEObserverSupportsBOMCRLFAndMultilineData(t *testing.T) {
	stream := "\xef\xbb\xbfevent: response.created\r\ndata: {\"type\":\"response.created\"}\r\n\r\n" +
		"event: response.completed\r\n" +
		"data: {\"type\":\"response.completed\",\r\n" +
		"data: \"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}\r\n\r\n"
	observer := &sseObserver{}
	for _, chunk := range splitBytes([]byte(stream), 1) {
		if err := observer.Observe(chunk); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := observer.Finalize()
	if err != nil || !usage.Known || usage.TotalTokens != 3 {
		t.Fatalf("usage=%+v error=%v", usage, err)
	}
}

func TestSSEObserverCompletedWithoutUsageIsUnknown(t *testing.T) {
	observer := &sseObserver{}
	if err := observer.Observe([]byte("data: {\"type\":\"response.completed\",\"response\":{}}\n\n")); err != nil {
		t.Fatal(err)
	}
	usage, err := observer.Finalize()
	if err != nil || usage.Known || usage.Provenance != "unknown" {
		t.Fatalf("usage=%+v error=%v", usage, err)
	}
}

func TestSSEObserverRejectsMalformedAndNonterminalStreams(t *testing.T) {
	completed := `{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}`
	tests := []struct {
		name        string
		stream      string
		after       string
		wantObserve bool
	}{
		{name: "missing completed", stream: "data: {\"type\":\"response.created\"}\n\n"},
		{name: "failed terminal", stream: "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{}}\n\n"},
		{name: "DONE sentinel", stream: "data: [DONE]\n\n", wantObserve: true},
		{name: "event mismatch", stream: "event: response.created\ndata: " + completed + "\n\n", wantObserve: true},
		{name: "duplicate event field", stream: "event: response.completed\nevent: response.completed\ndata: " + completed + "\n\n", wantObserve: true},
		{name: "duplicate JSON", stream: "data: {\"type\":\"response.completed\",\"type\":\"response.completed\",\"response\":{}}\n\n", wantObserve: true},
		{name: "missing data type", stream: "data: {\"response\":{}}\n\n", wantObserve: true},
		{name: "completed missing response", stream: "data: {\"type\":\"response.completed\"}\n\n", wantObserve: true},
		{name: "malformed usage", stream: "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":4}}}\n\n", wantObserve: true},
		{name: "incomplete event", stream: "data: " + completed + "\n"},
		{name: "bytes after completed", stream: "data: " + completed + "\n\n", after: "data: {\"type\":\"response.created\"}\n\n", wantObserve: true},
		{name: "duplicate completed", stream: "data: " + completed + "\n\ndata: " + completed + "\n\n", wantObserve: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &sseObserver{}
			observeErr := observer.Observe([]byte(test.stream))
			if observeErr == nil && test.after != "" {
				observeErr = observer.Observe([]byte(test.after))
			}
			if test.wantObserve {
				if !protocol.IsCode(observeErr, "upstream_protocol_error") {
					t.Fatalf("Observe() error = %v, want upstream_protocol_error", observeErr)
				}
				return
			}
			if observeErr != nil {
				t.Fatalf("Observe() error = %v; expected Finalize failure", observeErr)
			}
			if _, err := observer.Finalize(); !protocol.IsCode(err, "upstream_protocol_error") {
				t.Fatalf("Finalize() error = %v, want upstream_protocol_error", err)
			}
		})
	}
}

func TestSSEObserverRejectsOversizedEvent(t *testing.T) {
	observer := &sseObserver{}
	oversized := append([]byte("data: "), bytes.Repeat([]byte{'x'}, maximumSSEEvent+8)...)
	if err := observer.Observe(oversized); !protocol.IsCode(err, "upstream_protocol_error") {
		t.Fatalf("Observe() error = %v, want upstream_protocol_error", err)
	}
}

func newRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/responses", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func requestWithBody(t *testing.T, body io.ReadCloser) *http.Request {
	t.Helper()
	request := newRequest(t, `{"model":"client","input":"hello"}`)
	request.Body = body
	request.ContentLength = -1
	return request
}

func appliedRequest(t *testing.T, streaming bool) *http.Request {
	t.Helper()
	body := `{"model":"client","input":"hello"}`
	if streaming {
		body = `{"model":"client","input":"hello","stream":true}`
	}
	request := newRequest(t, body)
	if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "server", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
	}); err != nil {
		t.Fatal(err)
	}
	return request
}

func readBody(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	result, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func readBodyFactory(t *testing.T, request *http.Request) []byte {
	t.Helper()
	if request.GetBody == nil {
		t.Fatal("GetBody is nil")
	}
	body, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	return readBody(t, body)
}

func mustJSONInt64(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(jsonNumber)
	if !ok {
		// json.Number is named; use the small interface to avoid a test-only
		// dependency on its concrete spelling in assertions.
		t.Fatalf("value is not a JSON number: %#v", value)
	}
	parsed, err := number.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

type jsonNumber interface {
	Int64() (int64, error)
}

func splitBytes(input []byte, size int) [][]byte {
	if size <= 0 {
		size = 1
	}
	result := make([][]byte, 0, (len(input)+size-1)/size)
	for offset := 0; offset < len(input); offset += size {
		end := offset + size
		if end > len(input) {
			end = len(input)
		}
		result = append(result, input[offset:end])
	}
	return result
}

type cancelingBody struct {
	reader *strings.Reader
	cancel context.CancelFunc
	done   bool
}

func (body *cancelingBody) Read(destination []byte) (int, error) {
	if !body.done {
		body.done = true
		body.cancel()
	}
	return body.reader.Read(destination)
}

func (*cancelingBody) Close() error { return nil }

type errorBody struct {
	reader   *strings.Reader
	readErr  error
	closeErr error
}

func (body *errorBody) Read(destination []byte) (int, error) {
	if body.readErr != nil {
		return 0, body.readErr
	}
	return body.reader.Read(destination)
}

func (body *errorBody) Close() error { return body.closeErr }
