package anthropicmessages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

func TestMatchRequiresCanonicalMessagesEndpoint(t *testing.T) {
	if !(Adapter{}).Match(newRequest(t, validRequestBody)) {
		t.Fatal("canonical Messages endpoint did not match")
	}
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "method", mutate: func(request *http.Request) { request.Method = http.MethodGet }},
		{name: "path", mutate: func(request *http.Request) { request.URL.Path = "/messages" }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "forced query", mutate: func(request *http.Request) { request.URL.ForceQuery = true }},
		{name: "encoded path", mutate: func(request *http.Request) { request.URL.RawPath = "/v1/%6dessages" }},
		{name: "opaque URL", mutate: func(request *http.Request) { request.URL.Opaque = "//provider.example/v1/messages" }},
		{name: "URL user info", mutate: func(request *http.Request) { request.URL.User = url.User("client") }},
		{name: "fragment", mutate: func(request *http.Request) { request.URL.Fragment = "ignored" }},
		{name: "raw fragment", mutate: func(request *http.Request) { request.URL.RawFragment = "ignored" }},
		{name: "nil URL", mutate: func(request *http.Request) { request.URL = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, validRequestBody)
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
	if (Adapter{}).ID() != protocol.AnthropicMessagesID {
		t.Fatalf("ID = %q", (Adapter{}).ID())
	}
	want := protocol.Capabilities{
		Streaming: true, ModelRewrite: true, OutputTokenClamp: true, ProviderUsage: true,
		TrustedInputPreflight: true,
	}
	if got := (Adapter{}).Capabilities(); got != want {
		t.Fatalf("Capabilities() = %+v, want %+v", got, want)
	}
}

func TestTrustedInputPreflightBindsExactTextMessagesAndOutput(t *testing.T) {
	request := newRequest(t, `{
		"model":"client","system":[{"type":"text","text":"Be concise 🌉"}],
		"messages":[
			{"role":"user","content":"你好"},
			{"role":"assistant","content":[{"type":"text","text":"hello"}]}
		],"stream":true,"max_tokens":17
	}`)
	applied, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "claude-model", DefaultOutputTokens: 64, MaximumOutputTokens: 128,
	})
	if err != nil || applied != 17 {
		t.Fatalf("ApplyFeature() output=%d error=%v", applied, err)
	}
	rewritten := readBodyFactory(t, request)
	profile := protocol.TrustedInputProfile{
		ID: "anthropic_profile", Protocol: ID,
		Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel: "claude-model", MaximumFramingTokensPerRequest: 9,
		MaximumFramingTokensPerMessage: 4, MaximumContextTokens: 1_000_000,
	}
	preflight, err := (Adapter{}).PreflightInput(context.Background(), request, profile)
	if err != nil {
		t.Fatalf("PreflightInput() error = %v", err)
	}
	wantInput := int64(len(rewritten)) + 9 + 2*4
	if preflight.RewrittenBodySHA256 != sha256.Sum256(rewritten) || preflight.MessageCount != 2 ||
		preflight.InputTokenBound != wantInput || preflight.OutputTokenBound != applied ||
		preflight.TotalTokenBound != wantInput+applied || preflight.ProfileDigest != profile.Digest() {
		t.Fatalf("trusted Anthropic proof = %+v", preflight)
	}
	if got := readBody(t, request.Body); !bytes.Equal(got, rewritten) {
		t.Fatal("preflight did not preserve the exact rewritten body")
	}
}

func TestTrustedInputPreflightRejectsMediaAndTools(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "image",
			body: `{"model":"client","messages":[{"role":"user","content":[{"type":"text","text":"look"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGk="}}]}]}`,
		},
		{
			name: "tools",
			body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, test.body)
			if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
				PhysicalModel: "server", DefaultOutputTokens: 8, MaximumOutputTokens: 16,
			}); err != nil {
				t.Fatalf("rich request must remain available without trusted accounting: %v", err)
			}
			profile := protocol.TrustedInputProfile{
				ID: "anthropic_profile", Protocol: ID,
				Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
				PhysicalModel: "server", MaximumContextTokens: 1_000_000,
			}
			if result, err := (Adapter{}).PreflightInput(context.Background(), request, profile); err == nil || result != (protocol.TrustedInputPreflight{}) {
				t.Fatalf("PreflightInput() result=%+v error=%v, want closed failure", result, err)
			}
		})
	}
}

func TestInspectAndApplyFeaturePreserveSupportedRelayData(t *testing.T) {
	body := []byte(`{
		"model":"client-model",
		"messages":[
			{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGk="}}]},
			{"role":"assistant","content":[{"type":"text","text":"checking"},{"type":"tool_use","id":"toolu_1","name":"lookup","input":{"q":"hello"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"found"}],"is_error":false}]}
		],
		"system":[{"type":"text","text":"be concise"}],
		"stop_sequences":["STOP"],
		"temperature":0.5,
		"top_p":0.9,
		"top_k":40,
		"tools":[{"name":"lookup","description":"relay only","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}],
		"tool_choice":{"type":"tool","name":"lookup","disable_parallel_tool_use":true},
		"stream":true,
		"max_tokens":500
	}`)
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header["content-length"] = []string{"untrusted"}
	request.TransferEncoding = []string{"chunked"}

	metadata, err := (Adapter{}).InspectRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if metadata.ClientModel != "client-model" || !metadata.Streaming ||
		metadata.RequestedOutputLimit != 500 || metadata.RequestBytes != int64(len(body)) ||
		metadata.EstimatedInputTokens != (int64(len(body))+2)/3 {
		t.Fatalf("metadata = %+v", metadata)
	}

	// InspectRequest replaced the original caller-owned body with owned bytes.
	for index := range body {
		body[index] = 'x'
	}
	effective, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
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
	if object["model"] != "server/model" || mustJSONInt64(t, object["max_tokens"]) != 128 || object["stream"] != true {
		t.Fatalf("rewritten server fields = %#v", object)
	}
	if len(object["messages"].([]any)) != 3 || len(object["tools"].([]any)) != 1 ||
		object["tool_choice"].(map[string]any)["name"] != "lookup" {
		t.Fatalf("supported relay fields were not preserved: %#v", object)
	}
	if request.ContentLength != int64(len(rewritten)) || request.Header.Get("Content-Type") != "application/json" ||
		len(caseInsensitiveHeaderValues(request.Header, "Content-Length")) != 0 || len(request.TransferEncoding) != 0 {
		t.Fatalf("rewritten transport metadata is invalid: length=%d headers=%v transfer=%v", request.ContentLength, request.Header, request.TransferEncoding)
	}
	versions := caseInsensitiveHeaderValues(request.Header, "Anthropic-Version")
	if len(versions) != 1 || versions[0] != CanonicalAPIVersion {
		t.Fatalf("server-owned Anthropic version = %#v", versions)
	}
	first := readBodyFactory(t, request)
	second := readBodyFactory(t, request)
	if !bytes.Equal(first, rewritten) || !bytes.Equal(second, rewritten) {
		t.Fatal("GetBody did not return stable owned rewritten bytes")
	}
}

func TestApplyFeatureDefaultsPreservesAndClampsMaxTokens(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int64
	}{
		{name: "default", body: `{"model":"client","messages":[{"role":"user","content":"hello"}]}`, want: 64},
		{name: "preserve lower", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":12}`, want: 12},
		{name: "clamp", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":1000}`, want: 128},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, test.body)
			metadata, err := (Adapter{}).InspectRequest(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "default" && metadata.RequestedOutputLimit != 0 {
				t.Fatalf("missing max_tokens metadata = %+v", metadata)
			}
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
			if actual := mustJSONInt64(t, value.(map[string]any)["max_tokens"]); actual != test.want {
				t.Fatalf("rewritten max_tokens = %d, want %d", actual, test.want)
			}
		})
	}
}

func TestAnthropicVersionAndExtensionHeadersAreServerOwned(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "client canonical version", mutate: func(request *http.Request) { request.Header.Set("Anthropic-Version", CanonicalAPIVersion) }},
		{name: "client other version", mutate: func(request *http.Request) { request.Header.Set("anthropic-version", "2099-01-01") }},
		{name: "duplicate version casing", mutate: func(request *http.Request) {
			request.Header["Anthropic-Version"] = []string{CanonicalAPIVersion}
			request.Header["anthropic-version"] = []string{CanonicalAPIVersion}
		}},
		{name: "beta", mutate: func(request *http.Request) { request.Header.Set("Anthropic-Beta", "unsafe-beta") }},
		{name: "profile", mutate: func(request *http.Request) { request.Header.Set("Anthropic-User-Profile-Id", "user_1") }},
		{name: "future extension", mutate: func(request *http.Request) { request.Header.Set("Anthropic-Future", "on") }},
		{name: "provider credential", mutate: func(request *http.Request) { request.Header.Set("X-Api-Key", "client-secret") }},
		{name: "empty version values", mutate: func(request *http.Request) { request.Header["Anthropic-Version"] = nil }},
		{name: "empty credential values", mutate: func(request *http.Request) { request.Header["X-Api-Key"] = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, validRequestBody)
			test.mutate(request)
			if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}

	request := appliedRequest(t, false)
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); err != nil {
		t.Fatalf("adapter did not recognize its own trusted canonical header: %v", err)
	}
	request.Header.Set("Anthropic-Version", "2099-01-01")
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("tampered trusted version error = %v", err)
	}
}

func TestInspectAcceptsSupportedMessageAndClientToolForms(t *testing.T) {
	tests := []string{
		`{"model":"client","messages":[{"role":"user","content":"hello"}]}`,
		`{"model":"client","messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"YQ=="}}]}],"stream":false,"max_tokens":1}`,
		`{"model":"client","messages":[{"role":"user","content":"use it"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"","is_error":true}]}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"tool_choice":{"type":"auto"}}`,
		`{"model":"client","messages":[{"role":"user","content":"use it"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}]}`,
		`{"model":"client","messages":[{"role":"user","content":"hello"}],"system":"system","stop_sequences":["one","two"],"temperature":0,"top_p":0,"top_k":0,"tool_choice":{"type":"none"}}`,
	}
	for _, body := range tests {
		if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); err != nil {
			t.Fatalf("valid request rejected: %s: %v", body, err)
		}
	}
}

func TestInspectRejectsUnsafeRequestShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing model", body: `{"messages":[{"role":"user","content":"hello"}]}`},
		{name: "empty model", body: `{"model":"","messages":[{"role":"user","content":"hello"}]}`},
		{name: "trimmed model", body: `{"model":" client","messages":[{"role":"user","content":"hello"}]}`},
		{name: "control model", body: `{"model":"client\nmodel","messages":[{"role":"user","content":"hello"}]}`},
		{name: "missing messages", body: `{"model":"client"}`},
		{name: "null messages", body: `{"model":"client","messages":null}`},
		{name: "empty messages", body: `{"model":"client","messages":[]}`},
		{name: "scalar message", body: `{"model":"client","messages":["hello"]}`},
		{name: "message extension", body: `{"model":"client","messages":[{"role":"user","content":"hello","name":"unsafe"}]}`},
		{name: "system role", body: `{"model":"client","messages":[{"role":"system","content":"hello"}]}`},
		{name: "missing content", body: `{"model":"client","messages":[{"role":"user"}]}`},
		{name: "empty content", body: `{"model":"client","messages":[{"role":"user","content":""}]}`},
		{name: "NUL content", body: `{"model":"client","messages":[{"role":"user","content":"bad\u0000text"}]}`},
		{name: "empty blocks", body: `{"model":"client","messages":[{"role":"user","content":[]}]}`},
		{name: "block extension", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}]}]}`},
		{name: "unknown block", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"document","source":{}}]}]}`},
		{name: "assistant image", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"YQ=="}}]}]}`},
		{name: "URL image", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.test"}}]}]}`},
		{name: "invalid base64", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"%%%"}}]}]}`},
		{name: "user tool use", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]}]}`},
		{name: "tool use scalar input", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":"{}"}]}]}`},
		{name: "duplicate tool use id", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}},{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]}]}`},
		{name: "assistant tool result", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"x"}]}]}`},
		{name: "unknown tool result", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"x"}]}]}`},
		{name: "recursive tool result", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"tool_use","id":"nested","name":"x","input":{}}]}]}]}`},
		{name: "unresolved final tool use", body: `{"model":"client","messages":[{"role":"user","content":"use it"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]}]}`},
		{name: "non-immediate tool result", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]},{"role":"assistant","content":"later"},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`},
		{name: "text before tool result", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}}]},{"role":"user","content":[{"type":"text","text":"result"},{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`},
		{name: "missing parallel result", body: `{"model":"client","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"x","input":{}},{"type":"tool_use","id":"toolu_2","name":"x","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1"}]}]}`},
		{name: "zero max", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":0}`},
		{name: "negative max", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":-1}`},
		{name: "fractional max", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":1.0}`},
		{name: "null max", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":null}`},
		{name: "overflow max", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":9223372036854775808}`},
		{name: "stream null", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":null}`},
		{name: "stream string", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":"true"}`},
		{name: "empty stop sequences", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"stop_sequences":[]}`},
		{name: "duplicate stop sequence", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"stop_sequences":["x","x"]}`},
		{name: "temperature range", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"temperature":2}`},
		{name: "top p negative", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"top_p":-0.1}`},
		{name: "top k fraction", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"top_k":1.0}`},
		{name: "server tool", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"web_search_20250305","name":"web_search"}]}`},
		{name: "tool schema missing object type", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"x","input_schema":{}}]}`},
		{name: "remote tool schema reference", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"x","input_schema":{"type":"object","properties":{"value":{"$ref":"https://remote.example/schema"}}}}]}`},
		{name: "duplicate tools", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"x","input_schema":{"type":"object"}},{"name":"x","input_schema":{"type":"object"}}]}`},
		{name: "unknown named choice", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"x","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"y"}}`},
		{name: "choice extension", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"x","input_schema":{"type":"object"}}],"tool_choice":{"type":"any","extra":true}}`},
		{name: "provider metadata", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"metadata":{"user_id":"untrusted"}}`},
		{name: "thinking extension", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"thinking":{"type":"enabled","budget_tokens":1024}}`},
		{name: "MCP extension", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"mcp_servers":[]}`},
		{name: "container extension", body: `{"model":"client","messages":[{"role":"user","content":"hello"}],"container":"container_1"}`},
		{name: "duplicate member", body: `{"model":"client","model":"other","messages":[{"role":"user","content":"hello"}]}`},
		{name: "nested duplicate", body: `{"model":"client","messages":[{"role":"user","role":"assistant","content":"hello"}]}`},
		{name: "trailing value", body: validRequestBody + `{}`},
		{name: "nonobject root", body: `[]`},
		{name: "invalid JSON", body: `{`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := (Adapter{MaximumBodyBytes: 256 << 10}).InspectRequest(
				context.Background(), newRequest(t, test.body),
			); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectEnforcesStructuralLimits(t *testing.T) {
	messages := make([]string, maximumMessages+1)
	for index := range messages {
		messages[index] = `{"role":"user","content":"x"}`
	}
	body := `{"model":"client","messages":[` + strings.Join(messages, ",") + `]}`
	if _, err := (Adapter{MaximumBodyBytes: maximumProviderBody}).InspectRequest(
		context.Background(), newRequest(t, body),
	); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("message limit error = %v", err)
	}
	if got := (Adapter{MaximumBodyBytes: math.MaxInt64}).maximumBodyBytes(); got != maximumProviderBody {
		t.Fatalf("provider request cap = %d, want %d", got, maximumProviderBody)
	}
}

func TestInspectRejectsUnsafeTransportMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "wrong method", mutate: func(request *http.Request) { request.Method = http.MethodPut }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "raw path", mutate: func(request *http.Request) { request.URL.RawPath = "/v1/%6dessages" }},
		{name: "wrong content type", mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }},
		{name: "missing content type", mutate: func(request *http.Request) { request.Header.Del("Content-Type") }},
		{name: "duplicate content type", mutate: func(request *http.Request) { request.Header["content-type"] = []string{"application/json"} }},
		{name: "encoded", mutate: func(request *http.Request) { request.Header["content-encoding"] = []string{"gzip"} }},
		{name: "empty encoding values", mutate: func(request *http.Request) { request.Header["Content-Encoding"] = nil }},
		{name: "nil body", mutate: func(request *http.Request) { request.Body = nil }},
		{name: "invalid negative length", mutate: func(request *http.Request) { request.ContentLength = -2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, validRequestBody)
			test.mutate(request)
			if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestRequestReadingHonorsLimitsCloseErrorsAndCancellation(t *testing.T) {
	if _, err := (Adapter{MaximumBodyBytes: 8}).InspectRequest(
		context.Background(), newRequest(t, validRequestBody),
	); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("oversized request error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Adapter{}).InspectRequest(cancelled, newRequest(t, validRequestBody)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel error = %v, want context.Canceled", err)
	}

	duringRead, cancelDuringRead := context.WithCancel(context.Background())
	request := requestWithBody(t, &cancelingBody{reader: strings.NewReader(validRequestBody), cancel: cancelDuringRead})
	if _, err := (Adapter{}).InspectRequest(duringRead, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-read cancellation error = %v, want context.Canceled", err)
	}

	request = requestWithBody(t, &errorBody{readErr: errors.New("sensitive read detail")})
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("read error = %v", err)
	}
	request = requestWithBody(t, &errorBody{reader: strings.NewReader(validRequestBody), closeErr: errors.New("sensitive close detail")})
	if _, err := (Adapter{}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("close error = %v", err)
	}
}

func TestApplyFeatureRejectsInvalidDecisionAndRewriteExpansion(t *testing.T) {
	for _, decision := range []protocol.FeatureDecision{
		{},
		{PhysicalModel: " bad", DefaultOutputTokens: 1, MaximumOutputTokens: 1},
		{PhysicalModel: "server", DefaultOutputTokens: 0, MaximumOutputTokens: 1},
		{PhysicalModel: "server", DefaultOutputTokens: 2, MaximumOutputTokens: 1},
	} {
		if _, err := (Adapter{}).ApplyFeature(context.Background(), newRequest(t, validRequestBody), decision); err == nil {
			t.Fatalf("invalid decision accepted: %+v", decision)
		}
	}

	body := validRequestBody
	if _, err := (Adapter{MaximumBodyBytes: int64(len(body) + 1)}).ApplyFeature(
		context.Background(), newRequest(t, body),
		protocol.FeatureDecision{PhysicalModel: strings.Repeat("m", 100), DefaultOutputTokens: 1, MaximumOutputTokens: 1},
	); err == nil || protocol.IsCode(err, "request_invalid") {
		t.Fatalf("rewrite expansion error = %v, want internal configuration failure", err)
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
				if err := observer.Observe([]byte(`{"type":"error","error":{"message":"provider secret"}}`)); err != nil {
					t.Fatal(err)
				}
				usage, finalizeErr := observer.Finalize()
				if finalizeErr != nil || usage.Known || usage.Provenance != "unknown" {
					t.Fatalf("discard observer usage=%+v error=%v", usage, finalizeErr)
				}
			}
		})
	}
}

func TestObserveResponseHonorsContextAndRequiresAppliedMode(t *testing.T) {
	response := &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}},
		Request: newRequest(t, validRequestBody),
	}
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
		name     string
		body     string
		want     protocol.Usage
		wantCode string
	}{
		{name: "known", body: `{"type":"message","usage":{"input_tokens":10,"output_tokens":4}}`, want: protocol.Usage{InputTokens: 10, OutputTokens: 4, TotalTokens: 14, Known: true, Provenance: providerUsageProvenance}},
		{name: "zero with extensions", body: `{"type":"message","usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":7}}`, want: protocol.Usage{Known: true, Provenance: providerUsageProvenance}},
		{name: "missing usage", body: `{"type":"message"}`, wantCode: "upstream_protocol_error"},
		{name: "null usage", body: `{"type":"message","usage":null}`, wantCode: "upstream_protocol_error"},
		{name: "partial usage", body: `{"type":"message","usage":{"input_tokens":10}}`, wantCode: "upstream_protocol_error"},
		{name: "wrong type", body: `{"type":"error","usage":{"input_tokens":1,"output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "nonobject root", body: `[]`, wantCode: "upstream_protocol_error"},
		{name: "wrong value", body: `{"type":"message","usage":{"input_tokens":"1","output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "negative", body: `{"type":"message","usage":{"input_tokens":-1,"output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "fraction", body: `{"type":"message","usage":{"input_tokens":1.0,"output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "exponent", body: `{"type":"message","usage":{"input_tokens":1e0,"output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "integer overflow", body: `{"type":"message","usage":{"input_tokens":9223372036854775808,"output_tokens":0}}`, wantCode: "upstream_protocol_error"},
		{name: "sum overflow", body: `{"type":"message","usage":{"input_tokens":9223372036854775807,"output_tokens":1}}`, wantCode: "upstream_protocol_error"},
		{name: "duplicate usage", body: `{"type":"message","usage":{"input_tokens":1,"input_tokens":2,"output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "duplicate root", body: `{"type":"message","type":"message","usage":{"input_tokens":1,"output_tokens":2}}`, wantCode: "upstream_protocol_error"},
		{name: "malformed", body: `{`, wantCode: "upstream_protocol_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &jsonObserver{ctx: context.Background()}
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
			if err != nil || usage != test.want {
				t.Fatalf("Finalize() usage=%+v error=%v, want %+v", usage, err, test.want)
			}
		})
	}
}

func TestJSONObserverBoundsMemoryAndHonorsCancellation(t *testing.T) {
	observer := &jsonObserver{ctx: context.Background()}
	chunk := bytes.Repeat([]byte{'x'}, int(maximumObservedJSON)+1)
	if err := observer.Observe(chunk); !protocol.IsCode(err, "upstream_protocol_error") {
		t.Fatalf("oversize Observe() error = %v", err)
	}
	if observer.buffer.Len() != 0 || !observer.overflow {
		t.Fatalf("overflow retained memory: length=%d overflow=%v", observer.buffer.Len(), observer.overflow)
	}
	if _, err := observer.Finalize(); !protocol.IsCode(err, "upstream_protocol_error") {
		t.Fatalf("overflow Finalize() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelled := &jsonObserver{ctx: ctx}
	cancel()
	if err := cancelled.Observe([]byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Observe() error = %v", err)
	}
	if _, err := cancelled.Finalize(); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Finalize() error = %v", err)
	}
}

func TestSSEObserverExtractsTerminalCumulativeUsage(t *testing.T) {
	stream := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: ping\n" +
		"data: {\"type\":\"ping\"}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":12,\"output_tokens\":4}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
	observer := &sseObserver{ctx: context.Background()}
	for _, chunk := range splitBytes([]byte(stream), 7) {
		if err := observer.Observe(chunk); err != nil {
			t.Fatalf("Observe() error = %v", err)
		}
	}
	usage, err := observer.Finalize()
	want := protocol.Usage{InputTokens: 12, OutputTokens: 4, TotalTokens: 16, Known: true, Provenance: providerUsageProvenance}
	if err != nil || usage != want {
		t.Fatalf("Finalize() usage=%+v error=%v, want %+v", usage, err, want)
	}
}

func TestSSEObserverSupportsBOMCRLFMultilineDataAndUnknownEvents(t *testing.T) {
	stream := "\xef\xbb\xbfevent: message_start\r\n" +
		"data: {\"type\":\"message_start\",\r\n" +
		"data: \"message\":{\"type\":\"message\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\r\n\r\n" +
		"event: future_event\r\ndata: {\"type\":\"future_event\",\"new\":true}\r\n\r\n" +
		": heartbeat\r\n\r\n" +
		"event: message_delta\r\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\r\n\r\n" +
		"event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n"
	observer := &sseObserver{ctx: context.Background()}
	for _, chunk := range splitBytes([]byte(stream), 1) {
		if err := observer.Observe(chunk); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := observer.Finalize()
	if err != nil || usage.InputTokens != 1 || usage.OutputTokens != 2 || usage.TotalTokens != 3 {
		t.Fatalf("Finalize() usage=%+v error=%v", usage, err)
	}
}

func TestSSEObserverRejectsMalformedAndNonterminalStreams(t *testing.T) {
	start := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n"
	delta := "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\n\n"
	stop := "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	tests := []struct {
		name        string
		stream      string
		after       string
		wantObserve bool
	}{
		{name: "missing start", stream: "event: ping\ndata: {\"type\":\"ping\"}\n\n", wantObserve: true},
		{name: "unnamed", stream: "data: {\"type\":\"message_start\"}\n\n", wantObserve: true},
		{name: "event mismatch", stream: "event: ping\ndata: {\"type\":\"message_start\"}\n\n", wantObserve: true},
		{name: "duplicate event field", stream: "event: message_start\nevent: message_start\ndata: {}\n\n", wantObserve: true},
		{name: "duplicate JSON member", stream: "event: message_start\ndata: {\"type\":\"message_start\",\"type\":\"message_start\"}\n\n", wantObserve: true},
		{name: "stream error", stream: "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"secret\"}}\n\n", wantObserve: true},
		{name: "duplicate start", stream: start + start, wantObserve: true},
		{name: "start missing usage", stream: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"type\":\"message\"}}\n\n", wantObserve: true},
		{name: "start fractional usage", stream: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"usage\":{\"input_tokens\":1.0,\"output_tokens\":0}}}\n\n", wantObserve: true},
		{name: "delta missing output", stream: start + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":1}}\n\n", wantObserve: true},
		{name: "input decreases", stream: start + "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":0,\"output_tokens\":2}}\n\n", wantObserve: true},
		{name: "output decreases", stream: strings.Replace(start, `"output_tokens":0`, `"output_tokens":3`, 1) + delta, wantObserve: true},
		{name: "stop before delta", stream: start + stop, wantObserve: true},
		{name: "usage total overflow", stream: strings.Replace(start, `"input_tokens":1`, `"input_tokens":9223372036854775807`, 1) + strings.Replace(delta, `"output_tokens":2`, `"output_tokens":1`, 1) + stop, wantObserve: true},
		{name: "bytes after stop", stream: start + delta + stop, after: "event: ping\ndata: {\"type\":\"ping\"}\n\n", wantObserve: true},
		{name: "incomplete event", stream: start + delta + "event: message_stop\ndata: {\"type\":\"message_stop\"}\n"},
		{name: "missing stop", stream: start + delta},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &sseObserver{ctx: context.Background()}
			observeErr := observer.Observe([]byte(test.stream))
			if observeErr == nil && test.after != "" {
				observeErr = observer.Observe([]byte(test.after))
			}
			if test.wantObserve {
				if !protocol.IsCode(observeErr, "upstream_protocol_error") {
					t.Fatalf("Observe() error = %v, want upstream_protocol_error", observeErr)
				}
				if strings.Contains(errString(observeErr), "secret") {
					t.Fatalf("provider error detail leaked: %v", observeErr)
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

func TestSSEObserverEnforcesEventAndCountLimitsAndCancellation(t *testing.T) {
	observer := &sseObserver{ctx: context.Background()}
	oversized := append([]byte("event: future\ndata: "), bytes.Repeat([]byte{'x'}, maximumSSEEvent+8)...)
	if err := observer.Observe(oversized); !protocol.IsCode(err, "upstream_protocol_error") {
		t.Fatalf("oversized event error = %v", err)
	}

	observer = &sseObserver{ctx: context.Background(), events: maximumSSEEvents}
	if err := observer.Observe([]byte("event: message_start\ndata: {}\n\n")); !protocol.IsCode(err, "upstream_protocol_error") {
		t.Fatalf("event count error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	observer = &sseObserver{ctx: ctx}
	cancel()
	if err := observer.Observe([]byte("event: ping\ndata: {}\n\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Observe() error = %v", err)
	}
	if _, err := observer.Finalize(); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Finalize() error = %v", err)
	}
}

const validRequestBody = `{"model":"client","messages":[{"role":"user","content":"hello"}],"max_tokens":64}`

func newRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func requestWithBody(t *testing.T, body io.ReadCloser) *http.Request {
	t.Helper()
	request := newRequest(t, validRequestBody)
	request.Body = body
	request.ContentLength = -1
	return request
}

func appliedRequest(t *testing.T, streaming bool) *http.Request {
	t.Helper()
	body := `{"model":"client","messages":[{"role":"user","content":"hello"}]}`
	if streaming {
		body = `{"model":"client","messages":[{"role":"user","content":"hello"}],"stream":true}`
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
	number, ok := value.(interface{ Int64() (int64, error) })
	if !ok {
		t.Fatalf("value is not a JSON number: %#v", value)
	}
	parsed, err := number.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return parsed
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

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
