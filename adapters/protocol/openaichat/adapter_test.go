package openaichat

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
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

func TestTrustedInputPreflightBindsExactRewrittenUnicodeBody(t *testing.T) {
	t.Parallel()

	body := `{
		"model":"client-alias",
		"messages":[
			{"role":"developer","content":"Respond briefly."},
			{"role":"user","content":"你好 🌉"}
		],
		"stream":true,
		"n":1,
		"max_completion_tokens":100
	}`
	request := rewrittenTrustedInputRequest(t, body, protocol.FeatureDecision{
		PhysicalModel: "gpt-5.1", DefaultOutputTokens: 40, MaximumOutputTokens: 80,
	})
	rewrittenBefore := requestBodyFromFactory(t, request)
	profile := testTrustedInputProfile("gpt-5.1")
	profile.MaximumFramingTokensPerRequest = 11
	profile.MaximumFramingTokensPerMessage = 7

	preflight, err := (Adapter{}).PreflightInput(context.Background(), request, profile)
	if err != nil {
		t.Fatalf("PreflightInput() error = %v", err)
	}
	wantInput := int64(len(rewrittenBefore)) + 11 + 2*7
	if preflight.ProfileID != profile.ID || preflight.ProfileDigest != profile.Digest() ||
		preflight.Protocol != ID || preflight.Method != protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1 ||
		preflight.PhysicalModel != "gpt-5.1" || preflight.RequestBytes != int64(len(rewrittenBefore)) ||
		preflight.MessageCount != 2 || preflight.InputTokenBound != wantInput ||
		preflight.OutputTokenBound != 80 || preflight.TotalTokenBound != wantInput+80 {
		t.Fatalf("unexpected trusted input preflight: %+v", preflight)
	}
	if wantDigest := sha256.Sum256(rewrittenBefore); preflight.RewrittenBodySHA256 != wantDigest {
		t.Fatalf("rewritten body digest = %x, want %x", preflight.RewrittenBodySHA256, wantDigest)
	}
	rewrittenAfter, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rewrittenAfter) != string(rewrittenBefore) {
		t.Fatalf("preflight mutated rewritten body:\n before=%s\n  after=%s", rewrittenBefore, rewrittenAfter)
	}
	if request.ContentLength != int64(len(rewrittenBefore)) || string(requestBodyFromFactory(t, request)) != string(rewrittenBefore) {
		t.Fatal("preflight did not preserve immutable request body accessors")
	}
	if !strings.Contains(string(rewrittenBefore), "你好 🌉") {
		t.Fatalf("Unicode content was not preserved in rewritten body: %s", rewrittenBefore)
	}
	if capabilities := (Adapter{}).Capabilities(); !capabilities.TrustedInputPreflight || capabilities.ExactInputPreflight {
		t.Fatalf("unexpected input preflight capabilities: %+v", capabilities)
	}
	var _ protocol.InputPreflighter = Adapter{}
}

func TestTrustedInputPreflightRejectsUnboundedRequestShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "unknown root extension", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"temperature":0.2}`},
		{name: "tools", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup"}}]}`},
		{name: "legacy functions", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"lookup"}]}`},
		{name: "root file", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"file":"remote"}`},
		{name: "root file id", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"file_id":"file_01"}`},
		{name: "root data", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"data":"AA=="}`},
		{name: "remote reference", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"image_url":"https://example.test/image.png"}`},
		{name: "message extension", body: `{"model":"client","messages":[{"role":"user","content":"hi","name":"alias"}]}`},
		{name: "tool message", body: `{"model":"client","messages":[{"role":"tool","tool_call_id":"call_01","content":"result"}]}`},
		{name: "function message", body: `{"model":"client","messages":[{"role":"function","name":"lookup","content":"result"}]}`},
		{name: "null assistant content", body: `{"model":"client","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_01","type":"function","function":{"name":"lookup","arguments":"{}"}}]}]}`},
		{name: "text content array", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`},
		{name: "image content array", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]}]}`},
		{name: "file content array", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"file","file":{"file_id":"file_01"}}]}]}`},
		{name: "audio content array", body: `{"model":"client","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AA==","format":"wav"}}]}]}`},
		{name: "nullable stream", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"stream":null}`},
		{name: "nullable n", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"n":null}`},
		{name: "nonstream options", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"stream_options":{"include_usage":true}}`},
		{name: "stream options extension", body: `{"model":"client","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"future_option":true}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := rewrittenTrustedInputRequest(t, test.body, protocol.FeatureDecision{
				PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32,
			})
			before := requestBodyFromFactory(t, request)
			preflight, err := (Adapter{}).PreflightInput(context.Background(), request, testTrustedInputProfile("physical"))
			if !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("PreflightInput() result=%+v error=%v, want request_invalid", preflight, err)
			}
			if preflight != (protocol.TrustedInputPreflight{}) {
				t.Fatalf("failed preflight returned partial proof: %+v", preflight)
			}
			after, readErr := io.ReadAll(request.Body)
			if readErr != nil || string(after) != string(before) {
				t.Fatalf("failed preflight changed request body: after=%q error=%v", after, readErr)
			}
		})
	}
}

func TestTrustedInputPreflightRejectsInvalidOrMismatchedProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*protocol.TrustedInputProfile)
	}{
		{name: "missing id", mutate: func(profile *protocol.TrustedInputProfile) { profile.ID = "" }},
		{name: "wrong protocol", mutate: func(profile *protocol.TrustedInputProfile) { profile.Protocol = "openai_responses" }},
		{name: "wrong method", mutate: func(profile *protocol.TrustedInputProfile) { profile.Method = "heuristic" }},
		{name: "missing physical model", mutate: func(profile *protocol.TrustedInputProfile) { profile.PhysicalModel = "" }},
		{name: "different physical model", mutate: func(profile *protocol.TrustedInputProfile) { profile.PhysicalModel = "other-physical" }},
		{name: "physical model contains internal control", mutate: func(profile *protocol.TrustedInputProfile) { profile.PhysicalModel = "phy\tsical" }},
		{name: "negative request framing", mutate: func(profile *protocol.TrustedInputProfile) { profile.MaximumFramingTokensPerRequest = -1 }},
		{name: "negative message framing", mutate: func(profile *protocol.TrustedInputProfile) { profile.MaximumFramingTokensPerMessage = -1 }},
		{name: "zero context", mutate: func(profile *protocol.TrustedInputProfile) { profile.MaximumContextTokens = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := rewrittenTrustedInputRequest(t,
				`{"model":"client","messages":[{"role":"user","content":"hi"}]}`,
				protocol.FeatureDecision{PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32},
			)
			profile := testTrustedInputProfile("physical")
			test.mutate(&profile)
			preflight, err := (Adapter{}).PreflightInput(context.Background(), request, profile)
			if err == nil || preflight != (protocol.TrustedInputPreflight{}) {
				t.Fatalf("PreflightInput() result=%+v error=%v, want closed failure", preflight, err)
			}
		})
	}
}

func TestTrustedInputPreflightRejectsContextAndArithmeticOverflow(t *testing.T) {
	t.Parallel()

	baseBody := `{"model":"client","messages":[{"role":"user","content":"hi"}]}`
	t.Run("context maximum", func(t *testing.T) {
		request := rewrittenTrustedInputRequest(t, baseBody, protocol.FeatureDecision{
			PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32,
		})
		profile := testTrustedInputProfile("physical")
		profile.MaximumContextTokens = 1
		if _, err := (Adapter{}).PreflightInput(context.Background(), request, profile); !protocol.IsCode(err, "request_invalid") {
			t.Fatalf("context mismatch error = %v, want request_invalid", err)
		}
	})
	t.Run("request framing addition", func(t *testing.T) {
		request := rewrittenTrustedInputRequest(t, baseBody, protocol.FeatureDecision{
			PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32,
		})
		profile := testTrustedInputProfile("physical")
		profile.MaximumFramingTokensPerRequest = math.MaxInt64
		profile.MaximumContextTokens = math.MaxInt64
		if result, err := (Adapter{}).PreflightInput(context.Background(), request, profile); err == nil || result != (protocol.TrustedInputPreflight{}) {
			t.Fatalf("request-framing overflow result=%+v error=%v", result, err)
		}
	})
	t.Run("message framing multiplication", func(t *testing.T) {
		request := rewrittenTrustedInputRequest(t,
			`{"model":"client","messages":[{"role":"system","content":"one"},{"role":"user","content":"two"}]}`,
			protocol.FeatureDecision{PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32},
		)
		profile := testTrustedInputProfile("physical")
		profile.MaximumFramingTokensPerMessage = math.MaxInt64
		profile.MaximumContextTokens = math.MaxInt64
		if result, err := (Adapter{}).PreflightInput(context.Background(), request, profile); err == nil || result != (protocol.TrustedInputPreflight{}) {
			t.Fatalf("message-framing overflow result=%+v error=%v", result, err)
		}
	})
	t.Run("total addition", func(t *testing.T) {
		request := rewrittenTrustedInputRequest(t, baseBody, protocol.FeatureDecision{
			PhysicalModel: "physical", DefaultOutputTokens: math.MaxInt64, MaximumOutputTokens: math.MaxInt64,
		})
		profile := testTrustedInputProfile("physical")
		profile.MaximumContextTokens = math.MaxInt64
		if result, err := (Adapter{}).PreflightInput(context.Background(), request, profile); err == nil || result != (protocol.TrustedInputPreflight{}) {
			t.Fatalf("total overflow result=%+v error=%v", result, err)
		}
	})
}

func TestTrustedInputPreflightHonorsCancellationWithoutMutatingBody(t *testing.T) {
	t.Parallel()

	request := rewrittenTrustedInputRequest(t,
		`{"model":"client","messages":[{"role":"user","content":"hi"}]}`,
		protocol.FeatureDecision{PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32},
	)
	before := requestBodyFromFactory(t, request)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := (Adapter{}).PreflightInput(ctx, request, testTrustedInputProfile("physical"))
	if !errors.Is(err, context.Canceled) || result != (protocol.TrustedInputPreflight{}) {
		t.Fatalf("cancelled preflight result=%+v error=%v", result, err)
	}
	after, readErr := io.ReadAll(request.Body)
	if readErr != nil || string(after) != string(before) {
		t.Fatalf("cancelled preflight changed request body: after=%q error=%v", after, readErr)
	}
}

func testTrustedInputProfile(physicalModel string) protocol.TrustedInputProfile {
	return protocol.TrustedInputProfile{
		ID:                             "fixture_profile",
		Protocol:                       ID,
		Method:                         protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel:                  physicalModel,
		MaximumFramingTokensPerRequest: 8,
		MaximumFramingTokensPerMessage: 4,
		MaximumContextTokens:           1_000_000,
	}
}

func rewrittenTrustedInputRequest(t *testing.T, body string, decision protocol.FeatureDecision) *http.Request {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodPost,
		"https://gateway.example/v1/chat/completions",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if _, err := (Adapter{}).ApplyFeature(context.Background(), request, decision); err != nil {
		t.Fatalf("ApplyFeature() error = %v", err)
	}
	return request
}

func requestBodyFromFactory(t *testing.T, request *http.Request) []byte {
	t.Helper()
	if request == nil || request.GetBody == nil {
		t.Fatal("request body factory is missing")
	}
	body, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	value, readErr := io.ReadAll(body)
	closeErr := body.Close()
	if readErr != nil {
		t.Fatalf("read request body factory: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("close request body factory: %v", closeErr)
	}
	return value
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
	if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "physical", DefaultOutputTokens: 32, MaximumOutputTokens: 64,
	}); err != nil {
		t.Fatalf("rich request stopped working without trusted input preflight: %v", err)
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
		_ = observer.Observe([]byte(`{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14,"cost":0.000043235}}`))
		usage, err := observer.Finalize()
		if err != nil || !usage.Known || usage.TotalTokens != 14 ||
			usage.ReportedCost != (protocol.ProviderReportedCost{NanoUSD: 43_235, Present: true, Known: true}) {
			t.Fatalf("usage=%+v err=%v", usage, err)
		}
		if observer.FirstTokenObserved() {
			t.Fatal("usage metadata without generated content marked first token")
		}
	})

	t.Run("json generated content", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		if _, err := observer.Finalize(); err != nil {
			t.Fatal(err)
		}
		if !observer.FirstTokenObserved() {
			t.Fatal("generated JSON content did not mark first token")
		}
	})

	t.Run("partial usage is conservative", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"choices":[],"usage":{"prompt_tokens":10,"total_tokens":14,"cost":1e-9}}`))
		usage, err := observer.Finalize()
		if err != nil || usage.Known || usage.Provenance != "unknown" ||
			usage.ReportedCost != (protocol.ProviderReportedCost{NanoUSD: 1, Present: true, Known: true}) {
			t.Fatalf("usage=%+v err=%v", usage, err)
		}
	})

	t.Run("invalid optional cost is marked unknown without discarding tokens", func(t *testing.T) {
		observer := &jsonObserver{}
		_ = observer.Observe([]byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"cost":0.0000000001}}`))
		usage, err := observer.Finalize()
		if err != nil || !usage.Known ||
			usage.ReportedCost != (protocol.ProviderReportedCost{Present: true}) {
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
			"\"completion_tokens\":2,\"total_tokens\":7,\"cost\":1e-9}}\n\ndata: [DONE]\n\n",
		}
		for _, chunk := range chunks {
			if err := observer.Observe([]byte(chunk)); err != nil {
				t.Fatal(err)
			}
		}
		usage, err := observer.Finalize()
		if err != nil || !usage.Known || usage.InputTokens != 5 || usage.OutputTokens != 2 ||
			usage.ReportedCost != (protocol.ProviderReportedCost{NanoUSD: 1, Present: true, Known: true}) {
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

func TestSSEObserverFirstTokenRequiresGeneratedContent(t *testing.T) {
	t.Parallel()

	observer := &sseObserver{}
	for _, lifecycle := range []string{
		": heartbeat\n\n",
		"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"audio\":{\"id\":\"audio_fixture\"}}}]}\n\n",
	} {
		if err := observer.Observe([]byte(lifecycle)); err != nil {
			t.Fatal(err)
		}
		if observer.FirstTokenObserved() {
			t.Fatalf("lifecycle-only SSE event marked first token: %q", lifecycle)
		}
	}
	if err := observer.Observe([]byte(
		"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
	)); err != nil {
		t.Fatal(err)
	}
	if !observer.FirstTokenObserved() {
		t.Fatal("generated content delta did not mark first token")
	}
}

func TestSSEObserverFirstTokenRecognizesGeneratedToolContent(t *testing.T) {
	t.Parallel()

	observer := &sseObserver{}
	if err := observer.Observe([]byte(
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_fixture\",\"type\":\"custom\"}]}}]}\n\n",
	)); err != nil {
		t.Fatal(err)
	}
	if observer.FirstTokenObserved() {
		t.Fatal("tool-call lifecycle metadata marked first token")
	}
	if err := observer.Observe([]byte(
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"custom\":{\"input\":\"print(1)\"}}]}}]}\n\n",
	)); err != nil {
		t.Fatal(err)
	}
	if !observer.FirstTokenObserved() {
		t.Fatal("generated custom-tool delta did not mark first token")
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
