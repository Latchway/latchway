package openaiembeddings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

func TestMatchRequiresCanonicalEmbeddingsEndpoint(t *testing.T) {
	valid := newRequest(t, `{"model":"client","input":"hello"}`)
	if !(Adapter{}).Match(valid) {
		t.Fatal("canonical Embeddings endpoint did not match")
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "method", mutate: func(request *http.Request) { request.Method = http.MethodGet }},
		{name: "path", mutate: func(request *http.Request) { request.URL.Path = "/embeddings" }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "x=1" }},
		{name: "forced query", mutate: func(request *http.Request) { request.URL.ForceQuery = true }},
		{name: "encoded raw path", mutate: func(request *http.Request) { request.URL.RawPath = "/v1/%65mbeddings" }},
		{name: "opaque URL", mutate: func(request *http.Request) { request.URL.Opaque = "//gateway.example/v1/embeddings" }},
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
	if (Adapter{}).ID() != protocol.OpenAIEmbeddingsID {
		t.Fatalf("ID = %q", (Adapter{}).ID())
	}
	want := protocol.Capabilities{
		Streaming: false, ModelRewrite: true, OutputTokenClamp: false, ProviderUsage: true,
		TrustedInputPreflight: true,
	}
	if got := (Adapter{}).Capabilities(); got != want {
		t.Fatalf("Capabilities() = %+v, want %+v", got, want)
	}
}

func TestTrustedInputPreflightBindsTextBatchWithZeroOutput(t *testing.T) {
	request := newRequest(t, `{"model":"client","input":["hello","你好 🌉"],"encoding_format":"float","dimensions":128}`)
	if output, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "embedding-model",
	}); err != nil || output != 0 {
		t.Fatalf("ApplyFeature() output=%d error=%v", output, err)
	}
	rewritten := readBodyFactory(t, request)
	profile := protocol.TrustedInputProfile{
		ID: "embeddings_profile", Protocol: ID,
		Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel: "embedding-model", MaximumFramingTokensPerRequest: 5,
		MaximumFramingTokensPerMessage: 2, MaximumContextTokens: 1_000_000,
	}
	preflight, err := (Adapter{}).PreflightInput(context.Background(), request, profile)
	if err != nil {
		t.Fatalf("PreflightInput() error = %v", err)
	}
	wantInput := int64(len(rewritten)) + 5 + 2*2
	if preflight.RewrittenBodySHA256 != sha256.Sum256(rewritten) || preflight.MessageCount != 2 ||
		preflight.InputTokenBound != wantInput || preflight.OutputTokenBound != 0 ||
		preflight.TotalTokenBound != wantInput || preflight.ProfileDigest != profile.Digest() {
		t.Fatalf("trusted Embeddings proof = %+v", preflight)
	}
	if got := readBody(t, request.Body); !bytes.Equal(got, rewritten) {
		t.Fatal("preflight did not preserve the exact rewritten body")
	}
}

func TestTrustedInputPreflightRejectsCallerTokenizationAndContextOverflow(t *testing.T) {
	for _, body := range []string{
		`{"model":"client","input":[0,1,2]}`,
		`{"model":"client","input":[[0,1],[2,3]]}`,
	} {
		request := newRequest(t, body)
		if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server"}); err != nil {
			t.Fatalf("token input must remain available without trusted accounting: %v", err)
		}
		profile := protocol.TrustedInputProfile{
			ID: "embeddings_profile", Protocol: ID,
			Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
			PhysicalModel: "server", MaximumContextTokens: 1_000_000,
		}
		if result, err := (Adapter{}).PreflightInput(context.Background(), request, profile); err == nil || result != (protocol.TrustedInputPreflight{}) {
			t.Fatalf("token input result=%+v error=%v", result, err)
		}
	}

	request := appliedRequest(t, Adapter{})
	profile := protocol.TrustedInputProfile{
		ID: "embeddings_profile", Protocol: ID,
		Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel: "server", MaximumContextTokens: 1,
	}
	if result, err := (Adapter{}).PreflightInput(context.Background(), request, profile); !protocol.IsCode(err, "request_invalid") || result != (protocol.TrustedInputPreflight{}) {
		t.Fatalf("context overflow result=%+v error=%v", result, err)
	}
}

func TestInspectAcceptsOfficialLocalInputForms(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantTokenized  bool
		wantTokenCount int64
	}{
		{name: "text", body: `{"model":"client","input":"hello"}`},
		{name: "text batch", body: `{"model":"client","input":["hello","world"]}`},
		{name: "token array", body: `{"model":"client","input":[0,1,2147483647]}`, wantTokenized: true, wantTokenCount: 3},
		{name: "token batch", body: `{"model":"client","input":[[0,1],[2,3,4]],"encoding_format":"float","dimensions":1024}`, wantTokenized: true, wantTokenCount: 5},
		{name: "base64", body: `{"model":"client","input":"hello","encoding_format":"base64"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, test.body)
			metadata, err := (Adapter{}).InspectRequest(context.Background(), request)
			if err != nil {
				t.Fatalf("InspectRequest() error = %v", err)
			}
			if metadata.ClientModel != "client" || metadata.Streaming || metadata.RequestedOutputLimit != 0 ||
				metadata.RequestBytes != int64(len(test.body)) {
				t.Fatalf("metadata = %+v", metadata)
			}
			wantEstimate := (int64(len(test.body)) + 2) / 3
			if test.wantTokenized {
				wantEstimate = test.wantTokenCount
			}
			if metadata.EstimatedInputTokens != wantEstimate {
				t.Fatalf("EstimatedInputTokens = %d, want %d", metadata.EstimatedInputTokens, wantEstimate)
			}
		})
	}
}

func TestInspectAndApplyFeatureRewriteOnlyModel(t *testing.T) {
	body := []byte(`{
		"model":"client-model",
		"input":["hello","world"],
		"encoding_format":"base64",
		"dimensions":1024
	}`)
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/embeddings", bytes.NewReader(body))
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
	if metadata.ClientModel != "client-model" || metadata.Streaming || metadata.RequestedOutputLimit != 0 ||
		metadata.RequestBytes != int64(len(body)) {
		t.Fatalf("metadata = %+v", metadata)
	}

	effective, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "server/model", DefaultOutputTokens: 0, MaximumOutputTokens: 0,
	})
	if err != nil {
		t.Fatalf("ApplyFeature() error = %v", err)
	}
	if effective != 0 {
		t.Fatalf("effective output = %d, want 0", effective)
	}
	rewritten := readBody(t, request.Body)
	value, err := jsonsafe.Decode(rewritten)
	if err != nil {
		t.Fatalf("rewritten body is not strict JSON: %v", err)
	}
	object := value.(map[string]any)
	if len(object) != 4 || object["model"] != "server/model" || object["encoding_format"] != "base64" ||
		mustJSONInt64(t, object["dimensions"]) != 1024 {
		t.Fatalf("rewritten fields = %#v", object)
	}
	input := object["input"].([]any)
	if len(input) != 2 || input[0] != "hello" || input[1] != "world" {
		t.Fatalf("input changed: %#v", input)
	}
	if request.ContentLength != int64(len(rewritten)) || request.Header.Get("Content-Type") != "application/json" ||
		len(caseInsensitiveHeaderValues(request.Header, "Content-Length")) != 0 || len(request.TransferEncoding) != 0 {
		t.Fatalf("rewritten transport metadata is invalid: length=%d headers=%v transfer=%v", request.ContentLength, request.Header, request.TransferEncoding)
	}

	for index := range body {
		body[index] = 'x'
	}
	first := readBodyFactory(t, request)
	second := readBodyFactory(t, request)
	if !bytes.Equal(first, rewritten) || !bytes.Equal(second, rewritten) {
		t.Fatal("GetBody did not return stable owned rewritten bytes")
	}
}

func TestApplyFeatureRequiresZeroGenerativeOutputBounds(t *testing.T) {
	request := newRequest(t, `{"model":"client","input":"hello"}`)
	got, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server"})
	if err != nil || got != 0 {
		t.Fatalf("zero-bound ApplyFeature() = %d, %v", got, err)
	}

	for _, decision := range []protocol.FeatureDecision{
		{PhysicalModel: "server", DefaultOutputTokens: -1},
		{PhysicalModel: "server", MaximumOutputTokens: -1},
		{PhysicalModel: "server", DefaultOutputTokens: 1},
		{PhysicalModel: "server", MaximumOutputTokens: 1},
		{PhysicalModel: "server", DefaultOutputTokens: 100, MaximumOutputTokens: 1},
	} {
		request := newRequest(t, `{"model":"client","input":"hello"}`)
		if got, err := (Adapter{}).ApplyFeature(context.Background(), request, decision); err == nil || got != 0 {
			t.Fatalf("ApplyFeature(%+v) = %d, %v; want rejection", decision, got, err)
		}
	}
}

func TestInspectRejectsUnsupportedRootMembers(t *testing.T) {
	for _, member := range []string{
		`"user":"client-controlled"`,
		`"stream":false`,
		`"stream_options":{}`,
		`"max_output_tokens":1`,
		`"metadata":{"tenant":"other"}`,
		`"service_tier":"auto"`,
		`"store":false`,
		`"future_extension":true`,
	} {
		body := `{"model":"client","input":"hello",` + member + `}`
		if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); !protocol.IsCode(err, "request_invalid") {
			t.Fatalf("unsupported member %s error = %v, want request_invalid", member, err)
		}
	}
}

func TestInspectRejectsMalformedModelAndControls(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing model", body: `{"input":"hello"}`},
		{name: "null model", body: `{"model":null,"input":"hello"}`},
		{name: "empty model", body: `{"model":"","input":"hello"}`},
		{name: "leading space model", body: `{"model":" client","input":"hello"}`},
		{name: "control model", body: `{"model":"client\nmodel","input":"hello"}`},
		{name: "long model", body: `{"model":"` + strings.Repeat("m", 257) + `","input":"hello"}`},
		{name: "null encoding", body: `{"model":"client","input":"hello","encoding_format":null}`},
		{name: "wrong encoding", body: `{"model":"client","input":"hello","encoding_format":"json"}`},
		{name: "capital encoding", body: `{"model":"client","input":"hello","encoding_format":"FLOAT"}`},
		{name: "null dimensions", body: `{"model":"client","input":"hello","dimensions":null}`},
		{name: "zero dimensions", body: `{"model":"client","input":"hello","dimensions":0}`},
		{name: "negative dimensions", body: `{"model":"client","input":"hello","dimensions":-1}`},
		{name: "fraction dimensions", body: `{"model":"client","input":"hello","dimensions":1.0}`},
		{name: "exponent dimensions", body: `{"model":"client","input":"hello","dimensions":1e2}`},
		{name: "string dimensions", body: `{"model":"client","input":"hello","dimensions":"1"}`},
		{name: "large dimensions", body: `{"model":"client","input":"hello","dimensions":65537}`},
		{name: "overflow dimensions", body: `{"model":"client","input":"hello","dimensions":9223372036854775808}`},
		{name: "duplicate root", body: `{"model":"client","model":"other","input":"hello"}`},
		{name: "trailing value", body: `{"model":"client","input":"hello"}{}`},
		{name: "nonobject root", body: `[]`},
		{name: "invalid JSON", body: `{`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, test.body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestInspectRejectsMalformedInputShapes(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "missing", input: ""},
		{name: "null", input: `,"input":null`},
		{name: "empty text", input: `,"input":""`},
		{name: "NUL text", input: `,"input":"bad\u0000text"`},
		{name: "scalar token", input: `,"input":1`},
		{name: "boolean", input: `,"input":true`},
		{name: "object", input: `,"input":{"text":"hello"}`},
		{name: "empty array", input: `,"input":[]`},
		{name: "empty text in batch", input: `,"input":["hello",""]`},
		{name: "mixed text and tokens", input: `,"input":["hello",1]`},
		{name: "mixed tokens and text", input: `,"input":[1,"hello"]`},
		{name: "negative token", input: `,"input":[1,-1]`},
		{name: "fractional token", input: `,"input":[1,2.0]`},
		{name: "exponent token", input: `,"input":[1,2e1]`},
		{name: "large token", input: `,"input":[2147483648]`},
		{name: "overflow token", input: `,"input":[9223372036854775808]`},
		{name: "empty nested token input", input: `,"input":[[]]`},
		{name: "mixed token batches", input: `,"input":[[1,2],"hello"]`},
		{name: "nested noninteger", input: `,"input":[[1,true]]`},
		{name: "too deeply nested", input: `,"input":[[[1]]]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"model":"client"` + test.input + `}`
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid; body=%s", err, body)
			}
		})
	}
}

func TestInspectEnforcesInputArrayLimits(t *testing.T) {
	tooManyTexts := `{"model":"client","input":[` + strings.TrimSuffix(strings.Repeat(`"x",`, maximumBatchInputs+1), ",") + `]}`
	tooManyTokens := `{"model":"client","input":[` + strings.TrimSuffix(strings.Repeat("0,", maximumTokensPerInput+1), ",") + `]}`

	tokenInput := `[` + strings.TrimSuffix(strings.Repeat("0,", maximumTokensPerInput), ",") + `]`
	tooManyTotal := `{"model":"client","input":[` + strings.TrimSuffix(strings.Repeat(tokenInput+",", maximumTotalTokenInputs/maximumTokensPerInput+1), ",") + `]}`
	for name, body := range map[string]string{
		"too many text inputs":  tooManyTexts,
		"too many input tokens": tooManyTokens,
		"too many total tokens": tooManyTotal,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, body)); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}
}

func TestRequestTransportAndBodyFailuresAreSafe(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "nil body", mutate: func(request *http.Request) { request.Body = nil }},
		{name: "missing content type", mutate: func(request *http.Request) { request.Header.Del("Content-Type") }},
		{name: "wrong content type", mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }},
		{name: "malformed content type", mutate: func(request *http.Request) { request.Header.Set("Content-Type", "application/json; charset") }},
		{name: "duplicate content type", mutate: func(request *http.Request) { request.Header["content-type"] = []string{"application/json"} }},
		{name: "encoded body", mutate: func(request *http.Request) { request.Header.Set("Content-Encoding", "gzip") }},
		{name: "empty encoding header", mutate: func(request *http.Request) { request.Header["content-encoding"] = []string{""} }},
		{name: "declared oversize", mutate: func(request *http.Request) { request.ContentLength = 1000 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(t, `{"model":"client","input":"hello"}`)
			test.mutate(request)
			if _, err := (Adapter{MaximumBodyBytes: 128}).InspectRequest(context.Background(), request); !protocol.IsCode(err, "request_invalid") {
				t.Fatalf("InspectRequest() error = %v, want request_invalid", err)
			}
		})
	}

	oversize := newRequest(t, `{"model":"client","input":"`+strings.Repeat("x", 256)+`"}`)
	oversize.ContentLength = -1
	if _, err := (Adapter{MaximumBodyBytes: 128}).InspectRequest(context.Background(), oversize); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("oversize streamed body error = %v, want request_invalid", err)
	}

	readFailure := newRequest(t, `{"model":"client","input":"hello"}`)
	readFailure.Body = &failingBody{readErr: errors.New("secret read failure")}
	readFailure.ContentLength = -1
	if _, err := (Adapter{}).InspectRequest(context.Background(), readFailure); !protocol.IsCode(err, "request_invalid") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("read failure error = %v", err)
	}

	closeFailure := newRequest(t, `{"model":"client","input":"hello"}`)
	closeFailure.Body = &failingBody{reader: strings.NewReader(`{"model":"client","input":"hello"}`), closeErr: errors.New("secret close failure")}
	if _, err := (Adapter{}).InspectRequest(context.Background(), closeFailure); !protocol.IsCode(err, "request_invalid") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("close failure error = %v", err)
	}
}

func TestContextCancellationAndApplyFailures(t *testing.T) {
	if _, err := (Adapter{}).InspectRequest(nil, newRequest(t, `{"model":"client","input":"hello"}`)); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("nil InspectRequest context error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Adapter{}).InspectRequest(ctx, newRequest(t, `{"model":"client","input":"hello"}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled InspectRequest error = %v", err)
	}
	if _, err := (Adapter{}).ApplyFeature(ctx, newRequest(t, `{"model":"client","input":"hello"}`), protocol.FeatureDecision{PhysicalModel: "server"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ApplyFeature error = %v", err)
	}
	if _, err := (Adapter{}).ApplyFeature(nil, newRequest(t, `{"model":"client","input":"hello"}`), protocol.FeatureDecision{PhysicalModel: "server"}); !protocol.IsCode(err, "request_invalid") {
		t.Fatalf("nil ApplyFeature context error = %v", err)
	}

	for _, model := range []string{"", " server", "server\nmodel", strings.Repeat("m", 257)} {
		if _, err := (Adapter{}).ApplyFeature(context.Background(), newRequest(t, `{"model":"client","input":"hello"}`), protocol.FeatureDecision{PhysicalModel: model}); err == nil {
			t.Fatalf("unsafe physical model %q was accepted", model)
		}
	}

	cancelDuringRead, cancelRead := context.WithCancel(context.Background())
	request := newRequest(t, `{"model":"client","input":"hello"}`)
	request.Body = &cancelingBody{reader: strings.NewReader(`{"model":"client","input":"hello"}`), cancel: cancelRead}
	if _, err := (Adapter{}).ApplyFeature(cancelDuringRead, request, protocol.FeatureDecision{PhysicalModel: "server"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-read cancellation error = %v", err)
	}

	body := `{"model":"a","input":"x"}`
	request = newRequest(t, body)
	_, err := (Adapter{MaximumBodyBytes: int64(len(body))}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: strings.Repeat("m", 256),
	})
	if err == nil || !strings.Contains(err.Error(), "rewritten Embeddings request exceeds") {
		t.Fatalf("rewrite expansion error = %v", err)
	}
}

func TestObserveResponseRequiresAppliedJSONRequest(t *testing.T) {
	adapter := Adapter{}
	applied := appliedRequest(t, adapter)
	valid := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Request:    applied,
	}
	if _, err := adapter.ObserveResponse(context.Background(), valid); err != nil {
		t.Fatalf("ObserveResponse() error = %v", err)
	}

	if _, err := adapter.ObserveResponse(nil, valid); err == nil {
		t.Fatal("nil response context was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.ObserveResponse(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ObserveResponse error = %v", err)
	}
	if _, err := adapter.ObserveResponse(context.Background(), nil); err == nil {
		t.Fatal("nil response was accepted")
	}
	if _, err := adapter.ObserveResponse(context.Background(), &http.Response{}); err == nil {
		t.Fatal("response without request was accepted")
	}
	if _, err := adapter.ObserveResponse(context.Background(), &http.Response{Request: newRequest(t, `{"model":"client","input":"hello"}`)}); err == nil {
		t.Fatal("response without protocol marker was accepted")
	}

	for _, headers := range []http.Header{
		{},
		{"Content-Type": []string{"application/json", "application/json"}},
		{"Content-Type": []string{"text/event-stream"}},
		{"Content-Type": []string{"text/plain"}},
		{"Content-Type": []string{"application/json; charset"}},
		{"Content-Type": []string{"application/json"}, "content-type": []string{"application/json"}},
	} {
		response := &http.Response{StatusCode: http.StatusOK, Header: headers, Request: applied}
		if _, err := adapter.ObserveResponse(context.Background(), response); !protocol.IsCode(err, "upstream_protocol_error") {
			t.Fatalf("headers=%v error=%v, want upstream_protocol_error", headers, err)
		}
	}
}

func TestProviderErrorResponsesAreOpaqueAndSafe(t *testing.T) {
	adapter := Adapter{}
	for _, status := range []int{0, 199, 300, 400, 429, 500} {
		response := &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"malformed", "duplicate"}},
			Request:    appliedRequest(t, adapter),
		}
		observer, err := adapter.ObserveResponse(context.Background(), response)
		if err != nil {
			t.Fatalf("status %d ObserveResponse() error = %v", status, err)
		}
		if err := observer.Observe([]byte(`{"error":{"message":"provider secret"}}`)); err != nil {
			t.Fatalf("status %d Observe() error = %v", status, err)
		}
		usage, err := observer.Finalize()
		if err != nil || usage != unknownUsage() {
			t.Fatalf("status %d usage=%+v error=%v", status, usage, err)
		}
	}
}

func TestJSONUsageObservation(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		want      protocol.Usage
		wantError bool
	}{
		{name: "known", body: `{"object":"list","usage":{"prompt_tokens":7,"total_tokens":7}}`, want: protocol.Usage{InputTokens: 7, TotalTokens: 7, Known: true, Provenance: providerUsageProvenance}},
		{name: "known zero", body: `{"usage":{"prompt_tokens":0,"total_tokens":0}}`, want: protocol.Usage{Known: true, Provenance: providerUsageProvenance}},
		{name: "additional response fields", body: `{"usage":{"prompt_tokens":2,"total_tokens":2,"future_detail":{"cached":0}},"data":[]}`, want: protocol.Usage{InputTokens: 2, TotalTokens: 2, Known: true, Provenance: providerUsageProvenance}},
		{name: "missing usage", body: `{"data":[]}`, want: unknownUsage()},
		{name: "null usage", body: `{"usage":null}`, want: unknownUsage()},
		{name: "missing prompt", body: `{"usage":{"total_tokens":1}}`, want: unknownUsage()},
		{name: "missing total", body: `{"usage":{"prompt_tokens":1}}`, want: unknownUsage()},
		{name: "usage string", body: `{"usage":"secret"}`, wantError: true},
		{name: "negative prompt", body: `{"usage":{"prompt_tokens":-1,"total_tokens":0}}`, wantError: true},
		{name: "fractional prompt", body: `{"usage":{"prompt_tokens":1.0,"total_tokens":1}}`, wantError: true},
		{name: "exponent prompt", body: `{"usage":{"prompt_tokens":1e1,"total_tokens":10}}`, wantError: true},
		{name: "string prompt", body: `{"usage":{"prompt_tokens":"1","total_tokens":1}}`, wantError: true},
		{name: "overflow prompt", body: `{"usage":{"prompt_tokens":9223372036854775808,"total_tokens":0}}`, wantError: true},
		{name: "negative total", body: `{"usage":{"prompt_tokens":0,"total_tokens":-1}}`, wantError: true},
		{name: "inconsistent total", body: `{"usage":{"prompt_tokens":2,"total_tokens":3}}`, wantError: true},
		{name: "duplicate prompt", body: `{"usage":{"prompt_tokens":1,"prompt_tokens":1,"total_tokens":1}}`, wantError: true},
		{name: "duplicate usage", body: `{"usage":{"prompt_tokens":1,"total_tokens":1},"usage":null}`, wantError: true},
		{name: "trailing value", body: `{"usage":{"prompt_tokens":1,"total_tokens":1}}{}`, wantError: true},
		{name: "nonobject root", body: `[]`, wantError: true},
		{name: "malformed JSON", body: `{`, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &jsonObserver{}
			midpoint := len(test.body) / 2
			if err := observer.Observe([]byte(test.body[:midpoint])); err != nil {
				t.Fatal(err)
			}
			if err := observer.Observe([]byte(test.body[midpoint:])); err != nil {
				t.Fatal(err)
			}
			usage, err := observer.Finalize()
			if test.wantError {
				if !protocol.IsCode(err, "upstream_protocol_error") {
					t.Fatalf("Finalize() usage=%+v error=%v, want upstream_protocol_error", usage, err)
				}
				return
			}
			if err != nil || usage != test.want {
				t.Fatalf("Finalize() usage=%+v error=%v, want %+v", usage, err, test.want)
			}
		})
	}
}

func TestJSONObserverOverflowReturnsUnknownUsage(t *testing.T) {
	observer := &jsonObserver{}
	if err := observer.Observe(bytes.Repeat([]byte{'x'}, int(maximumObservedJSON))); err != nil {
		t.Fatal(err)
	}
	if err := observer.Observe([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if err := observer.Observe([]byte(`{"usage":{"prompt_tokens":1,"total_tokens":1}}`)); err != nil {
		t.Fatal(err)
	}
	usage, err := observer.Finalize()
	if err != nil || usage != unknownUsage() {
		t.Fatalf("Finalize() usage=%+v error=%v", usage, err)
	}
}

func TestAdapterCanBeUsedConcurrently(t *testing.T) {
	adapter := Adapter{}
	const workers = 32
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			body := `{"model":"client","input":[` + strconv.Itoa(worker) + `]}`
			request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/embeddings", strings.NewReader(body))
			if err != nil {
				errorsByWorker <- err
				return
			}
			request.Header.Set("Content-Type", "application/json")
			if _, err := adapter.InspectRequest(context.Background(), request); err != nil {
				errorsByWorker <- err
				return
			}
			if output, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server"}); err != nil || output != 0 {
				if err == nil {
					err = errors.New("nonzero output maximum")
				}
				errorsByWorker <- err
				return
			}
			observer, err := adapter.ObserveResponse(context.Background(), &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    request,
			})
			if err != nil {
				errorsByWorker <- err
				return
			}
			usageBody := `{"usage":{"prompt_tokens":1,"total_tokens":1}}`
			if err := observer.Observe([]byte(usageBody)); err != nil {
				errorsByWorker <- err
				return
			}
			usage, err := observer.Finalize()
			if err != nil || !usage.Known || usage.InputTokens != 1 || usage.OutputTokens != 0 {
				if err == nil {
					err = errors.New("unexpected normalized usage")
				}
				errorsByWorker <- err
			}
		}(worker)
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Errorf("concurrent adapter use failed: %v", err)
	}
}

func appliedRequest(t *testing.T, adapter Adapter) *http.Request {
	t.Helper()
	request := newRequest(t, `{"model":"client","input":"hello"}`)
	if output, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server"}); err != nil || output != 0 {
		t.Fatalf("ApplyFeature() output=%d error=%v", output, err)
	}
	return request
}

func newRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/embeddings", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func readBody(t *testing.T, body io.ReadCloser) []byte {
	t.Helper()
	result, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
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

type failingBody struct {
	reader   io.Reader
	readErr  error
	closeErr error
}

func (body *failingBody) Read(buffer []byte) (int, error) {
	if body.readErr != nil {
		return 0, body.readErr
	}
	return body.reader.Read(buffer)
}

func (body *failingBody) Close() error { return body.closeErr }

type cancelingBody struct {
	reader io.Reader
	cancel context.CancelFunc
	once   sync.Once
}

func (body *cancelingBody) Read(buffer []byte) (int, error) {
	body.once.Do(body.cancel)
	return body.reader.Read(buffer)
}

func (*cancelingBody) Close() error { return nil }
