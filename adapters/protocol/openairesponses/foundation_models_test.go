package openairesponses

import (
	"context"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestFoundationModelsInlineControlsAndDisabledHistoricalTool(t *testing.T) {
	request := newRequest(t, `{"model":"placeholder","input":[
		{"role":"user","content":"weather"},
		{"type":"function_call","name":"old_weather","call_id":"call_old","arguments":"{}"},
		{"type":"function_call_output","call_id":"call_old","output":"sunny"},
		{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"Check next city"}]}],
		"tools":[{"type":"function","name":"new_weather","parameters":{"type":"object","properties":{"city":{"$ref":"#/$defs/city"}},"$defs":{"city":{"type":"string"}}}}],
		"tool_choice":"auto","temperature":0.7,"top_p":0.9,"top_k":20,
		"reasoning":{"effort":"medium","summary":"auto"},"metadata":{"latchway_generation_id":"example"},
		"text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"value":{"type":"string"}}},"strict":true}}}`)
	if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server", DefaultOutputTokens: 32, MaximumOutputTokens: 64}); err != nil {
		t.Fatal(err)
	}
	profile := protocol.TrustedInputProfile{ID: "responses", Protocol: ID, Method: protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1, PhysicalModel: "server", MaximumFramingTokensPerRequest: 7, MaximumFramingTokensPerMessage: 3, MaximumContextTokens: 100_000}
	bound, err := (Adapter{}).PreflightInput(context.Background(), request, profile)
	if err != nil {
		t.Fatal(err)
	}
	if bound.InputTokenBound <= bound.RequestBytes+7+4*3 || bound.MessageCount <= 4 {
		t.Fatalf("schema/tool expansion was not counted: %+v", bound)
	}
}

func TestFoundationModelsAccountingRejectsUnboundedShapes(t *testing.T) {
	for _, body := range []string{
		`{"model":"x","input":"hello","tools":[{"type":"function","name":"recursive","parameters":{"type":"object","properties":{"next":{"$ref":"#"}}}}]}`,
		`{"model":"x","input":"hello","text":{"format":{"type":"json_schema","name":"missing","schema":{"$ref":"#/$defs/missing"}}}}`,
		`{"model":"x","input":[{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"opaque"},{"role":"user","content":"hi"}]}`,
	} {
		request := newRequest(t, body)
		if _, err := (Adapter{}).ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server", DefaultOutputTokens: 8, MaximumOutputTokens: 16}); err != nil {
			t.Fatal(err)
		}
		profile := protocol.TrustedInputProfile{ID: "responses", Protocol: ID, Method: protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1, PhysicalModel: "server", MaximumContextTokens: 100_000}
		if _, err := (Adapter{}).PreflightInput(context.Background(), request, profile); err == nil {
			t.Fatal("expected closed failure for unbounded schema/opaque reasoning")
		}
	}
}

func TestFoundationModelsControlsRejectInvalidValues(t *testing.T) {
	for _, fragment := range []string{
		`"top_k":0`, `"top_k":1.5`, `"top_k":1000001`, `"reasoning":{"effort":{}}`,
		`"reasoning":{"summary":"unbounded"}`, `"metadata":{"bad[key]":"x"}`,
		`"metadata":{"x":123}`, `"reasoning":{"provider":"evil"}`,
	} {
		if _, err := (Adapter{}).InspectRequest(context.Background(), newRequest(t, `{"model":"x","input":"hello",`+fragment+`}`)); err == nil {
			t.Fatalf("accepted %s", fragment)
		}
	}
}
