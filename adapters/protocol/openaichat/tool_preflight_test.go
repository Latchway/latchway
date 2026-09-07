package openaichat

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

const weatherTool = `{"type":"function","function":{"name":"weather_check","description":"Read current weather","strict":true,"parameters":{"type":"object","$defs":{"city":{"type":"string"}},"properties":{"city":{"$ref":"#/$defs/city"}},"required":["city"],"additionalProperties":false}}}`

func TestTrustedToolPreflightPreservesBoundedRequests(t *testing.T) {
	t.Parallel()
	for _, streaming := range []bool{false, true} {
		for _, history := range []string{
			`[{"role":"user","name":"user","content":[{"type":"text","text":"Weather in Hà Nội?"}]}]`,
			`[{"role":"user","content":"Compare weather"},{"role":"assistant","content":null,"tool_calls":[{"id":"one","type":"function","function":{"name":"old_weather","arguments":"{\"city\":\"Hà Nội\"}"}},{"id":"two","type":"function","function":{"name":"weather_check","arguments":"{\"city\":\"Singapore\"}"}}]},{"role":"tool","tool_call_id":"two","name":"weather_check","content":"Sunny"},{"role":"tool","tool_call_id":"one","content":[{"type":"text","text":"Rain"}]}]`,
		} {
			root := `{"model":"client","messages":` + history + `,"tools":[` + weatherTool + `],"tool_choice":{"type":"function","function":{"name":"weather_check"}},"parallel_tool_calls":false`
			if streaming {
				root += `,"stream":true`
			}
			request := rewrittenTrustedInputRequest(t, root+`}`, protocol.FeatureDecision{
				PhysicalModel: "physical", DefaultOutputTokens: 16, MaximumOutputTokens: 32,
			})
			before := requestBodyFromFactory(t, request)
			profile := testTrustedInputProfile("physical")
			proof, err := (Adapter{}).PreflightInput(context.Background(), request, profile)
			if err != nil {
				t.Fatal(err)
			}
			wantInput := int64(len(before)) + proof.ExpandedSchemaBytes + profile.MaximumFramingTokensPerRequest + proof.MessageCount*profile.MaximumFramingTokensPerMessage
			if proof.ExpandedSchemaBytes <= 0 || proof.MessageCount <= 2 || proof.InputTokenBound != wantInput || proof.TotalTokenBound != wantInput+16 || proof.RewrittenBodySHA256 != sha256.Sum256(before) {
				t.Fatalf("incorrect tool reservation proof: %+v", proof)
			}
			after, err := io.ReadAll(request.Body)
			if err != nil || string(after) != string(before) || string(requestBodyFromFactory(t, request)) != string(before) {
				t.Fatal("preflight changed the provider payload")
			}
		}
	}
}

func TestTrustedToolPreflightRejectsUnsafeShapes(t *testing.T) {
	t.Parallel()
	base := `{"model":"physical","max_tokens":16,"messages":[{"role":"user","content":"Weather?"}],"tools":[` + weatherTool + `]}`
	tests := map[string]func(map[string]any){
		"remote ref":          func(r map[string]any) { toolSchema(r)["$ref"] = "https://example.test/schema" },
		"recursive ref":       func(r map[string]any) { toolSchema(r)["$ref"] = "#" },
		"missing ref":         func(r map[string]any) { toolSchema(r)["$ref"] = "#/$defs/missing" },
		"dynamic ref":         func(r map[string]any) { toolSchema(r)["$dynamicRef"] = "#root" },
		"scope changing id":   func(r map[string]any) { toolSchema(r)["$id"] = "https://example.test" },
		"unknown tool member": func(r map[string]any) { r["tools"].([]any)[0].(map[string]any)["provider"] = "remote" },
		"hosted tool":         func(r map[string]any) { r["tools"] = []any{map[string]any{"type": "web_search"}} },
		"null tools":          func(r map[string]any) { r["tools"] = nil },
		"null strict": func(r map[string]any) {
			r["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)["strict"] = nil
		},
		"null parallel":  func(r map[string]any) { r["parallel_tool_calls"] = nil },
		"unknown choice": func(r map[string]any) { r["tool_choice"] = "remote" },
		"missing choice function": func(r map[string]any) {
			r["tool_choice"] = map[string]any{"type": "function", "function": map[string]any{"name": "missing"}}
		},
		"required without tools": func(r map[string]any) { delete(r, "tools"); r["tool_choice"] = "required" },
		"too many tools": func(r map[string]any) {
			items := make([]any, 129)
			for i := range items {
				items[i] = r["tools"].([]any)[0]
			}
			r["tools"] = items
		},
		"schema bytes": func(r map[string]any) { toolSchema(r)["description"] = strings.Repeat("x", 4*1024*1024) },
		"schema framing": func(r map[string]any) {
			items := make([]any, 4096)
			for i := range items {
				items[i] = map[string]any{"type": "string"}
			}
			toolSchema(r)["anyOf"] = items
		},
		"schema depth": func(r map[string]any) {
			var child any = "string"
			for i := 0; i < 65; i++ {
				child = map[string]any{"items": child}
			}
			toolSchema(r)["items"] = child
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var root map[string]any
			if err := json.Unmarshal([]byte(base), &root); err != nil {
				t.Fatal(err)
			}
			mutate(root)
			encoded, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			assertToolPreflightRejected(t, string(encoded))
		})
	}
	for name, history := range map[string]string{
		"orphan result":      `[{"role":"tool","tool_call_id":"one","content":"Sunny"}]`,
		"missing result":     `[{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"weather_check","arguments":"{}"}}]}]`,
		"interleaved result": `[{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"weather_check","arguments":"{}"}}]},{"role":"user","content":"Hello"},{"role":"tool","tool_call_id":"one","content":"Sunny"}]`,
		"duplicate result":   `[{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"weather_check","arguments":"{}"}}]},{"role":"tool","tool_call_id":"one","content":"Sunny"},{"role":"tool","tool_call_id":"one","content":"Sunny"}]`,
		"duplicate call":     `[{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"weather_check","arguments":"{}"}},{"id":"one","type":"function","function":{"name":"weather_check","arguments":"{}"}}]},{"role":"tool","tool_call_id":"one","content":"Sunny"}]`,
		"call extension":     `[{"role":"assistant","tool_calls":[{"id":"one","provider":"remote","type":"function","function":{"name":"weather_check","arguments":"{}"}}]},{"role":"tool","tool_call_id":"one","content":"Sunny"}]`,
		"argument extension": `[{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"weather_check","arguments":"{}","remote_context":"remote"}}]},{"role":"tool","tool_call_id":"one","content":"Sunny"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			assertToolPreflightRejected(t, `{"model":"physical","max_tokens":16,"messages":`+history+`}`)
		})
	}
}

func toolSchema(root map[string]any) map[string]any {
	return root["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)
}

func assertToolPreflightRejected(t *testing.T, body string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	proof, err := (Adapter{}).PreflightInput(context.Background(), request, testTrustedInputProfile("physical"))
	if !protocol.IsCode(err, "request_invalid") || proof != (protocol.TrustedInputPreflight{}) {
		t.Fatalf("unsafe preflight = %+v, %v", proof, err)
	}
}
