package openaichat

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestMeasureRequestCountsExactRewrittenChatUnits(t *testing.T) {
	t.Parallel()
	body := `{
		"model":"client",
		"messages":[
			{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"https://example.test/a.png"}},{"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}}]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}},{"id":"call_2","type":"custom","custom":{"name":"render","input":"circle"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"ok"},
			{"role":"tool","tool_call_id":"call_2","content":"ok"}
		],
		"tools":[{"type":"function","function":{"name":"lookup"}},{"type":"custom","custom":{"name":"render","format":{"type":"text"}}}]
	}`
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	adapter := Adapter{}
	if _, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "server", DefaultOutputTokens: 8, MaximumOutputTokens: 16,
	}); err != nil {
		t.Fatal(err)
	}
	rewritten := bodyFromFactory(t, request)
	measurement, err := adapter.MeasureRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if measurement.Protocol != ID || measurement.RewrittenBodySHA256 != sha256.Sum256(rewritten) ||
		measurement.RequestBytes != int64(len(rewritten)) || measurement.ImageUnits != 2 ||
		measurement.ToolCalls != 2 || !measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
		t.Fatalf("measurement = %+v", measurement)
	}
	if got := bodyFromFactory(t, request); string(got) != string(rewritten) {
		t.Fatal("measurement changed the rewritten body")
	}
}

func bodyFromFactory(t *testing.T, request *http.Request) []byte {
	t.Helper()
	body, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	value, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
