package anthropicmessages

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestMeasureRequestCountsNestedAnthropicImageAndToolUnits(t *testing.T) {
	t.Parallel()

	request := newRequest(t, `{
		"model":"client",
		"messages":[
			{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"YQ=="}}]},
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"lookup","input":{}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"Yg=="}}]}]}
		],
		"tools":[{"name":"lookup","input_schema":{"type":"object"}}]
	}`)
	adapter := Adapter{}
	if _, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{
		PhysicalModel: "server", DefaultOutputTokens: 8, MaximumOutputTokens: 16,
	}); err != nil {
		t.Fatal(err)
	}
	rewritten := readBodyFactory(t, request)
	measurement, err := adapter.MeasureRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if measurement.Protocol != ID || measurement.RewrittenBodySHA256 != sha256.Sum256(rewritten) ||
		measurement.RequestBytes != int64(len(rewritten)) || measurement.ImageUnits != 2 ||
		measurement.ToolCalls != 1 || !measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
		t.Fatalf("measurement = %+v", measurement)
	}
}
