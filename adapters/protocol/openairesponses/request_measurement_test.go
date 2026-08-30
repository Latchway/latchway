package openairesponses

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestMeasureRequestCountsClosedResponsesToolUnits(t *testing.T) {
	t.Parallel()

	request := newRequest(t, `{
		"model":"client",
		"input":[
			{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},
			{"type":"function_call_output","call_id":"call_1","output":"ok"},
			{"type":"custom_tool_call","call_id":"call_2","name":"render","input":"circle"},
			{"type":"custom_tool_call_output","call_id":"call_2","output":"done"}
		],
		"tools":[{"type":"function","name":"lookup"},{"type":"custom","name":"render","format":{"type":"text"}}]
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
		measurement.RequestBytes != int64(len(rewritten)) || measurement.ImageUnits != 0 ||
		measurement.ToolCalls != 2 || !measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
		t.Fatalf("measurement = %+v", measurement)
	}
}
