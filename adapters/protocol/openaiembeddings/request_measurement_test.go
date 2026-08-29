package openaiembeddings

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestMeasureRequestBindsEmbeddingsBytesAndExactZeroStructuredUnits(t *testing.T) {
	t.Parallel()

	request := newRequest(t, `{"model":"client","input":["one","two"]}`)
	adapter := Adapter{}
	if _, err := adapter.ApplyFeature(context.Background(), request, protocol.FeatureDecision{PhysicalModel: "server"}); err != nil {
		t.Fatal(err)
	}
	rewritten := readBodyFactory(t, request)
	measurement, err := adapter.MeasureRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if measurement.Protocol != ID || measurement.RewrittenBodySHA256 != sha256.Sum256(rewritten) ||
		measurement.RequestBytes != int64(len(rewritten)) || measurement.ImageUnits != 0 ||
		measurement.ToolCalls != 0 || !measurement.ImageUnitsKnown || !measurement.ToolCallsKnown {
		t.Fatalf("measurement = %+v", measurement)
	}
}
