package opaquehttp

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMeasureRequestBindsOpaqueBytesButLeavesStructuredUnitsUnknown(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/proxy/weather/v2/current", strings.NewReader("\x00opaque\xff"))
	adapter := Adapter{MaximumBodyBytes: 64}
	if _, err := adapter.ApplyFeature(context.Background(), request, opaqueDecision()); err != nil {
		t.Fatal(err)
	}
	measurement, err := adapter.MeasureRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("\x00opaque\xff")
	if measurement.Protocol != ID || measurement.RewrittenBodySHA256 != sha256.Sum256(body) ||
		measurement.RequestBytes != int64(len(body)) || measurement.ImageUnits != 0 ||
		measurement.ToolCalls != 0 || measurement.ImageUnitsKnown || measurement.ToolCallsKnown {
		t.Fatalf("measurement = %+v", measurement)
	}
}
