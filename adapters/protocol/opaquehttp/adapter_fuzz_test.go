package opaquehttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func FuzzInspectAndApplyFeature(f *testing.F) {
	f.Add(http.MethodPost, "v2/current", []byte("opaque"))
	f.Add(http.MethodGet, "v2/events", []byte(nil))
	f.Add(http.MethodPost, "v2/../private", []byte("blocked"))
	f.Add(http.MethodPost, "https://evil.example/private", []byte("blocked"))

	f.Fuzz(func(t *testing.T, method, remaining string, input []byte) {
		if len(input) > 64<<10 || len(remaining) > protocol.MaximumOpaqueHTTPProviderPathBytes {
			t.Skip()
		}
		request := &http.Request{
			Method: method,
			URL:    &url.URL{Path: protocol.OpaqueHTTPPublicPrefix + "weather/" + remaining},
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(input)),
			GetBody: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(input)), nil
			},
			ContentLength: int64(len(input)),
		}
		request = request.WithContext(context.Background())
		adapter := Adapter{MaximumBodyBytes: 64 << 10}
		metadata, err := adapter.InspectRequest(context.Background(), request)
		if err != nil {
			return
		}
		if metadata.RequestBytes != int64(len(input)) || metadata.Streaming || request.GetBody == nil {
			t.Fatalf("successful inspection returned invalid metadata: %+v", metadata)
		}
		decision := protocol.FeatureDecision{OpaqueHTTP: &protocol.OpaqueHTTPDecision{
			FeatureID:            "weather",
			ProviderPath:         "/" + remaining,
			AllowedMethods:       []string{method},
			PathPrefixes:         []string{"/"},
			MaximumBodyBytes:     64 << 10,
			MaximumResponseBytes: 64 << 10,
		}}
		if _, err := adapter.ApplyFeature(context.Background(), request, decision); err != nil {
			t.Fatalf("ApplyFeature rejected a successfully inspected request: %v", err)
		}
		measurement, measurementErr := adapter.MeasureRequest(context.Background(), request)
		if measurementErr != nil || measurement.Protocol != ID ||
			measurement.RequestBytes != int64(len(input)) ||
			measurement.RewrittenBodySHA256 != sha256.Sum256(input) ||
			measurement.ImageUnitsKnown || measurement.ToolCallsKnown {
			t.Fatalf("opaque exact-byte measurement = %+v, %v", measurement, measurementErr)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || !bytes.Equal(body, input) {
			t.Fatalf("opaque body was not preserved: error=%v", err)
		}
	})
}
