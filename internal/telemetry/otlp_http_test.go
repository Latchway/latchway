package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistryEnvironmentOTLPHTTPExporterFlushesOnShutdown(t *testing.T) {
	type observation struct {
		body        []byte
		contentType string
		method      string
		path        string
		readErr     error
	}

	requests := make(chan observation, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		requests <- observation{
			body:        body,
			contentType: request.Header.Get("Content-Type"),
			method:      request.Method,
			path:        request.URL.Path,
			readErr:     err,
		}
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	t.Setenv("OTEL_SDK_DISABLED", "false")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", collector.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_COMPRESSION", "")
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", "")

	registry, err := NewRegistryFromEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, finish := registry.StartStage(context.Background(), "identity verification", Labels{
		Application: "app_mobile",
		Environment: "production",
	})
	finish("succeeded")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := registry.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown process telemetry: %v", err)
	}

	select {
	case request := <-requests:
		if request.readErr != nil {
			t.Fatalf("read OTLP request: %v", request.readErr)
		}
		if request.path != "/v1/traces" {
			t.Fatalf("OTLP request path=%q", request.path)
		}
		if request.method != http.MethodPost {
			t.Fatalf("OTLP request method=%q", request.method)
		}
		if request.contentType != "application/x-protobuf" {
			t.Fatalf("OTLP content type=%q", request.contentType)
		}
		if len(request.body) == 0 {
			t.Fatal("OTLP shutdown sent an empty trace payload")
		}
	default:
		t.Fatal("telemetry shutdown did not flush a trace to the OTLP/HTTP collector")
	}
}
