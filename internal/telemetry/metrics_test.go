package telemetry

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestRegistryExposesPlanMetricsWithoutHighCardinalityLabels(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Shutdown(context.Background()) })

	ctx, finish := registry.StartRequest(context.Background(), Labels{
		Application: "app_mobile", Environment: "production", Feature: "assistant",
		Route: "responses", Platform: "ios", AttestationLevel: "hardware_verified",
		Plan: "standard",
	})
	finish("succeeded", 250*time.Millisecond)
	registry.RecordUpstreamAttempt(ctx, Labels{Route: "primary", Upstream: "openai", ModelAlias: "fast", Outcome: "succeeded"}, 12, 8, 900, 50*time.Millisecond)
	registry.RecordQuotaDenial(ctx, Labels{Feature: "assistant", Outcome: "denied"}, false)
	registry.RecordWorkerJob(ctx, "enforce_retention", "succeeded", 20*time.Millisecond)

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, name := range []string{
		"latchway_client_requests_total", "latchway_upstream_attempts_total",
		"latchway_request_duration_seconds", "latchway_time_to_first_token_seconds",
		"latchway_input_tokens_total", "latchway_output_tokens_total",
		"latchway_cost_nano_usd_total", "latchway_quota_denials_total",
		"latchway_worker_job_duration_seconds",
	} {
		if !strings.Contains(text, name) {
			t.Fatalf("metrics output missing %s:\n%s", name, text)
		}
	}
	for _, forbidden := range []string{"user_id=", "installation_id=", "request_id=", "external_subject=", "raw_model_input="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("metrics output contains forbidden label %q:\n%s", forbidden, text)
		}
	}
}

func TestRegistryReplacesCredentialShapedLabelValues(t *testing.T) {
	t.Parallel()

	const credential = "Bearer_private-provider-token"
	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Shutdown(context.Background()) })
	_, finish := registry.StartRequest(context.Background(), Labels{
		Application: "app_mobile", Environment: "env_production",
		Route: credential, Feature: "req_01J67V7X5JS9VD4AFM3J8MSX91",
	})
	finish("succeeded", time.Millisecond)
	_, misplaced := registry.StartRequest(context.Background(), Labels{
		Application: "usr_01J67V7X5JS9VD4AFM3J8MSX91",
		Environment: "ins_01J67V7X5JS9VD4AFM3J8MSX91", Route: "client",
	})
	misplaced("denied", time.Millisecond)

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	text := recorder.Body.String()
	if strings.Contains(text, credential) || strings.Contains(text, "req_01J67V7X5JS9VD4AFM3J8MSX91") ||
		strings.Contains(text, "usr_01J67V7X5JS9VD4AFM3J8MSX91") ||
		strings.Contains(text, "ins_01J67V7X5JS9VD4AFM3J8MSX91") ||
		!strings.Contains(text, `route="invalid"`) || !strings.Contains(text, `feature="invalid"`) ||
		!strings.Contains(text, `application="app_mobile"`) || !strings.Contains(text, `environment="env_production"`) {
		t.Fatalf("private or high-cardinality label was not redacted:\n%s", text)
	}
}

func TestRegistryEnvironmentTraceExporterFailsClosedForUnsupportedProtocol(t *testing.T) {
	t.Setenv("OTEL_SDK_DISABLED", "false")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc")
	if _, err := NewRegistryFromEnvironment(context.Background()); err == nil {
		t.Fatal("unsupported OTLP trace protocol silently disabled tracing")
	}
}

func TestRegistryRecordsOnlyBoundedRequestLifecycleSpans(t *testing.T) {
	t.Parallel()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	registry, err := NewRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Shutdown(context.Background()) })
	ctx := context.Background()
	for _, stage := range []string{
		"identity verification", "DPoP verification", "policy evaluation", "quota reservation",
		"route selection", "upstream attempt", "streaming observation", "quota settlement",
		"req_01J67V7X5JS9VD4AFM3J8MSX91",
	} {
		_, finish := registry.StartStage(ctx, stage, Labels{Route: "primary"})
		finish("succeeded")
	}
	spans := recorder.Ended()
	if len(spans) != 9 {
		t.Fatalf("ended spans=%d", len(spans))
	}
	if spans[len(spans)-1].Name() != "request stage" {
		t.Fatalf("unbounded stage name=%q", spans[len(spans)-1].Name())
	}
	for _, span := range spans {
		if strings.Contains(span.Name(), "req_") {
			t.Fatalf("span name disclosed request identifier: %q", span.Name())
		}
	}
}
