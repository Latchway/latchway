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
	registry.RecordUpstreamAttempt(ctx, Labels{Route: "primary", Upstream: "openai", ModelAlias: "fast"}, RouteAttemptObservation{
		Condition: RouteAttemptConditionNone, Outcome: "succeeded",
		CircuitState: CircuitObservationClosed,
	}, 12, 8, 900, 50*time.Millisecond)
	registry.RecordQuotaDenial(ctx, Labels{Feature: "assistant", Outcome: "denied"}, false)
	registry.RecordWorkerJob(ctx, "enforce_retention", "succeeded", 20*time.Millisecond)
	registry.RecordWorkerJob(ctx, "release_expired_concurrency_leases", "succeeded", 10*time.Millisecond)
	registry.RecordScheduledSelfTest(ctx, Labels{Application: "app_mobile", Environment: "production", Outcome: "passed"})

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
		"latchway_scheduled_self_tests_total",
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
	for _, expected := range []string{`condition="none"`, `outcome="succeeded"`, `circuit_state="closed"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("route-attempt metric missing closed observation %q:\n%s", expected, text)
		}
	}
	if !strings.Contains(text, `job="release_expired_concurrency_leases"`) {
		t.Fatalf("worker metric omitted the closed concurrency job label:\n%s", text)
	}
}

func TestRegistryRouteAttemptObservationVocabularyIncludesCircuitLifecycle(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Shutdown(context.Background()) })
	for _, state := range []string{
		CircuitObservationStale,
		CircuitObservationClosed,
		CircuitObservationOpen,
		CircuitObservationHalfOpen,
	} {
		registry.RecordUpstreamAttempt(context.Background(), Labels{Route: state}, RouteAttemptObservation{
			Condition:    RouteAttemptConditionFirstByteTimeout,
			Outcome:      "timed_out",
			CircuitState: state,
		}, -1, -1, -1, -1)
	}

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	text := recorder.Body.String()
	for _, state := range []string{"stale", "closed", "open", "half_open"} {
		if !strings.Contains(text, `circuit_state="`+state+`",condition="first_byte_timeout"`) {
			t.Fatalf("route-attempt metric missing circuit state %q:\n%s", state, text)
		}
	}
}

func TestRegistryRouteAttemptLabelsRejectValuesOutsideClosedVocabulary(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Shutdown(context.Background()) })
	registry.RecordUpstreamAttempt(context.Background(), Labels{
		Route: "primary", Outcome: "credential=must-not-win",
	}, RouteAttemptObservation{
		Condition:    "req_01J67V7X5JS9VD4AFM3J8MSX91",
		Outcome:      "provider_private_failure_text",
		CircuitState: "closed_without_a_configured_breaker",
	}, -1, -1, -1, -1)

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	text := recorder.Body.String()
	if !strings.Contains(text, `latchway_upstream_attempts_total{circuit_state="invalid",condition="invalid",outcome="invalid",route="primary"} 1`) {
		t.Fatalf("attempt labels did not collapse to the closed invalid value:\n%s", text)
	}
	for _, forbidden := range []string{
		"credential=must-not-win", "req_01J67V7X5JS9VD4AFM3J8MSX91",
		"provider_private_failure_text", "closed_without_a_configured_breaker",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("attempt metric disclosed unbounded value %q:\n%s", forbidden, text)
		}
	}
}

func TestRegistryAttestationAndActivationMetricsUseClosedDimensions(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Shutdown(context.Background()) })
	registry.RecordAttestationResult(context.Background(), Labels{
		Application: "app_mobile", Environment: "env_production",
		Feature: "must_not_appear", Route: "must_not_appear",
		Platform: "react_native_ios", AttestationLevel: "app_verified",
		Outcome: AttestationOutcomeSucceeded,
	})
	registry.RecordAttestationResult(context.Background(), Labels{
		Application: "app_mobile", Environment: "env_production",
		Upstream: "provider-private-value", Platform: "attacker-platform",
		AttestationLevel: "attacker-verdict", Outcome: "provider-private-outcome",
	})
	registry.RecordConfigurationActivation(context.Background(), Labels{
		Application: "app_mobile", Environment: "env_production",
		Plan: "must_not_appear", Outcome: ConfigurationActivationOutcomeRolledBack,
	})
	registry.RecordConfigurationActivation(context.Background(), Labels{
		Application: "app_mobile", Environment: "env_production",
		Outcome: "administrator-private-action",
	})

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	text := recorder.Body.String()
	for _, expected := range []string{
		`latchway_attestation_results_total{application="app_mobile",attestation_level="app_verified",environment="env_production",outcome="succeeded",platform="react_native_ios"} 1`,
		`latchway_attestation_results_total{application="app_mobile",attestation_level="invalid",environment="env_production",outcome="invalid",platform="invalid"} 1`,
		`latchway_config_revision_activations_total{application="app_mobile",environment="env_production",outcome="rolled_back"} 1`,
		`latchway_config_revision_activations_total{application="app_mobile",environment="env_production",outcome="invalid"} 1`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("metrics output missing closed series %q:\n%s", expected, text)
		}
	}
	for _, forbidden := range []string{
		"must_not_appear", "provider-private-value", "attacker-platform",
		"attacker-verdict", "provider-private-outcome", "administrator-private-action",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("closed metric disclosed %q:\n%s", forbidden, text)
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
