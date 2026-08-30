// Package telemetry configures redaction-safe OpenTelemetry instrumentation.
package telemetry

import (
	"context"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otlptracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	otelnoop "go.opentelemetry.io/otel/trace/noop"
)

const instrumentationName = "github.com/latchway/latchway"

const (
	AttestationOutcomeSucceeded   = "succeeded"
	AttestationOutcomeRejected    = "rejected"
	AttestationOutcomeUnavailable = "unavailable"

	ConfigurationActivationOutcomeActivated  = "activated"
	ConfigurationActivationOutcomeRolledBack = "rolled_back"

	RouteAttemptConditionNone                 = "none"
	RouteAttemptConditionConnectError         = "connect_error"
	RouteAttemptConditionTimeoutBeforeHeaders = "timeout_before_headers"
	RouteAttemptConditionStatus408            = "status_408"
	RouteAttemptConditionStatus429            = "status_429"
	RouteAttemptConditionStatus500            = "status_500"
	RouteAttemptConditionStatus502            = "status_502"
	RouteAttemptConditionStatus503            = "status_503"
	RouteAttemptConditionStatus504            = "status_504"

	// CircuitObservationNotConfigured is an explicit observation, not a
	// breaker state. This release does not suppress or admit a route based on
	// inferred circuit behavior.
	CircuitObservationNotConfigured = "not_configured"
)

var telemetryLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

var highCardinalityIdentifierPattern = regexp.MustCompile(`(?i)^(?:usr|ins|req|sgr|rft|rff|atm|drp)_[A-Za-z0-9_-]{8,}$`)

// Labels is the complete public metric-label vocabulary. Keeping attributes
// in a closed type prevents request, installation, user, identity-subject, or
// provider-payload data from becoming metric dimensions.
type Labels struct {
	Application      string
	Environment      string
	Feature          string
	Route            string
	Upstream         string
	ModelAlias       string
	Platform         string
	AttestationLevel string
	Plan             string
	Outcome          string
}

// RouteAttemptObservation is the closed route-attempt telemetry vocabulary.
// Every field is emitted on every dispatched attempt. Invalid or future values
// collapse to "invalid" instead of creating attacker-controlled time series.
type RouteAttemptObservation struct {
	Condition    string
	Outcome      string
	CircuitState string
}

// Registry owns the process metric instruments and Prometheus scrape surface.
// It accepts an explicit tracer provider so deployments can attach an OTLP
// exporter without coupling the core process to one collector topology.
type Registry struct {
	provider      *sdkmetric.MeterProvider
	handler       http.Handler
	tracer        trace.Tracer
	shutdownTrace func(context.Context) error

	clientRequests        metric.Int64Counter
	upstreamAttempts      metric.Int64Counter
	requestDuration       metric.Float64Histogram
	timeToFirstToken      metric.Float64Histogram
	inputTokens           metric.Int64Counter
	outputTokens          metric.Int64Counter
	costNanoUSD           metric.Int64Counter
	quotaDenials          metric.Int64Counter
	concurrencyDenials    metric.Int64Counter
	identityFailures      metric.Int64Counter
	attestationResults    metric.Int64Counter
	dpopFailures          metric.Int64Counter
	activeRequests        metric.Int64UpDownCounter
	activeStreams         metric.Int64UpDownCounter
	reservationsActive    metric.Int64UpDownCounter
	reservationsReclaimed metric.Int64Counter
	configActivations     metric.Int64Counter
	scheduledSelfTests    metric.Int64Counter
	workerJobDuration     metric.Float64Histogram
}

// NewRegistry constructs an isolated Prometheus registry backed by the stable
// OpenTelemetry Go metric SDK. Tests and multiple in-process replicas can each
// construct one without colliding through global registries.
func NewRegistry(tracerProvider trace.TracerProvider) (*Registry, error) {
	return newRegistry(tracerProvider, nil)
}

// NewRegistryFromEnvironment enables OTLP/HTTP trace export when
// OTEL_TRACES_EXPORTER=otlp. The official exporter consumes the standard
// OTEL_EXPORTER_OTLP_* environment variables. No global OTel provider is
// mutated, so multiple in-process runtimes and tests remain isolated.
func NewRegistryFromEnvironment(ctx context.Context) (*Registry, error) {
	if ctx == nil {
		return nil, errors.New("construct process telemetry")
	}
	exporterName := strings.TrimSpace(strings.ToLower(os.Getenv("OTEL_TRACES_EXPORTER")))
	if exporterName == "" || exporterName == "none" || strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
		return NewRegistry(nil)
	}
	if exporterName != "otlp" {
		return nil, errors.New("construct process telemetry")
	}
	protocol := strings.TrimSpace(strings.ToLower(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")))
	if protocol == "" {
		protocol = strings.TrimSpace(strings.ToLower(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")))
	}
	if protocol != "" && protocol != "http/protobuf" {
		return nil, errors.New("construct process telemetry")
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, errors.New("construct process telemetry")
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter))
	registry, err := newRegistry(provider, provider.Shutdown)
	if err != nil {
		_ = provider.Shutdown(context.Background())
		return nil, err
	}
	return registry, nil
}

func newRegistry(tracerProvider trace.TracerProvider, shutdownTrace func(context.Context) error) (*Registry, error) {
	prometheusRegistry := prometheus.NewRegistry()
	exporter, err := otelprom.New(
		otelprom.WithRegisterer(prometheusRegistry),
		otelprom.WithoutTargetInfo(),
		otelprom.WithoutScopeInfo(),
		otelprom.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithoutSuffixes),
	)
	if err != nil {
		return nil, errors.New("construct OpenTelemetry Prometheus exporter")
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	meter := provider.Meter(instrumentationName)
	if tracerProvider == nil {
		tracerProvider = otelnoop.NewTracerProvider()
	}
	registry := &Registry{
		provider: provider,
		handler: promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{
			ErrorHandling: promhttp.HTTPErrorOnError,
		}),
		tracer: tracerProvider.Tracer(instrumentationName), shutdownTrace: shutdownTrace,
	}
	if err := registry.initialize(meter); err != nil {
		_ = provider.Shutdown(context.Background())
		return nil, err
	}
	return registry, nil
}

func (registry *Registry) initialize(meter metric.Meter) (err error) {
	if registry == nil {
		return errors.New("telemetry registry is nil")
	}
	registry.clientRequests, err = meter.Int64Counter("latchway_client_requests_total")
	if err != nil {
		return err
	}
	registry.upstreamAttempts, err = meter.Int64Counter("latchway_upstream_attempts_total")
	if err != nil {
		return err
	}
	registry.requestDuration, err = meter.Float64Histogram("latchway_request_duration_seconds", metric.WithUnit("s"))
	if err != nil {
		return err
	}
	registry.timeToFirstToken, err = meter.Float64Histogram("latchway_time_to_first_token_seconds", metric.WithUnit("s"))
	if err != nil {
		return err
	}
	registry.inputTokens, err = meter.Int64Counter("latchway_input_tokens_total")
	if err != nil {
		return err
	}
	registry.outputTokens, err = meter.Int64Counter("latchway_output_tokens_total")
	if err != nil {
		return err
	}
	registry.costNanoUSD, err = meter.Int64Counter("latchway_cost_nano_usd_total")
	if err != nil {
		return err
	}
	registry.quotaDenials, err = meter.Int64Counter("latchway_quota_denials_total")
	if err != nil {
		return err
	}
	registry.concurrencyDenials, err = meter.Int64Counter("latchway_concurrency_denials_total")
	if err != nil {
		return err
	}
	registry.identityFailures, err = meter.Int64Counter("latchway_identity_failures_total")
	if err != nil {
		return err
	}
	registry.attestationResults, err = meter.Int64Counter("latchway_attestation_results_total")
	if err != nil {
		return err
	}
	registry.dpopFailures, err = meter.Int64Counter("latchway_dpop_failures_total")
	if err != nil {
		return err
	}
	registry.activeRequests, err = meter.Int64UpDownCounter("latchway_active_requests")
	if err != nil {
		return err
	}
	registry.activeStreams, err = meter.Int64UpDownCounter("latchway_active_streams")
	if err != nil {
		return err
	}
	registry.reservationsActive, err = meter.Int64UpDownCounter("latchway_reservations_active")
	if err != nil {
		return err
	}
	registry.reservationsReclaimed, err = meter.Int64Counter("latchway_reservations_reclaimed_total")
	if err != nil {
		return err
	}
	registry.configActivations, err = meter.Int64Counter("latchway_config_revision_activations_total")
	if err != nil {
		return err
	}
	registry.scheduledSelfTests, err = meter.Int64Counter("latchway_scheduled_self_tests_total")
	if err != nil {
		return err
	}
	registry.workerJobDuration, err = meter.Float64Histogram("latchway_worker_job_duration_seconds", metric.WithUnit("s"))
	return err
}

// Handler returns the Prometheus scrape handler. It intentionally exposes only
// this Registry's metrics and no process-global third-party collectors.
func (registry *Registry) Handler() http.Handler {
	if registry == nil || registry.handler == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		})
	}
	return registry.handler
}

// Shutdown releases the metric reader. It is safe to call during process
// shutdown after all instrumented components have drained.
func (registry *Registry) Shutdown(ctx context.Context) error {
	if registry == nil {
		return nil
	}
	var metricErr, traceErr error
	if registry.provider != nil {
		metricErr = registry.provider.Shutdown(ctx)
	}
	if registry.shutdownTrace != nil {
		traceErr = registry.shutdownTrace(ctx)
	}
	return errors.Join(metricErr, traceErr)
}

// StartRequest records one active request and creates the incoming-request
// span. The returned completion function must be called exactly once.
func (registry *Registry) StartRequest(ctx context.Context, labels Labels) (context.Context, func(string, time.Duration)) {
	if registry == nil {
		return ctx, func(string, time.Duration) {}
	}
	attributes := labels.attributes()
	registry.activeRequests.Add(ctx, 1, metric.WithAttributes(attributes...))
	spanCtx, span := registry.tracer.Start(ctx, "incoming request", trace.WithAttributes(attributes...))
	return spanCtx, func(outcome string, duration time.Duration) {
		finished := labels
		finished.Outcome = outcome
		finishedAttributes := finished.attributes()
		registry.activeRequests.Add(spanCtx, -1, metric.WithAttributes(attributes...))
		registry.clientRequests.Add(spanCtx, 1, metric.WithAttributes(finishedAttributes...))
		registry.requestDuration.Record(spanCtx, duration.Seconds(), metric.WithAttributes(finishedAttributes...))
		span.SetAttributes(attribute.String("outcome", safeMetricLabel("outcome", outcome)))
		span.End()
	}
}

// StartStage starts one of the fixed request-lifecycle spans required by the
// operational contract. Unknown names collapse to a bounded generic stage;
// callers cannot turn request data into span names or attributes.
func (registry *Registry) StartStage(ctx context.Context, stage string, labels Labels) (context.Context, func(string)) {
	if registry == nil {
		return ctx, func(string) {}
	}
	stage = safeTraceStage(stage)
	spanCtx, span := registry.tracer.Start(ctx, stage, trace.WithAttributes(labels.attributes()...))
	return spanCtx, func(outcome string) {
		outcome = safeMetricLabel("outcome", outcome)
		span.SetAttributes(attribute.String("outcome", outcome))
		if outcome == "failed" || outcome == "denied" {
			span.SetStatus(codes.Error, outcome)
		}
		span.End()
	}
}

func (registry *Registry) RecordUpstreamAttempt(
	ctx context.Context,
	labels Labels,
	observation RouteAttemptObservation,
	inputTokens, outputTokens, costNanoUSD int64,
	firstToken time.Duration,
) {
	if registry == nil {
		return
	}
	// Generic lifecycle outcomes are intentionally ignored here. Attempt
	// outcome, route condition, and circuit observation use stricter enums.
	labels.Outcome = ""
	attributes := append(labels.attributes(), observation.attributes()...)
	registry.upstreamAttempts.Add(ctx, 1, metric.WithAttributes(attributes...))
	if inputTokens >= 0 {
		registry.inputTokens.Add(ctx, inputTokens, metric.WithAttributes(attributes...))
	}
	if outputTokens >= 0 {
		registry.outputTokens.Add(ctx, outputTokens, metric.WithAttributes(attributes...))
	}
	if costNanoUSD >= 0 {
		registry.costNanoUSD.Add(ctx, costNanoUSD, metric.WithAttributes(attributes...))
	}
	if firstToken >= 0 {
		registry.timeToFirstToken.Record(ctx, firstToken.Seconds(), metric.WithAttributes(attributes...))
	}
}

func (observation RouteAttemptObservation) attributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("condition", safeRouteAttemptCondition(observation.Condition)),
		attribute.String("outcome", safeRouteAttemptOutcome(observation.Outcome)),
		attribute.String("circuit_state", safeCircuitObservationState(observation.CircuitState)),
	}
}

func safeRouteAttemptCondition(condition string) string {
	switch condition {
	case RouteAttemptConditionNone,
		RouteAttemptConditionConnectError,
		RouteAttemptConditionTimeoutBeforeHeaders,
		RouteAttemptConditionStatus408,
		RouteAttemptConditionStatus429,
		RouteAttemptConditionStatus500,
		RouteAttemptConditionStatus502,
		RouteAttemptConditionStatus503,
		RouteAttemptConditionStatus504:
		return condition
	default:
		return "invalid"
	}
}

func safeRouteAttemptOutcome(outcome string) string {
	switch outcome {
	case "succeeded", "failed", "cancelled", "timed_out":
		return outcome
	default:
		return "invalid"
	}
}

func safeCircuitObservationState(state string) string {
	if state == CircuitObservationNotConfigured {
		return state
	}
	return "invalid"
}

func (registry *Registry) RecordQuotaDenial(ctx context.Context, labels Labels, concurrency bool) {
	if registry == nil {
		return
	}
	instrument := registry.quotaDenials
	if concurrency {
		instrument = registry.concurrencyDenials
	}
	instrument.Add(ctx, 1, metric.WithAttributes(labels.attributes()...))
}

func (registry *Registry) RecordIdentityFailure(ctx context.Context, labels Labels) {
	if registry != nil {
		registry.identityFailures.Add(ctx, 1, metric.WithAttributes(labels.attributes()...))
	}
}

func (registry *Registry) RecordAttestationResult(ctx context.Context, labels Labels) {
	if registry == nil {
		return
	}
	// Attestation telemetry has a deliberately smaller vocabulary than the
	// general request label set. Provider payloads, policy identifiers, and
	// installation/user identifiers can therefore never become dimensions,
	// even if a future caller accidentally supplies them in Labels.
	labels.Feature = ""
	labels.Route = ""
	labels.Upstream = ""
	labels.ModelAlias = ""
	labels.Plan = ""
	labels.Platform = safeAttestationPlatform(labels.Platform)
	labels.AttestationLevel = safeAttestationLevel(labels.AttestationLevel)
	labels.Outcome = safeAttestationOutcome(labels.Outcome)
	registry.attestationResults.Add(ctx, 1, metric.WithAttributes(labels.attributes()...))
}

func (registry *Registry) RecordDPoPFailure(ctx context.Context, labels Labels) {
	if registry != nil {
		registry.dpopFailures.Add(ctx, 1, metric.WithAttributes(labels.attributes()...))
	}
}

func (registry *Registry) AddActiveStreams(ctx context.Context, labels Labels, delta int64) {
	if registry != nil {
		registry.activeStreams.Add(ctx, delta, metric.WithAttributes(labels.attributes()...))
	}
}

func (registry *Registry) AddActiveReservations(ctx context.Context, labels Labels, delta int64) {
	if registry != nil {
		registry.reservationsActive.Add(ctx, delta, metric.WithAttributes(labels.attributes()...))
	}
}

func (registry *Registry) RecordReservationsReclaimed(ctx context.Context, labels Labels, count int64) {
	if registry != nil && count > 0 {
		registry.reservationsReclaimed.Add(ctx, count, metric.WithAttributes(labels.attributes()...))
	}
}

func (registry *Registry) RecordConfigurationActivation(ctx context.Context, labels Labels) {
	if registry == nil {
		return
	}
	// Configuration activation is scoped only by the bounded application and
	// environment resources plus the closed mutation outcome. Revision IDs and
	// administrator identities are intentionally excluded.
	labels.Feature = ""
	labels.Route = ""
	labels.Upstream = ""
	labels.ModelAlias = ""
	labels.Platform = ""
	labels.AttestationLevel = ""
	labels.Plan = ""
	labels.Outcome = safeConfigurationActivationOutcome(labels.Outcome)
	registry.configActivations.Add(ctx, 1, metric.WithAttributes(labels.attributes()...))
}

func (registry *Registry) RecordWorkerJob(ctx context.Context, job, outcome string, duration time.Duration) {
	if registry == nil {
		return
	}
	attributes := []attribute.KeyValue{
		attribute.String("job", safeBoundedJob(job)),
		attribute.String("outcome", safeMetricLabel("outcome", outcome)),
	}
	registry.workerJobDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))
}

// RecordScheduledSelfTest records only tenant resource identifiers and a
// closed outcome. Schedule, job, administrator, credential, provider response
// and secret identifiers are intentionally absent from the metric surface.
func (registry *Registry) RecordScheduledSelfTest(ctx context.Context, labels Labels) {
	if registry == nil {
		return
	}
	labels.Feature = ""
	labels.Route = ""
	labels.Upstream = ""
	labels.ModelAlias = ""
	labels.Platform = ""
	labels.AttestationLevel = ""
	labels.Plan = ""
	switch labels.Outcome {
	case "passed", "failed", "rejected", "recovered":
	default:
		labels.Outcome = "invalid"
	}
	registry.scheduledSelfTests.Add(ctx, 1, metric.WithAttributes(labels.attributes()...))
}

func (labels Labels) attributes() []attribute.KeyValue {
	values := []struct{ key, value string }{
		{"application", labels.Application}, {"environment", labels.Environment},
		{"feature", labels.Feature}, {"route", labels.Route}, {"upstream", labels.Upstream},
		{"model_alias", labels.ModelAlias}, {"platform", labels.Platform},
		{"attestation_level", labels.AttestationLevel}, {"plan", labels.Plan}, {"outcome", labels.Outcome},
	}
	attributes := make([]attribute.KeyValue, 0, len(values))
	for _, value := range values {
		if value.value != "" {
			attributes = append(attributes, attribute.String(value.key, safeMetricLabel(value.key, value.value)))
		}
	}
	return attributes
}

func safeMetricLabel(_ string, value string) string {
	value = strings.TrimSpace(value)
	if !telemetryLabelPattern.MatchString(value) || sensitiveLabelValue(value) ||
		highCardinalityIdentifierPattern.MatchString(value) {
		return "invalid"
	}
	return value
}

func safeAttestationPlatform(platform string) string {
	switch platform {
	case "ios", "android", "web", "react_native_ios", "react_native_android", "node":
		return platform
	default:
		return "invalid"
	}
}

func safeAttestationLevel(level string) string {
	switch level {
	case "none", "identity_only", "web_risk_verified", "app_verified",
		"device_verified", "strong_device_verified", "debug":
		return level
	default:
		return "invalid"
	}
}

func safeAttestationOutcome(outcome string) string {
	switch outcome {
	case AttestationOutcomeSucceeded, AttestationOutcomeRejected, AttestationOutcomeUnavailable:
		return outcome
	default:
		return "invalid"
	}
}

func safeConfigurationActivationOutcome(outcome string) string {
	switch outcome {
	case ConfigurationActivationOutcomeActivated, ConfigurationActivationOutcomeRolledBack:
		return outcome
	default:
		return "invalid"
	}
}

func sensitiveLabelValue(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "bearer") || strings.Contains(lower, "authorization=") ||
		strings.Contains(lower, "credential=") || strings.ContainsAny(value, "\r\n\x00")
}

func safeBoundedJob(job string) string {
	switch job {
	case "release_expired_reservations", "prune_dpop_replays", "prune_challenges",
		"rotate_signing_keys", "refresh_jwks", "aggregate_hourly_usage", "aggregate_daily_usage",
		"enforce_retention", "reconcile_pending_usage", "release_expired_concurrency_leases",
		"worker_heartbeat":
		return job
	default:
		return "unknown"
	}
}

func safeTraceStage(stage string) string {
	switch stage {
	case "incoming request", "identity verification", "DPoP verification", "policy evaluation",
		"quota reservation", "route selection", "upstream attempt", "streaming observation",
		"quota settlement":
		return stage
	default:
		return "request stage"
	}
}
