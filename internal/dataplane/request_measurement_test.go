package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/session"
)

func TestDecisionAndProtocolCapabilityAdmitOnlyExactRequestMetrics(t *testing.T) {
	t.Parallel()

	for _, metric := range []string{
		quota.RequestBytesMetric, quota.ImageUnitsMetric, quota.ToolCallsMetric,
	} {
		limit := configuration.Limit{
			Metric: metric, Algorithm: quota.PerRequestAlgorithm,
			Scope:             []string{"user", "platform", "normalized_claim:region"},
			PerRequestMaximum: 10, Hard: true,
		}
		if !supportedDecisionLimit(limit) {
			t.Fatalf("valid %s per-request rule rejected", metric)
		}
		limit.Algorithm = quota.CalendarAlgorithm
		limit.Window = "1d"
		limit.Maximum = 10
		limit.PerRequestMaximum = 0
		if supportedDecisionLimit(limit) {
			t.Fatalf("stateful %s rule accepted", metric)
		}
	}
	for _, protocolID := range []string{
		protocol.OpenAIResponsesID, protocol.OpenAIChatID,
		protocol.OpenAIEmbeddingsID, protocol.AnthropicMessagesID,
	} {
		for _, metric := range []string{quota.RequestBytesMetric, quota.ImageUnitsMetric, quota.ToolCallsMetric} {
			if !protocolSupportsLimitMetric(protocolID, metric) {
				t.Fatalf("%s unexpectedly rejects %s", protocolID, metric)
			}
		}
	}
	if !protocolSupportsLimitMetric(protocol.OpaqueHTTPID, quota.RequestBytesMetric) ||
		protocolSupportsLimitMetric(protocol.OpaqueHTTPID, quota.ImageUnitsMetric) ||
		protocolSupportsLimitMetric(protocol.OpaqueHTTPID, quota.ToolCallsMetric) {
		t.Fatal("opaque protocol did not fail closed for structured request metrics")
	}
}

func TestMeasuredBodyOwnershipAndDispatchBoundaryRejectSameLengthMutation(t *testing.T) {
	t.Parallel()

	original := []byte(`{"model":"physical","input":"hello"}`)
	measurement := protocol.RequestMeasurements{
		Protocol:            protocol.OpenAIResponsesID,
		RewrittenBodySHA256: sha256.Sum256(original), RequestBytes: int64(len(original)),
		ImageUnitsKnown: true, ToolCallsKnown: true,
	}
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/responses", bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAndRebindMeasuredBody(request, measurement); err != nil {
		t.Fatalf("bind measured body: %v", err)
	}
	for index := range original {
		original[index] = 'x'
	}
	rebound, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	reboundBytes, readErr := io.ReadAll(rebound)
	closeErr := rebound.Close()
	if readErr != nil || closeErr != nil || sha256.Sum256(reboundBytes) != measurement.RewrittenBodySHA256 {
		t.Fatalf("owned measured body changed: read=%v close=%v body=%q", readErr, closeErr, reboundBytes)
	}

	tampered := append([]byte(nil), reboundBytes...)
	tampered[len(tampered)-3] ^= 1
	request.Body = io.NopCloser(bytes.NewReader(tampered))
	request.ContentLength = int64(len(tampered))
	beginCalled := false
	decision := testDecision()
	decision.Feature.Protocol = protocol.OpenAIResponsesID
	result := (&Handler{}).executeAttempt(
		context.Background(), httptest.NewRecorder(), request,
		endpointMatch{protocolID: protocol.OpenAIResponsesID}, session.Authorization{}, decision,
		nil, &measurement,
		func(context.Context) (quota.Attempt, bool, error) {
			beginCalled = true
			return quota.Attempt{}, false, nil
		},
	)
	if beginCalled || !errors.Is(result.err, policy.ErrConfiguration) {
		t.Fatalf("same-length mutation result=%v beginCalled=%t", result.err, beginCalled)
	}
}

func TestAssignRequestMeasurementUnitsIsExactAndBucketless(t *testing.T) {
	t.Parallel()

	rules := []quota.Rule{
		{Metric: quota.RequestBytesMetric, Algorithm: quota.PerRequestAlgorithm, PerRequestMaximum: 100},
		{Metric: quota.ImageUnitsMetric, Algorithm: quota.PerRequestAlgorithm, PerRequestMaximum: 5},
		{Metric: quota.ToolCallsMetric, Algorithm: quota.PerRequestAlgorithm, PerRequestMaximum: 5},
	}
	measurement := &protocol.RequestMeasurements{
		RequestBytes: 90, ImageUnits: 2, ToolCalls: 3,
		ImageUnitsKnown: true, ToolCallsKnown: true,
	}
	if err := assignRequestMeasurementUnits(rules, measurement); err != nil {
		t.Fatal(err)
	}
	for index, want := range []int64{90, 2, 3} {
		units, applicable := quota.ProjectedReservationUnits(rules[index], false)
		if units != want || !applicable || rules[index].ReservedUnits != want {
			t.Fatalf("rule %d projection = %d/%t rule=%+v", index, units, applicable, rules[index])
		}
	}
	unknown := *measurement
	unknown.ImageUnitsKnown = false
	unknown.ImageUnits = 0
	if err := assignRequestMeasurementUnits(rules, &unknown); !errors.Is(err, policy.ErrConfiguration) {
		t.Fatalf("unknown image measurement error = %v", err)
	}
}

func TestValidateRequestMeasurementsRejectsValuesAboveTrustedBounds(t *testing.T) {
	t.Parallel()

	decision := testDecision()
	decision.Feature.Protocol = protocol.OpenAIChatID
	measurement := protocol.RequestMeasurements{
		Protocol:            protocol.OpenAIChatID,
		RewrittenBodySHA256: sha256.Sum256([]byte("bounded body")),
		RequestBytes:        int64(len("bounded body")),
		ImageUnitsKnown:     true,
		ToolCallsKnown:      true,
	}
	for name, mutate := range map[string]func(*protocol.RequestMeasurements){
		"request bytes": func(value *protocol.RequestMeasurements) {
			value.RequestBytes = protocol.MaximumMeasuredRequestBytes + 1
		},
		"image units": func(value *protocol.RequestMeasurements) {
			value.ImageUnits = protocol.MaximumRequestStructuredUnits + 1
		},
		"tool calls": func(value *protocol.RequestMeasurements) {
			value.ToolCalls = protocol.MaximumRequestStructuredUnits + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := measurement
			mutate(&candidate)
			if err := validateRequestMeasurements(decision, nil, candidate); !errors.Is(err, policy.ErrConfiguration) {
				t.Fatalf("validation error = %v, want policy configuration error", err)
			}
		})
	}
}
