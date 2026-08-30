package quota

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/limitscope"
	"github.com/latchway/latchway/internal/protocol"
)

func TestPrepareRequestBindsBucketlessExactRequestMeasurementsAndSealedScopes(t *testing.T) {
	t.Parallel()

	input := requestMeasurementInput(t)
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RequestMeasurements == input.RequestMeasurements {
		t.Fatal("prepared request retained caller-owned measurement pointer")
	}
	units := make(map[string]int64, len(prepared.rules))
	for _, rule := range prepared.rules {
		units[rule.Metric] = rule.ReservedUnits
	}
	if units[RequestBytesMetric] != 321 || units[ImageUnitsMetric] != 2 ||
		units[ToolCallsMetric] != 3 {
		t.Fatalf("reserved measurement units = %#v", units)
	}
	for _, rule := range prepared.rules {
		if rule.stateful || rule.scopeType != "composite" ||
			!slices.Equal(rule.scopeDimensions, []string{
				"user", "platform", "normalized_claim:region",
			}) {
			t.Fatalf("prepared request-local rule = %+v", rule)
		}
	}
	plans, err := plannedBucketsAt(prepared, time.Now().UTC())
	if err != nil || len(plans) != 0 {
		t.Fatalf("per-request rules materialized durable buckets: plans=%+v err=%v", plans, err)
	}

	fingerprint := requestFingerprint(prepared)
	mutated := requestMeasurementInput(t)
	mutated.RequestMeasurements.RequestBytes++
	mutated.Rules[0].ReservedUnits++
	changed, err := prepareRequest(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if requestFingerprint(changed) == fingerprint {
		t.Fatal("request measurement was omitted from replay fingerprint")
	}
	input.RequestMeasurements.RequestBytes = 999
	input.NormalizedClaimDigests["region"] = "invalid"
	if prepared.RequestMeasurements.RequestBytes != 321 {
		t.Fatal("caller mutation reached prepared measurement")
	}
}

func TestPrepareRequestRejectsUntrustedOrInexactRequestMeasurements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ReserveInput)
	}{
		{name: "missing binding", mutate: func(input *ReserveInput) { input.RequestMeasurements = nil }},
		{name: "unit mismatch", mutate: func(input *ReserveInput) { input.Rules[1].ReservedUnits++ }},
		{name: "unknown image count", mutate: func(input *ReserveInput) {
			input.RequestMeasurements.ImageUnitsKnown = false
			input.RequestMeasurements.ImageUnits = 0
		}},
		{name: "unknown tool count", mutate: func(input *ReserveInput) {
			input.RequestMeasurements.ToolCallsKnown = false
			input.RequestMeasurements.ToolCalls = 0
		}},
		{name: "missing platform", mutate: func(input *ReserveInput) { input.Platform = "" }},
		{name: "raw claim value", mutate: func(input *ReserveInput) { input.NormalizedClaimDigests["region"] = "eu" }},
		{name: "missing claim identity", mutate: func(input *ReserveInput) { delete(input.NormalizedClaimDigests, "region") }},
		{name: "image count exceeds trusted bound", mutate: func(input *ReserveInput) {
			input.RequestMeasurements.ImageUnits = protocol.MaximumRequestStructuredUnits + 1
			input.Rules[1].ReservedUnits = input.RequestMeasurements.ImageUnits
		}},
		{name: "tool count exceeds trusted bound", mutate: func(input *ReserveInput) {
			input.RequestMeasurements.ToolCalls = protocol.MaximumRequestStructuredUnits + 1
			input.Rules[2].ReservedUnits = input.RequestMeasurements.ToolCalls
		}},
		{name: "limit plan duplicate scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = []string{"limit_plan"} }},
		{name: "opaque image", mutate: func(input *ReserveInput) {
			input.Protocol = "opaque_http"
			input.RequestMeasurements.Protocol = "opaque_http"
			input.RequestMeasurements.ImageUnitsKnown = false
			input.RequestMeasurements.ToolCallsKnown = false
			input.RequestMeasurements.ImageUnits = 0
			input.RequestMeasurements.ToolCalls = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := requestMeasurementInput(t)
			test.mutate(&input)
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("prepare request error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestRequestMeasurementPerRequestBoundsAreAtomicDecisionMetadata(t *testing.T) {
	t.Parallel()

	input := requestMeasurementInput(t)
	input.Rules[1].PerRequestMaximum = 1
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	exceeded := requestBoundExceededRules(prepared.rules)
	if len(exceeded) != 1 || exceeded[0].Metric != ImageUnitsMetric ||
		exceeded[0].ReservedUnits != 2 || exceeded[0].PerRequestMaximum != 1 {
		t.Fatalf("exceeded request-local rules = %+v", exceeded)
	}
}

func TestMissingNormalizedClaimHasStableNonBypassScopeIdentity(t *testing.T) {
	t.Parallel()

	present := requestMeasurementInput(t)
	presentPrepared, err := prepareRequest(present)
	if err != nil {
		t.Fatal(err)
	}
	missingDigest, ok := limitscope.ClaimDigest("region", nil, false)
	if !ok {
		t.Fatal("derive missing digest")
	}
	missing := requestMeasurementInput(t)
	missing.NormalizedClaimDigests["region"] = missingDigest
	missingPrepared, err := prepareRequest(missing)
	if err != nil {
		t.Fatal(err)
	}
	if presentPrepared.rules[0].scopeKey == missingPrepared.rules[0].scopeKey ||
		len(missingPrepared.rules[0].scopeKey) != 43 {
		t.Fatalf("present/missing scope keys = %q/%q", presentPrepared.rules[0].scopeKey, missingPrepared.rules[0].scopeKey)
	}
}

func requestMeasurementInput(t *testing.T) ReserveInput {
	t.Helper()
	input := validReserveInput(t)
	input.Protocol = "openai_chat"
	input.Platform = "react_native_ios"
	digest, ok := limitscope.ClaimDigest("region", "eu", true)
	if !ok {
		t.Fatal("derive claim digest")
	}
	input.NormalizedClaimDigests = map[string]string{"region": digest}
	bodyDigest := sha256.Sum256([]byte("exact rewritten body"))
	input.RequestMeasurements = &RequestMeasurementBinding{
		Protocol: "openai_chat", RewrittenBodySHA256: bodyDigest,
		RequestBytes: 321, ImageUnits: 2, ToolCalls: 3,
		ImageUnitsKnown: true, ToolCallsKnown: true,
	}
	input.Rules = []Rule{
		{Metric: RequestBytesMetric, Algorithm: PerRequestAlgorithm, Scope: []string{"normalized_claim:region", "user", "platform"}, PerRequestMaximum: 500, ReservedUnits: 321, Hard: true},
		{Metric: ImageUnitsMetric, Algorithm: PerRequestAlgorithm, Scope: []string{"platform", "normalized_claim:region", "user"}, PerRequestMaximum: 10, ReservedUnits: 2, Hard: true},
		{Metric: ToolCallsMetric, Algorithm: PerRequestAlgorithm, Scope: []string{"user", "normalized_claim:region", "platform"}, PerRequestMaximum: 10, ReservedUnits: 3, Hard: true},
	}
	return input
}
