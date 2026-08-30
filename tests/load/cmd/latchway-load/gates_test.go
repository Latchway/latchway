package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestStableProblemCodeAcceptsOnlyBoundedStableCodes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "problem", status: http.StatusTooManyRequests, body: `{"code":"quota_exceeded","detail":"redacted"}`, want: "quota_exceeded"},
		{name: "success body is not a problem", status: http.StatusOK, body: `{"code":"must_not_count"}`},
		{name: "nested provider code", status: http.StatusBadGateway, body: `{"error":{"code":"provider_secret"}}`},
		{name: "invalid code characters", status: http.StatusBadRequest, body: `{"code":"Unsafe/Code"}`},
		{name: "invalid JSON", status: http.StatusBadRequest, body: `{`},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := stableProblemCode(test.status, []byte(test.body)); got != test.want {
				t.Fatalf("stableProblemCode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResultEvidenceContainsCountsButNeverResponseBodies(t *testing.T) {
	t.Parallel()
	const secretMarker = "prompt-and-token-must-not-enter-evidence"
	evidence := newResultEvidence()
	evidence.observe(requestResult{
		Status: http.StatusTooManyRequests, Body: []byte(secretMarker),
		ProblemCode: "quota_exceeded",
	})
	evidence.observe(requestResult{Status: http.StatusServiceUnavailable, Body: []byte(secretMarker)})
	evidence.observe(requestResult{Err: errors.New("bounded transport failure"), Body: []byte(secretMarker)})
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(secretMarker)) ||
		evidence.Statuses[http.StatusTooManyRequests] != 1 ||
		evidence.ProblemCodes["quota_exceeded"] != 1 ||
		evidence.InvalidProblemResponses != 1 || evidence.RequestErrors != 1 {
		t.Fatalf("unsafe or incorrect result evidence: %s", encoded)
	}
	rawResult, err := json.Marshal(requestResult{Status: http.StatusBadRequest, Body: []byte(secretMarker)})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawResult, []byte(secretMarker)) || bytes.Contains(rawResult, []byte(`"Body"`)) {
		t.Fatalf("requestResult JSON exposed response body: %s", rawResult)
	}
}

func TestExactTerminalQuotaCheckRequiresFeatureAndEveryCounter(t *testing.T) {
	t.Parallel()
	maximum, used, reserved, remaining := int64(10), int64(7), int64(0), int64(3)
	snapshot := quotaSnapshot{
		Feature: "load",
		Limits: []quotaLimit{{
			Metric: "logical_requests", Maximum: &maximum, Used: &used,
			Reserved: &reserved, Remaining: &remaining, Hard: true,
		}},
	}
	expected := []quotaLimitExpectation{{
		Metric: "logical_requests", Maximum: 10, Used: 7,
		Reserved: 0, Remaining: 3, Hard: true,
	}}
	check, err := exactTerminalQuotaCheck(snapshot, "load", expected)
	if err != nil || !check.Exact || check.ExpectedFeature != "load" || check.ObservedFeature != "load" {
		t.Fatalf("exactTerminalQuotaCheck() check=%+v error=%v", check, err)
	}

	wrongFeature := snapshot
	wrongFeature.Feature = "other"
	if _, err := exactTerminalQuotaCheck(wrongFeature, "load", expected); err == nil {
		t.Fatal("mismatched feature passed exact terminal check")
	}
	wrongRemaining := snapshot
	wrong := int64(2)
	wrongRemaining.Limits = append([]quotaLimit(nil), snapshot.Limits...)
	wrongRemaining.Limits[0].Remaining = &wrong
	if _, err := exactTerminalQuotaCheck(wrongRemaining, "load", expected); err == nil {
		t.Fatal("mismatched remaining units passed exact terminal check")
	}
}

func TestExactContentionTransitionIncludesWindowAndZeroReservations(t *testing.T) {
	t.Parallel()
	reset := time.Date(2026, time.August, 30, 0, 0, 0, 0, time.UTC)
	maximum, beforeUsed, beforeReserved, beforeRemaining := int64(64), int64(0), int64(0), int64(64)
	afterUsed, afterReserved, afterRemaining := int64(64), int64(0), int64(0)
	before := quotaLimit{
		Metric: "logical_requests", Maximum: &maximum, Used: &beforeUsed,
		Reserved: &beforeReserved, Remaining: &beforeRemaining, ResetsAt: &reset, Hard: true,
	}
	after := quotaLimit{
		Metric: "logical_requests", Maximum: &maximum, Used: &afterUsed,
		Reserved: &afterReserved, Remaining: &afterRemaining, ResetsAt: &reset, Hard: true,
	}
	if err := validateExactContentionTransition(before, after, 64); err != nil {
		t.Fatalf("valid contention transition rejected: %v", err)
	}
	afterReserved = 1
	if err := validateExactContentionTransition(before, after, 64); err == nil {
		t.Fatal("retained contention reservation passed exact transition check")
	}
}
