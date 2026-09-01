package adminapi

import (
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestPublicAttemptFailureCodeUsesClosedVocabulary(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"client_cancelled":        "canceled",
		"request_cancelled":       "canceled",
		"pricing_unavailable":     "gateway_error",
		"quota_state_unavailable": "gateway_error",
		"configuration_invalid":   "gateway_error",
		"upstream_protocol_error": "protocol_error",
		"upstream_timeout":        "timeout",
		"upstream_timed_out":      "timeout",
		"upstream_unavailable":    "unavailable",
		"upstream_non_success":    "upstream_rejected",
		"provider body: secret":   "unknown",
		"":                        "unknown",
	}
	allowed := map[string]bool{
		"canceled": true, "gateway_error": true, "protocol_error": true,
		"timeout": true, "unavailable": true, "upstream_rejected": true, "unknown": true,
	}
	for stored, want := range tests {
		stored, want := stored, want
		t.Run(stored, func(t *testing.T) {
			t.Parallel()
			got := publicAttemptFailureCode(stored)
			if got != want || !allowed[got] {
				t.Fatalf("publicAttemptFailureCode(%q)=%q, want %q in closed vocabulary", stored, got, want)
			}
		})
	}
}

func TestPublicLogicalDecisionFailureCodeUsesRegisteredOrClosedValues(t *testing.T) {
	t.Parallel()
	for stored, want := range map[string]string{
		"quota_exceeded":       "quota_exceeded",
		"request_cancelled":    "canceled",
		"provider_secret_hint": "unknown",
	} {
		stored, want := stored, want
		t.Run(stored, func(t *testing.T) {
			t.Parallel()
			got := publicDecisionFailureCode(&stored)
			if got == nil || *got != want {
				t.Fatalf("publicDecisionFailureCode(%q)=%v, want %q", stored, got, want)
			}
		})
	}
	if publicDecisionFailureCode(nil) != nil {
		t.Fatal("nil decision failure became present")
	}
}

func TestValidateRequestDecisionStageAcceptsOnlyClosedStageProvenance(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	request := logicalRequestDocument{
		ConfigRevisionID: id.Must(id.ConfigRevision), SelectedLimitPlan: "legacy_unknown",
	}
	failureCode := "internal_error"
	valid := requestDecisionStageDocument{
		Number: 1, Stage: "lifecycle_recovered", Outcome: "failed",
		ConfigRevisionID: request.ConfigRevisionID, StartedAt: now, CompletedAt: now,
	}
	if err := validateRequestDecisionStage(valid, &failureCode, request, 1); err != nil {
		t.Fatalf("valid recovery stage: %v", err)
	}
	invalid := valid
	invalid.Stage = "dependency_private_stage"
	if err := validateRequestDecisionStage(invalid, &failureCode, request, 1); !errors.Is(err, errOperationalCorrupt) {
		t.Fatalf("unknown decision stage validation=%v", err)
	}
	invalid = valid
	route := "primary"
	invalid.Route = &route
	if err := validateRequestDecisionStage(invalid, &failureCode, request, 1); !errors.Is(err, errOperationalCorrupt) {
		t.Fatalf("partial recovery route validation=%v", err)
	}
}

func TestValidateUpstreamAttemptRejectsCorruptLifecycle(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	firstByte := started.Add(time.Second)
	completed := started.Add(2 * time.Second)
	status := int32(200)
	valid := upstreamAttemptDocument{
		ID: id.Must(id.UpstreamAttempt), AttemptNumber: 1, Route: "primary",
		Upstream: "openai", Model: "gpt-test", StartedAt: started,
		FirstByteAt: &firstByte, CompletedAt: &completed, HTTPStatus: &status,
	}
	if err := validateUpstreamAttempt(valid, "succeeded", nil, 1); err != nil {
		t.Fatalf("valid attempt: %v", err)
	}
	failure := "upstream_timeout"
	failedStatus := int32(504)
	validFailure := valid
	validFailure.FirstByteAt = nil
	validFailure.HTTPStatus = &failedStatus
	if err := validateUpstreamAttempt(validFailure, "timed_out", &failure, 1); err != nil {
		t.Fatalf("valid failed attempt: %v", err)
	}

	tests := map[string]func(*upstreamAttemptDocument) (string, *string, int32){
		"number gap": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			attempt.AttemptNumber = 2
			return "succeeded", nil, 1
		},
		"number overflow": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			attempt.AttemptNumber = 33
			return "succeeded", nil, 33
		},
		"noncanonical route": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			attempt.Route = "Invalid Route"
			return "succeeded", nil, 1
		},
		"first byte before start": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			value := attempt.StartedAt.Add(-time.Nanosecond)
			attempt.FirstByteAt = &value
			return "succeeded", nil, 1
		},
		"first byte after completion": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			value := attempt.CompletedAt.Add(time.Nanosecond)
			attempt.FirstByteAt = &value
			return "succeeded", nil, 1
		},
		"started with terminal fields": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			return "started", nil, 1
		},
		"success without HTTP status": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			attempt.HTTPStatus = nil
			return "succeeded", nil, 1
		},
		"success with failure": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			return "succeeded", &failure, 1
		},
		"failure without code": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			return "failed", nil, 1
		},
		"terminal without completion": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			attempt.CompletedAt = nil
			return "failed", &failure, 1
		},
		"unknown stored status": func(attempt *upstreamAttemptDocument) (string, *string, int32) {
			return "mystery", nil, 1
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			attempt := valid
			storedStatus, failureCode, expected := mutate(&attempt)
			if err := validateUpstreamAttempt(attempt, storedStatus, failureCode, expected); !errors.Is(err, errOperationalCorrupt) {
				t.Fatalf("validation=%v, want errOperationalCorrupt", err)
			}
		})
	}
}
