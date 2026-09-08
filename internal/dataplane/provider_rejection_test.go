package dataplane

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/upstream"
)

func TestProviderRejectionNeverOverridesObservedOrUncertainExecution(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*executionResult)
	}{
		{"client response started", func(r *executionResult) { r.relay.ClientStarted = true }},
		{"body accepted", func(r *executionResult) { r.relay.BodyBytes = 1 }},
		{"negative byte count", func(r *executionResult) { r.relay.BodyBytes = -1 }},
		{"first-byte hook ran", func(r *executionResult) { r.firstByteAt = time.Now() }},
		{"first-token hook ran", func(r *executionResult) { r.firstTokenAt = time.Now() }},
		{"client canceled", func(r *executionResult) { r.err = errors.Join(r.err, context.Canceled) }},
		{"execution timed out", func(r *executionResult) { r.err = errors.Join(r.err, upstream.ErrResponseIdleTimeout) }},
		{"provider reported usage", func(r *executionResult) {
			r.relay.Usage = protocol.Usage{Known: true, Provenance: quota.ProviderReportedProvenance, InputTokens: 2, OutputTokens: 3, TotalTokens: 5}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := executionResult{err: upstream.ErrUpstreamNonSuccess, relay: upstream.RelayOutcome{StatusCode: 400, RejectionConfirmed: true, ProviderError: upstream.ProviderErrorDiagnostics{Category: "invalid_request"}}}
			test.mutate(&result)
			result, outcome := calculateAttemptOutcome(preparedExecutionAttempt{appliedOutputMaximum: 8}, result)
			if outcome.Diagnostics != nil && outcome.Diagnostics.AccountingPolicy == quota.ProviderRejectionAccountingV1 ||
				outcome.FailureCode == "upstream_request_rejected" || errors.Is(result.err, errProviderRequestRejected) {
				t.Fatalf("contradiction conferred rejection policy: outcome=%#v err=%v", outcome, result.err)
			}
		})
	}
}

func TestProviderErrorTrustUsesProtectedOrigin(t *testing.T) {
	for _, tc := range []struct {
		url   string
		allow bool
	}{
		{"https://openrouter.ai/api/v1", true}, {"https://eu.openrouter.ai/api/v1/", true},
		{"https://us.openrouter.ai:443/api/v1", true}, {"https://openrouter.ai.attacker.test/api/v1", false},
		{"http://openrouter.ai/api/v1", false}, {"https://openrouter.ai:444/api/v1", false},
		{"https://user@openrouter.ai/api/v1", false}, {"https://openrouter.ai/api/v1?x=1", false},
		{"https://openrouter.ai/other", false}, {"https://example.com/api/v1", false},
	} {
		got := providerErrorMode(configuration.Upstream{Type: "openai_compatible", BaseURL: tc.url})
		if (got == upstream.ProviderErrorModeOpenRouter) != tc.allow {
			t.Fatalf("trust %s = %v", tc.url, got)
		}
	}
	if providerErrorMode(configuration.Upstream{Type: "generic", BaseURL: "https://openrouter.ai/api/v1"}) != upstream.ProviderErrorModeNone {
		t.Fatal("generic mode trusted")
	}
}

func TestProviderRejectionOutcomeRequiresEvidence(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		result := executionResult{err: upstream.ErrUpstreamNonSuccess, relay: upstream.RelayOutcome{
			StatusCode: 400, RejectionConfirmed: confirmed,
			ProviderError: upstream.ProviderErrorDiagnostics{Category: "invalid_request", Parameter: "tools[0].function.parameters"},
		}}
		result, outcome := calculateAttemptOutcome(preparedExecutionAttempt{}, result)
		if outcome.Diagnostics == nil {
			t.Fatal("diagnostics not retained")
		}
		if confirmed {
			if outcome.Diagnostics.AccountingPolicy != quota.ProviderRejectionAccountingV1 || outcome.FailureCode != "upstream_request_rejected" || outcome.Usage.Known || outcome.Cost.Known {
				t.Fatalf("rejection: %#v", outcome)
			}
			code, _ := errorCode(result.err, time.Now())
			if code != "request_invalid" {
				t.Fatalf("client code %s", code)
			}
		} else if outcome.Diagnostics.AccountingPolicy != "" || outcome.FailureCode != "upstream_non_success" {
			t.Fatalf("unconfirmed refund: %#v", outcome)
		}
	}
}

func TestFailedKnownUsageOptsIntoVersionedAccounting(t *testing.T) {
	result := executionResult{err: errors.New("fixture downstream failure"), relay: upstream.RelayOutcome{
		StatusCode: http.StatusOK, Usage: protocol.Usage{Known: true, Provenance: quota.ProviderReportedProvenance, InputTokens: 2, OutputTokens: 3, TotalTokens: 5},
	}}
	_, outcome := calculateAttemptOutcome(preparedExecutionAttempt{appliedOutputMaximum: 8}, result)
	if outcome.Diagnostics == nil || outcome.Diagnostics.AccountingPolicy != quota.ReportedUsageAccountingV1 || !outcome.Usage.Known {
		t.Fatalf("outcome %#v", outcome)
	}
}
