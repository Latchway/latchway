package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/upstream"
)

func diagnosticRequestFixtureCLI() logicalRequestCLI {
	return logicalRequestCLI{
		ID: "req_00000000000000000000000000", EnvironmentID: controlTestEnvironment,
		UserID: "usr_00000000000000000000000000", InstallationID: "ins_00000000000000000000000000",
		ConfigRevisionID: controlTestRevision, SelectedLimitPlan: "paid", Feature: "assistant", Protocol: "openai_chat",
		Status: "denied", StartedAt: "2026-08-29T00:00:00Z", CompletedAt: "2026-08-29T00:00:03Z",
	}
}

func diagnosticStagesCLI() []requestDecisionStageCLI {
	stages := []requestDecisionStageCLI{
		{Stage: "quota_rule_evaluated", Outcome: "denied", FailureCode: "quota_exceeded"},
		{Stage: "quota_rule_evaluated", Outcome: "succeeded"},
		{Stage: "quota_rule_evaluated", Outcome: "denied", FailureCode: "quota_exceeded"},
		{Stage: "quota_reserved", Outcome: "denied", FailureCode: "quota_exceeded"},
	}
	for i := range stages {
		stages[i].Number = int32(i + 1)
		stages[i].ConfigRevisionID = controlTestRevision
		stages[i].StartedAt = "2026-08-29T00:00:00Z"
		stages[i].CompletedAt = stages[i].StartedAt
	}
	return stages
}

func TestCLIQuotaDenialBatchSequenceMatchesRequestAndEffectiveViews(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func([]requestDecisionStageCLI) []requestDecisionStageCLI
		valid  bool
	}{
		{"denied rules followed by aggregate", func(s []requestDecisionStageCLI) []requestDecisionStageCLI { return s }, true},
		{"incomplete denied batch", func(s []requestDecisionStageCLI) []requestDecisionStageCLI { return s[:3] }, false},
		{"mismatched rule denial", func(s []requestDecisionStageCLI) []requestDecisionStageCLI {
			s[2].FailureCode = "different_code"
			return s
		}, false},
		{"mismatched aggregate denial", func(s []requestDecisionStageCLI) []requestDecisionStageCLI {
			s[3].FailureCode = "different_code"
			return s
		}, false},
		{"unrelated stage after rule denial", func(s []requestDecisionStageCLI) []requestDecisionStageCLI { s[1].Stage = "route_selected"; return s }, false},
		{"success aggregate after rule denial", func(s []requestDecisionStageCLI) []requestDecisionStageCLI {
			s[3].Outcome = "succeeded"
			s[3].FailureCode = ""
			return s
		}, false},
		{"failed rule after rule denial", func(s []requestDecisionStageCLI) []requestDecisionStageCLI { s[2].Outcome = "failed"; return s }, false},
		{"continuation after aggregate", func(s []requestDecisionStageCLI) []requestDecisionStageCLI {
			s = append(s, s[1])
			s[4].Number = 5
			return s
		}, false},
		{"non quota terminal remains terminal", func(s []requestDecisionStageCLI) []requestDecisionStageCLI { s[0].Stage = "policy_evaluated"; return s }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := diagnosticRequestFixtureCLI()
			request.DecisionStages = test.mutate(diagnosticStagesCLI())
			if validLogicalRequestCLI(request) != test.valid {
				t.Fatal("logical request timeline validation mismatch")
			}
			effective := effectiveConfigurationCLI{
				Subject: effectiveSubjectCLI{Kind: "request", ID: request.ID, UserID: request.UserID}, EvaluationMode: "recorded_request",
				EnvironmentID: request.EnvironmentID, EnvironmentKind: "production", RevisionID: request.ConfigRevisionID,
				Feature: request.Feature, Protocol: request.Protocol, RequestStatus: "denied", PolicyOutcome: "denied",
				LimitPlan: "paid", LimitPlanSource: "recorded_configuration", DecisionStages: request.DecisionStages,
			}
			if validEffectiveConfigurationCLI(effective) != test.valid {
				t.Fatal("effective request timeline validation mismatch")
			}
		})
	}
}

const diagnosticUsageJSONCLI = `{"logical_requests":1,"input_tokens":100,"output_tokens":0,"total_tokens":100,"cost_nano_usd":0,"details":{
"input_tokens":{"recorded_units":100,"reported_units":100,"unknown_units":null,"provenance":["upstream_reported"]},
"output_tokens":{"recorded_units":0,"reported_units":0,"unknown_units":null,"provenance":["upstream_reported"]},
"total_tokens":{"recorded_units":100,"reported_units":100,"unknown_units":null,"provenance":["upstream_reported"]},
"cost_nano_usd":{"recorded_units":0,"reported_units":null,"unknown_units":0,"provenance":["unknown"]}}}`

const diagnosticBreakdownJSONCLI = `{"version":1,"rewritten_request_bytes":100,"framing_unit_count":2,"maximum_framing_tokens_per_request":8,"maximum_framing_tokens_per_unit":4,"expanded_schema_bytes":0}`

func TestCLIRequestDiagnosticsStrictDecodeAndRender(t *testing.T) {
	t.Parallel()
	request := diagnosticRequestFixtureCLI()
	request.Status = "failed"
	data, _ := json.Marshal(request)
	body := strings.TrimSuffix(string(data), "}") + `,"usage":` + diagnosticUsageJSONCLI + `,"attempts":[{
"id":"atm_00000000000000000000000000","attempt_number":1,"route":"primary","upstream":"openrouter","model":"openai/gpt",
"started_at":"2026-08-29T00:00:00Z","completed_at":"2026-08-29T00:00:02Z","status":"failed","http_status":400,"failure_code":"upstream_rejected",
"usage_provenance":"upstream_reported","cost_provenance":"unknown","accounting_policy":"reported_usage_v1",
"provider_error":{"category":"invalid_request","parameter":"max_output_tokens","provider_code":"unsupported_parameter","generation_id":"gen-abcdefgh12345678"},
"input_accounting_breakdown":` + diagnosticBreakdownJSONCLI + `,"usage":` + diagnosticUsageJSONCLI + `}]}`
	// The fixture's existing nil attempts must not create duplicate keys.
	body = strings.Replace(body, `"attempts":null,`, "", 1)
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&request); err != nil {
		t.Fatal(err)
	}
	if !validLogicalRequestCLI(request) {
		t.Fatal("safe request diagnostics rejected")
	}
	var output bytes.Buffer
	if err := printRequest(&options{stdout: &output, stderr: io.Discard}, request); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"invalid_request", "max_output_tokens", "gen-abcdefgh12345678", "reported_usage_v1", "INPUT BOUND", "116", "REPORTED", "UNKNOWN CHARGE", "not recorded"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("text diagnostics missing %s", want)
		}
	}
	output.Reset()
	if err := printRequest(&options{output: "json", stdout: &output, stderr: io.Discard}, request); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"reported_units": 0`, `"reported_units": null`, `"unknown_units": 0`, `"expanded_schema_bytes": 0`, `"category": "invalid_request"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("JSON diagnostics lost distinction: %s", want)
		}
	}
}

func TestCLIUsageDetailsRejectMalformedShapesAndInconsistentProvenance(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		old         string
		replacement string
	}{
		{"missing nullable", `"reported_units":100,`, ""},
		{"unknown key", `"unknown_units":null`, `"unknown_units":null,"prompt":"SECRET"`},
		{"string units", `"recorded_units":100`, `"recorded_units":"100"`},
		{"negative units", `"reported_units":100`, `"reported_units":-1`},
		{"unknown provenance", `"upstream_reported"`, `"SECRET"`},
		{"missing provenance", `["upstream_reported"]`, `[]`},
		{"null provenance", `["upstream_reported"]`, `null`},
		{"overlapping sums", `"unknown_units":null,"provenance":["upstream_reported"]`, `"unknown_units":1,"provenance":["upstream_reported","unknown"]`},
		{"recorded mismatch", `"recorded_units":100`, `"recorded_units":101`},
		{"wrong observed source", `"upstream_reported"`, `"estimated"`},
		{"duplicate key", `"recorded_units":100`, `"recorded_units":100,"recorded_units":100`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var usage usageValuesCLI
			err := json.Unmarshal([]byte(strings.Replace(diagnosticUsageJSONCLI, test.old, test.replacement, 1)), &usage)
			if err == nil && validUsageValuesCLI(usage) {
				t.Fatal("unsafe usage details accepted")
			}
		})
	}
	var legacy usageValuesCLI
	if err := json.Unmarshal([]byte(`{"logical_requests":0,"input_tokens":0,"output_tokens":0,"total_tokens":0,"cost_nano_usd":0}`), &legacy); err != nil || !validUsageValuesCLI(legacy) {
		t.Fatal("historical usage rejected")
	}
}

func TestCLIInputBreakdownRejectsMissingMembersAndUnsafeValues(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		strings.Replace(diagnosticBreakdownJSONCLI, `,"expanded_schema_bytes":0`, "", 1),
		strings.Replace(diagnosticBreakdownJSONCLI, `"version":1`, `"version":2`, 1),
		strings.Replace(diagnosticBreakdownJSONCLI, `"framing_unit_count":2`, `"framing_unit_count":0`, 1),
		strings.Replace(diagnosticBreakdownJSONCLI, `"rewritten_request_bytes":100`, `"rewritten_request_bytes":9223372036854775807`, 1),
		strings.Replace(diagnosticBreakdownJSONCLI, `"version":1`, `"version":1,"prompt":"SECRET"`, 1),
	} {
		var breakdown inputAccountingBreakdownCLI
		if json.Unmarshal([]byte(body), &breakdown) == nil {
			t.Fatalf("unsafe breakdown accepted: %s", body)
		}
	}
}

func TestCLIAttemptRejectionPolicyRequiresSafeEvidence(t *testing.T) {
	t.Parallel()
	base := upstreamAttemptCLI{Status: "failed", HTTPStatus: 400, FailureCode: "upstream_rejected", AccountingPolicy: "provider_rejection_v1",
		ProviderError: &upstream.ProviderErrorDiagnostics{Category: "invalid_request"}}
	if !validAttemptDiagnosticsCLI(base) {
		t.Fatal("valid rejection diagnostic policy rejected")
	}
	for _, mutate := range []func(*upstreamAttemptCLI){
		func(v *upstreamAttemptCLI) { v.HTTPStatus = 500 }, func(v *upstreamAttemptCLI) { v.Status = "succeeded" },
		func(v *upstreamAttemptCLI) { v.ProviderError = nil }, func(v *upstreamAttemptCLI) { v.FirstByteAt = "2026-08-29T00:00:01Z" },
		func(v *upstreamAttemptCLI) { v.AccountingPolicy = "unsafe_policy" },
		func(v *upstreamAttemptCLI) { v.ProviderError = &upstream.ProviderErrorDiagnostics{Category: "timeout"} },
		func(v *upstreamAttemptCLI) {
			v.ProviderError = &upstream.ProviderErrorDiagnostics{Category: "invalid_request", Parameter: "SECRET"}
		},
	} {
		candidate := base
		mutate(&candidate)
		if validAttemptDiagnosticsCLI(candidate) {
			t.Fatalf("unsafe rejection evidence accepted: %#v", candidate)
		}
	}
}
