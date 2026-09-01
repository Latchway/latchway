package quota

import (
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

func TestPrepareAuthenticatedRequestAcceptsOnlyBoundedRedactionSafeAttribution(t *testing.T) {
	t.Parallel()
	reserve := validReserveInput(t)
	input := AuthenticatedRequestInput{
		LogicalRequestID: reserve.LogicalRequestID,
		OrganizationID:   reserve.OrganizationID, ApplicationID: reserve.ApplicationID,
		EnvironmentID: reserve.EnvironmentID, ApplicationUserID: reserve.ApplicationUserID,
		InstallationID: reserve.InstallationID, SessionGrantID: reserve.SessionGrantID,
		ConfigRevisionID: reserve.ConfigRevisionID, FeatureKey: reserve.FeatureKey,
		Protocol: reserve.Protocol, ClientRequestID: reserve.ClientRequestID,
	}
	prepared, err := prepareAuthenticatedRequest(input)
	if err != nil || prepared.FeatureKey != "assistant" {
		t.Fatalf("prepare authenticated request = %#v, %v", prepared, err)
	}

	for name, mutate := range map[string]func(*AuthenticatedRequestInput){
		"missing logical identity": func(value *AuthenticatedRequestInput) { value.LogicalRequestID = requestidentity.LogicalID{} },
		"unsafe feature":           func(value *AuthenticatedRequestInput) { value.FeatureKey = "assistant\npayload" },
		"unknown protocol":         func(value *AuthenticatedRequestInput) { value.Protocol = "provider_private" },
		"short client hint":        func(value *AuthenticatedRequestInput) { value.ClientRequestID = "short" },
		"partial component": func(value *AuthenticatedRequestInput) {
			value.InstallationFamilyID = id.Must(id.InstallationFamily)
		},
		"partial framework": func(value *AuthenticatedRequestInput) {
			value.Framework = "swift-openai"
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			invalid := input
			mutate(&invalid)
			if _, err := prepareAuthenticatedRequest(invalid); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("prepareAuthenticatedRequest accepted invalid input: %v", err)
			}
		})
	}
}

func TestPrepareDecisionStageEnforcesClosedProvenanceTuples(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	valid := DecisionStage{
		Stage: DecisionQuotaRuleEvaluated, Outcome: DecisionSucceeded,
		StartedAt: now, CompletedAt: now.Add(time.Millisecond),
		LimitPlanKey: "free",
		LimitRuleKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		LimitMetric:  LogicalRequestsMetric, LimitAlgorithm: CalendarAlgorithm,
		LimitMaximum: 10, HasLimitMaximum: true,
	}
	if _, err := prepareDecisionStage(valid); err != nil {
		t.Fatalf("prepare valid decision stage: %v", err)
	}

	for name, mutate := range map[string]func(*DecisionStage){
		"unknown stage":      func(value *DecisionStage) { value.Stage = "provider_decision" },
		"failure on success": func(value *DecisionStage) { value.FailureCode = "internal_error" },
		"missing failure":    func(value *DecisionStage) { value.Outcome = DecisionDenied },
		"unsafe failure": func(value *DecisionStage) {
			value.Outcome, value.FailureCode = DecisionFailed, "dependency secret"
		},
		"partial limit": func(value *DecisionStage) { value.LimitMetric = "" },
		"partial route": func(value *DecisionStage) { value.RouteKey = "primary" },
		"route on quota rule": func(value *DecisionStage) {
			value.RouteKey, value.UpstreamKey, value.ModelKey = "primary", "openai", "fast"
			value.PhysicalModel = "provider/model-v1"
		},
		"policy key on quota rule": func(value *DecisionStage) { value.PolicyRuleKey = "feature_access" },
		"reversed time":            func(value *DecisionStage) { value.CompletedAt = now.Add(-time.Second) },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			invalid := valid
			mutate(&invalid)
			if _, err := prepareDecisionStage(invalid); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("prepareDecisionStage accepted invalid provenance: %v", err)
			}
		})
	}
}

func TestPrepareDecisionStagesAllowsOnlyOneFinalTerminalStage(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	succeeded := DecisionStage{
		Stage: DecisionIdentityVerified, Outcome: DecisionSucceeded,
		StartedAt: now, CompletedAt: now.Add(time.Millisecond),
	}
	terminal := DecisionStage{
		Stage: DecisionClientContextValidated, Outcome: DecisionDenied,
		FailureCode: "request_invalid",
		StartedAt:   now.Add(time.Millisecond), CompletedAt: now.Add(2 * time.Millisecond),
	}

	prepared, err := prepareDecisionStages([]DecisionStage{succeeded, terminal}, true)
	if err != nil || len(prepared) != 2 || prepared[1].Outcome != DecisionDenied {
		t.Fatalf("prepare valid terminal batch = %#v, %v", prepared, err)
	}
	for name, stages := range map[string][]DecisionStage{
		"terminal before final stage":   {terminal, succeeded},
		"terminal in reservation batch": {succeeded, terminal},
	} {
		name, stages := name, stages
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			allowTerminal := name != "terminal in reservation batch"
			if _, err := prepareDecisionStages(stages, allowTerminal); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("prepareDecisionStages accepted invalid terminal placement: %v", err)
			}
		})
	}

	overflow := make([]DecisionStage, maximumDecisionStages+1)
	for index := range overflow {
		overflow[index] = succeeded
	}
	if _, err := prepareDecisionStages(overflow, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("prepareDecisionStages accepted %d stages: %v", len(overflow), err)
	}
}
