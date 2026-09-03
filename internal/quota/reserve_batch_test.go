package quota

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestQueueDecisionStagesPreservesOrderAndProvenance(t *testing.T) {
	t.Parallel()
	input, err := prepareRequest(validReserveInput(t))
	if err != nil {
		t.Fatal(err)
	}
	request := requestHandleForPrepared(input)
	startedAt := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Second)
	rule := input.rules[0]
	stages := quotaDecisionStages(input, startedAt, completedAt,
		map[string]struct{}{rule.ruleKey: {}}, map[string]struct{}{rule.ruleKey: {}}, "quota_exceeded")
	if len(stages) != 2 {
		t.Fatalf("quota stages = %d, want 2", len(stages))
	}
	batch := &pgx.Batch{}
	batch.Queue("SELECT 1")
	if err := queueDecisionStages(batch, request, 7, stages); err != nil {
		t.Fatal(err)
	}
	if batch.Len() != 3 || batch.QueuedQueries[0].SQL != "SELECT 1" {
		t.Fatalf("queue did not preserve its existing prefix: %#v", batch)
	}
	for index, stage := range stages {
		want := []any{
			request.organizationID, request.applicationID, request.environmentID,
			request.logicalRequestID, int32(7 + index), stage.Stage, DecisionDenied,
			"quota_exceeded", request.configRevisionID,
			nullableString(stage.PolicyRuleKey), input.LimitPlanKey,
			nullableString(stage.LimitRuleKey), nullableString(stage.LimitMetric),
			nullableString(stage.LimitAlgorithm), nullableInt64(stage.LimitMaximum, stage.HasLimitMaximum),
			nullableString(stage.RouteKey), nullableString(stage.UpstreamKey),
			nullableString(stage.ModelKey), nullableString(stage.PhysicalModel), startedAt, completedAt,
		}
		if got := batch.QueuedQueries[index+1].Arguments; !reflect.DeepEqual(got, want) {
			t.Fatalf("stage %d arguments = %#v, want %#v", index, got, want)
		}
	}
	if stages[0].Stage != DecisionQuotaRuleEvaluated || stages[0].LimitRuleKey != rule.ruleKey ||
		stages[0].LimitMetric != rule.Metric || stages[0].LimitAlgorithm != rule.Algorithm ||
		stages[1].Stage != DecisionQuotaReserved || stages[1].PhysicalModel != input.PhysicalModel {
		t.Fatalf("quota provenance changed: %#v", stages)
	}
}

func TestQueueDecisionStagesRejectsOverflowWithoutMutatingBatch(t *testing.T) {
	t.Parallel()
	for _, next := range []int32{0, maximumDecisionStages} {
		batch := &pgx.Batch{}
		batch.Queue("SELECT 1")
		if err := queueDecisionStages(batch, AuthenticatedRequest{}, next, make([]DecisionStage, 2)); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("next %d = %v, want ErrInvalidState", next, err)
		}
		if batch.Len() != 1 {
			t.Fatalf("invalid stage range appended %d queries", batch.Len()-1)
		}
	}
	batch := &pgx.Batch{}
	if err := queueDecisionStages(batch, AuthenticatedRequest{}, 0, nil); err != nil || batch.Len() != 0 {
		t.Fatalf("empty stage queue = %d, %v", batch.Len(), err)
	}
}
