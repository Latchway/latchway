package quota

import (
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestStorePostgreSQLInputAccountingBreakdownPersistsInitialAndRetry(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	input := fixture.calendarTokenInput(t, "input-breakdown",
		calendarTokenReservation{metric: InputTokensMetric, maximum: 10000, reserved: 400},
		calendarTokenReservation{metric: OutputTokensMetric, maximum: 10000, reserved: 16},
		calendarTokenReservation{metric: TotalTokensMetric, maximum: 10000, reserved: 416})
	input.InputPreflight.Breakdown = &protocol.InputAccountingBreakdown{Version: 1,
		RewrittenRequestBytes: 100, FramingUnitCount: 2, MaximumFramingTokensPerRequest: 16,
		MaximumFramingTokensPerUnit: 8, ExpandedSchemaBytes: 268}
	_, first := reserveAndBeginTokenAttempt(t, fixture, input)
	assertStored := func(attemptID string, bound int64, expected protocol.InputAccountingBreakdown) {
		t.Helper()
		var raw []byte
		if err := fixture.pool.QueryRow(fixture.ctx, `SELECT input_accounting_breakdown FROM upstream_attempts WHERE upstream_attempt_id=$1`, attemptID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		value, err := protocol.DecodeInputAccountingBreakdown(raw, bound, input.Protocol)
		if err != nil || value == nil || *value != expected {
			t.Fatalf("stored accounting components differ: %+v %v", value, err)
		}
	}
	assertStored(first.ID(), 400, *input.InputPreflight.Breakdown)
	if err := fixture.store.SettleForRetry(fixture.ctx, first, Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}); err != nil {
		t.Fatal(err)
	}
	retry := RetryAttemptInput{RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2", PhysicalModel: "provider/model-v2",
		Allocations: []AttemptAllocation{{Metric: InputTokensMetric, Units: 450}, {Metric: OutputTokensMetric, Units: 8}, {Metric: TotalTokensMetric, Units: 458}}}
	proofInput := input
	proofInput.PhysicalModel = retry.PhysicalModel
	retry.InputPreflight = trustedInputPreflight(proofInput, 450, 8)
	breakdown := *input.InputPreflight.Breakdown
	breakdown.ExpandedSchemaBytes += 50
	retry.InputPreflight.Breakdown = &breakdown
	second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retry)
	if err != nil || !owner {
		t.Fatalf("begin retry: owner=%t %v", owner, err)
	}
	assertStored(second.ID(), 450, breakdown)
	if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}); err != nil {
		t.Fatal(err)
	}
	assertStored(second.ID(), 450, breakdown)
}
