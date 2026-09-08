package quota

import (
	"testing"

	"github.com/latchway/latchway/internal/protocol"
)

func TestInputAccountingBreakdownCopiesWithoutChangingFingerprint(t *testing.T) {
	input := validReserveInput(t)
	input.Rules = []Rule{{Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 1000, ReservedUnits: 400, Hard: true}}
	input.InputPreflight = trustedInputPreflight(input, 400, 16)
	legacy, err := prepareRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	input.InputPreflight.Breakdown = &protocol.InputAccountingBreakdown{Version: 1,
		RewrittenRequestBytes: 100, FramingUnitCount: 2, MaximumFramingTokensPerRequest: 16,
		MaximumFramingTokensPerUnit: 8, ExpandedSchemaBytes: 268}
	prepared, err := prepareRequest(input)
	if err != nil || requestFingerprint(prepared) != requestFingerprint(legacy) {
		t.Fatalf("diagnostics changed enforcement fingerprint: %v", err)
	}
	input.InputPreflight.Breakdown.ExpandedSchemaBytes++
	if prepared.InputPreflight.Breakdown.ExpandedSchemaBytes != 268 {
		t.Fatal("prepared proof retained caller-owned breakdown")
	}
	if _, err := prepareRequest(input); err == nil {
		t.Fatal("mismatched diagnostic bound was accepted")
	}
	if _, err := inputAccountingBreakdownJSON(input.InputPreflight); err == nil {
		t.Fatal("mismatched diagnostic bound was persisted")
	}
	if raw, err := inputAccountingBreakdownJSON(legacy.InputPreflight); err != nil || raw != nil {
		t.Fatal("legacy proof should persist SQL NULL diagnostics")
	}
}
