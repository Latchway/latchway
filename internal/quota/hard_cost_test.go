package quota

import (
	"errors"
	"testing"
	"time"
)

func TestPrepareRequestHardCostCalendarRules(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Pricing = PricingSelection{CatalogID: "standard-usd", Currency: USDCurrency}
	input.Rules = []Rule{
		{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: 1_000, ReservedUnits: 25, Hard: true,
		},
		{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"organization"}, Window: "1mo",
			Maximum: 5_000, ReservedUnits: 25, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare hard cost rules: %v", err)
	}
	if len(prepared.rules) != 2 {
		t.Fatalf("prepared hard cost rules = %d, want 2", len(prepared.rules))
	}
	for _, rule := range prepared.rules {
		if !rule.stateful || rule.Metric != CostNanoUSDMetric ||
			rule.Algorithm != CalendarAlgorithm || rule.ReservedUnits != 25 {
			t.Fatalf("prepared hard cost rule = %#v", rule)
		}
	}

	reordered := cloneReserveInput(input)
	reordered.Rules[0], reordered.Rules[1] = reordered.Rules[1], reordered.Rules[0]
	reorderedPrepared, err := prepareRequest(reordered)
	if err != nil || requestFingerprint(reorderedPrepared) != requestFingerprint(prepared) {
		t.Fatalf("reordered hard cost fingerprint changed: %v", err)
	}
	changed := cloneReserveInput(input)
	changed.Rules[0].ReservedUnits++
	changed.Rules[1].ReservedUnits++
	changedPrepared, err := prepareRequest(changed)
	if err != nil {
		t.Fatalf("prepare changed hard cost reservation: %v", err)
	}
	if requestFingerprint(changedPrepared) == requestFingerprint(prepared) {
		t.Fatal("hard cost reservation is not fingerprint-bound")
	}

	free := cloneReserveInput(input)
	for index := range free.Rules {
		free.Rules[index].ReservedUnits = 0
	}
	if _, err := prepareRequest(free); err != nil {
		t.Fatalf("prepare free hard cost reservation: %v", err)
	}

	unsafe := []ReserveInput{
		func() ReserveInput {
			value := cloneReserveInput(input)
			value.Pricing = PricingSelection{}
			return value
		}(),
		func() ReserveInput {
			value := cloneReserveInput(input)
			value.Rules[1].ReservedUnits++
			return value
		}(),
		func() ReserveInput {
			value := cloneReserveInput(input)
			value.Rules[0].ReservedUnits = -1
			return value
		}(),
		func() ReserveInput {
			value := cloneReserveInput(input)
			value.Rules[0].Algorithm = TokenBucketAlgorithm
			value.Rules[0].Window = ""
			value.Rules[0].Maximum = 0
			value.Rules[0].Capacity = 1_000
			value.Rules[0].RefillNumerator = 1
			value.Rules[0].RefillDenominator = 1
			return value
		}(),
	}
	for _, value := range unsafe {
		if _, err := prepareRequest(value); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unsafe hard cost input returned %v", err)
		}
	}
}

func TestHardCostReservationIdempotencyKeyBindsPricingCatalog(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Pricing = PricingSelection{CatalogID: "standard-usd", Currency: USDCurrency}
	input.Rules = []Rule{{
		Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user", "feature"}, Window: "1d",
		Maximum: 100, ReservedUnits: 25, Hard: true,
	}}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare priced reservation binding: %v", err)
	}
	fingerprint := requestFingerprint(prepared)
	pricing := pricingForRequest(prepared)
	bound := reservationIdempotencyKey(fingerprint, pricing, true)
	if len(bound) != 43 || bound == fingerprint {
		t.Fatalf("priced reservation binding = %q", bound)
	}
	other := pricing
	other.source = "enterprise-usd"
	if reservationIdempotencyKey(fingerprint, other, true) == bound {
		t.Fatal("same-revision catalog substitution preserved reservation binding")
	}
	if got := reservationIdempotencyKey(fingerprint, pricing, false); got != fingerprint {
		t.Fatalf("historical priced reservation binding = %q, want raw fingerprint", got)
	}
	if got := reservationIdempotencyKey(fingerprint, selectedPricing{}, false); got != fingerprint {
		t.Fatalf("unpriced reservation binding = %q, want raw fingerprint", got)
	}
}

func TestHardCostSnapshotUsesCalendarAccounting(t *testing.T) {
	t.Parallel()
	input := validSnapshotInput(t)
	input.Rules = []Rule{{
		Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user", "feature"}, Window: "1d",
		Maximum: 100, Hard: true,
	}}
	prepared, err := prepareSnapshot(input)
	if err != nil {
		t.Fatalf("prepare hard cost snapshot: %v", err)
	}
	at := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	plans, err := snapshotPlansAt(prepared.rules, at)
	if err != nil || len(plans) != 1 {
		t.Fatalf("plan hard cost snapshot = %#v, %v", plans, err)
	}
	limit, err := limitSnapshotAt(plans[0], at)
	if err != nil || limit.Metric != CostNanoUSDMetric || limit.Maximum == nil ||
		*limit.Maximum != 100 || limit.Used == nil || *limit.Used != 0 ||
		limit.Reserved == nil || *limit.Reserved != 0 ||
		limit.Remaining == nil || *limit.Remaining != 100 || limit.ResetsAt == nil {
		t.Fatalf("pristine hard cost snapshot = %#v, %v", limit, err)
	}
	plans[0].bucket = &lockedBucket{
		id: "qbk_00000000000000000000000000", hardMaximum: int64Pointer(100),
		used: 30, reserved: 20,
	}
	limit, err = limitSnapshotAt(plans[0], at)
	if err != nil || *limit.Used != 30 || *limit.Reserved != 20 || *limit.Remaining != 50 {
		t.Fatalf("materialized hard cost snapshot = %#v, %v", limit, err)
	}
	invalid := input
	invalid.Rules = clonePreparedRules(prepared.rules)
	invalid.Rules[0].ReservedUnits = 1
	if _, err := prepareSnapshot(invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("reserved hard cost snapshot returned %v", err)
	}
}

func int64Pointer(value int64) *int64 { return &value }

func TestHardCostReservationEntryUnitsAreTheOnlyZeroStatefulUnits(t *testing.T) {
	t.Parallel()
	if !validReservationEntryUnits(CostNanoUSDMetric, CalendarAlgorithm, 0) ||
		!validReservationEntryUnits(CostNanoUSDMetric, CalendarAlgorithm, 7) {
		t.Fatal("valid hard cost reservation units were rejected")
	}
	for _, shape := range []struct {
		metric    string
		algorithm string
	}{
		{LogicalRequestsMetric, CalendarAlgorithm},
		{OutputTokensMetric, CalendarAlgorithm},
		{LogicalRequestsMetric, TokenBucketAlgorithm},
		{ConcurrentRequestsMetric, ConcurrencyAlgorithm},
		{CostNanoUSDMetric, TokenBucketAlgorithm},
	} {
		if validReservationEntryUnits(shape.metric, shape.algorithm, 0) {
			t.Fatalf("zero units accepted for %s/%s", shape.metric, shape.algorithm)
		}
	}
}

func TestHardCostSettlementValidationAndExactTerminalSplit(t *testing.T) {
	t.Parallel()
	entries := []lockedEntry{
		{metric: CostNanoUSDMetric, algorithm: CalendarAlgorithm, reservedUnits: 10},
		{metric: CostNanoUSDMetric, algorithm: CalendarAlgorithm, reservedUnits: 10},
	}
	known := Cost{NanoUSD: 7, Known: true, Confidence: CalculatedCostConfidence}
	if err := validateCostSettlement(entries, known); err != nil {
		t.Fatalf("validate known hard cost: %v", err)
	}
	for index := range entries {
		entries[index].settledUnits = 7
		entries[index].releasedUnits = 3
	}
	if !terminalCostEntriesMatch(entries, known) {
		t.Fatal("exact known hard cost terminal split did not match")
	}
	if terminalCostEntriesMatch(entries, Cost{Confidence: UnknownCostConfidence}) {
		t.Fatal("known partial split matched an unknown hard cost replay")
	}
	entries[0].settledUnits, entries[0].releasedUnits = 8, 2
	if terminalCostEntriesMatch(entries, known) {
		t.Fatal("tampered hard cost terminal split matched")
	}
	if err := validateCostSettlement(entries, Cost{
		NanoUSD: 11, Known: true, Confidence: CalculatedCostConfidence,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("over-reservation hard cost returned %v", err)
	}
	entries[1].reservedUnits = 9
	if err := validateCostSettlement(entries, Cost{}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("mismatched hard cost reservations returned %v", err)
	}

	zero := []lockedEntry{{
		metric: CostNanoUSDMetric, algorithm: CalendarAlgorithm, reservedUnits: 0,
	}}
	if err := validateCostSettlement(zero, Cost{}); err != nil ||
		!terminalCostEntriesMatch(zero, Cost{}) {
		t.Fatalf("zero hard cost unknown terminal state = %v", err)
	}
}

func TestHardCostReservationLifecycleStateAllowsExactPartialSettlement(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                        string
		logical, reservation        string
		reserved, settled, released int64
		want                        bool
	}{
		{name: "pending zero", logical: "reserved", reservation: "pending", want: true},
		{name: "known success", logical: "succeeded", reservation: "settled", reserved: 10, settled: 7, released: 3, want: true},
		{name: "known failure", logical: "failed", reservation: "settled", reserved: 10, settled: 4, released: 6, want: true},
		{name: "unknown", logical: "failed", reservation: "settled", reserved: 10, settled: 10, want: true},
		{name: "release zero", logical: "failed", reservation: "released", want: true},
		{name: "missing units", logical: "succeeded", reservation: "settled", reserved: 10, settled: 7, released: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := existingReservationStateMatches(
				test.logical, test.reservation, CostNanoUSDMetric, CalendarAlgorithm,
				test.reserved, test.reserved, test.settled, test.released,
			)
			if got != test.want {
				t.Fatalf("cost lifecycle match = %t, want %t", got, test.want)
			}
		})
	}
}
