package quota

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestPrepareRequestSupportsHardInputAndTotalTokenCalendars(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{
		{
			Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: 1_000, ReservedUnits: 11, Hard: true,
		},
		{
			Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"organization"}, Window: "1mo",
			Maximum: 10_000, ReservedUnits: 11, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"installation"}, Window: "1h",
			Maximum: 2_000, ReservedUnits: 18, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"environment"}, Window: "1d",
			Maximum: 20_000, ReservedUnits: 18, Hard: true,
		},
	}

	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare input/total calendar rules: %v", err)
	}
	if len(prepared.rules) != len(input.Rules) {
		t.Fatalf("prepared rules = %d, want %d", len(prepared.rules), len(input.Rules))
	}
	for _, rule := range prepared.rules {
		if !rule.stateful || rule.Algorithm != CalendarAlgorithm {
			t.Fatalf("prepared non-calendar or stateless rule: %#v", rule)
		}
		wantReserved := int64(11)
		if rule.Metric == TotalTokensMetric {
			wantReserved = 18
		} else if rule.Metric != InputTokensMetric {
			t.Fatalf("prepared unexpected metric: %#v", rule)
		}
		if rule.ReservedUnits != wantReserved {
			t.Fatalf("%s reserved units = %d, want %d", rule.Metric, rule.ReservedUnits, wantReserved)
		}
	}

	reordered := cloneReserveInput(input)
	for left, right := 0, len(reordered.Rules)-1; left < right; left, right = left+1, right-1 {
		reordered.Rules[left], reordered.Rules[right] = reordered.Rules[right], reordered.Rules[left]
	}
	reorderedPrepared, err := prepareRequest(reordered)
	if err != nil {
		t.Fatalf("prepare reordered input/total rules: %v", err)
	}
	if requestFingerprint(reorderedPrepared) != requestFingerprint(prepared) {
		t.Fatal("input/total configuration order changed the trusted fingerprint")
	}
}

func TestPrepareRequestRejectsUnsupportedInputAndTotalTokenShapes(t *testing.T) {
	t.Parallel()
	for _, metric := range []string{InputTokensMetric, TotalTokensMetric} {
		metric := metric
		t.Run(metric, func(t *testing.T) {
			t.Parallel()
			base := validReserveInput(t)
			base.Rules = []Rule{{
				Metric: metric, Algorithm: CalendarAlgorithm, Scope: []string{"user"},
				Window: "1d", Maximum: 1_000, ReservedUnits: 8, Hard: true,
			}}
			tests := []struct {
				name   string
				mutate func(*Rule)
			}{
				{name: "zero reservation", mutate: func(rule *Rule) { rule.ReservedUnits = 0 }},
				{name: "negative reservation", mutate: func(rule *Rule) { rule.ReservedUnits = -1 }},
				{name: "zero maximum", mutate: func(rule *Rule) { rule.Maximum = 0 }},
				{name: "missing window", mutate: func(rule *Rule) { rule.Window = "" }},
				{name: "per-request field", mutate: func(rule *Rule) { rule.PerRequestMaximum = 8 }},
				{name: "capacity field", mutate: func(rule *Rule) { rule.Capacity = 8 }},
				{name: "refill field", mutate: func(rule *Rule) {
					rule.RefillNumerator, rule.RefillDenominator = 1, 1
				}},
				{name: "token bucket", mutate: func(rule *Rule) {
					rule.Algorithm, rule.Window, rule.Maximum = TokenBucketAlgorithm, "", 0
					rule.Capacity, rule.RefillNumerator, rule.RefillDenominator = 100, 1, 1
				}},
				{name: "per request", mutate: func(rule *Rule) {
					rule.Algorithm, rule.Window, rule.Maximum = PerRequestAlgorithm, "", 0
					rule.PerRequestMaximum = 100
				}},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					input := cloneReserveInput(base)
					test.mutate(&input.Rules[0])
					if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
						t.Fatalf("unsupported %s shape returned %v", metric, err)
					}
				})
			}
		})
	}
}

func TestPrepareRequestRequiresUniformReservationsPerInputAndTotalMetric(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	base.Rules = []Rule{
		{
			Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 100,
			ReservedUnits: 11, Hard: true,
		},
		{
			Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"organization"}, Window: "1mo", Maximum: 1_000,
			ReservedUnits: 11, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"feature"}, Window: "1h", Maximum: 200,
			ReservedUnits: 18, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"environment"}, Window: "1d", Maximum: 2_000,
			ReservedUnits: 18, Hard: true,
		},
	}
	if _, err := prepareRequest(base); err != nil {
		t.Fatalf("prepare independently uniform input/total reservations: %v", err)
	}

	for _, test := range []struct {
		name  string
		index int
	}{
		{name: "input", index: 1},
		{name: "total", index: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			input.Rules[test.index].ReservedUnits++
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("nonuniform %s reservations returned %v", test.name, err)
			}
		})
	}
}

func TestPrepareRequestValidatesProvableTotalReservationRelationships(t *testing.T) {
	t.Parallel()

	newInput := func() ReserveInput {
		input := validReserveInput(t)
		input.Rules = []Rule{
			{
				Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user"}, Window: "1d", Maximum: math.MaxInt64,
				ReservedUnits: 11, Hard: true,
			},
			{
				Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"feature"}, Window: "1d", Maximum: math.MaxInt64,
				ReservedUnits: 7, Hard: true,
			},
			{
				Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"environment"}, Window: "1d", Maximum: math.MaxInt64,
				ReservedUnits: 18, Hard: true,
			},
		}
		return input
	}
	if _, err := prepareRequest(newInput()); err != nil {
		t.Fatalf("prepare exact input/output/total reservation: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*ReserveInput)
	}{
		{name: "total below input", mutate: func(input *ReserveInput) {
			input.Rules = append([]Rule(nil), input.Rules[0], input.Rules[2])
			input.Rules[1].ReservedUnits = 10
		}},
		{name: "total below output", mutate: func(input *ReserveInput) {
			input.Rules = append([]Rule(nil), input.Rules[1], input.Rules[2])
			input.Rules[1].ReservedUnits = 6
		}},
		{name: "all three nonexact", mutate: func(input *ReserveInput) {
			input.Rules[2].ReservedUnits = 19
		}},
		{name: "component sum overflow", mutate: func(input *ReserveInput) {
			input.Rules[0].ReservedUnits = math.MaxInt64
			input.Rules[1].ReservedUnits = 1
			input.Rules[2].ReservedUnits = math.MaxInt64
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := newInput()
			test.mutate(&input)
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid total reservation relationship returned %v", err)
			}
		})
	}
}

func TestInputAndTotalTokenFingerprintBindingsPreserveOutputSerialization(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{
		{
			Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 1_000,
			ReservedUnits: 11, Hard: true,
		},
		{
			Metric: TotalTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"feature"}, Window: "1d", Maximum: 2_000,
			ReservedUnits: 18, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare fingerprint rules: %v", err)
	}
	parts := inputTotalFingerprintHeader(prepared)
	for _, rule := range prepared.rules {
		parts = append(parts,
			rule.ruleKey, rule.scopeKey, strconv.FormatInt(rule.Maximum, 10),
			strconv.FormatInt(rule.PerRequestMaximum, 10),
			strconv.FormatInt(rule.ReservedUnits, 10),
		)
	}
	if got, want := requestFingerprint(prepared), canonicalDigest(requestDigestDomain, parts); got != want {
		t.Fatalf("input/total fingerprint = %q, want reservation-bound serialization %q", got, want)
	}

	changedReservation := cloneReserveInput(input)
	changedReservation.Rules[0].ReservedUnits++
	changed, err := prepareRequest(changedReservation)
	if err != nil {
		t.Fatalf("prepare changed input reservation: %v", err)
	}
	if requestFingerprint(changed) == requestFingerprint(prepared) {
		t.Fatal("input reservation was omitted from the trusted fingerprint")
	}

	changedPerRequest := prepared
	changedPerRequest.rules = append([]preparedRule(nil), prepared.rules...)
	changedPerRequest.rules[0].PerRequestMaximum++
	if requestFingerprint(changedPerRequest) == requestFingerprint(prepared) {
		t.Fatal("new token per-request field was omitted from fingerprint serialization")
	}

	output := validReserveInput(t)
	output.Rules = []Rule{{
		Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "1d", Maximum: 1_000,
		ReservedUnits: 64, Hard: true,
	}}
	outputPrepared, err := prepareRequest(output)
	if err != nil {
		t.Fatalf("prepare historical output-only request: %v", err)
	}
	outputRule := outputPrepared.rules[0]
	historicalOutputParts := append(inputTotalFingerprintHeader(outputPrepared),
		outputRule.ruleKey, outputRule.scopeKey, strconv.FormatInt(outputRule.Maximum, 10),
		strconv.FormatInt(outputRule.PerRequestMaximum, 10),
		strconv.FormatInt(outputRule.ReservedUnits, 10),
	)
	if got, want := requestFingerprint(outputPrepared), canonicalDigest(requestDigestDomain, historicalOutputParts); got != want {
		t.Fatalf("output-only fingerprint = %q, want historical serialization %q", got, want)
	}
}

func TestInputAndTotalTokenCalendarStateValidation(t *testing.T) {
	t.Parallel()
	for _, metric := range []string{InputTokensMetric, TotalTokensMetric} {
		if !isStatefulMetric(metric) || !isStatefulRule(metric, CalendarAlgorithm) {
			t.Fatalf("%s calendar is not stateful", metric)
		}
		if isStatefulRule(metric, TokenBucketAlgorithm) || isStatefulRule(metric, PerRequestAlgorithm) {
			t.Fatalf("%s accepted a non-calendar stateful algorithm", metric)
		}
		if !validReservationEntryUnits(metric, CalendarAlgorithm, 1) ||
			validReservationEntryUnits(metric, CalendarAlgorithm, 0) ||
			validReservationEntryUnits(metric, TokenBucketAlgorithm, 1) ||
			validReservationEntryUnits(metric, PerRequestAlgorithm, 1) {
			t.Fatalf("%s reservation entry validation accepted an unsafe shape", metric)
		}
	}

	input := validReserveInput(t)
	resetAt := time.Date(2026, time.August, 29, 0, 0, 0, 0, time.UTC)
	entries := []reservationEntry{
		{
			bucketID: mustInputTotalModelID(t, id.QuotaBucket),
			entryID:  mustInputTotalModelID(t, id.QuotaEntry),
			metric:   InputTokensMetric, algorithm: CalendarAlgorithm,
			reservedUnits: 11, resetAt: resetAt,
		},
		{
			bucketID: mustInputTotalModelID(t, id.QuotaBucket),
			entryID:  mustInputTotalModelID(t, id.QuotaEntry),
			metric:   InputTokensMetric, algorithm: CalendarAlgorithm,
			reservedUnits: 11, resetAt: resetAt,
		},
		{
			bucketID: mustInputTotalModelID(t, id.QuotaBucket),
			entryID:  mustInputTotalModelID(t, id.QuotaEntry),
			metric:   TotalTokensMetric, algorithm: CalendarAlgorithm,
			reservedUnits: 18, resetAt: resetAt,
		},
		{
			bucketID: mustInputTotalModelID(t, id.QuotaBucket),
			entryID:  mustInputTotalModelID(t, id.QuotaEntry),
			metric:   TotalTokensMetric, algorithm: CalendarAlgorithm,
			reservedUnits: 18, resetAt: resetAt,
		},
		{
			bucketID: mustInputTotalModelID(t, id.QuotaBucket),
			entryID:  mustInputTotalModelID(t, id.QuotaEntry),
			metric:   OutputTokensMetric, algorithm: CalendarAlgorithm,
			reservedUnits: 7, resetAt: resetAt,
		},
		{
			bucketID: mustInputTotalModelID(t, id.QuotaBucket),
			entryID:  mustInputTotalModelID(t, id.QuotaEntry),
			metric:   OutputTokensMetric, algorithm: CalendarAlgorithm,
			reservedUnits: 7, resetAt: resetAt,
		},
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].bucketID < entries[right].bucketID })
	reservation := Reservation{
		organizationID: input.OrganizationID, applicationID: input.ApplicationID,
		environmentID: input.EnvironmentID, logicalRequestID: input.LogicalRequestID.String(),
		reservationID: mustInputTotalModelID(t, id.QuotaReservation),
		entries:       entries, routeKey: input.RouteKey, upstreamKey: input.UpstreamKey,
		modelKey: input.ModelKey, physicalModel: input.PhysicalModel,
		windowResetAt: resetAt, expiresAt: resetAt.Add(time.Minute),
	}
	if err := reservation.validate(); err != nil {
		t.Fatalf("validate input/total calendar reservation: %v", err)
	}

	for _, metric := range []string{InputTokensMetric, OutputTokensMetric, TotalTokensMetric} {
		nonuniform := reservation
		nonuniform.entries = append([]reservationEntry(nil), reservation.entries...)
		for index := range nonuniform.entries {
			if nonuniform.entries[index].metric == metric {
				nonuniform.entries[index].reservedUnits++
				break
			}
		}
		if err := nonuniform.validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("nonuniform %s reservation entries returned %v", metric, err)
		}
	}

	for _, total := range []int64{17, 19} {
		invalid := reservation
		invalid.entries = append([]reservationEntry(nil), reservation.entries...)
		for index := range invalid.entries {
			if invalid.entries[index].metric == TotalTokensMetric {
				invalid.entries[index].reservedUnits = total
			}
		}
		if err := invalid.validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("nonexact durable total reservation %d returned %v", total, err)
		}
	}
}

func TestUsageValidationRequiresOverflowSafeExactTokenTotal(t *testing.T) {
	t.Parallel()
	for _, usage := range []Usage{
		{Known: true, Provenance: ProviderReportedProvenance},
		{
			InputTokens: math.MaxInt64 - 1, OutputTokens: 1, TotalTokens: math.MaxInt64,
			Known: true, Provenance: ProviderReportedProvenance,
		},
		{
			OutputTokens: math.MaxInt64, TotalTokens: math.MaxInt64,
			Known: true, Provenance: ProviderReportedProvenance,
		},
	} {
		if err := usage.validate(); err != nil {
			t.Fatalf("valid exact usage %#v returned %v", usage, err)
		}
	}

	for _, usage := range []Usage{
		{
			InputTokens: 2, OutputTokens: 3, TotalTokens: 4,
			Known: true, Provenance: ProviderReportedProvenance,
		},
		{
			InputTokens: 2, OutputTokens: 3, TotalTokens: 6,
			Known: true, Provenance: ProviderReportedProvenance,
		},
		{
			InputTokens: math.MaxInt64, OutputTokens: 1, TotalTokens: math.MaxInt64,
			Known: true, Provenance: ProviderReportedProvenance,
		},
	} {
		if err := usage.validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("inconsistent or overflowing usage %#v returned %v", usage, err)
		}
	}
}

func inputTotalFingerprintHeader(prepared preparedRequest) []string {
	return []string{
		prepared.LogicalRequestID.String(), prepared.OrganizationID,
		prepared.ApplicationID, prepared.EnvironmentID, prepared.ApplicationUserID,
		prepared.InstallationID, prepared.SessionGrantID, prepared.ConfigRevisionID,
		prepared.FeatureKey, prepared.Protocol, prepared.ClientRequestID,
		prepared.LimitPlanKey, prepared.RouteKey, prepared.UpstreamKey,
		prepared.ModelKey, prepared.PhysicalModel,
	}
}

func mustInputTotalModelID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
