package quota

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

func TestPrepareRequestCanonicalizesTrustedBucketIdentity(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules[0].Scope = []string{"feature", "user", "environment"}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	preparedRule := prepared.rules[0]
	if got, want := strings.Join(preparedRule.scopeDimensions, ","), "environment,user,feature"; got != want {
		t.Fatalf("scope dimensions = %q, want %q", got, want)
	}
	if preparedRule.scopeType != "composite" || len(preparedRule.ruleKey) != 43 || len(preparedRule.scopeKey) != 43 || preparedRule.ruleKey == preparedRule.scopeKey {
		t.Fatalf("unexpected bucket identity: %#v", prepared)
	}

	reordered := input
	reordered.Rules = []Rule{input.Rules[0]}
	reordered.Rules[0].Scope = []string{"environment", "feature", "user"}
	canonical, err := prepareRequest(reordered)
	if err != nil {
		t.Fatalf("prepare reordered request: %v", err)
	}
	if canonical.rules[0].ruleKey != preparedRule.ruleKey || canonical.rules[0].scopeKey != preparedRule.scopeKey {
		t.Fatal("scope order changed a canonical digest")
	}

	changedMaximum := input
	changedMaximum.Rules = []Rule{input.Rules[0]}
	changedMaximum.Rules[0].Maximum++
	maximumPrepared, err := prepareRequest(changedMaximum)
	if err != nil {
		t.Fatalf("prepare changed maximum: %v", err)
	}
	if maximumPrepared.rules[0].ruleKey != preparedRule.ruleKey || maximumPrepared.rules[0].scopeKey != preparedRule.scopeKey {
		t.Fatal("mutable maximum changed persistent quota identity")
	}

	changedFeature := input
	changedFeature.FeatureKey = "other-feature"
	featurePrepared, err := prepareRequest(changedFeature)
	if err != nil {
		t.Fatalf("prepare changed feature: %v", err)
	}
	if featurePrepared.rules[0].ruleKey != preparedRule.ruleKey || featurePrepared.rules[0].scopeKey == preparedRule.scopeKey {
		t.Fatal("server-owned scope value was omitted from scope identity")
	}
}

func TestRequestFingerprintBindsOpaqueLogicalIdentityAndTrustedDecision(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	fingerprint := requestFingerprint(prepared)
	if len(fingerprint) != 43 {
		t.Fatalf("fingerprint length = %d, want 43", len(fingerprint))
	}

	changedHint := cloneReserveInput(input)
	changedHint.ClientRequestID = "different-client-hint"
	hintPrepared, err := prepareRequest(changedHint)
	if err != nil {
		t.Fatalf("prepare changed hint: %v", err)
	}
	if hintPrepared.LogicalRequestID.String() != input.LogicalRequestID.String() {
		t.Fatal("client hint changed the opaque logical request identity")
	}
	if requestFingerprint(hintPrepared) == fingerprint {
		t.Fatal("durable client correlation was omitted from replay comparison")
	}

	changedLogicalID := cloneReserveInput(input)
	changedLogicalID.LogicalRequestID = mustLogicalID(t)
	logicalPrepared, err := prepareRequest(changedLogicalID)
	if err != nil {
		t.Fatalf("prepare changed logical ID: %v", err)
	}
	if requestFingerprint(logicalPrepared) == fingerprint {
		t.Fatal("opaque logical request identity was omitted from fingerprint")
	}
}

func TestLegacyLogicalOnlyFingerprintSerializationIsUnchanged(t *testing.T) {
	t.Parallel()
	prepared, err := prepareRequest(validReserveInput(t))
	if err != nil {
		t.Fatalf("prepare legacy request: %v", err)
	}
	rule := prepared.rules[0]
	legacyParts := []string{
		prepared.LogicalRequestID.String(), prepared.OrganizationID,
		prepared.ApplicationID, prepared.EnvironmentID, prepared.ApplicationUserID,
		prepared.InstallationID, prepared.SessionGrantID, prepared.ConfigRevisionID,
		prepared.FeatureKey, prepared.Protocol, prepared.ClientRequestID,
		prepared.LimitPlanKey, prepared.RouteKey, prepared.UpstreamKey,
		prepared.ModelKey, prepared.PhysicalModel,
		rule.ruleKey, rule.scopeKey, strconv.FormatInt(rule.Maximum, 10),
	}
	if got, want := requestFingerprint(prepared), canonicalDigest(requestDigestDomain, legacyParts); got != want {
		t.Fatalf("legacy fingerprint = %q, want historical serialization %q", got, want)
	}
}

func TestConfiguredPricingFingerprintAppendsOnlyCatalogIdentity(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	unpriced, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare unpriced request: %v", err)
	}
	input.Pricing = PricingSelection{CatalogID: "standard-usd", Currency: USDCurrency}
	priced, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare priced request: %v", err)
	}
	rule := priced.rules[0]
	parts := []string{
		priced.LogicalRequestID.String(), priced.OrganizationID,
		priced.ApplicationID, priced.EnvironmentID, priced.ApplicationUserID,
		priced.InstallationID, priced.SessionGrantID, priced.ConfigRevisionID,
		priced.FeatureKey, priced.Protocol, priced.ClientRequestID,
		priced.LimitPlanKey, priced.RouteKey, priced.UpstreamKey,
		priced.ModelKey, priced.PhysicalModel,
		rule.ruleKey, rule.scopeKey, strconv.FormatInt(rule.Maximum, 10),
		"standard-usd",
	}
	want := canonicalDigest(requestDigestDomain, parts)
	if got := requestFingerprint(priced); got != want {
		t.Fatalf("priced fingerprint = %q, want catalog-appended serialization %q", got, want)
	}
	if requestFingerprint(priced) == requestFingerprint(unpriced) {
		t.Fatal("configured catalog was omitted from trusted fingerprint")
	}
	otherInput := cloneReserveInput(input)
	otherInput.Pricing.CatalogID = "enterprise-usd"
	other, err := prepareRequest(otherInput)
	if err != nil {
		t.Fatalf("prepare alternate catalog: %v", err)
	}
	if requestFingerprint(other) == requestFingerprint(priced) {
		t.Fatal("distinct configured catalogs produced the same trusted fingerprint")
	}
}

func TestPrepareRequestSupportsBoundedOutputTokenShapes(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 20, Hard: true,
		},
		{
			Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"feature", "user"}, Window: "1mo", Maximum: 10_000,
			ReservedUnits: 64, Hard: true,
		},
		{
			Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm,
			Scope: []string{"user"}, PerRequestMaximum: 128,
			ReservedUnits: 64, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare mixed output rules: %v", err)
	}
	plans, err := plannedBucketsAt(prepared, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("plan mixed output rules: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("stateful plans = %d, want 2", len(plans))
	}
	unitsByMetric := map[string]int64{}
	for _, plan := range plans {
		unitsByMetric[plan.rule.Metric] = plan.reservedUnits
	}
	if unitsByMetric[LogicalRequestsMetric] != 1 || unitsByMetric[OutputTokensMetric] != 64 {
		t.Fatalf("planned units = %#v, want logical=1 output=64", unitsByMetric)
	}

	reversed := cloneReserveInput(input)
	slices.Reverse(reversed.Rules)
	reordered, err := prepareRequest(reversed)
	if err != nil {
		t.Fatalf("prepare reversed output rules: %v", err)
	}
	if requestFingerprint(reordered) != requestFingerprint(prepared) {
		t.Fatal("output-rule order changed the trusted fingerprint")
	}

	perRequestOnly := cloneReserveInput(input)
	perRequestOnly.Rules = []Rule{input.Rules[2]}
	metadata, err := prepareRequest(perRequestOnly)
	if err != nil {
		t.Fatalf("prepare per-request-only rule: %v", err)
	}
	metadataPlans, err := plannedBucketsAt(metadata, time.Now().UTC())
	if err != nil || len(metadataPlans) != 0 {
		t.Fatalf("per-request-only plans = %#v, %v; want zero", metadataPlans, err)
	}
}

func TestPrepareRequestSupportsApplicableConcurrencyShapes(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Streaming = true
	input.Rules = []Rule{
		{
			Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm,
			Scope: []string{"environment"}, Maximum: 7, Hard: true,
		},
		{
			Metric: ConcurrentStreamsMetric, Algorithm: ConcurrencyAlgorithm,
			Scope: []string{"feature", "user"}, Maximum: 3, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare concurrency request: %v", err)
	}
	plans, err := plannedBucketsAt(prepared, time.Now().UTC())
	if err != nil {
		t.Fatalf("plan concurrency request: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("applicable concurrency plans = %d, want 2", len(plans))
	}
	for _, plan := range plans {
		if plan.period.key != "active" || !plan.period.end.IsZero() || plan.reservedUnits != 1 ||
			!isConcurrencyMetric(plan.rule.Metric) {
			t.Fatalf("unexpected concurrency plan: %#v", plan)
		}
	}

	nonStreaming := cloneReserveInput(input)
	nonStreaming.Streaming = false
	nonStreamingPrepared, err := prepareRequest(nonStreaming)
	if err != nil {
		t.Fatalf("prepare non-streaming request: %v", err)
	}
	nonStreamingPlans, err := plannedBucketsAt(nonStreamingPrepared, time.Now().UTC())
	if err != nil {
		t.Fatalf("plan non-streaming request: %v", err)
	}
	if len(nonStreamingPlans) != 1 || nonStreamingPlans[0].rule.Metric != ConcurrentRequestsMetric {
		t.Fatalf("non-streaming plans = %#v, want request concurrency only", nonStreamingPlans)
	}
	if requestFingerprint(prepared) == requestFingerprint(nonStreamingPrepared) {
		t.Fatal("stream applicability was omitted from the trusted fingerprint")
	}

	requestOnly := cloneReserveInput(input)
	requestOnly.Rules = requestOnly.Rules[:1]
	requestOnly.Streaming = false
	requestOnlyPrepared, err := prepareRequest(requestOnly)
	if err != nil {
		t.Fatalf("prepare request-only concurrency: %v", err)
	}
	requestOnly.Streaming = true
	requestOnlyStreaming, err := prepareRequest(requestOnly)
	if err != nil {
		t.Fatalf("prepare streaming request-only concurrency: %v", err)
	}
	if requestFingerprint(requestOnlyPrepared) != requestFingerprint(requestOnlyStreaming) {
		t.Fatal("irrelevant streaming metadata changed request-concurrency fingerprint")
	}
}

func TestPrepareRequestRejectsMalformedConcurrencyRules(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	base.Rules = []Rule{{
		Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm,
		Scope: []string{"user"}, Maximum: 2, Hard: true,
	}}
	tests := []struct {
		name   string
		mutate func(*Rule)
	}{
		{name: "soft", mutate: func(rule *Rule) { rule.Hard = false }},
		{name: "zero maximum", mutate: func(rule *Rule) { rule.Maximum = 0 }},
		{name: "window", mutate: func(rule *Rule) { rule.Window = "1m" }},
		{name: "per request", mutate: func(rule *Rule) { rule.PerRequestMaximum = 1 }},
		{name: "reserved units", mutate: func(rule *Rule) { rule.ReservedUnits = 1 }},
		{name: "wrong algorithm", mutate: func(rule *Rule) { rule.Algorithm = CalendarAlgorithm; rule.Window = "1m" }},
		{name: "wrong metric", mutate: func(rule *Rule) { rule.Metric = "concurrent_tokens" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			test.mutate(&input.Rules[0])
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("malformed concurrency rule returned %v", err)
			}
		})
	}
}

func TestReserveIdentifierGenerationPreservesLegacyOrderAndSupportsZeroEntries(t *testing.T) {
	t.Parallel()
	var calls []id.Prefix
	store := &Store{newID: func(prefix id.Prefix) (string, error) {
		calls = append(calls, prefix)
		value, err := id.New(prefix)
		if err != nil {
			return "", err
		}
		return value, nil
	}}
	legacy, err := store.newReserveIDs(1)
	if err != nil {
		t.Fatalf("generate legacy reserve IDs: %v", err)
	}
	wantLegacyOrder := []id.Prefix{id.QuotaBucket, id.QuotaReservation, id.QuotaEntry}
	if !slices.Equal(calls, wantLegacyOrder) || len(legacy.buckets) != 1 || len(legacy.entries) != 1 || legacy.reservation == "" {
		t.Fatalf("legacy generation calls=%v IDs=%#v", calls, legacy)
	}
	calls = nil
	entryless, err := store.newReserveIDs(0)
	if err != nil {
		t.Fatalf("generate entryless reserve IDs: %v", err)
	}
	if !slices.Equal(calls, []id.Prefix{id.QuotaReservation}) ||
		len(entryless.buckets) != 0 || len(entryless.entries) != 0 || entryless.reservation == "" {
		t.Fatalf("entryless generation calls=%v IDs=%#v", calls, entryless)
	}
	calls = nil
	withLeases, err := store.newReserveIDs(3, 2)
	if err != nil {
		t.Fatalf("generate concurrency reserve IDs: %v", err)
	}
	wantConcurrencyOrder := []id.Prefix{
		id.QuotaBucket, id.QuotaBucket, id.QuotaBucket,
		id.QuotaReservation,
		id.QuotaEntry, id.QuotaEntry, id.QuotaEntry,
		id.ConcurrencyLease, id.ConcurrencyLease,
	}
	if !slices.Equal(calls, wantConcurrencyOrder) || len(withLeases.leases) != 2 {
		t.Fatalf("concurrency generation calls=%v IDs=%#v", calls, withLeases)
	}
}

func TestSettlementUsageIdentifierGenerationAddsOnlyKnownPricedCost(t *testing.T) {
	t.Parallel()
	var calls int
	store := &Store{newID: func(prefix id.Prefix) (string, error) {
		if prefix != id.UsageRecord {
			t.Fatalf("settlement requested %s identifier", prefix)
		}
		calls++
		return id.New(prefix)
	}}
	usage := Usage{
		InputTokens: 1, OutputTokens: 2, TotalTokens: 3,
		Known: true, Provenance: ProviderReportedProvenance,
	}
	if _, err := store.newSettlementUsageIDs(usage, false, Cost{}, selectedPricing{}); err != nil {
		t.Fatalf("generate legacy usage identifiers: %v", err)
	}
	if calls != 4 {
		t.Fatalf("legacy usage identifier calls = %d, want 4", calls)
	}
	pricing := selectedPricing{
		source: "standard-usd", currency: USDCurrency,
		revision: validReserveInput(t).ConfigRevisionID,
	}
	calls = 0
	identifiers, err := store.newSettlementUsageIDs(
		usage, false,
		Cost{NanoUSD: 7, Known: true, Confidence: CalculatedCostConfidence}, pricing,
	)
	if err != nil {
		t.Fatalf("generate priced usage identifiers: %v", err)
	}
	if calls != 5 || identifiers.cost == "" {
		t.Fatalf("priced usage identifier calls = %d IDs=%#v, want 5 with cost", calls, identifiers)
	}
	calls = 0
	if _, err := store.newSettlementUsageIDs(usage, false, Cost{}, pricing); err != nil {
		t.Fatalf("generate unknown priced usage identifiers: %v", err)
	}
	if calls != 4 {
		t.Fatalf("unknown priced identifier calls = %d, want historical 4", calls)
	}
}

func TestPrepareRequestRejectsUnsafeOutputReservations(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	base.Rules = []Rule{
		{
			Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 1_000,
			ReservedUnits: 64, Hard: true,
		},
		{
			Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm,
			Scope: []string{"user"}, PerRequestMaximum: 128,
			ReservedUnits: 64, Hard: true,
		},
	}
	tests := []struct {
		name   string
		mutate func(*ReserveInput)
	}{
		{name: "missing calendar units", mutate: func(input *ReserveInput) { input.Rules[0].ReservedUnits = 0 }},
		{name: "mismatched trusted cap", mutate: func(input *ReserveInput) { input.Rules[1].ReservedUnits = 63 }},
		{name: "calendar per request maximum", mutate: func(input *ReserveInput) { input.Rules[0].PerRequestMaximum = 128 }},
		{name: "per request window", mutate: func(input *ReserveInput) { input.Rules[1].Window = "1d" }},
		{name: "per request calendar maximum", mutate: func(input *ReserveInput) { input.Rules[1].Maximum = 1000 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			test.mutate(&input)
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsafe output reservation returned %v", err)
			}
		})
	}
	overBound := cloneReserveInput(base)
	overBound.Rules[0].ReservedUnits = 129
	overBound.Rules[1].ReservedUnits = 129
	prepared, err := prepareRequest(overBound)
	if err != nil || len(requestBoundExceededRules(prepared.rules)) != 1 {
		t.Fatalf("per-request output over-bound classification = (%#v, %v)", prepared.rules, err)
	}
	logical := validReserveInput(t)
	logical.Rules[0].ReservedUnits = 1
	if _, err := prepareRequest(logical); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("caller-supplied logical units returned %v", err)
	}
}

func TestPrepareRequestCanonicalizesMultipleRulesIndependentOfConfigurationOrder(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"feature", "user"}, Window: "1d", Maximum: 5, Hard: true,
		},
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"organization"}, Window: "1mo", Maximum: 500, Hard: true,
		},
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"installation", "environment"}, Window: "1h", Maximum: 20, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare multi-rule request: %v", err)
	}
	if len(prepared.rules) != len(input.Rules) || len(prepared.Rules) != len(input.Rules) {
		t.Fatalf("prepared rules = %d/%d, want %d", len(prepared.rules), len(prepared.Rules), len(input.Rules))
	}
	for index := 1; index < len(prepared.rules); index++ {
		left, right := prepared.rules[index-1], prepared.rules[index]
		if left.ruleKey > right.ruleKey || (left.ruleKey == right.ruleKey && left.scopeKey >= right.scopeKey) {
			t.Fatalf("prepared rules are not in canonical identity order: %#v", prepared.rules)
		}
	}

	reversed := cloneReserveInput(input)
	slices.Reverse(reversed.Rules)
	for index := range reversed.Rules {
		slices.Reverse(reversed.Rules[index].Scope)
	}
	reordered, err := prepareRequest(reversed)
	if err != nil {
		t.Fatalf("prepare reversed multi-rule request: %v", err)
	}
	if requestFingerprint(reordered) != requestFingerprint(prepared) {
		t.Fatal("configuration order changed the trusted request fingerprint")
	}
	for index := range prepared.rules {
		if prepared.rules[index].ruleKey != reordered.rules[index].ruleKey ||
			prepared.rules[index].scopeKey != reordered.rules[index].scopeKey ||
			prepared.rules[index].Maximum != reordered.rules[index].Maximum {
			t.Fatalf("canonical rule %d differs after reversal", index)
		}
	}

	changed := cloneReserveInput(input)
	changed.Rules[1].Maximum++
	changedPrepared, err := prepareRequest(changed)
	if err != nil {
		t.Fatalf("prepare changed multi-rule maximum: %v", err)
	}
	if requestFingerprint(changedPrepared) == requestFingerprint(prepared) {
		t.Fatal("one rule maximum was omitted from the trusted request fingerprint")
	}
}

func TestPrepareRequestRejectsDuplicateImmutableBucketIdentity(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	duplicate := input.Rules[0]
	duplicate.Scope = []string{"feature", "user"}
	duplicate.Maximum++
	input.Rules = append(input.Rules, duplicate)
	if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate immutable bucket identity returned %v", err)
	}
}

func TestPrepareRequestSupportsBoundedRuleSet(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = make([]Rule, maximumRulesPerRequest)
	for index := range input.Rules {
		input.Rules[index] = Rule{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: fmt.Sprintf("%dm", index+1),
			Maximum: int64(index + 1), Hard: true,
		}
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare maximum bounded rule set: %v", err)
	}
	if len(prepared.rules) != maximumRulesPerRequest {
		t.Fatalf("prepared rule count = %d, want %d", len(prepared.rules), maximumRulesPerRequest)
	}

	over := cloneReserveInput(input)
	over.Rules = append(over.Rules, Rule{
		Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user"}, Window: "129m", Maximum: 129, Hard: true,
	})
	if _, err := prepareRequest(over); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("over-limit rule set returned %v", err)
	}
}

func TestExceededErrorTieBreaksByCanonicalRuleIdentity(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: 3, Hard: true,
		},
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 7, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare equal-reset rules: %v", err)
	}
	period, err := calendarWindow(time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC), "1d")
	if err != nil {
		t.Fatalf("build equal calendar window: %v", err)
	}

	const lowBucketID = "qbk_00000000000000000000000000"
	const highBucketID = "qbk_7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
	makePlans := func(canonicalFirstBucketID, canonicalSecondBucketID string) []plannedBucket {
		plans := []plannedBucket{
			{
				rule: prepared.rules[0], period: period, bucketID: canonicalFirstBucketID,
				locked: lockedBucket{used: 11, reserved: 2},
			},
			{
				rule: prepared.rules[1], period: period, bucketID: canonicalSecondBucketID,
				locked: lockedBucket{used: 17, reserved: 5},
			},
		}
		sort.Slice(plans, func(left, right int) bool { return plans[left].bucketID < plans[right].bucketID })
		return plans
	}

	firstAllocation := makePlans(highBucketID, lowBucketID)
	secondAllocation := makePlans(lowBucketID, highBucketID)
	first := exceededError(input.LogicalRequestID.String(), firstAllocation, []int{0, 1})
	second := exceededError(input.LogicalRequestID.String(), secondAllocation, []int{0, 1})
	want := prepared.rules[0]
	if first.Maximum() != want.Maximum || first.Used() != 11 || first.Reserved() != 2 ||
		second.Maximum() != want.Maximum || second.Used() != 11 || second.Reserved() != 2 ||
		!first.RetryAt().Equal(period.end) || !second.RetryAt().Equal(period.end) {
		t.Fatalf("equal-reset denials changed with bucket allocation: first=%#v second=%#v", first, second)
	}
}

func TestPrepareRequestRejectsUnsupportedAndAmbiguousRules(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	tests := []struct {
		name   string
		mutate func(*ReserveInput)
	}{
		{name: "organization", mutate: func(input *ReserveInput) { input.OrganizationID = "invalid" }},
		{name: "logical request", mutate: func(input *ReserveInput) { input.LogicalRequestID = requestidentity.LogicalID{} }},
		{name: "application", mutate: func(input *ReserveInput) { input.ApplicationID = "invalid" }},
		{name: "environment", mutate: func(input *ReserveInput) { input.EnvironmentID = "invalid" }},
		{name: "user", mutate: func(input *ReserveInput) { input.ApplicationUserID = "invalid" }},
		{name: "installation", mutate: func(input *ReserveInput) { input.InstallationID = "invalid" }},
		{name: "grant", mutate: func(input *ReserveInput) { input.SessionGrantID = "invalid" }},
		{name: "revision", mutate: func(input *ReserveInput) { input.ConfigRevisionID = "invalid" }},
		{name: "feature", mutate: func(input *ReserveInput) { input.FeatureKey = "Not-Canonical" }},
		{name: "protocol", mutate: func(input *ReserveInput) { input.Protocol = "invented" }},
		{name: "client correlation", mutate: func(input *ReserveInput) { input.ClientRequestID = "bad hint" }},
		{name: "plan", mutate: func(input *ReserveInput) { input.LimitPlanKey = "Premium" }},
		{name: "route", mutate: func(input *ReserveInput) { input.RouteKey = "" }},
		{name: "upstream", mutate: func(input *ReserveInput) { input.UpstreamKey = "UPSTREAM" }},
		{name: "model", mutate: func(input *ReserveInput) { input.ModelKey = "" }},
		{name: "physical model", mutate: func(input *ReserveInput) { input.PhysicalModel = "model\nsecret" }},
		{name: "pricing source only", mutate: func(input *ReserveInput) { input.Pricing.CatalogID = "standard-usd" }},
		{name: "pricing currency only", mutate: func(input *ReserveInput) { input.Pricing.Currency = USDCurrency }},
		{name: "pricing currency", mutate: func(input *ReserveInput) {
			input.Pricing = PricingSelection{CatalogID: "standard-usd", Currency: "EUR"}
		}},
		{name: "pricing catalog", mutate: func(input *ReserveInput) {
			input.Pricing = PricingSelection{CatalogID: "Not Canonical", Currency: USDCurrency}
		}},
		{name: "no rules", mutate: func(input *ReserveInput) { input.Rules = nil }},
		{name: "ambiguous rules", mutate: func(input *ReserveInput) { input.Rules = append(input.Rules, input.Rules[0]) }},
		{name: "metric", mutate: func(input *ReserveInput) { input.Rules[0].Metric = "total_tokens" }},
		{name: "algorithm", mutate: func(input *ReserveInput) { input.Rules[0].Algorithm = "token_bucket" }},
		{name: "soft", mutate: func(input *ReserveInput) { input.Rules[0].Hard = false }},
		{name: "zero maximum", mutate: func(input *ReserveInput) { input.Rules[0].Maximum = 0 }},
		{name: "empty scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = nil }},
		{name: "duplicate scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = []string{"user", "user"} }},
		{name: "unknown scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = []string{"claim"} }},
		{name: "invalid window", mutate: func(input *ReserveInput) { input.Rules[0].Window = "daily" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			test.mutate(&input)
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid input returned %v", err)
			}
		})
	}
}

func TestPrepareRequestSupportsExactLogicalTokenBucket(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{{
		Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
		Scope: []string{"feature", "user"}, Capacity: 3,
		RefillNumerator: 333_333, RefillDenominator: tokenRateDecimalScale,
		Hard: true,
	}}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare token bucket: %v", err)
	}
	plans, err := plannedBucketsAt(prepared, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("plan token bucket: %v", err)
	}
	if len(plans) != 1 || plans[0].period.key != tokenBucketWindowKey ||
		!plans[0].period.end.IsZero() || plans[0].reservedUnits != 1 {
		t.Fatalf("token plan = %#v", plans)
	}

	var baseToken preparedRule
	for _, rule := range prepared.rules {
		if rule.Algorithm == TokenBucketAlgorithm {
			baseToken = rule
			break
		}
	}
	baseRuleKey := baseToken.ruleKey
	baseScopeKey := baseToken.scopeKey
	baseFingerprint := requestFingerprint(prepared)
	for _, mutate := range []func(*Rule){
		func(rule *Rule) { rule.Capacity++ },
		func(rule *Rule) { rule.RefillNumerator = 1; rule.RefillDenominator = 2 },
	} {
		changed := cloneReserveInput(input)
		mutate(&changed.Rules[0])
		other, prepareErr := prepareRequest(changed)
		if prepareErr != nil {
			t.Fatalf("prepare changed token policy: %v", prepareErr)
		}
		if other.rules[0].ruleKey != baseRuleKey || other.rules[0].scopeKey != baseScopeKey {
			t.Fatal("mutable token policy changed durable bucket identity")
		}
		if requestFingerprint(other) == baseFingerprint {
			t.Fatal("mutable token policy was omitted from replay fingerprint")
		}
	}
}

func TestPrepareRequestSupportsExactOutputTokenBucket(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules = []Rule{
		{
			Metric: OutputTokensMetric, Algorithm: TokenBucketAlgorithm,
			Scope: []string{"feature", "user"}, ReservedUnits: 64, Capacity: 100,
			RefillNumerator: 333_333, RefillDenominator: tokenRateDecimalScale,
			Hard: true,
		},
		{
			Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm,
			Scope: []string{"feature", "user"}, PerRequestMaximum: 128,
			ReservedUnits: 64, Hard: true,
		},
	}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare output token bucket: %v", err)
	}
	plans, err := plannedBucketsAt(prepared, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("plan output token bucket: %v", err)
	}
	if len(plans) != 1 || plans[0].rule.Algorithm != TokenBucketAlgorithm ||
		plans[0].period.key != tokenBucketWindowKey || !plans[0].period.end.IsZero() ||
		plans[0].reservedUnits != 64 {
		t.Fatalf("output token plan = %#v", plans)
	}

	var baseToken preparedRule
	for _, rule := range prepared.rules {
		if rule.Algorithm == TokenBucketAlgorithm {
			baseToken = rule
			break
		}
	}
	baseRuleKey := baseToken.ruleKey
	baseScopeKey := baseToken.scopeKey
	baseFingerprint := requestFingerprint(prepared)
	for _, mutate := range []func([]Rule){
		func(rules []Rule) { rules[0].Capacity++ },
		func(rules []Rule) { rules[0].RefillNumerator = 1; rules[0].RefillDenominator = 2 },
		func(rules []Rule) { rules[0].ReservedUnits--; rules[1].ReservedUnits-- },
	} {
		changed := cloneReserveInput(input)
		mutate(changed.Rules)
		other, prepareErr := prepareRequest(changed)
		if prepareErr != nil {
			t.Fatalf("prepare changed output token policy: %v", prepareErr)
		}
		var token preparedRule
		for _, rule := range other.rules {
			if rule.Algorithm == TokenBucketAlgorithm {
				token = rule
				break
			}
		}
		if token.ruleKey != baseRuleKey || token.scopeKey != baseScopeKey {
			t.Fatal("mutable output token policy changed durable bucket identity")
		}
		if requestFingerprint(other) == baseFingerprint {
			t.Fatal("mutable output token policy was omitted from replay fingerprint")
		}
	}
}

func TestPrepareRequestRejectsUnsafeOutputTokenBuckets(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	base.Rules = []Rule{{
		Metric: OutputTokensMetric, Algorithm: TokenBucketAlgorithm,
		Scope: []string{"user"}, ReservedUnits: 64, Capacity: 100,
		RefillNumerator: 1, RefillDenominator: tokenRateDecimalScale,
		Hard: true,
	}}
	tests := []struct {
		name   string
		mutate func(*Rule)
	}{
		{name: "missing units", mutate: func(rule *Rule) { rule.ReservedUnits = 0 }},
		{name: "capacity overflow", mutate: func(rule *Rule) {
			rule.Capacity = maximumTokenCapacity + 1
			rule.ReservedUnits = maximumTokenCapacity + 1
		}},
		{name: "window", mutate: func(rule *Rule) { rule.Window = "1d" }},
		{name: "maximum", mutate: func(rule *Rule) { rule.Maximum = 100 }},
		{name: "per request maximum", mutate: func(rule *Rule) { rule.PerRequestMaximum = 100 }},
		{name: "invalid rate", mutate: func(rule *Rule) { rule.RefillDenominator = 3 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			test.mutate(&input.Rules[0])
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsafe output token bucket returned %v", err)
			}
		})
	}
	overBound := cloneReserveInput(base)
	overBound.Rules[0].ReservedUnits = 101
	prepared, err := prepareRequest(overBound)
	if err != nil || len(requestBoundExceededRules(prepared.rules)) != 1 {
		t.Fatalf("token-bucket output over-bound classification = (%#v, %v)", prepared.rules, err)
	}

	mismatched := cloneReserveInput(base)
	mismatched.Rules = append(mismatched.Rules, Rule{
		Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"feature"}, Window: "1d", Maximum: 1_000,
		ReservedUnits: 63, Hard: true,
	})
	if _, err := prepareRequest(mismatched); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mismatched output reservations returned %v", err)
	}
}

func TestPrepareRequestRejectsInvalidTokenBucketPolicies(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	base.Rules = []Rule{{
		Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
		Scope: []string{"user"}, Capacity: 1,
		RefillNumerator: 1, RefillDenominator: tokenRateDecimalScale,
		Hard: true,
	}}
	tests := []struct {
		name   string
		mutate func(*Rule)
	}{
		{name: "window", mutate: func(rule *Rule) { rule.Window = "1d" }},
		{name: "maximum", mutate: func(rule *Rule) { rule.Maximum = 1 }},
		{name: "per request", mutate: func(rule *Rule) { rule.PerRequestMaximum = 1 }},
		{name: "reserved units", mutate: func(rule *Rule) { rule.ReservedUnits = 1 }},
		{name: "zero capacity", mutate: func(rule *Rule) { rule.Capacity = 0 }},
		{name: "capacity overflow", mutate: func(rule *Rule) { rule.Capacity = maximumTokenCapacity + 1 }},
		{name: "zero numerator", mutate: func(rule *Rule) { rule.RefillNumerator = 0 }},
		{name: "zero denominator", mutate: func(rule *Rule) { rule.RefillDenominator = 0 }},
		{name: "unsupported scale", mutate: func(rule *Rule) { rule.RefillDenominator = 3 }},
		{name: "unreduced", mutate: func(rule *Rule) { rule.RefillNumerator = 2; rule.RefillDenominator = 2 }},
		{name: "rate above maximum", mutate: func(rule *Rule) {
			rule.RefillNumerator = tokenRateDecimalScale + 1
			rule.RefillDenominator = 1
		}},
		{name: "rate overflow", mutate: func(rule *Rule) { rule.RefillNumerator = math.MaxInt64; rule.RefillDenominator = 1 }},
		{name: "unsupported metric", mutate: func(rule *Rule) { rule.Metric = OutputTokensMetric }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			test.mutate(&input.Rules[0])
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid token policy returned %v", err)
			}
		})
	}

	legacy := validReserveInput(t)
	legacy.Rules[0].Capacity = 1
	if _, err := prepareRequest(legacy); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("calendar rule with token fields returned %v", err)
	}
}

func TestTokenBucketReservationHasNoCalendarReset(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	bucketID, err := id.New(id.QuotaBucket)
	if err != nil {
		t.Fatal(err)
	}
	entryID, err := id.New(id.QuotaEntry)
	if err != nil {
		t.Fatal(err)
	}
	reservationID, err := id.New(id.QuotaReservation)
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{
		organizationID: input.OrganizationID, applicationID: input.ApplicationID,
		environmentID: input.EnvironmentID, logicalRequestID: input.LogicalRequestID.String(),
		reservationID: reservationID, routeKey: input.RouteKey, upstreamKey: input.UpstreamKey,
		modelKey: input.ModelKey, physicalModel: input.PhysicalModel,
		expiresAt: time.Now().UTC().Add(time.Minute),
		entries: []reservationEntry{{
			bucketID: bucketID, entryID: entryID, metric: LogicalRequestsMetric,
			algorithm: TokenBucketAlgorithm, reservedUnits: 1,
		}},
	}
	if err := reservation.validate(); err != nil || !reservation.ResetAt().IsZero() {
		t.Fatalf("valid token reservation reset=%s: %v", reservation.ResetAt(), err)
	}
	reservation.entries[0].metric = OutputTokensMetric
	reservation.entries[0].reservedUnits = maximumTokenCapacity
	if err := reservation.validate(); err != nil || !reservation.ResetAt().IsZero() {
		t.Fatalf("valid output token reservation reset=%s: %v", reservation.ResetAt(), err)
	}
	reservation.entries[0].reservedUnits++
	if err := reservation.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized output token reservation returned %v", err)
	}
	reservation.entries[0].reservedUnits = 64
	reservation.entries[0].resetAt = time.Now().UTC()
	reservation.windowResetAt = reservation.entries[0].resetAt
	if err := reservation.validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("token reservation with fabricated reset returned %v", err)
	}
}

func TestOutcomeValidation(t *testing.T) {
	t.Parallel()
	for _, outcome := range []Outcome{
		{Status: AttemptSucceeded, HTTPStatus: 200},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
			Known: true, Provenance: ProviderReportedProvenance,
		}},
		{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable"},
		{Status: AttemptSucceeded, HTTPStatus: 200, Cost: Cost{
			NanoUSD: 7, Known: true, Confidence: ProviderReportedCostConfidence,
			Currency: USDCurrency, Source: ProviderReportedCostSource,
		}},
		{Status: AttemptCancelled, FailureCode: "client_cancelled"},
		{Status: AttemptTimedOut, FailureCode: "upstream_timeout"},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 1, OutputTokens: 0, TotalTokens: 1,
			Known: true, Provenance: ProviderReportedProvenance,
		}, Cost: Cost{NanoUSD: 0, Known: true, Confidence: CalculatedCostConfidence}},
		{Status: AttemptFailed, FailureCode: "calculation_overflow", Usage: Usage{
			InputTokens: 1, TotalTokens: 1, Known: true, Provenance: ProviderReportedProvenance,
		}, Cost: Cost{Confidence: UnknownCostConfidence}},
	} {
		if err := outcome.validate(); err != nil {
			t.Fatalf("valid outcome %#v: %v", outcome, err)
		}
	}
	for _, outcome := range []Outcome{
		{},
		{Status: AttemptSucceeded},
		{Status: AttemptSucceeded, HTTPStatus: 199},
		{Status: AttemptSucceeded, HTTPStatus: 302},
		{Status: AttemptSucceeded, HTTPStatus: 500},
		{Status: AttemptSucceeded, FailureCode: "unexpected"},
		{Status: AttemptFailed},
		{Status: AttemptFailed, HTTPStatus: 99, FailureCode: "failed"},
		{Status: AttemptTimedOut, FailureCode: "Bad Code"},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: -1, TotalTokens: 1, Known: true,
			Provenance: ProviderReportedProvenance,
		}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 1, OutputTokens: 1, TotalTokens: 2, Known: true,
			Provenance: "estimated",
		}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			OutputTokens: 1, Known: false, Provenance: UnknownUsageProvenance,
		}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 1, TotalTokens: 1, Known: true, Provenance: ProviderReportedProvenance,
		}, Cost: Cost{NanoUSD: -1, Known: true, Confidence: CalculatedCostConfidence}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 1, TotalTokens: 1, Known: true, Provenance: ProviderReportedProvenance,
		}, Cost: Cost{NanoUSD: 1, Known: true}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 1, TotalTokens: 1, Known: true, Provenance: ProviderReportedProvenance,
		}, Cost: Cost{NanoUSD: 1, Confidence: UnknownCostConfidence}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Cost: Cost{
			NanoUSD: 1, Known: true, Confidence: CalculatedCostConfidence,
		}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Cost: Cost{Confidence: "estimated"}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Cost: Cost{
			NanoUSD: 1, Known: true, Confidence: ProviderReportedCostConfidence,
		}},
		{Status: AttemptSucceeded, HTTPStatus: 200, Cost: Cost{
			NanoUSD: 1, Known: true, Confidence: ProviderReportedCostConfidence,
			Currency: USDCurrency, Source: "other",
		}},
	} {
		if err := outcome.validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid outcome %#v returned %v", outcome, err)
		}
	}
}

func TestOutcomePricingNormalizationIsContextBound(t *testing.T) {
	t.Parallel()
	knownUsage := Usage{
		InputTokens: 2, OutputTokens: 3, TotalTokens: 5,
		Known: true, Provenance: ProviderReportedProvenance,
	}
	priced := selectedPricing{
		source: "standard-usd", currency: USDCurrency,
		revision: validReserveInput(t).ConfigRevisionID,
	}
	unknown, err := normalizeOutcomeForPricing(Outcome{
		Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
	}, priced)
	if err != nil || unknown.Cost != (Cost{Confidence: UnknownCostConfidence}) {
		t.Fatalf("normalize priced unknown cost = %#v, %v", unknown, err)
	}
	legacy, err := normalizeOutcomeForPricing(Outcome{
		Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
		Cost: Cost{Confidence: UnknownCostConfidence},
	}, selectedPricing{})
	if err != nil || legacy.Cost != (Cost{}) {
		t.Fatalf("normalize unpriced unknown cost = %#v, %v", legacy, err)
	}
	if _, err := normalizeOutcomeForPricing(Outcome{
		Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
		Cost: Cost{NanoUSD: 1, Known: true, Confidence: CalculatedCostConfidence},
	}, selectedPricing{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("known unpriced cost returned %v", err)
	}
	reported := Cost{
		NanoUSD: 7, Known: true, Confidence: ProviderReportedCostConfidence,
		Currency: USDCurrency, Source: ProviderReportedCostSource,
	}
	providerOutcome, err := normalizeOutcomeForPricing(Outcome{
		Status: AttemptSucceeded, HTTPStatus: 200, Cost: reported,
	}, selectedPricing{})
	if err != nil || providerOutcome.Cost != reported {
		t.Fatalf("unpriced provider-reported cost = %#v, %v", providerOutcome, err)
	}
}

func validReserveInput(t *testing.T) ReserveInput {
	t.Helper()
	mustID := func(prefix id.Prefix) string {
		value, err := id.New(prefix)
		if err != nil {
			t.Fatalf("generate %s ID: %v", prefix, err)
		}
		return value
	}
	return ReserveInput{
		LogicalRequestID: mustLogicalID(t),
		OrganizationID:   mustID(id.Organization), ApplicationID: mustID(id.Application),
		EnvironmentID: mustID(id.Environment), ApplicationUserID: mustID(id.ApplicationUser),
		InstallationID: mustID(id.Installation), SessionGrantID: mustID(id.SessionGrant),
		ConfigRevisionID: mustID(id.ConfigRevision), FeatureKey: "assistant",
		Protocol: "openai_chat", ClientRequestID: "client-hint-123",
		LimitPlanKey: "free", RouteKey: "primary", UpstreamKey: "openrouter",
		ModelKey: "fast", PhysicalModel: "provider/model-v1",
		Rules: []Rule{{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: 5, Hard: true,
		}},
	}
}

func mustLogicalID(t *testing.T) requestidentity.LogicalID {
	t.Helper()
	ctx, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatalf("generate logical request identity: %v", err)
	}
	logicalID, ok := requestidentity.FromContext(ctx)
	if !ok {
		t.Fatal("generated logical request identity is missing")
	}
	return logicalID
}

func cloneReserveInput(input ReserveInput) ReserveInput {
	result := input
	if input.InputPreflight != nil {
		binding := *input.InputPreflight
		result.InputPreflight = &binding
	}
	if input.RequestMeasurements != nil {
		binding := *input.RequestMeasurements
		result.RequestMeasurements = &binding
	}
	result.NormalizedClaimDigests = cloneStringMap(input.NormalizedClaimDigests)
	result.Rules = append([]Rule(nil), input.Rules...)
	for index := range result.Rules {
		result.Rules[index].Scope = append([]string(nil), input.Rules[index].Scope...)
	}
	return result
}

func trustedInputPreflight(input ReserveInput, inputTokens, outputTokens int64) *InputPreflightBinding {
	profileDigest := sha256.Sum256([]byte("test-input-accounting-profile-v1"))
	bodyDigest := sha256.Sum256([]byte("rewritten:" + input.LogicalRequestID.String()))
	totalTokens := inputTokens + outputTokens
	return &InputPreflightBinding{
		Method: UTF8ByteBPEDeclaredFramingV1, Protocol: input.Protocol, ProfileID: "test-profile",
		ProfileDigest: profileDigest, RewrittenBodySHA256: bodyDigest,
		PhysicalModel: input.PhysicalModel, InputTokenBound: inputTokens,
		OutputTokenBound: outputTokens, TotalTokenBound: totalTokens,
	}
}
