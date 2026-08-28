package quota

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestPrepareSnapshotSharesCanonicalRuleAndScopeIdentity(t *testing.T) {
	t.Parallel()
	reserve := validReserveInput(t)
	reserve.Rules = []Rule{
		{
			Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"feature", "user"}, Window: "1d",
			Maximum: 100, ReservedUnits: 8, Hard: true,
		},
		{
			Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
			Scope: []string{"environment", "user"}, Capacity: 4,
			RefillNumerator: 1, RefillDenominator: 2, Hard: true,
		},
	}
	preparedReserve, err := prepareRequest(reserve)
	if err != nil {
		t.Fatalf("prepare reservation: %v", err)
	}
	snapshot := snapshotInputFromReserve(reserve)
	for index := range snapshot.Rules {
		snapshot.Rules[index].ReservedUnits = 0
	}
	preparedSnapshot, err := prepareSnapshot(snapshot)
	if err != nil {
		t.Fatalf("prepare snapshot: %v", err)
	}
	if len(preparedSnapshot.rules) != len(preparedReserve.rules) {
		t.Fatalf("snapshot rules = %d, want %d", len(preparedSnapshot.rules), len(preparedReserve.rules))
	}
	for index := range preparedReserve.rules {
		reserveRule, snapshotRule := preparedReserve.rules[index], preparedSnapshot.rules[index]
		if reserveRule.ruleKey != snapshotRule.ruleKey || reserveRule.scopeKey != snapshotRule.scopeKey ||
			!slices.Equal(reserveRule.scopeDimensions, snapshotRule.scopeDimensions) {
			t.Fatalf("canonical identity %d drifted between reserve and snapshot", index)
		}
	}
}

func TestPrepareSnapshotAcceptsEveryExecutablePolicyShapeWithoutReservation(t *testing.T) {
	t.Parallel()
	input := validSnapshotInput(t)
	input.Rules = []Rule{
		{Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm, Scope: []string{"user"}, Window: "1h", Maximum: 10, Hard: true},
		{Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm, Scope: []string{"feature"}, Capacity: 5, RefillNumerator: 1, RefillDenominator: 2, Hard: true},
		{Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm, Scope: []string{"installation"}, Window: "1d", Maximum: 100, Hard: true},
		{Metric: OutputTokensMetric, Algorithm: TokenBucketAlgorithm, Scope: []string{"environment"}, Capacity: 200, RefillNumerator: 3, RefillDenominator: 4, Hard: true},
		{Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm, Scope: []string{"application"}, PerRequestMaximum: 25, Hard: true},
		{Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm, Scope: []string{"organization"}, Maximum: 2, Hard: true},
		{Metric: ConcurrentStreamsMetric, Algorithm: ConcurrencyAlgorithm, Scope: []string{"user", "feature"}, Maximum: 1, Hard: true},
	}
	prepared, err := prepareSnapshot(input)
	if err != nil {
		t.Fatalf("prepare every snapshot rule shape: %v", err)
	}
	if len(prepared.rules) != len(input.Rules) {
		t.Fatalf("prepared rules = %d, want %d", len(prepared.rules), len(input.Rules))
	}

	for index := range input.Rules {
		invalid := input
		invalid.Rules = cloneRules(input.Rules)
		invalid.Rules[index].ReservedUnits = 1
		if _, err := prepareSnapshot(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("rule %d accepted nonzero snapshot reservation: %v", index, err)
		}
	}
}

func TestPrepareSnapshotValidatesOptionalScopeValuesOnlyWhenReferenced(t *testing.T) {
	t.Parallel()
	input := validSnapshotInput(t)
	input.RouteKey, input.UpstreamKey, input.ModelKey = "", "NOT AN ID", ""
	if _, err := prepareSnapshot(input); err != nil {
		t.Fatalf("unused optional scope values rejected: %v", err)
	}

	for _, dimension := range []string{"route", "upstream", "model"} {
		scoped := input
		scoped.Rules = cloneRules(input.Rules)
		scoped.Rules[0].Scope = append(scoped.Rules[0].Scope, dimension)
		if _, err := prepareSnapshot(scoped); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("missing/invalid %s scope value accepted: %v", dimension, err)
		}
	}

	input.RouteKey, input.UpstreamKey, input.ModelKey = "primary", "provider", "fast"
	input.Rules[0].Scope = []string{"route", "upstream", "model"}
	if _, err := prepareSnapshot(input); err != nil {
		t.Fatalf("valid optional scopes rejected: %v", err)
	}
}

func TestSnapshotPlansArePrivateDeterministicAndIncludeStreams(t *testing.T) {
	t.Parallel()
	input := validSnapshotInput(t)
	input.Rules = []Rule{
		{Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm, Scope: []string{"user"}, PerRequestMaximum: 12, Hard: true},
		{Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm, Scope: []string{"feature"}, Window: "1h", Maximum: 3, Hard: true},
		{Metric: ConcurrentStreamsMetric, Algorithm: ConcurrencyAlgorithm, Scope: []string{"user"}, Maximum: 1, Hard: true},
		{Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm, Scope: []string{"user"}, Window: "1d", Maximum: 5, Hard: true},
	}
	prepared, err := prepareSnapshot(input)
	if err != nil {
		t.Fatalf("prepare snapshot: %v", err)
	}
	at := time.Date(2026, time.August, 28, 9, 0, 0, 0, time.UTC)
	plans, err := snapshotPlansAt(prepared.rules, at)
	if err != nil {
		t.Fatalf("plan snapshot: %v", err)
	}
	wantMetrics := []string{ConcurrentStreamsMetric, LogicalRequestsMetric, LogicalRequestsMetric, OutputTokensMetric}
	gotMetrics := make([]string, len(plans))
	for index := range plans {
		gotMetrics[index] = plans[index].rule.Metric
	}
	if !slices.Equal(gotMetrics, wantMetrics) {
		t.Fatalf("metric order = %v, want %v", gotMetrics, wantMetrics)
	}
	if plans[0].period.key != "active" {
		t.Fatalf("stream rule was not planned unconditionally: %#v", plans[0])
	}
	for index := 1; index < len(plans); index++ {
		left, right := plans[index-1], plans[index]
		if left.rule.Metric == right.rule.Metric &&
			(left.rule.ruleKey > right.rule.ruleKey ||
				(left.rule.ruleKey == right.rule.ruleKey && left.rule.scopeKey > right.rule.scopeKey)) {
			t.Fatal("same-metric snapshot rules are not in private identity order")
		}
	}
}

func TestLimitSnapshotMissingAndPerRequestSemantics(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, time.August, 28, 9, 1, 2, 345_000_000, time.UTC)
	calendarPeriod, err := calendarWindow(at, "1h")
	if err != nil {
		t.Fatalf("calendar window: %v", err)
	}
	tests := []struct {
		name  string
		plan  snapshotPlan
		max   int64
		used  *int64
		res   *int64
		rem   *int64
		reset bool
	}{
		{
			name: "calendar missing is pristine",
			plan: snapshotPlan{rule: preparedRule{Rule: Rule{Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm, Maximum: 8, Hard: true}, stateful: true}, period: calendarPeriod},
			max:  8, used: pointerInt64(0), res: pointerInt64(0), rem: pointerInt64(8), reset: true,
		},
		{
			name: "token missing is full",
			plan: snapshotPlan{rule: preparedRule{Rule: Rule{Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm, Capacity: 6, Hard: true}, stateful: true}},
			max:  6, used: pointerInt64(0), res: pointerInt64(0), rem: pointerInt64(6),
		},
		{
			name: "concurrency missing is empty",
			plan: snapshotPlan{rule: preparedRule{Rule: Rule{Metric: ConcurrentStreamsMetric, Algorithm: ConcurrencyAlgorithm, Maximum: 2, Hard: true}, stateful: true}},
			max:  2, used: pointerInt64(0), res: pointerInt64(0), rem: pointerInt64(2),
		},
		{
			name: "per request is metadata only",
			plan: snapshotPlan{rule: preparedRule{Rule: Rule{Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm, PerRequestMaximum: 24, Hard: true}}},
			max:  24,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limit, err := limitSnapshotAt(test.plan, at)
			if err != nil {
				t.Fatalf("snapshot limit: %v", err)
			}
			if limit.Maximum == nil || *limit.Maximum != test.max || !sameOptionalInt64(limit.Used, test.used) ||
				!sameOptionalInt64(limit.Reserved, test.res) || !sameOptionalInt64(limit.Remaining, test.rem) ||
				(limit.ResetsAt != nil) != test.reset || !limit.Hard {
				t.Fatalf("limit = %#v", limit)
			}
		})
	}
}

func TestLimitSnapshotUsesFractionalTokenQuantaWithoutMutation(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, time.August, 28, 9, 0, 0, 500_000, time.UTC)
	refilledAt := at.Add(-500 * time.Microsecond)
	maximum := int64(2)
	available := int64(0)
	numerator, denominator := int64(1_000), int64(1)
	bucket := lockedBucket{
		id: "qbk_00000000000000000000000001", hardMaximum: &maximum,
		available: &available, refillNumerator: &numerator, refillDenominator: &denominator,
		refilledAt: &refilledAt,
	}
	before := bucket
	plan := snapshotPlan{
		rule: preparedRule{Rule: Rule{
			Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
			Capacity: 2, RefillNumerator: 1_000, RefillDenominator: 1, Hard: true,
		}, stateful: true},
		bucket: &bucket,
	}
	limit, err := limitSnapshotAt(plan, at)
	if err != nil {
		t.Fatalf("fractional token snapshot: %v", err)
	}
	// 1,000 tokens/second earns exactly 0.5 tokens in 500 microseconds. The
	// public contract exposes whole usable tokens only, so remaining floors to
	// zero and the unavailable fraction remains conservatively counted as used.
	if *limit.Maximum != 2 || *limit.Used != 2 || *limit.Reserved != 0 || *limit.Remaining != 0 || limit.ResetsAt != nil {
		t.Fatalf("fractional token limit = %#v", limit)
	}
	if bucket.available != before.available || *bucket.available != available ||
		bucket.refilledAt != before.refilledAt || !bucket.refilledAt.Equal(refilledAt) {
		t.Fatal("token snapshot mutated durable state in memory")
	}
}

func TestLimitSnapshotConservativelyReconcilesPolicyTransitions(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, time.August, 28, 9, 0, 0, 0, time.UTC)
	refilledAt := at.Add(-time.Second)
	oldMaximum := int64(1)
	oldBalance := tokenBalanceScale
	oldNumerator, oldDenominator := int64(1), int64(1)
	bucket := lockedBucket{
		hardMaximum: &oldMaximum, available: &oldBalance,
		refillNumerator: &oldNumerator, refillDenominator: &oldDenominator,
		refilledAt: &refilledAt,
	}
	plan := snapshotPlan{
		rule: preparedRule{Rule: Rule{
			Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
			Capacity: 3, RefillNumerator: 2, RefillDenominator: 1, Hard: true,
		}, stateful: true},
		bucket: &bucket,
	}
	limit, err := limitSnapshotAt(plan, at)
	if err != nil {
		t.Fatalf("policy transition snapshot: %v", err)
	}
	if *limit.Maximum != 3 || *limit.Used != 2 || *limit.Remaining != 1 {
		t.Fatalf("increased-capacity limit = %#v, want conservative 3/2/1", limit)
	}

	used, reserved, storedMaximum := int64(7), int64(2), int64(10)
	calendar := snapshotPlan{
		rule:   preparedRule{Rule: Rule{Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm, Maximum: 5, Hard: true}, stateful: true},
		period: calendarPeriod{end: at.Add(time.Hour)},
		bucket: &lockedBucket{hardMaximum: &storedMaximum, used: used, reserved: reserved},
	}
	limit, err = limitSnapshotAt(calendar, at)
	if err != nil {
		t.Fatalf("decreased calendar maximum: %v", err)
	}
	if *limit.Maximum != 5 || *limit.Used != 7 || *limit.Reserved != 2 || *limit.Remaining != 0 {
		t.Fatalf("decreased calendar limit = %#v", limit)
	}
}

func validSnapshotInput(t *testing.T) SnapshotInput {
	t.Helper()
	return snapshotInputFromReserve(validReserveInput(t))
}

func snapshotInputFromReserve(input ReserveInput) SnapshotInput {
	rules := cloneRules(input.Rules)
	return SnapshotInput{
		OrganizationID: input.OrganizationID, ApplicationID: input.ApplicationID,
		EnvironmentID: input.EnvironmentID, ApplicationUserID: input.ApplicationUserID,
		InstallationID: input.InstallationID, ConfigRevisionID: input.ConfigRevisionID,
		FeatureKey: input.FeatureKey, LimitPlanKey: input.LimitPlanKey,
		RouteKey: input.RouteKey, UpstreamKey: input.UpstreamKey, ModelKey: input.ModelKey,
		Rules: rules,
	}
}

func cloneRules(input []Rule) []Rule {
	result := make([]Rule, len(input))
	for index := range input {
		result[index] = input[index]
		result[index].Scope = append([]string(nil), input[index].Scope...)
	}
	return result
}

func pointerInt64(value int64) *int64 { return &value }

func sameOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
