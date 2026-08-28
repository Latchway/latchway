package quota

import (
	"errors"
	"testing"
	"time"
)

func TestPrepareSnapshotAcceptsOnlyCalendarInputAndTotalTokenRules(t *testing.T) {
	t.Parallel()

	for _, metric := range []string{InputTokensMetric, TotalTokensMetric} {
		metric := metric
		t.Run(metric, func(t *testing.T) {
			t.Parallel()
			input := validSnapshotInput(t)
			input.Rules = []Rule{{
				Metric: metric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user", "feature"}, Window: "1d",
				Maximum: 100, Hard: true,
			}}
			prepared, err := prepareSnapshot(input)
			if err != nil {
				t.Fatalf("prepare %s calendar snapshot: %v", metric, err)
			}
			if len(prepared.rules) != 1 || !prepared.rules[0].stateful ||
				prepared.rules[0].Metric != metric ||
				prepared.rules[0].Algorithm != CalendarAlgorithm {
				t.Fatalf("prepared %s rule = %#v", metric, prepared.rules)
			}

			for _, rule := range []Rule{
				{
					Metric: metric, Algorithm: TokenBucketAlgorithm,
					Scope: []string{"user"}, Capacity: 100,
					RefillNumerator: 1, RefillDenominator: 1, Hard: true,
				},
				{
					Metric: metric, Algorithm: PerRequestAlgorithm,
					Scope: []string{"user"}, PerRequestMaximum: 100, Hard: true,
				},
			} {
				input.Rules = []Rule{rule}
				if _, err := prepareSnapshot(input); !errors.Is(err, ErrInvalidInput) {
					t.Errorf("%s/%s snapshot = %v, want ErrInvalidInput", metric, rule.Algorithm, err)
				}
			}
		})
	}
}

func TestLimitSnapshotProjectsInputAndTotalCalendarStateGenerically(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.August, 28, 9, 1, 2, 0, time.UTC)
	for _, metric := range []string{InputTokensMetric, TotalTokensMetric} {
		metric := metric
		t.Run(metric, func(t *testing.T) {
			t.Parallel()
			input := validSnapshotInput(t)
			input.Rules = []Rule{{
				Metric: metric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user"}, Window: "1d",
				Maximum: 100, Hard: true,
			}}
			prepared, err := prepareSnapshot(input)
			if err != nil {
				t.Fatalf("prepare %s snapshot: %v", metric, err)
			}
			plans, err := snapshotPlansAt(prepared.rules, observedAt)
			if err != nil || len(plans) != 1 {
				t.Fatalf("plan %s snapshot = (%#v, %v)", metric, plans, err)
			}
			plan := plans[0]

			pristine, err := limitSnapshotAt(plan, observedAt)
			if err != nil {
				t.Fatalf("project pristine %s calendar state: %v", metric, err)
			}
			if pristine.Maximum == nil || *pristine.Maximum != 100 ||
				pristine.Used == nil || *pristine.Used != 0 ||
				pristine.Reserved == nil || *pristine.Reserved != 0 ||
				pristine.Remaining == nil || *pristine.Remaining != 100 ||
				pristine.ResetsAt == nil || !pristine.ResetsAt.Equal(plan.period.end) {
				t.Fatalf("pristine %s limit = %#v", metric, pristine)
			}

			maximum, used, reserved := int64(100), int64(24), int64(6)
			bucket := lockedBucket{
				id:          "qbk_00000000000000000000000001",
				hardMaximum: &maximum, used: used, reserved: reserved,
				scopeType: plan.rule.scopeType, scopeDimensions: plan.rule.scopeDimensions,
			}
			if err := validateSnapshotBucket(
				prepared, plan, bucket, input.OrganizationID, input.ApplicationID,
			); err != nil {
				t.Fatalf("validate %s generic calendar bucket: %v", metric, err)
			}
			before := bucket
			plan.bucket = &bucket

			limit, err := limitSnapshotAt(plan, observedAt)
			if err != nil {
				t.Fatalf("project %s calendar state: %v", metric, err)
			}
			if limit.Metric != metric || limit.Maximum == nil || *limit.Maximum != maximum ||
				limit.Used == nil || *limit.Used != used ||
				limit.Reserved == nil || *limit.Reserved != reserved ||
				limit.Remaining == nil || *limit.Remaining != maximum-used-reserved ||
				limit.ResetsAt == nil || !limit.ResetsAt.Equal(plan.period.end) || !limit.Hard {
				t.Fatalf("%s limit = %#v", metric, limit)
			}
			if bucket.hardMaximum != before.hardMaximum || *bucket.hardMaximum != maximum ||
				bucket.used != before.used || bucket.reserved != before.reserved {
				t.Fatalf("%s snapshot mutated bucket in memory", metric)
			}

			refilledAt := observedAt
			corrupt := bucket
			corrupt.refilledAt = &refilledAt
			if err := validateSnapshotBucket(
				prepared, plan, corrupt, input.OrganizationID, input.ApplicationID,
			); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("corrupt %s calendar bucket = %v, want ErrInvalidState", metric, err)
			}
		})
	}
}
