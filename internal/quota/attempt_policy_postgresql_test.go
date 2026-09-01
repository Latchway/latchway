package quota

import (
	"errors"
	"testing"
)

func TestStorePostgreSQLUpstreamAttemptLimitsChargeDispatchesAtomically(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	tests := []struct {
		name                 string
		rule                 Rule
		wantAttemptQuotaRows int64
	}{
		{
			name: "calendar",
			rule: Rule{
				Metric: UpstreamAttemptsMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user", "feature"}, Window: "1d", Maximum: 2, Hard: true,
			},
			wantAttemptQuotaRows: 2,
		},
		{
			name: "token_bucket",
			rule: Rule{
				Metric: UpstreamAttemptsMetric, Algorithm: TokenBucketAlgorithm,
				Scope: []string{"user", "feature"}, Capacity: 2,
				RefillNumerator: 1, RefillDenominator: tokenRateDecimalScale, Hard: true,
			},
			wantAttemptQuotaRows: 2,
		},
		{
			name: "per_request",
			rule: Rule{
				Metric: UpstreamAttemptsMetric, Algorithm: PerRequestAlgorithm,
				Scope: []string{"user", "feature"}, PerRequestMaximum: 2, Hard: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := fixture.input(t, "attempt-policy-"+test.name, 100)
			input.LimitPlanKey = "attempt-policy-" + test.name
			input.Rules = append(input.Rules, test.rule)
			reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
			failed := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
			if err := fixture.store.SettleForRetry(fixture.ctx, first, failed); err != nil {
				t.Fatalf("settle first attempt: %v", err)
			}

			retry := RetryAttemptInput{
				RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
				PhysicalModel: "provider/model-v2",
			}
			second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retry)
			if err != nil || !owner || second.Number() != 2 {
				t.Fatalf("begin second attempt = %#v owner=%t: %v", second, owner, err)
			}
			if err := fixture.store.SettleForRetry(fixture.ctx, second, failed); err != nil {
				t.Fatalf("settle second attempt: %v", err)
			}

			if _, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, second, retry); !errors.Is(err, ErrExceeded) || owner {
				t.Fatalf("third attempt denial owner=%t err=%v, want atomic ErrExceeded", owner, err)
			}
			if got := fixture.count(t, `
				SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1
			`, input.LogicalRequestID.String()); got != 2 {
				t.Fatalf("physical attempts after denial = %d, want 2", got)
			}
			if got := fixture.count(t, `
				SELECT count(*) FROM upstream_attempt_quota_entries
				WHERE logical_request_id = $1 AND metric = 'upstream_attempts'
			`, input.LogicalRequestID.String()); got != test.wantAttemptQuotaRows {
				t.Fatalf("attempt quota rows = %d, want %d", got, test.wantAttemptQuotaRows)
			}
			if test.rule.Algorithm != PerRequestAlgorithm {
				var reserved, settled, released, used, bucketReserved int64
				if err := fixture.pool.QueryRow(fixture.ctx, `
					SELECT entry.reserved_units, entry.settled_units, entry.released_units,
					       bucket.used_units, bucket.reserved_units
					FROM quota_reservation_entries AS entry
					JOIN quota_buckets AS bucket USING (quota_bucket_id)
					WHERE entry.quota_reservation_id = $1
					  AND bucket.metric = 'upstream_attempts'
				`, reservation.ID()).Scan(&reserved, &settled, &released, &used, &bucketReserved); err != nil {
					t.Fatalf("read attempt quota state: %v", err)
				}
				wantUsed := int64(2)
				if test.rule.Algorithm == TokenBucketAlgorithm {
					// Token buckets debit fixed-point availability rather than the
					// calendar used/reserved counters.
					wantUsed = 0
				}
				if reserved != 2 || settled != 2 || released != 0 || used != wantUsed || bucketReserved != 0 {
					t.Fatalf("attempt quota state = %d/%d/%d bucket=%d/%d, want 2/2/0 bucket=%d/0",
						reserved, settled, released, used, bucketReserved, wantUsed)
				}
			}
			if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, failed); err != nil {
				t.Fatalf("finalize denied retry sequence: %v", err)
			}
			if got := fixture.count(t, `
				SELECT count(*) FROM usage_records
				WHERE logical_request_id = $1 AND metric = 'logical_requests'
			`, input.LogicalRequestID.String()); got != 1 {
				t.Fatalf("logical request usage = %d, want exactly 1", got)
			}
		})
	}
}

func TestStorePostgreSQLUserCostCanChargeInitialAttemptWhileOrganizationChargesAll(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	input := fixture.input(t, "cost-retry-treatment", 100)
	input.LimitPlanKey = "cost-retry-treatment"
	input.Pricing = PricingSelection{CatalogID: "output-only", Currency: USDCurrency}
	input.Rules = append(input.Rules,
		Rule{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"organization"}, Window: "1d", Maximum: 100,
			ReservedUnits: 10, CostRetryTreatment: ActualAttemptsCostRetryTreatment, Hard: true,
		},
		Rule{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 100,
			ReservedUnits: 10, CostRetryTreatment: InitialAttemptOnlyCostRetryTreatment, Hard: true,
		},
	)
	reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
	firstOutcome := Outcome{
		Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy",
		Cost: Cost{
			NanoUSD: 4, Known: true, Confidence: ProviderReportedCostConfidence,
			Currency: USDCurrency, Source: ProviderReportedCostSource,
		},
	}
	if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
		t.Fatalf("settle first priced attempt: %v", err)
	}
	retry := RetryAttemptInput{
		RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
		PhysicalModel: "provider/model-v2",
		Pricing:       PricingSelection{CatalogID: "output-only", Currency: USDCurrency},
		Allocations:   []AttemptAllocation{{Metric: CostNanoUSDMetric, Units: 10}},
	}
	second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retry)
	if err != nil || !owner {
		t.Fatalf("begin priced retry owner=%t: %v", owner, err)
	}
	changedRetry := retry
	changedRetry.Allocations = []AttemptAllocation{{Metric: CostNanoUSDMetric, Units: 20}}
	if _, replayOwner, replayErr := fixture.store.BeginRetryAttempt(
		fixture.ctx, first, changedRetry,
	); !errors.Is(replayErr, ErrInvalidState) || replayOwner {
		t.Fatalf("changed retry allocation replay owner=%t err=%v, want ErrInvalidState", replayOwner, replayErr)
	}
	secondOutcome := Outcome{
		Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy",
		Cost: Cost{
			NanoUSD: 7, Known: true, Confidence: ProviderReportedCostConfidence,
			Currency: USDCurrency, Source: ProviderReportedCostSource,
		},
	}
	overBoundOutcome := secondOutcome
	overBoundOutcome.Cost.NanoUSD = 11
	if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, overBoundOutcome); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("retry cost above bound error = %v, want ErrInvalidInput", err)
	}
	if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
		t.Fatalf("settle final priced retry: %v", err)
	}

	type state struct {
		reserved int64
		settled  int64
		released int64
		used     int64
		rows     int64
	}
	states := make(map[string]state)
	rows, err := fixture.pool.Query(fixture.ctx, `
		SELECT entry.cost_retry_treatment, entry.reserved_units,
		       entry.settled_units, entry.released_units, bucket.used_units,
		       (SELECT count(*) FROM upstream_attempt_quota_entries AS quota
		        WHERE quota.quota_reservation_entry_id = entry.quota_reservation_entry_id)
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE entry.quota_reservation_id = $1 AND bucket.metric = 'cost_nano_usd'
	`, reservation.ID())
	if err != nil {
		t.Fatalf("read cost retry states: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var treatment string
		var value state
		if err := rows.Scan(
			&treatment, &value.reserved, &value.settled, &value.released, &value.used, &value.rows,
		); err != nil {
			t.Fatalf("scan cost retry state: %v", err)
		}
		states[treatment] = value
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate cost retry states: %v", err)
	}
	if got := states[ActualAttemptsCostRetryTreatment]; got != (state{reserved: 20, settled: 11, released: 9, used: 11, rows: 2}) {
		t.Fatalf("organization actual-attempt cost = %+v", got)
	}
	if got := states[InitialAttemptOnlyCostRetryTreatment]; got != (state{reserved: 10, settled: 4, released: 6, used: 4, rows: 1}) {
		t.Fatalf("user initial-only cost = %+v", got)
	}
	var usageCost int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT COALESCE(sum(units), 0) FROM usage_records
		WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'
	`, input.LogicalRequestID.String()).Scan(&usageCost); err != nil {
		t.Fatalf("read physical cost usage: %v", err)
	}
	if usageCost != 11 {
		t.Fatalf("physical attempt cost usage = %d, want 11", usageCost)
	}
}
