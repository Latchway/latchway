package quota

import (
	"errors"
	"sync"
	"testing"
)

func TestStorePostgreSQLHardCostLifecycle(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)
	knownUsage := Usage{Known: true, Provenance: ProviderReportedProvenance}

	t.Run("known success and failure settle actual cost and replay exactly", func(t *testing.T) {
		tests := []struct {
			feature string
			outcome Outcome
			cost    int64
		}{
			{
				feature: "cost-known-success", cost: 7,
				outcome: Outcome{
					Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
					Cost: Cost{NanoUSD: 7, Known: true, Confidence: CalculatedCostConfidence},
				},
			},
			{
				feature: "cost-known-failure", cost: 9,
				outcome: Outcome{
					Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_protocol_error",
					Usage: knownUsage,
					Cost:  Cost{NanoUSD: 9, Known: true, Confidence: CalculatedCostConfidence},
				},
			},
		}
		for _, test := range tests {
			t.Run(test.feature, func(t *testing.T) {
				input := fixture.hardCostInput(t, test.feature, 100, 25)
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				if err != nil {
					t.Fatalf("reserve hard cost: %v", err)
				}
				attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
				if err != nil || !owner {
					t.Fatalf("begin hard cost attempt owner=%t: %v", owner, err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, test.outcome); err != nil {
					t.Fatalf("settle hard cost: %v", err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, test.outcome); err != nil {
					t.Fatalf("replay hard cost settlement: %v", err)
				}
				state := fixture.readHardCostState(t, reservation.ID())
				if state.reservedEntry != 25 || state.settledEntry != test.cost ||
					state.releasedEntry != 25-test.cost || state.bucketUsed != test.cost ||
					state.bucketReserved != 0 || state.reservationStatus != "settled" {
					t.Fatalf("known hard cost state = %#v", state)
				}
				assertConfiguredCostUsage(
					t, fixture, input.LogicalRequestID.String(), attempt.ID(), test.cost, "hard-cost-usd",
				)
			})
		}
	})

	t.Run("unknown post-dispatch cost charges the full reservation", func(t *testing.T) {
		input := fixture.hardCostInput(t, "cost-unknown", 100, 25)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve unknown hard cost: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin unknown hard cost owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable",
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle unknown hard cost: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("replay unknown hard cost: %v", err)
		}
		state := fixture.readHardCostState(t, reservation.ID())
		if state.settledEntry != 25 || state.releasedEntry != 0 ||
			state.bucketUsed != 25 || state.bucketReserved != 0 {
			t.Fatalf("unknown hard cost state = %#v", state)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records
			WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'
		`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("unknown hard cost usage rows = %d, want 0", got)
		}
	})

	t.Run("known cost above reservation fails closed without mutation", func(t *testing.T) {
		input := fixture.hardCostInput(t, "cost-over-reservation", 100, 25)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve capped hard cost: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin capped hard cost owner=%t: %v", owner, err)
		}
		over := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{
				NanoUSD: 26, Known: true, Confidence: ProviderReportedCostConfidence,
				Currency: USDCurrency, Source: ProviderReportedCostSource,
			},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, over); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("over-reservation hard cost = %v, want ErrInvalidInput", err)
		}
		state := fixture.readHardCostState(t, reservation.ID())
		if state.settledEntry != 0 || state.releasedEntry != 0 ||
			state.bucketUsed != 0 || state.bucketReserved != 25 ||
			state.reservationStatus != "pending" {
			t.Fatalf("mutated over-reservation hard cost state = %#v", state)
		}
		unknown := Outcome{Status: AttemptTimedOut, FailureCode: "cost_overflow"}
		if err := fixture.store.Settle(fixture.ctx, attempt, unknown); err != nil {
			t.Fatalf("conservatively settle rejected hard cost: %v", err)
		}
		state = fixture.readHardCostState(t, reservation.ID())
		if state.settledEntry != 25 || state.releasedEntry != 0 ||
			state.bucketUsed != 25 || state.bucketReserved != 0 ||
			state.reservationStatus != "settled" {
			t.Fatalf("conservatively settled over-reported hard cost = %#v", state)
		}
	})

	t.Run("zero reservation survives settle replay and predispatch release", func(t *testing.T) {
		settledInput := fixture.hardCostInput(t, "cost-zero-settle", 100, 0)
		settled, err := fixture.store.Reserve(fixture.ctx, settledInput)
		if err != nil {
			t.Fatalf("reserve zero hard cost: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, settled)
		if err != nil || !owner {
			t.Fatalf("begin zero hard cost owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle zero hard cost: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("replay zero hard cost: %v", err)
		}
		state := fixture.readHardCostState(t, settled.ID())
		if state.reservedEntry != 0 || state.settledEntry != 0 || state.releasedEntry != 0 ||
			state.bucketUsed != 0 || state.bucketReserved != 0 {
			t.Fatalf("settled zero hard cost state = %#v", state)
		}

		releasedInput := fixture.hardCostInput(t, "cost-zero-release", 100, 0)
		released, err := fixture.store.Reserve(fixture.ctx, releasedInput)
		if err != nil {
			t.Fatalf("reserve releasable zero hard cost: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, released, "transport_setup_failed"); err != nil {
			t.Fatalf("release zero hard cost: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, released, "transport_setup_failed"); err != nil {
			t.Fatalf("replay zero hard cost release: %v", err)
		}
		state = fixture.readHardCostState(t, released.ID())
		if state.releasedEntry != 0 || state.bucketUsed != 0 || state.bucketReserved != 0 ||
			state.reservationStatus != "released" {
			t.Fatalf("released zero hard cost state = %#v", state)
		}
	})

	t.Run("expiry refunds undispatched and charges dispatched reservation", func(t *testing.T) {
		undispatchedInput := fixture.hardCostInput(t, "cost-expiry-undispatched", 100, 25)
		undispatched, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
		if err != nil {
			t.Fatalf("reserve undispatched expiry: %v", err)
		}
		fixture.expireHardCostReservation(t, undispatched.ID())
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire undispatched processed=%d err=%v", processed, err)
		}
		state := fixture.readHardCostState(t, undispatched.ID())
		if state.settledEntry != 0 || state.releasedEntry != 25 ||
			state.bucketUsed != 0 || state.bucketReserved != 0 ||
			state.reservationStatus != "expired" {
			t.Fatalf("undispatched expiry hard cost state = %#v", state)
		}

		dispatchedInput := fixture.hardCostInput(t, "cost-expiry-dispatched", 100, 25)
		dispatched, err := fixture.store.Reserve(fixture.ctx, dispatchedInput)
		if err != nil {
			t.Fatalf("reserve dispatched expiry: %v", err)
		}
		if _, owner, err := fixture.store.BeginAttempt(fixture.ctx, dispatched); err != nil || !owner {
			t.Fatalf("begin dispatched expiry owner=%t: %v", owner, err)
		}
		fixture.expireHardCostReservation(t, dispatched.ID())
		processed, err = fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire dispatched processed=%d err=%v", processed, err)
		}
		state = fixture.readHardCostState(t, dispatched.ID())
		if state.settledEntry != 25 || state.releasedEntry != 0 ||
			state.bucketUsed != 25 || state.bucketReserved != 0 ||
			state.reservationStatus != "settled" {
			t.Fatalf("dispatched expiry hard cost state = %#v", state)
		}
	})

	t.Run("contention cannot overspend", func(t *testing.T) {
		const callers = 12
		start := make(chan struct{})
		results := make(chan struct {
			reservation Reservation
			err         error
		}, callers)
		var wait sync.WaitGroup
		for range callers {
			input := fixture.hardCostInput(t, "cost-contention", 100, 60)
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				results <- struct {
					reservation Reservation
					err         error
				}{reservation: reservation, err: err}
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		var winner Reservation
		accepted, denied := 0, 0
		for result := range results {
			switch {
			case result.err == nil:
				accepted++
				winner = result.reservation
			case errors.Is(result.err, ErrExceeded):
				denied++
			default:
				t.Fatalf("contended hard cost reserve = %v", result.err)
			}
		}
		if accepted != 1 || denied != callers-1 {
			t.Fatalf("hard cost contention accepted=%d denied=%d", accepted, denied)
		}
		state := fixture.readHardCostState(t, winner.ID())
		if state.bucketUsed+state.bucketReserved > state.hardMaximum || state.bucketReserved != 60 {
			t.Fatalf("overspent hard cost bucket = %#v", state)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, winner, "contention_complete"); err != nil {
			t.Fatalf("release hard cost contention winner: %v", err)
		}
	})

	t.Run("mixed denial is atomic and policy maximum changes conservatively", func(t *testing.T) {
		mixed := fixture.hardCostInput(t, "cost-mixed-denial", 5, 6)
		mixed.Rules = append(mixed.Rules, Rule{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: 1, Hard: true,
		})
		if _, err := fixture.store.Reserve(fixture.ctx, mixed); !errors.Is(err, ErrExceeded) {
			t.Fatalf("mixed hard cost denial = %v, want ErrExceeded", err)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM quota_buckets
			WHERE environment_id = $1 AND reserved_units <> 0
			  AND scope_key IN ($2, $3)
		`, quotaTestEnvironmentID,
			mustPreparedMetricScopeKey(t, mixed, CostNanoUSDMetric),
			mustPreparedMetricScopeKey(t, mixed, LogicalRequestsMetric)); got != 0 {
			t.Fatalf("mixed denial mutated %d quota buckets", got)
		}

		seedInput := fixture.hardCostInput(t, "cost-policy-change", 100, 60)
		seed, err := fixture.store.Reserve(fixture.ctx, seedInput)
		if err != nil {
			t.Fatalf("reserve policy-change seed: %v", err)
		}
		lower := fixture.hardCostInput(t, "cost-policy-change", 50, 0)
		if _, err := fixture.store.Reserve(fixture.ctx, lower); !errors.Is(err, ErrExceeded) {
			t.Fatalf("lower hard cost maximum with occupancy = %v, want ErrExceeded", err)
		}
		state := fixture.readHardCostState(t, seed.ID())
		if state.hardMaximum != 100 || state.bucketReserved != 60 {
			t.Fatalf("unsafe hard cost maximum transition = %#v", state)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seed, "policy_change_release"); err != nil {
			t.Fatalf("release policy-change seed: %v", err)
		}
		lowerFresh := fixture.hardCostInput(t, "cost-policy-change", 50, 0)
		accepted, err := fixture.store.Reserve(fixture.ctx, lowerFresh)
		if err != nil {
			t.Fatalf("reserve lowered free hard cost: %v", err)
		}
		state = fixture.readHardCostState(t, accepted.ID())
		if state.hardMaximum != 50 || state.bucketReserved != 0 {
			t.Fatalf("lowered hard cost state = %#v", state)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, accepted, "policy_change_complete"); err != nil {
			t.Fatalf("release lowered hard cost: %v", err)
		}
	})

	t.Run("tampered pending and terminal entries fail closed", func(t *testing.T) {
		pendingInput := fixture.hardCostInput(t, "cost-tamper-pending", 100, 25)
		pending, err := fixture.store.Reserve(fixture.ctx, pendingInput)
		if err != nil {
			t.Fatalf("reserve pending tamper: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservation_entries SET settled_units = 1
			WHERE quota_reservation_id = $1
		`, pending.ID()); err != nil {
			t.Fatalf("tamper pending hard cost: %v", err)
		}
		if _, _, err := fixture.store.BeginAttempt(fixture.ctx, pending); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("tampered pending hard cost = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservation_entries SET settled_units = 0
			WHERE quota_reservation_id = $1
		`, pending.ID()); err != nil {
			t.Fatalf("restore pending hard cost: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, pending, "tamper_complete"); err != nil {
			t.Fatalf("release restored pending hard cost: %v", err)
		}

		terminalInput := fixture.hardCostInput(t, "cost-tamper-terminal", 100, 25)
		terminal, err := fixture.store.Reserve(fixture.ctx, terminalInput)
		if err != nil {
			t.Fatalf("reserve terminal tamper: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, terminal)
		if err != nil || !owner {
			t.Fatalf("begin terminal tamper owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{NanoUSD: 7, Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle terminal tamper: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservation_entries
			SET settled_units = 6, released_units = 19
			WHERE quota_reservation_id = $1
		`, terminal.ID()); err != nil {
			t.Fatalf("tamper terminal hard cost: %v", err)
		}
		if _, _, err := fixture.store.BeginAttempt(fixture.ctx, terminal); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("tampered terminal attempt replay = %v, want ErrInvalidState", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("tampered terminal settlement replay = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, terminalInput); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("tampered terminal reserve replay = %v, want ErrInvalidState", err)
		}
	})

	t.Run("tampered unknown terminal split fails closed at attempt replay", func(t *testing.T) {
		input := fixture.hardCostInput(t, "cost-tamper-unknown-terminal", 100, 25)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve unknown terminal tamper: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin unknown terminal tamper owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable",
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle unknown terminal tamper: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservation_entries
			SET settled_units = 24, released_units = 1
			WHERE quota_reservation_id = $1
		`, reservation.ID()); err != nil {
			t.Fatalf("tamper unknown terminal hard cost: %v", err)
		}
		if _, _, err := fixture.store.BeginAttempt(fixture.ctx, reservation); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("tampered unknown attempt replay = %v, want ErrInvalidState", err)
		}
	})

	t.Run("expiry rejects missing or mismatched hard cost pricing", func(t *testing.T) {
		tests := []struct {
			name      string
			feature   string
			query     string
			arguments []any
		}{
			{
				name: "missing selection", feature: "cost-expiry-pricing-missing",
				query: `
					UPDATE upstream_attempts
					SET currency = NULL, price_revision = NULL,
					    pricing_source = NULL, cost_confidence = NULL
					WHERE logical_request_id = $1
				`,
			},
			{
				name: "mismatched revision", feature: "cost-expiry-pricing-revision",
				query: `
					UPDATE upstream_attempts SET price_revision = $2
					WHERE logical_request_id = $1
				`,
				arguments: []any{"rev_00000000000000000000000002"},
			},
			{
				name: "same-revision catalog substitution", feature: "cost-expiry-pricing-source",
				query: `
					UPDATE upstream_attempts SET pricing_source = $2
					WHERE logical_request_id = $1
				`,
				arguments: []any{"enterprise-usd"},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				input := fixture.hardCostInput(t, test.feature, 100, 25)
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				if err != nil {
					t.Fatalf("reserve pricing-tampered expiry: %v", err)
				}
				if _, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation); err != nil || !owner {
					t.Fatalf("begin pricing-tampered expiry owner=%t: %v", owner, err)
				}
				arguments := append([]any{input.LogicalRequestID.String()}, test.arguments...)
				if _, err := fixture.pool.Exec(fixture.ctx, test.query, arguments...); err != nil {
					t.Fatalf("tamper hard cost attempt pricing: %v", err)
				}
				fixture.expireHardCostReservation(t, reservation.ID())
				processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
				if processed != 0 || !errors.Is(err, ErrInvalidState) {
					t.Fatalf("pricing-tampered expiry processed=%d err=%v, want 0/ErrInvalidState", processed, err)
				}
				state := fixture.readHardCostState(t, reservation.ID())
				if state.settledEntry != 0 || state.releasedEntry != 0 ||
					state.bucketUsed != 0 || state.bucketReserved != 25 ||
					state.reservationStatus != "pending" {
					t.Fatalf("pricing-tampered expiry mutated state = %#v", state)
				}
				if _, err := fixture.pool.Exec(fixture.ctx, `
					UPDATE upstream_attempts
					SET currency = $2, price_revision = $3,
					    pricing_source = $4, cost_confidence = $5
					WHERE logical_request_id = $1
				`, input.LogicalRequestID.String(), USDCurrency, quotaTestConfigRevisionID,
					"hard-cost-usd", UnknownCostConfidence); err != nil {
					t.Fatalf("restore hard cost attempt pricing: %v", err)
				}
				processed, err = fixture.store.ExpirePendingBatch(fixture.ctx, 1)
				if err != nil || processed != 1 {
					t.Fatalf("expire restored hard cost processed=%d err=%v", processed, err)
				}
			})
		}
	})

	t.Run("historical priced reservation keys still replay and expire", func(t *testing.T) {
		input := fixture.pricedInput(t, "cost-priced-key-compatibility", 100, "legacy-usd")
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve historical priced compatibility request: %v", err)
		}
		prepared, err := prepareRequest(input)
		if err != nil {
			t.Fatalf("prepare historical priced compatibility request: %v", err)
		}
		var storedKey string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT idempotency_key FROM quota_reservations
			WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&storedKey); err != nil {
			t.Fatalf("read historical priced reservation key: %v", err)
		}
		if fingerprint := requestFingerprint(prepared); storedKey != fingerprint {
			t.Fatalf("historical priced reservation key = %q, want %q", storedKey, fingerprint)
		}
		replay, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("replay historical priced reservation = %#v, %v", replay, err)
		}
		if _, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation); err != nil || !owner {
			t.Fatalf("begin historical priced expiry owner=%t: %v", owner, err)
		}
		fixture.expireHardCostReservation(t, reservation.ID())
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire historical priced reservation processed=%d err=%v", processed, err)
		}
		var status string
		var used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT reservation.status, bucket.used_units, bucket.reserved_units
			FROM quota_reservations AS reservation
			JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE reservation.quota_reservation_id = $1
		`, reservation.ID()).Scan(&status, &used, &reserved); err != nil {
			t.Fatalf("read historical priced expiry state: %v", err)
		}
		if status != "settled" || used != 1 || reserved != 0 {
			t.Fatalf("historical priced expiry state status=%s used=%d reserved=%d", status, used, reserved)
		}
	})

	t.Run("snapshot exposes exact hard cost used reserved and remaining", func(t *testing.T) {
		input := fixture.hardCostInput(t, "cost-snapshot", 100, 25)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve snapshotted hard cost: %v", err)
		}
		snapshotInput := snapshotInputFromReserve(input)
		for index := range snapshotInput.Rules {
			snapshotInput.Rules[index].ReservedUnits = 0
		}
		snapshot, err := fixture.store.Snapshot(fixture.ctx, snapshotInput)
		if err != nil || len(snapshot.Limits) != 1 || snapshot.Limits[0].Metric != CostNanoUSDMetric ||
			snapshot.Limits[0].Used == nil || *snapshot.Limits[0].Used != 0 ||
			snapshot.Limits[0].Reserved == nil || *snapshot.Limits[0].Reserved != 25 ||
			snapshot.Limits[0].Remaining == nil || *snapshot.Limits[0].Remaining != 75 {
			t.Fatalf("pending hard cost snapshot = %#v, %v", snapshot, err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin snapshotted hard cost owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{NanoUSD: 7, Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle snapshotted hard cost: %v", err)
		}
		snapshot, err = fixture.store.Snapshot(fixture.ctx, snapshotInput)
		if err != nil || *snapshot.Limits[0].Used != 7 ||
			*snapshot.Limits[0].Reserved != 0 || *snapshot.Limits[0].Remaining != 93 {
			t.Fatalf("settled hard cost snapshot = %#v, %v", snapshot, err)
		}
	})
}

type hardCostState struct {
	reservedEntry, settledEntry, releasedEntry int64
	bucketUsed, bucketReserved, hardMaximum    int64
	reservationStatus                          string
}

func (fixture quotaPostgreSQLFixture) hardCostInput(
	t *testing.T,
	feature string,
	maximum int64,
	reserved int64,
) ReserveInput {
	t.Helper()
	input := fixture.pricedInput(t, feature, 1, "hard-cost-usd")
	input.Rules = []Rule{{
		Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user", "feature"}, Window: "1d",
		Maximum: maximum, ReservedUnits: reserved, Hard: true,
	}}
	return input
}

func (fixture quotaPostgreSQLFixture) readHardCostState(t *testing.T, reservationID string) hardCostState {
	t.Helper()
	var result hardCostState
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT entry.reserved_units, entry.settled_units, entry.released_units,
		       bucket.used_units, bucket.reserved_units, bucket.hard_maximum,
		       reservation.status
		FROM quota_reservations AS reservation
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE reservation.quota_reservation_id = $1
		  AND bucket.metric = 'cost_nano_usd'
	`, reservationID).Scan(
		&result.reservedEntry, &result.settledEntry, &result.releasedEntry,
		&result.bucketUsed, &result.bucketReserved, &result.hardMaximum,
		&result.reservationStatus,
	); err != nil {
		t.Fatalf("read hard cost state: %v", err)
	}
	return result
}

func (fixture quotaPostgreSQLFixture) expireHardCostReservation(t *testing.T, reservationID string) {
	t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = $1
	`, reservationID); err != nil {
		t.Fatalf("backdate hard cost reservation: %v", err)
	}
}

func mustPreparedMetricScopeKey(t *testing.T, input ReserveInput, metric string) string {
	t.Helper()
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare metric quota input: %v", err)
	}
	for _, rule := range prepared.rules {
		if rule.Metric == metric {
			return rule.scopeKey
		}
	}
	t.Fatalf("prepared quota input has no %s rule", metric)
	return ""
}
