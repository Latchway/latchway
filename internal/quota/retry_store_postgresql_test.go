package quota

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestStorePostgreSQLMultiAttemptQuotaLifecycle(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("charges attempts independently and the logical request once", func(t *testing.T) {
		input := fixture.input(t, "multi-attempt-basic", 10)
		input.LimitPlanKey = "multi-attempt-basic"
		input.Rules = append(input.Rules,
			Rule{
				Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
				Scope: []string{"user", "feature"}, Window: "1d",
				Maximum: 100, ReservedUnits: 10, Hard: true,
			},
			Rule{
				Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm,
				Scope: []string{"user"}, Maximum: 2, Hard: true,
			},
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve logical request: %v", err)
		}
		first, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin first attempt owner=%t: %v", owner, err)
		}
		var allocated int64
		var charged *int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT allocated_units, charged_units
			FROM upstream_attempt_quota_entries
			WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
		`, first.ID()).Scan(&allocated, &charged); err != nil {
			t.Fatalf("read first-attempt allocation: %v", err)
		}
		if allocated != 10 || charged != nil {
			t.Fatalf("first-attempt allocation = %d/%v, want 10/unsettled", allocated, charged)
		}

		firstOutcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_unavailable",
		}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle retryable first attempt: %v", err)
		}
		assertRetryLogicalState(t, fixture, reservation.ID(), "dispatched", "pending", 0, 1)
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), OutputTokensMetric, 10, 10, 0, 10, 0)
		assertRetryUnknownUsage(
			t, fixture, input.LogicalRequestID.String(), first.ID(), OutputTokensMetric,
			10, unknownTokenUsageProvenanceKey(reservation.ID(), OutputTokensMetric),
		)

		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 8}},
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner || second.Number() != 2 {
			t.Fatalf("begin second attempt = %#v owner=%t: %v", second, owner, err)
		}
		replayedSecond, replayOwner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || replayOwner || replayedSecond.ID() != second.ID() {
			t.Fatalf("replay second attempt = %#v owner=%t: %v", replayedSecond, replayOwner, err)
		}
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), OutputTokensMetric, 18, 10, 0, 10, 8)

		secondOutcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200,
			Usage: Usage{
				InputTokens: 2, OutputTokens: 6, TotalTokens: 8,
				Known: true, Provenance: ProviderReportedProvenance,
			},
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("settle final second attempt: %v", err)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("replay final second settlement: %v", err)
		}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("replay first settlement after finalization: %v", err)
		}
		replayedSecond, replayOwner, err = fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || replayOwner || replayedSecond.ID() != second.ID() {
			t.Fatalf("replay second begin after finalization = %#v owner=%t: %v", replayedSecond, replayOwner, err)
		}
		changedRetry := retryInput
		changedRetry.PhysicalModel = "provider/model-v3"
		if _, _, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, changedRetry); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("changed retry replay = %v, want ErrInvalidState", err)
		}
		conflictingFirst := firstOutcome
		conflictingFirst.FailureCode = "different_failure"
		if err := fixture.store.SettleForRetry(fixture.ctx, first, conflictingFirst); !errors.Is(err, ErrFinalized) {
			t.Fatalf("conflicting first settlement = %v, want ErrFinalized", err)
		}

		assertRetryLogicalState(t, fixture, reservation.ID(), "succeeded", "settled", 1, 0)
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), OutputTokensMetric, 18, 16, 2, 16, 0)
		assertConcurrencyEntryState(
			t, fixture, reservation.ID(), ConcurrentRequestsMetric,
			1, 0, 1, 0, 0, true,
		)
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 2 {
			t.Fatalf("upstream attempts = %d, want 2", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempt_quota_entries
			WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 2 {
			t.Fatalf("attempt quota rows = %d, want 2", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 5 {
			t.Fatalf("usage records = %d, want 5", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records
			WHERE logical_request_id = $1 AND metric = 'logical_requests'
		`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("logical-request usage records = %d, want 1", got)
		}

		firstReplay, replayOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || replayOwner || firstReplay.ID() != first.ID() {
			t.Fatalf("first begin terminal replay = %#v owner=%t: %v", firstReplay, replayOwner, err)
		}
		reservationReplay, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || reservationReplay.ID() != reservation.ID() {
			t.Fatalf("terminal reservation replay = %#v: %v", reservationReplay, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			WITH first_attempt AS (
				UPDATE upstream_attempt_quota_entries
				SET allocated_units = 9, charged_units = 9, released_units = 0
				WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
			), second_attempt AS (
				UPDATE upstream_attempt_quota_entries
				SET allocated_units = 9, charged_units = 6, released_units = 3
				WHERE upstream_attempt_id = $2 AND metric = 'output_tokens'
			), changed_usage AS (
				UPDATE usage_records SET units = 9
				WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
			), changed_entry AS (
				UPDATE quota_reservation_entries AS entry
				SET settled_units = 15, released_units = 3
				FROM quota_buckets AS bucket
				WHERE entry.quota_bucket_id = bucket.quota_bucket_id
				  AND entry.quota_reservation_id = $3 AND bucket.metric = 'output_tokens'
				RETURNING entry.quota_bucket_id
			)
			UPDATE quota_buckets
			SET used_units = 15
			WHERE quota_bucket_id IN (SELECT quota_bucket_id FROM changed_entry)
		`, first.ID(), second.ID(), reservation.ID()); err != nil {
			t.Fatalf("redistribute attempt allocations: %v", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("terminal replay with redistributed attempt allocations = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			WITH first_attempt AS (
				UPDATE upstream_attempt_quota_entries
				SET allocated_units = 10, charged_units = 10, released_units = 0
				WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
			), second_attempt AS (
				UPDATE upstream_attempt_quota_entries
				SET allocated_units = 8, charged_units = 6, released_units = 2
				WHERE upstream_attempt_id = $2 AND metric = 'output_tokens'
			), changed_usage AS (
				UPDATE usage_records SET units = 10
				WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
			), changed_entry AS (
				UPDATE quota_reservation_entries AS entry
				SET settled_units = 16, released_units = 2
				FROM quota_buckets AS bucket
				WHERE entry.quota_bucket_id = bucket.quota_bucket_id
				  AND entry.quota_reservation_id = $3 AND bucket.metric = 'output_tokens'
				RETURNING entry.quota_bucket_id
			)
			UPDATE quota_buckets
			SET used_units = 16
			WHERE quota_bucket_id IN (SELECT quota_bucket_id FROM changed_entry)
		`, first.ID(), second.ID(), reservation.ID()); err != nil {
			t.Fatalf("restore attempt allocations: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE usage_records
			SET cost_nano_usd = 1, currency = 'USD', price_revision = 'tampered',
			    pricing_source = 'tampered'
			WHERE logical_request_id = $1 AND upstream_attempt_id IS NULL
		`, input.LogicalRequestID.String()); err != nil {
			t.Fatalf("tamper logical usage price metadata: %v", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("terminal replay with priced logical usage = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE usage_records
			SET cost_nano_usd = NULL, currency = NULL, price_revision = NULL,
			    pricing_source = NULL
			WHERE logical_request_id = $1 AND upstream_attempt_id IS NULL
		`, input.LogicalRequestID.String()); err != nil {
			t.Fatalf("restore logical usage price metadata: %v", err)
		}
		extraUsageID, err := fixture.store.newID(id.UsageRecord)
		if err != nil {
			t.Fatalf("generate extra logical usage ID: %v", err)
		}
		extraProvenance := "logical-request-extra:" + input.LogicalRequestID.String()
		if _, err := fixture.pool.Exec(fixture.ctx, `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				confidence, provenance_key
			) VALUES ($1, $2, $3, $4, $5, NULL, 'logical_requests', 1,
			          'calculated', $6)
		`, extraUsageID, input.OrganizationID, input.ApplicationID, input.EnvironmentID,
			input.LogicalRequestID.String(), extraProvenance); err != nil {
			t.Fatalf("insert extra logical usage: %v", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("terminal replay with extra logical usage = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			DELETE FROM usage_records WHERE usage_record_id = $1
		`, extraUsageID); err != nil {
			t.Fatalf("delete extra logical usage: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			DELETE FROM usage_records
			WHERE logical_request_id = $1 AND upstream_attempt_id = $2
			  AND metric = 'output_tokens'
		`, input.LogicalRequestID.String(), first.ID()); err != nil {
			t.Fatalf("delete earlier attempt usage: %v", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("terminal replay with missing earlier usage = %v, want ErrInvalidState", err)
		}
	})

	t.Run("retry capacity denial rolls back atomically", func(t *testing.T) {
		input := fixture.outputInput(t, "multi-attempt-denial", 10, 10)
		input.LimitPlanKey = "multi-attempt-denial"
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		outcome := Outcome{
			Status: AttemptTimedOut, FailureCode: "upstream_timeout",
		}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("settle first attempt before denial: %v", err)
		}
		denied := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 1}},
		}
		_, _, denialErr := fixture.store.BeginRetryAttempt(fixture.ctx, first, denied)
		var exceeded *ExceededError
		if !errors.Is(denialErr, ErrExceeded) || !errors.As(denialErr, &exceeded) ||
			exceeded.LogicalRequestID() != input.LogicalRequestID.String() || exceeded.Maximum() != 10 ||
			exceeded.Used() != 10 || exceeded.Reserved() != 0 || !exceeded.RetryAt().After(time.Now().Add(-time.Second)) {
			t.Fatalf("retry capacity denial = %#v (%v), want typed calendar ExceededError", exceeded, denialErr)
		}
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), OutputTokensMetric, 10, 10, 0, 10, 0)
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("attempts after denied retry = %d, want 1", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempt_quota_entries
			WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("attempt quota rows after denied retry = %d, want 1", got)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("finalize between attempts: %v", err)
		}
		assertRetryLogicalState(t, fixture, reservation.ID(), "failed", "settled", 1, 0)
	})

	t.Run("token retry capacity denial returns safe retry time and rolls back", func(t *testing.T) {
		input := fixture.outputTokenBucketInput(t, "multi-attempt-token-denial", 10, 1, 1, 10)
		input.LimitPlanKey = "multi-attempt-token-denial"
		input.Rules = append(input.Rules, Rule{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: 100, Hard: true,
		})
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		outcome := Outcome{Status: AttemptTimedOut, FailureCode: "upstream_timeout"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("settle first token attempt before denial: %v", err)
		}
		denied := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 1}},
		}
		_, _, denialErr := fixture.store.BeginRetryAttempt(fixture.ctx, first, denied)
		var exceeded *ExceededError
		if !errors.Is(denialErr, ErrExceeded) || !errors.As(denialErr, &exceeded) ||
			exceeded.LogicalRequestID() != input.LogicalRequestID.String() || exceeded.Maximum() != 10 ||
			exceeded.Used() != 10 || exceeded.Reserved() != 0 || !exceeded.RetryAt().After(time.Now().Add(-time.Second)) {
			t.Fatalf("token retry denial = %#v (%v), want typed token ExceededError", exceeded, denialErr)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("attempts after token retry denial = %d, want 1", got)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("finalize token denial request: %v", err)
		}
		assertRetryLogicalState(t, fixture, reservation.ID(), "failed", "settled", 1, 0)
	})

	t.Run("retry denial reports latest reset without partial reservation writes", func(t *testing.T) {
		input := fixture.outputTokenBucketInput(
			t, "multi-attempt-latest-retry-reset", 1, 1, 1_000_000, 1,
		)
		input.LimitPlanKey = "multi-attempt-latest-retry-reset"
		input.Pricing = PricingSelection{CatalogID: "output-only", Currency: USDCurrency}
		input.Rules = append(input.Rules, Rule{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1h",
			Maximum: 1, ReservedUnits: 1, Hard: true,
		})
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		outcome := Outcome{Status: AttemptFailed, FailureCode: "upstream_unavailable"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("settle both exhausted allocations: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Pricing:       PricingSelection{CatalogID: "output-only", Currency: USDCurrency},
			Allocations: []AttemptAllocation{
				{Metric: OutputTokensMetric, Units: 1},
				{Metric: CostNanoUSDMetric, Units: 1},
			},
		}
		_, _, denialErr := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		var exceeded *ExceededError
		if !errors.Is(denialErr, ErrExceeded) || !errors.As(denialErr, &exceeded) ||
			exceeded.LogicalRequestID() != input.LogicalRequestID.String() ||
			exceeded.Maximum() != 1 || exceeded.Used() != 1 || exceeded.Reserved() != 0 ||
			!exceeded.RetryAt().After(time.Now().Add(10*24*time.Hour)) {
			t.Fatalf("multi-bucket retry denial = %#v (%v), want latest token reset", exceeded, denialErr)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
			  AND initial_reserved_units = 1 AND reserved_units = 1
			  AND settled_units = 1 AND released_units = 0
		`, reservation.ID()); got != 2 {
			t.Fatalf("unchanged exhausted reservation entries = %d, want 2", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("attempts after multi-bucket retry denial = %d, want 1", got)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("finalize multi-bucket retry denial: %v", err)
		}
	})

	t.Run("concurrent exact retry begin elects one dispatch owner", func(t *testing.T) {
		input := fixture.outputInput(t, "multi-attempt-concurrent", 30, 5)
		input.LimitPlanKey = "multi-attempt-concurrent"
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		firstOutcome := Outcome{
			Status: AttemptTimedOut, FailureCode: "upstream_timeout",
		}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle first attempt before concurrent retry: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 5}},
		}
		type result struct {
			attempt Attempt
			owner   bool
			err     error
		}
		const callers = 8
		start := make(chan struct{})
		results := make(chan result, callers)
		var wait sync.WaitGroup
		for range callers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				attempt, owner, err := fixture.store.BeginRetryAttempt(
					fixture.ctx, first, retryInput,
				)
				results <- result{attempt: attempt, owner: owner, err: err}
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		owners := 0
		attemptID := ""
		var second Attempt
		for result := range results {
			if result.err != nil {
				t.Errorf("concurrent retry begin: %v", result.err)
				continue
			}
			if result.attempt.Number() != 2 {
				t.Errorf("concurrent retry attempt number = %d, want 2", result.attempt.Number())
			}
			if attemptID == "" {
				attemptID = result.attempt.ID()
				second = result.attempt
			} else if result.attempt.ID() != attemptID {
				t.Errorf("concurrent retry attempt ID = %q, want %q", result.attempt.ID(), attemptID)
			}
			if result.owner {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("concurrent retry dispatch owners = %d, want 1", owners)
		}
		secondOutcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy",
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("settle concurrently-created retry: %v", err)
		}
		assertRetryLogicalState(t, fixture, reservation.ID(), "failed", "settled", 1, 0)
		assertCalendarTokenEntryState(
			t, fixture, reservation.ID(), OutputTokensMetric, 10, 10, 0, 10, 0,
		)
	})

	t.Run("retry decision tamper cannot advance first byte", func(t *testing.T) {
		input := fixture.outputInput(t, "multi-attempt-first-byte-tamper", 30, 5)
		input.LimitPlanKey = "multi-attempt-first-byte-tamper"
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle first attempt before first-byte tamper: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 5}},
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner {
			t.Fatalf("begin retry before first-byte tamper owner=%t: %v", owner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			WITH changed_attempt AS (
				UPDATE upstream_attempt_quota_entries
				SET allocated_units = 6
				WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
			), changed_entry AS (
				UPDATE quota_reservation_entries AS entry
				SET reserved_units = 11
				FROM quota_buckets AS bucket
				WHERE entry.quota_bucket_id = bucket.quota_bucket_id
				  AND entry.quota_reservation_id = $2 AND bucket.metric = 'output_tokens'
				RETURNING entry.quota_bucket_id
			)
			UPDATE quota_buckets SET reserved_units = 6
			WHERE quota_bucket_id IN (SELECT quota_bucket_id FROM changed_entry)
		`, second.ID(), reservation.ID()); err != nil {
			t.Fatalf("tamper retry allocation before first byte: %v", err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, second); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("mark first byte with tampered retry allocation = %v, want ErrInvalidState", err)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts
			WHERE upstream_attempt_id = $1 AND first_byte_at IS NULL
		`, second.ID()); got != 1 {
			t.Fatalf("retry first-byte rows after rejected tamper = %d, want 1", got)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			WITH changed_attempt AS (
				UPDATE upstream_attempt_quota_entries
				SET allocated_units = 5
				WHERE upstream_attempt_id = $1 AND metric = 'output_tokens'
			), changed_entry AS (
				UPDATE quota_reservation_entries AS entry
				SET reserved_units = 10
				FROM quota_buckets AS bucket
				WHERE entry.quota_bucket_id = bucket.quota_bucket_id
				  AND entry.quota_reservation_id = $2 AND bucket.metric = 'output_tokens'
				RETURNING entry.quota_bucket_id
			)
			UPDATE quota_buckets SET reserved_units = 5
			WHERE quota_bucket_id IN (SELECT quota_bucket_id FROM changed_entry)
		`, second.ID(), reservation.ID()); err != nil {
			t.Fatalf("restore retry allocation before first byte: %v", err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, second); err != nil {
			t.Fatalf("mark first byte after restoring retry decision: %v", err)
		}
		secondOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		extraUsageID, err := fixture.store.newID(id.UsageRecord)
		if err != nil {
			t.Fatalf("generate started-attempt extra usage ID: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				confidence, provenance_key
			) VALUES ($1, $2, $3, $4, $5, $6, 'output_tokens', 1,
			          'reported', $7)
		`, extraUsageID, input.OrganizationID, input.ApplicationID, input.EnvironmentID,
			input.LogicalRequestID.String(), second.ID(),
			"started-attempt-extra:"+second.ID()); err != nil {
			t.Fatalf("insert started-attempt extra usage: %v", err)
		}
		if err := fixture.store.SettleFinalAttempt(
			fixture.ctx, second, secondOutcome,
		); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("settle retry with pre-existing usage = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			DELETE FROM usage_records WHERE usage_record_id = $1
		`, extraUsageID); err != nil {
			t.Fatalf("delete started-attempt extra usage: %v", err)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("settle retry after first-byte tamper test: %v", err)
		}
	})

	t.Run("target-scoped rules atomically materialize for fallback targets", func(t *testing.T) {
		input := fixture.outputInput(t, "multi-attempt-target-scope", 30, 5)
		input.LimitPlanKey = "multi-attempt-target-scope"
		targetScope := []string{"user", "route", "upstream", "model"}
		input.Rules[1].Scope = append([]string(nil), targetScope...)
		input.Rules = append(input.Rules, Rule{
			Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm,
			Scope: append([]string(nil), targetScope...), Maximum: 2, Hard: true,
		})
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle first target-scoped attempt: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "backup/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 5}},
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner || second.Number() != 2 {
			t.Fatalf("begin target-scoped retry = %#v owner=%t: %v", second, owner, err)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			  AND entry.origin_attempt_number = 2
			  AND bucket.metric IN ('output_tokens', 'concurrent_requests')
			  AND bucket.scope_dimensions = ARRAY['user','route','upstream','model']::text[]
		`, reservation.ID()); got != 2 {
			t.Fatalf("fallback target materialized entries = %d, want 2", got)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM upstream_attempt_quota_entries AS quota
			JOIN quota_reservation_entries AS entry
			  ON entry.quota_reservation_entry_id = quota.quota_reservation_entry_id
		WHERE quota.upstream_attempt_id = $1
		  AND quota.metric = 'output_tokens'
		  AND quota.allocated_units = 5
		  AND entry.origin_attempt_number = 2
		`, second.ID()); got != 1 {
			t.Fatalf("fallback target attempt ledger rows = %d, want 1", got)
		}
		replayed, replayOwner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || replayOwner || replayed.ID() != second.ID() {
			t.Fatalf("replay target-scoped retry = %#v owner=%t: %v", replayed, replayOwner, err)
		}
		secondOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "backup_busy"}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("finalize target-scoped fallback request: %v", err)
		}
		assertRetryLogicalState(t, fixture, reservation.ID(), "failed", "settled", 1, 0)
		if got := fixture.count(t, `
			SELECT count(*)
			FROM concurrency_leases
			WHERE logical_request_id = $1 AND released_at IS NOT NULL
		`, input.LogicalRequestID.String()); got != 2 {
			t.Fatalf("released target concurrency leases = %d, want 2", got)
		}
		if replay, err := fixture.store.Reserve(fixture.ctx, input); err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("target-scoped terminal reservation replay = %#v: %v", replay, err)
		}
	})

	t.Run("retry admission uses the request sealed target maximum", func(t *testing.T) {
		const feature = "multi-attempt-sealed-target-maximum"
		low := fixture.outputInput(t, feature, 6, 5)
		low.LimitPlanKey = feature
		low.Rules[1].Scope = []string{"user", "route", "upstream", "model"}
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, low)
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle sealed-maximum first attempt: %v", err)
		}

		high := fixture.outputInput(t, feature, 100, 5)
		high.LimitPlanKey = feature
		high.RouteKey = "secondary"
		high.UpstreamKey = "backup"
		high.ModelKey = "model-v2"
		high.PhysicalModel = "backup/model-v2"
		high.Rules[1].Scope = []string{"user", "route", "upstream", "model"}
		highReservation, err := fixture.store.Reserve(fixture.ctx, high)
		if err != nil {
			t.Fatalf("reserve raised shared target maximum: %v", err)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			  AND bucket.metric = 'output_tokens'
			  AND bucket.hard_maximum = 100
			  AND bucket.reserved_units = 5
		`, highReservation.ID()); got != 1 {
			t.Fatalf("raised shared target bucket rows = %d, want 1", got)
		}

		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "backup/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 5}},
		}
		if _, _, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput); !errors.Is(err, ErrExceeded) {
			t.Fatalf("retry under sealed maximum = %v, want ErrExceeded", err)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM quota_reservation_entries
			WHERE quota_reservation_id = $1 AND origin_attempt_number = 2
		`, reservation.ID()); got != 0 {
			t.Fatalf("sealed-maximum denied materialization rows = %d, want 0", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1
		`, low.LogicalRequestID.String()); got != 1 {
			t.Fatalf("sealed-maximum denied attempts = %d, want 1", got)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, highReservation, "test_cleanup"); err != nil {
			t.Fatalf("release raised shared target reservation: %v", err)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("finalize sealed-maximum request after denial: %v", err)
		}
	})

	t.Run("retry reconciles shared token bucket to sealed capacity and rate", func(t *testing.T) {
		const feature = "multi-attempt-sealed-token-policy"
		low := fixture.outputTokenBucketInput(t, feature, 6, 1, 1, 5)
		low.LimitPlanKey = feature
		low.Rules[0].Scope = []string{"user", "route", "upstream", "model"}
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, low)
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle sealed-token first attempt: %v", err)
		}

		high := fixture.outputTokenBucketInput(t, feature, 100, 100, 1, 5)
		high.LimitPlanKey = feature
		high.RouteKey = "secondary"
		high.UpstreamKey = "backup"
		high.ModelKey = "model-v2"
		high.PhysicalModel = "backup/model-v2"
		high.Rules[0].Scope = []string{"user", "route", "upstream", "model"}
		highReservation, err := fixture.store.Reserve(fixture.ctx, high)
		if err != nil {
			t.Fatalf("reserve raised shared token policy: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "backup/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 5}},
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner {
			t.Fatalf("begin sealed-token retry owner=%t: %v", owner, err)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			  AND entry.origin_attempt_number = 2
			  AND bucket.metric = 'output_tokens'
			  AND bucket.algorithm = 'token_bucket'
			  AND bucket.hard_maximum = 6
			  AND bucket.refill_numerator = 1
			  AND bucket.refill_denominator = 1
		`, reservation.ID()); got != 1 {
			t.Fatalf("sealed retry token policy rows = %d, want 1", got)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, highReservation, "test_cleanup"); err != nil {
			t.Fatalf("release raised shared token reservation: %v", err)
		}
		secondOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "backup_busy"}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("finalize sealed-token retry: %v", err)
		}
	})

	t.Run("per-request-only retries durably bind output allocation", func(t *testing.T) {
		input := fixture.perRequestOutputInput(t, "multi-attempt-per-request", 64, 32)
		input.LimitPlanKey = "multi-attempt-per-request"
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve per-request retry: %v", err)
		}
		first, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin per-request first attempt owner=%t: %v", owner, err)
		}
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle per-request first attempt: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "backup/model-v2",
			Allocations:   []AttemptAllocation{{Metric: OutputTokensMetric, Units: 24}},
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner {
			t.Fatalf("begin per-request retry owner=%t: %v", owner, err)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts
			WHERE upstream_attempt_id = $1
			  AND attempt_decision_binding_version = 1
			  AND per_request_output_token_bound = 24
		`, second.ID()); got != 1 {
			t.Fatalf("per-request retry output binding rows = %d, want 1", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempt_quota_entries
			WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("per-request retry stateful ledger rows = %d, want 0", got)
		}
		if replay, replayOwner, err := fixture.store.BeginRetryAttempt(
			fixture.ctx, first, retryInput,
		); err != nil || replayOwner || replay.ID() != second.ID() {
			t.Fatalf("replay per-request retry = %#v owner=%t: %v", replay, replayOwner, err)
		}
		changed := retryInput
		changed.Allocations = []AttemptAllocation{{Metric: OutputTokensMetric, Units: 23}}
		if _, _, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, changed); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("changed per-request retry replay = %v, want ErrInvalidState", err)
		}
		secondOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "backup_busy"}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("settle per-request final attempt: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE upstream_attempts
			SET attempt_decision_binding_version = 0,
			    model_key = NULL,
			    attempt_decision_sha256 = NULL,
			    per_request_output_token_bound = NULL,
			    input_accounting_binding_version = 0
			WHERE upstream_attempt_id = $1
		`, first.ID()); err != nil {
			t.Fatalf("simulate schema-11 per-request first attempt: %v", err)
		}
		if replay, err := fixture.store.Reserve(fixture.ctx, input); err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("schema-11 per-request reservation replay = %#v: %v", replay, err)
		}
		if replay, replayOwner, err := fixture.store.BeginAttempt(
			fixture.ctx, reservation,
		); err != nil || replayOwner || replay.ID() != first.ID() {
			t.Fatalf("schema-11 per-request attempt replay = %#v owner=%t: %v", replay, replayOwner, err)
		}
	})

	t.Run("schema-11 settler can finalize a schema-12 first attempt exactly", func(t *testing.T) {
		input := fixture.outputInput(t, "multi-attempt-reverse-rolling", 30, 5)
		input.LimitPlanKey = "multi-attempt-reverse-rolling"
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		logicalUsageID, err := fixture.store.newID(id.UsageRecord)
		if err != nil {
			t.Fatalf("generate rolling logical usage ID: %v", err)
		}
		outputUsageID, err := fixture.store.newID(id.UsageRecord)
		if err != nil {
			t.Fatalf("generate rolling output usage ID: %v", err)
		}
		tx, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin frozen schema-11 settlement: %v", err)
		}
		defer func() { _ = tx.Rollback(fixture.ctx) }()
		exec := func(operation, statement string, arguments ...any) {
			t.Helper()
			if _, err := tx.Exec(fixture.ctx, statement, arguments...); err != nil {
				t.Fatalf("%s: %v", operation, err)
			}
		}
		exec("settle frozen schema-11 buckets", `
			UPDATE quota_buckets AS bucket
			SET used_units = bucket.used_units + entry.reserved_units,
			    reserved_units = bucket.reserved_units - entry.reserved_units
			FROM quota_reservation_entries AS entry
			WHERE entry.quota_reservation_id = $1
			  AND entry.quota_bucket_id = bucket.quota_bucket_id
		`, reservation.ID())
		exec("settle frozen schema-11 entries", `
			UPDATE quota_reservation_entries
			SET settled_units = reserved_units, released_units = 0
			WHERE quota_reservation_id = $1
		`, reservation.ID())
		exec("settle frozen schema-11 reservation", `
			UPDATE quota_reservations
			SET status = 'settled', settled_at = CURRENT_TIMESTAMP
			WHERE quota_reservation_id = $1
		`, reservation.ID())
		exec("insert frozen schema-11 logical usage", `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				confidence, provenance_key, recorded_at
			) VALUES ($1, $2, $3, $4, $5, NULL, 'logical_requests', 1,
			          'calculated', $6, CURRENT_TIMESTAMP)
		`, logicalUsageID, input.OrganizationID, input.ApplicationID, input.EnvironmentID,
			input.LogicalRequestID.String(), logicalUsageProvenanceKey(input.LogicalRequestID.String()))
		exec("insert frozen schema-11 output usage", `
			INSERT INTO usage_records (
				usage_record_id, organization_id, application_id, environment_id,
				logical_request_id, upstream_attempt_id, metric, units,
				confidence, provenance_key, recorded_at
			) VALUES ($1, $2, $3, $4, $5, $6, 'output_tokens', 5,
			          'unknown', $7, CURRENT_TIMESTAMP)
		`, outputUsageID, input.OrganizationID, input.ApplicationID, input.EnvironmentID,
			input.LogicalRequestID.String(), first.ID(),
			unknownTokenUsageProvenanceKey(reservation.ID(), OutputTokensMetric))
		exec("complete frozen schema-11 logical request", `
			UPDATE logical_requests
			SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
			    failure_code = 'provider_busy'
			WHERE logical_request_id = $1
		`, input.LogicalRequestID.String())
		exec("complete frozen schema-11 first attempt", `
			UPDATE upstream_attempts
			SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
			    http_status = 503, failure_code = 'provider_busy'
			WHERE upstream_attempt_id = $1
		`, first.ID())
		if err := tx.Commit(fixture.ctx); err != nil {
			t.Fatalf("commit frozen schema-11 settlement: %v", err)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM upstream_attempt_quota_entries AS quota
			JOIN upstream_attempts AS attempt USING (upstream_attempt_id)
			WHERE quota.upstream_attempt_id = $1
			  AND quota.allocated_units = 5
			  AND quota.charged_units = 5
			  AND quota.released_units = 0
			  AND quota.settled_at = attempt.completed_at
		`, first.ID()); got != 1 {
			t.Fatalf("reverse rolling attempt ledger rows = %d, want 1", got)
		}
		outcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if replay, err := fixture.store.Reserve(fixture.ctx, input); err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("reverse rolling reservation replay = %#v: %v", replay, err)
		}
		if replay, owner, err := fixture.store.BeginAttempt(
			fixture.ctx, reservation,
		); err != nil || owner || replay.ID() != first.ID() {
			t.Fatalf("reverse rolling attempt replay = %#v owner=%t: %v", replay, owner, err)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, first, outcome); err != nil {
			t.Fatalf("reverse rolling settlement replay: %v", err)
		}
	})

	t.Run("input total and cost retries require a fresh trusted binding", func(t *testing.T) {
		input := fixture.calendarTokenInput(t, "multi-attempt-preflight",
			calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 5},
			calendarTokenReservation{metric: OutputTokensMetric, maximum: 100, reserved: 5},
			calendarTokenReservation{metric: TotalTokensMetric, maximum: 200, reserved: 10},
		)
		input.LimitPlanKey = "multi-attempt-preflight"
		input.Pricing = PricingSelection{CatalogID: "standard-usd", Currency: USDCurrency}
		input.Rules = append(input.Rules, Rule{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: 100, ReservedUnits: 20, Hard: true,
		})
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts
				WHERE upstream_attempt_id = $1
				  AND attempt_decision_binding_version = 1
				  AND model_key = $2
				  AND octet_length(attempt_decision_sha256) = 32
				  AND input_accounting_binding_version = 1
				  AND input_accounting_method = $3
				  AND input_accounting_profile_id = $4
				  AND input_accounting_profile_digest = $5
				  AND rewritten_body_sha256 = $6
				  AND input_token_bound = $7
				  AND output_token_bound = $8
				  AND total_token_bound = $9
			`, first.ID(), input.ModelKey, input.InputPreflight.Method, input.InputPreflight.ProfileID,
			input.InputPreflight.ProfileDigest[:], input.InputPreflight.RewrittenBodySHA256[:],
			input.InputPreflight.InputTokenBound, input.InputPreflight.OutputTokenBound,
			input.InputPreflight.TotalTokenBound); got != 1 {
			t.Fatalf("first-attempt durable preflight bindings = %d, want 1", got)
		}
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle priced first attempt: %v", err)
		}
		allocations := []AttemptAllocation{
			{Metric: InputTokensMetric, Units: 4},
			{Metric: OutputTokensMetric, Units: 6},
			{Metric: TotalTokensMetric, Units: 10},
			{Metric: CostNanoUSDMetric, Units: 15},
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel:          "provider/model-v2",
			Pricing:                PricingSelection{CatalogID: "standard-usd", Currency: USDCurrency},
			InputNanoUSDPerMillion: 1,
			Allocations:            allocations,
		}
		if _, _, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unbound priced retry = %v, want ErrInvalidInput", err)
		}
		proofInput := input
		proofInput.PhysicalModel = retryInput.PhysicalModel
		retryInput.InputPreflight = trustedInputPreflight(proofInput, 4, 6)
		unpricedCost := retryInput
		unpricedCost.Pricing = PricingSelection{}
		if _, _, err := fixture.store.BeginRetryAttempt(
			fixture.ctx, first, unpricedCost,
		); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unpriced hard-cost retry = %v, want ErrInvalidInput", err)
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner {
			t.Fatalf("begin preflight-bound retry owner=%t: %v", owner, err)
		}
		changedProof := retryInput
		binding := *retryInput.InputPreflight
		binding.RewrittenBodySHA256[0] ^= 0xff
		changedProof.InputPreflight = &binding
		if _, _, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, changedProof); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("changed retry proof replay = %v, want ErrInvalidState", err)
		}
		secondOutcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200,
			Usage: Usage{
				InputTokens: 3, OutputTokens: 4, TotalTokens: 7,
				Known: true, Provenance: ProviderReportedProvenance,
			},
			Cost: Cost{
				NanoUSD: 10, Known: true, Confidence: ProviderReportedCostConfidence,
				Currency: USDCurrency, Source: ProviderReportedCostSource,
			},
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("settle priced retry: %v", err)
		}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("replay exact provider-reported retry settlement: %v", err)
		}
		for _, want := range []struct {
			metric                  string
			reserved, settled, free int64
		}{
			{metric: InputTokensMetric, reserved: 9, settled: 8, free: 1},
			{metric: OutputTokensMetric, reserved: 11, settled: 9, free: 2},
			{metric: TotalTokensMetric, reserved: 20, settled: 17, free: 3},
			{metric: CostNanoUSDMetric, reserved: 35, settled: 30, free: 5},
		} {
			assertCalendarTokenEntryState(
				t, fixture, reservation.ID(), want.metric,
				want.reserved, want.settled, want.free, want.settled, 0,
			)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 8 {
			t.Fatalf("priced retry usage records = %d, want 8", got)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM upstream_attempts AS attempt
			JOIN usage_records AS usage
			  ON usage.upstream_attempt_id = attempt.upstream_attempt_id
			WHERE attempt.upstream_attempt_id = $1
			  AND attempt.pricing_source = 'standard-usd'
			  AND attempt.cost_confidence = 'reported'
			  AND usage.metric = 'cost_nano_usd'
			  AND usage.pricing_source = 'openrouter_usage_cost'
			  AND usage.price_revision IS NULL
			  AND usage.confidence = 'reported'
			  AND usage.provenance_key = $2
		`, second.ID(), providerUsageProvenanceKey(second.ID(), CostNanoUSDMetric)); got != 1 {
			t.Fatalf("reported retry catalog/source attribution rows = %d, want 1", got)
		}
		if replay, err := fixture.store.Reserve(fixture.ctx, input); err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("preflight terminal reservation replay = %#v: %v", replay, err)
		}
		var firstDecisionDigest []byte
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT attempt_decision_sha256 FROM upstream_attempts
			WHERE upstream_attempt_id = $1
		`, first.ID()).Scan(&firstDecisionDigest); err != nil {
			t.Fatalf("read first-attempt decision digest: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE upstream_attempts
			SET attempt_decision_binding_version = 0,
			    model_key = NULL,
			    attempt_decision_sha256 = NULL,
			    input_accounting_binding_version = 0,
			    input_accounting_method = NULL,
			    input_accounting_profile_id = NULL,
			    input_accounting_profile_digest = NULL,
			    rewritten_body_sha256 = NULL,
			    input_token_bound = NULL,
			    output_token_bound = NULL,
			    total_token_bound = NULL
			WHERE upstream_attempt_id = $1
		`, first.ID()); err != nil {
			t.Fatalf("simulate schema-11 first-attempt binding: %v", err)
		}
		if replay, err := fixture.store.Reserve(fixture.ctx, input); err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("schema-11 terminal reservation replay = %#v: %v", replay, err)
		}
		if replay, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation); err != nil || owner || replay.ID() != first.ID() {
			t.Fatalf("schema-11 terminal attempt replay = %#v owner=%t: %v", replay, owner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE upstream_attempts
			SET attempt_decision_binding_version = 1,
			    model_key = $2,
			    attempt_decision_sha256 = $3,
			    input_accounting_binding_version = 1,
			    input_accounting_method = $4,
			    input_accounting_profile_id = $5,
			    input_accounting_profile_digest = $6,
			    rewritten_body_sha256 = decode(repeat('ff', 32), 'hex'),
			    input_token_bound = $7,
			    output_token_bound = $8,
			    total_token_bound = $9
			WHERE upstream_attempt_id = $1
		`, first.ID(), input.ModelKey, firstDecisionDigest,
			input.InputPreflight.Method, input.InputPreflight.ProfileID,
			input.InputPreflight.ProfileDigest[:], input.InputPreflight.InputTokenBound,
			input.InputPreflight.OutputTokenBound, input.InputPreflight.TotalTokenBound); err != nil {
			t.Fatalf("tamper first-attempt preflight: %v", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("reserve replay with tampered first proof = %v, want ErrInvalidState", err)
		}
		if _, _, err := fixture.store.BeginAttempt(fixture.ctx, reservation); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("begin replay with tampered first proof = %v, want ErrInvalidState", err)
		}
	})

	t.Run("zero-input-rate cost retry is safely bounded without input proof", func(t *testing.T) {
		input := fixture.input(t, "multi-attempt-output-priced-cost", 100)
		input.LimitPlanKey = "multi-attempt-output-priced-cost"
		input.Pricing = PricingSelection{CatalogID: "output-only", Currency: USDCurrency}
		input.Rules = append(input.Rules, Rule{
			Metric: CostNanoUSDMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: 100, ReservedUnits: 10, Hard: true,
		})
		reservation, first := reserveAndBeginTokenAttempt(t, fixture, input)
		firstOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleForRetry(fixture.ctx, first, firstOutcome); err != nil {
			t.Fatalf("settle output-priced first attempt: %v", err)
		}
		retryInput := RetryAttemptInput{
			RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
			PhysicalModel: "provider/model-v2",
			Pricing:       PricingSelection{CatalogID: "output-only", Currency: USDCurrency},
			Allocations:   []AttemptAllocation{{Metric: CostNanoUSDMetric, Units: 15}},
		}
		inputPriced := retryInput
		inputPriced.InputNanoUSDPerMillion = 1
		if _, _, err := fixture.store.BeginRetryAttempt(
			fixture.ctx, first, inputPriced,
		); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("input-priced cost retry without proof = %v, want ErrInvalidInput", err)
		}
		second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retryInput)
		if err != nil || !owner || second.Number() != 2 {
			t.Fatalf("begin output-priced cost retry = %#v owner=%t: %v", second, owner, err)
		}
		secondOutcome := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
		if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, secondOutcome); err != nil {
			t.Fatalf("settle output-priced cost retry: %v", err)
		}
		assertRetryLogicalState(t, fixture, reservation.ID(), "failed", "settled", 1, 0)
		if got := fixture.count(t, `
			SELECT count(*)
			FROM upstream_attempt_quota_entries
			WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'
			  AND allocated_units IN (10, 15) AND charged_units = allocated_units
		`, input.LogicalRequestID.String()); got != 2 {
			t.Fatalf("output-priced cost attempt ledger rows = %d, want 2", got)
		}
	})
}

func assertRetryLogicalState(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationID string,
	wantLogical string,
	wantReservation string,
	wantLogicalUsed int64,
	wantConcurrencyReserved int64,
) {
	t.Helper()
	var logicalStatus, reservationStatus string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT request.status, reservation.status
		FROM quota_reservations AS reservation
		JOIN logical_requests AS request USING (logical_request_id)
		WHERE reservation.quota_reservation_id = $1
	`, reservationID).Scan(&logicalStatus, &reservationStatus); err != nil {
		t.Fatalf("read retry logical state: %v", err)
	}
	if logicalStatus != wantLogical || reservationStatus != wantReservation {
		t.Fatalf("retry lifecycle = %s/%s, want %s/%s",
			logicalStatus, reservationStatus, wantLogical, wantReservation)
	}
	var logicalUsed, concurrencyReserved int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT COALESCE(sum(used_units) FILTER (WHERE metric = 'logical_requests'), 0),
		       COALESCE(sum(reserved_units) FILTER (WHERE metric = 'concurrent_requests'), 0)
		FROM quota_buckets
		WHERE quota_bucket_id IN (
			SELECT quota_bucket_id FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
		)
	`, reservationID).Scan(&logicalUsed, &concurrencyReserved); err != nil {
		t.Fatalf("read retry bucket state: %v", err)
	}
	if logicalUsed != wantLogicalUsed || concurrencyReserved != wantConcurrencyReserved {
		t.Fatalf("retry buckets logical-used=%d concurrency-reserved=%d, want %d/%d",
			logicalUsed, concurrencyReserved, wantLogicalUsed, wantConcurrencyReserved)
	}
}

func assertRetryUnknownUsage(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	logicalRequestID string,
	attemptID string,
	metric string,
	wantUnits int64,
	wantProvenance string,
) {
	t.Helper()
	var units int64
	var confidence, provenance, storedAttemptID string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT units, confidence, provenance_key, upstream_attempt_id
		FROM usage_records
		WHERE logical_request_id = $1 AND metric = $2 AND upstream_attempt_id = $3
	`, logicalRequestID, metric, attemptID).Scan(
		&units, &confidence, &provenance, &storedAttemptID,
	); err != nil {
		t.Fatalf("read retry unknown usage: %v", err)
	}
	if units != wantUnits || confidence != UnknownCostConfidence ||
		provenance != wantProvenance || storedAttemptID != attemptID {
		t.Fatalf("retry unknown usage = %d/%s/%s/%s, want %d/%s/%s/%s",
			units, confidence, provenance, storedAttemptID,
			wantUnits, UnknownCostConfidence, wantProvenance, attemptID)
	}
}

func TestPrepareRetryAttemptInput(t *testing.T) {
	t.Parallel()
	valid := RetryAttemptInput{
		RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "model-v2",
		PhysicalModel: "provider/model-v2",
		Allocations: []AttemptAllocation{
			{Metric: OutputTokensMetric, Units: 8},
			{Metric: InputTokensMetric, Units: 4},
			{Metric: TotalTokensMetric, Units: 12},
		},
	}
	prepared, err := prepareRetryAttemptInput(valid)
	if err != nil {
		t.Fatalf("prepare retry attempt: %v", err)
	}
	for index, metric := range []string{InputTokensMetric, OutputTokensMetric, TotalTokensMetric} {
		if prepared.Allocations[index].Metric != metric {
			t.Fatalf("allocation %d metric = %s, want %s", index, prepared.Allocations[index].Metric, metric)
		}
	}
	for index, mutate := range []func(*RetryAttemptInput){
		func(input *RetryAttemptInput) { input.Allocations[2].Units++ },
		func(input *RetryAttemptInput) { input.Allocations[0].Metric = InputTokensMetric },
		func(input *RetryAttemptInput) { input.Allocations[0].Units = 0 },
		func(input *RetryAttemptInput) { input.Allocations[0].Metric = LogicalRequestsMetric },
		func(input *RetryAttemptInput) { input.PhysicalModel = " model" },
		func(input *RetryAttemptInput) { input.InputNanoUSDPerMillion = -1 },
		func(input *RetryAttemptInput) { input.InputNanoUSDPerMillion = 1 },
	} {
		candidate := valid
		candidate.Allocations = append([]AttemptAllocation(nil), valid.Allocations...)
		mutate(&candidate)
		if _, err := prepareRetryAttemptInput(candidate); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid retry shape %d = %v, want ErrInvalidInput: %s", index, err, fmt.Sprint(candidate))
		}
	}
}

func TestStoredAttemptLifecycleValidation(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 32)
	digest[0] = 1
	modelKey := "model-v1"
	physicalModel := "provider/model-v1"
	valid := storedAttempt{
		number: 1, routeKey: "primary", upstreamKey: "provider",
		physicalModel: &physicalModel, modelKey: &modelKey, status: "started",
		attemptDecisionBindingVersion: 1, attemptDecisionSHA256: digest,
		inputAccountingBindingVersion: 1,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("validate started attempt: %v", err)
	}
	now := time.Now().UTC()
	status := int32(503)
	failure := "provider_busy"
	terminal := valid
	terminal.status = AttemptFailed
	terminal.completedAt = &now
	terminal.httpStatus = &status
	terminal.failureCode = &failure
	if err := terminal.validate(); err != nil {
		t.Fatalf("validate terminal attempt: %v", err)
	}
	for name, mutate := range map[string]func(*storedAttempt){
		"unknown status": func(attempt *storedAttempt) { attempt.status = "unknown" },
		"terminal without completion": func(attempt *storedAttempt) {
			attempt.status = AttemptFailed
		},
		"started with completion":  func(attempt *storedAttempt) { attempt.completedAt = &now },
		"started with HTTP status": func(attempt *storedAttempt) { attempt.httpStatus = &status },
		"started with failure":     func(attempt *storedAttempt) { attempt.failureCode = &failure },
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.validate(); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s validation = %v, want ErrInvalidState", name, err)
		}
	}
}
