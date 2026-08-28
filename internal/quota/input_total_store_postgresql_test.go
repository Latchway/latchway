package quota

import (
	"errors"
	"sync"
	"testing"

	"github.com/latchway/latchway/internal/id"
)

type calendarTokenReservation struct {
	metric   string
	maximum  int64
	reserved int64
}

func TestStorePostgreSQLInputAndTotalTokenQuota(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	knownUsage := Usage{
		InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
		Known: true, Provenance: ProviderReportedProvenance,
	}

	t.Run("input-only and total-only known success settle their reported metric", func(t *testing.T) {
		tests := []struct {
			name        string
			metric      string
			actual      int64
			conflicting func(*Usage)
		}{
			{
				name: "input", metric: InputTokensMetric, actual: knownUsage.InputTokens,
				conflicting: func(usage *Usage) {
					usage.InputTokens++
					usage.TotalTokens++
				},
			},
			{
				name: "total", metric: TotalTokensMetric, actual: knownUsage.TotalTokens,
				conflicting: func(usage *Usage) {
					usage.OutputTokens++
					usage.TotalTokens++
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				input := fixture.calendarTokenInput(t, "store-known-"+test.name,
					calendarTokenReservation{metric: test.metric, maximum: 100, reserved: 32},
				)
				reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
				outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage}
				if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
					t.Fatalf("settle known %s tokens: %v", test.name, err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
					t.Fatalf("replay known %s tokens: %v", test.name, err)
				}
				replayed, err := fixture.store.Reserve(fixture.ctx, input)
				if err != nil || replayed.ID() != reservation.ID() {
					t.Fatalf("reserve replay known %s = %#v, %v", test.name, replayed, err)
				}
				assertCalendarTokenEntryState(
					t, fixture, reservation.ID(), test.metric, 32, test.actual, 32-test.actual,
					test.actual, 0,
				)
				assertProviderTokenUsage(
					t, fixture, input.LogicalRequestID.String(), attempt.ID(), test.metric, test.actual,
				)
				if got := fixture.count(t, `
					SELECT count(*) FROM usage_records WHERE logical_request_id = $1
				`, input.LogicalRequestID.String()); got != 4 {
					t.Fatalf("known %s usage rows = %d, want logical plus three provider rows", test.name, got)
				}
				conflicting := outcome
				test.conflicting(&conflicting.Usage)
				if err := fixture.store.Settle(fixture.ctx, attempt, conflicting); !errors.Is(err, ErrFinalized) {
					t.Fatalf("conflicting %s replay = %v, want ErrFinalized", test.name, err)
				}
			})
		}
	})

	t.Run("mixed input output and total known success refunds each metric independently", func(t *testing.T) {
		input := fixture.calendarTokenInput(t, "store-known-mixed",
			calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 20},
			calendarTokenReservation{metric: OutputTokensMetric, maximum: 100, reserved: 15},
			calendarTokenReservation{metric: TotalTokensMetric, maximum: 100, reserved: 35},
		)
		reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle mixed token reservation: %v", err)
		}
		for _, expected := range []struct {
			metric   string
			reserved int64
			actual   int64
		}{
			{metric: InputTokensMetric, reserved: 20, actual: knownUsage.InputTokens},
			{metric: OutputTokensMetric, reserved: 15, actual: knownUsage.OutputTokens},
			{metric: TotalTokensMetric, reserved: 35, actual: knownUsage.TotalTokens},
		} {
			assertCalendarTokenEntryState(
				t, fixture, reservation.ID(), expected.metric, expected.reserved,
				expected.actual, expected.reserved-expected.actual, expected.actual, 0,
			)
		}
	})

	t.Run("two input rules share one usage record and settle both buckets", func(t *testing.T) {
		newInput := func(t *testing.T, feature string) ReserveInput {
			t.Helper()
			input := fixture.input(t, feature, 1)
			input.Rules = []Rule{
				{
					Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
					Scope: []string{"user", "feature"}, Window: "1d", Maximum: 100,
					ReservedUnits: 13, Hard: true,
				},
				{
					Metric: InputTokensMetric, Algorithm: CalendarAlgorithm,
					Scope: []string{"feature"}, Window: "1h", Maximum: 50,
					ReservedUnits: 13, Hard: true,
				},
			}
			return input
		}
		tests := []struct {
			name         string
			usage        Usage
			wantSettled  int64
			wantReleased int64
			confidence   string
		}{
			{name: "reported", usage: knownUsage, wantSettled: 11, wantReleased: 2, confidence: "reported"},
			{
				name: "unknown", usage: Usage{Provenance: UnknownUsageProvenance},
				wantSettled: 13, confidence: "unknown",
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				input := newInput(t, "store-two-input-"+test.name)
				reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
				if err := fixture.store.Settle(fixture.ctx, attempt, Outcome{
					Status: AttemptSucceeded, HTTPStatus: 200, Usage: test.usage,
				}); err != nil {
					t.Fatalf("settle two-rule %s input: %v", test.name, err)
				}
				if got := fixture.count(t, `
					SELECT count(*)
					FROM quota_reservation_entries AS entry
					JOIN quota_buckets AS bucket USING (quota_bucket_id)
					WHERE entry.quota_reservation_id = $1 AND bucket.metric = $2
					  AND entry.reserved_units = 13
					  AND entry.settled_units = $3 AND entry.released_units = $4
					  AND bucket.used_units = $3 AND bucket.reserved_units = 0
				`, reservation.ID(), InputTokensMetric, test.wantSettled, test.wantReleased); got != 2 {
					t.Fatalf("two-rule %s settled entries = %d, want 2", test.name, got)
				}
				if got := fixture.count(t, `
					SELECT count(*) FROM usage_records
					WHERE logical_request_id = $1 AND metric = $2 AND confidence = $3
				`, input.LogicalRequestID.String(), InputTokensMetric, test.confidence); got != 1 {
					t.Fatalf("two-rule %s input usage rows = %d, want 1", test.name, got)
				}
			})
		}
	})

	t.Run("known failed cancelled and timed-out attempts retain full reservations", func(t *testing.T) {
		tests := []struct {
			status      string
			httpStatus  int
			failureCode string
		}{
			{status: AttemptFailed, httpStatus: 502, failureCode: "upstream_failed"},
			{status: AttemptCancelled, failureCode: "request_cancelled"},
			{status: AttemptTimedOut, httpStatus: 504, failureCode: "upstream_timed_out"},
		}
		for _, test := range tests {
			t.Run(test.status, func(t *testing.T) {
				input := fixture.calendarTokenInput(t, "store-retain-"+test.status,
					calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 8},
					calendarTokenReservation{metric: TotalTokensMetric, maximum: 100, reserved: 12},
				)
				reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
				usage := Usage{
					InputTokens: 50, OutputTokens: 10, TotalTokens: 60,
					Known: true, Provenance: ProviderReportedProvenance,
				}
				outcome := Outcome{
					Status: test.status, HTTPStatus: test.httpStatus,
					FailureCode: test.failureCode, Usage: usage,
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
					t.Fatalf("settle known %s above reservation: %v", test.status, err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
					t.Fatalf("replay known %s: %v", test.status, err)
				}
				assertCalendarTokenEntryState(t, fixture, reservation.ID(), InputTokensMetric, 8, 8, 0, 8, 0)
				assertCalendarTokenEntryState(t, fixture, reservation.ID(), TotalTokensMetric, 12, 12, 0, 12, 0)
			})
		}
	})

	t.Run("successful known usage above a reserved metric is rejected without mutation", func(t *testing.T) {
		tests := []struct {
			name     string
			metric   string
			reserved int64
			usage    Usage
		}{
			{
				name: "input", metric: InputTokensMetric, reserved: 8,
				usage: Usage{InputTokens: 9, OutputTokens: 1, TotalTokens: 10, Known: true, Provenance: ProviderReportedProvenance},
			},
			{
				name: "total", metric: TotalTokensMetric, reserved: 9,
				usage: Usage{InputTokens: 5, OutputTokens: 5, TotalTokens: 10, Known: true, Provenance: ProviderReportedProvenance},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				input := fixture.calendarTokenInput(t, "store-over-"+test.name,
					calendarTokenReservation{metric: test.metric, maximum: 100, reserved: test.reserved},
				)
				reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
				success := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: test.usage}
				if err := fixture.store.Settle(fixture.ctx, attempt, success); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("above-reservation %s success = %v, want ErrInvalidInput", test.name, err)
				}
				assertCalendarTokenEntryState(
					t, fixture, reservation.ID(), test.metric, test.reserved, 0, 0, 0, test.reserved,
				)
				if got := fixture.count(t, `
					SELECT count(*) FROM usage_records WHERE logical_request_id = $1
				`, input.LogicalRequestID.String()); got != 0 {
					t.Fatalf("rejected %s settlement usage rows = %d, want 0", test.name, got)
				}
				failure := Outcome{
					Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_failed",
					Usage: test.usage,
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, failure); err != nil {
					t.Fatalf("settle retained %s reservation after rejection: %v", test.name, err)
				}
				assertCalendarTokenEntryState(
					t, fixture, reservation.ID(), test.metric, test.reserved,
					test.reserved, 0, test.reserved, 0,
				)
			})
		}
	})

	t.Run("mixed denial leaves the other token metric untouched", func(t *testing.T) {
		tests := []struct {
			name            string
			holderMetric    string
			untouchedMetric string
		}{
			{name: "input exceeded", holderMetric: InputTokensMetric, untouchedMetric: TotalTokensMetric},
			{name: "total exceeded", holderMetric: TotalTokensMetric, untouchedMetric: InputTokensMetric},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				feature := "store-atomic-" + test.holderMetric
				holderInput := fixture.calendarTokenInput(t, feature,
					calendarTokenReservation{metric: test.holderMetric, maximum: 10, reserved: 8},
				)
				holder, err := fixture.store.Reserve(fixture.ctx, holderInput)
				if err != nil {
					t.Fatalf("reserve %s denial holder: %v", test.holderMetric, err)
				}
				deniedInput := fixture.calendarTokenInput(t, feature,
					calendarTokenReservation{metric: test.holderMetric, maximum: 10, reserved: 4},
					calendarTokenReservation{metric: test.untouchedMetric, maximum: 4, reserved: 4},
				)
				if _, err := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(err, ErrExceeded) {
					t.Fatalf("mixed %s denial = %v, want ErrExceeded", test.holderMetric, err)
				}
				assertCalendarTokenEntryState(
					t, fixture, holder.ID(), test.holderMetric, 8, 0, 0, 0, 8,
				)
				probeInput := fixture.calendarTokenInput(t, feature,
					calendarTokenReservation{metric: test.untouchedMetric, maximum: 4, reserved: 4},
				)
				probe, err := fixture.store.Reserve(fixture.ctx, probeInput)
				if err != nil {
					t.Fatalf("reserve exact untouched %s capacity after denial: %v", test.untouchedMetric, err)
				}
				assertCalendarTokenEntryState(
					t, fixture, probe.ID(), test.untouchedMetric, 4, 0, 0, 0, 4,
				)
				if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, probe, "atomic_probe_done"); err != nil {
					t.Fatalf("release untouched %s probe: %v", test.untouchedMetric, err)
				}
				if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, holder, "atomic_holder_done"); err != nil {
					t.Fatalf("release %s denial holder: %v", test.holderMetric, err)
				}
			})
		}
	})

	t.Run("input token contention accepts exactly capacity without overspend", func(t *testing.T) {
		const callers = 8
		const maximum = 24
		const units = 6
		inputs := make([]ReserveInput, callers)
		for index := range inputs {
			inputs[index] = fixture.calendarTokenInput(t, "store-input-contention",
				calendarTokenReservation{metric: InputTokensMetric, maximum: maximum, reserved: units},
			)
		}
		start := make(chan struct{})
		reservations := make(chan Reservation, callers)
		failures := make(chan error, callers)
		var wait sync.WaitGroup
		for _, input := range inputs {
			wait.Add(1)
			go func(input ReserveInput) {
				defer wait.Done()
				<-start
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				if err != nil {
					failures <- err
					return
				}
				reservations <- reservation
			}(input)
		}
		close(start)
		wait.Wait()
		close(reservations)
		close(failures)
		accepted := make([]Reservation, 0, maximum/units)
		for reservation := range reservations {
			accepted = append(accepted, reservation)
		}
		denied := 0
		for err := range failures {
			if !errors.Is(err, ErrExceeded) {
				t.Errorf("input contention error = %v, want ErrExceeded", err)
			}
			denied++
		}
		if len(accepted) != maximum/units || denied != callers-maximum/units {
			t.Fatalf(
				"input contention accepted=%d denied=%d, want %d/%d",
				len(accepted), denied, maximum/units, callers-maximum/units,
			)
		}
		assertCalendarTokenEntryState(
			t, fixture, accepted[0].ID(), InputTokensMetric, units, 0, 0, 0, maximum,
		)
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "contention_done"); err != nil {
				t.Fatalf("release accepted input contention reservation: %v", err)
			}
		}
		assertCalendarTokenEntryState(
			t, fixture, accepted[0].ID(), InputTokensMetric, units, 0, units, 0, 0,
		)
	})

	t.Run("historical output-only unknown allocation and provenance remain unchanged", func(t *testing.T) {
		input := fixture.outputInput(t, "store-output-history", 100, 19)
		reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
		originalNewID := fixture.store.newID
		defer func() { fixture.store.newID = originalNewID }()
		generated := make([]string, 0, 2)
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix != id.UsageRecord {
				t.Fatalf("historical output settlement requested %s identifier", prefix)
			}
			value, err := originalNewID(prefix)
			if err == nil {
				generated = append(generated, value)
			}
			return value, err
		}
		outcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200,
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle historical output-only unknown usage: %v", err)
		}
		if len(generated) != 2 {
			t.Fatalf("historical output-only usage IDs = %d, want logical then unknown output", len(generated))
		}
		var logicalUsageID, logicalProvenance string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT usage_record_id, provenance_key
			FROM usage_records
			WHERE logical_request_id = $1 AND metric = $2
		`, input.LogicalRequestID.String(), LogicalRequestsMetric).Scan(
			&logicalUsageID, &logicalProvenance,
		); err != nil {
			t.Fatalf("read historical logical usage: %v", err)
		}
		var outputUsageID, outputProvenance string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT usage_record_id, provenance_key
			FROM usage_records
			WHERE logical_request_id = $1 AND metric = $2
		`, input.LogicalRequestID.String(), OutputTokensMetric).Scan(
			&outputUsageID, &outputProvenance,
		); err != nil {
			t.Fatalf("read historical unknown output usage: %v", err)
		}
		if logicalUsageID != generated[0] ||
			logicalProvenance != logicalUsageProvenanceKey(input.LogicalRequestID.String()) ||
			outputUsageID != generated[1] ||
			outputProvenance != "quota-reservation:"+reservation.ID()+":unknown-output" {
			t.Fatalf(
				"historical output-only IDs/provenance logical=%s/%s output=%s/%s generated=%v",
				logicalUsageID, logicalProvenance, outputUsageID, outputProvenance, generated,
			)
		}
		fixture.store.newID = func(id.Prefix) (string, error) {
			return "", errors.New("unexpected replay identifier allocation")
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("historical output-only replay allocated a new ID or mismatched: %v", err)
		}
		fixture.store.newID = originalNewID
	})

	t.Run("unknown success and dispatched expiry record one conservative row per reserved metric", func(t *testing.T) {
		reservations := []calendarTokenReservation{
			{metric: InputTokensMetric, maximum: 100, reserved: 13},
			{metric: OutputTokensMetric, maximum: 100, reserved: 17},
			{metric: TotalTokensMetric, maximum: 100, reserved: 30},
		}
		unknownInput := fixture.calendarTokenInput(t, "store-unknown-mixed", reservations...)
		unknownReservation, unknownAttempt := reserveAndBeginTokenAttempt(t, fixture, unknownInput)
		unknownOutcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200,
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}
		if err := fixture.store.Settle(fixture.ctx, unknownAttempt, unknownOutcome); err != nil {
			t.Fatalf("settle unknown mixed tokens: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, unknownAttempt, unknownOutcome); err != nil {
			t.Fatalf("replay unknown mixed tokens: %v", err)
		}
		assertUnknownTokenUsageSet(t, fixture, unknownInput, unknownReservation, unknownAttempt, reservations)

		expiryInput := fixture.calendarTokenInput(t, "store-expired-mixed", reservations...)
		expiryReservation, expiryAttempt := reserveAndBeginTokenAttempt(t, fixture, expiryInput)
		backdateTokenReservation(t, fixture, expiryReservation.ID())
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire dispatched mixed tokens processed=%d err=%v", processed, err)
		}
		assertUnknownTokenUsageSet(t, fixture, expiryInput, expiryReservation, expiryAttempt, reservations)
		for _, reserved := range reservations {
			assertCalendarTokenEntryState(
				t, fixture, expiryReservation.ID(), reserved.metric,
				reserved.reserved, reserved.reserved, 0, reserved.reserved, 0,
			)
		}
	})

	t.Run("pre-dispatch release refunds every input and total token unit", func(t *testing.T) {
		input := fixture.calendarTokenInput(t, "store-release-mixed",
			calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 23},
			calendarTokenReservation{metric: TotalTokensMetric, maximum: 100, reserved: 41},
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve pre-dispatch mixed tokens: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "transport_setup_failed"); err != nil {
			t.Fatalf("release pre-dispatch mixed tokens: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "transport_setup_failed"); err != nil {
			t.Fatalf("replay pre-dispatch mixed release: %v", err)
		}
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), InputTokensMetric, 23, 0, 23, 0, 0)
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), TotalTokensMetric, 41, 0, 41, 0, 0)
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("pre-dispatch release usage rows = %d, want 0", got)
		}
	})

	t.Run("undispatched expiry refunds input and total without usage", func(t *testing.T) {
		input := fixture.calendarTokenInput(t, "store-undispatched-expiry",
			calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 29},
			calendarTokenReservation{metric: TotalTokensMetric, maximum: 100, reserved: 47},
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve undispatched expiry: %v", err)
		}
		backdateTokenReservation(t, fixture, reservation.ID())
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire undispatched input/total processed=%d err=%v", processed, err)
		}
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), InputTokensMetric, 29, 0, 29, 0, 0)
		assertCalendarTokenEntryState(t, fixture, reservation.ID(), TotalTokensMetric, 47, 0, 47, 0, 0)
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("undispatched input/total expiry usage rows = %d, want 0", got)
		}
	})

	t.Run("expiry rejects a coherently corrupted total reservation relationship", func(t *testing.T) {
		input := fixture.calendarTokenInput(t, "store-corrupt-total-expiry",
			calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 11},
			calendarTokenReservation{metric: OutputTokensMetric, maximum: 100, reserved: 7},
			calendarTokenReservation{metric: TotalTokensMetric, maximum: 100, reserved: 18},
		)
		reservation, _ := reserveAndBeginTokenAttempt(t, fixture, input)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservation_entries AS entry
			SET reserved_units = 19
			FROM quota_buckets AS bucket
			WHERE entry.quota_bucket_id = bucket.quota_bucket_id
			  AND entry.quota_reservation_id = $1 AND bucket.metric = $2
		`, reservation.ID(), TotalTokensMetric); err != nil {
			t.Fatalf("corrupt durable total reservation entry: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET reserved_units = 19
			WHERE environment_id = $1 AND metric = $2
			  AND quota_bucket_id IN (
			      SELECT quota_bucket_id FROM quota_reservation_entries
			      WHERE quota_reservation_id = $3
			  )
		`, input.EnvironmentID, TotalTokensMetric, reservation.ID()); err != nil {
			t.Fatalf("corrupt durable total quota bucket: %v", err)
		}
		backdateTokenReservation(t, fixture, reservation.ID())
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if processed != 0 || !errors.Is(err, ErrInvalidState) {
			t.Fatalf("corrupt total expiry processed=%d err=%v, want 0/ErrInvalidState", processed, err)
		}
		var status string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status FROM quota_reservations WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&status); err != nil {
			t.Fatalf("read corrupt total reservation status: %v", err)
		}
		if status != "pending" {
			t.Fatalf("corrupt total reservation status = %q, want pending", status)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("corrupt total expiry usage rows = %d, want 0", got)
		}
	})

	t.Run("exact replay rejects missing usage rows and tampered successful splits", func(t *testing.T) {
		t.Run("missing unknown metric", func(t *testing.T) {
			reservations := []calendarTokenReservation{
				{metric: InputTokensMetric, maximum: 100, reserved: 13},
				{metric: TotalTokensMetric, maximum: 100, reserved: 30},
			}
			input := fixture.calendarTokenInput(t, "store-replay-missing-usage", reservations...)
			reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
			outcome := Outcome{
				Status: AttemptSucceeded, HTTPStatus: 200,
				Usage: Usage{Provenance: UnknownUsageProvenance},
			}
			if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
				t.Fatalf("settle unknown replay fixture: %v", err)
			}
			if _, err := fixture.pool.Exec(fixture.ctx, `
				DELETE FROM usage_records
				WHERE logical_request_id = $1 AND metric = $2
			`, input.LogicalRequestID.String(), TotalTokensMetric); err != nil {
				t.Fatalf("remove expected unknown total usage: %v", err)
			}
			if err := fixture.store.Settle(fixture.ctx, attempt, outcome); !errors.Is(err, ErrFinalized) {
				t.Fatalf("missing unknown usage replay = %v, want ErrFinalized", err)
			}
			if _, _, err := fixture.store.BeginAttempt(fixture.ctx, reservation); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("begin replay with missing unknown usage = %v, want ErrInvalidState", err)
			}
		})

		t.Run("tampered known split", func(t *testing.T) {
			input := fixture.calendarTokenInput(t, "store-replay-split",
				calendarTokenReservation{metric: InputTokensMetric, maximum: 100, reserved: 20},
				calendarTokenReservation{metric: TotalTokensMetric, maximum: 100, reserved: 30},
			)
			reservation, attempt := reserveAndBeginTokenAttempt(t, fixture, input)
			outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage}
			if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
				t.Fatalf("settle known split fixture: %v", err)
			}
			if _, err := fixture.pool.Exec(fixture.ctx, `
				UPDATE quota_reservation_entries AS entry
				SET settled_units = $2, released_units = entry.reserved_units - $2
				FROM quota_buckets AS bucket
				WHERE entry.quota_bucket_id = bucket.quota_bucket_id
				  AND entry.quota_reservation_id = $1 AND bucket.metric = $3
			`, reservation.ID(), knownUsage.InputTokens+1, InputTokensMetric); err != nil {
				t.Fatalf("tamper successful input split: %v", err)
			}
			if err := fixture.store.Settle(fixture.ctx, attempt, outcome); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("tampered split exact settlement replay = %v, want ErrInvalidState", err)
			}
			if _, _, err := fixture.store.BeginAttempt(fixture.ctx, reservation); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("tampered split attempt replay = %v, want ErrInvalidState", err)
			}
			if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("tampered split reserve replay = %v, want ErrInvalidState", err)
			}
		})
	})
}

func (fixture quotaPostgreSQLFixture) calendarTokenInput(
	t *testing.T,
	feature string,
	reservations ...calendarTokenReservation,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, 1)
	input.Rules = make([]Rule, 0, len(reservations))
	for _, reservation := range reservations {
		input.Rules = append(input.Rules, Rule{
			Metric: reservation.metric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: reservation.maximum, ReservedUnits: reservation.reserved, Hard: true,
		})
	}
	return input
}

func reserveAndBeginTokenAttempt(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	input ReserveInput,
) (Reservation, Attempt) {
	t.Helper()
	reservation, err := fixture.store.Reserve(fixture.ctx, input)
	if err != nil {
		t.Fatalf("reserve token quota: %v", err)
	}
	attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
	if err != nil || !owner {
		t.Fatalf("begin token attempt owner=%t: %v", owner, err)
	}
	return reservation, attempt
}

func assertCalendarTokenEntryState(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationID string,
	metric string,
	wantReserved int64,
	wantSettled int64,
	wantReleased int64,
	wantBucketUsed int64,
	wantBucketReserved int64,
) {
	t.Helper()
	var reserved, settled, released, bucketUsed, bucketReserved int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT entry.reserved_units, entry.settled_units, entry.released_units,
		       bucket.used_units, bucket.reserved_units
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		WHERE entry.quota_reservation_id = $1 AND bucket.metric = $2
	`, reservationID, metric).Scan(
		&reserved, &settled, &released, &bucketUsed, &bucketReserved,
	); err != nil {
		t.Fatalf("read %s token entry state: %v", metric, err)
	}
	if reserved != wantReserved || settled != wantSettled || released != wantReleased ||
		bucketUsed != wantBucketUsed || bucketReserved != wantBucketReserved {
		t.Fatalf(
			"%s token state entry=%d/%d/%d bucket=%d/%d, want %d/%d/%d and %d/%d",
			metric, reserved, settled, released, bucketUsed, bucketReserved,
			wantReserved, wantSettled, wantReleased, wantBucketUsed, wantBucketReserved,
		)
	}
}

func assertProviderTokenUsage(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	logicalRequestID string,
	attemptID string,
	metric string,
	wantUnits int64,
) {
	t.Helper()
	var units int64
	var confidence, provenance, storedAttemptID string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT units, confidence, provenance_key, upstream_attempt_id
		FROM usage_records
		WHERE logical_request_id = $1 AND metric = $2
	`, logicalRequestID, metric).Scan(&units, &confidence, &provenance, &storedAttemptID); err != nil {
		t.Fatalf("read provider %s usage: %v", metric, err)
	}
	if units != wantUnits || confidence != "reported" ||
		provenance != providerUsageProvenanceKey(attemptID, metric) || storedAttemptID != attemptID {
		t.Fatalf("provider %s usage=%d/%s/%s/%s", metric, units, confidence, provenance, storedAttemptID)
	}
}

func assertUnknownTokenUsageSet(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	input ReserveInput,
	reservation Reservation,
	attempt Attempt,
	reservations []calendarTokenReservation,
) {
	t.Helper()
	if got := fixture.count(t, `
		SELECT count(*) FROM usage_records
		WHERE logical_request_id = $1 AND confidence = 'unknown'
	`, input.LogicalRequestID.String()); got != int64(len(reservations)) {
		t.Fatalf("unknown token usage rows = %d, want %d", got, len(reservations))
	}
	for _, expected := range reservations {
		var units int64
		var confidence, provenance, attemptID string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT units, confidence, provenance_key, upstream_attempt_id
			FROM usage_records
			WHERE logical_request_id = $1 AND metric = $2
		`, input.LogicalRequestID.String(), expected.metric).Scan(
			&units, &confidence, &provenance, &attemptID,
		); err != nil {
			t.Fatalf("read unknown %s usage: %v", expected.metric, err)
		}
		wantProvenance := unknownTokenUsageProvenanceKey(reservation.ID(), expected.metric)
		if units != expected.reserved || confidence != "unknown" ||
			provenance != wantProvenance || attemptID != attempt.ID() {
			t.Fatalf(
				"unknown %s usage=%d/%s/%s/%s, want %d/unknown/%s/%s",
				expected.metric, units, confidence, provenance, attemptID,
				expected.reserved, wantProvenance, attempt.ID(),
			)
		}
	}
}

func backdateTokenReservation(t *testing.T, fixture quotaPostgreSQLFixture, reservationID string) {
	t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = $1
	`, reservationID); err != nil {
		t.Fatalf("backdate token reservation: %v", err)
	}
}
