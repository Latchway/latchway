package quota

import (
	"errors"
	"testing"

	"github.com/latchway/latchway/internal/upstream"
)

func rejectedAttemptOutcome() Outcome {
	return Outcome{Status: AttemptFailed, HTTPStatus: 400, FailureCode: "upstream_request_rejected",
		Diagnostics: &AttemptDiagnostics{AccountingPolicy: ProviderRejectionAccountingV1,
			ProviderError: upstream.ProviderErrorDiagnostics{Category: "invalid_request", Parameter: "messages[0].content"}}}
}

func TestRejectedAttemptAccountingValidation(t *testing.T) {
	valid := rejectedAttemptOutcome()
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Outcome){
		func(o *Outcome) { o.Diagnostics = nil },
		func(o *Outcome) { o.HTTPStatus = 200 },
		func(o *Outcome) { o.HTTPStatus = 422 },
		func(o *Outcome) { o.Status = AttemptTimedOut },
		func(o *Outcome) { o.FailureCode = "upstream_non_success" },
		func(o *Outcome) { o.Usage = Usage{Known: true, Provenance: ProviderReportedProvenance} },
		func(o *Outcome) { o.Diagnostics.ProviderError.Category = "timeout" },
		func(o *Outcome) { o.Diagnostics.ProviderError.Parameter = "secret-user-text" },
		func(o *Outcome) { o.Diagnostics.AccountingPolicy = "refund_everything" },
	} {
		o := rejectedAttemptOutcome()
		mutate(&o)
		if o.validate() == nil {
			t.Fatalf("accepted invalid rejection: %#v", o)
		}
	}
}

func TestVersionedFailedAttemptCharges(t *testing.T) {
	known := Usage{InputTokens: 2, OutputTokens: 3, TotalTokens: 5, Known: true, Provenance: ProviderReportedProvenance}
	for _, tc := range []struct {
		name    string
		outcome Outcome
		want    int64
	}{
		{"rejected", rejectedAttemptOutcome(), 0},
		{"unknown400", Outcome{Status: AttemptFailed, HTTPStatus: 400, FailureCode: "upstream_non_success"}, 100},
		{"timeout", Outcome{Status: AttemptTimedOut, FailureCode: "upstream_timeout"}, 100},
		{"legacy reported failure", Outcome{Status: AttemptFailed, HTTPStatus: 200, FailureCode: "upstream_protocol_error", Usage: known}, 100},
		{"reported failure v1", Outcome{Status: AttemptFailed, HTTPStatus: 200, FailureCode: "upstream_protocol_error", Usage: known, Diagnostics: &AttemptDiagnostics{AccountingPolicy: ReportedUsageAccountingV1}}, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.outcome.validate() != nil {
				t.Fatal("invalid fixture")
			}
			got, err := retryAttemptChargedUnits(lockedAttemptQuotaEntry{metric: TotalTokensMetric, allocated: 100}, tc.outcome)
			if err != nil || got != tc.want {
				t.Fatalf("got %d/%v want %d", got, err, tc.want)
			}
		})
	}
	for _, metric := range []string{InputTokensMetric, OutputTokensMetric, TotalTokensMetric, CostNanoUSDMetric} {
		got, err := retryAttemptChargedUnits(lockedAttemptQuotaEntry{metric: metric, allocated: 100}, rejectedAttemptOutcome())
		if err != nil || got != 0 {
			t.Fatalf("%s not released", metric)
		}
	}
	got, err := retryAttemptChargedUnits(lockedAttemptQuotaEntry{metric: UpstreamAttemptsMetric, allocated: 1}, rejectedAttemptOutcome())
	if err != nil || got != 1 {
		t.Fatal("rejected attempt must still count")
	}
}

func TestStorePostgreSQLRejectedAttemptReleasesTokensAndReplays(t *testing.T) {
	f := newQuotaPostgreSQLFixture(t)
	input := f.calendarTokenInput(t, "rejected-input-total",
		calendarTokenReservation{metric: InputTokensMetric, maximum: 100000, reserved: 91420},
		calendarTokenReservation{metric: OutputTokensMetric, maximum: 100000, reserved: 1024},
		calendarTokenReservation{metric: TotalTokensMetric, maximum: 100000, reserved: 92444})
	reservation, attempt := reserveAndBeginTokenAttempt(t, f, input)
	outcome := rejectedAttemptOutcome()
	for range 2 {
		if err := f.store.SettleFinalAttempt(f.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle/replay: %v", err)
		}
	}
	for _, item := range []struct {
		metric string
		bound  int64
	}{{InputTokensMetric, 91420}, {OutputTokensMetric, 1024}, {TotalTokensMetric, 92444}} {
		assertCalendarTokenEntryState(t, f, reservation.ID(), item.metric, item.bound, 0, item.bound, 0, 0)
	}
	if got := f.count(t, `SELECT count(*) FROM usage_records WHERE upstream_attempt_id=$1 AND confidence='calculated' AND units=0`, attempt.ID()); got != 3 {
		t.Fatalf("calculated zero records %d", got)
	}
	if got := f.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id=$1 AND metric='logical_requests' AND units=1`, input.LogicalRequestID.String()); got != 1 {
		t.Fatalf("logical request count %d", got)
	}
	changed := rejectedAttemptOutcome()
	changed.Diagnostics.ProviderError.Parameter = "model"
	if err := f.store.SettleFinalAttempt(f.ctx, attempt, changed); !errors.Is(err, ErrFinalized) {
		t.Fatalf("conflicting diagnostics: %v", err)
	}
	if _, err := f.store.Reserve(f.ctx, input); err != nil {
		t.Fatalf("reservation replay after rejection: %v", err)
	}
}

func TestStorePostgreSQLFailedReportedUsageVersionedSettlement(t *testing.T) {
	f := newQuotaPostgreSQLFixture(t)
	input := f.calendarTokenInput(t, "failed-reported-v1", calendarTokenReservation{metric: TotalTokensMetric, maximum: 1000, reserved: 100})
	reservation, attempt := reserveAndBeginTokenAttempt(t, f, input)
	outcome := Outcome{Status: AttemptFailed, HTTPStatus: 200, FailureCode: "upstream_protocol_error",
		Usage:       Usage{InputTokens: 2, OutputTokens: 3, TotalTokens: 5, Known: true, Provenance: ProviderReportedProvenance},
		Diagnostics: &AttemptDiagnostics{AccountingPolicy: ReportedUsageAccountingV1}}
	for range 2 {
		if err := f.store.SettleFinalAttempt(f.ctx, attempt, outcome); err != nil {
			t.Fatal(err)
		}
	}
	assertCalendarTokenEntryState(t, f, reservation.ID(), TotalTokensMetric, 100, 5, 95, 5, 0)
	if _, err := f.store.Reserve(f.ctx, input); err != nil {
		t.Fatalf("reservation replay: %v", err)
	}
}

func TestStorePostgreSQLRejectionCannotRefundObservedAttempt(t *testing.T) {
	for _, tokenObserved := range []bool{false, true} {
		f := newQuotaPostgreSQLFixture(t)
		input := f.calendarTokenInput(t, "observed-not-rejected", calendarTokenReservation{metric: TotalTokensMetric, maximum: 1000, reserved: 100})
		reservation, attempt := reserveAndBeginTokenAttempt(t, f, input)
		if err := f.store.MarkFirstByte(f.ctx, attempt); err != nil {
			t.Fatal(err)
		}
		if tokenObserved {
			if err := f.store.MarkFirstToken(f.ctx, attempt); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.store.SettleFinalAttempt(f.ctx, attempt, rejectedAttemptOutcome()); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("observed attempt accepted rejection: %v", err)
		}
		if got := f.count(t, `SELECT count(*) FROM upstream_attempt_diagnostics WHERE upstream_attempt_id=$1`, attempt.ID()); got != 0 {
			t.Fatalf("rejected evidence committed: %d", got)
		}
		if got := f.count(t, `SELECT count(*) FROM usage_records WHERE upstream_attempt_id=$1`, attempt.ID()); got != 0 {
			t.Fatalf("rejection usage committed: %d", got)
		}
		// The failed claim changed nothing; ordinary uncertain settlement still
		// completes the lifecycle and charges its conservative reservation.
		uncertain := Outcome{Status: AttemptFailed, HTTPStatus: 400, FailureCode: "upstream_non_success"}
		if err := f.store.SettleFinalAttempt(f.ctx, attempt, uncertain); err != nil {
			t.Fatal(err)
		}
		assertCalendarTokenEntryState(t, f, reservation.ID(), TotalTokensMetric, 100, 100, 0, 100, 0)
	}
}

func TestStorePostgreSQLRejectionReplayRejectsContradictoryStoredObservation(t *testing.T) {
	f := newQuotaPostgreSQLFixture(t)
	input := f.calendarTokenInput(t, "rejected-observation-corruption", calendarTokenReservation{metric: TotalTokensMetric, maximum: 1000, reserved: 100})
	_, attempt := reserveAndBeginTokenAttempt(t, f, input)
	outcome := rejectedAttemptOutcome()
	if err := f.store.SettleFinalAttempt(f.ctx, attempt, outcome); err != nil {
		t.Fatal(err)
	}
	// Deliberately corrupt only this isolated test record after a valid
	// settlement; no historical production evidence is modified.
	if _, err := f.pool.Exec(f.ctx, `UPDATE upstream_attempts SET first_byte_at=started_at, first_token_at=started_at WHERE upstream_attempt_id=$1`, attempt.ID()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SettleFinalAttempt(f.ctx, attempt, outcome); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("settlement replay accepted contradictory evidence: %v", err)
	}
	if _, err := f.store.Reserve(f.ctx, input); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reservation replay accepted contradictory evidence: %v", err)
	}
}
