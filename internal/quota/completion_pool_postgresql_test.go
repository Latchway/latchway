package quota

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCompletionLifecycleUsesReservedPoolWhenRegularPoolIsSaturated(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	regularConfig := fixture.pool.Config()
	regularConfig.MaxConns = 2
	regularConfig.MinConns = 0
	regular, err := pgxpool.NewWithConfig(fixture.ctx, regularConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(regular.Close)
	completionConfig := fixture.pool.Config()
	completionConfig.MaxConns = 1
	completionConfig.MinConns = 0
	completion, err := pgxpool.NewWithConfig(fixture.ctx, completionConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(completion.Close)
	store, err := NewStore(StoreConfig{
		Pool: regular, CompletionPool: completion, MaxConcurrentReservations: 1,
		ReservationTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	reserveAttempt := func(feature string) (Reservation, Attempt) {
		t.Helper()
		reservation, reserveErr := store.Reserve(fixture.ctx, fixture.input(t, feature, 10))
		if reserveErr != nil {
			t.Fatalf("reserve %s: %v", feature, reserveErr)
		}
		attempt, owner, beginErr := store.BeginAttempt(fixture.ctx, reservation)
		if beginErr != nil || !owner {
			t.Fatalf("begin %s owner=%t: %v", feature, owner, beginErr)
		}
		return reservation, attempt
	}
	fallbackReservation, fallbackAttempt := reserveAttempt("completion-fast-fallback")
	markedReservation, markedAttempt := reserveAttempt("completion-first-byte")
	released, err := store.Reserve(fixture.ctx, fixture.input(t, "completion-release", 10))
	if err != nil {
		t.Fatal(err)
	}
	retryPendingReservation, retryPendingAttempt := reserveAttempt("completion-retry-settle")
	finalRetryReservation, finalRetryFirst := reserveAttempt("completion-retry-final")
	retryFailure := Outcome{
		Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy",
	}
	if err := store.SettleForRetry(fixture.ctx, finalRetryFirst, retryFailure); err != nil {
		t.Fatalf("prepare final retry first settlement: %v", err)
	}
	finalRetrySecond, owner, err := store.BeginRetryAttempt(fixture.ctx, finalRetryFirst, RetryAttemptInput{
		RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "retry",
		PhysicalModel: "provider/model-v2",
	})
	if err != nil || !owner {
		t.Fatalf("prepare final retry second attempt owner=%t: %v", owner, err)
	}
	expired, err := store.Reserve(fixture.ctx, fixture.input(t, "completion-expiry", 10))
	if err != nil {
		t.Fatalf("reserve expiry fixture: %v", err)
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = $1
	`, expired.ID()); err != nil {
		t.Fatalf("expire completion-pool fixture: %v", err)
	}

	held := make([]*pgxpool.Conn, 0, regularConfig.MaxConns)
	for range regularConfig.MaxConns {
		connection, acquireErr := regular.Acquire(fixture.ctx)
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		held = append(held, connection)
	}
	defer func() {
		for _, connection := range held {
			connection.Release()
		}
	}()

	operationContext, cancel := context.WithTimeout(fixture.ctx, 2*time.Second)
	defer cancel()
	// With no first-byte record, the narrow initial fast settlement rolls back
	// and the exhaustive classifier must reacquire the same completion class.
	if err := store.Settle(operationContext, fallbackAttempt, hotPathSuccessOutcome()); err != nil {
		t.Fatalf("fallback settlement while regular pool saturated: %v", err)
	}
	if err := store.MarkFirstByte(operationContext, markedAttempt); err != nil {
		t.Fatalf("first-byte record while regular pool saturated: %v", err)
	}
	if err := store.Settle(operationContext, markedAttempt, hotPathSuccessOutcome()); err != nil {
		t.Fatalf("marked settlement while regular pool saturated: %v", err)
	}
	if err := store.ReleaseBeforeDispatch(operationContext, released, "routing_failed"); err != nil {
		t.Fatalf("release while regular pool saturated: %v", err)
	}
	if err := store.SettleForRetry(operationContext, retryPendingAttempt, retryFailure); err != nil {
		t.Fatalf("retry settlement while regular pool saturated: %v", err)
	}
	if err := store.SettleFinalAttempt(operationContext, finalRetrySecond, retryFailure); err != nil {
		t.Fatalf("final retry settlement while regular pool saturated: %v", err)
	}
	if processed, err := store.ExpirePendingBatch(operationContext, 1); err != nil || processed != 1 {
		t.Fatalf("expiry while regular pool saturated processed=%d err=%v, want 1 nil", processed, err)
	}

	for _, expected := range []struct {
		reservation Reservation
		status      string
	}{
		{fallbackReservation, "settled"},
		{markedReservation, "settled"},
		{released, "released"},
		{retryPendingReservation, "pending"},
		{finalRetryReservation, "settled"},
		{expired, "expired"},
	} {
		var status string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status FROM quota_reservations WHERE quota_reservation_id = $1
		`, expected.reservation.ID()).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != expected.status {
			t.Fatalf("reservation %s status=%q, want %q",
				expected.reservation.ID(), status, expected.status)
		}
	}
	for _, attempt := range []Attempt{retryPendingAttempt, finalRetrySecond} {
		var status string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status FROM upstream_attempts WHERE upstream_attempt_id = $1
		`, attempt.ID()).Scan(&status); err != nil {
			t.Fatalf("read completion-pool attempt %s: %v", attempt.ID(), err)
		}
		if status != AttemptFailed {
			t.Fatalf("completion-pool attempt %s status=%q, want %q", attempt.ID(), status, AttemptFailed)
		}
	}
}

func TestBeginRetryAdmissionIsIndependentFromCompletionProgressPostgreSQL(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	regularConfig := fixture.pool.Config()
	regularConfig.MaxConns = 2
	regularConfig.MinConns = 0
	var observeRegularAcquisition atomic.Bool
	var observedRegularAcquisitions atomic.Int32
	regularConfig.BeforeAcquire = func(context.Context, *pgx.Conn) bool {
		if observeRegularAcquisition.Load() {
			observedRegularAcquisitions.Add(1)
		}
		return true
	}
	regular, err := pgxpool.NewWithConfig(fixture.ctx, regularConfig)
	if err != nil {
		t.Fatalf("open retry-admission regular pool: %v", err)
	}
	t.Cleanup(regular.Close)
	completionConfig := fixture.pool.Config()
	completionConfig.MaxConns = 1
	completionConfig.MinConns = 0
	completion, err := pgxpool.NewWithConfig(fixture.ctx, completionConfig)
	if err != nil {
		t.Fatalf("open retry-admission completion pool: %v", err)
	}
	t.Cleanup(completion.Close)
	store, err := NewStore(StoreConfig{
		Pool: regular, CompletionPool: completion, MaxConcurrentReservations: 1,
		ReservationTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("construct retry-admission store: %v", err)
	}

	retryReservation, err := store.Reserve(
		fixture.ctx, fixture.input(t, "retry-admission-gate", 10),
	)
	if err != nil {
		t.Fatalf("reserve retry-admission request: %v", err)
	}
	firstRetryAttempt, owner, err := store.BeginAttempt(fixture.ctx, retryReservation)
	if err != nil || !owner {
		t.Fatalf("begin retry-admission first attempt owner=%t: %v", owner, err)
	}
	retryFailure := Outcome{
		Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy",
	}
	if err := store.SettleForRetry(fixture.ctx, firstRetryAttempt, retryFailure); err != nil {
		t.Fatalf("settle retry-admission first attempt: %v", err)
	}

	completionReservation, err := store.Reserve(
		fixture.ctx, fixture.input(t, "retry-admission-completion", 10),
	)
	if err != nil {
		t.Fatalf("reserve independent completion request: %v", err)
	}
	completionAttempt, owner, err := store.BeginAttempt(fixture.ctx, completionReservation)
	if err != nil || !owner {
		t.Fatalf("begin independent completion attempt owner=%t: %v", owner, err)
	}

	// Leave an idle regular connection available and begin observing only after
	// fixture preparation. If BeginRetryAttempt bypasses reservation admission,
	// BeforeAcquire makes that pool access visible even when a slow database
	// causes the bounded call to return a context error.
	idle, err := regular.Acquire(fixture.ctx)
	if err != nil {
		t.Fatalf("prepare idle regular connection: %v", err)
	}
	idle.Release()
	observeRegularAcquisition.Store(true)

	releaseAdmission, err := acquireStoreAdmission(fixture.ctx, store.reservationAdmission)
	if err != nil {
		t.Fatalf("hold reservation admission: %v", err)
	}
	admissionHeld := true
	defer func() {
		if admissionHeld {
			releaseAdmission()
		}
	}()

	retryInput := RetryAttemptInput{
		RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "retry",
		PhysicalModel: "provider/model-v2",
	}
	blockedContext, cancelBlocked := context.WithTimeout(fixture.ctx, 500*time.Millisecond)
	_, _, blockedErr := store.BeginRetryAttempt(blockedContext, firstRetryAttempt, retryInput)
	cancelBlocked()
	if !errors.Is(blockedErr, context.DeadlineExceeded) {
		t.Fatalf("retry while reservation admission held = %v, want deadline exceeded", blockedErr)
	}
	if acquired := observedRegularAcquisitions.Load(); acquired != 0 {
		t.Fatalf("blocked retry acquired the regular pool %d times", acquired)
	}

	completionContext, cancelCompletion := context.WithTimeout(fixture.ctx, 2*time.Second)
	defer cancelCompletion()
	if err := store.MarkFirstByte(completionContext, completionAttempt); err != nil {
		t.Fatalf("mark first byte while reservation admission held: %v", err)
	}
	if err := store.Settle(completionContext, completionAttempt, hotPathSuccessOutcome()); err != nil {
		t.Fatalf("settle while reservation admission held: %v", err)
	}
	if acquired := observedRegularAcquisitions.Load(); acquired != 0 {
		t.Fatalf("completion lifecycle acquired the regular pool %d times", acquired)
	}

	releaseAdmission()
	admissionHeld = false
	secondRetryAttempt, owner, err := store.BeginRetryAttempt(
		fixture.ctx, firstRetryAttempt, retryInput,
	)
	if err != nil || !owner || secondRetryAttempt.Number() != 2 {
		t.Fatalf("begin retry after admission release = %#v owner=%t: %v",
			secondRetryAttempt, owner, err)
	}
	if acquired := observedRegularAcquisitions.Load(); acquired == 0 {
		t.Fatal("released retry did not acquire the regular pool")
	}
	if err := store.SettleFinalAttempt(fixture.ctx, secondRetryAttempt, retryFailure); err != nil {
		t.Fatalf("settle retry-admission final attempt: %v", err)
	}
}

func TestReservationAdmissionPreservesRegularPoolHeadroomDuringSharedBucketContention(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	regularConfig, err := pgxpool.ParseConfig(fixture.databaseURL)
	if err != nil {
		t.Fatalf("parse regular pool config: %v", err)
	}
	regularConfig.MaxConns = 4
	regularConfig.MinConns = 0
	applicationName := fmt.Sprintf("quota-admission-%d", time.Now().UnixNano())
	if regularConfig.ConnConfig.RuntimeParams == nil {
		regularConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	regularConfig.ConnConfig.RuntimeParams["application_name"] = applicationName
	regular, err := pgxpool.NewWithConfig(fixture.ctx, regularConfig)
	if err != nil {
		t.Fatalf("open regular pool: %v", err)
	}
	t.Cleanup(regular.Close)
	store, err := NewStore(StoreConfig{
		Pool: regular, CompletionPool: fixture.pool, MaxConcurrentReservations: 2,
		ReservationTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("construct admission-limited store: %v", err)
	}

	const feature = "shared-bucket-admission"
	seed, err := store.Reserve(fixture.ctx, fixture.input(t, feature, 100))
	if err != nil {
		t.Fatalf("materialize shared quota bucket: %v", err)
	}
	if err := store.ReleaseBeforeDispatch(fixture.ctx, seed, "routing_failed"); err != nil {
		t.Fatalf("release shared-bucket seed: %v", err)
	}
	var bucketID string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT quota_bucket_id
		FROM quota_reservation_entries
		WHERE quota_reservation_id = $1
	`, seed.ID()).Scan(&bucketID); err != nil {
		t.Fatalf("resolve shared quota bucket: %v", err)
	}

	lockTx, err := fixture.pool.Begin(fixture.ctx)
	if err != nil {
		t.Fatalf("begin shared-row lock: %v", err)
	}
	lockReleased := false
	if err := lockTx.QueryRow(fixture.ctx, `
		SELECT quota_bucket_id FROM quota_buckets
		WHERE quota_bucket_id = $1
		FOR UPDATE
	`, bucketID).Scan(&bucketID); err != nil {
		_ = lockTx.Rollback(fixture.ctx)
		t.Fatalf("lock shared quota bucket: %v", err)
	}

	const reservationCount = 6
	contentionContext, cancelContention := context.WithTimeout(fixture.ctx, 10*time.Second)
	type reserveResult struct {
		reservation Reservation
		err         error
	}
	started := make(chan struct{}, reservationCount)
	results := make(chan reserveResult, reservationCount)
	start := make(chan struct{})
	inputs := make([]ReserveInput, reservationCount)
	for index := range inputs {
		inputs[index] = fixture.input(t, feature, 100)
	}
	var wait sync.WaitGroup
	wait.Add(reservationCount)
	for index := range inputs {
		go func(input ReserveInput) {
			defer wait.Done()
			<-start
			started <- struct{}{}
			reservation, reserveErr := store.Reserve(
				contentionContext,
				input,
			)
			results <- reserveResult{reservation: reservation, err: reserveErr}
		}(inputs[index])
	}
	close(start)

	var headroom []*pgxpool.Conn
	defer func() {
		cancelContention()
		for _, connection := range headroom {
			connection.Release()
		}
		if !lockReleased {
			cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
			_ = lockTx.Rollback(cleanupContext)
			cleanupCancel()
		}
		wait.Wait()
	}()
	for range reservationCount {
		select {
		case <-started:
		case <-contentionContext.Done():
			t.Fatalf("reservation goroutines did not start: %v", context.Cause(contentionContext))
		}
	}

	waitContext, cancelWait := context.WithTimeout(contentionContext, 3*time.Second)
	defer cancelWait()
	blocked := int64(0)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for blocked != 2 {
		if err := fixture.pool.QueryRow(waitContext, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE application_name = $1 AND wait_event_type = 'Lock'
		`, applicationName).Scan(&blocked); err != nil {
			t.Fatalf("inspect blocked reservations: %v", err)
		}
		if blocked > 2 {
			t.Fatalf("blocked reservation transactions=%d, exceeds admission cap 2", blocked)
		}
		if blocked == 2 {
			break
		}
		select {
		case <-ticker.C:
		case <-waitContext.Done():
			t.Fatalf("blocked reservation transactions=%d, want 2: %v", blocked, context.Cause(waitContext))
		}
	}

	cancelWait()
	headroomContext, cancelHeadroom := context.WithTimeout(contentionContext, 2*time.Second)
	defer cancelHeadroom()
	for len(headroom) < 2 {
		connection, acquireErr := regular.Acquire(headroomContext)
		if acquireErr != nil {
			t.Fatalf("acquire non-reservation connection %d: %v", len(headroom)+1, acquireErr)
		}
		var probe int
		if err := connection.QueryRow(headroomContext, "SELECT 1").Scan(&probe); err != nil || probe != 1 {
			connection.Release()
			t.Fatalf("run non-reservation database work on headroom connection: value=%d err=%v", probe, err)
		}
		headroom = append(headroom, connection)
	}
	if acquired := regular.Stat().AcquiredConns(); acquired != 4 {
		t.Fatalf("regular acquired connections=%d, want two reservations plus two headroom", acquired)
	}
	select {
	case result := <-results:
		t.Fatalf("reservation completed while shared quota row remained locked: %v", result.err)
	default:
	}
	for _, connection := range headroom {
		connection.Release()
	}
	headroom = nil
	if err := lockTx.Commit(contentionContext); err != nil {
		t.Fatalf("release shared quota row: %v", err)
	}
	lockReleased = true

	for range reservationCount {
		select {
		case result := <-results:
			if result.err != nil {
				t.Errorf("reserve after shared-row release: %v", result.err)
			} else if result.reservation.ID() == "" {
				t.Error("reserve after shared-row release returned an empty reservation")
			}
		case <-contentionContext.Done():
			t.Fatalf("reservations did not finish after shared-row release: %v", context.Cause(contentionContext))
		}
	}
	wait.Wait()
}
