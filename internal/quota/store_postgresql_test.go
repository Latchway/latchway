package quota

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

const (
	quotaTestOrganizationID    = "org_00000000000000000000000001"
	quotaTestApplicationID     = "app_00000000000000000000000001"
	quotaTestEnvironmentID     = "env_00000000000000000000000001"
	quotaTestApplicationUserID = "usr_00000000000000000000000001"
	quotaTestInstallationID    = "ins_00000000000000000000000001"
	quotaTestSessionGrantID    = "sgr_00000000000000000000000001"
	quotaTestConfigRevisionID  = "rev_00000000000000000000000001"
)

var quotaTestSchemaPattern = regexp.MustCompile(`^latchway_quota_test_[0-9]+$`)

type quotaPostgreSQLFixture struct {
	ctx         context.Context
	pool        *pgxpool.Pool
	store       *Store
	databaseURL string
}

func TestStorePostgreSQLQuotaLifecycle(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("reserve attempt settle denial and duplicate client hint", func(t *testing.T) {
		input := fixture.input(t, "lifecycle", 1)
		input.ClientRequestID = "shared-client-hint"
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if reservation.LogicalRequestID() != input.LogicalRequestID.String() {
			t.Fatalf("persisted logical ID = %q, want %q", reservation.LogicalRequestID(), input.LogicalRequestID.String())
		}

		deniedInput := fixture.input(t, "lifecycle", 1)
		deniedInput.ClientRequestID = input.ClientRequestID
		const denialCallers = 8
		denialStart := make(chan struct{})
		denials := make(chan error, denialCallers)
		var denialWait sync.WaitGroup
		for range denialCallers {
			denialWait.Add(1)
			go func() {
				defer denialWait.Done()
				<-denialStart
				_, reserveErr := fixture.store.Reserve(fixture.ctx, deniedInput)
				denials <- reserveErr
			}()
		}
		close(denialStart)
		denialWait.Wait()
		close(denials)
		for denialErr := range denials {
			var denial *ExceededError
			if !errors.As(denialErr, &denial) || !errors.Is(denialErr, ErrExceeded) {
				t.Errorf("concurrent denial = %v, want quota denial", denialErr)
				continue
			}
			if denial.LogicalRequestID() != deniedInput.LogicalRequestID.String() || denial.RetryAt().IsZero() {
				t.Errorf("denial = %#v", denial)
			}
		}
		if _, replayErr := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(replayErr, ErrExceeded) {
			t.Fatalf("denial replay = %v, want ErrExceeded", replayErr)
		}
		deniedMutations := []struct {
			name   string
			mutate func(*ReserveInput)
		}{
			{name: "route", mutate: func(input *ReserveInput) { input.RouteKey = "secondary" }},
			{name: "upstream", mutate: func(input *ReserveInput) { input.UpstreamKey = "alternate" }},
			{name: "model", mutate: func(input *ReserveInput) {
				input.ModelKey = "accurate"
				input.PhysicalModel = "provider/model-v2"
			}},
			{name: "rule maximum", mutate: func(input *ReserveInput) { input.Rules[0].Maximum++ }},
			{name: "rule window", mutate: func(input *ReserveInput) { input.Rules[0].Window = "1h" }},
			{name: "scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = []string{"installation"} }},
		}
		for _, mutation := range deniedMutations {
			changed := cloneReserveInput(deniedInput)
			mutation.mutate(&changed)
			if _, replayErr := fixture.store.Reserve(fixture.ctx, changed); !errors.Is(replayErr, ErrInvalidInput) {
				t.Errorf("denied %s replay = %v, want ErrInvalidInput", mutation.name, replayErr)
			}
		}
		if got := fixture.count(t, `SELECT count(*) FROM logical_requests WHERE client_request_id = $1`, input.ClientRequestID); got != 2 {
			t.Fatalf("logical rows sharing client hint = %d, want 2", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied attempts = %d, want 0", got)
		}

		attempt, dispatchOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin attempt owner=%t: %v", dispatchOwner, err)
		}
		originalNewID := fixture.store.newID
		defer func() { fixture.store.newID = originalNewID }()
		fixture.store.newID = func(id.Prefix) (string, error) {
			return "", errors.New("entropy unavailable")
		}
		replayedAttempt, replayOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || replayOwner || replayedAttempt.ID() != attempt.ID() {
			t.Fatalf("begin attempt replay = %#v owner=%t, %v", replayedAttempt, replayOwner, err)
		}
		fixture.store.newID = originalNewID
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark first byte: %v", err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark first byte replay: %v", err)
		}
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle: %v", err)
		}
		terminalAttempt, terminalOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || terminalOwner || terminalAttempt.ID() != attempt.ID() {
			t.Fatalf("terminal begin replay = %#v owner=%t, %v", terminalAttempt, terminalOwner, err)
		}
		fixture.store.newID = func(id.Prefix) (string, error) {
			return "", errors.New("entropy unavailable")
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle replay: %v", err)
		}
		fixture.store.newID = originalNewID
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "transport_setup_failed"); !errors.Is(err, ErrFinalized) {
			t.Fatalf("release after settle = %v, want ErrFinalized", err)
		}

		var logicalStatus, attemptStatus, reservationStatus string
		var httpStatus int
		var used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT request.status, attempt.status, attempt.http_status,
			       reservation.status, bucket.used_units, bucket.reserved_units
			FROM logical_requests AS request
			JOIN upstream_attempts AS attempt USING (logical_request_id)
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE request.logical_request_id = $1
		`, input.LogicalRequestID.String()).Scan(
			&logicalStatus, &attemptStatus, &httpStatus, &reservationStatus, &used, &reserved,
		); err != nil {
			t.Fatalf("read settled state: %v", err)
		}
		if logicalStatus != "succeeded" || attemptStatus != AttemptSucceeded || httpStatus != 200 ||
			reservationStatus != "settled" || used != 1 || reserved != 0 {
			t.Fatalf("settled state logical=%s attempt=%s http=%d reservation=%s used=%d reserved=%d",
				logicalStatus, attemptStatus, httpStatus, reservationStatus, used, reserved)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("logical-request usage records = %d, want 1", got)
		}
	})

	t.Run("same opaque logical ID is sequentially and concurrently idempotent", func(t *testing.T) {
		input := fixture.input(t, "idempotent", 10)
		const callers = 16
		start := make(chan struct{})
		results := make(chan Reservation, callers)
		errorsFound := make(chan error, callers)
		var wait sync.WaitGroup
		for range callers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				result, reserveErr := fixture.store.Reserve(fixture.ctx, input)
				if reserveErr != nil {
					errorsFound <- reserveErr
					return
				}
				results <- result
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		close(errorsFound)
		for reserveErr := range errorsFound {
			t.Errorf("concurrent replay: %v", reserveErr)
		}
		var first Reservation
		returned := 0
		for result := range results {
			if returned == 0 {
				first = result
			}
			returned++
			if result.ID() != first.ID() || result.LogicalRequestID() != input.LogicalRequestID.String() {
				t.Errorf("concurrent replay returned %#v, want reservation %s request %s", result, first.ID(), input.LogicalRequestID.String())
			}
		}
		if returned != callers {
			t.Fatalf("successful concurrent replays = %d, want %d", returned, callers)
		}
		second, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || second.ID() != first.ID() {
			t.Fatalf("sequential replay = %#v, %v", second, err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM logical_requests WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("logical request rows = %d, want 1", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservations WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("reservation rows = %d, want 1", got)
		}
		var used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT bucket.used_units, bucket.reserved_units
			FROM quota_reservations AS reservation
			JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE reservation.logical_request_id = $1
		`, input.LogicalRequestID.String()).Scan(&used, &reserved); err != nil {
			t.Fatalf("read replay bucket: %v", err)
		}
		if used != 0 || reserved != 1 {
			t.Fatalf("replay bucket used=%d reserved=%d, want 0/1", used, reserved)
		}

		changed := cloneReserveInput(input)
		changed.RouteKey = "other-route"
		if _, err := fixture.store.Reserve(fixture.ctx, changed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("changed trusted decision replay = %v, want ErrInvalidInput", err)
		}
		changed = cloneReserveInput(input)
		changed.ClientRequestID = "different-client-hint"
		if _, err := fixture.store.Reserve(fixture.ctx, changed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("changed durable hint replay = %v, want ErrInvalidInput", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, first, "pre_dispatch_failed"); err != nil {
			t.Fatalf("release idempotent reservation: %v", err)
		}
	})

	t.Run("exactly one concurrent attempt caller owns dispatch", func(t *testing.T) {
		input := fixture.input(t, "attempt-owner", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}

		const callers = 16
		type beginResult struct {
			attempt Attempt
			owner   bool
			err     error
		}
		start := make(chan struct{})
		results := make(chan beginResult, callers)
		var wait sync.WaitGroup
		for range callers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				attempt, owner, beginErr := fixture.store.BeginAttempt(fixture.ctx, reservation)
				results <- beginResult{attempt: attempt, owner: owner, err: beginErr}
			}()
		}
		close(start)
		wait.Wait()
		close(results)

		owners := 0
		var attempt Attempt
		for result := range results {
			if result.err != nil {
				t.Errorf("concurrent begin: %v", result.err)
				continue
			}
			if attempt.ID() == "" {
				attempt = result.attempt
			}
			if result.attempt.ID() != attempt.ID() {
				t.Errorf("concurrent attempt ID = %q, want %q", result.attempt.ID(), attempt.ID())
			}
			if result.owner {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("dispatch owners = %d, want exactly 1", owners)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, Outcome{
			Status: AttemptFailed, FailureCode: "concurrent_owner_test",
		}); err != nil {
			t.Fatalf("settle owned attempt: %v", err)
		}
		terminal, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || owner || terminal.ID() != attempt.ID() {
			t.Fatalf("terminal replay = %q owner=%t err=%v", terminal.ID(), owner, err)
		}
	})

	t.Run("blocking attempt ID generation cannot dispatch an expired reservation", func(t *testing.T) {
		const shortTTL = 250 * time.Millisecond
		originalTTL := fixture.store.reservationTTL
		fixture.store.reservationTTL = shortTTL
		defer func() { fixture.store.reservationTTL = originalTTL }()

		input := fixture.input(t, "attempt-expiry", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}

		originalNewID := fixture.store.newID
		idGenerationStarted := make(chan struct{}, 1)
		releaseIDGeneration := make(chan struct{})
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix == id.UpstreamAttempt {
				idGenerationStarted <- struct{}{}
				<-releaseIDGeneration
			}
			return originalNewID(prefix)
		}
		defer func() { fixture.store.newID = originalNewID }()

		type beginResult struct {
			attempt Attempt
			owner   bool
			err     error
		}
		begun := make(chan beginResult, 1)
		go func() {
			attempt, owner, beginErr := fixture.store.BeginAttempt(fixture.ctx, reservation)
			begun <- beginResult{attempt: attempt, owner: owner, err: beginErr}
		}()
		select {
		case <-idGenerationStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("BeginAttempt did not reach attempt ID generation")
		}
		if remaining := time.Until(reservation.ExpiresAt()) + 50*time.Millisecond; remaining > 0 {
			time.Sleep(remaining)
		}
		close(releaseIDGeneration)

		select {
		case result := <-begun:
			if !errors.Is(result.err, ErrExpired) || result.owner || result.attempt.ID() != "" {
				t.Fatalf("expired begin = %#v owner=%t err=%v", result.attempt, result.owner, result.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("BeginAttempt did not return after ID generation resumed")
		}
		fixture.store.newID = originalNewID
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("expired dispatch created %d attempts, want 0", got)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "attempt_expired"); err != nil {
			t.Fatalf("release expired reservation: %v", err)
		}
	})

	t.Run("new fingerprints are mandatory for replay", func(t *testing.T) {
		input := fixture.input(t, "fingerprint", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		var fingerprint string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT trusted_decision_fingerprint
			FROM logical_requests
			WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()).Scan(&fingerprint); err != nil {
			t.Fatalf("read trusted decision fingerprint: %v", err)
		}
		if len(fingerprint) != 43 {
			t.Fatalf("trusted decision fingerprint length = %d, want 43", len(fingerprint))
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE logical_requests
			SET trusted_decision_fingerprint = NULL
			WHERE logical_request_id = $1
		`, input.LogicalRequestID.String()); err != nil {
			t.Fatalf("simulate legacy logical request: %v", err)
		}
		if _, err := fixture.store.Reserve(fixture.ctx, input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("legacy replay = %v, want fail-closed ErrInvalidInput", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "legacy_test_done"); err != nil {
			t.Fatalf("release legacy replay fixture: %v", err)
		}
	})

	t.Run("contention enforces the exact hard maximum", func(t *testing.T) {
		const maximum = 8
		const callers = 32
		start := make(chan struct{})
		reservations := make(chan Reservation, callers)
		failures := make(chan error, callers)
		var wait sync.WaitGroup
		for range callers {
			input := fixture.input(t, "contention", maximum)
			input.ClientRequestID = "duplicate-contention-hint"
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

		accepted := make([]Reservation, 0, maximum)
		for reservation := range reservations {
			accepted = append(accepted, reservation)
		}
		denied := 0
		for err := range failures {
			if !errors.Is(err, ErrExceeded) {
				t.Errorf("contention error = %v, want ErrExceeded", err)
				continue
			}
			denied++
		}
		if len(accepted) != maximum || denied != callers-maximum {
			t.Fatalf("contention accepted=%d denied=%d, want %d/%d", len(accepted), denied, maximum, callers-maximum)
		}
		var used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT used_units, reserved_units FROM quota_buckets
			WHERE environment_id = $1 AND limit_plan_key = 'test-plan'
			  AND scope_key = $2
		`, quotaTestEnvironmentID, mustPreparedScopeKey(t, fixture.input(t, "contention", maximum))).Scan(&used, &reserved); err != nil {
			t.Fatalf("read contended bucket: %v", err)
		}
		if used != 0 || reserved != maximum {
			t.Fatalf("contended bucket used=%d reserved=%d, want 0/%d", used, reserved, maximum)
		}
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "contention_test_done"); err != nil {
				t.Fatalf("release contended reservation: %v", err)
			}
		}
	})

	t.Run("reservation lifetime begins after a contended bucket lock", func(t *testing.T) {
		seedInput := fixture.input(t, "reserve-clock", 2)
		seedReservation, err := fixture.store.Reserve(fixture.ctx, seedInput)
		if err != nil {
			t.Fatalf("seed quota bucket: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seedReservation, "clock_test_seeded"); err != nil {
			t.Fatalf("release seed reservation: %v", err)
		}

		const shortTTL = 250 * time.Millisecond
		originalTTL := fixture.store.reservationTTL
		fixture.store.reservationTTL = shortTTL
		defer func() { fixture.store.reservationTTL = originalTTL }()

		blocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin bucket blocker: %v", err)
		}
		defer func() { _ = blocker.Rollback(fixture.ctx) }()
		var bucketID string
		if err := blocker.QueryRow(fixture.ctx, `
			SELECT quota_bucket_id
			FROM quota_buckets
			WHERE environment_id = $1
			  AND limit_plan_key = $2
			  AND scope_key = $3
			FOR UPDATE
		`, seedInput.EnvironmentID, seedInput.LimitPlanKey,
			mustPreparedScopeKey(t, seedInput)).Scan(&bucketID); err != nil {
			t.Fatalf("lock quota bucket: %v", err)
		}

		input := fixture.input(t, "reserve-clock", 2)
		type reserveResult struct {
			reservation Reservation
			err         error
		}
		reserved := make(chan reserveResult, 1)
		go func() {
			reservation, reserveErr := fixture.store.Reserve(fixture.ctx, input)
			reserved <- reserveResult{reservation: reservation, err: reserveErr}
		}()
		waitForQuotaBucketLock(t, fixture)
		time.Sleep(shortTTL + 50*time.Millisecond)

		var unlockedAt time.Time
		if err := blocker.QueryRow(fixture.ctx, `SELECT statement_timestamp()`).Scan(&unlockedAt); err != nil {
			t.Fatalf("capture bucket unlock time: %v", err)
		}
		if err := blocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("unlock quota bucket: %v", err)
		}

		var result reserveResult
		select {
		case result = <-reserved:
			if result.err != nil {
				t.Fatalf("reserve after bucket wait: %v", result.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("reservation did not resume after bucket unlock")
		}
		var requestedAt, createdAt, expiresAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT request.requested_at, reservation.created_at, reservation.expires_at
			FROM logical_requests AS request
			JOIN quota_reservations AS reservation USING (logical_request_id)
			WHERE request.logical_request_id = $1
		`, input.LogicalRequestID.String()).Scan(&requestedAt, &createdAt, &expiresAt); err != nil {
			t.Fatalf("read delayed reservation timestamps: %v", err)
		}
		if !requestedAt.Before(unlockedAt) {
			t.Fatalf("requested_at %s did not preserve the pre-lock request time %s", requestedAt, unlockedAt)
		}
		if createdAt.Before(unlockedAt) {
			t.Fatalf("reservation created_at %s precedes bucket unlock %s", createdAt, unlockedAt)
		}
		if !expiresAt.Equal(createdAt.Add(shortTTL)) {
			t.Fatalf("reservation lifetime = %s, want %s", expiresAt.Sub(createdAt), shortTTL)
		}
		if !expiresAt.After(unlockedAt) || !result.reservation.ExpiresAt().Equal(expiresAt) {
			t.Fatalf("returned expiration %s was stale at unlock %s (stored %s)",
				result.reservation.ExpiresAt(), unlockedAt, expiresAt)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, result.reservation, "clock_test_done"); err != nil {
			t.Fatalf("release delayed reservation: %v", err)
		}
	})

	t.Run("pre-dispatch release is idempotent and proves no attempt", func(t *testing.T) {
		input := fixture.input(t, "release", 2)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "request_validation_failed"); err != nil {
			t.Fatalf("release: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "request_validation_failed"); err != nil {
			t.Fatalf("release replay: %v", err)
		}
		if _, _, err := fixture.store.BeginAttempt(fixture.ctx, reservation); !errors.Is(err, ErrFinalized) {
			t.Fatalf("begin attempt after release = %v, want ErrFinalized", err)
		}
		var logicalStatus, failureCode, reservationStatus string
		var released, used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT request.status, request.failure_code, reservation.status,
			       entry.released_units, bucket.used_units, bucket.reserved_units
			FROM logical_requests AS request
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE request.logical_request_id = $1
		`, input.LogicalRequestID.String()).Scan(
			&logicalStatus, &failureCode, &reservationStatus, &released, &used, &reserved,
		); err != nil {
			t.Fatalf("read released state: %v", err)
		}
		if logicalStatus != "failed" || failureCode != "request_validation_failed" ||
			reservationStatus != "released" || released != 1 || used != 0 || reserved != 0 {
			t.Fatalf("released state logical=%s failure=%s reservation=%s released=%d used=%d reserved=%d",
				logicalStatus, failureCode, reservationStatus, released, used, reserved)
		}
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("attempt rows after release = %d, want 0", got)
		}
	})

	t.Run("settle wins the settle release race after dispatch", func(t *testing.T) {
		input := fixture.input(t, "settle-race", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		attempt, dispatchOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin attempt owner=%t: %v", dispatchOwner, err)
		}
		start := make(chan struct{})
		settled := make(chan error, 1)
		released := make(chan error, 1)
		go func() {
			<-start
			settled <- fixture.store.Settle(fixture.ctx, attempt, Outcome{
				Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable",
			})
		}()
		go func() {
			<-start
			released <- fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "transport_failed")
		}()
		close(start)
		if err := <-settled; err != nil {
			t.Fatalf("settle race result: %v", err)
		}
		if err := <-released; !errors.Is(err, ErrFinalized) {
			t.Fatalf("release race result = %v, want ErrFinalized", err)
		}
		var used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT bucket.used_units, bucket.reserved_units
			FROM quota_reservations AS reservation
			JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE reservation.logical_request_id = $1
		`, input.LogicalRequestID.String()).Scan(&used, &reserved); err != nil {
			t.Fatalf("read race bucket: %v", err)
		}
		if used != 1 || reserved != 0 {
			t.Fatalf("post-dispatch failure used=%d reserved=%d, want 1/0", used, reserved)
		}
	})

	t.Run("reservation replay locks one read committed lifecycle snapshot", func(t *testing.T) {
		input := fixture.input(t, "replay-lock", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}

		blocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin replay blocker: %v", err)
		}
		defer func() { _ = blocker.Rollback(fixture.ctx) }()
		if _, err := blocker.Exec(fixture.ctx, `
			SELECT quota_reservation_id
			FROM quota_reservations
			WHERE quota_reservation_id = $1
			FOR UPDATE
		`, reservation.ID()); err != nil {
			t.Fatalf("lock replay reservation: %v", err)
		}

		type replayResult struct {
			reservation Reservation
			err         error
		}
		replayed := make(chan replayResult, 1)
		go func() {
			result, replayErr := fixture.store.Reserve(fixture.ctx, input)
			replayed <- replayResult{reservation: result, err: replayErr}
		}()
		waitForQuotaReservationLock(t, fixture)
		select {
		case early := <-replayed:
			t.Fatalf("replay escaped lifecycle lock early: %#v, %v", early.reservation, early.err)
		default:
		}
		if err := blocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("release replay blocker: %v", err)
		}
		select {
		case result := <-replayed:
			if result.err != nil || result.reservation.ID() != reservation.ID() {
				t.Fatalf("locked replay = %#v, %v", result.reservation, result.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("locked replay did not resume")
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "replay_lock_test_done"); err != nil {
			t.Fatalf("release replay fixture: %v", err)
		}
	})

	t.Run("settlement time follows a first byte committed during lock wait", func(t *testing.T) {
		input := fixture.input(t, "completion-order", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		attempt, dispatchOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin attempt owner=%t: %v", dispatchOwner, err)
		}

		blocker, err := fixture.pool.Begin(fixture.ctx)
		if err != nil {
			t.Fatalf("begin completion blocker: %v", err)
		}
		defer func() { _ = blocker.Rollback(fixture.ctx) }()
		if _, err := blocker.Exec(fixture.ctx, `
			SELECT quota_reservation_id
			FROM quota_reservations
			WHERE quota_reservation_id = $1
			FOR UPDATE
		`, reservation.ID()); err != nil {
			t.Fatalf("lock completion reservation: %v", err)
		}

		settled := make(chan error, 1)
		go func() {
			settled <- fixture.store.Settle(fixture.ctx, attempt, Outcome{
				Status: AttemptFailed, HTTPStatus: 502, FailureCode: "lock_wait_failure",
			})
		}()
		waitForQuotaReservationLock(t, fixture)
		if _, err := blocker.Exec(fixture.ctx, `
			UPDATE upstream_attempts
			SET first_byte_at = GREATEST(started_at, statement_timestamp())
			WHERE upstream_attempt_id = $1 AND status = 'started'
		`, attempt.ID()); err != nil {
			t.Fatalf("record injected first byte: %v", err)
		}
		if _, err := blocker.Exec(fixture.ctx, `
			UPDATE logical_requests
			SET status = 'streaming'
			WHERE logical_request_id = $1 AND status = 'dispatched'
		`, input.LogicalRequestID.String()); err != nil {
			t.Fatalf("record injected streaming state: %v", err)
		}
		if err := blocker.Commit(fixture.ctx); err != nil {
			t.Fatalf("commit injected first byte: %v", err)
		}
		select {
		case err := <-settled:
			if err != nil {
				t.Fatalf("settle after lock wait: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("settlement did not resume after lock wait")
		}

		var firstByteAt, attemptCompletedAt, logicalCompletedAt time.Time
		var reservationSettledAt, usageRecordedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT attempt.first_byte_at, attempt.completed_at,
			       request.completed_at, reservation.settled_at, usage.recorded_at
			FROM upstream_attempts AS attempt
			JOIN logical_requests AS request USING (logical_request_id)
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN usage_records AS usage USING (logical_request_id)
			WHERE attempt.upstream_attempt_id = $1
		`, attempt.ID()).Scan(
			&firstByteAt, &attemptCompletedAt, &logicalCompletedAt,
			&reservationSettledAt, &usageRecordedAt,
		); err != nil {
			t.Fatalf("read completion ordering: %v", err)
		}
		for name, completedAt := range map[string]time.Time{
			"attempt":     attemptCompletedAt,
			"logical":     logicalCompletedAt,
			"reservation": reservationSettledAt,
			"usage":       usageRecordedAt,
		} {
			if completedAt.Before(firstByteAt) {
				t.Errorf("%s completion %s precedes first byte %s", name, completedAt, firstByteAt)
			}
		}
	})

	t.Run("settlement completion follows blocking usage ID generation", func(t *testing.T) {
		input := fixture.input(t, "settlement-id-clock", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		attempt, dispatchOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin attempt owner=%t: %v", dispatchOwner, err)
		}
		if err := fixture.store.MarkFirstByte(fixture.ctx, attempt); err != nil {
			t.Fatalf("mark first byte: %v", err)
		}

		originalNewID := fixture.store.newID
		idGenerationStarted := make(chan struct{}, 1)
		releaseIDGeneration := make(chan struct{})
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix == id.UsageRecord {
				idGenerationStarted <- struct{}{}
				<-releaseIDGeneration
			}
			return originalNewID(prefix)
		}
		defer func() { fixture.store.newID = originalNewID }()

		settled := make(chan error, 1)
		go func() {
			settled <- fixture.store.Settle(fixture.ctx, attempt, Outcome{
				Status: AttemptFailed, HTTPStatus: 503, FailureCode: "blocked_usage_id",
			})
		}()
		select {
		case <-idGenerationStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("Settle did not reach usage ID generation")
		}
		time.Sleep(25 * time.Millisecond)
		var idCompletedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `SELECT statement_timestamp()`).Scan(&idCompletedAt); err != nil {
			t.Fatalf("capture usage ID completion boundary: %v", err)
		}
		close(releaseIDGeneration)
		select {
		case err := <-settled:
			if err != nil {
				t.Fatalf("settle after usage ID generation: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Settle did not resume after usage ID generation")
		}
		fixture.store.newID = originalNewID

		var attemptCompletedAt, logicalCompletedAt, reservationSettledAt, usageRecordedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT attempt.completed_at, request.completed_at,
			       reservation.settled_at, usage.recorded_at
			FROM upstream_attempts AS attempt
			JOIN logical_requests AS request USING (logical_request_id)
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN usage_records AS usage USING (logical_request_id)
			WHERE attempt.upstream_attempt_id = $1
		`, attempt.ID()).Scan(
			&attemptCompletedAt, &logicalCompletedAt,
			&reservationSettledAt, &usageRecordedAt,
		); err != nil {
			t.Fatalf("read usage ID completion ordering: %v", err)
		}
		for name, completedAt := range map[string]time.Time{
			"attempt":     attemptCompletedAt,
			"logical":     logicalCompletedAt,
			"reservation": reservationSettledAt,
			"usage":       usageRecordedAt,
		} {
			if completedAt.Before(idCompletedAt) {
				t.Errorf("%s completion %s precedes ID completion boundary %s", name, completedAt, idCompletedAt)
			}
		}
	})

	t.Run("recovery releases undispatched and settles dispatched reservations", func(t *testing.T) {
		firstInput := fixture.input(t, "recovery", 2)
		first, err := fixture.store.Reserve(fixture.ctx, firstInput)
		if err != nil {
			t.Fatalf("reserve dispatched recovery row: %v", err)
		}
		attempt, dispatchOwner, err := fixture.store.BeginAttempt(fixture.ctx, first)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin recovered attempt owner=%t: %v", dispatchOwner, err)
		}
		secondInput := fixture.input(t, "recovery", 2)
		second, err := fixture.store.Reserve(fixture.ctx, secondInput)
		if err != nil {
			t.Fatalf("reserve undispatched recovery row: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = transaction_timestamp() - interval '2 hours',
			    expires_at = transaction_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = ANY($1::text[])
		`, []string{first.ID(), second.ID()}); err != nil {
			t.Fatalf("expire recovery fixtures: %v", err)
		}
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 10)
		if err != nil || processed != 2 {
			t.Fatalf("expire batch processed=%d err=%v, want 2 nil", processed, err)
		}
		processed, err = fixture.store.ExpirePendingBatch(fixture.ctx, 10)
		if err != nil || processed != 0 {
			t.Fatalf("expire replay processed=%d err=%v, want 0 nil", processed, err)
		}

		var attemptStatus, attemptFailure, dispatchedReservationStatus string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT attempt.status, attempt.failure_code, reservation.status
			FROM upstream_attempts AS attempt
			JOIN quota_reservations AS reservation USING (logical_request_id)
			WHERE attempt.upstream_attempt_id = $1
		`, attempt.ID()).Scan(&attemptStatus, &attemptFailure, &dispatchedReservationStatus); err != nil {
			t.Fatalf("read recovered attempt: %v", err)
		}
		if attemptStatus != AttemptTimedOut || attemptFailure != expiryFailureCode || dispatchedReservationStatus != "settled" {
			t.Fatalf("recovered attempt status=%s failure=%s reservation=%s",
				attemptStatus, attemptFailure, dispatchedReservationStatus)
		}
		var undispatchedStatus, undispatchedFailure string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status, failure_code FROM logical_requests WHERE logical_request_id = $1
		`, secondInput.LogicalRequestID.String()).Scan(&undispatchedStatus, &undispatchedFailure); err != nil {
			t.Fatalf("read recovered undispatched request: %v", err)
		}
		if undispatchedStatus != "failed" || undispatchedFailure != expiryFailureCode {
			t.Fatalf("recovered undispatched status=%s failure=%s", undispatchedStatus, undispatchedFailure)
		}
		var used, reserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT used_units, reserved_units FROM quota_buckets
			WHERE environment_id = $1 AND scope_key = $2
		`, quotaTestEnvironmentID, mustPreparedScopeKey(t, firstInput)).Scan(&used, &reserved); err != nil {
			t.Fatalf("read recovered bucket: %v", err)
		}
		if used != 1 || reserved != 0 {
			t.Fatalf("recovered bucket used=%d reserved=%d, want 1/0", used, reserved)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, firstInput.LogicalRequestID.String()); got != 1 {
			t.Fatalf("recovered usage rows = %d, want 1", got)
		}
	})

	t.Run("recovery completion follows blocking usage ID generation", func(t *testing.T) {
		input := fixture.input(t, "recovery-id-clock", 1)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		attempt, dispatchOwner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin attempt owner=%t: %v", dispatchOwner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = $1
		`, reservation.ID()); err != nil {
			t.Fatalf("expire recovery reservation: %v", err)
		}

		originalNewID := fixture.store.newID
		idGenerationStarted := make(chan struct{}, 1)
		releaseIDGeneration := make(chan struct{})
		fixture.store.newID = func(prefix id.Prefix) (string, error) {
			if prefix == id.UsageRecord {
				idGenerationStarted <- struct{}{}
				<-releaseIDGeneration
			}
			return originalNewID(prefix)
		}
		defer func() { fixture.store.newID = originalNewID }()

		type expiryResult struct {
			processed int64
			err       error
		}
		expired := make(chan expiryResult, 1)
		go func() {
			processed, expiryErr := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
			expired <- expiryResult{processed: processed, err: expiryErr}
		}()
		select {
		case <-idGenerationStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("ExpirePendingBatch did not reach usage ID generation")
		}
		time.Sleep(25 * time.Millisecond)
		var idCompletedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `SELECT statement_timestamp()`).Scan(&idCompletedAt); err != nil {
			t.Fatalf("capture recovery ID completion boundary: %v", err)
		}
		close(releaseIDGeneration)
		select {
		case result := <-expired:
			if result.err != nil || result.processed != 1 {
				t.Fatalf("expiry after usage ID generation processed=%d err=%v", result.processed, result.err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ExpirePendingBatch did not resume after usage ID generation")
		}
		fixture.store.newID = originalNewID

		var attemptCompletedAt, logicalCompletedAt, reservationSettledAt, usageRecordedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT attempt.completed_at, request.completed_at,
			       reservation.settled_at, usage.recorded_at
			FROM upstream_attempts AS attempt
			JOIN logical_requests AS request USING (logical_request_id)
			JOIN quota_reservations AS reservation USING (logical_request_id)
			JOIN usage_records AS usage USING (logical_request_id)
			WHERE attempt.upstream_attempt_id = $1
		`, attempt.ID()).Scan(
			&attemptCompletedAt, &logicalCompletedAt,
			&reservationSettledAt, &usageRecordedAt,
		); err != nil {
			t.Fatalf("read recovery ID completion ordering: %v", err)
		}
		for name, completedAt := range map[string]time.Time{
			"attempt":     attemptCompletedAt,
			"logical":     logicalCompletedAt,
			"reservation": reservationSettledAt,
			"usage":       usageRecordedAt,
		} {
			if completedAt.Before(idCompletedAt) {
				t.Errorf("recovered %s completion %s precedes ID completion boundary %s", name, completedAt, idCompletedAt)
			}
		}
	})

	t.Run("cross tenant identities fail closed without a logical row", func(t *testing.T) {
		input := fixture.input(t, "cross-tenant", 1)
		input.OrganizationID = mustNewID(t, id.Organization)
		_, err := fixture.store.Reserve(fixture.ctx, input)
		if !errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrDependency) {
			t.Fatalf("cross-tenant reserve classification = %v", err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM logical_requests WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("cross-tenant logical rows = %d, want 0", got)
		}
	})

	t.Run("one connection remains free during simulated upstream IO", func(t *testing.T) {
		pool, err := database.Open(fixture.ctx, fixture.databaseURL, 1)
		if err != nil {
			t.Fatalf("open one-connection pool: %v", err)
		}
		defer pool.Close()
		store, err := NewStore(StoreConfig{Pool: pool, ReservationTTL: time.Hour})
		if err != nil {
			t.Fatalf("new one-connection store: %v", err)
		}
		input := fixture.input(t, "one-connection", 1)
		reservation, err := store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve on one connection: %v", err)
		}
		attempt, dispatchOwner, err := store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !dispatchOwner {
			t.Fatalf("begin attempt on one connection owner=%t: %v", dispatchOwner, err)
		}
		upstreamStarted := make(chan struct{})
		upstreamDone := make(chan struct{})
		go func() {
			close(upstreamStarted)
			<-upstreamDone
		}()
		<-upstreamStarted
		queryCtx, cancel := context.WithTimeout(fixture.ctx, 2*time.Second)
		defer cancel()
		var one int
		if err := pool.QueryRow(queryCtx, "SELECT 1").Scan(&one); err != nil {
			close(upstreamDone)
			t.Fatalf("query while upstream IO is blocked: %v", err)
		}
		close(upstreamDone)
		if one != 1 {
			t.Fatalf("one-connection query = %d", one)
		}
		if err := store.Settle(fixture.ctx, attempt, Outcome{Status: AttemptSucceeded, HTTPStatus: 204}); err != nil {
			t.Fatalf("settle one-connection attempt: %v", err)
		}
	})
}

func newQuotaPostgreSQLFixture(t *testing.T) quotaPostgreSQLFixture {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL admin pool: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_quota_test_%d", time.Now().UnixNano())
	if !quotaTestSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe generated schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create quota test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	isolatedURL := parsed.String()
	pool, err := database.Open(ctx, isolatedURL, 20)
	if err != nil {
		t.Fatalf("open isolated quota pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("apply quota migrations: %v", err)
	}
	seedQuotaPostgreSQLFixture(t, ctx, pool)
	store, err := NewStore(StoreConfig{Pool: pool, ReservationTTL: time.Hour})
	if err != nil {
		t.Fatalf("new quota store: %v", err)
	}
	return quotaPostgreSQLFixture{ctx: ctx, pool: pool, store: store, databaseURL: isolatedURL}
}

func seedQuotaPostgreSQLFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	exec := func(operation, statement string, arguments ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, statement, arguments...); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	exec("insert organization", `
		INSERT INTO organizations (organization_id, slug, display_name)
		VALUES ($1, 'quota-test', 'Quota Test')
	`, quotaTestOrganizationID)
	exec("insert application", `
		INSERT INTO applications (application_id, organization_id, slug, display_name)
		VALUES ($1, $2, 'quota-app', 'Quota App')
	`, quotaTestApplicationID, quotaTestOrganizationID)
	exec("insert environment", `
		INSERT INTO environments (
			environment_id, organization_id, application_id, slug, display_name, kind
		) VALUES ($1, $2, $3, 'production', 'Production', 'production')
	`, quotaTestEnvironmentID, quotaTestOrganizationID, quotaTestApplicationID)
	exec("insert admin user", `
		INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name)
		VALUES ('adm_00000000000000000000000001', 'quota@example.test',
		        'quota@example.test', 'Quota Admin')
	`)
	exec("insert admin membership", `
		INSERT INTO admin_memberships (
			admin_membership_id, organization_id, admin_user_id, role
		) VALUES ('amb_00000000000000000000000001', $1,
		          'adm_00000000000000000000000001', 'owner')
	`, quotaTestOrganizationID)
	exec("insert config revision", `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, created_by_admin_user_id
		) VALUES ($1, $2, $3, $4, 1, 'quota-test-etag-001', 'draft', '{}'::jsonb,
		          'adm_00000000000000000000000001')
	`, quotaTestConfigRevisionID, quotaTestOrganizationID, quotaTestApplicationID, quotaTestEnvironmentID)
	exec("insert application user", `
		INSERT INTO application_users (application_user_id, organization_id, application_id)
		VALUES ($1, $2, $3)
	`, quotaTestApplicationUserID, quotaTestOrganizationID, quotaTestApplicationID)
	exec("insert installation", `
		INSERT INTO installations (
			installation_id, organization_id, application_id, environment_id,
			application_user_id, platform, dpop_jkt, dpop_public_jwk,
			key_storage, trust_level
		) VALUES ($1, $2, $3, $4, $5, 'ios', $6, '{}'::jsonb, 'unknown', 'debug')
	`, quotaTestInstallationID, quotaTestOrganizationID, quotaTestApplicationID,
		quotaTestEnvironmentID, quotaTestApplicationUserID, strings.Repeat("j", 43))
	exec("insert session grant", `
		INSERT INTO session_grants (
			session_grant_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, access_token_jti_hash,
			dpop_jkt, policy_revision_id, trust_level, identity_verified_at,
			issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, decode(repeat('11', 32), 'hex'),
		          $7, $8, 'debug', CURRENT_TIMESTAMP - interval '1 minute',
		          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '1 day')
	`, quotaTestSessionGrantID, quotaTestOrganizationID, quotaTestApplicationID,
		quotaTestEnvironmentID, quotaTestApplicationUserID, quotaTestInstallationID,
		strings.Repeat("j", 43), quotaTestConfigRevisionID)
}

func (fixture quotaPostgreSQLFixture) input(t *testing.T, feature string, maximum int64) ReserveInput {
	t.Helper()
	return ReserveInput{
		LogicalRequestID: mustLogicalID(t),
		OrganizationID:   quotaTestOrganizationID, ApplicationID: quotaTestApplicationID,
		EnvironmentID: quotaTestEnvironmentID, ApplicationUserID: quotaTestApplicationUserID,
		InstallationID: quotaTestInstallationID, SessionGrantID: quotaTestSessionGrantID,
		ConfigRevisionID: quotaTestConfigRevisionID, FeatureKey: feature,
		Protocol: "openai_chat", ClientRequestID: "client-correlation-hint",
		LimitPlanKey: "test-plan", RouteKey: "primary", UpstreamKey: "provider",
		ModelKey: "fast", PhysicalModel: "provider/model-v1",
		Rules: []Rule{{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: maximum, Hard: true,
		}},
	}
}

func (fixture quotaPostgreSQLFixture) count(t *testing.T, statement string, arguments ...any) int64 {
	t.Helper()
	var count int64
	if err := fixture.pool.QueryRow(fixture.ctx, statement, arguments...).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return count
}

func waitForQuotaReservationLock(t *testing.T, fixture quotaPostgreSQLFixture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_stat_activity
				WHERE datname = current_database()
				  AND pid <> pg_backend_pid()
				  AND wait_event_type = 'Lock'
				  AND query LIKE '%FROM quota_reservations%'
			)
		`).Scan(&waiting); err != nil {
			t.Fatalf("inspect quota lock wait: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("quota reservation waiter did not reach the row lock")
}

func waitForQuotaBucketLock(t *testing.T, fixture quotaPostgreSQLFixture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_stat_activity
				WHERE datname = current_database()
				  AND pid <> pg_backend_pid()
				  AND wait_event_type = 'Lock'
				  AND query LIKE '%quota_buckets%'
			)
		`).Scan(&waiting); err != nil {
			t.Fatalf("inspect quota bucket lock wait: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("quota reservation did not reach the bucket lock")
}

func mustPreparedScopeKey(t *testing.T, input ReserveInput) string {
	t.Helper()
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare quota input: %v", err)
	}
	return prepared.scopeKey
}

func mustNewID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
