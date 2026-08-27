package quota

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"regexp"
	"slices"
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

	t.Run("multi rule replay is order independent and release finalizes every entry", func(t *testing.T) {
		input := fixture.multiRuleInput(t, "multi-replay", 4, "5h", 9)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve multi-rule request: %v", err)
		}
		if len(reservation.entries) != 2 || reservation.ResetAt().IsZero() {
			t.Fatalf("multi-rule reservation entries=%d reset=%s", len(reservation.entries), reservation.ResetAt())
		}

		reversed := cloneReserveInput(input)
		slices.Reverse(reversed.Rules)
		for index := range reversed.Rules {
			slices.Reverse(reversed.Rules[index].Scope)
		}
		replayed, err := fixture.store.Reserve(fixture.ctx, reversed)
		if err != nil {
			t.Fatalf("reserve reversed replay: %v", err)
		}
		if replayed.ID() != reservation.ID() || len(replayed.entries) != len(reservation.entries) ||
			!replayed.ResetAt().Equal(reservation.ResetAt()) {
			t.Fatalf("reversed replay = %#v, want reservation %s", replayed, reservation.ID())
		}
		for index := range reservation.entries {
			if replayed.entries[index].bucketID != reservation.entries[index].bucketID ||
				replayed.entries[index].entryID != reservation.entries[index].entryID ||
				!replayed.entries[index].resetAt.Equal(reservation.entries[index].resetAt) {
				t.Fatalf("replayed entry %d differs: %#v / %#v", index, replayed.entries[index], reservation.entries[index])
			}
		}
		var entryCount, reservedTotal int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT count(*), sum(reserved_units)
			FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&entryCount, &reservedTotal); err != nil {
			t.Fatalf("read multi-rule entries: %v", err)
		}
		if entryCount != 2 || reservedTotal != 2 {
			t.Fatalf("multi-rule entries count=%d reserved=%d, want 2/2", entryCount, reservedTotal)
		}

		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, replayed, "multi_replay_done"); err != nil {
			t.Fatalf("release multi-rule replay: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "multi_replay_done"); err != nil {
			t.Fatalf("release multi-rule idempotent replay: %v", err)
		}
		var releasedTotal int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT sum(released_units)
			FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&releasedTotal); err != nil {
			t.Fatalf("read released multi-rule entries: %v", err)
		}
		if releasedTotal != 2 {
			t.Fatalf("released multi-rule entry units = %d, want 2", releasedTotal)
		}
		for _, entry := range reservation.entries {
			var used, reserved int64
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT used_units, reserved_units FROM quota_buckets WHERE quota_bucket_id = $1
			`, entry.bucketID).Scan(&used, &reserved); err != nil {
				t.Fatalf("read released bucket %s: %v", entry.bucketID, err)
			}
			if used != 0 || reserved != 0 {
				t.Fatalf("released bucket %s used=%d reserved=%d, want 0/0", entry.bucketID, used, reserved)
			}
		}
	})

	t.Run("bytewise bucket order is stable across reservation and replay", func(t *testing.T) {
		const lowBucketID = "qbk_00000000000000000000000000"
		const highBucketID = "qbk_7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
		for _, bucketID := range []string{lowBucketID, highBucketID} {
			if err := id.Validate(bucketID, id.QuotaBucket); err != nil {
				t.Fatalf("fixed bucket ID %q is invalid: %v", bucketID, err)
			}
		}
		bucketIDs := []string{highBucketID, lowBucketID}
		bucketIndex := 0
		orderedStore, err := NewStore(StoreConfig{
			Pool: fixture.pool, ReservationTTL: time.Hour,
			NewID: func(prefix id.Prefix) (string, error) {
				if prefix != id.QuotaBucket {
					return id.New(prefix)
				}
				if bucketIndex >= len(bucketIDs) {
					return "", errors.New("unexpected extra bucket identifier")
				}
				value := bucketIDs[bucketIndex]
				bucketIndex++
				return value, nil
			},
		})
		if err != nil {
			t.Fatalf("new bytewise-order store: %v", err)
		}
		input := fixture.multiRuleInput(t, "bytewise-order", 3, "19h", 5)
		prepared, err := prepareRequest(input)
		if err != nil {
			t.Fatalf("prepare bytewise-order request: %v", err)
		}
		reservation, err := orderedStore.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve divergent bucket identifiers: %v", err)
		}
		if len(reservation.entries) != 2 || reservation.entries[0].bucketID != lowBucketID ||
			reservation.entries[1].bucketID != highBucketID || reservation.validate() != nil {
			t.Fatalf("reservation entry order = %#v, want bytewise low/high", reservation.entries)
		}

		replayed, err := orderedStore.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("replay divergent bucket identifiers: %v", err)
		}
		if len(replayed.entries) != 2 || replayed.entries[0].bucketID != lowBucketID ||
			replayed.entries[1].bucketID != highBucketID || replayed.validate() != nil {
			t.Fatalf("replayed entry order = %#v, want bytewise low/high", replayed.entries)
		}

		rows, err := fixture.pool.Query(fixture.ctx, `
			SELECT bucket.quota_bucket_id, bucket.rule_key
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			ORDER BY bucket.quota_bucket_id COLLATE "C"
		`, reservation.ID())
		if err != nil {
			t.Fatalf("query explicit bytewise bucket order: %v", err)
		}
		defer rows.Close()
		var gotBucketIDs, gotRuleKeys []string
		for rows.Next() {
			var bucketID, ruleKey string
			if err := rows.Scan(&bucketID, &ruleKey); err != nil {
				t.Fatalf("scan explicit bytewise bucket order: %v", err)
			}
			gotBucketIDs = append(gotBucketIDs, bucketID)
			gotRuleKeys = append(gotRuleKeys, ruleKey)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate explicit bytewise bucket order: %v", err)
		}
		if !slices.Equal(gotBucketIDs, []string{lowBucketID, highBucketID}) ||
			!slices.Equal(gotRuleKeys, []string{prepared.rules[1].ruleKey, prepared.rules[0].ruleKey}) {
			t.Fatalf("database bytewise order ids=%v rules=%v", gotBucketIDs, gotRuleKeys)
		}
		if err := orderedStore.ReleaseBeforeDispatch(fixture.ctx, replayed, "bytewise_order_done"); err != nil {
			t.Fatalf("release bytewise-order reservation: %v", err)
		}
	})

	t.Run("multi rule denial never partially reserves an available bucket", func(t *testing.T) {
		seedInput := fixture.multiRuleInput(t, "multi-atomic-denial", 1, "7h", 10)
		seed, err := fixture.store.Reserve(fixture.ctx, seedInput)
		if err != nil {
			t.Fatalf("reserve atomic-denial seed: %v", err)
		}
		deniedInput := fixture.multiRuleInput(t, "multi-atomic-denial", 1, "7h", 10)
		if _, err := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(err, ErrExceeded) {
			t.Fatalf("multi-rule denial = %v, want ErrExceeded", err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservations WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied multi-rule reservations = %d, want 0", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservation_entries WHERE quota_reservation_id = $1`, seed.ID()); got != 2 {
			t.Fatalf("seed multi-rule entries = %d, want 2", got)
		}
		for _, entry := range seed.entries {
			var used, reserved int64
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT used_units, reserved_units FROM quota_buckets WHERE quota_bucket_id = $1
			`, entry.bucketID).Scan(&used, &reserved); err != nil {
				t.Fatalf("read atomic-denial bucket: %v", err)
			}
			if used != 0 || reserved != 1 {
				t.Fatalf("denial partially changed bucket %s to used=%d reserved=%d", entry.bucketID, used, reserved)
			}
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seed, "multi_denial_done"); err != nil {
			t.Fatalf("release atomic-denial seed: %v", err)
		}
	})

	t.Run("overlapping multi rule contention enforces the tightest bucket", func(t *testing.T) {
		const tightMaximum = 5
		const looseMaximum = 8
		const callers = 24
		start := make(chan struct{})
		reservations := make(chan Reservation, callers)
		failures := make(chan error, callers)
		var wait sync.WaitGroup
		for caller := range callers {
			input := fixture.multiRuleInput(t, "multi-contention", tightMaximum, "11h", looseMaximum)
			if caller%2 != 0 {
				slices.Reverse(input.Rules)
			}
			wait.Add(1)
			go func(input ReserveInput) {
				defer wait.Done()
				<-start
				reservation, reserveErr := fixture.store.Reserve(fixture.ctx, input)
				if reserveErr != nil {
					failures <- reserveErr
					return
				}
				reservations <- reservation
			}(input)
		}
		close(start)
		wait.Wait()
		close(reservations)
		close(failures)

		accepted := make([]Reservation, 0, tightMaximum)
		for reservation := range reservations {
			accepted = append(accepted, reservation)
			if len(reservation.entries) != 2 {
				t.Errorf("contended reservation entries = %d, want 2", len(reservation.entries))
			}
		}
		denied := 0
		for reserveErr := range failures {
			if !errors.Is(reserveErr, ErrExceeded) {
				t.Errorf("multi contention error = %v, want ErrExceeded", reserveErr)
				continue
			}
			denied++
		}
		if len(accepted) != tightMaximum || denied != callers-tightMaximum {
			t.Fatalf("multi contention accepted=%d denied=%d, want %d/%d", len(accepted), denied, tightMaximum, callers-tightMaximum)
		}
		if len(accepted) != 0 {
			for _, entry := range accepted[0].entries {
				var maximum, used, reserved int64
				if err := fixture.pool.QueryRow(fixture.ctx, `
					SELECT hard_maximum, used_units, reserved_units
					FROM quota_buckets WHERE quota_bucket_id = $1
				`, entry.bucketID).Scan(&maximum, &used, &reserved); err != nil {
					t.Fatalf("read multi-contention bucket: %v", err)
				}
				if used != 0 || reserved != tightMaximum || (maximum != tightMaximum && maximum != looseMaximum) {
					t.Fatalf("multi-contention bucket max=%d used=%d reserved=%d", maximum, used, reserved)
				}
			}
		}
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "multi_contention_done"); err != nil {
				t.Fatalf("release multi-contention reservation: %v", err)
			}
		}
	})

	t.Run("multi entry settlement and expiry recovery finalize every bucket", func(t *testing.T) {
		settleInput := fixture.multiRuleInput(t, "multi-settle", 3, "13h", 4)
		settleReservation, err := fixture.store.Reserve(fixture.ctx, settleInput)
		if err != nil {
			t.Fatalf("reserve multi-settle: %v", err)
		}
		settleAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, settleReservation)
		if err != nil || !owner {
			t.Fatalf("begin multi-settle owner=%t: %v", owner, err)
		}
		settleOutcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200}
		if err := fixture.store.Settle(fixture.ctx, settleAttempt, settleOutcome); err != nil {
			t.Fatalf("settle multi-entry reservation: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, settleAttempt, settleOutcome); err != nil {
			t.Fatalf("settle multi-entry replay: %v", err)
		}
		var settledCount int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT count(*) FROM quota_reservation_entries
			WHERE quota_reservation_id = $1 AND settled_units = 1 AND released_units = 0
		`, settleReservation.ID()).Scan(&settledCount); err != nil {
			t.Fatalf("read settled multi entries: %v", err)
		}
		if settledCount != 2 || fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, settleInput.LogicalRequestID.String()) != 1 {
			t.Fatalf("settled entries=%d or logical usage count != 1", settledCount)
		}

		recoveryInput := fixture.multiRuleInput(t, "multi-recovery", 4, "17h", 5)
		dispatched, err := fixture.store.Reserve(fixture.ctx, recoveryInput)
		if err != nil {
			t.Fatalf("reserve dispatched multi-recovery: %v", err)
		}
		recoveredAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, dispatched)
		if err != nil || !owner {
			t.Fatalf("begin multi-recovery owner=%t: %v", owner, err)
		}
		undispatchedInput := fixture.multiRuleInput(t, "multi-recovery", 4, "17h", 5)
		undispatched, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
		if err != nil {
			t.Fatalf("reserve undispatched multi-recovery: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = ANY($1::text[])
		`, []string{dispatched.ID(), undispatched.ID()}); err != nil {
			t.Fatalf("expire multi-recovery reservations: %v", err)
		}
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 10)
		if err != nil || processed != 2 {
			t.Fatalf("recover multi entries processed=%d err=%v, want 2 nil", processed, err)
		}
		processed, err = fixture.store.ExpirePendingBatch(fixture.ctx, 10)
		if err != nil || processed != 0 {
			t.Fatalf("recover multi-entry replay processed=%d err=%v", processed, err)
		}
		var recoveredStatus, recoveredFailure string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status, failure_code FROM upstream_attempts WHERE upstream_attempt_id = $1
		`, recoveredAttempt.ID()).Scan(&recoveredStatus, &recoveredFailure); err != nil {
			t.Fatalf("read recovered multi attempt: %v", err)
		}
		if recoveredStatus != AttemptTimedOut || recoveredFailure != expiryFailureCode {
			t.Fatalf("recovered multi attempt status=%s failure=%s", recoveredStatus, recoveredFailure)
		}
		var recoveredSettled, recoveredReleased int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT
				count(*) FILTER (WHERE quota_reservation_id = $1 AND settled_units = 1),
				count(*) FILTER (WHERE quota_reservation_id = $2 AND released_units = 1)
			FROM quota_reservation_entries
			WHERE quota_reservation_id = ANY($3::text[])
		`, dispatched.ID(), undispatched.ID(), []string{dispatched.ID(), undispatched.ID()}).Scan(
			&recoveredSettled, &recoveredReleased,
		); err != nil {
			t.Fatalf("read recovered multi entries: %v", err)
		}
		if recoveredSettled != 2 || recoveredReleased != 2 {
			t.Fatalf("recovered multi entries settled=%d released=%d, want 2/2", recoveredSettled, recoveredReleased)
		}
		for _, entry := range dispatched.entries {
			var used, reserved int64
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT used_units, reserved_units FROM quota_buckets WHERE quota_bucket_id = $1
			`, entry.bucketID).Scan(&used, &reserved); err != nil {
				t.Fatalf("read recovered multi bucket: %v", err)
			}
			if used != 1 || reserved != 0 {
				t.Fatalf("recovered multi bucket %s used=%d reserved=%d, want 1/0", entry.bucketID, used, reserved)
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

func TestStorePostgreSQLOutputTokenQuota(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("known success settles actual output and releases the remainder", func(t *testing.T) {
		input := fixture.outputInput(t, "output-known", 1_000, 64)
		input.Rules = append(input.Rules, Rule{
			Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm,
			Scope: []string{"user", "feature"}, PerRequestMaximum: 128,
			ReservedUnits: 64, Hard: true,
		})
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve known output: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin known output owner=%t: %v", owner, err)
		}
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
			Known: true, Provenance: ProviderReportedProvenance,
		}}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle known output: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle exact known output replay: %v", err)
		}
		conflicting := outcome
		conflicting.Usage.OutputTokens = 8
		conflicting.Usage.TotalTokens = 19
		if err := fixture.store.Settle(fixture.ctx, attempt, conflicting); !errors.Is(err, ErrFinalized) {
			t.Fatalf("conflicting known settlement replay = %v, want ErrFinalized", err)
		}

		var reservedUnits, settledUnits, releasedUnits, bucketUsed, bucketReserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT entry.reserved_units, entry.settled_units, entry.released_units,
			       bucket.used_units, bucket.reserved_units
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1 AND bucket.metric = 'output_tokens'
		`, reservation.ID()).Scan(
			&reservedUnits, &settledUnits, &releasedUnits, &bucketUsed, &bucketReserved,
		); err != nil {
			t.Fatalf("read known output settlement: %v", err)
		}
		if reservedUnits != 64 || settledUnits != 7 || releasedUnits != 57 ||
			bucketUsed != 7 || bucketReserved != 0 {
			t.Fatalf("known output entry=%d/%d/%d bucket=%d/%d, want 64/7/57 and 7/0",
				reservedUnits, settledUnits, releasedUnits, bucketUsed, bucketReserved)
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservation_entries WHERE quota_reservation_id = $1`, reservation.ID()); got != 2 {
			t.Fatalf("stateful entries = %d, want logical + output only", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 4 {
			t.Fatalf("known usage rows = %d, want logical + three provider rows", got)
		}
		var reportedOutput int64
		var confidence, provenance string
		var usageAttemptID string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT units, confidence, provenance_key, upstream_attempt_id
			FROM usage_records
			WHERE logical_request_id = $1 AND metric = 'output_tokens'
		`, input.LogicalRequestID.String()).Scan(
			&reportedOutput, &confidence, &provenance, &usageAttemptID,
		); err != nil {
			t.Fatalf("read provider output usage: %v", err)
		}
		if reportedOutput != 7 || confidence != "reported" ||
			provenance != providerUsageProvenanceKey(attempt.ID(), OutputTokensMetric) ||
			usageAttemptID != attempt.ID() {
			t.Fatalf("provider output usage=%d/%s/%s/%s", reportedOutput, confidence, provenance, usageAttemptID)
		}
	})

	t.Run("unknown failure and expiry conservatively charge full output", func(t *testing.T) {
		unknownInput := fixture.outputInput(t, "output-unknown", 500, 32)
		unknownReservation, err := fixture.store.Reserve(fixture.ctx, unknownInput)
		if err != nil {
			t.Fatalf("reserve unknown output: %v", err)
		}
		unknownAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, unknownReservation)
		if err != nil || !owner {
			t.Fatalf("begin unknown output owner=%t: %v", owner, err)
		}
		unknownOutcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200,
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}
		if err := fixture.store.Settle(fixture.ctx, unknownAttempt, unknownOutcome); err != nil {
			t.Fatalf("settle unknown output: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, unknownAttempt, unknownOutcome); err != nil {
			t.Fatalf("settle exact unknown output replay: %v", err)
		}
		conflictingUnknown := unknownOutcome
		conflictingUnknown.Usage = Usage{Known: true, Provenance: ProviderReportedProvenance}
		if err := fixture.store.Settle(fixture.ctx, unknownAttempt, conflictingUnknown); !errors.Is(err, ErrFinalized) {
			t.Fatalf("conflicting unknown provenance replay = %v, want ErrFinalized", err)
		}
		assertOutputEntryState(t, fixture, unknownReservation.ID(), 32, 32, 0, 32, 0)
		assertOutputUsage(t, fixture, unknownInput.LogicalRequestID.String(), unknownAttempt.ID(), 32, "unknown")

		failureInput := fixture.outputInput(t, "output-failure", 500, 32)
		failureReservation, err := fixture.store.Reserve(fixture.ctx, failureInput)
		if err != nil {
			t.Fatalf("reserve failed output: %v", err)
		}
		failureAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, failureReservation)
		if err != nil || !owner {
			t.Fatalf("begin failed output owner=%t: %v", owner, err)
		}
		failureOutcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_protocol_error",
			Usage: Usage{
				InputTokens: 11, OutputTokens: 70, TotalTokens: 81,
				Known: true, Provenance: ProviderReportedProvenance,
			},
		}
		if err := fixture.store.Settle(fixture.ctx, failureAttempt, failureOutcome); err != nil {
			t.Fatalf("settle failed over-cap output: %v", err)
		}
		assertOutputEntryState(t, fixture, failureReservation.ID(), 32, 32, 0, 32, 0)
		assertOutputUsage(t, fixture, failureInput.LogicalRequestID.String(), failureAttempt.ID(), 70, "reported")

		expiredInput := fixture.outputInput(t, "output-expired", 500, 48)
		expiredReservation, err := fixture.store.Reserve(fixture.ctx, expiredInput)
		if err != nil {
			t.Fatalf("reserve dispatched expiry: %v", err)
		}
		expiredAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, expiredReservation)
		if err != nil || !owner {
			t.Fatalf("begin dispatched expiry owner=%t: %v", owner, err)
		}
		undispatchedInput := fixture.outputInput(t, "output-expired-undispatched", 500, 48)
		undispatchedReservation, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
		if err != nil {
			t.Fatalf("reserve undispatched expiry: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = ANY($1::text[])
		`, []string{expiredReservation.ID(), undispatchedReservation.ID()}); err != nil {
			t.Fatalf("backdate output expiries: %v", err)
		}
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 10)
		if err != nil || processed != 2 {
			t.Fatalf("expire output reservations processed=%d err=%v, want 2 nil", processed, err)
		}
		assertOutputEntryState(t, fixture, expiredReservation.ID(), 48, 48, 0, 48, 0)
		assertOutputUsage(t, fixture, expiredInput.LogicalRequestID.String(), expiredAttempt.ID(), 48, "unknown")
		assertOutputEntryState(t, fixture, undispatchedReservation.ID(), 48, 0, 48, 0, 0)
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, undispatchedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("undispatched expiry usage rows = %d, want 0", got)
		}
	})

	t.Run("pre-dispatch release returns every output unit", func(t *testing.T) {
		input := fixture.outputInput(t, "output-release", 500, 64)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve output release: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "transport_setup_failed"); err != nil {
			t.Fatalf("release output before dispatch: %v", err)
		}
		assertOutputEntryState(t, fixture, reservation.ID(), 64, 0, 64, 0, 0)
	})

	t.Run("per-request-only decision has a zero-entry idempotent lifecycle", func(t *testing.T) {
		input := fixture.perRequestOutputInput(t, "output-per-request", 128, 64)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve per-request-only: %v", err)
		}
		replay, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("replay per-request-only = %#v, %v", replay, err)
		}
		if len(reservation.entries) != 0 || !reservation.ResetAt().IsZero() {
			t.Fatalf("entryless reservation entries=%d reset=%s", len(reservation.entries), reservation.ResetAt())
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservation_entries WHERE quota_reservation_id = $1`, reservation.ID()); got != 0 {
			t.Fatalf("per-request-only entries = %d, want 0", got)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin per-request-only owner=%t: %v", owner, err)
		}
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 3, OutputTokens: 5, TotalTokens: 8,
			Known: true, Provenance: ProviderReportedProvenance,
		}}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle per-request-only: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle per-request-only replay: %v", err)
		}
		conflicting := outcome
		conflicting.Usage.OutputTokens = 6
		conflicting.Usage.TotalTokens = 9
		if err := fixture.store.Settle(fixture.ctx, attempt, conflicting); !errors.Is(err, ErrFinalized) {
			t.Fatalf("conflicting entryless settlement = %v, want ErrFinalized", err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 4 {
			t.Fatalf("entryless known usage rows = %d, want 4", got)
		}

		expiredInput := fixture.perRequestOutputInput(t, "output-per-request-expired", 128, 64)
		expiredReservation, err := fixture.store.Reserve(fixture.ctx, expiredInput)
		if err != nil {
			t.Fatalf("reserve entryless expiry: %v", err)
		}
		expiredAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, expiredReservation)
		if err != nil || !owner {
			t.Fatalf("begin entryless expiry owner=%t: %v", owner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = $1
		`, expiredReservation.ID()); err != nil {
			t.Fatalf("backdate entryless expiry: %v", err)
		}
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire entryless attempt processed=%d err=%v", processed, err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, expiredInput.LogicalRequestID.String()); got != 1 {
			t.Fatalf("expired entryless usage rows = %d, want logical request only", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1 AND metric = 'output_tokens'`, expiredInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("expired entryless output usage rows = %d, want 0 without recoverable persisted cap", got)
		}
		var attemptStatus string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT status FROM upstream_attempts WHERE upstream_attempt_id = $1
		`, expiredAttempt.ID()).Scan(&attemptStatus); err != nil {
			t.Fatalf("read expired entryless attempt: %v", err)
		}
		if attemptStatus != AttemptTimedOut {
			t.Fatalf("expired entryless attempt status=%s, want %s", attemptStatus, AttemptTimedOut)
		}
	})

	t.Run("mixed denial never partially reserves logical or variable output units", func(t *testing.T) {
		seedInput := fixture.outputInput(t, "output-atomic", 100, 80)
		seed, err := fixture.store.Reserve(fixture.ctx, seedInput)
		if err != nil {
			t.Fatalf("reserve output atomic seed: %v", err)
		}
		deniedInput := fixture.outputInput(t, "output-atomic", 100, 30)
		if _, err := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(err, ErrExceeded) {
			t.Fatalf("mixed output denial = %v, want ErrExceeded", err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservations WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied mixed reservation rows = %d, want 0", got)
		}
		for _, entry := range seed.entries {
			var used, reserved int64
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT used_units, reserved_units FROM quota_buckets WHERE quota_bucket_id = $1
			`, entry.bucketID).Scan(&used, &reserved); err != nil {
				t.Fatalf("read mixed atomic bucket: %v", err)
			}
			wantReserved := int64(1)
			if entry.metric == OutputTokensMetric {
				wantReserved = 80
			}
			if used != 0 || reserved != wantReserved {
				t.Fatalf("mixed denial changed %s bucket to %d/%d, want 0/%d", entry.metric, used, reserved, wantReserved)
			}
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seed, "output_atomic_done"); err != nil {
			t.Fatalf("release output atomic seed: %v", err)
		}
	})

	t.Run("variable-unit contention never overspends", func(t *testing.T) {
		const callers = 10
		const units = 17
		const maximum = 100
		start := make(chan struct{})
		reservations := make(chan Reservation, callers)
		failures := make(chan error, callers)
		var wait sync.WaitGroup
		for caller := range callers {
			input := fixture.outputInput(t, "output-contention", maximum, units)
			if caller%2 != 0 {
				slices.Reverse(input.Rules)
			}
			wait.Add(1)
			go func(input ReserveInput) {
				defer wait.Done()
				<-start
				reservation, reserveErr := fixture.store.Reserve(fixture.ctx, input)
				if reserveErr != nil {
					failures <- reserveErr
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
		for reserveErr := range failures {
			if !errors.Is(reserveErr, ErrExceeded) {
				t.Errorf("variable contention error = %v", reserveErr)
			}
			denied++
		}
		if len(accepted) != maximum/units || denied != callers-maximum/units {
			t.Fatalf("variable contention accepted=%d denied=%d, want %d/%d",
				len(accepted), denied, maximum/units, callers-maximum/units)
		}
		if len(accepted) != 0 {
			var outputEntry reservationEntry
			for _, entry := range accepted[0].entries {
				if entry.metric == OutputTokensMetric {
					outputEntry = entry
				}
			}
			var used, reserved int64
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT used_units, reserved_units FROM quota_buckets WHERE quota_bucket_id = $1
			`, outputEntry.bucketID).Scan(&used, &reserved); err != nil {
				t.Fatalf("read variable contention bucket: %v", err)
			}
			if used != 0 || reserved != int64(len(accepted))*units || reserved > maximum {
				t.Fatalf("variable contention bucket used=%d reserved=%d max=%d", used, reserved, maximum)
			}
		}
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "output_contention_done"); err != nil {
				t.Fatalf("release variable contention reservation: %v", err)
			}
		}
	})

	t.Run("maximum integer reservation denies without overflow", func(t *testing.T) {
		seedInput := fixture.outputInput(t, "output-overflow", math.MaxInt64, math.MaxInt64)
		seed, err := fixture.store.Reserve(fixture.ctx, seedInput)
		if err != nil {
			t.Fatalf("reserve maximum integer output: %v", err)
		}
		deniedInput := fixture.outputInput(t, "output-overflow", math.MaxInt64, 1)
		if _, err := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(err, ErrExceeded) {
			t.Fatalf("overflow-edge denial = %v, want ErrExceeded", err)
		}
		assertOutputEntryState(t, fixture, seed.ID(), math.MaxInt64, 0, 0, 0, math.MaxInt64)
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seed, "output_overflow_done"); err != nil {
			t.Fatalf("release maximum integer output: %v", err)
		}
		assertOutputEntryState(t, fixture, seed.ID(), math.MaxInt64, 0, math.MaxInt64, 0, 0)
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

func (fixture quotaPostgreSQLFixture) multiRuleInput(
	t *testing.T,
	feature string,
	featureMaximum int64,
	userWindow string,
	userMaximum int64,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, featureMaximum)
	input.Rules = []Rule{
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d",
			Maximum: featureMaximum, Hard: true,
		},
		{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: userWindow,
			Maximum: userMaximum, Hard: true,
		},
	}
	return input
}

func (fixture quotaPostgreSQLFixture) outputInput(
	t *testing.T,
	feature string,
	maximum int64,
	reservedUnits int64,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, 10_000)
	input.Rules = append(input.Rules, Rule{
		Metric: OutputTokensMetric, Algorithm: CalendarAlgorithm,
		Scope: []string{"user", "feature"}, Window: "1d",
		Maximum: maximum, ReservedUnits: reservedUnits, Hard: true,
	})
	return input
}

func (fixture quotaPostgreSQLFixture) perRequestOutputInput(
	t *testing.T,
	feature string,
	perRequestMaximum int64,
	reservedUnits int64,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, 1)
	input.Rules = []Rule{{
		Metric: OutputTokensMetric, Algorithm: PerRequestAlgorithm,
		Scope: []string{"user", "feature"}, PerRequestMaximum: perRequestMaximum,
		ReservedUnits: reservedUnits, Hard: true,
	}}
	return input
}

func assertOutputEntryState(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationID string,
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
		WHERE entry.quota_reservation_id = $1 AND bucket.metric = 'output_tokens'
	`, reservationID).Scan(&reserved, &settled, &released, &bucketUsed, &bucketReserved); err != nil {
		t.Fatalf("read output entry state: %v", err)
	}
	if reserved != wantReserved || settled != wantSettled || released != wantReleased ||
		bucketUsed != wantBucketUsed || bucketReserved != wantBucketReserved {
		t.Fatalf("output state entry=%d/%d/%d bucket=%d/%d, want %d/%d/%d and %d/%d",
			reserved, settled, released, bucketUsed, bucketReserved,
			wantReserved, wantSettled, wantReleased, wantBucketUsed, wantBucketReserved)
	}
}

func assertOutputUsage(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	logicalRequestID string,
	attemptID string,
	wantUnits int64,
	wantConfidence string,
) {
	t.Helper()
	var units int64
	var confidence, provenance, storedAttemptID string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT units, confidence, provenance_key, upstream_attempt_id
		FROM usage_records
		WHERE logical_request_id = $1 AND metric = 'output_tokens'
	`, logicalRequestID).Scan(&units, &confidence, &provenance, &storedAttemptID); err != nil {
		t.Fatalf("read output usage: %v", err)
	}
	wantProvenance := providerUsageProvenanceKey(attemptID, OutputTokensMetric)
	if wantConfidence == "unknown" {
		var reservationID string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT quota_reservation_id FROM quota_reservations WHERE logical_request_id = $1
		`, logicalRequestID).Scan(&reservationID); err != nil {
			t.Fatalf("read output usage reservation: %v", err)
		}
		wantProvenance = unknownOutputUsageProvenanceKey(reservationID)
	}
	if units != wantUnits || confidence != wantConfidence || provenance != wantProvenance || storedAttemptID != attemptID {
		t.Fatalf("output usage=%d/%s/%s/%s, want %d/%s/%s/%s",
			units, confidence, provenance, storedAttemptID,
			wantUnits, wantConfidence, wantProvenance, attemptID)
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
	return prepared.rules[0].scopeKey
}

func mustNewID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
