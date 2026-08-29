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
		var observationMu sync.Mutex
		var denialObservations []DenialObservation
		fixture.store.onDenial = func(_ context.Context, observation DenialObservation) {
			observationMu.Lock()
			defer observationMu.Unlock()
			denialObservations = append(denialObservations, observation)
		}
		defer func() { fixture.store.onDenial = nil }()
		input := fixture.input(t, "lifecycle", 1)
		input.ClientRequestID = "shared-client-hint"
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if reservation.LogicalRequestID() != input.LogicalRequestID.String() {
			t.Fatalf("persisted logical ID = %q, want %q", reservation.LogicalRequestID(), input.LogicalRequestID.String())
		}
		var selectedLimitPlan string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT selected_limit_plan_key
			FROM logical_requests
			WHERE organization_id = $1 AND environment_id = $2 AND logical_request_id = $3
		`, input.OrganizationID, input.EnvironmentID, input.LogicalRequestID.String()).Scan(&selectedLimitPlan); err != nil {
			t.Fatalf("read persisted selected limit plan: %v", err)
		}
		if selectedLimitPlan != input.LimitPlanKey {
			t.Fatalf("persisted selected limit plan = %q, want %q", selectedLimitPlan, input.LimitPlanKey)
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
		observationMu.Lock()
		if len(denialObservations) != 1 || denialObservations[0].ApplicationID != deniedInput.ApplicationID ||
			denialObservations[0].EnvironmentID != deniedInput.EnvironmentID ||
			denialObservations[0].Feature != deniedInput.FeatureKey ||
			denialObservations[0].LimitPlan != deniedInput.LimitPlanKey || denialObservations[0].Concurrency {
			t.Fatalf("denial observations = %#v, want one original quota denial", denialObservations)
		}
		observationMu.Unlock()
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

func TestStorePostgreSQLConfiguredPricing(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	knownUsage := Usage{
		InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
		Known: true, Provenance: ProviderReportedProvenance,
	}

	t.Run("known success persists immutable selection and exact cost replay", func(t *testing.T) {
		input := fixture.pricedInput(t, "pricing-known", 100, "standard-usd")
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve priced request: %v", err)
		}
		replay, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || replay.ID() != reservation.ID() || replay.pricing != reservation.pricing {
			t.Fatalf("reserve priced replay = %#v, %v", replay, err)
		}
		changed := cloneReserveInput(input)
		changed.Pricing.CatalogID = "enterprise-usd"
		if _, err := fixture.store.Reserve(fixture.ctx, changed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("changed catalog replay = %v, want ErrInvalidInput", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin priced attempt owner=%t: %v", owner, err)
		}
		assertAttemptPricing(t, fixture, attempt.ID(), nil, UnknownCostConfidence, "standard-usd")
		wrong := reservation
		wrong.pricing.source = "enterprise-usd"
		if _, _, err := fixture.store.BeginAttempt(fixture.ctx, wrong); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("changed opaque pricing selection = %v, want ErrInvalidState", err)
		}
		outcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{NanoUSD: 123_456, Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle known priced request: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle exact known priced replay: %v", err)
		}
		conflicting := outcome
		conflicting.Cost.NanoUSD++
		if err := fixture.store.Settle(fixture.ctx, attempt, conflicting); !errors.Is(err, ErrFinalized) {
			t.Fatalf("conflicting priced settlement = %v, want ErrFinalized", err)
		}
		amount := int64(123_456)
		assertAttemptPricing(t, fixture, attempt.ID(), &amount, CalculatedCostConfidence, "standard-usd")
		assertConfiguredCostUsage(t, fixture, input.LogicalRequestID.String(), attempt.ID(), 123_456, "standard-usd")
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 5 {
			t.Fatalf("priced known usage rows = %d, want logical + provider three + cost", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records
			WHERE logical_request_id = $1 AND metric <> 'cost_nano_usd'
			  AND (cost_nano_usd IS NOT NULL OR currency IS NOT NULL
			       OR price_revision IS NOT NULL OR pricing_source IS NOT NULL)
		`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("non-cost usage rows with pricing metadata = %d, want 0", got)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE usage_records
			SET pricing_source = 'tampered-usd'
			WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'
		`, input.LogicalRequestID.String()); err != nil {
			t.Fatalf("tamper terminal cost usage: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); !errors.Is(err, ErrFinalized) {
			t.Fatalf("tampered cost usage replay = %v, want ErrFinalized", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE usage_records
			SET pricing_source = 'standard-usd'
			WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'
		`, input.LogicalRequestID.String()); err != nil {
			t.Fatalf("restore terminal cost usage: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE upstream_attempts
			SET billed_cost_nano_usd = billed_cost_nano_usd + 1
			WHERE upstream_attempt_id = $1
		`, attempt.ID()); err != nil {
			t.Fatalf("tamper terminal attempt cost: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); !errors.Is(err, ErrFinalized) {
			t.Fatalf("tampered attempt cost replay = %v, want ErrFinalized", err)
		}
	})

	t.Run("explicit known zero cost creates a durable cost row", func(t *testing.T) {
		input := fixture.pricedInput(t, "pricing-zero", 100, "zero-usd")
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve zero priced request: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin zero priced attempt owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle zero priced request: %v", err)
		}
		zero := int64(0)
		assertAttemptPricing(t, fixture, attempt.ID(), &zero, CalculatedCostConfidence, "zero-usd")
		assertConfiguredCostUsage(t, fixture, input.LogicalRequestID.String(), attempt.ID(), 0, "zero-usd")
	})

	t.Run("failed attempt retains known calculated cost", func(t *testing.T) {
		input := fixture.pricedInput(t, "pricing-failed-known", 100, "failure-usd")
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve failed priced request: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin failed priced attempt owner=%t: %v", owner, err)
		}
		outcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_protocol_error",
			Usage: knownUsage,
			Cost:  Cost{NanoUSD: 77, Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle failed known price: %v", err)
		}
		amount := int64(77)
		assertAttemptPricing(t, fixture, attempt.ID(), &amount, CalculatedCostConfidence, "failure-usd")
		assertConfiguredCostUsage(t, fixture, input.LogicalRequestID.String(), attempt.ID(), 77, "failure-usd")
	})

	t.Run("unknown cost preserves selection without manufacturing zero", func(t *testing.T) {
		tests := []struct {
			name      string
			feature   string
			catalog   string
			outcome   Outcome
			usageRows int64
		}{
			{
				name: "successful known usage", feature: "pricing-unknown-success", catalog: "overflow-usd",
				outcome:   Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage},
				usageRows: 4,
			},
			{
				name: "failed unknown usage", feature: "pricing-unknown-failure", catalog: "unknown-usd",
				outcome:   Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable"},
				usageRows: 1,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				input := fixture.pricedInput(t, test.feature, 100, test.catalog)
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				if err != nil {
					t.Fatalf("reserve unknown price: %v", err)
				}
				attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
				if err != nil || !owner {
					t.Fatalf("begin unknown price owner=%t: %v", owner, err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, test.outcome); err != nil {
					t.Fatalf("settle unknown price: %v", err)
				}
				if err := fixture.store.Settle(fixture.ctx, attempt, test.outcome); err != nil {
					t.Fatalf("settle exact unknown price replay: %v", err)
				}
				assertAttemptPricing(t, fixture, attempt.ID(), nil, UnknownCostConfidence, test.catalog)
				if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != test.usageRows {
					t.Fatalf("unknown price usage rows = %d, want %d", got, test.usageRows)
				}
				if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'`, input.LogicalRequestID.String()); got != 0 {
					t.Fatalf("unknown price cost rows = %d, want 0", got)
				}
			})
		}
	})

	t.Run("expiry recovers priced attempt as unknown", func(t *testing.T) {
		input := fixture.pricedInput(t, "pricing-expiry", 100, "expiry-usd")
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve priced expiry: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin priced expiry owner=%t: %v", owner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = $1
		`, reservation.ID()); err != nil {
			t.Fatalf("backdate priced expiry: %v", err)
		}
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire priced attempt processed=%d err=%v", processed, err)
		}
		assertAttemptPricing(t, fixture, attempt.ID(), nil, UnknownCostConfidence, "expiry-usd")
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'`, input.LogicalRequestID.String()); got != 0 {
			t.Fatalf("expired priced cost rows = %d, want 0", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 1 {
			t.Fatalf("expired priced usage rows = %d, want logical request only", got)
		}
	})

	t.Run("predispatch paths and unpriced provider reports remain distinct", func(t *testing.T) {
		releasedInput := fixture.pricedInput(t, "pricing-release", 100, "release-usd")
		released, err := fixture.store.Reserve(fixture.ctx, releasedInput)
		if err != nil {
			t.Fatalf("reserve priced release: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, released, "transport_setup_failed"); err != nil {
			t.Fatalf("release priced request: %v", err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, releasedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("released priced attempts = %d, want 0", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, releasedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("released priced usage rows = %d, want 0", got)
		}

		seedInput := fixture.pricedInput(t, "pricing-denial", 1, "denial-usd")
		seed, err := fixture.store.Reserve(fixture.ctx, seedInput)
		if err != nil {
			t.Fatalf("reserve priced denial seed: %v", err)
		}
		deniedInput := fixture.pricedInput(t, "pricing-denial", 1, "denial-usd")
		if _, err := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(err, ErrExceeded) {
			t.Fatalf("priced denial = %v, want ErrExceeded", err)
		}
		if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied priced attempts = %d, want 0", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied priced usage rows = %d, want 0", got)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, seed, "pricing_denial_done"); err != nil {
			t.Fatalf("release priced denial seed: %v", err)
		}

		unpricedInput := fixture.input(t, "pricing-unpriced", 100)
		unpricedReservation, err := fixture.store.Reserve(fixture.ctx, unpricedInput)
		if err != nil {
			t.Fatalf("reserve unpriced request: %v", err)
		}
		unpricedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, unpricedReservation)
		if err != nil || !owner {
			t.Fatalf("begin unpriced attempt owner=%t: %v", owner, err)
		}
		invalidCost := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage,
			Cost: Cost{NanoUSD: 1, Known: true, Confidence: CalculatedCostConfidence},
		}
		if err := fixture.store.Settle(fixture.ctx, unpricedAttempt, invalidCost); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("known unpriced cost = %v, want ErrInvalidInput", err)
		}
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: knownUsage}
		if err := fixture.store.Settle(fixture.ctx, unpricedAttempt, outcome); err != nil {
			t.Fatalf("settle unpriced request: %v", err)
		}
		assertAttemptUnpriced(t, fixture, unpricedAttempt.ID())
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, unpricedInput.LogicalRequestID.String()); got != 4 {
			t.Fatalf("unpriced usage rows = %d, want historical 4", got)
		}

		reportedInput := fixture.input(t, "pricing-unpriced-reported", 100)
		reportedReservation, err := fixture.store.Reserve(fixture.ctx, reportedInput)
		if err != nil {
			t.Fatalf("reserve unpriced reported request: %v", err)
		}
		reportedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reportedReservation)
		if err != nil || !owner {
			t.Fatalf("begin unpriced reported attempt owner=%t: %v", owner, err)
		}
		reportedCost := Cost{
			NanoUSD: 123_456_789, Known: true, Confidence: ProviderReportedCostConfidence,
			Currency: USDCurrency, Source: ProviderReportedCostSource,
		}
		reportedOutcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200, Cost: reportedCost,
		}
		if err := fixture.store.Settle(fixture.ctx, reportedAttempt, reportedOutcome); err != nil {
			t.Fatalf("settle unpriced reported request: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, reportedAttempt, reportedOutcome); err != nil {
			t.Fatalf("replay unpriced reported settlement: %v", err)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM upstream_attempts
			WHERE upstream_attempt_id = $1 AND billed_cost_nano_usd = $2
			  AND cost_confidence = 'reported' AND currency IS NULL
			  AND price_revision IS NULL AND pricing_source IS NULL
		`, reportedAttempt.ID(), reportedCost.NanoUSD); got != 1 {
			t.Fatalf("unpriced reported attempt attribution = %d, want 1", got)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records
			WHERE logical_request_id = $1 AND upstream_attempt_id = $2
			  AND metric = 'cost_nano_usd' AND units = $3 AND cost_nano_usd = $3
			  AND currency = 'USD' AND price_revision IS NULL
			  AND pricing_source = 'openrouter_usage_cost' AND confidence = 'reported'
			  AND provenance_key = $4
		`, reportedInput.LogicalRequestID.String(), reportedAttempt.ID(), reportedCost.NanoUSD,
			providerUsageProvenanceKey(reportedAttempt.ID(), CostNanoUSDMetric)); got != 1 {
			t.Fatalf("unpriced reported cost usage attribution = %d, want 1", got)
		}
		conflicting := reportedOutcome
		conflicting.Cost.NanoUSD++
		if err := fixture.store.Settle(fixture.ctx, reportedAttempt, conflicting); !errors.Is(err, ErrFinalized) {
			t.Fatalf("conflicting unpriced reported settlement = %v, want ErrFinalized", err)
		}
	})
}

func TestStorePostgreSQLConcurrencyLeases(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	t.Run("request and stream leases replay and release on every terminal path", func(t *testing.T) {
		nonStream := fixture.concurrencyInput(t, "concurrency-basic", 3, 2, false, true)
		reservation, err := fixture.store.Reserve(fixture.ctx, nonStream)
		if err != nil {
			t.Fatalf("reserve non-streaming concurrency: %v", err)
		}
		if len(reservation.entries) != 1 || reservation.entries[0].metric != ConcurrentRequestsMetric ||
			!reservation.ResetAt().IsZero() {
			t.Fatalf("non-streaming reservation entries=%#v reset=%s", reservation.entries, reservation.ResetAt())
		}
		replay, err := fixture.store.Reserve(fixture.ctx, nonStream)
		if err != nil || replay.ID() != reservation.ID() ||
			replay.entries[0].leaseID != reservation.entries[0].leaseID {
			t.Fatalf("replay non-streaming reservation=%#v err=%v", replay, err)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM quota_buckets
			WHERE limit_plan_key = $1 AND metric = 'concurrent_streams'
		`, nonStream.LimitPlanKey); got != 0 {
			t.Fatalf("non-streaming stream buckets = %d, want 0", got)
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM concurrency_leases AS lease
			JOIN quota_reservations AS reservation USING (logical_request_id)
			WHERE reservation.quota_reservation_id = $1
			  AND lease.expires_at = reservation.expires_at
			  AND lease.released_at IS NULL
		`, reservation.ID()); got != 1 {
			t.Fatalf("active non-streaming leases with exact expiry = %d, want 1", got)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin concurrency attempt owner=%t: %v", owner, err)
		}
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 204}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle concurrency attempt: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("replay concurrency settlement: %v", err)
		}
		settledReplay, err := fixture.store.Reserve(fixture.ctx, nonStream)
		if err != nil || settledReplay.ID() != reservation.ID() ||
			settledReplay.entries[0].leaseID != reservation.entries[0].leaseID {
			t.Fatalf("settled reserve replay=%#v err=%v", settledReplay, err)
		}
		assertConcurrencyEntryState(t, fixture, reservation.ID(), ConcurrentRequestsMetric, 1, 0, 1, 0, 0, true)
		if got := fixture.count(t, `
			SELECT count(*) FROM usage_records
			WHERE logical_request_id = $1
			  AND metric IN ('concurrent_requests', 'concurrent_streams')
		`, nonStream.LogicalRequestID.String()); got != 0 {
			t.Fatalf("concurrency usage records = %d, want 0", got)
		}

		stream := fixture.concurrencyInput(t, "concurrency-basic", 3, 2, true, true)
		streamReservation, err := fixture.store.Reserve(fixture.ctx, stream)
		if err != nil {
			t.Fatalf("reserve streaming concurrency: %v", err)
		}
		if len(streamReservation.entries) != 2 || !streamReservation.ResetAt().IsZero() {
			t.Fatalf("streaming entries=%d reset=%s, want 2 and zero", len(streamReservation.entries), streamReservation.ResetAt())
		}
		if got := fixture.count(t, `
			SELECT count(*)
			FROM concurrency_leases AS lease
			JOIN quota_reservations AS reservation USING (logical_request_id)
			WHERE reservation.quota_reservation_id = $1
			  AND lease.expires_at = reservation.expires_at
			  AND lease.released_at IS NULL
		`, streamReservation.ID()); got != 2 {
			t.Fatalf("active streaming leases with exact expiry = %d, want 2", got)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, streamReservation, "transport_setup_failed"); err != nil {
			t.Fatalf("release streaming concurrency: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, streamReservation, "transport_setup_failed"); err != nil {
			t.Fatalf("replay streaming release: %v", err)
		}
		releasedReplay, err := fixture.store.Reserve(fixture.ctx, stream)
		if err != nil || releasedReplay.ID() != streamReservation.ID() {
			t.Fatalf("released reserve replay=%#v err=%v", releasedReplay, err)
		}
		for index := range releasedReplay.entries {
			if releasedReplay.entries[index].leaseID != streamReservation.entries[index].leaseID {
				t.Fatalf("released replay lease %d = %q, want %q", index,
					releasedReplay.entries[index].leaseID, streamReservation.entries[index].leaseID)
			}
		}
		assertConcurrencyEntryState(t, fixture, streamReservation.ID(), ConcurrentRequestsMetric, 1, 0, 1, 0, 0, true)
		assertConcurrencyEntryState(t, fixture, streamReservation.ID(), ConcurrentStreamsMetric, 1, 0, 1, 0, 0, true)
	})

	t.Run("every settled outcome releases its lease without consuming usage", func(t *testing.T) {
		outcomes := []Outcome{
			{Status: AttemptSucceeded, HTTPStatus: 204},
			{Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_unavailable"},
			{Status: AttemptCancelled, FailureCode: "client_cancelled"},
			{Status: AttemptTimedOut, FailureCode: "upstream_timeout"},
		}
		for index, outcome := range outcomes {
			input := fixture.concurrencyInput(t, "concurrency-outcomes", 1, 0, false, false)
			reservation, err := fixture.store.Reserve(fixture.ctx, input)
			if err != nil {
				t.Fatalf("outcome %d reserve: %v", index, err)
			}
			attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
			if err != nil || !owner {
				t.Fatalf("outcome %d begin owner=%t: %v", index, owner, err)
			}
			if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
				t.Fatalf("outcome %d settle: %v", index, err)
			}
			assertConcurrencyEntryState(
				t, fixture, reservation.ID(), ConcurrentRequestsMetric,
				1, 0, 1, 0, 0, true,
			)
		}
	})

	t.Run("denial is atomic replay-stable and calendar denial wins", func(t *testing.T) {
		holderInput := fixture.concurrencyInput(t, "concurrency-denial", 1, 0, false, false)
		holder, err := fixture.store.Reserve(fixture.ctx, holderInput)
		if err != nil {
			t.Fatalf("reserve concurrency holder: %v", err)
		}
		deniedInput := fixture.concurrencyInput(t, "concurrency-denial", 1, 0, false, false)
		deniedInput.Rules = append(deniedInput.Rules, Rule{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 10, Hard: true,
		})
		_, denialErr := fixture.store.Reserve(fixture.ctx, deniedInput)
		var denial *ConcurrencyExceededError
		if !errors.As(denialErr, &denial) || !errors.Is(denialErr, ErrConcurrencyExceeded) ||
			errors.Is(denialErr, ErrExceeded) || denial.LogicalRequestID() != deniedInput.LogicalRequestID.String() ||
			denial.Maximum() != 1 || denial.Active() != 1 {
			t.Fatalf("concurrency denial = %#v / %v", denial, denialErr)
		}
		if got := fixture.count(t, `SELECT count(*) FROM quota_reservations WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied reservations = %d, want 0", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM concurrency_leases WHERE logical_request_id = $1`, deniedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("denied leases = %d, want 0", got)
		}
		var calendarUsed, calendarReserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT used_units, reserved_units FROM quota_buckets
			WHERE limit_plan_key = $1 AND metric = 'logical_requests'
		`, deniedInput.LimitPlanKey).Scan(&calendarUsed, &calendarReserved); err != nil {
			t.Fatalf("read atomically denied calendar bucket: %v", err)
		}
		if calendarUsed != 0 || calendarReserved != 0 {
			t.Fatalf("atomically denied calendar bucket = %d/%d, want 0/0", calendarUsed, calendarReserved)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, holder, "holder_done"); err != nil {
			t.Fatalf("release concurrency holder: %v", err)
		}
		if _, replayErr := fixture.store.Reserve(fixture.ctx, deniedInput); !errors.Is(replayErr, ErrConcurrencyExceeded) {
			t.Fatalf("released-capacity denial replay = %v, want ErrConcurrencyExceeded", replayErr)
		}
		reuseInput := fixture.concurrencyInput(t, "concurrency-denial", 1, 0, false, false)
		reuse, err := fixture.store.Reserve(fixture.ctx, reuseInput)
		if err != nil {
			t.Fatalf("reuse concurrency capacity: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reuse, "reuse_done"); err != nil {
			t.Fatalf("release reused concurrency capacity: %v", err)
		}

		priorityHolderInput := fixture.concurrencyInput(t, "concurrency-priority", 1, 0, false, false)
		priorityHolderInput.Rules = append(priorityHolderInput.Rules, Rule{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user"}, Window: "1d", Maximum: 1, Hard: true,
		})
		priorityHolder, err := fixture.store.Reserve(fixture.ctx, priorityHolderInput)
		if err != nil {
			t.Fatalf("reserve mixed priority holder: %v", err)
		}
		if priorityHolder.ResetAt().IsZero() {
			t.Fatal("mixed calendar/concurrency reservation lost its calendar reset")
		}
		priorityDenied := cloneReserveInput(priorityHolderInput)
		priorityDenied.LogicalRequestID = mustLogicalID(t)
		_, priorityErr := fixture.store.Reserve(fixture.ctx, priorityDenied)
		if !errors.Is(priorityErr, ErrExceeded) || errors.Is(priorityErr, ErrConcurrencyExceeded) {
			t.Fatalf("mixed calendar-priority denial = %v, want ErrExceeded only", priorityErr)
		}
		var failureCode string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT failure_code FROM logical_requests WHERE logical_request_id = $1
		`, priorityDenied.LogicalRequestID.String()).Scan(&failureCode); err != nil {
			t.Fatalf("read mixed denial code: %v", err)
		}
		if failureCode != "quota_exceeded" {
			t.Fatalf("mixed denial code = %q, want quota_exceeded", failureCode)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, priorityHolder, "priority_done"); err != nil {
			t.Fatalf("release mixed priority holder: %v", err)
		}
	})

	t.Run("expiry releases undispatched and dispatched leases and terminal replay detects tamper", func(t *testing.T) {
		dispatchedInput := fixture.concurrencyInput(t, "concurrency-expiry", 3, 0, false, false)
		dispatchedReservation, err := fixture.store.Reserve(fixture.ctx, dispatchedInput)
		if err != nil {
			t.Fatalf("reserve dispatched expiry: %v", err)
		}
		dispatchedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, dispatchedReservation)
		if err != nil || !owner {
			t.Fatalf("begin dispatched expiry owner=%t: %v", owner, err)
		}
		undispatchedInput := fixture.concurrencyInput(t, "concurrency-expiry", 3, 0, false, false)
		undispatchedReservation, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
		if err != nil {
			t.Fatalf("reserve undispatched expiry: %v", err)
		}
		backdateConcurrencyReservations(t, fixture, dispatchedReservation.ID(), undispatchedReservation.ID())
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 10)
		if err != nil || processed != 2 {
			t.Fatalf("expire concurrency reservations processed=%d err=%v, want 2 nil", processed, err)
		}
		assertConcurrencyEntryState(t, fixture, dispatchedReservation.ID(), ConcurrentRequestsMetric, 1, 0, 1, 0, 0, true)
		assertConcurrencyEntryState(t, fixture, undispatchedReservation.ID(), ConcurrentRequestsMetric, 1, 0, 1, 0, 0, true)
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, dispatchedInput.LogicalRequestID.String()); got != 1 {
			t.Fatalf("dispatched expiry usage rows = %d, want logical request only", got)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, undispatchedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("undispatched expiry usage rows = %d, want 0", got)
		}
		expiryOutcome := Outcome{
			Status: AttemptTimedOut, FailureCode: expiryFailureCode,
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}
		if err := fixture.store.Settle(fixture.ctx, dispatchedAttempt, expiryOutcome); err != nil {
			t.Fatalf("replay recovered concurrency settlement: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE concurrency_leases SET released_at = NULL WHERE logical_request_id = $1
		`, dispatchedInput.LogicalRequestID.String()); err != nil {
			t.Fatalf("tamper terminal concurrency lease: %v", err)
		}
		if err := fixture.store.Settle(fixture.ctx, dispatchedAttempt, expiryOutcome); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("tampered terminal settlement replay = %v, want ErrInvalidState", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE concurrency_leases
			SET released_at = statement_timestamp()
			WHERE logical_request_id = $1
		`, dispatchedInput.LogicalRequestID.String()); err != nil {
			t.Fatalf("restore terminal concurrency lease: %v", err)
		}
	})

	t.Run("contention enforces exact maximum and capacity is reusable", func(t *testing.T) {
		const maximum = 5
		const callers = 24
		start := make(chan struct{})
		acceptedChannel := make(chan Reservation, callers)
		failures := make(chan error, callers)
		var wait sync.WaitGroup
		for range callers {
			input := fixture.concurrencyInput(t, "concurrency-contention", maximum, 0, false, false)
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				reservation, reserveErr := fixture.store.Reserve(fixture.ctx, input)
				if reserveErr != nil {
					failures <- reserveErr
					return
				}
				acceptedChannel <- reservation
			}()
		}
		close(start)
		wait.Wait()
		close(acceptedChannel)
		close(failures)
		accepted := make([]Reservation, 0, maximum)
		for reservation := range acceptedChannel {
			accepted = append(accepted, reservation)
		}
		denied := 0
		for reserveErr := range failures {
			if !errors.Is(reserveErr, ErrConcurrencyExceeded) {
				t.Errorf("contention failure = %v, want ErrConcurrencyExceeded", reserveErr)
			}
			denied++
		}
		if len(accepted) != maximum || denied != callers-maximum {
			t.Fatalf("contention accepted=%d denied=%d, want %d/%d", len(accepted), denied, maximum, callers-maximum)
		}
		var used, reserved, activeLeases int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT bucket.used_units, bucket.reserved_units,
			       count(*) FILTER (WHERE lease.released_at IS NULL)
			FROM quota_buckets AS bucket
			JOIN concurrency_leases AS lease USING (quota_bucket_id)
			WHERE bucket.limit_plan_key = 'concurrency-contention'
			GROUP BY bucket.quota_bucket_id
		`).Scan(&used, &reserved, &activeLeases); err != nil {
			t.Fatalf("read contention occupancy: %v", err)
		}
		if used != 0 || reserved != maximum || activeLeases != maximum {
			t.Fatalf("contention bucket used=%d reserved=%d leases=%d", used, reserved, activeLeases)
		}
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "contention_done"); err != nil {
				t.Fatalf("release contention reservation: %v", err)
			}
		}
		for range maximum {
			reuseInput := fixture.concurrencyInput(t, "concurrency-contention", maximum, 0, false, false)
			reuse, err := fixture.store.Reserve(fixture.ctx, reuseInput)
			if err != nil {
				t.Fatalf("reuse contention capacity: %v", err)
			}
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reuse, "reuse_done"); err != nil {
				t.Fatalf("release reused contention capacity: %v", err)
			}
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM quota_buckets
			WHERE limit_plan_key = 'concurrency-contention'
			  AND used_units = 0 AND reserved_units = 0
		`); got != 1 {
			t.Fatalf("reusable empty concurrency bucket = %d, want 1", got)
		}
	})

	t.Run("settlement and expiry serialize one lease release", func(t *testing.T) {
		for iteration := range 8 {
			input := fixture.concurrencyInput(t, "concurrency-race", 1, 0, false, false)
			reservation, err := fixture.store.Reserve(fixture.ctx, input)
			if err != nil {
				t.Fatalf("iteration %d reserve: %v", iteration, err)
			}
			attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
			if err != nil || !owner {
				t.Fatalf("iteration %d begin owner=%t: %v", iteration, owner, err)
			}
			backdateConcurrencyReservations(t, fixture, reservation.ID())
			start := make(chan struct{})
			settlement := make(chan error, 1)
			expiry := make(chan struct {
				processed int64
				err       error
			}, 1)
			go func() {
				<-start
				settlement <- fixture.store.Settle(
					fixture.ctx, attempt, Outcome{Status: AttemptSucceeded, HTTPStatus: 204},
				)
			}()
			go func() {
				<-start
				processed, expiryErr := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
				expiry <- struct {
					processed int64
					err       error
				}{processed: processed, err: expiryErr}
			}()
			close(start)
			settleErr := <-settlement
			expiryResult := <-expiry
			settleWon := settleErr == nil && expiryResult.err == nil && expiryResult.processed == 0
			expiryWon := errors.Is(settleErr, ErrFinalized) && expiryResult.err == nil && expiryResult.processed == 1
			if !settleWon && !expiryWon {
				t.Fatalf("iteration %d settle=%v expiry=%d/%v", iteration, settleErr, expiryResult.processed, expiryResult.err)
			}
			assertConcurrencyEntryState(t, fixture, reservation.ID(), ConcurrentRequestsMetric, 1, 0, 1, 0, 0, true)
		}
	})
}

func TestStorePostgreSQLTokenBucket(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	type bucketState struct {
		capacity, used, reserved, balance, numerator, denominator, version int64
		refilledAt                                                         time.Time
		algorithm, windowKey                                               string
	}
	readBucket := func(t *testing.T, bucketID string) bucketState {
		t.Helper()
		var state bucketState
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT hard_maximum, used_units, reserved_units, available_units,
			       refill_numerator, refill_denominator, refilled_at, version,
			       algorithm, window_key
			FROM quota_buckets
			WHERE quota_bucket_id = $1
		`, bucketID).Scan(
			&state.capacity, &state.used, &state.reserved, &state.balance,
			&state.numerator, &state.denominator, &state.refilledAt, &state.version,
			&state.algorithm, &state.windowKey,
		); err != nil {
			t.Fatalf("read token bucket: %v", err)
		}
		state.refilledAt = state.refilledAt.UTC()
		return state
	}

	t.Run("exact executable capacity and rate bounds", func(t *testing.T) {
		input := fixture.tokenBucketInput(
			t, "token-bounds", maximumTokenCapacity, tokenRateDecimalScale, 1,
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve maximum token policy: %v", err)
		}
		state := readBucket(t, reservation.entries[0].bucketID)
		maximumBalance, ok := tokenCapacityBalance(maximumTokenCapacity)
		if !ok || state.capacity != maximumTokenCapacity ||
			state.balance != maximumBalance-tokenBalanceScale ||
			state.numerator != tokenRateDecimalScale || state.denominator != 1 {
			t.Fatalf("maximum token policy state = %#v", state)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
			t.Fatalf("release maximum token policy: %v", err)
		}

		for _, invalid := range []ReserveInput{
			fixture.tokenBucketInput(t, "token-capacity-overflow", maximumTokenCapacity+1, 1, 1),
			fixture.tokenBucketInput(t, "token-rate-overflow", 1, tokenRateDecimalScale+1, 1),
		} {
			if _, err := fixture.store.Reserve(fixture.ctx, invalid); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid bounded policy returned %v", err)
			}
			if got := fixture.count(t, `
				SELECT count(*) FROM logical_requests WHERE logical_request_id = $1
			`, invalid.LogicalRequestID.String()); got != 0 {
				t.Fatalf("invalid bounded policy logical rows=%d", got)
			}
		}
	})

	t.Run("reserve denial replay and pre-dispatch release", func(t *testing.T) {
		input := fixture.tokenBucketInput(t, "token-release", 1, 1, tokenRateDecimalScale)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve token: %v", err)
		}
		if len(reservation.entries) != 1 || !reservation.ResetAt().IsZero() ||
			reservation.entries[0].algorithm != TokenBucketAlgorithm ||
			reservation.entries[0].reservedUnits != 1 {
			t.Fatalf("token reservation = %#v reset=%s", reservation.entries, reservation.ResetAt())
		}
		bucketID := reservation.entries[0].bucketID
		state := readBucket(t, bucketID)
		if state.capacity != 1 || state.used != 0 || state.reserved != 0 || state.balance != 0 ||
			state.numerator != 1 || state.denominator != tokenRateDecimalScale ||
			state.algorithm != TokenBucketAlgorithm || state.windowKey != tokenBucketWindowKey {
			t.Fatalf("reserved token state = %#v", state)
		}
		var entryReserved, entrySettled, entryReleased int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT reserved_units, settled_units, released_units
			FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&entryReserved, &entrySettled, &entryReleased); err != nil {
			t.Fatalf("read token entry: %v", err)
		}
		if entryReserved != 1 || entrySettled != 0 || entryReleased != 0 {
			t.Fatalf("token entry=%d/%d/%d, want 1/0/0", entryReserved, entrySettled, entryReleased)
		}

		replayed, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || replayed.ID() != reservation.ID() {
			t.Fatalf("accepted replay=%s: %v", replayed.ID(), err)
		}
		if afterReplay := readBucket(t, bucketID); afterReplay != state {
			t.Fatalf("accepted replay mutated token bucket: before=%#v after=%#v", state, afterReplay)
		}

		deniedInput := fixture.tokenBucketInput(t, "token-release", 1, 1, tokenRateDecimalScale)
		_, err = fixture.store.Reserve(fixture.ctx, deniedInput)
		var denial *ExceededError
		if !errors.As(err, &denial) || denial.Maximum() != 1 || denial.Reserved() != 0 ||
			denial.Used() != 1 || denial.RetryAt().IsZero() {
			t.Fatalf("token denial = %#v, %v", denial, err)
		}
		deniedState := readBucket(t, bucketID)
		expectedRetry, retryErr := tokenRetryAt(tokenBucketState{
			capacity: deniedState.capacity, balance: deniedState.balance,
			numerator: deniedState.numerator, denominator: deniedState.denominator,
			refilledAt: deniedState.refilledAt,
		}, 1, deniedState.refilledAt)
		if retryErr != nil || !denial.RetryAt().Equal(expectedRetry) {
			t.Fatalf("denial retry=%s want=%s: %v", denial.RetryAt(), expectedRetry, retryErr)
		}
		_, replayErr := fixture.store.Reserve(fixture.ctx, deniedInput)
		var replayDenial *ExceededError
		if !errors.As(replayErr, &replayDenial) || !replayDenial.RetryAt().Equal(denial.RetryAt()) {
			t.Fatalf("denied replay=%#v, %v", replayDenial, replayErr)
		}
		changed := cloneReserveInput(deniedInput)
		changed.Rules[0].Capacity = 2
		if _, replayErr := fixture.store.Reserve(fixture.ctx, changed); !errors.Is(replayErr, ErrInvalidInput) {
			t.Fatalf("changed-policy replay = %v", replayErr)
		}

		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
			t.Fatalf("release token: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
			t.Fatalf("release replay: %v", err)
		}
		refunded := readBucket(t, bucketID)
		var releasedAt time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT released_at FROM quota_reservations WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&releasedAt); err != nil {
			t.Fatalf("read token release time: %v", err)
		}
		if refunded.balance != tokenBalanceScale || refunded.used != 0 || refunded.reserved != 0 ||
			!refunded.refilledAt.Equal(releasedAt.UTC()) {
			t.Fatalf("refunded token state = %#v", refunded)
		}
		var released int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT released_units FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&released); err != nil || released != 1 {
			t.Fatalf("released semantic token=%d: %v", released, err)
		}
		afterRefund := fixture.tokenBucketInput(t, "token-release", 1, 1, tokenRateDecimalScale)
		accepted, err := fixture.store.Reserve(fixture.ctx, afterRefund)
		if err != nil {
			t.Fatalf("reserve refunded token: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, accepted, "routing_failed"); err != nil {
			t.Fatalf("clean refunded token: %v", err)
		}
	})

	t.Run("settlement keeps the dispatch-time debit", func(t *testing.T) {
		input := fixture.tokenBucketInput(t, "token-settle", 1, 1, tokenRateDecimalScale)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
		if err != nil || !owner {
			t.Fatalf("begin attempt owner=%t: %v", owner, err)
		}
		if err := fixture.store.Settle(fixture.ctx, attempt, Outcome{Status: AttemptSucceeded, HTTPStatus: 204}); err != nil {
			t.Fatalf("settle: %v", err)
		}
		state := readBucket(t, reservation.entries[0].bucketID)
		if state.balance != 0 || state.used != 0 || state.reserved != 0 {
			t.Fatalf("settled token state = %#v", state)
		}
		var settled, released int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT settled_units, released_units FROM quota_reservation_entries
			WHERE quota_reservation_id = $1
		`, reservation.ID()).Scan(&settled, &released); err != nil {
			t.Fatalf("read settled token entry: %v", err)
		}
		if settled != 1 || released != 0 {
			t.Fatalf("settled token entry=%d/%d, want 1/0", settled, released)
		}
	})

	t.Run("pending requests do not become accidental concurrency", func(t *testing.T) {
		firstInput := fixture.tokenBucketInput(t, "token-refill", 1, 1_000, 1)
		first, err := fixture.store.Reserve(fixture.ctx, firstInput)
		if err != nil {
			t.Fatalf("reserve first: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET refilled_at = statement_timestamp() - interval '10 milliseconds'
			WHERE quota_bucket_id = $1
		`, first.entries[0].bucketID); err != nil {
			t.Fatalf("backdate token refill: %v", err)
		}
		secondInput := fixture.tokenBucketInput(t, "token-refill", 1, 1_000, 1)
		second, err := fixture.store.Reserve(fixture.ctx, secondInput)
		if err != nil {
			t.Fatalf("reserve refilled token while first pending: %v", err)
		}
		state := readBucket(t, first.entries[0].bucketID)
		if state.used != 0 || state.reserved != 0 || state.balance != 0 {
			t.Fatalf("refilled pending state = %#v", state)
		}
		for _, reservation := range []Reservation{first, second} {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
				t.Fatalf("release pending token: %v", err)
			}
		}
	})

	t.Run("submillisecond balances enforce the exact eligibility boundary", func(t *testing.T) {
		input := fixture.tokenBucketInput(t, "token-submillisecond", 1, 2_000, 1)
		holder, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve submillisecond holder: %v", err)
		}
		credit, err := tokenCreditPerTick(2_000, 1)
		if err != nil {
			t.Fatalf("calculate submillisecond credit: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET available_units = $2,
			    refilled_at = statement_timestamp() + interval '1 hour'
			WHERE quota_bucket_id = $1
		`, holder.entries[0].bucketID, 499*credit); err != nil {
			t.Fatalf("set 499us-equivalent balance: %v", err)
		}
		at499Microseconds := fixture.tokenBucketInput(t, "token-submillisecond", 1, 2_000, 1)
		if _, err := fixture.store.Reserve(fixture.ctx, at499Microseconds); !errors.Is(err, ErrExceeded) {
			t.Fatalf("499us-equivalent reserve = %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets SET available_units = $2
			WHERE quota_bucket_id = $1
		`, holder.entries[0].bucketID, 500*credit); err != nil {
			t.Fatalf("set 500us-equivalent balance: %v", err)
		}
		at500Microseconds := fixture.tokenBucketInput(t, "token-submillisecond", 1, 2_000, 1)
		accepted, err := fixture.store.Reserve(fixture.ctx, at500Microseconds)
		if err != nil {
			t.Fatalf("500us-equivalent reserve: %v", err)
		}
		for _, reservation := range []Reservation{holder, accepted} {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
				t.Fatalf("release submillisecond reservation: %v", err)
			}
		}
	})

	t.Run("capacity increase gives no instantaneous tokens", func(t *testing.T) {
		oldInput := fixture.tokenBucketInput(t, "token-policy", 1, 1, tokenRateDecimalScale)
		oldReservation, err := fixture.store.Reserve(fixture.ctx, oldInput)
		if err != nil {
			t.Fatalf("reserve old policy: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, oldReservation, "routing_failed"); err != nil {
			t.Fatalf("restore old token: %v", err)
		}
		newInput := fixture.tokenBucketInput(t, "token-policy", 3, 1, tokenRateDecimalScale)
		newReservation, err := fixture.store.Reserve(fixture.ctx, newInput)
		if err != nil {
			t.Fatalf("reserve transitioned policy: %v", err)
		}
		state := readBucket(t, newReservation.entries[0].bucketID)
		if state.capacity != 3 || state.balance != 0 || state.numerator != 1 ||
			state.denominator != tokenRateDecimalScale {
			t.Fatalf("capacity transition state = %#v", state)
		}
		third := fixture.tokenBucketInput(t, "token-policy", 3, 1, tokenRateDecimalScale)
		if _, err := fixture.store.Reserve(fixture.ctx, third); !errors.Is(err, ErrExceeded) {
			t.Fatalf("instant capacity gift reserve = %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, newReservation, "routing_failed"); err != nil {
			t.Fatalf("release transitioned token: %v", err)
		}
	})

	t.Run("rate increase reconciles the pending interval at the lower rate", func(t *testing.T) {
		oldInput := fixture.tokenBucketInput(t, "token-rate-policy", 2, 1, tokenRateDecimalScale)
		first, err := fixture.store.Reserve(fixture.ctx, oldInput)
		if err != nil {
			t.Fatalf("reserve first old-rate token: %v", err)
		}
		secondInput := fixture.tokenBucketInput(t, "token-rate-policy", 2, 1, tokenRateDecimalScale)
		second, err := fixture.store.Reserve(fixture.ctx, secondInput)
		if err != nil {
			t.Fatalf("reserve second old-rate token: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET available_units = 0, refilled_at = statement_timestamp()
			WHERE quota_bucket_id = $1
		`, first.entries[0].bucketID); err != nil {
			t.Fatalf("anchor old-rate cursor: %v", err)
		}
		faster := fixture.tokenBucketInput(t, "token-rate-policy", 2, 1_000, 1)
		if _, err := fixture.store.Reserve(fixture.ctx, faster); !errors.Is(err, ErrExceeded) {
			t.Fatalf("rate increase minted prior-interval token: %v", err)
		}
		state := readBucket(t, first.entries[0].bucketID)
		if state.numerator != 1_000 || state.denominator != 1 ||
			state.balance >= tokenBalanceScale || state.used != 0 || state.reserved != 0 {
			t.Fatalf("rate transition state = %#v", state)
		}
		for _, reservation := range []Reservation{first, second} {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
				t.Fatalf("release old-rate reservation: %v", err)
			}
		}
	})

	t.Run("calendar denial does not debit a mixed token bucket", func(t *testing.T) {
		calendarHolderInput := fixture.input(t, "token-mixed", 1)
		calendarHolder, err := fixture.store.Reserve(fixture.ctx, calendarHolderInput)
		if err != nil {
			t.Fatalf("reserve calendar holder: %v", err)
		}
		mixed := fixture.tokenBucketInput(t, "token-mixed", 1, 1, tokenRateDecimalScale)
		mixed.Rules = append(mixed.Rules, calendarHolderInput.Rules[0])
		if _, err := fixture.store.Reserve(fixture.ctx, mixed); !errors.Is(err, ErrExceeded) {
			t.Fatalf("mixed denial = %v", err)
		}
		scopeKey := mustPreparedTokenScopeKey(t, mixed)
		var tokenBucketID string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT quota_bucket_id FROM quota_buckets
			WHERE environment_id = $1 AND limit_plan_key = $2
			  AND algorithm = 'token_bucket' AND scope_key = $3
		`, mixed.EnvironmentID, mixed.LimitPlanKey, scopeKey).Scan(&tokenBucketID); err != nil {
			t.Fatalf("find mixed token bucket: %v", err)
		}
		state := readBucket(t, tokenBucketID)
		if state.balance != tokenBalanceScale || state.used != 0 || state.reserved != 0 {
			t.Fatalf("mixed-denied token state = %#v", state)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, calendarHolder, "routing_failed"); err != nil {
			t.Fatalf("release calendar holder: %v", err)
		}
	})

	t.Run("contention admits exactly available tokens", func(t *testing.T) {
		const capacity = 3
		const callers = 12
		inputs := make([]ReserveInput, callers)
		for index := range inputs {
			inputs[index] = fixture.tokenBucketInput(t, "token-contention", capacity, 1, tokenRateDecimalScale)
		}
		start := make(chan struct{})
		type result struct {
			reservation Reservation
			err         error
		}
		results := make(chan result, callers)
		for index := range inputs {
			go func(input ReserveInput) {
				<-start
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				results <- result{reservation: reservation, err: err}
			}(inputs[index])
		}
		close(start)
		accepted := make([]Reservation, 0, capacity)
		denied := 0
		for range callers {
			result := <-results
			if result.err == nil {
				accepted = append(accepted, result.reservation)
			} else if errors.Is(result.err, ErrExceeded) {
				denied++
			} else {
				t.Fatalf("contended reserve: %v", result.err)
			}
		}
		if len(accepted) != capacity || denied != callers-capacity {
			t.Fatalf("contention accepted=%d denied=%d", len(accepted), denied)
		}
		state := readBucket(t, accepted[0].entries[0].bucketID)
		if state.balance >= tokenBalanceScale || state.used != 0 || state.reserved != 0 {
			t.Fatalf("contended state = %#v", state)
		}
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
				t.Fatalf("release contended reservation: %v", err)
			}
		}
		if state := readBucket(t, accepted[0].entries[0].bucketID); state.balance != capacity*tokenBalanceScale {
			t.Fatalf("released contended state = %#v", state)
		}
	})

	t.Run("expiry refunds only an undispatched request", func(t *testing.T) {
		undispatchedInput := fixture.tokenBucketInput(t, "token-expire-undispatched", 1, 1, tokenRateDecimalScale)
		undispatched, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
		if err != nil {
			t.Fatalf("reserve undispatched: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = $1
		`, undispatched.ID()); err != nil {
			t.Fatalf("backdate undispatched: %v", err)
		}
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire undispatched=%d: %v", processed, err)
		}
		if state := readBucket(t, undispatched.entries[0].bucketID); state.balance != tokenBalanceScale {
			t.Fatalf("expired undispatched state = %#v", state)
		}

		dispatchedInput := fixture.tokenBucketInput(t, "token-expire-dispatched", 1, 1, tokenRateDecimalScale)
		dispatched, err := fixture.store.Reserve(fixture.ctx, dispatchedInput)
		if err != nil {
			t.Fatalf("reserve dispatched: %v", err)
		}
		if _, owner, err := fixture.store.BeginAttempt(fixture.ctx, dispatched); err != nil || !owner {
			t.Fatalf("begin dispatched owner=%t: %v", owner, err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = $1
		`, dispatched.ID()); err != nil {
			t.Fatalf("backdate dispatched: %v", err)
		}
		processed, err = fixture.store.ExpirePendingBatch(fixture.ctx, 1)
		if err != nil || processed != 1 {
			t.Fatalf("expire dispatched=%d: %v", processed, err)
		}
		if state := readBucket(t, dispatched.entries[0].bucketID); state.balance != 0 {
			t.Fatalf("expired dispatched token was refunded: %#v", state)
		}
	})

	t.Run("corrupt persisted balance fails closed", func(t *testing.T) {
		input := fixture.tokenBucketInput(t, "token-corrupt", 2, 1, tokenRateDecimalScale)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve token for corruption: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
			t.Fatalf("release token for corruption: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets SET available_units = hard_maximum * $2 + 1
			WHERE quota_bucket_id = $1
		`, reservation.entries[0].bucketID, tokenBalanceScale); err != nil {
			t.Fatalf("corrupt token balance: %v", err)
		}
		other := fixture.tokenBucketInput(t, "token-corrupt", 2, 1, tokenRateDecimalScale)
		if _, err := fixture.store.Reserve(fixture.ctx, other); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("reserve corrupt token bucket = %v", err)
		}
	})
}

func TestStorePostgreSQLOutputTokenBucket(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)

	type bucketState struct {
		capacity, used, reserved, balance, numerator, denominator, version int64
		refilledAt                                                         time.Time
	}
	readBucket := func(t *testing.T, bucketID string) bucketState {
		t.Helper()
		var state bucketState
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT hard_maximum, used_units, reserved_units, available_units,
			       refill_numerator, refill_denominator, refilled_at, version
			FROM quota_buckets
			WHERE quota_bucket_id = $1 AND metric = 'output_tokens'
			  AND algorithm = 'token_bucket' AND window_key = 'rolling'
		`, bucketID).Scan(
			&state.capacity, &state.used, &state.reserved, &state.balance,
			&state.numerator, &state.denominator, &state.refilledAt, &state.version,
		); err != nil {
			t.Fatalf("read output token bucket: %v", err)
		}
		state.refilledAt = state.refilledAt.UTC()
		return state
	}
	tokenEntry := func(t *testing.T, reservation Reservation) reservationEntry {
		t.Helper()
		for _, entry := range reservation.entries {
			if entry.metric == OutputTokensMetric && entry.algorithm == TokenBucketAlgorithm {
				return entry
			}
		}
		t.Fatal("reservation has no output token entry")
		return reservationEntry{}
	}
	assertEntry := func(
		t *testing.T,
		reservationID string,
		wantReserved int64,
		wantSettled int64,
		wantReleased int64,
	) {
		t.Helper()
		var reserved, settled, released, bucketUsed, bucketReserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT entry.reserved_units, entry.settled_units, entry.released_units,
			       bucket.used_units, bucket.reserved_units
			FROM quota_reservation_entries AS entry
			JOIN quota_buckets AS bucket USING (quota_bucket_id)
			WHERE entry.quota_reservation_id = $1
			  AND bucket.metric = 'output_tokens' AND bucket.algorithm = 'token_bucket'
		`, reservationID).Scan(
			&reserved, &settled, &released, &bucketUsed, &bucketReserved,
		); err != nil {
			t.Fatalf("read output token entry: %v", err)
		}
		if reserved != wantReserved || settled != wantSettled || released != wantReleased ||
			bucketUsed != 0 || bucketReserved != 0 {
			t.Fatalf("output token entry=%d/%d/%d bucket=%d/%d, want %d/%d/%d and 0/0",
				reserved, settled, released, bucketUsed, bucketReserved,
				wantReserved, wantSettled, wantReleased)
		}
	}

	t.Run("variable reserve denial replay release and known refund", func(t *testing.T) {
		input := fixture.outputTokenBucketInput(
			t, "output-token-reserve", 100, 1, tokenRateDecimalScale, 64,
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve variable output tokens: %v", err)
		}
		entry := tokenEntry(t, reservation)
		if !reservation.ResetAt().IsZero() || entry.reservedUnits != 64 || !entry.resetAt.IsZero() {
			t.Fatalf("output token reservation=%#v reset=%s", reservation.entries, reservation.ResetAt())
		}
		state := readBucket(t, entry.bucketID)
		if state.capacity != 100 || state.balance != 36*tokenBalanceScale ||
			state.used != 0 || state.reserved != 0 || state.numerator != 1 ||
			state.denominator != tokenRateDecimalScale {
			t.Fatalf("variable reserve state=%#v", state)
		}
		assertEntry(t, reservation.ID(), 64, 0, 0)

		replay, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil || replay.ID() != reservation.ID() {
			t.Fatalf("accepted output token replay=%s: %v", replay.ID(), err)
		}
		if afterReplay := readBucket(t, entry.bucketID); afterReplay != state {
			t.Fatalf("accepted replay mutated bucket: before=%#v after=%#v", state, afterReplay)
		}
		for name, mutate := range map[string]func(*Rule){
			"cost":     func(rule *Rule) { rule.ReservedUnits-- },
			"capacity": func(rule *Rule) { rule.Capacity++ },
			"rate": func(rule *Rule) {
				rule.RefillNumerator = 1
				rule.RefillDenominator = 2
			},
		} {
			changed := cloneReserveInput(input)
			mutate(&changed.Rules[0])
			if _, replayErr := fixture.store.Reserve(fixture.ctx, changed); !errors.Is(replayErr, ErrInvalidInput) {
				t.Fatalf("changed %s replay=%v", name, replayErr)
			}
		}

		deniedInput := fixture.outputTokenBucketInput(
			t, "output-token-reserve", 100, 1, tokenRateDecimalScale, 64,
		)
		_, err = fixture.store.Reserve(fixture.ctx, deniedInput)
		var denial *ExceededError
		if !errors.As(err, &denial) || denial.Maximum() != 100 || denial.Reserved() != 0 ||
			denial.Used() != 64 || denial.RetryAt().IsZero() {
			t.Fatalf("variable output denial=%#v: %v", denial, err)
		}
		deniedState := readBucket(t, entry.bucketID)
		expectedRetry, retryErr := tokenRetryAt(tokenBucketState{
			capacity: deniedState.capacity, balance: deniedState.balance,
			numerator: deniedState.numerator, denominator: deniedState.denominator,
			refilledAt: deniedState.refilledAt,
		}, 64, deniedState.refilledAt)
		if retryErr != nil || !denial.RetryAt().Equal(expectedRetry) {
			t.Fatalf("variable denial retry=%v want=%v: %v", denial.RetryAt(), expectedRetry, retryErr)
		}
		_, replayErr := fixture.store.Reserve(fixture.ctx, deniedInput)
		var replayDenial *ExceededError
		if !errors.As(replayErr, &replayDenial) || !replayDenial.RetryAt().Equal(denial.RetryAt()) {
			t.Fatalf("denied output replay=%#v: %v", replayDenial, replayErr)
		}
		if afterDeniedReplay := readBucket(t, entry.bucketID); afterDeniedReplay != deniedState {
			t.Fatalf("denied replay persisted virtual refill: before=%#v after=%#v", deniedState, afterDeniedReplay)
		}

		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
			t.Fatalf("release variable output tokens: %v", err)
		}
		refunded := readBucket(t, entry.bucketID)
		if refunded.balance != 100*tokenBalanceScale || refunded.used != 0 || refunded.reserved != 0 ||
			refunded.refilledAt.Before(deniedState.refilledAt) {
			t.Fatalf("full variable refund=%#v", refunded)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "routing_failed"); err != nil {
			t.Fatalf("release replay: %v", err)
		}
		if afterReleaseReplay := readBucket(t, entry.bucketID); afterReleaseReplay != refunded {
			t.Fatalf("release replay mutated bucket: before=%#v after=%#v", refunded, afterReleaseReplay)
		}
		assertEntry(t, reservation.ID(), 64, 0, 64)

		knownInput := fixture.outputTokenBucketInput(
			t, "output-token-known", 100, 1, tokenRateDecimalScale, 64,
		)
		knownReservation, err := fixture.store.Reserve(fixture.ctx, knownInput)
		if err != nil {
			t.Fatalf("reserve known output: %v", err)
		}
		knownEntry := tokenEntry(t, knownReservation)
		attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, knownReservation)
		if err != nil || !owner {
			t.Fatalf("begin known output owner=%t: %v", owner, err)
		}
		beforeSettlement := readBucket(t, knownEntry.bucketID)
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
			Known: true, Provenance: ProviderReportedProvenance,
		}}
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("settle known output: %v", err)
		}
		afterSettlement := readBucket(t, knownEntry.bucketID)
		if beforeSettlement.balance != 36*tokenBalanceScale ||
			afterSettlement.balance != 93*tokenBalanceScale ||
			afterSettlement.version != beforeSettlement.version+1 ||
			!afterSettlement.refilledAt.Equal(beforeSettlement.refilledAt) ||
			afterSettlement.used != 0 || afterSettlement.reserved != 0 {
			t.Fatalf("known output refund before=%#v after=%#v", beforeSettlement, afterSettlement)
		}
		assertEntry(t, knownReservation.ID(), 64, 7, 57)
		assertOutputUsage(t, fixture, knownInput.LogicalRequestID.String(), attempt.ID(), 7, "reported")
		if err := fixture.store.Settle(fixture.ctx, attempt, outcome); err != nil {
			t.Fatalf("known settlement replay: %v", err)
		}
		if afterReplay := readBucket(t, knownEntry.bucketID); afterReplay != afterSettlement {
			t.Fatalf("known settlement replay mutated bucket: before=%#v after=%#v", afterSettlement, afterReplay)
		}
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, knownInput.LogicalRequestID.String()); got != 4 {
			t.Fatalf("known settlement usage rows=%d, want 4", got)
		}

		zeroUnusedInput := fixture.outputTokenBucketInput(
			t, "output-token-zero-unused", 100, 1, tokenRateDecimalScale, 64,
		)
		zeroUnusedReservation, err := fixture.store.Reserve(fixture.ctx, zeroUnusedInput)
		if err != nil {
			t.Fatalf("reserve zero-unused output: %v", err)
		}
		zeroUnusedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, zeroUnusedReservation)
		if err != nil || !owner {
			t.Fatalf("begin zero-unused output owner=%t: %v", owner, err)
		}
		zeroUnusedEntry := tokenEntry(t, zeroUnusedReservation)
		beforeZeroUnused := readBucket(t, zeroUnusedEntry.bucketID)
		zeroUnusedOutcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 11, OutputTokens: 64, TotalTokens: 75,
			Known: true, Provenance: ProviderReportedProvenance,
		}}
		if err := fixture.store.Settle(fixture.ctx, zeroUnusedAttempt, zeroUnusedOutcome); err != nil {
			t.Fatalf("settle zero-unused output: %v", err)
		}
		if afterZeroUnused := readBucket(t, zeroUnusedEntry.bucketID); afterZeroUnused != beforeZeroUnused {
			t.Fatalf("zero-unused settlement wrote bucket: before=%#v after=%#v", beforeZeroUnused, afterZeroUnused)
		}
		assertEntry(t, zeroUnusedReservation.ID(), 64, 64, 0)
		assertOutputUsage(t, fixture, zeroUnusedInput.LogicalRequestID.String(), zeroUnusedAttempt.ID(), 64, "reported")

		fullUnusedInput := fixture.outputTokenBucketInput(
			t, "output-token-full-unused", 100, 1, tokenRateDecimalScale, 64,
		)
		fullUnusedReservation, err := fixture.store.Reserve(fixture.ctx, fullUnusedInput)
		if err != nil {
			t.Fatalf("reserve full-unused output: %v", err)
		}
		fullUnusedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, fullUnusedReservation)
		if err != nil || !owner {
			t.Fatalf("begin full-unused output owner=%t: %v", owner, err)
		}
		fullUnusedEntry := tokenEntry(t, fullUnusedReservation)
		beforeFullUnused := readBucket(t, fullUnusedEntry.bucketID)
		fullUnusedOutcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 11, OutputTokens: 0, TotalTokens: 11,
			Known: true, Provenance: ProviderReportedProvenance,
		}}
		if err := fixture.store.Settle(fixture.ctx, fullUnusedAttempt, fullUnusedOutcome); err != nil {
			t.Fatalf("settle full-unused output: %v", err)
		}
		afterFullUnused := readBucket(t, fullUnusedEntry.bucketID)
		if afterFullUnused.balance != 100*tokenBalanceScale ||
			afterFullUnused.version != beforeFullUnused.version+1 ||
			afterFullUnused.refilledAt.Before(beforeFullUnused.refilledAt) ||
			afterFullUnused.used != 0 || afterFullUnused.reserved != 0 {
			t.Fatalf("full-unused settlement before=%#v after=%#v", beforeFullUnused, afterFullUnused)
		}
		assertEntry(t, fullUnusedReservation.ID(), 64, 0, 64)
		assertOutputUsage(t, fixture, fullUnusedInput.LogicalRequestID.String(), fullUnusedAttempt.ID(), 0, "reported")
	})

	t.Run("variable cost requires every balance quantum", func(t *testing.T) {
		holderInput := fixture.outputTokenBucketInput(
			t, "output-token-quantum-boundary", 100,
			tokenRateDecimalScale, 1, 100,
		)
		holder, err := fixture.store.Reserve(fixture.ctx, holderInput)
		if err != nil {
			t.Fatalf("reserve quantum-boundary holder: %v", err)
		}
		entry := tokenEntry(t, holder)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets
			SET available_units = $2,
			    refilled_at = statement_timestamp() + interval '1 hour'
			WHERE quota_bucket_id = $1
		`, entry.bucketID, 64*tokenBalanceScale-1); err != nil {
			t.Fatalf("set one-quantum-short balance: %v", err)
		}
		shortInput := fixture.outputTokenBucketInput(
			t, "output-token-quantum-boundary", 100,
			tokenRateDecimalScale, 1, 64,
		)
		if _, err := fixture.store.Reserve(fixture.ctx, shortInput); !errors.Is(err, ErrExceeded) {
			t.Fatalf("one-quantum-short variable reserve=%v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets SET available_units = $2 WHERE quota_bucket_id = $1
		`, entry.bucketID, 64*tokenBalanceScale); err != nil {
			t.Fatalf("set exact variable balance: %v", err)
		}
		exactInput := fixture.outputTokenBucketInput(
			t, "output-token-quantum-boundary", 100,
			tokenRateDecimalScale, 1, 64,
		)
		exact, err := fixture.store.Reserve(fixture.ctx, exactInput)
		if err != nil {
			t.Fatalf("exact variable balance reserve: %v", err)
		}
		if state := readBucket(t, entry.bucketID); state.balance != 0 || state.used != 0 || state.reserved != 0 {
			t.Fatalf("exact variable balance state=%#v", state)
		}
		for _, reservation := range []Reservation{holder, exact} {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "quantum_test_done"); err != nil {
				t.Fatalf("release quantum-boundary reservation: %v", err)
			}
		}
	})

	t.Run("failure unknown and expiry retain conservative debit", func(t *testing.T) {
		unknownInput := fixture.outputTokenBucketInput(
			t, "output-token-unknown", 100, 1, tokenRateDecimalScale, 32,
		)
		unknownReservation, err := fixture.store.Reserve(fixture.ctx, unknownInput)
		if err != nil {
			t.Fatalf("reserve unknown output: %v", err)
		}
		unknownAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, unknownReservation)
		if err != nil || !owner {
			t.Fatalf("begin unknown output owner=%t: %v", owner, err)
		}
		unknownEntry := tokenEntry(t, unknownReservation)
		beforeUnknown := readBucket(t, unknownEntry.bucketID)
		unknownOutcome := Outcome{
			Status: AttemptSucceeded, HTTPStatus: 200,
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}
		if err := fixture.store.Settle(fixture.ctx, unknownAttempt, unknownOutcome); err != nil {
			t.Fatalf("settle unknown output: %v", err)
		}
		if afterUnknown := readBucket(t, unknownEntry.bucketID); afterUnknown != beforeUnknown {
			t.Fatalf("unknown output changed debit: before=%#v after=%#v", beforeUnknown, afterUnknown)
		}
		assertEntry(t, unknownReservation.ID(), 32, 32, 0)
		assertOutputUsage(t, fixture, unknownInput.LogicalRequestID.String(), unknownAttempt.ID(), 32, "unknown")

		failedInput := fixture.outputTokenBucketInput(
			t, "output-token-failed", 100, 1, tokenRateDecimalScale, 32,
		)
		failedReservation, err := fixture.store.Reserve(fixture.ctx, failedInput)
		if err != nil {
			t.Fatalf("reserve failed output: %v", err)
		}
		failedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, failedReservation)
		if err != nil || !owner {
			t.Fatalf("begin failed output owner=%t: %v", owner, err)
		}
		failedEntry := tokenEntry(t, failedReservation)
		beforeFailure := readBucket(t, failedEntry.bucketID)
		failedOutcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_protocol_error",
			Usage: Usage{
				InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
				Known: true, Provenance: ProviderReportedProvenance,
			},
		}
		if err := fixture.store.Settle(fixture.ctx, failedAttempt, failedOutcome); err != nil {
			t.Fatalf("settle failed output: %v", err)
		}
		if afterFailure := readBucket(t, failedEntry.bucketID); afterFailure != beforeFailure {
			t.Fatalf("failed output changed debit: before=%#v after=%#v", beforeFailure, afterFailure)
		}
		assertEntry(t, failedReservation.ID(), 32, 32, 0)
		assertOutputUsage(t, fixture, failedInput.LogicalRequestID.String(), failedAttempt.ID(), 7, "reported")

		failedUnknownInput := fixture.outputTokenBucketInput(
			t, "output-token-failed-unknown", 100, 1, tokenRateDecimalScale, 32,
		)
		failedUnknownReservation, err := fixture.store.Reserve(fixture.ctx, failedUnknownInput)
		if err != nil {
			t.Fatalf("reserve failed unknown output: %v", err)
		}
		failedUnknownAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, failedUnknownReservation)
		if err != nil || !owner {
			t.Fatalf("begin failed unknown output owner=%t: %v", owner, err)
		}
		failedUnknownEntry := tokenEntry(t, failedUnknownReservation)
		beforeFailedUnknown := readBucket(t, failedUnknownEntry.bucketID)
		failedUnknownOutcome := Outcome{
			Status: AttemptFailed, HTTPStatus: 502, FailureCode: "upstream_protocol_error",
			Usage: Usage{Provenance: UnknownUsageProvenance},
		}
		if err := fixture.store.Settle(fixture.ctx, failedUnknownAttempt, failedUnknownOutcome); err != nil {
			t.Fatalf("settle failed unknown output: %v", err)
		}
		if afterFailedUnknown := readBucket(t, failedUnknownEntry.bucketID); afterFailedUnknown != beforeFailedUnknown {
			t.Fatalf("failed unknown output changed debit: before=%#v after=%#v", beforeFailedUnknown, afterFailedUnknown)
		}
		assertEntry(t, failedUnknownReservation.ID(), 32, 32, 0)
		assertOutputUsage(t, fixture, failedUnknownInput.LogicalRequestID.String(), failedUnknownAttempt.ID(), 32, "unknown")

		dispatchedInput := fixture.outputTokenBucketInput(
			t, "output-token-expired-dispatched", 100, 1, tokenRateDecimalScale, 48,
		)
		dispatched, err := fixture.store.Reserve(fixture.ctx, dispatchedInput)
		if err != nil {
			t.Fatalf("reserve dispatched expiry: %v", err)
		}
		dispatchedAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, dispatched)
		if err != nil || !owner {
			t.Fatalf("begin dispatched expiry owner=%t: %v", owner, err)
		}
		undispatchedInput := fixture.outputTokenBucketInput(
			t, "output-token-expired-undispatched", 100, 1, tokenRateDecimalScale, 48,
		)
		undispatched, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
		if err != nil {
			t.Fatalf("reserve undispatched expiry: %v", err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_reservations
			SET created_at = statement_timestamp() - interval '2 hours',
			    expires_at = statement_timestamp() - interval '1 hour'
			WHERE quota_reservation_id = ANY($1::text[])
		`, []string{dispatched.ID(), undispatched.ID()}); err != nil {
			t.Fatalf("backdate output token expiries: %v", err)
		}
		beforeDispatched := readBucket(t, tokenEntry(t, dispatched).bucketID)
		beforeUndispatched := readBucket(t, tokenEntry(t, undispatched).bucketID)
		processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 2)
		if err != nil || processed != 2 {
			t.Fatalf("expire output token reservations=%d: %v", processed, err)
		}
		if afterDispatched := readBucket(t, tokenEntry(t, dispatched).bucketID); afterDispatched != beforeDispatched {
			t.Fatalf("dispatched expiry refunded debit: before=%#v after=%#v", beforeDispatched, afterDispatched)
		}
		afterUndispatched := readBucket(t, tokenEntry(t, undispatched).bucketID)
		if beforeUndispatched.balance != 52*tokenBalanceScale ||
			afterUndispatched.balance != 100*tokenBalanceScale ||
			afterUndispatched.used != 0 || afterUndispatched.reserved != 0 {
			t.Fatalf("undispatched expiry before=%#v after=%#v", beforeUndispatched, afterUndispatched)
		}
		assertEntry(t, dispatched.ID(), 48, 48, 0)
		assertEntry(t, undispatched.ID(), 48, 0, 48)
		assertOutputUsage(t, fixture, dispatchedInput.LogicalRequestID.String(), dispatchedAttempt.ID(), 48, "unknown")
		if got := fixture.count(t, `SELECT count(*) FROM usage_records WHERE logical_request_id = $1`, undispatchedInput.LogicalRequestID.String()); got != 0 {
			t.Fatalf("undispatched expiry usage rows=%d, want 0", got)
		}
	})

	t.Run("policy decrease bounds an old reservation refund", func(t *testing.T) {
		oldInput := fixture.outputTokenBucketInput(
			t, "output-token-policy", 100, 1, tokenRateDecimalScale, 64,
		)
		oldReservation, err := fixture.store.Reserve(fixture.ctx, oldInput)
		if err != nil {
			t.Fatalf("reserve old output policy: %v", err)
		}
		newInput := fixture.outputTokenBucketInput(
			t, "output-token-policy", 50, 2, 1, 1,
		)
		newReservation, err := fixture.store.Reserve(fixture.ctx, newInput)
		if err != nil {
			t.Fatalf("reserve decreased output policy: %v", err)
		}
		entry := tokenEntry(t, oldReservation)
		transitioned := readBucket(t, entry.bucketID)
		if transitioned.capacity != 50 || transitioned.numerator != 2 || transitioned.denominator != 1 ||
			transitioned.balance >= 36*tokenBalanceScale || transitioned.used != 0 || transitioned.reserved != 0 {
			t.Fatalf("decreased output policy state=%#v", transitioned)
		}
		oldAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, oldReservation)
		if err != nil || !owner {
			t.Fatalf("begin old output reservation owner=%t: %v", owner, err)
		}
		outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
			InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
			Known: true, Provenance: ProviderReportedProvenance,
		}}
		if err := fixture.store.Settle(fixture.ctx, oldAttempt, outcome); err != nil {
			t.Fatalf("settle old output reservation: %v", err)
		}
		refunded := readBucket(t, entry.bucketID)
		if refunded.capacity != 50 || refunded.balance != 50*tokenBalanceScale ||
			refunded.numerator != 2 || refunded.denominator != 1 ||
			refunded.refilledAt.Before(transitioned.refilledAt) || refunded.used != 0 || refunded.reserved != 0 {
			t.Fatalf("old reservation refund=%#v transitioned=%#v", refunded, transitioned)
		}
		assertEntry(t, oldReservation.ID(), 64, 7, 57)
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, newReservation, "policy_test_done"); err != nil {
			t.Fatalf("release new-policy reservation: %v", err)
		}
	})

	t.Run("mixed rules deny atomically in either direction", func(t *testing.T) {
		calendarHolderInput := fixture.input(t, "output-token-calendar-denial", 1)
		calendarHolder, err := fixture.store.Reserve(fixture.ctx, calendarHolderInput)
		if err != nil {
			t.Fatalf("reserve calendar holder: %v", err)
		}
		calendarDenied := fixture.outputTokenBucketInput(
			t, "output-token-calendar-denial", 100, 1, tokenRateDecimalScale, 64,
		)
		calendarDenied.Rules = append(calendarDenied.Rules, calendarHolderInput.Rules[0])
		if _, err := fixture.store.Reserve(fixture.ctx, calendarDenied); !errors.Is(err, ErrExceeded) {
			t.Fatalf("calendar-first mixed denial=%v", err)
		}
		calendarDeniedScope := mustPreparedTokenScopeKey(t, calendarDenied)
		var calendarDeniedTokenID string
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT quota_bucket_id FROM quota_buckets
			WHERE environment_id = $1 AND limit_plan_key = $2
			  AND metric = 'output_tokens' AND algorithm = 'token_bucket'
			  AND scope_key = $3
		`, calendarDenied.EnvironmentID, calendarDenied.LimitPlanKey, calendarDeniedScope).Scan(&calendarDeniedTokenID); err != nil {
			t.Fatalf("find calendar-denied token bucket: %v", err)
		}
		if state := readBucket(t, calendarDeniedTokenID); state.balance != 100*tokenBalanceScale ||
			state.used != 0 || state.reserved != 0 {
			t.Fatalf("calendar denial debited output token=%#v", state)
		}

		tokenHolderInput := fixture.outputTokenBucketInput(
			t, "output-token-token-denial", 100, 1, tokenRateDecimalScale, 80,
		)
		tokenHolder, err := fixture.store.Reserve(fixture.ctx, tokenHolderInput)
		if err != nil {
			t.Fatalf("reserve token holder: %v", err)
		}
		tokenEntryValue := tokenEntry(t, tokenHolder)
		beforeDenial := readBucket(t, tokenEntryValue.bucketID)
		tokenDenied := fixture.outputTokenBucketInput(
			t, "output-token-token-denial", 100, 1, tokenRateDecimalScale, 30,
		)
		tokenDenied.Rules = append(tokenDenied.Rules, Rule{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: 10, Hard: true,
		})
		if _, err := fixture.store.Reserve(fixture.ctx, tokenDenied); !errors.Is(err, ErrExceeded) {
			t.Fatalf("token-first mixed denial=%v", err)
		}
		afterDenial := readBucket(t, tokenEntryValue.bucketID)
		credit, err := tokenCreditPerTick(afterDenial.numerator, afterDenial.denominator)
		if err != nil {
			t.Fatalf("token-denial credit: %v", err)
		}
		expectedBalance, expectedCursor, err := refillTokenBalance(
			beforeDenial.balance, beforeDenial.capacity*tokenBalanceScale, credit,
			beforeDenial.refilledAt, afterDenial.refilledAt,
		)
		if err != nil || afterDenial.balance != expectedBalance ||
			!afterDenial.refilledAt.Equal(expectedCursor) || afterDenial.used != 0 || afterDenial.reserved != 0 {
			t.Fatalf("token denial state before=%#v after=%#v expected=%d/%v: %v",
				beforeDenial, afterDenial, expectedBalance, expectedCursor, err)
		}
		var calendarUsed, calendarReserved int64
		if err := fixture.pool.QueryRow(fixture.ctx, `
			SELECT used_units, reserved_units FROM quota_buckets
			WHERE environment_id = $1 AND limit_plan_key = $2
			  AND metric = 'logical_requests' AND algorithm = 'calendar'
			  AND scope_key = $3
		`, tokenDenied.EnvironmentID, tokenDenied.LimitPlanKey, mustPreparedScopeKey(t, tokenDenied)).Scan(
			&calendarUsed, &calendarReserved,
		); err != nil {
			t.Fatalf("read token-denied calendar bucket: %v", err)
		}
		if calendarUsed != 0 || calendarReserved != 0 {
			t.Fatalf("token denial partially reserved calendar=%d/%d", calendarUsed, calendarReserved)
		}
		for _, reservation := range []Reservation{calendarHolder, tokenHolder} {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "mixed_test_done"); err != nil {
				t.Fatalf("release mixed holder: %v", err)
			}
		}
	})

	t.Run("contention admits only whole variable reservations", func(t *testing.T) {
		const callers = 12
		inputs := make([]ReserveInput, callers)
		for index := range inputs {
			inputs[index] = fixture.outputTokenBucketInput(
				t, "output-token-contention", 100, 1, tokenRateDecimalScale, 17,
			)
		}
		type result struct {
			reservation Reservation
			err         error
		}
		start := make(chan struct{})
		results := make(chan result, callers)
		for index := range inputs {
			go func(input ReserveInput) {
				<-start
				reservation, err := fixture.store.Reserve(fixture.ctx, input)
				results <- result{reservation: reservation, err: err}
			}(inputs[index])
		}
		close(start)
		accepted := make([]Reservation, 0, 5)
		denied := 0
		for range callers {
			result := <-results
			if result.err == nil {
				accepted = append(accepted, result.reservation)
			} else if errors.Is(result.err, ErrExceeded) {
				denied++
			} else {
				t.Fatalf("contended output token reserve: %v", result.err)
			}
		}
		if len(accepted) != 5 || denied != callers-5 {
			t.Fatalf("output token contention accepted=%d denied=%d", len(accepted), denied)
		}
		state := readBucket(t, tokenEntry(t, accepted[0]).bucketID)
		if state.balance < 15*tokenBalanceScale || state.balance >= 16*tokenBalanceScale ||
			state.used != 0 || state.reserved != 0 {
			t.Fatalf("contended output token state=%#v", state)
		}
		for _, reservation := range accepted {
			if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "contention_done"); err != nil {
				t.Fatalf("release contended output tokens: %v", err)
			}
		}
		if state := readBucket(t, tokenEntry(t, accepted[0]).bucketID); state.balance != 100*tokenBalanceScale ||
			state.used != 0 || state.reserved != 0 {
			t.Fatalf("released contention state=%#v", state)
		}
	})

	t.Run("maximum cost has an exact huge retry horizon", func(t *testing.T) {
		invalid := fixture.outputTokenBucketInput(
			t, "output-token-cost-over-cap", 100, 1, tokenRateDecimalScale, 101,
		)
		_, err := fixture.store.Reserve(fixture.ctx, invalid)
		var impossible *ExceededError
		if !errors.As(err, &impossible) || impossible.Maximum() != 100 ||
			!impossible.RetryAt().IsZero() {
			t.Fatalf("over-cap output denial=%#v: %v", impossible, err)
		}
		if got := fixture.count(t, `
			SELECT count(*) FROM logical_requests
			WHERE logical_request_id = $1 AND status = 'denied'
			  AND failure_code = 'quota_exceeded'
		`, invalid.LogicalRequestID.String()); got != 1 {
			t.Fatalf("over-cap output durable denial rows=%d", got)
		}
		if _, replayErr := fixture.store.Reserve(fixture.ctx, invalid); !errors.As(replayErr, &impossible) ||
			!impossible.RetryAt().IsZero() {
			t.Fatalf("over-cap output denial replay=%#v: %v", impossible, replayErr)
		}

		input := fixture.outputTokenBucketInput(
			t, "output-token-huge-retry", maximumTokenCapacity,
			1, tokenRateDecimalScale, maximumTokenCapacity,
		)
		holder, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve maximum output cost: %v", err)
		}
		entry := tokenEntry(t, holder)
		if state := readBucket(t, entry.bucketID); state.balance != 0 || state.used != 0 || state.reserved != 0 {
			t.Fatalf("maximum output debit=%#v", state)
		}
		deniedInput := fixture.outputTokenBucketInput(
			t, "output-token-huge-retry", maximumTokenCapacity,
			1, tokenRateDecimalScale, maximumTokenCapacity,
		)
		_, err = fixture.store.Reserve(fixture.ctx, deniedInput)
		var denial *ExceededError
		if !errors.As(err, &denial) || denial.RetryAt().Year() < 294_000 {
			t.Fatalf("huge output denial=%#v: %v", denial, err)
		}
		deniedState := readBucket(t, entry.bucketID)
		expected, expectedErr := tokenRetryAt(tokenBucketState{
			capacity: deniedState.capacity, balance: deniedState.balance,
			numerator: deniedState.numerator, denominator: deniedState.denominator,
			refilledAt: deniedState.refilledAt,
		}, maximumTokenCapacity, deniedState.refilledAt)
		if expectedErr != nil || !denial.RetryAt().Equal(expected) {
			t.Fatalf("huge output retry=%v want=%v: %v", denial.RetryAt(), expected, expectedErr)
		}
		_, replayErr := fixture.store.Reserve(fixture.ctx, deniedInput)
		var replayDenial *ExceededError
		if !errors.As(replayErr, &replayDenial) || !replayDenial.RetryAt().Equal(denial.RetryAt()) {
			t.Fatalf("huge denied replay=%#v: %v", replayDenial, replayErr)
		}
		if replayedState := readBucket(t, entry.bucketID); replayedState != deniedState {
			t.Fatalf("huge denied replay mutated state: before=%#v after=%#v", deniedState, replayedState)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, holder, "huge_test_done"); err != nil {
			t.Fatalf("release maximum output cost: %v", err)
		}
	})

	t.Run("settlement and expiry serialize one token refund", func(t *testing.T) {
		for iteration := range 4 {
			input := fixture.outputTokenBucketInput(
				t, fmt.Sprintf("output-token-race-%d", iteration),
				100, 1, tokenRateDecimalScale, 64,
			)
			reservation, err := fixture.store.Reserve(fixture.ctx, input)
			if err != nil {
				t.Fatalf("iteration %d reserve: %v", iteration, err)
			}
			attempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
			if err != nil || !owner {
				t.Fatalf("iteration %d begin owner=%t: %v", iteration, owner, err)
			}
			if _, err := fixture.pool.Exec(fixture.ctx, `
				UPDATE quota_reservations
				SET created_at = statement_timestamp() - interval '2 hours',
				    expires_at = statement_timestamp() - interval '1 hour'
				WHERE quota_reservation_id = $1
			`, reservation.ID()); err != nil {
				t.Fatalf("iteration %d backdate: %v", iteration, err)
			}
			entry := tokenEntry(t, reservation)
			before := readBucket(t, entry.bucketID)
			outcome := Outcome{Status: AttemptSucceeded, HTTPStatus: 200, Usage: Usage{
				InputTokens: 11, OutputTokens: 7, TotalTokens: 18,
				Known: true, Provenance: ProviderReportedProvenance,
			}}
			start := make(chan struct{})
			settlement := make(chan error, 1)
			expiry := make(chan struct {
				processed int64
				err       error
			}, 1)
			go func() {
				<-start
				settlement <- fixture.store.Settle(fixture.ctx, attempt, outcome)
			}()
			go func() {
				<-start
				processed, expiryErr := fixture.store.ExpirePendingBatch(fixture.ctx, 1)
				expiry <- struct {
					processed int64
					err       error
				}{processed: processed, err: expiryErr}
			}()
			close(start)
			settleErr := <-settlement
			expiryResult := <-expiry
			settleWon := settleErr == nil && expiryResult.err == nil && expiryResult.processed == 0
			expiryWon := errors.Is(settleErr, ErrFinalized) && expiryResult.err == nil && expiryResult.processed == 1
			if !settleWon && !expiryWon {
				t.Fatalf("iteration %d settle=%v expiry=%d/%v", iteration, settleErr, expiryResult.processed, expiryResult.err)
			}
			after := readBucket(t, entry.bucketID)
			if settleWon {
				if after.balance != before.balance+57*tokenBalanceScale ||
					after.version != before.version+1 || !after.refilledAt.Equal(before.refilledAt) {
					t.Fatalf("iteration %d settled race before=%#v after=%#v", iteration, before, after)
				}
				assertEntry(t, reservation.ID(), 64, 7, 57)
				assertOutputUsage(t, fixture, input.LogicalRequestID.String(), attempt.ID(), 7, "reported")
			} else {
				if after != before {
					t.Fatalf("iteration %d expired race changed debit: before=%#v after=%#v", iteration, before, after)
				}
				assertEntry(t, reservation.ID(), 64, 64, 0)
				assertOutputUsage(t, fixture, input.LogicalRequestID.String(), attempt.ID(), 64, "unknown")
			}
		}
	})

	t.Run("corrupt output token state fails closed", func(t *testing.T) {
		input := fixture.outputTokenBucketInput(
			t, "output-token-corrupt", 100, 1, tokenRateDecimalScale, 1,
		)
		reservation, err := fixture.store.Reserve(fixture.ctx, input)
		if err != nil {
			t.Fatalf("reserve output token for corruption: %v", err)
		}
		if err := fixture.store.ReleaseBeforeDispatch(fixture.ctx, reservation, "corrupt_test_setup"); err != nil {
			t.Fatalf("release output token for corruption: %v", err)
		}
		entry := tokenEntry(t, reservation)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			UPDATE quota_buckets SET used_units = 1 WHERE quota_bucket_id = $1
		`, entry.bucketID); err != nil {
			t.Fatalf("corrupt output token counters: %v", err)
		}
		other := fixture.outputTokenBucketInput(
			t, "output-token-corrupt", 100, 1, tokenRateDecimalScale, 1,
		)
		if _, err := fixture.store.Reserve(fixture.ctx, other); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("reserve corrupt output token=%v", err)
		}
	})
}

func TestStorePostgreSQLExpiryLanesPartitionConcurrencyAcrossReplicas(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	second, err := NewStore(StoreConfig{Pool: fixture.pool, ReservationTTL: time.Hour})
	if err != nil {
		t.Fatalf("construct second quota replica: %v", err)
	}

	const concurrencyReservations = 6
	concurrencyIDs := make([]string, 0, concurrencyReservations)
	allIDs := make([]string, 0, concurrencyReservations+2)
	for index := range concurrencyReservations {
		input := fixture.concurrencyInput(t, "concurrency-expiry-lane", 20, 0, false, false)
		reservation, reserveErr := fixture.store.Reserve(fixture.ctx, input)
		if reserveErr != nil {
			t.Fatalf("reserve concurrency fixture %d: %v", index, reserveErr)
		}
		if index%2 == 0 {
			if _, owner, beginErr := fixture.store.BeginAttempt(fixture.ctx, reservation); beginErr != nil || !owner {
				t.Fatalf("dispatch concurrency fixture %d owner=%t err=%v", index, owner, beginErr)
			}
		}
		concurrencyIDs = append(concurrencyIDs, reservation.ID())
		allIDs = append(allIDs, reservation.ID())
	}
	undispatchedInput := fixture.input(t, "calendar-undispatched-expiry-lane", 5)
	undispatched, err := fixture.store.Reserve(fixture.ctx, undispatchedInput)
	if err != nil {
		t.Fatalf("reserve non-concurrency undispatched fixture: %v", err)
	}
	dispatchedInput := fixture.input(t, "calendar-dispatched-expiry-lane", 5)
	dispatched, err := fixture.store.Reserve(fixture.ctx, dispatchedInput)
	if err != nil {
		t.Fatalf("reserve non-concurrency dispatched fixture: %v", err)
	}
	if _, owner, beginErr := fixture.store.BeginAttempt(fixture.ctx, dispatched); beginErr != nil || !owner {
		t.Fatalf("dispatch non-concurrency fixture owner=%t err=%v", owner, beginErr)
	}
	allIDs = append(allIDs, undispatched.ID(), dispatched.ID())
	backdateConcurrencyReservations(t, fixture, concurrencyIDs...)
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = ANY($1::text[])
	`, []string{undispatched.ID(), dispatched.ID()}); err != nil {
		t.Fatalf("backdate non-concurrency reservations: %v", err)
	}

	type laneResult struct {
		lane      string
		processed int64
		err       error
	}
	start := make(chan struct{})
	results := make(chan laneResult, 4)
	run := func(lane string, operation func(context.Context, int) (int64, error)) {
		<-start
		processed, operationErr := operation(fixture.ctx, 20)
		results <- laneResult{lane: lane, processed: processed, err: operationErr}
	}
	go run("undispatched", fixture.store.ReleaseExpiredUndispatchedBatch)
	go run("reconcile", second.ReconcilePendingUsageBatch)
	go run("concurrency", fixture.store.ReleaseExpiredConcurrencyLeasesBatch)
	go run("concurrency", second.ReleaseExpiredConcurrencyLeasesBatch)
	close(start)
	totals := map[string]int64{}
	for range 4 {
		result := <-results
		if result.err != nil {
			t.Fatalf("%s expiry lane: %v", result.lane, result.err)
		}
		totals[result.lane] += result.processed
	}
	if totals["undispatched"] != 1 || totals["reconcile"] != 1 ||
		totals["concurrency"] != concurrencyReservations {
		t.Fatalf("expiry lane totals=%v, want undispatched=1 reconcile=1 concurrency=%d",
			totals, concurrencyReservations)
	}
	for lane, operation := range map[string]func(context.Context, int) (int64, error){
		"undispatched": fixture.store.ReleaseExpiredUndispatchedBatch,
		"reconcile":    fixture.store.ReconcilePendingUsageBatch,
		"concurrency":  fixture.store.ReleaseExpiredConcurrencyLeasesBatch,
	} {
		processed, replayErr := operation(fixture.ctx, 20)
		if replayErr != nil || processed != 0 {
			t.Fatalf("%s replay processed=%d err=%v, want 0 nil", lane, processed, replayErr)
		}
	}
	var pendingReservations, activeLeases, outstandingConcurrencyEntries int
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT
		  count(*) FILTER (WHERE reservation.status = 'pending'),
		  count(*) FILTER (
		    WHERE lease.concurrency_lease_id IS NOT NULL AND lease.released_at IS NULL
		  ),
		  count(*) FILTER (
		    WHERE bucket.algorithm = 'concurrency'
		      AND (entry.settled_units <> 0 OR entry.released_units <> entry.reserved_units)
		  )
		FROM quota_reservations AS reservation
		JOIN quota_reservation_entries AS entry USING (quota_reservation_id)
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		LEFT JOIN concurrency_leases AS lease
		  ON lease.logical_request_id = reservation.logical_request_id
		 AND lease.quota_bucket_id = bucket.quota_bucket_id
		WHERE reservation.quota_reservation_id = ANY($1::text[])
	`, allIDs).Scan(&pendingReservations, &activeLeases, &outstandingConcurrencyEntries); err != nil {
		t.Fatalf("inspect partitioned expiry state: %v", err)
	}
	if pendingReservations != 0 || activeLeases != 0 || outstandingConcurrencyEntries != 0 {
		t.Fatalf("partitioned expiry state pending=%d active_leases=%d outstanding_concurrency=%d",
			pendingReservations, activeLeases, outstandingConcurrencyEntries)
	}
	var concurrencyBucketReserved int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT reserved_units FROM quota_buckets
		WHERE environment_id = $1 AND limit_plan_key = 'concurrency-expiry-lane'
		  AND metric = 'concurrent_requests'
	`, quotaTestEnvironmentID).Scan(&concurrencyBucketReserved); err != nil {
		t.Fatalf("read recovered concurrency bucket: %v", err)
	}
	if concurrencyBucketReserved != 0 {
		t.Fatalf("recovered concurrency reserved units=%d, want 0", concurrencyBucketReserved)
	}
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

func (fixture quotaPostgreSQLFixture) tokenBucketInput(
	t *testing.T,
	feature string,
	capacity int64,
	numerator int64,
	denominator int64,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, 1)
	input.Rules = []Rule{{
		Metric: LogicalRequestsMetric, Algorithm: TokenBucketAlgorithm,
		Scope: []string{"user", "feature"}, Capacity: capacity,
		RefillNumerator: numerator, RefillDenominator: denominator, Hard: true,
	}}
	return input
}

func (fixture quotaPostgreSQLFixture) outputTokenBucketInput(
	t *testing.T,
	feature string,
	capacity int64,
	numerator int64,
	denominator int64,
	reservedUnits int64,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, 1)
	input.Rules = []Rule{{
		Metric: OutputTokensMetric, Algorithm: TokenBucketAlgorithm,
		Scope: []string{"user", "feature"}, Capacity: capacity,
		RefillNumerator: numerator, RefillDenominator: denominator,
		ReservedUnits: reservedUnits, Hard: true,
	}}
	return input
}

func (fixture quotaPostgreSQLFixture) pricedInput(
	t *testing.T,
	feature string,
	maximum int64,
	catalogID string,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, maximum)
	input.Pricing = PricingSelection{CatalogID: catalogID, Currency: USDCurrency}
	return input
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

func (fixture quotaPostgreSQLFixture) concurrencyInput(
	t *testing.T,
	plan string,
	requestMaximum int64,
	streamMaximum int64,
	streaming bool,
	includeStreamRule bool,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, plan, 1)
	input.LimitPlanKey = plan
	input.Streaming = streaming
	input.Rules = []Rule{{
		Metric: ConcurrentRequestsMetric, Algorithm: ConcurrencyAlgorithm,
		Scope: []string{"user"}, Maximum: requestMaximum, Hard: true,
	}}
	if includeStreamRule {
		input.Rules = append(input.Rules, Rule{
			Metric: ConcurrentStreamsMetric, Algorithm: ConcurrencyAlgorithm,
			Scope: []string{"user"}, Maximum: streamMaximum, Hard: true,
		})
	}
	return input
}

func assertConcurrencyEntryState(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationID string,
	metric string,
	wantReserved int64,
	wantSettled int64,
	wantReleased int64,
	wantBucketUsed int64,
	wantBucketReserved int64,
	wantLeaseReleased bool,
) {
	t.Helper()
	var reserved, settled, released, bucketUsed, bucketReserved int64
	var algorithm, windowKey string
	var leaseReleased bool
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT entry.reserved_units, entry.settled_units, entry.released_units,
		       bucket.used_units, bucket.reserved_units, bucket.algorithm,
		       bucket.window_key, lease.released_at IS NOT NULL
		FROM quota_reservation_entries AS entry
		JOIN quota_buckets AS bucket USING (quota_bucket_id)
		JOIN quota_reservations AS reservation USING (quota_reservation_id)
		JOIN concurrency_leases AS lease
		  ON lease.quota_bucket_id = bucket.quota_bucket_id
		 AND lease.logical_request_id = reservation.logical_request_id
		WHERE entry.quota_reservation_id = $1 AND bucket.metric = $2
	`, reservationID, metric).Scan(
		&reserved, &settled, &released, &bucketUsed, &bucketReserved,
		&algorithm, &windowKey, &leaseReleased,
	); err != nil {
		t.Fatalf("read %s concurrency state: %v", metric, err)
	}
	if reserved != wantReserved || settled != wantSettled || released != wantReleased ||
		bucketUsed != wantBucketUsed || bucketReserved != wantBucketReserved ||
		algorithm != ConcurrencyAlgorithm || windowKey != "active" ||
		leaseReleased != wantLeaseReleased {
		t.Fatalf(
			"%s state entry=%d/%d/%d bucket=%d/%d algorithm=%s window=%s released=%t, want %d/%d/%d %d/%d concurrency/active released=%t",
			metric, reserved, settled, released, bucketUsed, bucketReserved,
			algorithm, windowKey, leaseReleased, wantReserved, wantSettled,
			wantReleased, wantBucketUsed, wantBucketReserved, wantLeaseReleased,
		)
	}
}

func backdateConcurrencyReservations(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	reservationIDs ...string,
) {
	t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = statement_timestamp() - interval '2 hours',
		    expires_at = statement_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = ANY($1::text[])
	`, reservationIDs); err != nil {
		t.Fatalf("backdate concurrency reservations: %v", err)
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE concurrency_leases AS lease
		SET acquired_at = reservation.created_at,
		    expires_at = reservation.expires_at
		FROM quota_reservations AS reservation
		WHERE lease.logical_request_id = reservation.logical_request_id
		  AND reservation.quota_reservation_id = ANY($1::text[])
	`, reservationIDs); err != nil {
		t.Fatalf("backdate concurrency leases: %v", err)
	}
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

func assertAttemptPricing(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	attemptID string,
	wantBilled *int64,
	wantConfidence string,
	wantSource string,
) {
	t.Helper()
	var billed *int64
	var currency, revision, source, confidence *string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT billed_cost_nano_usd, currency, price_revision,
		       pricing_source, cost_confidence
		FROM upstream_attempts
		WHERE upstream_attempt_id = $1
	`, attemptID).Scan(&billed, &currency, &revision, &source, &confidence); err != nil {
		t.Fatalf("read attempt pricing: %v", err)
	}
	if !optionalInt64Matches(billed, wantBilled) || currency == nil || *currency != USDCurrency ||
		revision == nil || *revision != quotaTestConfigRevisionID ||
		source == nil || *source != wantSource || confidence == nil || *confidence != wantConfidence {
		t.Fatalf("attempt pricing billed=%v currency=%v revision=%v source=%v confidence=%v",
			billed, currency, revision, source, confidence)
	}
}

func assertAttemptUnpriced(t *testing.T, fixture quotaPostgreSQLFixture, attemptID string) {
	t.Helper()
	if got := fixture.count(t, `
		SELECT count(*) FROM upstream_attempts
		WHERE upstream_attempt_id = $1
		  AND billed_cost_nano_usd IS NULL AND currency IS NULL
		  AND price_revision IS NULL AND pricing_source IS NULL
		  AND cost_confidence IS NULL
	`, attemptID); got != 1 {
		t.Fatalf("unpriced attempt with null price fields = %d, want 1", got)
	}
	if got := fixture.count(t, `
		SELECT count(*) FROM usage_records AS usage
		JOIN upstream_attempts AS attempt USING (logical_request_id)
		WHERE attempt.upstream_attempt_id = $1 AND usage.metric = 'cost_nano_usd'
	`, attemptID); got != 0 {
		t.Fatalf("unpriced cost usage rows = %d, want 0", got)
	}
}

func assertConfiguredCostUsage(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	logicalRequestID string,
	attemptID string,
	wantAmount int64,
	wantSource string,
) {
	t.Helper()
	var units, cost int64
	var currency, revision, source, confidence, provenance, storedAttemptID string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT units, cost_nano_usd, currency, price_revision, pricing_source,
		       confidence, provenance_key, upstream_attempt_id
		FROM usage_records
		WHERE logical_request_id = $1 AND metric = 'cost_nano_usd'
	`, logicalRequestID).Scan(
		&units, &cost, &currency, &revision, &source,
		&confidence, &provenance, &storedAttemptID,
	); err != nil {
		t.Fatalf("read configured cost usage: %v", err)
	}
	if units != wantAmount || cost != wantAmount || currency != USDCurrency ||
		revision != quotaTestConfigRevisionID || source != wantSource ||
		confidence != CalculatedCostConfidence ||
		provenance != configuredCostProvenanceKey(attemptID) || storedAttemptID != attemptID {
		t.Fatalf("configured cost usage=%d/%d/%s/%s/%s/%s/%s/%s",
			units, cost, currency, revision, source, confidence, provenance, storedAttemptID)
	}
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

func mustPreparedTokenScopeKey(t *testing.T, input ReserveInput) string {
	t.Helper()
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare token quota input: %v", err)
	}
	for _, rule := range prepared.rules {
		if rule.Algorithm == TokenBucketAlgorithm {
			return rule.scopeKey
		}
	}
	t.Fatal("prepared quota input has no token-bucket rule")
	return ""
}

func mustNewID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
