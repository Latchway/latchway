package quota

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/latchway/latchway/internal/limitscope"
)

func TestStorePostgreSQLRequestMeasurementRetryReplayAndRecovery(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	beforeBuckets := fixture.count(t, `SELECT count(*) FROM quota_buckets`)

	input := fixtureRequestMeasurementInput(t, fixture, "measurement-retry", 500, 5, 5, 321, 2, 3)
	reservation, err := fixture.store.Reserve(fixture.ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if after := fixture.count(t, `SELECT count(*) FROM quota_buckets`); after != beforeBuckets {
		t.Fatalf("per-request rules materialized %d durable buckets", after-beforeBuckets)
	}
	first, owner, err := fixture.store.BeginAttempt(fixture.ctx, reservation)
	if err != nil || !owner {
		t.Fatalf("begin exact-measurement attempt owner=%t: %v", owner, err)
	}
	assertStoredRequestMeasurement(t, fixture, first.ID(), input.RequestMeasurements)
	for name, statement := range map[string]string{
		"image count": `UPDATE upstream_attempts SET measured_image_units = 1000001 WHERE upstream_attempt_id = $1`,
		"tool count":  `UPDATE upstream_attempts SET measured_tool_calls = 1000001 WHERE upstream_attempt_id = $1`,
	} {
		if _, err := fixture.pool.Exec(fixture.ctx, statement, first.ID()); err == nil {
			t.Errorf("database accepted out-of-bound %s", name)
		}
	}
	if replay, replayOwner, replayErr := fixture.store.BeginAttempt(fixture.ctx, reservation); replayErr != nil || replayOwner || replay.ID() != first.ID() {
		t.Fatalf("initial measurement replay=%+v owner=%t err=%v", replay, replayOwner, replayErr)
	}
	changedReserve := cloneReserveInput(input)
	changedReserve.RequestMeasurements.RewrittenBodySHA256 = sha256.Sum256([]byte("same units, changed exact body"))
	if _, err := fixture.store.Reserve(fixture.ctx, changedReserve); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("changed reservation measurement replay = %v, want ErrInvalidInput", err)
	}
	failed := Outcome{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "provider_busy"}
	if err := fixture.store.SettleForRetry(fixture.ctx, first, failed); err != nil {
		t.Fatal(err)
	}

	retryMeasurement := &RequestMeasurementBinding{
		Protocol: "openai_chat", RewrittenBodySHA256: sha256.Sum256([]byte("exact retry body")),
		RequestBytes: 111, ImageUnits: 1, ToolCalls: 4,
		ImageUnitsKnown: true, ToolCallsKnown: true,
	}
	retry := RetryAttemptInput{
		RouteKey: "secondary", UpstreamKey: "backup", ModelKey: "slow",
		PhysicalModel: "provider/model-v2", RequestMeasurements: retryMeasurement,
		Allocations: []AttemptAllocation{
			{Metric: RequestBytesMetric, Units: 111},
			{Metric: ImageUnitsMetric, Units: 1},
			{Metric: ToolCallsMetric, Units: 4},
		},
	}
	second, owner, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, retry)
	if err != nil || !owner {
		t.Fatalf("begin exact-measurement retry owner=%t: %v", owner, err)
	}
	assertStoredRequestMeasurement(t, fixture, second.ID(), retryMeasurement)
	if replay, replayOwner, replayErr := fixture.store.BeginRetryAttempt(fixture.ctx, first, retry); replayErr != nil || replayOwner || replay.ID() != second.ID() {
		t.Fatalf("retry measurement replay=%+v owner=%t err=%v", replay, replayOwner, replayErr)
	}
	changedRetry := retry
	changedBinding := *retryMeasurement
	changedBinding.RewrittenBodySHA256 = sha256.Sum256([]byte("different same-unit retry body"))
	changedRetry.RequestMeasurements = &changedBinding
	if _, _, err := fixture.store.BeginRetryAttempt(fixture.ctx, first, changedRetry); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("changed retry measurement replay = %v, want ErrInvalidState", err)
	}
	if err := fixture.store.SettleFinalAttempt(fixture.ctx, second, failed); err != nil {
		t.Fatal(err)
	}
	if got := fixture.count(t, `SELECT count(*) FROM upstream_attempt_quota_entries WHERE logical_request_id = $1`, input.LogicalRequestID.String()); got != 0 {
		t.Fatalf("request-local attempts created %d stateful ledger rows", got)
	}

	over := fixtureRequestMeasurementInput(t, fixture, "measurement-over", 500, 1, 5, 321, 2, 3)
	over.Rules = append(over.Rules, Rule{
		Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
		Scope:  []string{"user", "platform", "normalized_claim:region"},
		Window: "1d", Maximum: 1, Hard: true,
	})
	if _, err := fixture.store.Reserve(fixture.ctx, over); !errors.Is(err, ErrExceeded) {
		t.Fatalf("atomic image guard denial = %v", err)
	}
	if got := fixture.count(t, `SELECT count(*) FROM upstream_attempts WHERE logical_request_id = $1`, over.LogicalRequestID.String()); got != 0 {
		t.Fatalf("over-bound request created %d attempts", got)
	}
	if after := fixture.count(t, `SELECT count(*) FROM quota_buckets`); after != beforeBuckets {
		t.Fatalf("over-bound request changed durable bucket count from %d to %d", beforeBuckets, after)
	}

	recoveryInput := fixtureRequestMeasurementInput(t, fixture, "measurement-recovery", 500, 5, 5, 73, 0, 0)
	recoveryReservation, err := fixture.store.Reserve(fixture.ctx, recoveryInput)
	if err != nil {
		t.Fatal(err)
	}
	recoveryAttempt, owner, err := fixture.store.BeginAttempt(fixture.ctx, recoveryReservation)
	if err != nil || !owner {
		t.Fatalf("begin recovery measurement owner=%t: %v", owner, err)
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE quota_reservations
		SET created_at = transaction_timestamp() - interval '2 hours',
		    expires_at = transaction_timestamp() - interval '1 hour'
		WHERE quota_reservation_id = $1
	`, recoveryReservation.ID()); err != nil {
		t.Fatal(err)
	}
	processed, err := fixture.store.ExpirePendingBatch(fixture.ctx, 10)
	if err != nil || processed != 1 {
		t.Fatalf("recover measurement reservation processed=%d err=%v", processed, err)
	}
	if processed, err = fixture.store.ExpirePendingBatch(fixture.ctx, 10); err != nil || processed != 0 {
		t.Fatalf("recovery replay processed=%d err=%v", processed, err)
	}
	assertStoredRequestMeasurement(t, fixture, recoveryAttempt.ID(), recoveryInput.RequestMeasurements)
	var status string
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT status FROM upstream_attempts WHERE upstream_attempt_id = $1`, recoveryAttempt.ID()).Scan(&status); err != nil || status != AttemptTimedOut {
		t.Fatalf("recovered measurement attempt status=%q err=%v", status, err)
	}
}

func TestStorePostgreSQLCanonicalScopeConstraintAndMissingClaimSnapshot(t *testing.T) {
	fixture := newQuotaPostgreSQLFixture(t)
	activateQuotaSnapshotRevision(t, fixture)

	presentDigest, ok := limitscope.ClaimDigest("region", "private-eu-value", true)
	if !ok {
		t.Fatal("derive present claim digest")
	}
	present := fixture.input(t, "claim-snapshot", 5)
	present.LimitPlanKey = "claim-plan"
	present.Platform = "ios"
	present.NormalizedClaimDigests = map[string]string{"region": presentDigest}
	present.Rules[0].Scope = []string{"normalized_claim:region", "platform", "user"}
	presentReservation, err := fixture.store.Reserve(fixture.ctx, present)
	if err != nil {
		t.Fatal(err)
	}
	bucketID := onlyReservationEntry(t, presentReservation).bucketID
	var dimensions []string
	var scopeKey string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT scope_dimensions, scope_key FROM quota_buckets WHERE quota_bucket_id = $1
	`, bucketID).Scan(&dimensions, &scopeKey); err != nil {
		t.Fatal(err)
	}
	wantDimensions := []string{"user", "platform", "normalized_claim:region"}
	if !slicesEqual(dimensions, wantDimensions) || len(scopeKey) != 43 ||
		bytes.Contains([]byte(scopeKey), []byte("private-eu-value")) {
		t.Fatalf("persisted sealed scope dimensions=%#v key=%q", dimensions, scopeKey)
	}

	for name, invalid := range map[string][]string{
		"out of order":   {"platform", "user"},
		"duplicate":      {"user", "user"},
		"claim not last": {"normalized_claim:region", "platform"},
		"two claims":     {"normalized_claim:region", "normalized_claim:tier"},
	} {
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE quota_buckets SET scope_dimensions = $2 WHERE quota_bucket_id = $1`, bucketID, invalid); err == nil {
			t.Errorf("database accepted %s scope %#v", name, invalid)
		}
	}
	for name, expression := range map[string]string{
		"null":            `ARRAY['user', NULL]::text[]`,
		"two dimensional": `ARRAY[['user', 'platform']]::text[]`,
	} {
		if _, err := fixture.pool.Exec(fixture.ctx, `UPDATE quota_buckets SET scope_dimensions = `+expression+` WHERE quota_bucket_id = $1`, bucketID); err == nil {
			t.Errorf("database accepted %s scope", name)
		}
	}

	missingDigest, ok := limitscope.ClaimDigest("region", nil, false)
	if !ok || missingDigest == presentDigest {
		t.Fatal("derive distinct missing claim digest")
	}
	missing := fixture.input(t, "claim-snapshot", 5)
	missing.LimitPlanKey = present.LimitPlanKey
	missing.Platform = present.Platform
	missing.NormalizedClaimDigests = map[string]string{"region": missingDigest}
	missing.Rules[0].Scope = append([]string(nil), present.Rules[0].Scope...)
	pristine, err := fixture.store.Snapshot(fixture.ctx, snapshotInputFromReserve(missing))
	if err != nil || len(pristine.Limits) != 1 || pristine.Limits[0].Used == nil ||
		*pristine.Limits[0].Used != 0 || pristine.Limits[0].Reserved == nil ||
		*pristine.Limits[0].Reserved != 0 {
		t.Fatalf("missing-claim pristine snapshot=%+v err=%v", pristine, err)
	}
	missingReservation, err := fixture.store.Reserve(fixture.ctx, missing)
	if err != nil {
		t.Fatal(err)
	}
	after, err := fixture.store.Snapshot(fixture.ctx, snapshotInputFromReserve(missing))
	if err != nil || len(after.Limits) != 1 || after.Limits[0].Reserved == nil ||
		*after.Limits[0].Reserved != 1 {
		t.Fatalf("missing-claim reserved snapshot=%+v err=%v", after, err)
	}
	if got := fixture.count(t, `
		SELECT count(*) FROM quota_buckets
		WHERE quota_bucket_id IN ($1, $2)
		  AND position($3 in scope_key) = 0
		  AND position($3 in array_to_string(scope_dimensions, ',')) = 0
	`, bucketID, onlyReservationEntry(t, missingReservation).bucketID, "private-eu-value"); got != 2 {
		t.Fatalf("raw normalized claim affected persisted scope visibility: rows=%d", got)
	}
}

func onlyReservationEntry(t *testing.T, reservation Reservation) reservationEntry {
	t.Helper()
	if len(reservation.entries) != 1 {
		t.Fatalf("reservation entries=%d, want exactly one", len(reservation.entries))
	}
	return reservation.entries[0]
}

func fixtureRequestMeasurementInput(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	feature string,
	byteMaximum, imageMaximum, toolMaximum int64,
	requestBytes, imageUnits, toolCalls int64,
) ReserveInput {
	t.Helper()
	input := fixture.input(t, feature, 1)
	input.LimitPlanKey = feature
	input.Platform = "ios"
	digest, ok := limitscope.ClaimDigest("region", "eu", true)
	if !ok {
		t.Fatal("derive request measurement claim digest")
	}
	input.NormalizedClaimDigests = map[string]string{"region": digest}
	input.RequestMeasurements = &RequestMeasurementBinding{
		Protocol:            input.Protocol,
		RewrittenBodySHA256: sha256.Sum256([]byte("body:" + input.LogicalRequestID.String())),
		RequestBytes:        requestBytes, ImageUnits: imageUnits, ToolCalls: toolCalls,
		ImageUnitsKnown: true, ToolCallsKnown: true,
	}
	scope := []string{"user", "platform", "normalized_claim:region"}
	input.Rules = []Rule{
		{Metric: RequestBytesMetric, Algorithm: PerRequestAlgorithm, Scope: append([]string(nil), scope...), PerRequestMaximum: byteMaximum, ReservedUnits: requestBytes, Hard: true},
		{Metric: ImageUnitsMetric, Algorithm: PerRequestAlgorithm, Scope: append([]string(nil), scope...), PerRequestMaximum: imageMaximum, ReservedUnits: imageUnits, Hard: true},
		{Metric: ToolCallsMetric, Algorithm: PerRequestAlgorithm, Scope: append([]string(nil), scope...), PerRequestMaximum: toolMaximum, ReservedUnits: toolCalls, Hard: true},
	}
	return input
}

func assertStoredRequestMeasurement(
	t *testing.T,
	fixture quotaPostgreSQLFixture,
	attemptID string,
	want *RequestMeasurementBinding,
) {
	t.Helper()
	var decisionVersion, measurementVersion int16
	var digest []byte
	var requestBytes, imageUnits, toolCalls int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT attempt_decision_binding_version, request_measurement_binding_version,
		       request_measurement_sha256, measured_request_bytes,
		       measured_image_units, measured_tool_calls
		FROM upstream_attempts WHERE upstream_attempt_id = $1
	`, attemptID).Scan(
		&decisionVersion, &measurementVersion, &digest, &requestBytes, &imageUnits, &toolCalls,
	); err != nil {
		t.Fatal(err)
	}
	if decisionVersion != 2 || measurementVersion != 1 ||
		!bytes.Equal(digest, want.RewrittenBodySHA256[:]) || requestBytes != want.RequestBytes ||
		imageUnits != want.ImageUnits || toolCalls != want.ToolCalls {
		t.Fatalf("stored request measurement versions=%d/%d digest=%x units=%d/%d/%d", decisionVersion, measurementVersion, digest, requestBytes, imageUnits, toolCalls)
	}
}
