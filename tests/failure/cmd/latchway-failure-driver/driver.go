package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var scenarioOrder = []string{
	"live-process-kill-after-reservation",
	"live-process-kill-during-stream",
	"live-database-outage-boundaries",
	"live-graceful-shutdown-and-drain",
	"live-upstream-and-client-disconnect",
	"live-config-and-key-rotation-across-api-replicas",
}

type driver struct {
	ctx             context.Context
	pool            *pgxpool.Pool
	client          *protectedClient
	load            loadConfig
	provision       provisionSummary
	fixtureURL      *url.URL
	fixtureToken    string
	balancerToken   string
	rawHTTP         *http.Client
	scenarioTimeout time.Duration
	drainTimeout    time.Duration
	apiReplicas     int
	workerReplicas  int

	mutex         sync.Mutex
	scenarioIndex int
	current       *scenarioRun
	requestNumber atomic.Uint64
}

type scenarioRun struct {
	id            string
	phaseIndex    int
	assertions    map[string]assertion
	requests      map[string]*requestRecord
	states        map[string]requestState
	lockTx        pgx.Tx
	lockConn      *pgxpool.Conn
	fixture       fixtureObservations
	lbCounts      []int64
	oldKeyID      string
	newKeyID      string
	newRevisionID string
}

type requestRecord struct {
	request asyncRequest
	first   *requestResult
	done    *requestResult
}

type fixtureObservations struct {
	Mode                  string `json:"mode"`
	Active                int64  `json:"active"`
	Total                 int64  `json:"total"`
	Canceled              int64  `json:"canceled"`
	Disconnected          int64  `json:"disconnected"`
	WaitingBeforeResponse int64  `json:"waiting_before_response"`
	WaitingAfterFirstByte int64  `json:"waiting_after_first_byte"`
}

type balancerStats struct {
	SchemaVersion     int     `json:"schema_version"`
	BackendCount      int     `json:"backend_count"`
	RequestsByBackend []int64 `json:"requests_by_backend"`
	Total             int64   `json:"total"`
}

func newDriver(ctx context.Context) (*driver, error) {
	configurationPath := os.Getenv("LATCHWAY_FAILURE_CONFIG")
	provisionPath := os.Getenv("LATCHWAY_FAILURE_PROVISION")
	dialAddress := os.Getenv("LATCHWAY_FAILURE_GATEWAY_DIAL_ADDRESS")
	if configurationPath == "" || provisionPath == "" || dialAddress == "" {
		return nil, errors.New("failure driver file coordinates are missing")
	}
	load, client, err := loadFailureConfig(configurationPath, dialAddress)
	if err != nil {
		return nil, err
	}
	provision, err := loadProvision(provisionPath)
	if err != nil {
		return nil, err
	}
	fixtureURL, err := validatePrivateOrigin(os.Getenv("LATCHWAY_FAILURE_FIXTURE_URL"), 19090)
	if err != nil {
		return nil, err
	}
	fixtureToken := os.Getenv("LATCHWAY_FAILURE_FIXTURE_CONTROL_TOKEN")
	balancerToken := os.Getenv("LATCHWAY_FAILURE_BALANCER_CONTROL_TOKEN")
	if !validControlToken(fixtureToken) || !validControlToken(balancerToken) || fixtureToken == balancerToken {
		return nil, errors.New("failure driver control tokens are invalid")
	}
	scenarioSeconds, err := boundedIntegerEnvironment("LATCHWAY_FAILURE_SCENARIO_TIMEOUT_SECONDS", 30, 600)
	if err != nil {
		return nil, err
	}
	drainSeconds, err := boundedIntegerEnvironment("LATCHWAY_FAILURE_DRAIN_TIMEOUT_SECONDS", 5, 120)
	if err != nil || drainSeconds >= scenarioSeconds {
		return nil, errors.New("failure driver drain timeout is invalid")
	}
	apiReplicas, err := boundedIntegerEnvironment("LATCHWAY_FAILURE_API_REPLICAS", 2, 4)
	if err != nil {
		return nil, err
	}
	workerReplicas, err := boundedIntegerEnvironment("LATCHWAY_FAILURE_WORKER_REPLICAS", 2, 4)
	if err != nil {
		return nil, err
	}
	pool, err := newDatabase(ctx, os.Getenv("LATCHWAY_FAILURE_DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	return &driver{
		ctx: ctx, pool: pool, client: client, load: load, provision: provision,
		fixtureURL: fixtureURL, fixtureToken: fixtureToken, balancerToken: balancerToken,
		rawHTTP:         &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}},
		scenarioTimeout: time.Duration(scenarioSeconds) * time.Second,
		drainTimeout:    time.Duration(drainSeconds) * time.Second,
		apiReplicas:     apiReplicas, workerReplicas: workerReplicas,
	}, nil
}

func (value *driver) close() {
	value.mutex.Lock()
	defer value.mutex.Unlock()
	if value.current != nil {
		value.current.releaseLock(context.Background())
		for _, request := range value.current.requests {
			request.request.cancel()
		}
	}
	value.pool.Close()
}

func (value *driver) servePhase(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/phase" || request.Header.Get("Content-Type") != "application/json" {
		http.NotFound(writer, request)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 {
		value.writePhaseError(writer)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var input phaseRequest
	if err := decoder.Decode(&input); err != nil {
		value.writePhaseError(writer)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		value.writePhaseError(writer)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), value.scenarioTimeout)
	defer cancel()
	value.mutex.Lock()
	response, err := value.executePhase(ctx, input)
	value.mutex.Unlock()
	if err != nil {
		value.writePhaseError(writer)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(response)
}

func (value *driver) writePhaseError(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(writer, `{"code":"failure_phase_check_failed","status":503}`+"\n")
}

func (value *driver) executePhase(ctx context.Context, input phaseRequest) (phaseResponse, error) {
	if value.scenarioIndex >= len(scenarioOrder) || input.ScenarioID != scenarioOrder[value.scenarioIndex] {
		return phaseResponse{}, errors.New("failure scenario order is invalid")
	}
	if value.current == nil {
		if input.Phase != "prepare" {
			return phaseResponse{}, errors.New("failure scenario was not prepared")
		}
		value.current = &scenarioRun{
			id: input.ScenarioID, assertions: make(map[string]assertion),
			requests: make(map[string]*requestRecord), states: make(map[string]requestState),
		}
	}
	run := value.current
	expected, err := expectedPhase(run.id, run.phaseIndex)
	if err != nil || input.Phase != expected {
		return phaseResponse{}, errors.New("failure phase order is invalid")
	}
	observations, err := value.runPhase(ctx, run, input.Phase)
	if err != nil {
		return phaseResponse{}, err
	}
	marker, _ := phaseMarker(input.Phase)
	if observations == nil {
		observations = make(map[string]any)
	}
	observations[marker] = true
	response := phaseResponse{
		SchemaVersion: 1, ScenarioID: run.id, Phase: input.Phase,
		Status: "passed", Observations: observations,
	}
	if input.Phase == "verify" {
		response.Assertions, err = run.verifiedAssertions()
		if err != nil {
			return phaseResponse{}, err
		}
	}
	run.phaseIndex++
	if input.Phase == "verify" {
		run.releaseLock(ctx)
		value.current = nil
		value.scenarioIndex++
	}
	return response, nil
}

func (value *driver) runPhase(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch run.id {
	case "live-process-kill-after-reservation":
		return value.processKillAfterReservation(ctx, run, phase)
	case "live-process-kill-during-stream":
		return value.processKillDuringStream(ctx, run, phase)
	case "live-database-outage-boundaries":
		return value.databaseOutage(ctx, run, phase)
	case "live-graceful-shutdown-and-drain":
		return value.gracefulDrain(ctx, run, phase)
	case "live-upstream-and-client-disconnect":
		return value.disconnectSequence(ctx, run, phase)
	case "live-config-and-key-rotation-across-api-replicas":
		return value.replicaRotation(ctx, run, phase)
	default:
		return nil, errors.New("failure scenario is unsupported")
	}
}

func (run *scenarioRun) pass(name, detail string) error {
	expected := false
	for _, candidate := range scenarioAssertions[run.id] {
		if candidate == name {
			expected = true
			break
		}
	}
	if !expected || len(detail) < 2 || len(detail) > 1000 || strings.ContainsAny(detail, "\r\x00") {
		return errors.New("failure assertion is invalid")
	}
	if _, exists := run.assertions[name]; exists {
		return errors.New("failure assertion was recorded twice")
	}
	run.assertions[name] = assertion{Name: name, Passed: true, Detail: detail}
	return nil
}

func (run *scenarioRun) verifiedAssertions() ([]assertion, error) {
	names := scenarioAssertions[run.id]
	if len(run.assertions) != len(names) {
		return nil, errors.New("failure scenario assertions are incomplete")
	}
	result := make([]assertion, 0, len(names))
	for _, name := range names {
		item, ok := run.assertions[name]
		if !ok || !item.Passed {
			return nil, errors.New("failure scenario assertion is missing")
		}
		result = append(result, item)
	}
	return result, nil
}

func (run *scenarioRun) releaseLock(ctx context.Context) {
	if run.lockTx != nil {
		_ = run.lockTx.Rollback(ctx)
		run.lockTx = nil
	}
	if run.lockConn != nil {
		run.lockConn.Release()
		run.lockConn = nil
	}
}

func (value *driver) nextRequestID(label string) (string, error) {
	if len(label) < 2 || len(label) > 24 {
		return "", errors.New("failure request label is invalid")
	}
	random := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", errors.New("generate failure request identifier")
	}
	return fmt.Sprintf("failure-%02d-%s-%s", value.requestNumber.Add(1), label, base64.RawURLEncoding.EncodeToString(random)), nil
}

func (value *driver) startRequest(run *scenarioRun, label string, specification requestConfig, backend int, stream bool) (*requestRecord, error) {
	requestID, err := value.nextRequestID(label)
	if err != nil {
		return nil, err
	}
	async := value.client.start(value.ctx, specification, requestID, backend, stream)
	record := &requestRecord{request: async}
	run.requests[label] = record
	return record, nil
}

func waitFirst(ctx context.Context, record *requestRecord) (requestResult, error) {
	if record.first != nil {
		return *record.first, nil
	}
	select {
	case result := <-record.request.first:
		record.first = &result
		return result, nil
	case <-ctx.Done():
		return requestResult{}, errors.New("failure request first-byte wait expired")
	}
}

func waitDone(ctx context.Context, record *requestRecord) (requestResult, error) {
	if record.done != nil {
		return *record.done, nil
	}
	select {
	case result := <-record.request.done:
		record.done = &result
		return result, nil
	case <-ctx.Done():
		return requestResult{}, errors.New("failure request completion wait expired")
	}
}

func (value *driver) waitState(ctx context.Context, requestID string, predicate func(requestState) bool) (requestState, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last requestState
	for {
		state, err := readRequestState(ctx, value.pool, requestID)
		if err == nil {
			last = state
			if predicate(state) {
				return state, nil
			}
		}
		select {
		case <-ctx.Done():
			return last, errors.New("failure database state wait expired")
		case <-ticker.C:
		}
	}
}

func (value *driver) recoverRequest(ctx context.Context, record *requestRecord) (requestState, error) {
	state, err := value.waitState(ctx, record.request.clientRequestID, func(state requestState) bool {
		return state.ReservationID != ""
	})
	if err != nil {
		return state, err
	}
	if state.ReservationStatus == "pending" {
		if err := backdateReservation(ctx, value.pool, state); err != nil {
			return state, err
		}
	}
	return value.waitState(ctx, record.request.clientRequestID, func(state requestState) bool {
		return state.ReservationStatus != "pending" && isLogicalTerminal(state.LogicalStatus) &&
			state.TerminalAttemptCount == state.AttemptCount && state.ActiveLeases == 0 &&
			state.UnbalancedEntries == 0
	})
}

func isLogicalTerminal(status string) bool {
	switch status {
	case "succeeded", "failed", "cancelled", "denied":
		return true
	default:
		return false
	}
}

func validatePrivateOrigin(raw string, port int) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("failure private origin is invalid")
	}
	address := net.ParseIP(parsed.Hostname())
	if address == nil || !address.IsPrivate() || parsed.Port() != strconv.Itoa(port) {
		return nil, errors.New("failure private origin must use an exact private IP and port")
	}
	parsed.Path = ""
	return parsed, nil
}

func validControlToken(value string) bool {
	return len(value) >= 32 && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func boundedIntegerEnvironment(name string, minimum, maximum int) (int, error) {
	raw := os.Getenv(name)
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum || strconv.Itoa(value) != raw {
		return 0, errors.New("failure driver bounded integer environment is invalid")
	}
	return value, nil
}

func (value *driver) controlFixture(ctx context.Context, mode string) error {
	payload, _ := json.Marshal(map[string]any{
		"mode": mode, "first_byte_delay_ms": 0, "stream_hold_ms": 120000,
	})
	target := *value.fixtureURL
	target.Path = "/__latchway_test/control"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return errors.New("create failure fixture control request")
	}
	request.Header.Set("Authorization", "Bearer "+value.fixtureToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := value.rawHTTP.Do(request)
	if err != nil {
		return errors.New("failure fixture control unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK {
		return errors.New("failure fixture control rejected request")
	}
	return nil
}

func (value *driver) fixtureObservations(ctx context.Context) (fixtureObservations, error) {
	target := *value.fixtureURL
	target.Path = "/__latchway_test/observations"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	request.Header.Set("Authorization", "Bearer "+value.fixtureToken)
	response, err := value.rawHTTP.Do(request)
	if err != nil {
		return fixtureObservations{}, errors.New("failure fixture observations unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var result fixtureObservations
	if response.StatusCode != http.StatusOK || decoder.Decode(&result) != nil || result.Total < 0 || result.Active < 0 {
		return fixtureObservations{}, errors.New("failure fixture observations invalid")
	}
	return result, nil
}

func (value *driver) waitFixture(ctx context.Context, predicate func(fixtureObservations) bool) (fixtureObservations, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last fixtureObservations
	for {
		observed, err := value.fixtureObservations(ctx)
		if err == nil {
			last = observed
			if predicate(observed) {
				return observed, nil
			}
		}
		select {
		case <-ctx.Done():
			return last, errors.New("failure fixture state wait expired")
		case <-ticker.C:
		}
	}
}

func (value *driver) gatewayStatus(ctx context.Context, path string, backend int) (int, error) {
	target := value.client.target(path)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if backend > 0 {
		request.Header.Set("X-Latchway-Failure-Backend", strconv.Itoa(backend))
	}
	response, err := value.client.http.Do(request)
	if err != nil {
		return 0, nil
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, nil
}

func (value *driver) waitGatewayReady(ctx context.Context, backend int) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, _ := value.gatewayStatus(ctx, "/readyz", backend)
		if status == http.StatusOK {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("failure API replica did not become ready")
		case <-ticker.C:
		}
	}
}

func (value *driver) waitGatewayRejected(ctx context.Context, backend int) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, _ := value.gatewayStatus(ctx, "/healthz", backend)
		if status != http.StatusOK {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("failure API listener continued accepting work")
		case <-ticker.C:
		}
	}
}

func (value *driver) balancerStats(ctx context.Context) (balancerStats, error) {
	target := value.client.target("/__latchway_failure/stats")
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	request.Header.Set("Authorization", "Bearer "+value.balancerToken)
	response, err := value.client.http.Do(request)
	if err != nil {
		return balancerStats{}, errors.New("failure balancer counters unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	var result balancerStats
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if response.StatusCode != http.StatusOK || decoder.Decode(&result) != nil || result.SchemaVersion != 1 || result.BackendCount != value.apiReplicas || len(result.RequestsByBackend) != value.apiReplicas {
		return balancerStats{}, errors.New("failure balancer counters invalid")
	}
	return result, nil
}

func (value *driver) gatewayJWKS(ctx context.Context, backend int) ([]string, error) {
	target := value.client.target("/.well-known/jwks.json")
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	request.Header.Set("X-Latchway-Failure-Backend", strconv.Itoa(backend))
	response, err := value.client.http.Do(request)
	if err != nil {
		return nil, errors.New("failure JWKS unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	var document struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&document) != nil || len(document.Keys) == 0 || len(document.Keys) > 8 {
		return nil, errors.New("failure JWKS is invalid")
	}
	seen := make(map[string]struct{}, len(document.Keys))
	result := make([]string, 0, len(document.Keys))
	for _, key := range document.Keys {
		if len(key.Kid) < 8 || len(key.Kid) > 128 {
			return nil, errors.New("failure JWKS key identifier is invalid")
		}
		if _, exists := seen[key.Kid]; exists {
			return nil, errors.New("failure JWKS key identifier is duplicated")
		}
		seen[key.Kid] = struct{}{}
		result = append(result, key.Kid)
	}
	return sortedStrings(result), nil
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (value *driver) processKillAfterReservation(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch phase {
	case "prepare":
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		connection, err := value.pool.Acquire(ctx)
		if err != nil {
			return nil, errors.New("acquire failure database lock connection")
		}
		tx, err := connection.Begin(ctx)
		if err != nil {
			connection.Release()
			return nil, errors.New("begin failure dispatch boundary lock")
		}
		// SHARE permits read-only observer queries while blocking the candidate's
		// RowExclusive INSERT at the exact pre-dispatch attempt boundary.
		if _, err := tx.Exec(ctx, "LOCK TABLE upstream_attempts IN SHARE MODE"); err != nil {
			_ = tx.Rollback(ctx)
			connection.Release()
			return nil, errors.New("lock failure dispatch boundary")
		}
		run.lockConn, run.lockTx = connection, tx
		record, err := value.startRequest(run, "predispatch", value.load.NonStream, 1, false)
		if err != nil {
			return nil, err
		}
		state, err := value.waitState(ctx, record.request.clientRequestID, func(state requestState) bool {
			return state.LogicalStatus == "reserved" && state.ReservationStatus == "pending" && state.AttemptCount == 0
		})
		if err != nil {
			return nil, err
		}
		run.states["predispatch"] = state
		if err := run.pass("reservation_was_durable_before_kill", "The exact request had a committed pending reservation while the upstream-attempt table lock proved zero dispatch attempts."); err != nil {
			return nil, err
		}
		return map[string]any{"pending_reservations": 1, "attempts": 0}, nil
	case "after_fault":
		run.releaseLock(ctx)
		record := run.requests["predispatch"]
		result, err := waitDone(ctx, record)
		if err != nil {
			return nil, err
		}
		if result.Status < 500 && !result.TransportError {
			return nil, errors.New("killed predispatch request did not terminate abruptly")
		}
		if err := value.waitGatewayReady(ctx, 1); err != nil {
			return nil, err
		}
		if err := run.pass("process_sigkill_observed", "The locked in-flight request ended abruptly and the exact killed API backend subsequently returned ready."); err != nil {
			return nil, err
		}
		state, err := value.recoverRequest(ctx, record)
		if err != nil {
			return nil, err
		}
		run.states["predispatch"] = state
		if state.AttemptCount != 0 || state.UsageRows != 0 || state.ReservationStatus != "expired" {
			return nil, errors.New("undispatched failure reservation recovery is invalid")
		}
		if err := run.pass("replacement_worker_reclaimed_reservation", "A live replacement worker transitioned the exact backdated pending reservation to expired with balanced released entries."); err != nil {
			return nil, err
		}
		if err := run.pass("no_usage_recorded_for_undispatched_attempt", "The recovered logical request retained zero upstream attempts and zero usage records."); err != nil {
			return nil, err
		}
		violations, err := hardQuotaViolations(ctx, value.pool)
		if err != nil || violations != 0 {
			return nil, errors.New("hard quota invariant failed after predispatch recovery")
		}
		if err := run.pass("hard_quota_not_overspent", "Every hard bucket satisfied used plus reserved less than or equal to its maximum after recovery."); err != nil {
			return nil, err
		}
		return map[string]any{"terminal_requests": 1, "usage_rows": state.UsageRows}, nil
	case "verify":
		return map[string]any{"machine_checked_assertions": len(run.assertions)}, nil
	}
	return nil, errors.New("invalid predispatch kill phase")
}

func (value *driver) processKillDuringStream(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch phase {
	case "prepare":
		if err := value.controlFixture(ctx, "drain-hold"); err != nil {
			return nil, err
		}
		record, err := value.startRequest(run, "streamkill", value.load.Stream, 2, true)
		if err != nil {
			return nil, err
		}
		first, err := waitFirst(ctx, record)
		if err != nil || !first.FirstByte || first.Status != http.StatusOK {
			return nil, errors.New("failure stream did not establish first byte")
		}
		state, err := value.waitState(ctx, record.request.clientRequestID, func(state requestState) bool {
			return state.ReservationStatus == "pending" && state.FirstByteAttemptCount == 1 && state.LogicalStatus == "streaming"
		})
		if err != nil {
			return nil, err
		}
		run.states["streamkill"] = state
		if err := run.pass("sse_first_byte_observed_before_sigkill", "The exact API-2 stream emitted a valid first SSE event and persisted first_byte_at before the controller fault."); err != nil {
			return nil, err
		}
		return map[string]any{"first_byte_attempts": state.FirstByteAttemptCount, "pending_reservations": 1}, nil
	case "after_fault":
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		record := run.requests["streamkill"]
		result, err := waitDone(ctx, record)
		if err != nil || (!result.TransportError && result.Completed) {
			return nil, errors.New("killed stream did not truncate")
		}
		if err := value.waitGatewayReady(ctx, 2); err != nil {
			return nil, err
		}
		if err := run.pass("process_sigkill_observed", "The established SSE transport truncated before completion and the exact API-2 backend restarted."); err != nil {
			return nil, err
		}
		state, err := value.recoverRequest(ctx, record)
		if err != nil {
			return nil, err
		}
		if state.ReservationStatus != "settled" || state.AttemptCount != 1 || state.TerminalAttemptCount != 1 {
			return nil, errors.New("killed stream was not conservatively reconciled")
		}
		if err := run.pass("replacement_api_and_worker_recovered", "API-2 returned ready and a live worker terminalized the exact abandoned streaming attempt."); err != nil {
			return nil, err
		}
		if err := run.pass("reservation_settled_conservatively", "The dispatched reservation settled with one terminal attempt and balanced reservation entries."); err != nil {
			return nil, err
		}
		if err := run.pass("no_permanent_reservation", "The killed stream retained no pending reservation and no active concurrency lease."); err != nil {
			return nil, err
		}
		violations, err := hardQuotaViolations(ctx, value.pool)
		if err != nil || violations != 0 {
			return nil, errors.New("hard quota invariant failed after stream recovery")
		}
		if err := run.pass("hard_quota_not_overspent", "Every hard bucket remained within its durable maximum after conservative stream recovery."); err != nil {
			return nil, err
		}
		return map[string]any{"terminal_attempts": state.TerminalAttemptCount, "active_leases": state.ActiveLeases}, nil
	case "verify":
		return map[string]any{"machine_checked_assertions": len(run.assertions)}, nil
	}
	return nil, errors.New("invalid stream kill phase")
}

func (value *driver) databaseOutage(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch phase {
	case "prepare":
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		for backend := 1; backend <= 2; backend++ {
			if err := value.waitGatewayReady(ctx, backend); err != nil {
				return nil, err
			}
		}
		canaryID, err := value.nextRequestID("dbcanary")
		if err != nil {
			return nil, err
		}
		canary := value.client.execute(ctx, value.load.NonStream, canaryID, 2)
		if canary.Status != http.StatusOK || !canary.Completed {
			return nil, errors.New("database-outage target replica was not healthy before fault")
		}
		if err := value.controlFixture(ctx, "hold-before-response"); err != nil {
			return nil, err
		}
		before, err := value.fixtureObservations(ctx)
		if err != nil {
			return nil, err
		}
		record, err := value.startRequest(run, "settlement", value.load.NonStream, 1, false)
		if err != nil {
			return nil, err
		}
		observed, err := value.waitFixture(ctx, func(item fixtureObservations) bool {
			return item.Total == before.Total+1 && item.WaitingBeforeResponse == 1
		})
		if err != nil {
			return nil, err
		}
		state, err := value.waitState(ctx, record.request.clientRequestID, func(state requestState) bool {
			return state.ReservationStatus == "pending" && state.AttemptCount == 1 && state.TerminalAttemptCount == 0
		})
		if err != nil {
			return nil, err
		}
		run.fixture, run.states["settlement"] = observed, state
		return map[string]any{"upstream_requests": observed.Total, "pending_attempts": 1}, nil
	case "during_fault":
		before := run.fixture
		requestID, err := value.nextRequestID("dbpredispatch")
		if err != nil {
			return nil, err
		}
		requestContext, cancel := context.WithTimeout(ctx, 8*time.Second)
		result := value.client.execute(requestContext, value.load.NonStream, requestID, 2)
		cancel()
		if result.Status < 500 && !result.TransportError {
			return nil, errors.New("database-outage predispatch request did not fail closed")
		}
		after, err := value.fixtureObservations(ctx)
		if err != nil || after.Total != before.Total {
			return nil, errors.New("database-outage predispatch request reached upstream")
		}
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		if _, err := value.waitFixture(ctx, func(item fixtureObservations) bool {
			return item.WaitingBeforeResponse == 0 && item.Active == 0
		}); err != nil {
			return nil, err
		}
		completionContext, completionCancel := context.WithTimeout(ctx, 30*time.Second)
		_, err = waitDone(completionContext, run.requests["settlement"])
		completionCancel()
		if err != nil {
			return nil, errors.New("database-outage settlement did not fail within bound")
		}
		if err := run.pass("database_network_cut_observed", "A new database-dependent request failed while the fixture and balancer remained reachable on the isolated network."); err != nil {
			return nil, err
		}
		if err := run.pass("predispatch_outage_failed_closed", "The request initiated after the database partition returned only an error and never a successful provider response."); err != nil {
			return nil, err
		}
		if err := run.pass("no_upstream_dispatch_during_predispatch_outage", "The authenticated fixture total remained unchanged across the exact predispatch outage request."); err != nil {
			return nil, err
		}
		return map[string]any{"predispatch_failed": true, "upstream_delta": 0}, nil
	case "after_fault":
		record := run.requests["settlement"]
		state, err := value.waitState(ctx, record.request.clientRequestID, func(state requestState) bool {
			return state.ReservationID != "" && state.AttemptCount == 1 &&
				(state.ReservationStatus == "pending" ||
					(state.ReservationStatus == "settled" && state.TerminalAttemptCount == 1))
		})
		if err != nil {
			return nil, err
		}
		if err := run.pass("settlement_outage_created_bounded_pending_usage", "The already-dispatched request had one committed pending reservation and one started attempt at the partition boundary; restoration observed either that bounded state or its single worker reconciliation."); err != nil {
			return nil, err
		}
		state, err = value.recoverRequest(ctx, record)
		if err != nil {
			return nil, err
		}
		if state.ReservationStatus != "settled" || state.TerminalAttemptCount != 1 {
			return nil, errors.New("database-outage settlement was not reconciled")
		}
		if err := run.pass("worker_reconciled_pending_usage_after_restore", "A worker reconciled the exact dispatched pending reservation to one conservative terminal attempt after restoration."); err != nil {
			return nil, err
		}
		if err := run.pass("no_permanent_reservation", "Database restoration and reconciliation left no pending reservation or active lease."); err != nil {
			return nil, err
		}
		return map[string]any{"terminal_attempts": state.TerminalAttemptCount, "usage_rows": state.UsageRows}, nil
	case "verify":
		return map[string]any{"machine_checked_assertions": len(run.assertions)}, nil
	}
	return nil, errors.New("invalid database outage phase")
}

func (value *driver) gracefulDrain(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch phase {
	case "prepare":
		if err := value.controlFixture(ctx, "drain-hold"); err != nil {
			return nil, err
		}
		before, err := value.fixtureObservations(ctx)
		if err != nil {
			return nil, err
		}
		nonstream, err := value.startRequest(run, "drainnonstream", value.load.NonStream, 1, false)
		if err != nil {
			return nil, err
		}
		stream, err := value.startRequest(run, "drainstream", value.load.Stream, 1, true)
		if err != nil {
			return nil, err
		}
		first, err := waitFirst(ctx, stream)
		if err != nil || !first.FirstByte {
			return nil, errors.New("drain stream did not establish")
		}
		observed, err := value.waitFixture(ctx, func(item fixtureObservations) bool {
			return item.Total == before.Total+2 && item.WaitingBeforeResponse == 1 && item.WaitingAfterFirstByte == 1
		})
		if err != nil {
			return nil, err
		}
		_, err = value.waitState(ctx, nonstream.request.clientRequestID, func(state requestState) bool { return state.AttemptCount == 1 })
		if err != nil {
			return nil, err
		}
		return map[string]any{"held_nonstream": observed.WaitingBeforeResponse, "held_streams": observed.WaitingAfterFirstByte}, nil
	case "during_fault":
		started := time.Now()
		rejectContext, cancel := context.WithTimeout(ctx, min(10*time.Second, value.drainTimeout))
		err := value.waitGatewayRejected(rejectContext, 1)
		cancel()
		if err != nil {
			return nil, err
		}
		otherStatus, _ := value.gatewayStatus(ctx, "/healthz", 2)
		if otherStatus != http.StatusOK {
			return nil, errors.New("failure load balancer or non-draining API became unavailable")
		}
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		nonstream, err := waitDone(ctx, run.requests["drainnonstream"])
		if err != nil {
			return nil, err
		}
		stream, err := waitDone(ctx, run.requests["drainstream"])
		if err != nil {
			return nil, err
		}
		elapsed := time.Since(started)
		if elapsed > value.drainTimeout || (!nonstream.Completed && !nonstream.TransportError) || (!stream.Completed && !stream.TransportError) {
			return nil, errors.New("graceful drain requests exceeded bound")
		}
		for name, detail := range map[string]string{
			"sigterm_observed":                                     "API-1 stopped accepting traffic while two established requests were held at deterministic fixture barriers.",
			"listener_rejected_new_work_during_drain":              "The load balancer could no longer obtain a successful health response from the exact draining backend.",
			"nonstream_completed_or_terminated_within_drain_bound": "The held non-stream request completed or terminated before the configured drain deadline.",
			"sse_completed_or_terminated_within_drain_bound":       "The established SSE request completed or terminated before the configured drain deadline.",
		} {
			if err := run.pass(name, detail); err != nil {
				return nil, err
			}
		}
		return map[string]any{"drain_elapsed_milliseconds": elapsed.Milliseconds(), "listener_rejected": true}, nil
	case "after_fault":
		if err := value.waitGatewayReady(ctx, 1); err != nil {
			return nil, err
		}
		for _, name := range []string{"drainnonstream", "drainstream"} {
			state, err := value.recoverRequest(ctx, run.requests[name])
			if err != nil {
				return nil, err
			}
			if state.ReservationStatus == "pending" || state.ActiveLeases != 0 {
				return nil, errors.New("drained request retained permanent capacity")
			}
		}
		if err := run.pass("process_exited_within_drain_bound", "The controller observed API-1 exit and restart, and the repo driver observed readiness recover within the same scenario bound."); err != nil {
			return nil, err
		}
		if err := run.pass("no_permanent_reservation", "Both drained requests ended with terminal reservations, balanced entries, and no active leases."); err != nil {
			return nil, err
		}
		return map[string]any{"recovered_api_replicas": 1, "terminal_requests": 2}, nil
	case "verify":
		return map[string]any{"machine_checked_assertions": len(run.assertions)}, nil
	}
	return nil, errors.New("invalid graceful drain phase")
}

func (value *driver) disconnectSequence(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch phase {
	case "prepare":
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		observed, err := value.fixtureObservations(ctx)
		if err != nil {
			return nil, err
		}
		run.fixture = observed
		return map[string]any{"fixture_total": observed.Total, "fixture_disconnected": observed.Disconnected}, nil
	case "inject":
		before := run.fixture
		if err := value.controlFixture(ctx, "disconnect-before-response"); err != nil {
			return nil, err
		}
		pre, err := value.startRequest(run, "disconnectpre", value.load.NonStream, 1, false)
		if err != nil {
			return nil, err
		}
		preResult, err := waitDone(ctx, pre)
		if err != nil {
			return nil, err
		}
		if preResult.Status < http.StatusInternalServerError && !preResult.TransportError {
			return nil, errors.New("pre-response fixture disconnect was not a transport failure")
		}
		observed, err := value.waitFixture(ctx, func(item fixtureObservations) bool { return item.Disconnected >= before.Disconnected+1 })
		if err != nil {
			return nil, err
		}
		if err := run.pass("pre_response_upstream_disconnect_observed", "The authenticated fixture recorded a transport disconnect before emitting a provider response."); err != nil {
			return nil, err
		}
		if err := value.controlFixture(ctx, "disconnect-during-stream"); err != nil {
			return nil, err
		}
		mid, err := value.startRequest(run, "disconnectmid", value.load.Stream, 2, true)
		if err != nil {
			return nil, err
		}
		first, err := waitFirst(ctx, mid)
		if err != nil || !first.FirstByte {
			return nil, errors.New("mid-stream disconnect did not emit first event")
		}
		midResult, err := waitDone(ctx, mid)
		if err != nil || !midResult.TransportError || midResult.Completed {
			return nil, errors.New("mid-stream fixture disconnect was not a truncated transport")
		}
		observed, err = value.waitFixture(ctx, func(item fixtureObservations) bool { return item.Disconnected >= before.Disconnected+2 })
		if err != nil {
			return nil, err
		}
		if err := run.pass("mid_sse_upstream_disconnect_observed", "The fixture emitted one SSE event and then recorded an authenticated mid-stream transport disconnect."); err != nil {
			return nil, err
		}
		if err := value.controlFixture(ctx, "drain-hold"); err != nil {
			return nil, err
		}
		cancelRecord, err := value.startRequest(run, "clientcancel", value.load.Stream, 1, true)
		if err != nil {
			return nil, err
		}
		first, err = waitFirst(ctx, cancelRecord)
		if err != nil || !first.FirstByte {
			return nil, errors.New("client-cancel stream did not establish")
		}
		if _, err := value.waitFixture(ctx, func(item fixtureObservations) bool { return item.WaitingAfterFirstByte == 1 }); err != nil {
			return nil, err
		}
		cancelRecord.request.cancel()
		cancelResult, err := waitDone(ctx, cancelRecord)
		if err != nil || !cancelResult.TransportError || cancelResult.Completed {
			return nil, errors.New("downstream cancellation did not terminate the transport")
		}
		observed, err = value.waitFixture(ctx, func(item fixtureObservations) bool { return item.Canceled >= before.Canceled+1 })
		if err != nil {
			return nil, err
		}
		if err := value.controlFixture(ctx, "healthy"); err != nil {
			return nil, err
		}
		if err := run.pass("downstream_client_cancel_observed", "After one SSE event, the driver canceled the downstream context and the fixture recorded upstream cancellation."); err != nil {
			return nil, err
		}
		return map[string]any{"fixture_disconnects": observed.Disconnected - before.Disconnected, "fixture_cancels": observed.Canceled - before.Canceled}, nil
	case "after_fault":
		for _, name := range []string{"disconnectpre", "disconnectmid", "clientcancel"} {
			state, err := value.recoverRequest(ctx, run.requests[name])
			if err != nil {
				return nil, err
			}
			if state.AttemptCount != 1 || state.TerminalAttemptCount != 1 {
				return nil, errors.New("disconnect case did not retain exactly one terminal attempt")
			}
			if state.DuplicateProvenance != 0 || state.UsageRows < 1 || state.UsageRows > 4 || state.ActiveLeases != 0 || state.ReservationStatus == "pending" {
				return nil, errors.New("disconnect usage provenance or reservation bound failed")
			}
			run.states[name] = state
		}
		if err := run.pass("one_terminal_attempt_per_case", "Each of the pre-response disconnect, mid-SSE disconnect, and downstream cancellation cases retained exactly one terminal upstream attempt."); err != nil {
			return nil, err
		}
		if err := run.pass("usage_provenance_bounded_per_case", "Every case retained at most four unique metric provenance rows, with no duplicate provenance key."); err != nil {
			return nil, err
		}
		if err := run.pass("no_permanent_reservation", "All three disconnect cases ended with balanced terminal reservations and no active concurrency lease."); err != nil {
			return nil, err
		}
		return map[string]any{"terminal_cases": 3, "maximum_usage_rows_per_case": 4}, nil
	case "verify":
		return map[string]any{"machine_checked_assertions": len(run.assertions)}, nil
	}
	return nil, errors.New("invalid disconnect phase")
}

func (value *driver) replicaRotation(ctx context.Context, run *scenarioRun, phase string) (map[string]any, error) {
	switch phase {
	case "prepare":
		for backend := 1; backend <= value.apiReplicas; backend++ {
			if err := value.waitGatewayReady(ctx, backend); err != nil {
				return nil, err
			}
		}
		workers, err := liveWorkerCount(ctx, value.pool)
		if err != nil || workers < int64(value.workerReplicas) {
			return nil, errors.New("failure worker replica heartbeat count is insufficient")
		}
		for backend := 1; backend <= 2; backend++ {
			requestID, err := value.nextRequestID("replicapre")
			if err != nil {
				return nil, err
			}
			result := value.client.execute(ctx, value.load.NonStream, requestID, backend)
			if result.Status != http.StatusOK || !result.Completed {
				return nil, errors.New("failure API replica did not serve protected traffic")
			}
		}
		keyID, err := activeSigningKey(ctx, value.pool)
		if err != nil {
			return nil, errors.New("read active failure signing key")
		}
		firstJWKS, err := value.gatewayJWKS(ctx, 1)
		if err != nil || !containsString(firstJWKS, keyID) {
			return nil, errors.New("active failure signing key missing from JWKS")
		}
		secondJWKS, err := value.gatewayJWKS(ctx, 2)
		if err != nil || !equalStrings(firstJWKS, secondJWKS) {
			return nil, errors.New("failure API replica JWKS did not initially converge")
		}
		stats, err := value.balancerStats(ctx)
		if err != nil {
			return nil, err
		}
		run.oldKeyID, run.lbCounts = keyID, append([]int64(nil), stats.RequestsByBackend...)
		if err := run.pass("at_least_two_api_replicas_observed", "Two independently targeted API backends returned ready and served DPoP-protected traffic through the internal load balancer."); err != nil {
			return nil, err
		}
		if err := run.pass("at_least_two_workers_observed", "PostgreSQL contained at least two distinct fresh worker-role runtime heartbeats within the bounded freshness window."); err != nil {
			return nil, err
		}
		return map[string]any{"ready_api_replicas": value.apiReplicas, "live_worker_replicas": workers}, nil
	case "inject":
		for index := 0; index < value.apiReplicas*4; index++ {
			status, _ := value.gatewayStatus(ctx, "/healthz", 0)
			if status != http.StatusOK {
				return nil, errors.New("round-robin failure balancer health request failed")
			}
		}
		stats, err := value.balancerStats(ctx)
		if err != nil {
			return nil, err
		}
		for backend := range stats.RequestsByBackend {
			if stats.RequestsByBackend[backend] <= run.lbCounts[backend] {
				return nil, errors.New("failure balancer did not route every API replica")
			}
		}
		if err := run.pass("load_balancer_routed_multiple_api_replicas", "Authenticated load-balancer counters increased for every exact API backend under unpinned round-robin traffic."); err != nil {
			return nil, err
		}
		if err := forceSigningRotationBoundary(ctx, value.pool, run.oldKeyID); err != nil {
			return nil, err
		}
		rotationContext, cancel := context.WithTimeout(ctx, 100*time.Second)
		defer cancel()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for run.newKeyID == "" {
			keyID, err := activeSigningKey(rotationContext, value.pool)
			if err == nil && keyID != "" && keyID != run.oldKeyID {
				run.newKeyID = keyID
				break
			}
			select {
			case <-rotationContext.Done():
				return nil, errors.New("failure signing rotation did not complete")
			case <-ticker.C:
			}
		}
		var converged []string
		for {
			first, firstErr := value.gatewayJWKS(rotationContext, 1)
			second, secondErr := value.gatewayJWKS(rotationContext, 2)
			if firstErr == nil && secondErr == nil && equalStrings(first, second) && containsString(first, run.oldKeyID) && containsString(first, run.newKeyID) {
				converged = first
				break
			}
			select {
			case <-rotationContext.Done():
				return nil, errors.New("failure JWKS did not converge after signing rotation")
			case <-ticker.C:
			}
		}
		for backend := 1; backend <= 2; backend++ {
			requestID, _ := value.nextRequestID("postsign")
			result := value.client.execute(ctx, value.load.NonStream, requestID, backend)
			if result.Status != http.StatusOK || !result.Completed {
				return nil, errors.New("pre-rotation session failed after signing rotation")
			}
		}
		if err := run.pass("signing_rotation_preserved_active_sessions", "After the worker rotated the active signing key, the pre-rotation access token still served protected traffic on both API replicas."); err != nil {
			return nil, err
		}
		if err := run.pass("gateway_signing_jwks_converged", "Both API replicas returned the same gateway-signing JWKS containing the old retiring key and the new active key; issuer-JWKS rotation is a separate shared-cache scenario."); err != nil {
			return nil, err
		}
		newRevisionID, err := cloneAndActivateConfiguration(ctx, value.pool, value.provision)
		if err != nil {
			return nil, err
		}
		run.newRevisionID = newRevisionID
		beforeConfiguration, err := value.fixtureObservations(ctx)
		if err != nil {
			return nil, err
		}
		results := make([]requestResult, 2)
		for backend := 1; backend <= 2; backend++ {
			requestID, _ := value.nextRequestID("postconfig")
			results[backend-1] = value.client.execute(ctx, value.load.NonStream, requestID, backend)
		}
		active, err := activeConfigurationRevision(ctx, value.pool, value.provision.EnvironmentID)
		afterConfiguration, observationErr := value.fixtureObservations(ctx)
		if err != nil || observationErr != nil || active != newRevisionID ||
			results[0].Status != http.StatusUnprocessableEntity ||
			results[1].Status != http.StatusUnprocessableEntity ||
			results[0].ProblemCode != "configuration_invalid" ||
			results[1].ProblemCode != "configuration_invalid" ||
			afterConfiguration.Total != beforeConfiguration.Total {
			return nil, errors.New("failure configuration revision did not converge atomically")
		}
		if err := run.pass("configuration_revision_atomic_across_replicas", "One transaction moved the active immutable snapshot; both API replicas immediately and identically rejected the prior revision-bound session without serving mixed policy."); err != nil {
			return nil, err
		}
		return map[string]any{"routed_api_replicas": value.apiReplicas, "jwks_key_count": len(converged), "configuration_responses_equal": true}, nil
	case "after_fault":
		for backend := 1; backend <= value.apiReplicas; backend++ {
			if err := value.waitGatewayReady(ctx, backend); err != nil {
				return nil, err
			}
		}
		return map[string]any{"ready_api_replicas": value.apiReplicas, "rotation_recovered": true}, nil
	case "verify":
		return map[string]any{"machine_checked_assertions": len(run.assertions)}, nil
	}
	return nil, errors.New("invalid replica rotation phase")
}
