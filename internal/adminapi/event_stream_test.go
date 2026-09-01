package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/adminauth"
)

type scriptedAdminEventSource struct {
	mu        sync.Mutex
	snapshots []adminEventSnapshot
	err       error
	calls     int
}

type scriptedAdminEventPrincipalSource struct {
	mu       sync.Mutex
	calls    int
	rejectAt int
	err      error
}

type blockingAfterInitialAdminEventSource struct {
	mu    sync.Mutex
	calls int
}

type signalingAdminEventRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	once    sync.Once
}

func newSignalingAdminEventRecorder() *signalingAdminEventRecorder {
	return &signalingAdminEventRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		flushed:          make(chan struct{}),
	}
}

func (recorder *signalingAdminEventRecorder) Flush() {
	recorder.ResponseRecorder.Flush()
	recorder.once.Do(func() { close(recorder.flushed) })
}

func (source *scriptedAdminEventPrincipalSource) RevalidatePrincipal(
	_ context.Context,
	principal adminauth.Principal,
) (adminauth.Principal, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	if source.err != nil && (source.rejectAt == 0 || source.calls >= source.rejectAt) {
		return adminauth.Principal{}, source.err
	}
	return principal, nil
}

func (source *scriptedAdminEventSource) snapshot(
	context.Context,
	adminauth.Principal,
	string,
) (adminEventSnapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	if source.err != nil {
		return adminEventSnapshot{}, source.err
	}
	if len(source.snapshots) == 0 {
		return adminEventSnapshot{}, nil
	}
	index := source.calls - 1
	if index >= len(source.snapshots) {
		index = len(source.snapshots) - 1
	}
	return source.snapshots[index], nil
}

func (source *blockingAfterInitialAdminEventSource) snapshot(
	ctx context.Context,
	_ adminauth.Principal,
	_ string,
) (adminEventSnapshot, error) {
	source.mu.Lock()
	source.calls++
	call := source.calls
	source.mu.Unlock()
	if call == 1 {
		return adminEventSnapshot{Requests: "initial"}, nil
	}
	<-ctx.Done()
	return adminEventSnapshot{}, ctx.Err()
}

func TestChangedAdminEventTopicsAreClosedAndStable(t *testing.T) {
	t.Parallel()

	previous := adminEventSnapshot{
		Requests: "request-a", Usage: "usage-a", Configuration: "configuration-a",
		Audit: "audit-a", SelfTests: "self-test-a", Health: "health-a",
	}
	next := adminEventSnapshot{
		Requests: "request-b", Usage: "usage-a", Configuration: "configuration-b",
		Audit: "audit-a", SelfTests: "self-test-b", Health: "health-b",
	}
	want := []string{"requests", "configuration", "self_tests", "health"}
	if got := changedAdminEventTopics(previous, next); !reflect.DeepEqual(got, want) {
		t.Fatalf("changedAdminEventTopics() = %q, want %q", got, want)
	}
	if got := changedAdminEventTopics(previous, previous); len(got) != 0 {
		t.Fatalf("unchanged topics = %q", got)
	}
}

func TestAdminEventStreamEmitsOnlyRefreshHintsAndReauthenticates(t *testing.T) {
	t.Parallel()

	source := &scriptedAdminEventSource{snapshots: []adminEventSnapshot{
		{Requests: "confidential-request-fingerprint", Usage: "usage-a", Health: "health-a"},
		{Requests: "confidential-request-fingerprint", Usage: "usage-a", Health: "health-a"},
		{Requests: "confidential-request-fingerprint-b", Usage: "usage-b", Health: "health-a"},
	}}
	api := &API{
		events: source, eventPrincipals: &scriptedAdminEventPrincipalSource{},
		eventStream: adminEventStreamSettings{
			pollInterval: time.Millisecond, heartbeatInterval: 2 * time.Millisecond,
			maximumLifetime: 8 * time.Millisecond, operationTimeout: time.Millisecond,
			now: time.Now,
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleViewer,
		Method:         adminauth.AuthenticationSession,
	}))
	response := httptest.NewRecorder()

	api.adminEvents(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "text/event-stream; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"event: ready", `"stream_version":1`, `"topics":["requests","usage","configuration","audit","self_tests","health"]`,
		"retry: 5000", "event: refresh", `"topics":["requests","usage"]`, ": heartbeat", "event: reconnect", `"reauthenticate":true`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("stream omitted %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"confidential-request-fingerprint", "org_", "adm_"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("stream exposed %q: %s", forbidden, body)
		}
	}
	if strings.Contains(body, "id:") {
		t.Fatalf("non-replay stream emitted an event identifier: %s", body)
	}
}

func TestAdminEventStreamRejectsInvalidScopeBeforeStreaming(t *testing.T) {
	t.Parallel()

	api := &API{
		events:          &scriptedAdminEventSource{},
		eventPrincipals: &scriptedAdminEventPrincipalSource{},
		eventStream:     defaultAdminEventStreamSettings(),
	}
	request := httptest.NewRequest(http.MethodGet, "/events?environment_id=not-an-environment", nil)
	response := httptest.NewRecorder()
	api.adminEvents(response, request)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("invalid scope status/content-type = %d/%q, body = %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestAdminEventStreamMapsTenantMissBeforeStreaming(t *testing.T) {
	t.Parallel()

	source := &scriptedAdminEventSource{err: errOperationalNotFound}
	api := &API{
		events: source, eventPrincipals: &scriptedAdminEventPrincipalSource{},
		eventStream: defaultAdminEventStreamSettings(),
	}
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		Role: adminauth.RoleViewer,
	}))
	response := httptest.NewRecorder()
	api.adminEvents(response, request)
	if response.Code != http.StatusNotFound || strings.Contains(response.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("tenant miss status/content-type = %d/%q, body = %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	if !errors.Is(source.err, errOperationalNotFound) {
		t.Fatal("tenant miss fixture changed unexpectedly")
	}
}

func TestAdminEventStreamRevalidatesAndClosesRevokedCredential(t *testing.T) {
	t.Parallel()

	events := &scriptedAdminEventSource{snapshots: []adminEventSnapshot{{Requests: "initial"}}}
	principals := &scriptedAdminEventPrincipalSource{
		rejectAt: 2,
		err:      adminauth.ErrAdminAuthentication,
	}
	api := &API{
		events: events, eventPrincipals: principals,
		eventStream: adminEventStreamSettings{
			pollInterval: time.Millisecond, heartbeatInterval: 50 * time.Millisecond,
			maximumLifetime: 100 * time.Millisecond, operationTimeout: 10 * time.Millisecond,
			now: time.Now,
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleViewer,
		Method:         adminauth.AuthenticationSession,
	}))
	response := httptest.NewRecorder()

	api.adminEvents(response, request)

	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "event: ready") ||
		!strings.Contains(body, "event: reconnect") || strings.Contains(body, "event: unavailable") ||
		strings.Contains(body, "event: refresh") {
		t.Fatalf("revoked-credential stream status/body = %d %s", response.Code, body)
	}
	if principals.calls != 2 || events.calls != 1 {
		t.Fatalf("revoked-credential calls = principal:%d snapshot:%d, want 2/1", principals.calls, events.calls)
	}
}

func TestAdminEventStreamRejectsRevokedCredentialBeforeHeaders(t *testing.T) {
	t.Parallel()

	events := &scriptedAdminEventSource{}
	api := &API{
		events:          events,
		eventPrincipals: &scriptedAdminEventPrincipalSource{err: adminauth.ErrAdminAuthentication},
		eventStream:     defaultAdminEventStreamSettings(),
	}
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{}))
	response := httptest.NewRecorder()

	api.adminEvents(response, request)

	if response.Code != http.StatusUnauthorized || events.calls != 0 ||
		strings.Contains(response.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("initially revoked stream status/snapshots/content-type = %d/%d/%q, body = %s",
			response.Code, events.calls, response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestAdminEventStreamBoundsAStalledRefresh(t *testing.T) {
	t.Parallel()

	events := &blockingAfterInitialAdminEventSource{}
	api := &API{
		events: events, eventPrincipals: &scriptedAdminEventPrincipalSource{},
		eventStream: adminEventStreamSettings{
			pollInterval: time.Millisecond, heartbeatInterval: 100 * time.Millisecond,
			maximumLifetime: 500 * time.Millisecond, operationTimeout: 5 * time.Millisecond,
			now: time.Now,
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/events", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleViewer,
		Method:         adminauth.AuthenticationSession,
	}))
	response := httptest.NewRecorder()
	started := time.Now()

	api.adminEvents(response, request)

	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("stalled event refresh was not bounded: %s", elapsed)
	}
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "event: ready") ||
		!strings.Contains(body, "event: unavailable") || strings.Contains(body, "event: reconnect") {
		t.Fatalf("stalled event refresh status/body = %d %s", response.Code, body)
	}
}

func TestAdminEventStreamStopsSilentlyOnClientCancellation(t *testing.T) {
	t.Parallel()

	api := &API{
		events: &scriptedAdminEventSource{}, eventPrincipals: &scriptedAdminEventPrincipalSource{},
		eventStream: adminEventStreamSettings{
			pollInterval: 100 * time.Millisecond, heartbeatInterval: 100 * time.Millisecond,
			maximumLifetime: time.Second, operationTimeout: 50 * time.Millisecond,
			now: time.Now,
		},
	}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	request := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(requestContext)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminauth.Principal{
		OrganizationID: "org_00000000000000000000000000",
		AdminUserID:    "adm_00000000000000000000000000",
		Role:           adminauth.RoleViewer,
		Method:         adminauth.AuthenticationSession,
	}))
	response := newSignalingAdminEventRecorder()
	done := make(chan struct{})
	go func() {
		api.adminEvents(response, request)
		close(done)
	}()
	select {
	case <-response.flushed:
	case <-time.After(time.Second):
		t.Fatal("event stream did not flush ready before cancellation")
	}
	cancelRequest()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("event stream did not stop after request cancellation")
	}
	if body := response.Body.String(); strings.Contains(body, "event: reconnect") ||
		strings.Contains(body, "event: unavailable") {
		t.Fatalf("client cancellation emitted a misleading terminal event: %s", body)
	}
}
