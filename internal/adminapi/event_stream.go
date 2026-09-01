package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/problem"
)

const (
	adminEventStreamVersion     = 1
	adminEventReconnectMillis   = 5_000
	adminEventPollInterval      = 2 * time.Second
	adminEventHeartbeatInterval = 15 * time.Second
	adminEventMaximumLifetime   = 60 * time.Second
	adminEventOperationTimeout  = time.Second
)

var adminEventTopics = [...]string{
	"requests",
	"usage",
	"configuration",
	"audit",
	"self_tests",
	"health",
}

type adminEventSnapshot struct {
	Requests      string
	Usage         string
	Configuration string
	Audit         string
	SelfTests     string
	Health        string
}

type adminEventSource interface {
	snapshot(context.Context, adminauth.Principal, string) (adminEventSnapshot, error)
}

type adminEventPrincipalSource interface {
	RevalidatePrincipal(context.Context, adminauth.Principal) (adminauth.Principal, error)
}

type adminEventStreamSettings struct {
	pollInterval      time.Duration
	heartbeatInterval time.Duration
	maximumLifetime   time.Duration
	operationTimeout  time.Duration
	now               func() time.Time
}

func defaultAdminEventStreamSettings() adminEventStreamSettings {
	return adminEventStreamSettings{
		pollInterval:      adminEventPollInterval,
		heartbeatInterval: adminEventHeartbeatInterval,
		maximumLifetime:   adminEventMaximumLifetime,
		operationTimeout:  adminEventOperationTimeout,
		now:               time.Now,
	}
}

func (settings adminEventStreamSettings) valid() bool {
	return settings.pollInterval > 0 && settings.heartbeatInterval > 0 &&
		settings.maximumLifetime > 0 && settings.operationTimeout > 0 && settings.now != nil
}

func (api *API) adminEvents(w http.ResponseWriter, r *http.Request) {
	if !onlyQueryKeys(r, "environment_id") {
		api.writeProblem(w, r, invalidRequest("The administrative event-stream query is invalid."))
		return
	}
	environmentID, ok := optionalQueryValue(r, "environment_id")
	if !ok || (environmentID != "" && id.Validate(environmentID, id.Environment) != nil) {
		api.writeProblem(w, r, invalidRequest("The event-stream environment identifier is invalid."))
		return
	}
	if api.events == nil || api.eventPrincipals == nil || !api.eventStream.valid() {
		api.internal(w, r, errors.New("administrative event stream is unavailable"))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		api.internal(w, r, errors.New("administrative event stream requires response flushing"))
		return
	}
	operationContext, cancelOperation := context.WithTimeout(r.Context(), api.eventStream.operationTimeout)
	principal, err := api.eventPrincipals.RevalidatePrincipal(operationContext, mustPrincipal(r.Context()))
	var initial adminEventSnapshot
	if err == nil {
		initial, err = api.events.snapshot(operationContext, principal, environmentID)
	}
	cancelOperation()
	if err != nil {
		if errors.Is(err, adminauth.ErrAdminAuthentication) {
			api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "Administrator authentication is required."})
			return
		}
		api.handleOperationalError(w, r, err, "")
		return
	}
	api.streamAdminEvents(w, r, flusher, principal, environmentID, initial)
}

func (api *API) streamAdminEvents(
	w http.ResponseWriter,
	r *http.Request,
	flusher http.Flusher,
	principal adminauth.Principal,
	environmentID string,
	initial adminEventSnapshot,
) {
	lifetime := api.eventStream.maximumLifetime
	now := api.eventStream.now()
	if principal.CredentialExpiresAt != nil {
		remaining := principal.CredentialExpiresAt.Sub(now)
		if remaining <= 0 {
			api.writeProblem(w, r, problem.Error{Code: "authentication_required", Detail: "Administrator authentication is required."})
			return
		}
		if remaining < lifetime {
			lifetime = remaining
		}
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := writeAdminEvent(w, "ready", map[string]any{
		"stream_version": adminEventStreamVersion,
		"topics":         adminEventTopics[:],
	}); err != nil {
		return
	}
	if _, err := fmt.Fprintf(w, "retry: %d\n\n", adminEventReconnectMillis); err != nil {
		return
	}
	flusher.Flush()

	poll := time.NewTicker(api.eventStream.pollInterval)
	heartbeat := time.NewTicker(api.eventStream.heartbeatInterval)
	streamContext, cancelStream := context.WithTimeout(r.Context(), lifetime)
	defer cancelStream()
	defer poll.Stop()
	defer heartbeat.Stop()

	previous := initial
	for {
		select {
		case <-streamContext.Done():
			if r.Context().Err() == nil {
				_ = writeAdminEvent(w, "reconnect", map[string]any{"reauthenticate": true})
				flusher.Flush()
			}
			return
		case <-poll.C:
			operationContext, cancelOperation := context.WithTimeout(streamContext, api.eventStream.operationTimeout)
			refreshed, principalErr := api.eventPrincipals.RevalidatePrincipal(operationContext, principal)
			var next adminEventSnapshot
			var snapshotErr error
			if principalErr == nil {
				next, snapshotErr = api.events.snapshot(operationContext, refreshed, environmentID)
			}
			cancelOperation()
			if streamContext.Err() != nil {
				if r.Context().Err() == nil {
					_ = writeAdminEvent(w, "reconnect", map[string]any{"reauthenticate": true})
					flusher.Flush()
				}
				return
			}
			if errors.Is(principalErr, adminauth.ErrAdminAuthentication) ||
				errors.Is(snapshotErr, errOperationalForbidden) {
				_ = writeAdminEvent(w, "reconnect", map[string]any{"reauthenticate": true})
				flusher.Flush()
				return
			}
			if principalErr != nil {
				snapshotErr = principalErr
			}
			if snapshotErr != nil {
				_ = writeAdminEvent(w, "unavailable", map[string]any{"retry": true})
				flusher.Flush()
				return
			}
			principal = refreshed
			topics := changedAdminEventTopics(previous, next)
			previous = next
			if len(topics) == 0 {
				continue
			}
			if err := writeAdminEvent(w, "refresh", map[string]any{"topics": topics}); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeAdminEvent(w http.ResponseWriter, eventType string, data any) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode administrative event: %w", err)
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, encoded)
	return err
}

func changedAdminEventTopics(previous, next adminEventSnapshot) []string {
	result := make([]string, 0, len(adminEventTopics))
	if previous.Requests != next.Requests {
		result = append(result, "requests")
	}
	if previous.Usage != next.Usage {
		result = append(result, "usage")
	}
	if previous.Configuration != next.Configuration {
		result = append(result, "configuration")
	}
	if previous.Audit != next.Audit {
		result = append(result, "audit")
	}
	if previous.SelfTests != next.SelfTests {
		result = append(result, "self_tests")
	}
	if previous.Health != next.Health {
		result = append(result, "health")
	}
	return result
}

func (store *operationalStore) snapshot(
	ctx context.Context,
	principal adminauth.Principal,
	environmentID string,
) (adminEventSnapshot, error) {
	if !validOperationalRead(principal) {
		return adminEventSnapshot{}, errOperationalForbidden
	}
	if environmentID != "" {
		if err := store.ensureEnvironment(ctx, principal.OrganizationID, environmentID); err != nil {
			return adminEventSnapshot{}, err
		}
	}

	var snapshot adminEventSnapshot
	err := store.pool.QueryRow(ctx, `
		SELECT
		    COALESCE((
		        SELECT concat_ws('|', count(*)::text,
		            COALESCE(max(requested_at)::text, ''),
		            COALESCE(max(dispatched_at)::text, ''),
		            COALESCE(max(completed_at)::text, ''),
		            count(*) FILTER (WHERE status = 'reserved'),
		            count(*) FILTER (WHERE status = 'dispatched'),
		            count(*) FILTER (WHERE status = 'streaming'),
		            count(*) FILTER (WHERE status IN ('succeeded', 'failed', 'cancelled', 'denied')))
		        FROM logical_requests
		        WHERE organization_id = $1 AND ($2 = '' OR environment_id = $2)
		    ), ''),
		    COALESCE((
		        SELECT concat_ws('|', count(*)::text, COALESCE(max(recorded_at)::text, ''))
		        FROM usage_records
		        WHERE organization_id = $1 AND ($2 = '' OR environment_id = $2)
		    ), ''),
		    COALESCE((
		        SELECT concat_ws('|', event.occurred_at::text, event.audit_event_id)
		        FROM audit_events AS event
		        WHERE event.organization_id = $1
		          AND ($2 = '' OR event.environment_id = $2)
		          AND event.outcome = 'succeeded'
		          AND event.action IN (
		              'admin.configuration_revision_create',
		              'admin.configuration_revision_update',
		              'admin.configuration_revision_validate',
		              'admin.configuration_activate',
		              'admin.configuration_rollback'
		          )
		        ORDER BY event.occurred_at DESC, event.audit_event_id DESC
		        LIMIT 1
		    ), ''),
		    COALESCE((
		        SELECT concat_ws('|', count(*)::text, COALESCE(max(recorded_at)::text, ''))
		        FROM audit_events
		        WHERE organization_id = $1 AND ($2 = '' OR environment_id = $2)
		    ), ''),
		    concat_ws('|',
		        COALESCE((
		            SELECT concat_ws(':', count(*)::text, COALESCE(max(updated_at)::text, ''))
		            FROM self_test_schedules
		            WHERE organization_id = $1 AND ($2 = '' OR environment_id = $2)
		        ), ''),
		        COALESCE((
		            SELECT concat_ws(':', count(*)::text, COALESCE(max(updated_at)::text, ''))
		            FROM jobs
		            WHERE organization_id = $1 AND job_type = 'run_scheduled_self_test'
		              AND ($2 = '' OR environment_id = $2)
		        ), '')
		    ),
		    concat_ws('|',
		        COALESCE((
		            SELECT concat_ws(':',
		                count(*) FILTER (WHERE heartbeat_at >= statement_timestamp() - interval '1 minute'),
		                count(*) FILTER (WHERE role = 'api' AND heartbeat_at >= statement_timestamp() - interval '1 minute'),
		                count(*) FILTER (WHERE role = 'worker' AND heartbeat_at >= statement_timestamp() - interval '1 minute'))
		            FROM runtime_instances
		        ), ''),
		        COALESCE((
		            SELECT concat_ws(':',
		                count(*) FILTER (WHERE status = 'pending'),
		                count(*) FILTER (WHERE status = 'running'),
		                count(*) FILTER (WHERE status = 'failed'),
		                count(*) FILTER (WHERE status = 'dead'))
		            FROM jobs
		            WHERE organization_id = $1 AND ($2 = '' OR environment_id = $2)
		        ), '')
		    )
	`, principal.OrganizationID, environmentID).Scan(
		&snapshot.Requests,
		&snapshot.Usage,
		&snapshot.Configuration,
		&snapshot.Audit,
		&snapshot.SelfTests,
		&snapshot.Health,
	)
	if err != nil {
		return adminEventSnapshot{}, fmt.Errorf("snapshot administrative events: %w", err)
	}
	return snapshot, nil
}
