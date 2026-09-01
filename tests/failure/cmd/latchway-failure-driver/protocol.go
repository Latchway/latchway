package main

import (
	"errors"
	"fmt"
)

const (
	driverSocket = "/tmp/latchway-failure-driver.sock"
)

var scenarioAssertions = map[string][]string{
	"live-process-kill-after-reservation": {
		"process_sigkill_observed",
		"reservation_was_durable_before_kill",
		"replacement_worker_reclaimed_reservation",
		"no_usage_recorded_for_undispatched_attempt",
		"hard_quota_not_overspent",
	},
	"live-process-kill-during-stream": {
		"sse_first_byte_observed_before_sigkill",
		"process_sigkill_observed",
		"replacement_api_and_worker_recovered",
		"reservation_settled_conservatively",
		"no_permanent_reservation",
		"hard_quota_not_overspent",
	},
	"live-database-outage-boundaries": {
		"database_network_cut_observed",
		"predispatch_outage_failed_closed",
		"no_upstream_dispatch_during_predispatch_outage",
		"settlement_outage_created_bounded_pending_usage",
		"worker_reconciled_pending_usage_after_restore",
		"no_permanent_reservation",
	},
	"live-graceful-shutdown-and-drain": {
		"sigterm_observed",
		"listener_rejected_new_work_during_drain",
		"nonstream_completed_or_terminated_within_drain_bound",
		"sse_completed_or_terminated_within_drain_bound",
		"process_exited_within_drain_bound",
		"no_permanent_reservation",
	},
	"live-upstream-and-client-disconnect": {
		"pre_response_upstream_disconnect_observed",
		"mid_sse_upstream_disconnect_observed",
		"downstream_client_cancel_observed",
		"one_terminal_attempt_per_case",
		"usage_provenance_bounded_per_case",
		"no_permanent_reservation",
	},
	"live-config-and-key-rotation-across-api-replicas": {
		"at_least_two_api_replicas_observed",
		"at_least_two_workers_observed",
		"load_balancer_routed_multiple_api_replicas",
		"configuration_revision_atomic_across_replicas",
		"signing_rotation_preserved_active_sessions",
		"gateway_signing_jwks_converged",
	},
}

var scenarioPhases = map[string][]string{
	"live-process-kill-after-reservation":              {"prepare", "after_fault", "verify"},
	"live-process-kill-during-stream":                  {"prepare", "after_fault", "verify"},
	"live-database-outage-boundaries":                  {"prepare", "during_fault", "after_fault", "verify"},
	"live-graceful-shutdown-and-drain":                 {"prepare", "during_fault", "after_fault", "verify"},
	"live-upstream-and-client-disconnect":              {"prepare", "inject", "after_fault", "verify"},
	"live-config-and-key-rotation-across-api-replicas": {"prepare", "inject", "after_fault", "verify"},
}

type phaseRequest struct {
	ScenarioID string `json:"scenario_id"`
	Phase      string `json:"phase"`
}

type phaseResponse struct {
	SchemaVersion int            `json:"schema_version"`
	ScenarioID    string         `json:"scenario_id"`
	Phase         string         `json:"phase"`
	Status        string         `json:"status"`
	Observations  map[string]any `json:"observations"`
	Assertions    []assertion    `json:"assertions,omitempty"`
}

type assertion struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

func expectedPhase(scenarioID string, ordinal int) (string, error) {
	phases, ok := scenarioPhases[scenarioID]
	if !ok || ordinal < 0 || ordinal >= len(phases) {
		return "", errors.New("failure driver phase sequence is invalid")
	}
	return phases[ordinal], nil
}

func phaseMarker(phase string) (string, error) {
	switch phase {
	case "prepare":
		return "boundary_ready", nil
	case "during_fault", "inject":
		return "fault_observed", nil
	case "after_fault":
		return "recovery_observed", nil
	case "verify":
		return "verification_complete", nil
	default:
		return "", fmt.Errorf("unknown failure-driver phase")
	}
}
