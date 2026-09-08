package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	ProviderRejectionAccountingV1 = "provider_rejection_v1"
	ReportedUsageAccountingV1     = "reported_usage_v1"
)

// AttemptDiagnostics is a value-only sidecar. The policy is written atomically
// with settlement so replay never reinterprets historical failed attempts.
type AttemptDiagnostics struct {
	AccountingPolicy string                            `json:"accounting_policy,omitempty"`
	ProviderError    upstream.ProviderErrorDiagnostics `json:"provider_error"`
}

func validateAttemptDiagnostics(outcome Outcome) error {
	d := outcome.Diagnostics
	if d == nil {
		if outcome.FailureCode == "upstream_request_rejected" {
			return ErrInvalidInput
		}
		return nil
	}
	if outcome.Status == AttemptSucceeded {
		return ErrInvalidInput
	}
	if d.ProviderError.Validate() != nil {
		return ErrInvalidInput
	}
	switch d.AccountingPolicy {
	case "":
		if d.ProviderError == (upstream.ProviderErrorDiagnostics{}) || outcome.FailureCode == "upstream_request_rejected" {
			return ErrInvalidInput
		}
	case ProviderRejectionAccountingV1:
		if outcome.Status != AttemptFailed || outcome.HTTPStatus != 400 || outcome.FailureCode != "upstream_request_rejected" || outcome.Usage.Known || outcome.Cost.Known {
			return ErrInvalidInput
		}
		switch d.ProviderError.Category {
		case "invalid_request", "invalid_prompt", "context_length_exceeded", "string_too_long", "invalid_image", "unsupported_image_format":
		default:
			return ErrInvalidInput
		}
	case ReportedUsageAccountingV1:
		if outcome.Status == AttemptSucceeded || !outcome.Usage.Known || outcome.FailureCode == "upstream_request_rejected" {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func providerRejectedBeforeGeneration(outcome Outcome) bool {
	return outcome.Diagnostics != nil && outcome.Diagnostics.AccountingPolicy == ProviderRejectionAccountingV1
}

// The owning attempt is already locked by settlement/replay. Check both
// durable observation timestamps, not only a caller's value-only classification.
// This query is limited to the rejection policy and adds no round trip to
// successful requests, ordinary failures, or historical replay.
func rejectionObservationStateMatches(ctx context.Context, tx pgx.Tx, reservation lockedReservation, attemptID string, outcome Outcome) (bool, error) {
	if !providerRejectedBeforeGeneration(outcome) {
		return true, nil
	}
	var unobserved bool
	if err := tx.QueryRow(ctx, `SELECT first_byte_at IS NULL AND first_token_at IS NULL
		FROM upstream_attempts WHERE organization_id=$1 AND application_id=$2
		AND environment_id=$3 AND upstream_attempt_id=$4`, reservation.organizationID,
		reservation.applicationID, reservation.environmentID, attemptID).Scan(&unobserved); err != nil {
		return false, persistenceFailure("validate rejected attempt observation state", err)
	}
	return unobserved, nil
}

func usesReportedTokenSettlement(outcome Outcome) bool {
	return outcome.Usage.Known && (outcome.Status == AttemptSucceeded ||
		outcome.Diagnostics != nil && outcome.Diagnostics.AccountingPolicy == ReportedUsageAccountingV1)
}

func rejectedUsageProvenanceKey(attemptID, metric string) string {
	return "quota-attempt:" + attemptID + ":rejected-" + metric
}

func insertAttemptDiagnostics(ctx context.Context, tx pgx.Tx, reservation lockedReservation, attempt storedAttempt, outcome Outcome) error {
	if outcome.Diagnostics == nil {
		return nil
	}
	body, err := json.Marshal(outcome.Diagnostics.ProviderError)
	if err != nil {
		return ErrInvalidInput
	}
	_, err = tx.Exec(ctx, `INSERT INTO upstream_attempt_diagnostics
		(upstream_attempt_id, organization_id, application_id, environment_id, accounting_policy, provider_error)
		VALUES ($1,$2,$3,$4,$5,$6)`, attempt.id, reservation.organizationID, reservation.applicationID,
		reservation.environmentID, outcome.Diagnostics.AccountingPolicy, body)
	if err != nil {
		return persistenceFailure("insert safe attempt diagnostics", err)
	}
	return nil
}

func loadAttemptDiagnostics(ctx context.Context, tx pgx.Tx, reservation lockedReservation, attemptID string) (*AttemptDiagnostics, error) {
	var result AttemptDiagnostics
	var body []byte
	err := tx.QueryRow(ctx, `SELECT accounting_policy, provider_error FROM upstream_attempt_diagnostics
		WHERE organization_id=$1 AND application_id=$2 AND environment_id=$3 AND upstream_attempt_id=$4`,
		reservation.organizationID, reservation.applicationID, reservation.environmentID, attemptID).Scan(&result.AccountingPolicy, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, persistenceFailure("load safe attempt diagnostics", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if len(body) > 2048 || decoder.Decode(&result.ProviderError) != nil || result.ProviderError.Validate() != nil {
		return nil, ErrInvalidState
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrInvalidState
	}
	return &result, nil
}

func sameAttemptDiagnostics(left, right *AttemptDiagnostics) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
