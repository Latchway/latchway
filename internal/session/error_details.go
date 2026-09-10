package session

import (
	"errors"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
)

func environmentLookupFailure(err error, missingCode string) error {
	if errors.Is(err, ErrSessionScope) {
		return clientFailure(missingCode)
	}
	return clientFailure("server_not_ready")
}

func attestationClientFailure(err error) error {
	return &clientapi.DependencyError{
		Code: mapAttestationError(err), AttestationReason: attestation.ClientFailureReason(err),
	}
}
