package session

import (
	"errors"
	"fmt"
	"testing"

	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
)

func TestEnvironmentLookupDoesNotRevokeOnDependencyFailure(t *testing.T) {
	for _, terminal := range []string{"session_revoked", "conflict"} {
		for _, test := range []struct {
			err  error
			code string
		}{
			{ErrSessionScope, terminal}, {fmt.Errorf("wrapped: %w", ErrSessionScope), terminal},
			{errors.New("private database outage details"), "server_not_ready"},
		} {
			var failure *clientapi.DependencyError
			if !errors.As(environmentLookupFailure(test.err, terminal), &failure) || failure.Code != test.code {
				t.Fatalf("mapping = %+v", failure)
			}
		}
	}
}

func TestStaleAttestationMapsToExistingRecoveryCode(t *testing.T) {
	var failure *clientapi.DependencyError
	if !errors.As(attestationClientFailure(attestation.ErrStale), &failure) || failure.Code != "attestation_stale" || failure.AttestationReason != "evidence_stale" {
		t.Fatalf("stale mapping: %+v", failure)
	}
}
