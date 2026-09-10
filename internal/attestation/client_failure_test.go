package attestation

import (
	"errors"
	"testing"
)

func TestClientAttestationReasonsAreClosedAndWrapped(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{invalid("play integrity application certificate"), "android_certificate_rejected"},
		{invalid("play integrity testing response"), "android_testing_response_rejected"},
		{invalid("SECRET provider evidence"), ""},
		{errors.New("play integrity application certificate"), ""},
		{appAttestFailure(AppAttestFailurePhaseAttestationEnvironment, ErrInvalid), "apple_environment_rejected"},
		{appAttestFailure(AppAttestFailurePhaseAssertionSignature, ErrInvalid), ""},
		{ErrStale, "evidence_stale"},
	} {
		if got := ClientFailureReason(test.err); got != test.want {
			t.Fatalf("reason = %q, want %q", got, test.want)
		}
	}
	if !errors.Is(invalid("reason"), ErrInvalid) || !errors.Is(ErrStale, ErrInvalid) {
		t.Fatal("attestation error identity lost")
	}
}
