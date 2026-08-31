package attestation

import "errors"

// AppAttestFailurePhase is a closed, redaction-safe verifier branch. Values
// contain no provider payload, credential, installation, principal, request,
// or policy identifiers and are suitable only for bounded operational
// telemetry. Client transports continue to map the wrapped cause to their
// existing generic problem code.
type AppAttestFailurePhase string

const (
	AppAttestFailurePhaseRequest                  AppAttestFailurePhase = "request"
	AppAttestFailurePhaseContext                  AppAttestFailurePhase = "context"
	AppAttestFailurePhaseBinding                  AppAttestFailurePhase = "binding"
	AppAttestFailurePhaseEvidence                 AppAttestFailurePhase = "evidence"
	AppAttestFailurePhaseClock                    AppAttestFailurePhase = "clock"
	AppAttestFailurePhaseAttestationObject        AppAttestFailurePhase = "attestation_object"
	AppAttestFailurePhaseCertificateChain         AppAttestFailurePhase = "certificate_chain"
	AppAttestFailurePhaseCredentialBinding        AppAttestFailurePhase = "credential_binding"
	AppAttestFailurePhaseAttestationAuthenticator AppAttestFailurePhase = "attestation_authenticator"
	AppAttestFailurePhaseAttestationEnvironment   AppAttestFailurePhase = "attestation_environment"
	AppAttestFailurePhaseAttestationExtensions    AppAttestFailurePhase = "attestation_extensions"
	AppAttestFailurePhaseAttestationNonce         AppAttestFailurePhase = "attestation_nonce"
	AppAttestFailurePhaseRegistration             AppAttestFailurePhase = "registration"
	AppAttestFailurePhaseAssertionObject          AppAttestFailurePhase = "assertion_object"
	AppAttestFailurePhaseAssertionAuthenticator   AppAttestFailurePhase = "assertion_authenticator"
	AppAttestFailurePhaseAssertionKey             AppAttestFailurePhase = "assertion_key"
	AppAttestFailurePhaseAssertionScope           AppAttestFailurePhase = "assertion_scope"
	AppAttestFailurePhaseAssertionCounter         AppAttestFailurePhase = "assertion_counter"
	AppAttestFailurePhaseAssertionSignature       AppAttestFailurePhase = "assertion_signature"
	AppAttestFailurePhaseKeyStore                 AppAttestFailurePhase = "key_store"
	AppAttestFailurePhaseResult                   AppAttestFailurePhase = "result"
)

type appAttestFailureError struct {
	phase AppAttestFailurePhase
	cause error
}

func (failure *appAttestFailureError) Error() string { return failure.cause.Error() }
func (failure *appAttestFailureError) Unwrap() error { return failure.cause }

func appAttestFailure(phase AppAttestFailurePhase, cause error) error {
	if cause == nil {
		return nil
	}
	var existing *appAttestFailureError
	if errors.As(cause, &existing) {
		return cause
	}
	if !validAppAttestFailurePhase(phase) {
		return cause
	}
	return &appAttestFailureError{phase: phase, cause: cause}
}

// AppAttestFailurePhaseOf extracts only the closed verifier phase while
// preserving errors.Is/errors.As behavior for the original failure. Errors
// from other providers and failures outside the App Attest verifier return
// false and must not create a provider-phase metric.
func AppAttestFailurePhaseOf(err error) (AppAttestFailurePhase, bool) {
	var failure *appAttestFailureError
	if !errors.As(err, &failure) || failure == nil || !validAppAttestFailurePhase(failure.phase) {
		return "", false
	}
	return failure.phase, true
}

func validAppAttestFailurePhase(phase AppAttestFailurePhase) bool {
	switch phase {
	case AppAttestFailurePhaseRequest,
		AppAttestFailurePhaseContext,
		AppAttestFailurePhaseBinding,
		AppAttestFailurePhaseEvidence,
		AppAttestFailurePhaseClock,
		AppAttestFailurePhaseAttestationObject,
		AppAttestFailurePhaseCertificateChain,
		AppAttestFailurePhaseCredentialBinding,
		AppAttestFailurePhaseAttestationAuthenticator,
		AppAttestFailurePhaseAttestationEnvironment,
		AppAttestFailurePhaseAttestationExtensions,
		AppAttestFailurePhaseAttestationNonce,
		AppAttestFailurePhaseRegistration,
		AppAttestFailurePhaseAssertionObject,
		AppAttestFailurePhaseAssertionAuthenticator,
		AppAttestFailurePhaseAssertionKey,
		AppAttestFailurePhaseAssertionScope,
		AppAttestFailurePhaseAssertionCounter,
		AppAttestFailurePhaseAssertionSignature,
		AppAttestFailurePhaseKeyStore,
		AppAttestFailurePhaseResult:
		return true
	default:
		return false
	}
}
