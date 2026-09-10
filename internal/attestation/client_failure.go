package attestation

import "errors"

type invalidEvidenceError struct{ reason string }

func (failure *invalidEvidenceError) Error() string {
	return ErrInvalid.Error() + ": " + failure.reason
}
func (failure *invalidEvidenceError) Unwrap() error { return ErrInvalid }

// ClientFailureReason exposes only a closed set of coarse configuration and
// recovery categories. Never return wrapped errors, expected policy values,
// certificate hashes, decoded claims or evidence bytes to the client.
func ClientFailureReason(err error) string {
	if errors.Is(err, ErrStale) {
		return "evidence_stale"
	}
	if phase, ok := AppAttestFailurePhaseOf(err); ok {
		switch phase {
		case AppAttestFailurePhaseAttestationEnvironment:
			return "apple_environment_rejected"
		case AppAttestFailurePhaseAttestationExtensions:
			return "apple_signing_policy_rejected"
		}
	}
	var invalid *invalidEvidenceError
	if !errors.As(err, &invalid) {
		return ""
	}
	switch invalid.reason {
	case "play integrity application certificate":
		return "android_certificate_rejected"
	case "play integrity application version":
		return "android_version_rejected"
	case "play integrity device verdict":
		return "android_device_rejected"
	case "play integrity licensing verdict":
		return "android_license_rejected"
	case "play integrity testing response":
		return "android_testing_response_rejected"
	case "play integrity request or app binding":
		return "android_app_binding_rejected"
	default:
		return ""
	}
}
