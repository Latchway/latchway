package attestation

import (
	"context"
	"errors"
	"net/http"
)

// FailureDiagnostic is an operator-only, closed diagnostic vocabulary. It must
// not contain error text, evidence, decoded claims, credentials or policy values.
// HTTPStatus is zero unless a trusted Google decode response supplied a bounded
// status; Phase is an existing App Attest phase or the fixed Google decode phase.
type FailureDiagnostic struct {
	Reason     string
	Phase      string
	HTTPStatus int
}

// FailureDiagnosticOf never interprets err.Error(). Only package-owned typed
// errors and sentinel identities can select a diagnostic. A nil error produces
// the zero value. This does not change public client error codes or details.
func FailureDiagnosticOf(err error) FailureDiagnostic {
	if err == nil {
		return FailureDiagnostic{}
	}
	diagnostic := FailureDiagnostic{Reason: "verification_failed"}
	if phase, ok := AppAttestFailurePhaseOf(err); ok {
		diagnostic.Phase = string(phase)
	}
	var httpFailure *playIntegrityHTTPFailure
	if errors.As(err, &httpFailure) && httpFailure != nil && validDiagnosticHTTPStatus(httpFailure.status) {
		diagnostic.HTTPStatus = httpFailure.status
		if diagnostic.Phase == "" {
			diagnostic.Phase = "google_decode"
		}
		switch httpFailure.status {
		case http.StatusBadRequest:
			diagnostic.Reason = "play_integrity_token_rejected"
		case http.StatusUnauthorized:
			diagnostic.Reason = "play_integrity_decode_unauthenticated"
		case http.StatusForbidden:
			diagnostic.Reason = "play_integrity_decode_permission_denied"
		case http.StatusTooManyRequests:
			diagnostic.Reason = "play_integrity_decode_rate_limited"
		default:
			if httpFailure.status >= 500 {
				diagnostic.Reason = "play_integrity_decode_service_unavailable"
			} else {
				diagnostic.Reason = "play_integrity_decode_http_error"
			}
		}
		return diagnostic
	}
	var recognition *playIntegrityAppRecognitionFailure
	if errors.As(err, &recognition) && recognition != nil {
		switch recognition.category {
		case "unrecognized":
			diagnostic.Reason = "play_integrity_app_unrecognized"
			return diagnostic
		case "unevaluated":
			diagnostic.Reason = "play_integrity_app_unevaluated"
			return diagnostic
		}
	}
	switch {
	case errors.Is(err, context.Canceled):
		diagnostic.Reason = "operation_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		diagnostic.Reason = "operation_timed_out"
	case errors.Is(err, ErrStale):
		diagnostic.Reason = "evidence_stale"
	case errors.Is(err, ErrConfiguration):
		diagnostic.Reason = "configuration_invalid"
	case errors.Is(err, ErrAppAttestKeyStore):
		diagnostic.Reason = "app_attest_key_store_unavailable"
	case errors.Is(err, ErrPlayIntegrityService), errors.Is(err, ErrFirebaseAppCheckService), errors.Is(err, ErrTurnstileService):
		diagnostic.Reason = "service_unavailable"
	case errors.Is(err, ErrUnsupported):
		diagnostic.Reason = "provider_unsupported"
	case errors.Is(err, ErrPlayIntegrityTokenRejected):
		diagnostic.Reason = "play_integrity_token_rejected"
	default:
		var invalid *invalidEvidenceError
		if errors.As(err, &invalid) && invalid != nil {
			diagnostic.Reason = invalidEvidenceDiagnosticReason(invalid.reason)
		} else if errors.Is(err, ErrInvalid) {
			diagnostic.Reason = "evidence_invalid"
		}
	}
	return diagnostic
}

// This explicit mapping is intentionally not derived from arbitrary input text.
// The source-coverage test requires every authored mobile/shared binding reason
// to have a reviewed machine category. Unknown reasons remain evidence_invalid.
func invalidEvidenceDiagnosticReason(reason string) string {
	switch reason {
	case "binding fields":
		return "binding_fields_invalid"
	case "binding version 1 scope":
		return "binding_version_scope_invalid"
	case "component attestation binding scope":
		return "component_binding_scope_invalid"
	case "challenge nonce":
		return "challenge_nonce_invalid"
	case "DPoP thumbprint":
		return "dpop_thumbprint_invalid"
	case "app attest context":
		return "app_attest_context_invalid"
	case "app attest binding scope":
		return "app_attest_binding_scope_invalid"
	case "app attest evidence shape":
		return "app_attest_evidence_shape_invalid"
	case "app attest credential certificate key":
		return "app_attest_credential_certificate_key_invalid"
	case "app attest credential binding":
		return "app_attest_credential_binding_invalid"
	case "app attest authenticator data":
		return "app_attest_authenticator_data_invalid"
	case "app attest environment":
		return "app_attest_environment_rejected"
	case "app attest extensions":
		return "app_attest_extensions_invalid"
	case "app attest nonce":
		return "app_attest_nonce_invalid"
	case "app attest key registration":
		return "app_attest_key_registration_invalid"
	case "app attest assertion authenticator data":
		return "app_attest_assertion_authenticator_data_invalid"
	case "app attest assertion key":
		return "app_attest_assertion_key_invalid"
	case "app attest assertion scope":
		return "app_attest_assertion_scope_invalid"
	case "app attest assertion counter":
		return "app_attest_assertion_counter_invalid"
	case "app attest assertion signature":
		return "app_attest_assertion_signature_invalid"
	case "app attest key identifier":
		return "app_attest_key_identifier_invalid"
	case "app attest client data hash":
		return "app_attest_client_data_hash_invalid"
	case "app attest attestation encoding":
		return "app_attest_attestation_encoding_invalid"
	case "app attest assertion encoding":
		return "app_attest_assertion_encoding_invalid"
	case "app attest attestation size":
		return "app_attest_attestation_size_invalid"
	case "app attest attestation CBOR":
		return "app_attest_attestation_cbor_invalid"
	case "app attest attestation shape":
		return "app_attest_attestation_shape_invalid"
	case "app attest certificate size":
		return "app_attest_certificate_size_invalid"
	case "app attest authenticator size":
		return "app_attest_authenticator_size_invalid"
	case "app attest authenticator flags":
		return "app_attest_authenticator_flags_invalid"
	case "app attest credential identifier":
		return "app_attest_credential_identifier_invalid"
	case "app attest credential public key":
		return "app_attest_credential_public_key_invalid"
	case "app attest assertion size":
		return "app_attest_assertion_size_invalid"
	case "app attest assertion CBOR":
		return "app_attest_assertion_cbor_invalid"
	case "app attest assertion shape":
		return "app_attest_assertion_shape_invalid"
	case "app attest assertion flags":
		return "app_attest_assertion_flags_invalid"
	case "app attest certificate chain":
		return "app_attest_certificate_chain_invalid"
	case "app attest credential certificate":
		return "app_attest_credential_certificate_invalid"
	case "app attest nonce extension":
		return "app_attest_nonce_extension_invalid"
	case "play integrity context":
		return "play_integrity_context_invalid"
	case "play integrity binding scope":
		return "play_integrity_binding_scope_invalid"
	case "play integrity evidence shape":
		return "play_integrity_evidence_shape_invalid"
	case "play integrity token":
		return "play_integrity_token_invalid"
	case "play integrity token rejection":
		return "play_integrity_token_rejected"
	case "play integrity request or app binding":
		return "play_integrity_app_binding_rejected"
	case "play integrity request freshness":
		return "play_integrity_request_freshness_invalid"
	case "play integrity application certificate":
		return "play_integrity_application_certificate_rejected"
	case "play integrity application version":
		return "play_integrity_application_version_rejected"
	case "play integrity device verdict":
		return "play_integrity_device_verdict_rejected"
	case "play integrity licensing verdict":
		return "play_integrity_licensing_verdict_rejected"
	case "play integrity testing response":
		return "play_integrity_testing_response_rejected"
	case "play integrity decode response size":
		return "play_integrity_decode_response_size_invalid"
	case "play integrity decode response JSON":
		return "play_integrity_decode_response_json_invalid"
	case "play integrity decode response shape":
		return "play_integrity_decode_response_shape_invalid"
	case "play integrity token payload":
		return "play_integrity_token_payload_invalid"
	case "play integrity request details":
		return "play_integrity_request_details_invalid"
	case "play integrity app details":
		return "play_integrity_app_details_invalid"
	case "play integrity device details":
		return "play_integrity_device_details_invalid"
	case "play integrity account details":
		return "play_integrity_account_details_invalid"
	case "play integrity request package":
		return "play_integrity_request_package_invalid"
	case "play integrity request hash":
		return "play_integrity_request_hash_invalid"
	case "play integrity request mode":
		return "play_integrity_request_mode_invalid"
	case "play integrity request timestamp":
		return "play_integrity_request_timestamp_invalid"
	case "play integrity app verdict":
		return "play_integrity_app_verdict_invalid"
	case "play integrity app package":
		return "play_integrity_app_package_invalid"
	case "play integrity app version":
		return "play_integrity_app_version_invalid"
	case "play integrity app certificate":
		return "play_integrity_app_certificate_invalid"
	case "play integrity testing details":
		return "play_integrity_testing_details_invalid"
	default:
		return "evidence_invalid"
	}
}

// HTTP failures retain only the status and a safe sentinel/existing invalid
// error. They never retain Google's response body, headers or transport error.
type playIntegrityHTTPFailure struct {
	status int
	cause  error
}

func (failure *playIntegrityHTTPFailure) Error() string { return failure.cause.Error() }
func (failure *playIntegrityHTTPFailure) Unwrap() error { return failure.cause }

func validDiagnosticHTTPStatus(status int) bool { return status >= 300 && status <= 599 }

func playIntegrityDecodeHTTPFailure(status int) error {
	cause := ErrPlayIntegrityService
	if status == http.StatusBadRequest {
		cause = ErrPlayIntegrityTokenRejected
	}
	if !validDiagnosticHTTPStatus(status) {
		return cause
	}
	return &playIntegrityHTTPFailure{status: status, cause: cause}
}

func retainPlayIntegrityHTTPDiagnostic(cause, decoderErr error) error {
	var failure *playIntegrityHTTPFailure
	if errors.As(decoderErr, &failure) && failure != nil && validDiagnosticHTTPStatus(failure.status) {
		return &playIntegrityHTTPFailure{status: failure.status, cause: cause}
	}
	return cause
}

type playIntegrityAppRecognitionFailure struct {
	category string
	cause    error
}

func (failure *playIntegrityAppRecognitionFailure) Error() string { return failure.cause.Error() }
func (failure *playIntegrityAppRecognitionFailure) Unwrap() error { return failure.cause }

// Preserve the original invalid error and therefore the existing client detail.
// Store only fixed categories, never arbitrary decoded appRecognitionVerdict.
func playIntegrityAppRecognitionDiagnostic(cause error, verdict string) error {
	switch verdict {
	case "UNRECOGNIZED_VERSION":
		return &playIntegrityAppRecognitionFailure{category: "unrecognized", cause: cause}
	case "UNEVALUATED":
		return &playIntegrityAppRecognitionFailure{category: "unevaluated", cause: cause}
	default:
		return cause
	}
}
