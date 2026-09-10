package clientapi

// Every message is server-authored. Reason strings are never reflected unless
// both the canonical code and the closed diagnostic selection are valid.
func attestationFailureDetail(code, reason string) (string, bool) {
	if code == "attestation_stale" && reason == "evidence_stale" {
		return "The attestation evidence is too old. Request a new challenge and generate fresh evidence.", true
	}
	if code != "attestation_invalid" {
		return "", false
	}
	switch reason {
	case "apple_environment_rejected":
		return "App Attest evidence is from an environment not accepted by this app configuration. Check the signed App Attest entitlement and the gateway environment policy.", true
	case "apple_signing_policy_rejected":
		return "App Attest evidence does not satisfy the configured signing policy. Check the build signing category and the gateway policy.", true
	case "android_certificate_rejected":
		return "Play Integrity evidence has an application signing certificate not accepted by the gateway. Check the installed build and configured certificate digests.", true
	case "android_version_rejected":
		return "Play Integrity evidence has an application version not accepted by the gateway. Check the installed build and configured version policy.", true
	case "android_device_rejected":
		return "The device does not satisfy the configured Play Integrity device requirements. Use an eligible device or ask the administrator to review the policy.", true
	case "android_license_rejected":
		return "Play Integrity licensing does not satisfy the app policy. Check the Google Play installation and tester account.", true
	case "android_testing_response_rejected":
		return "Google Play returned testing evidence, but this gateway environment does not accept testing responses. Use real evidence or an explicitly enabled development environment.", true
	case "android_app_binding_rejected":
		return "Play Integrity could not verify the application and request binding. Check the package and Play recognition, then create fresh evidence for a new challenge.", true
	default:
		return "", false
	}
}
