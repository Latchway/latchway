package configuration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maximumConfiguredAppAttestBundleVersions = 64
	maximumConfiguredPlayCertificates        = 16
	maximumConfiguredFirebaseAppIDs          = 32
	maximumConfiguredTurnstileHostnames      = 32
	maximumConfiguredWebOrigins              = 32
	maximumConfiguredWebOriginBytes          = 2_048
)

var (
	configuredAppAttestPrefixPattern       = regexp.MustCompile(`^[A-Z0-9]{1,64}$`)
	configuredAppAttestBundlePattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
	configuredAppAttestVersionPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?$`)
	configuredPlayPackagePattern           = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
	configuredFirebaseProjectNumberPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	configuredTurnstileHostnamePattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	configuredTurnstileActionPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

func (selection *PlatformAttestation) UnmarshalJSON(encoded []byte) error {
	*selection = PlatformAttestation{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"provider": {}, "mode": {}, "minimumTrustLevel": {},
		"applicationIdentifiers": {}, "allowedOrigins": {}, "secretRef": {},
		"dangerousAllowInProduction": {}, "appAttest": {}, "playIntegrity": {},
		"firebaseAppCheck": {}, "turnstile": {},
	})
	if err != nil {
		return err
	}
	for _, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrInvalid
		}
	}
	type plainPlatformAttestation PlatformAttestation
	var decoded plainPlatformAttestation
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return ErrInvalid
	}
	*selection = PlatformAttestation(decoded)
	return nil
}

func (configuration *FirebaseAppCheckConfiguration) UnmarshalJSON(encoded []byte) error {
	*configuration = FirebaseAppCheckConfiguration{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"projectNumber": {}, "allowedAppIds": {},
	})
	if err != nil {
		return err
	}
	for _, required := range []string{"projectNumber", "allowedAppIds"} {
		if _, ok := fields[required]; !ok {
			return ErrInvalid
		}
	}
	if configuration.ProjectNumber, err = compiledJSONString(fields["projectNumber"]); err != nil {
		return err
	}
	if configuration.AllowedAppIDs, err = compiledAttestationStringArray(fields["allowedAppIds"]); err != nil {
		return err
	}
	return nil
}

func (configuration *TurnstileConfiguration) UnmarshalJSON(encoded []byte) error {
	*configuration = TurnstileConfiguration{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"allowedHostnames": {}, "expectedAction": {},
	})
	if err != nil {
		return err
	}
	for _, required := range []string{"allowedHostnames", "expectedAction"} {
		if _, ok := fields[required]; !ok {
			return ErrInvalid
		}
	}
	if configuration.AllowedHostnames, err = compiledAttestationStringArray(fields["allowedHostnames"]); err != nil {
		return err
	}
	if configuration.ExpectedAction, err = compiledJSONString(fields["expectedAction"]); err != nil {
		return err
	}
	return nil
}

func compiledAttestationStringArray(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, ErrInvalid
	}
	var values []string
	if err := json.Unmarshal(trimmed, &values); err != nil || values == nil {
		return nil, ErrInvalid
	}
	return values, nil
}

func validAppAttestConfiguration(configuration *AppAttestConfiguration) bool {
	if configuration == nil ||
		!configuredAppAttestPrefixPattern.MatchString(configuration.AppIDPrefix) ||
		!validConfiguredBundleID(configuration.BundleID) ||
		(configuration.Environment != "development" && configuration.Environment != "production") ||
		len(configuration.AllowedValidationCategories) == 0 ||
		len(configuration.AllowedValidationCategories) > 7 ||
		len(configuration.AllowedBundleVersions) == 0 ||
		len(configuration.AllowedBundleVersions) > maximumConfiguredAppAttestBundleVersions {
		return false
	}
	categories := make(map[uint32]struct{}, len(configuration.AllowedValidationCategories))
	for _, category := range configuration.AllowedValidationCategories {
		switch category {
		case 1, 2, 3, 4, 5, 6, 10:
		default:
			return false
		}
		if _, duplicate := categories[category]; duplicate {
			return false
		}
		categories[category] = struct{}{}
	}
	versions := make(map[string]struct{}, len(configuration.AllowedBundleVersions))
	for _, version := range configuration.AllowedBundleVersions {
		if !validConfiguredBundleVersion(version) {
			return false
		}
		if _, duplicate := versions[version]; duplicate {
			return false
		}
		versions[version] = struct{}{}
	}
	return true
}

func validConfiguredBundleID(bundleID string) bool {
	return utf8.RuneCountInString(bundleID) <= 255 && configuredAppAttestBundlePattern.MatchString(bundleID) &&
		!strings.Contains(bundleID, "..") && !strings.Contains(bundleID, ".-") && !strings.Contains(bundleID, "-.")
}

func validConfiguredBundleVersion(version string) bool {
	return utf8.RuneCountInString(version) <= 128 && configuredAppAttestVersionPattern.MatchString(version) &&
		!strings.Contains(version, "..")
}

func validPlayIntegrityConfiguration(configuration *PlayIntegrityConfiguration) bool {
	if configuration == nil || !configuredPlayPackagePattern.MatchString(configuration.PackageName) ||
		utf8.RuneCountInString(configuration.PackageName) > 255 ||
		configuration.CloudProjectNumber <= 0 ||
		(configuration.MinimumDeviceIntegrity != "device" && configuration.MinimumDeviceIntegrity != "strong") ||
		configuration.MinimumVersionCode < 0 || configuration.MaximumVersionCode < 0 ||
		(configuration.MaximumVersionCode != 0 &&
			(configuration.MinimumVersionCode == 0 || configuration.MaximumVersionCode < configuration.MinimumVersionCode)) ||
		(configuration.CredentialSource != "metadata" && configuration.CredentialSource != "service_account") ||
		len(configuration.CertificateSHA256Digests) == 0 ||
		len(configuration.CertificateSHA256Digests) > maximumConfiguredPlayCertificates {
		return false
	}
	digests := make(map[[sha256.Size]byte]struct{}, len(configuration.CertificateSHA256Digests))
	for _, encoded := range configuration.CertificateSHA256Digests {
		digest, ok := configuredPlayCertificateDigest(encoded)
		if !ok {
			return false
		}
		if _, duplicate := digests[digest]; duplicate {
			return false
		}
		digests[digest] = struct{}{}
	}
	return true
}

func configuredPlayCertificateDigest(encoded string) ([sha256.Size]byte, bool) {
	var result [sha256.Size]byte
	if len(encoded) != 43 && len(encoded) != 44 {
		return result, false
	}
	encoding := base64.RawURLEncoding.Strict()
	if len(encoded) == 44 {
		if encoded[43] != '=' {
			return result, false
		}
		encoding = base64.URLEncoding.Strict()
	}
	decoded, err := encoding.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return result, false
	}
	copy(result[:], decoded)
	return result, result != ([sha256.Size]byte{})
}

func validFirebaseAppCheckConfiguration(configuration *FirebaseAppCheckConfiguration) bool {
	if configuration == nil || !validConfiguredFirebaseProjectNumber(configuration.ProjectNumber) ||
		len(configuration.AllowedAppIDs) == 0 ||
		len(configuration.AllowedAppIDs) > maximumConfiguredFirebaseAppIDs {
		return false
	}
	appIDs := make(map[string]struct{}, len(configuration.AllowedAppIDs))
	for _, appID := range configuration.AllowedAppIDs {
		if !validConfiguredFirebaseAppID(appID) {
			return false
		}
		if _, duplicate := appIDs[appID]; duplicate {
			return false
		}
		appIDs[appID] = struct{}{}
	}
	return true
}

func validConfiguredFirebaseProjectNumber(projectNumber string) bool {
	if !configuredFirebaseProjectNumberPattern.MatchString(projectNumber) {
		return false
	}
	_, err := strconv.ParseUint(projectNumber, 10, 64)
	return err == nil
}

func validConfiguredFirebaseAppID(appID string) bool {
	if len(appID) < 5 || len(appID) > 256 || strings.TrimSpace(appID) != appID ||
		strings.ContainsAny(appID, "\r\n\x00") {
		return false
	}
	for _, character := range appID {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func validTurnstileConfiguration(configuration *TurnstileConfiguration) bool {
	if configuration == nil || len(configuration.AllowedHostnames) == 0 ||
		len(configuration.AllowedHostnames) > maximumConfiguredTurnstileHostnames ||
		!configuredTurnstileActionPattern.MatchString(configuration.ExpectedAction) {
		return false
	}
	hostnames := make(map[string]struct{}, len(configuration.AllowedHostnames))
	for _, hostname := range configuration.AllowedHostnames {
		if !validConfiguredTurnstileHostname(hostname) {
			return false
		}
		if _, duplicate := hostnames[hostname]; duplicate {
			return false
		}
		hostnames[hostname] = struct{}{}
	}
	return true
}

func validConfiguredTurnstileHostname(hostname string) bool {
	if len(hostname) > 253 || hostname != strings.ToLower(hostname) ||
		!configuredTurnstileHostnamePattern.MatchString(hostname) || strings.Contains(hostname, "..") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func runtimeAttestationProviderConfiguration(selection PlatformAttestation) bool {
	enabled := selection.Mode != "disabled"
	switch selection.Provider {
	case "app_attest":
		if selection.SecretRef != "" || selection.PlayIntegrity != nil ||
			selection.FirebaseAppCheck != nil || selection.Turnstile != nil ||
			(enabled && selection.AppAttest == nil) {
			return false
		}
		return selection.AppAttest == nil || validAppAttestConfiguration(selection.AppAttest)
	case "play_integrity":
		if selection.AppAttest != nil || selection.FirebaseAppCheck != nil || selection.Turnstile != nil ||
			(enabled && selection.PlayIntegrity == nil) {
			return false
		}
		if selection.PlayIntegrity == nil {
			return selection.SecretRef == ""
		}
		if !validPlayIntegrityConfiguration(selection.PlayIntegrity) {
			return false
		}
		if selection.PlayIntegrity.CredentialSource == "metadata" {
			return selection.SecretRef == ""
		}
		return runtimeSecretRefPattern.MatchString(selection.SecretRef)
	case "firebase_app_check":
		if selection.SecretRef != "" || selection.AppAttest != nil || selection.PlayIntegrity != nil ||
			selection.Turnstile != nil || (enabled && selection.FirebaseAppCheck == nil) {
			return false
		}
		return selection.FirebaseAppCheck == nil || validFirebaseAppCheckConfiguration(selection.FirebaseAppCheck)
	case "turnstile":
		if selection.AppAttest != nil || selection.PlayIntegrity != nil || selection.FirebaseAppCheck != nil ||
			(enabled && selection.Turnstile == nil) {
			return false
		}
		if selection.Turnstile == nil {
			return selection.SecretRef == ""
		}
		if !validTurnstileConfiguration(selection.Turnstile) {
			return false
		}
		if !enabled {
			return selection.SecretRef == ""
		}
		return runtimeSecretRefPattern.MatchString(selection.SecretRef)
	default:
		return selection.AppAttest == nil && selection.PlayIntegrity == nil &&
			selection.FirebaseAppCheck == nil && selection.Turnstile == nil
	}
}

func runtimeAttestationTrustCapability(platform string, selection PlatformAttestation) bool {
	if selection.Mode == "disabled" {
		return true
	}
	switch selection.Provider {
	case "app_attest":
		return selection.MinimumTrustLevel == "app_verified"
	case "play_integrity":
		if selection.PlayIntegrity == nil {
			return false
		}
		if selection.PlayIntegrity.MinimumDeviceIntegrity == "strong" {
			return selection.MinimumTrustLevel == "strong_device_verified"
		}
		return selection.MinimumTrustLevel == "device_verified"
	case "firebase_app_check":
		if selection.FirebaseAppCheck == nil {
			return false
		}
		if platform == "web" {
			return selection.MinimumTrustLevel == "web_risk_verified"
		}
		return selection.MinimumTrustLevel == "app_verified"
	case "turnstile":
		return selection.Turnstile != nil && platform == "web" &&
			selection.MinimumTrustLevel == "web_risk_verified"
	case "debug":
		return selection.MinimumTrustLevel == "debug"
	default:
		return false
	}
}
