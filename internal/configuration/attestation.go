package configuration

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maximumConfiguredAppAttestBundleVersions = 64
	maximumConfiguredPlayCertificates        = 16
)

var (
	configuredAppAttestPrefixPattern  = regexp.MustCompile(`^[A-Z0-9]{1,64}$`)
	configuredAppAttestBundlePattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
	configuredAppAttestVersionPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?$`)
	configuredPlayPackagePattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
)

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

func runtimeAttestationProviderConfiguration(selection PlatformAttestation) bool {
	enabled := selection.Mode != "disabled"
	switch selection.Provider {
	case "app_attest":
		if selection.SecretRef != "" || selection.PlayIntegrity != nil ||
			(enabled && selection.AppAttest == nil) {
			return false
		}
		return selection.AppAttest == nil || validAppAttestConfiguration(selection.AppAttest)
	case "play_integrity":
		if selection.AppAttest != nil || (enabled && selection.PlayIntegrity == nil) {
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
	default:
		return selection.AppAttest == nil && selection.PlayIntegrity == nil
	}
}

func runtimeAttestationTrustCapability(selection PlatformAttestation) bool {
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
	default:
		return true
	}
}
