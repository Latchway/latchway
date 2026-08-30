package configuration

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

type compiledSnapshotDocument struct {
	Spec struct {
		Session struct {
			AccessTokenTTL          string `json:"accessTokenTtl"`
			ChallengeTTL            string `json:"challengeTtl"`
			RefreshTokenTTL         string `json:"refreshTokenTtl"`
			MaximumClockSkewSeconds *int   `json:"maximumClockSkewSeconds"`
		} `json:"session"`
		IdentityProviders []IdentityProvider               `json:"identityProviders"`
		AttestationPolicy []compiledAttestationPolicy      `json:"attestationPolicies"`
		Upstreams         []compiledUpstream               `json:"upstreams"`
		Models            []compiledModel                  `json:"models"`
		InputAccounting   []compiledInputAccountingProfile `json:"inputAccountingProfiles"`
		PricingCatalogs   []compiledPricingCatalog         `json:"pricingCatalogs"`
		LimitPlans        []compiledLimitPlan              `json:"limitPlans"`
		Features          []compiledFeature                `json:"features"`
	} `json:"spec"`
}

type compiledAttestationPolicy struct {
	ID        string                         `json:"id"`
	MaxAge    string                         `json:"maxAge"`
	Platforms map[string]PlatformAttestation `json:"platforms"`
}

func newActiveSnapshot(revisionID, environmentID string, document, compiled json.RawMessage) (ActiveSnapshot, error) {
	var parsed compiledSnapshotDocument
	if err := json.Unmarshal(compiled, &parsed); err != nil {
		return ActiveSnapshot{}, fmt.Errorf("decode compiled active configuration: %w", err)
	}
	session, err := compiledSessionPolicy(parsed)
	if err != nil {
		return ActiveSnapshot{}, err
	}
	snapshot := ActiveSnapshot{
		RevisionID: revisionID, EnvironmentID: environmentID,
		document:        append(json.RawMessage(nil), document...),
		compiled:        append(json.RawMessage(nil), compiled...),
		session:         session,
		identities:      make(map[string]IdentityProvider, len(parsed.Spec.IdentityProviders)),
		attestations:    make(map[string]AttestationPolicy, len(parsed.Spec.AttestationPolicy)),
		upstreams:       make(map[string]Upstream, len(parsed.Spec.Upstreams)),
		models:          make(map[string]Model, len(parsed.Spec.Models)),
		inputAccounting: make(map[string]InputAccountingProfile, len(parsed.Spec.InputAccounting)),
		pricing:         make(map[string]PricingCatalog, len(parsed.Spec.PricingCatalogs)),
		limitPlans:      make(map[string]LimitPlan, len(parsed.Spec.LimitPlans)),
		features:        make(map[string]Feature, len(parsed.Spec.Features)),
	}
	for _, provider := range parsed.Spec.IdentityProviders {
		if provider.ID == "" {
			return ActiveSnapshot{}, errorsCorruptSnapshot("identity provider ID")
		}
		snapshot.identities[provider.ID] = provider.clone()
	}
	if len(parsed.Spec.AttestationPolicy) == 0 || len(parsed.Spec.AttestationPolicy) > 32 {
		return ActiveSnapshot{}, errorsCorruptSnapshot("attestation policy set")
	}
	requiredPolicyByPlatform := make(map[string]string)
	for _, rawPolicy := range parsed.Spec.AttestationPolicy {
		policy, policyErr := runtimeAttestationPolicy(rawPolicy)
		if policyErr != nil || !insertUnique(snapshot.attestations, policy.ID, policy) {
			return ActiveSnapshot{}, errorsCorruptSnapshot("attestation policy")
		}
		for platform, selection := range policy.Platforms {
			if selection.Mode != "required" {
				continue
			}
			if _, exists := requiredPolicyByPlatform[platform]; exists {
				return ActiveSnapshot{}, errorsCorruptSnapshot("ambiguous required attestation policy")
			}
			requiredPolicyByPlatform[platform] = policy.ID
		}
	}
	if err := snapshot.loadRuntimeConfiguration(
		parsed.Spec.Upstreams,
		parsed.Spec.InputAccounting,
		parsed.Spec.Models,
		parsed.Spec.PricingCatalogs,
		parsed.Spec.LimitPlans,
		parsed.Spec.Features,
	); err != nil {
		return ActiveSnapshot{}, err
	}
	return snapshot, nil
}

func runtimeAttestationPolicy(raw compiledAttestationPolicy) (AttestationPolicy, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) || raw.MaxAge == "" || len(raw.Platforms) == 0 || len(raw.Platforms) > 6 {
		return AttestationPolicy{}, ErrInvalid
	}
	maxAge, err := parseConfigDuration(raw.MaxAge)
	if err != nil || maxAge < time.Minute || maxAge > 30*24*time.Hour {
		return AttestationPolicy{}, ErrInvalid
	}
	policy := AttestationPolicy{ID: raw.ID, MaxAge: maxAge, Platforms: make(map[string]PlatformAttestation, len(raw.Platforms))}
	for platform, selection := range raw.Platforms {
		if !runtimeAttestationSelection(platform, selection) {
			return AttestationPolicy{}, ErrInvalid
		}
		policy.Platforms[platform] = selection.clone()
	}
	return policy, nil
}

func runtimeAttestationSelection(platform string, selection PlatformAttestation) bool {
	if !runtimeAttestationPlatform(platform) ||
		!providerAllowedOnPlatform(selection.Provider, platform) ||
		!runtimeAttestationMode(selection.Mode) ||
		!runtimeAttestationTrust(selection.MinimumTrustLevel) ||
		(selection.Mode == "required" && selection.MinimumTrustLevel == "none") ||
		(selection.SecretRef != "" && !runtimeSecretRefPattern.MatchString(selection.SecretRef)) ||
		(selection.Provider == "debug" && selection.Mode != "disabled" && selection.SecretRef == "") ||
		(selection.Mode != "disabled" && len(selection.ApplicationIdentifiers) != 0) ||
		!runtimeAttestationProviderConfiguration(selection) ||
		!runtimeAttestationTrustCapability(platform, selection) ||
		!runtimeAttestationAllowedOrigins(platform, selection) {
		return false
	}
	return runtimeAttestationStrings(selection.ApplicationIdentifiers, 256, false)
}

func runtimeAttestationAllowedOrigins(platform string, selection PlatformAttestation) bool {
	enabledWeb := selection.Mode != "disabled" && platform == "web"
	if !enabledWeb {
		return len(selection.AllowedOrigins) == 0
	}
	return len(selection.AllowedOrigins) > 0 &&
		len(selection.AllowedOrigins) <= maximumConfiguredWebOrigins &&
		runtimeAttestationStrings(selection.AllowedOrigins, maximumConfiguredWebOriginBytes, true)
}

func runtimeAttestationPlatform(platform string) bool {
	switch platform {
	case "ios", "android", "web", "react_native_ios", "react_native_android", "node":
		return true
	default:
		return false
	}
}

func runtimeAttestationMode(mode string) bool {
	return mode == "disabled" || mode == "preferred" || mode == "required"
}

func runtimeAttestationTrust(level string) bool {
	switch level {
	case "none", "identity_only", "web_risk_verified", "app_verified", "device_verified", "strong_device_verified", "debug":
		return true
	default:
		return false
	}
}

func runtimeAttestationStrings(values []string, maximumLength int, origins bool) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || (maximumLength > 0 && utf8.RuneCountInString(value) > maximumLength) {
			return false
		}
		if origins && !canonicalBrowserHTTPSOrigin(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func compiledSessionPolicy(document compiledSnapshotDocument) (SessionPolicy, error) {
	result := SessionPolicy{
		AccessTokenTTL: defaultAccessTokenTTL, ChallengeTTL: defaultChallengeTTL,
		RefreshTokenTTL: defaultRefreshTokenTTL, MaximumClockSkew: defaultClockSkew,
	}
	values := []struct {
		raw         string
		destination *time.Duration
		name        string
	}{
		{raw: document.Spec.Session.AccessTokenTTL, destination: &result.AccessTokenTTL, name: "access-token TTL"},
		{raw: document.Spec.Session.ChallengeTTL, destination: &result.ChallengeTTL, name: "challenge TTL"},
		{raw: document.Spec.Session.RefreshTokenTTL, destination: &result.RefreshTokenTTL, name: "refresh-token TTL"},
	}
	for _, value := range values {
		if value.raw == "" {
			continue
		}
		parsed, err := parseConfigDuration(value.raw)
		if err != nil {
			return SessionPolicy{}, errorsCorruptSnapshot(value.name)
		}
		*value.destination = parsed
	}
	if document.Spec.Session.MaximumClockSkewSeconds != nil {
		result.MaximumClockSkew = time.Duration(*document.Spec.Session.MaximumClockSkewSeconds) * time.Second
	}
	if result.AccessTokenTTL < time.Minute || result.AccessTokenTTL > time.Hour ||
		result.ChallengeTTL < 30*time.Second || result.ChallengeTTL > 10*time.Minute ||
		result.RefreshTokenTTL < time.Hour || result.RefreshTokenTTL > 90*24*time.Hour ||
		result.MaximumClockSkew < 0 || result.MaximumClockSkew > 5*time.Minute {
		return SessionPolicy{}, errorsCorruptSnapshot("session policy bounds")
	}
	return result, nil
}

func errorsCorruptSnapshot(field string) error {
	return fmt.Errorf("compiled active configuration has invalid %s", field)
}
