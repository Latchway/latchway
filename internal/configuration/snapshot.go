package configuration

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/weborigin"
)

type compiledSnapshotDocument struct {
	Spec struct {
		Session struct {
			AccessTokenTTL          string `json:"accessTokenTtl"`
			ChallengeTTL            string `json:"challengeTtl"`
			RefreshTokenTTL         string `json:"refreshTokenTtl"`
			MaximumClockSkewSeconds *int   `json:"maximumClockSkewSeconds"`
		} `json:"session"`
		IdentityProviders    []IdentityProvider               `json:"identityProviders"`
		AttestationPolicy    []compiledAttestationPolicy      `json:"attestationPolicies"`
		ComponentDefinitions []compiledComponentDefinition    `json:"componentDefinitions"`
		Upstreams            []compiledUpstream               `json:"upstreams"`
		Models               []compiledModel                  `json:"models"`
		InputAccounting      []compiledInputAccountingProfile `json:"inputAccountingProfiles"`
		PricingCatalogs      []compiledPricingCatalog         `json:"pricingCatalogs"`
		LimitPlans           []compiledLimitPlan              `json:"limitPlans"`
		Features             []compiledFeature                `json:"features"`
	} `json:"spec"`
}

type compiledAttestationPolicy struct {
	ID        string                         `json:"id"`
	MaxAge    string                         `json:"maxAge"`
	Platforms map[string]PlatformAttestation `json:"platforms"`
}

type compiledComponentDefinition struct {
	ID          string               `json:"id"`
	Platform    string               `json:"platform"`
	Kind        string               `json:"kind"`
	Identifiers ComponentIdentifiers `json:"identifiers"`
	FamilyRole  string               `json:"familyRole"`
	Delegation  *struct {
		AllowedParents       []string `json:"allowedParents"`
		MaximumLifetime      string   `json:"maximumLifetime"`
		AllowChildDelegation bool     `json:"allowChildDelegation"`
	} `json:"delegation,omitempty"`
	Attestation     ComponentAttestationPolicy `json:"attestation"`
	AllowedFeatures []string                   `json:"allowedFeatures"`
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
		components:      make(map[string]ComponentDefinition, len(parsed.Spec.ComponentDefinitions)),
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
	if len(parsed.Spec.ComponentDefinitions) > 64 {
		return ActiveSnapshot{}, errorsCorruptSnapshot("component definition set")
	}
	for _, rawDefinition := range parsed.Spec.ComponentDefinitions {
		definition, definitionErr := runtimeComponentDefinition(rawDefinition)
		if definitionErr != nil || !insertUnique(snapshot.components, definition.ID, definition) {
			return ActiveSnapshot{}, errorsCorruptSnapshot("component definition")
		}
	}
	if !runtimeComponentDefinitionGraph(snapshot.components) ||
		!runtimeRootComponentBindings(snapshot.components, snapshot.attestations) {
		return ActiveSnapshot{}, errorsCorruptSnapshot("component definition graph")
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

func runtimeComponentDefinition(raw compiledComponentDefinition) (ComponentDefinition, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) ||
		!runtimeComponentPlatform(raw.Platform) ||
		!runtimeComponentKind(raw.Kind) ||
		(raw.FamilyRole != "root" && raw.FamilyRole != "delegated") ||
		len(raw.AllowedFeatures) == 0 || len(raw.AllowedFeatures) > 256 ||
		!runtimeIdentifierStrings(raw.AllowedFeatures) ||
		!runtimeComponentIdentifiers(raw.Platform, raw.Identifiers) ||
		!runtimeComponentAttestation(raw.Platform, raw.Kind, raw.FamilyRole, raw.Attestation) {
		return ComponentDefinition{}, ErrInvalid
	}
	definition := ComponentDefinition{
		ID: raw.ID, Platform: raw.Platform, Kind: raw.Kind,
		FamilyRole: raw.FamilyRole, Identifiers: raw.Identifiers.clone(),
		Attestation:     raw.Attestation,
		AllowedFeatures: append([]string(nil), raw.AllowedFeatures...),
	}
	if raw.FamilyRole == "root" {
		if raw.Delegation != nil {
			return ComponentDefinition{}, ErrInvalid
		}
		return definition, nil
	}
	if raw.Delegation == nil || len(raw.Delegation.AllowedParents) == 0 ||
		len(raw.Delegation.AllowedParents) > 32 ||
		!runtimeIdentifierStrings(raw.Delegation.AllowedParents) ||
		raw.Delegation.AllowChildDelegation {
		return ComponentDefinition{}, ErrInvalid
	}
	lifetime, err := parseConfigDuration(raw.Delegation.MaximumLifetime)
	if err != nil || lifetime < time.Minute || lifetime > 30*24*time.Hour {
		return ComponentDefinition{}, ErrInvalid
	}
	definition.Delegation = &ComponentDelegationPolicy{
		AllowedParents:       append([]string(nil), raw.Delegation.AllowedParents...),
		MaximumLifetime:      lifetime,
		AllowChildDelegation: raw.Delegation.AllowChildDelegation,
	}
	return definition, nil
}

func runtimeComponentDefinitionGraph(definitions map[string]ComponentDefinition) bool {
	identifierOwners := make(map[string]string)
	for definitionID, definition := range definitions {
		for _, identifier := range append(
			append(append([]string(nil), definition.Identifiers.BundleIdentifiers...), definition.Identifiers.PackageNames...),
			definition.Identifiers.Origins...,
		) {
			if owner, exists := identifierOwners[identifier]; exists && owner != definitionID {
				return false
			}
			identifierOwners[identifier] = definitionID
		}
		if definition.Delegation == nil {
			continue
		}
		for _, parentID := range definition.Delegation.AllowedParents {
			parent, ok := definitions[parentID]
			if !ok || parentID == definitionID || parent.FamilyRole != "root" {
				return false
			}
		}
	}
	state := make(map[string]uint8, len(definitions))
	var visit func(string) bool
	visit = func(definitionID string) bool {
		switch state[definitionID] {
		case 1:
			return false
		case 2:
			return true
		}
		state[definitionID] = 1
		definition := definitions[definitionID]
		if definition.Delegation != nil {
			for _, parentID := range definition.Delegation.AllowedParents {
				if !visit(parentID) {
					return false
				}
			}
		}
		state[definitionID] = 2
		return true
	}
	for definitionID := range definitions {
		if !visit(definitionID) {
			return false
		}
	}
	return true
}

func runtimeRootComponentBindings(
	definitions map[string]ComponentDefinition,
	attestations map[string]AttestationPolicy,
) bool {
	required := make(map[string][]PlatformAttestation)
	for _, policy := range attestations {
		for platform, selection := range policy.Platforms {
			if selection.Mode == "required" {
				required[platform] = append(required[platform], selection)
			}
		}
	}
	rootsByPlatform := make(map[string][]ComponentDefinition)
	boundRoot := make(map[string]bool)
	for _, definition := range definitions {
		if definition.FamilyRole != "root" {
			continue
		}
		rootsByPlatform[definition.Platform] = append(rootsByPlatform[definition.Platform], definition)
		selections := required[definition.Platform]
		if len(selections) != 1 {
			return false
		}
		selection := selections[0]
		if definition.Attestation.Strategy == "direct" &&
			definition.Attestation.Provider != selection.Provider {
			return false
		}
		switch {
		case (definition.Platform == "ios" || definition.Platform == "react_native_ios" || definition.Platform == "watchos") &&
			selection.Provider == "app_attest" && selection.AppAttest != nil:
			if len(definition.Identifiers.BundleIdentifiers) != 1 ||
				definition.Identifiers.BundleIdentifiers[0] != selection.AppAttest.BundleID {
				return false
			}
			boundRoot[definition.ID] = definition.Attestation.Strategy == "direct"
		case (definition.Platform == "android" || definition.Platform == "react_native_android" || definition.Platform == "wearos") &&
			selection.Provider == "play_integrity" && selection.PlayIntegrity != nil:
			if len(definition.Identifiers.PackageNames) != 1 ||
				definition.Identifiers.PackageNames[0] != selection.PlayIntegrity.PackageName {
				return false
			}
			boundRoot[definition.ID] = definition.Attestation.Strategy == "direct"
		case definition.Platform == "web":
			allowed := make(map[string]struct{}, len(selection.AllowedOrigins))
			for _, origin := range selection.AllowedOrigins {
				allowed[origin] = struct{}{}
			}
			if len(definition.Identifiers.Origins) == 0 {
				return false
			}
			for _, origin := range definition.Identifiers.Origins {
				if _, ok := allowed[origin]; !ok {
					return false
				}
			}
			boundRoot[definition.ID] = definition.Attestation.Strategy == "direct" &&
				selection.Provider != "debug"
		default:
			boundRoot[definition.ID] = false
		}
	}
	platforms := make([]string, 0, len(rootsByPlatform))
	for platform := range rootsByPlatform {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	for _, platform := range platforms {
		roots := rootsByPlatform[platform]
		if platform == "web" {
			selections := required[platform]
			if len(selections) != 1 {
				return false
			}
			originOwners := make(map[string]int, len(selections[0].AllowedOrigins))
			for _, root := range roots {
				for _, origin := range root.Identifiers.Origins {
					originOwners[origin]++
				}
			}
			for _, origin := range selections[0].AllowedOrigins {
				if originOwners[origin] != 1 {
					return false
				}
			}
		}
		if len(roots) < 2 {
			continue
		}
		if platform != "web" {
			return false
		}
		for _, root := range roots {
			if !boundRoot[root.ID] {
				return false
			}
		}
	}
	return true
}

func runtimeIdentifierStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !runtimeIdentifierPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func runtimeComponentPlatform(platform string) bool {
	switch platform {
	case "ios", "android", "web", "node", "react_native_ios", "react_native_android", "watchos", "wearos":
		return true
	default:
		return false
	}
}

func runtimeComponentKind(kind string) bool {
	switch kind {
	case "main_app", "widget", "share_extension", "app_intent_extension",
		"notification_service_extension", "action_extension", "sso_extension",
		"watch_extension", "android_app", "wear_app", "browser", "node_process":
		return true
	default:
		return false
	}
}

func runtimeComponentIdentifiers(platform string, identifiers ComponentIdentifiers) bool {
	if !runtimeAttestationStrings(identifiers.BundleIdentifiers, 256, false) ||
		!runtimeAttestationStrings(identifiers.PackageNames, 256, false) ||
		!runtimeAttestationStrings(identifiers.Origins, 2048, true) {
		return false
	}
	switch platform {
	case "ios", "react_native_ios", "watchos":
		return len(identifiers.BundleIdentifiers) > 0 && len(identifiers.PackageNames) == 0 && len(identifiers.Origins) == 0
	case "android", "react_native_android", "wearos":
		return len(identifiers.PackageNames) > 0 && len(identifiers.BundleIdentifiers) == 0 && len(identifiers.Origins) == 0
	case "web":
		return len(identifiers.Origins) > 0 && len(identifiers.BundleIdentifiers) == 0 && len(identifiers.PackageNames) == 0
	case "node":
		return len(identifiers.BundleIdentifiers) == 0 && len(identifiers.PackageNames) == 0 && len(identifiers.Origins) == 0
	default:
		return false
	}
}

func runtimeComponentAttestation(platform, kind, role string, policy ComponentAttestationPolicy) bool {
	if role == "delegated" {
		if policy.Strategy != "delegated" || policy.Provider != "" {
			return false
		}
		if !policy.DirectStepUp {
			return policy.DirectAttestationPolicy == ""
		}
		return runtimeIdentifierPattern.MatchString(policy.DirectAttestationPolicy) &&
			componentDirectAppAttestSupported(platform, kind)
	}
	if policy.Strategy != "direct" || policy.Provider == "" || policy.DirectStepUp ||
		policy.DirectAttestationPolicy != "" {
		return false
	}
	switch policy.Provider {
	case "app_attest":
		return (platform == "ios" || platform == "react_native_ios" || platform == "watchos") &&
			(kind == "main_app" || kind == "action_extension" || kind == "sso_extension" || kind == "watch_extension")
	case "play_integrity":
		return (platform == "android" || platform == "react_native_android" || platform == "wearos") &&
			(kind == "android_app" || kind == "wear_app" || kind == "main_app")
	case "firebase_app_check", "turnstile":
		return platform == "web" && kind == "browser"
	case "debug":
		return true
	default:
		return false
	}
}

func componentDirectAppAttestSupported(platform, kind string) bool {
	return (platform == "ios" || platform == "react_native_ios" || platform == "watchos") &&
		(kind == "action_extension" || kind == "sso_extension" || kind == "watch_extension")
}

func runtimeAttestationPolicy(raw compiledAttestationPolicy) (AttestationPolicy, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) || raw.MaxAge == "" || len(raw.Platforms) == 0 || len(raw.Platforms) > 7 {
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
	case "ios", "android", "web", "react_native_ios", "react_native_android", "watchos", "node":
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
		if origins && !weborigin.Canonical(value) {
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
