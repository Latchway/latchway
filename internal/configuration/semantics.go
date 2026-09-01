package configuration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/latchway/latchway/internal/protocol"
	upstreamtarget "github.com/latchway/latchway/internal/upstream"
	"github.com/latchway/latchway/internal/weborigin"
)

var (
	constantIdentifierExpression = regexp.MustCompile(`^['"]([a-z][a-z0-9_-]{0,62})['"]$`)
	firebaseProjectIDExpression  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	identityClaimPathExpression  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}(\.[A-Za-z][A-Za-z0-9_-]{0,127})*$`)
)

func (validator *Validator) semanticIssues(root map[string]any, environment EnvironmentDescriptor) []Issue {
	issues := make([]Issue, 0)
	metadata := objectValue(root, "metadata")
	metadataChecks := []struct {
		key  string
		want string
		path string
	}{
		{key: "organization", want: environment.OrganizationSlug, path: "/metadata/organization"},
		{key: "application", want: environment.ApplicationSlug, path: "/metadata/application"},
		{key: "environment", want: environment.EnvironmentSlug, path: "/metadata/environment"},
	}
	for _, check := range metadataChecks {
		if stringValue(metadata, check.key) != check.want {
			issues = append(issues, errorIssue("metadata_scope_mismatch", check.path, "Configuration metadata must match the target environment."))
		}
	}

	spec := objectValue(root, "spec")
	identities, identityIssues := indexObjects(objectArray(spec, "identityProviders"), "/spec/identityProviders")
	issues = append(issues, identityIssues...)
	attestations, attestationIssues := indexObjects(objectArray(spec, "attestationPolicies"), "/spec/attestationPolicies")
	issues = append(issues, attestationIssues...)
	components, componentIssues := indexObjects(objectArray(spec, "componentDefinitions"), "/spec/componentDefinitions")
	issues = append(issues, componentIssues...)
	upstreams, upstreamIssues := indexObjects(objectArray(spec, "upstreams"), "/spec/upstreams")
	issues = append(issues, upstreamIssues...)
	models, modelIssues := indexObjects(objectArray(spec, "models"), "/spec/models")
	issues = append(issues, modelIssues...)
	inputAccounting, inputAccountingIssues := indexObjects(
		objectArray(spec, "inputAccountingProfiles"),
		"/spec/inputAccountingProfiles",
	)
	issues = append(issues, inputAccountingIssues...)
	pricing, pricingIssues := indexObjects(objectArray(spec, "pricingCatalogs"), "/spec/pricingCatalogs")
	issues = append(issues, pricingIssues...)
	limitPlans, limitPlanIssues := indexObjects(objectArray(spec, "limitPlans"), "/spec/limitPlans")
	issues = append(issues, limitPlanIssues...)
	features, featureIssues := indexObjects(objectArray(spec, "features"), "/spec/features")
	issues = append(issues, featureIssues...)

	issues = append(issues, validator.identityIssues(identities)...)
	issues = append(issues, attestationSemanticIssues(attestations, environment.EnvironmentKind)...)
	issues = append(issues, componentDefinitionSemanticIssues(components, features, attestations, environment.EnvironmentKind)...)
	issues = append(issues, upstreamSemanticIssues(upstreams, environment.EnvironmentKind)...)
	issues = append(issues, inputAccountingProfileSemanticIssues(inputAccounting)...)
	issues = append(issues, modelSemanticIssues(models, upstreams, pricing, inputAccounting)...)
	issues = append(issues, pricingSemanticIssues(pricing, models)...)
	issues = append(issues, limitSemanticIssues(limitPlans)...)
	issues = append(issues, validator.featureSemanticIssues(
		features, models, upstreams, attestations, limitPlans,
	)...)
	issues = append(issues, sessionSemanticIssues(objectValue(spec, "session"))...)
	issues = append(issues, privacySemanticIssues(objectValue(spec, "privacy"))...)
	issues = append(issues, secretReferenceIssues(root, environment.SecretNames)...)
	return deduplicateIssues(issues)
}

func componentDefinitionSemanticIssues(
	definitions map[string]map[string]any,
	features map[string]map[string]any,
	attestations map[string]map[string]any,
	environmentKind string,
) []Issue {
	issues := make([]Issue, 0)
	identifierOwners := make(map[string]string)
	parents := make(map[string][]string, len(definitions))

	for _, definitionID := range sortedMapKeys(definitions) {
		definition := definitions[definitionID]
		base := "/spec/componentDefinitions/" + pointerToken(definitionID)
		platform := stringValue(definition, "platform")
		kind := stringValue(definition, "kind")
		role := stringValue(definition, "familyRole")
		identifiers := objectValue(definition, "identifiers")
		for field, values := range map[string][]string{
			"bundleIdentifiers": stringArray(identifiers, "bundleIdentifiers"),
			"packageNames":      stringArray(identifiers, "packageNames"),
			"origins":           stringArray(identifiers, "origins"),
		} {
			for index, value := range values {
				if owner, exists := identifierOwners[value]; exists && owner != definitionID {
					issues = append(issues, errorIssue(
						"component_identifier_duplicate",
						fmt.Sprintf("%s/identifiers/%s/%d", base, field, index),
						"A platform identifier may belong to only one Component Definition.",
					))
				} else {
					identifierOwners[value] = definitionID
				}
			}
		}
		if !componentIdentifierShapeValid(platform, identifiers, environmentKind) {
			issues = append(issues, errorIssue(
				"component_identifier_platform_mismatch", base+"/identifiers",
				"Component identifiers must use the identifier kind owned by the configured platform.",
			))
		}

		for index, featureID := range stringArray(definition, "allowedFeatures") {
			if _, exists := features[featureID]; !exists {
				issues = append(issues, errorIssue(
					"component_feature_not_found",
					fmt.Sprintf("%s/allowedFeatures/%d", base, index),
					"A Component Definition may grant only a configured application feature.",
				))
			}
		}

		attestation := objectValue(definition, "attestation")
		strategy := stringValue(attestation, "strategy")
		provider := stringValue(attestation, "provider")
		directStepUp, _ := attestation["directStepUp"].(bool)
		directPolicyID := stringValue(attestation, "directAttestationPolicy")
		if role == "root" && strategy == "identity_only" {
			issues = append(issues, errorIssue(
				"component_root_identity_only_unsupported", base+"/attestation/strategy",
				"Explicit identity-only root Component Definitions are not supported in version 1; configure direct attestation.",
			))
		} else if !runtimeComponentAttestation(platform, kind, role, ComponentAttestationPolicy{
			Strategy: strategy, Provider: provider, DirectStepUp: directStepUp,
			DirectAttestationPolicy: directPolicyID,
		}) {
			issues = append(issues, errorIssue(
				"component_attestation_unsupported", base+"/attestation",
				"The component platform and kind do not support the configured trust-establishment strategy.",
			))
		}
		if directStepUp {
			directPolicy, exists := attestations[directPolicyID]
			selection := objectValue(objectValue(directPolicy, "platforms"), platform)
			typedSelection, selectionOK := decodePlatformAttestation(selection)
			bundles := stringArray(identifiers, "bundleIdentifiers")
			if !exists {
				issues = append(issues, errorIssue(
					"component_direct_attestation_policy_not_found", base+"/attestation/directAttestationPolicy",
					"Direct component attestation must reference a configured attestation policy.",
				))
			} else if !selectionOK || typedSelection.Provider != "app_attest" ||
				typedSelection.Mode != "preferred" || typedSelection.MinimumTrustLevel != "app_verified" ||
				typedSelection.AppAttest == nil ||
				len(bundles) != 1 || typedSelection.AppAttest.BundleID != bundles[0] {
				issues = append(issues, errorIssue(
					"component_direct_attestation_policy_mismatch", base+"/attestation/directAttestationPolicy",
					"The referenced App Attest policy must enable this component platform and exact bundle identifier.",
				))
			}
		}

		delegation := objectValue(definition, "delegation")
		allowedParents := stringArray(delegation, "allowedParents")
		parents[definitionID] = allowedParents
		if role == "root" && len(delegation) != 0 {
			issues = append(issues, errorIssue(
				"root_component_delegation_forbidden", base+"/delegation",
				"A root Component Definition cannot be delegated.",
			))
		}
		if role == "delegated" {
			allowChildDelegation, _ := delegation["allowChildDelegation"].(bool)
			if allowChildDelegation {
				issues = append(issues, errorIssue(
					"component_child_delegation_unsupported", base+"/delegation/allowChildDelegation",
					"Nested component delegation is not supported in the v1 runtime; delegated components must not allow child delegation.",
				))
			}
			lifetime, err := parseConfigDuration(stringValue(delegation, "maximumLifetime"))
			if err != nil || lifetime < time.Minute || lifetime > 30*24*time.Hour {
				issues = append(issues, errorIssue(
					"component_delegation_lifetime_unbounded", base+"/delegation/maximumLifetime",
					"Delegation lifetime must be between one minute and 30 days.",
				))
			}
			for index, parentID := range allowedParents {
				parent, exists := definitions[parentID]
				path := fmt.Sprintf("%s/delegation/allowedParents/%d", base, index)
				if !exists {
					issues = append(issues, errorIssue(
						"component_parent_not_found", path,
						"A delegated component parent must name a configured Component Definition.",
					))
					continue
				}
				if parentID == definitionID {
					issues = append(issues, errorIssue(
						"component_self_delegation", path,
						"A Component Definition cannot delegate to itself.",
					))
					continue
				}
				parentRole := stringValue(parent, "familyRole")
				if parentRole != "root" {
					issues = append(issues, errorIssue(
						"component_parent_delegation_forbidden", path,
						"A v1 delegated component parent must be a root Component Definition.",
					))
				}
			}
		}
	}
	issues = append(issues, componentRootBindingIssues(definitions, attestations)...)

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
		for _, parentID := range parents[definitionID] {
			if _, exists := definitions[parentID]; exists && !visit(parentID) {
				return false
			}
		}
		state[definitionID] = 2
		return true
	}
	for _, definitionID := range sortedMapKeys(definitions) {
		if !visit(definitionID) {
			issues = append(issues, errorIssue(
				"component_delegation_cycle", "/spec/componentDefinitions/"+pointerToken(definitionID)+"/delegation",
				"Component Definition delegation must be acyclic.",
			))
			break
		}
	}
	return issues
}

func componentRootBindingIssues(
	definitions map[string]map[string]any,
	attestations map[string]map[string]any,
) []Issue {
	required := make(map[string][]PlatformAttestation)
	for _, policyID := range sortedMapKeys(attestations) {
		platforms := objectValue(attestations[policyID], "platforms")
		for _, platform := range sortedObjectKeys(platforms) {
			selection, ok := platforms[platform].(map[string]any)
			if !ok || stringValue(selection, "mode") != "required" {
				continue
			}
			if typed, decoded := decodePlatformAttestation(selection); decoded {
				required[platform] = append(required[platform], typed)
			}
		}
	}

	issues := make([]Issue, 0)
	rootsByPlatform := make(map[string][]string)
	boundRoot := make(map[string]bool)
	for _, definitionID := range sortedMapKeys(definitions) {
		definition := definitions[definitionID]
		if stringValue(definition, "familyRole") != "root" {
			continue
		}
		platform := stringValue(definition, "platform")
		rootsByPlatform[platform] = append(rootsByPlatform[platform], definitionID)
		base := "/spec/componentDefinitions/" + pointerToken(definitionID)
		selections := required[platform]
		if len(selections) != 1 {
			issues = append(issues, errorIssue(
				"component_root_attestation_policy_ambiguous", base+"/attestation",
				"A root Component Definition requires exactly one required attestation selection for its platform.",
			))
			continue
		}
		selection := selections[0]
		attestation := objectValue(definition, "attestation")
		strategy := stringValue(attestation, "strategy")
		provider := stringValue(attestation, "provider")
		if strategy == "direct" && provider != selection.Provider {
			issues = append(issues, errorIssue(
				"component_root_attestation_provider_mismatch", base+"/attestation/provider",
				"A directly attested root must use the platform's required attestation provider.",
			))
			continue
		}

		identifiers := objectValue(definition, "identifiers")
		switch {
		case (platform == "ios" || platform == "react_native_ios" || platform == "watchos") &&
			selection.Provider == "app_attest" && selection.AppAttest != nil:
			bundles := stringArray(identifiers, "bundleIdentifiers")
			if len(bundles) != 1 || bundles[0] != selection.AppAttest.BundleID {
				issues = append(issues, errorIssue(
					"component_root_identifier_mismatch", base+"/identifiers/bundleIdentifiers",
					"The root bundle identifier must exactly equal the bundle identifier verified by the required App Attest policy.",
				))
				continue
			}
			boundRoot[definitionID] = strategy == "direct"
		case (platform == "android" || platform == "react_native_android" || platform == "wearos") &&
			selection.Provider == "play_integrity" && selection.PlayIntegrity != nil:
			packages := stringArray(identifiers, "packageNames")
			if len(packages) != 1 || packages[0] != selection.PlayIntegrity.PackageName {
				issues = append(issues, errorIssue(
					"component_root_identifier_mismatch", base+"/identifiers/packageNames",
					"The root package name must exactly equal the package name verified by the required Play Integrity policy.",
				))
				continue
			}
			boundRoot[definitionID] = strategy == "direct"
		case platform == "web":
			allowed := make(map[string]struct{}, len(selection.AllowedOrigins))
			for _, origin := range selection.AllowedOrigins {
				allowed[origin] = struct{}{}
			}
			origins := stringArray(identifiers, "origins")
			valid := len(origins) > 0
			for _, origin := range origins {
				if _, ok := allowed[origin]; !ok {
					valid = false
				}
			}
			if !valid {
				issues = append(issues, errorIssue(
					"component_root_identifier_mismatch", base+"/identifiers/origins",
					"Every root origin must be an exact origin allowed by the required web attestation policy.",
				))
				continue
			}
			boundRoot[definitionID] = strategy == "direct" && selection.Provider != "debug"
		default:
			// Debug and server runtimes do
			// not produce a durable platform identifier suitable for choosing
			// among sibling root definitions.
			boundRoot[definitionID] = false
		}
	}

	for _, platform := range sortedMapKeys(rootsByPlatform) {
		definitionIDs := rootsByPlatform[platform]
		if platform == "web" && len(required[platform]) == 1 {
			selection := required[platform][0]
			originOwners := make(map[string]int, len(selection.AllowedOrigins))
			for _, definitionID := range definitionIDs {
				identifiers := objectValue(definitions[definitionID], "identifiers")
				for _, origin := range stringArray(identifiers, "origins") {
					originOwners[origin]++
				}
			}
			for _, origin := range selection.AllowedOrigins {
				switch originOwners[origin] {
				case 0:
					issues = append(issues, errorIssue(
						"component_root_origin_unmapped",
						"/spec/componentDefinitions/"+pointerToken(definitionIDs[0])+"/identifiers/origins",
						"Every origin allowed by a required web attestation policy must select exactly one root Component Definition.",
					))
				case 1:
				default:
					issues = append(issues, errorIssue(
						"component_root_origin_ambiguous",
						"/spec/componentDefinitions/"+pointerToken(definitionIDs[0])+"/identifiers/origins",
						"An origin allowed by a required web attestation policy may select only one root Component Definition.",
					))
				}
			}
		}
		if len(definitionIDs) < 2 {
			continue
		}
		unambiguous := platform == "web"
		for _, definitionID := range definitionIDs {
			unambiguous = unambiguous && boundRoot[definitionID]
		}
		if !unambiguous {
			issues = append(issues, errorIssue(
				"component_root_ambiguous",
				"/spec/componentDefinitions/"+pointerToken(definitionIDs[0]),
				"A platform may have multiple root Component Definitions only when exact verified web origins select one directly attested root.",
			))
		}
	}
	return issues
}

func componentIdentifierShapeValid(platform string, identifiers map[string]any, environmentKind string) bool {
	bundles := stringArray(identifiers, "bundleIdentifiers")
	packages := stringArray(identifiers, "packageNames")
	origins := stringArray(identifiers, "origins")
	switch platform {
	case "ios", "react_native_ios", "watchos":
		return len(bundles) > 0 && len(packages) == 0 && len(origins) == 0
	case "android", "react_native_android", "wearos":
		return len(packages) > 0 && len(bundles) == 0 && len(origins) == 0
	case "web":
		if len(origins) == 0 || len(bundles) != 0 || len(packages) != 0 {
			return false
		}
		for _, origin := range origins {
			if !canonicalBrowserOrigin(origin, environmentKind) {
				return false
			}
		}
		return true
	case "node":
		return len(bundles) == 0 && len(packages) == 0 && len(origins) == 0
	default:
		return false
	}
}

func indexObjects(objects []map[string]any, basePath string) (map[string]map[string]any, []Issue) {
	result := make(map[string]map[string]any, len(objects))
	issues := make([]Issue, 0)
	for index, object := range objects {
		identifier := stringValue(object, "id")
		if _, exists := result[identifier]; exists {
			issues = append(issues, errorIssue("duplicate_identifier", fmt.Sprintf("%s/%d/id", basePath, index), "Identifiers must be unique within their configuration section."))
			continue
		}
		result[identifier] = object
	}
	return result, issues
}

func (validator *Validator) identityIssues(providers map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	for _, providerID := range sortedMapKeys(providers) {
		provider := providers[providerID]
		base := "/spec/identityProviders/" + pointerToken(providerID)
		providerType := stringValue(provider, "type")
		algorithms := stringArray(provider, "allowedAlgorithms")
		jwksURL := stringValue(provider, "jwksUrl")
		staticPublicKey := stringValue(provider, "staticPublicKeySecretRef")
		symmetricSecret := stringValue(provider, "symmetricSecretRef")
		if issuer := stringValue(provider, "issuer"); issuer != "" && !canonicalIdentityHTTPSURL(issuer) {
			issues = append(issues, errorIssue("identity_issuer_url_invalid", base+"/issuer", "The identity issuer must be one canonical HTTPS URL without credentials, query parameters, or a fragment."))
		}
		if jwksURL != "" && !canonicalIdentityHTTPSURL(jwksURL) {
			issues = append(issues, errorIssue("identity_jwks_url_invalid", base+"/jwksUrl", "The JWKS endpoint must be one canonical HTTPS URL without credentials, query parameters, or a fragment."))
		}
		if subjectClaim := stringValue(provider, "subjectClaim"); !identityClaimPathExpression.MatchString(subjectClaim) {
			issues = append(issues, errorIssue("identity_subject_claim_invalid", base+"/subjectClaim", "The subject claim must be a segmented claim path."))
		}
		for index, requiredClaim := range stringArray(provider, "requiredClaims") {
			if !identityClaimPathExpression.MatchString(requiredClaim) {
				issues = append(issues, errorIssue("identity_required_claim_invalid", fmt.Sprintf("%s/requiredClaims/%d", base, index), "Each required claim must be a segmented claim path."))
			}
		}
		acknowledgeSymmetricRisk, _ := provider["acknowledgeSymmetricRisk"].(bool)
		hasHS256 := slices.Contains(algorithms, "HS256")
		hs256Only := len(algorithms) == 1 && algorithms[0] == "HS256"
		sourceCount := populatedCount(jwksURL, staticPublicKey, symmetricSecret)
		if sourceCount > 1 {
			issues = append(issues, errorIssue("identity_key_source_ambiguous", base, "An identity provider must select at most one verification-key source."))
		}
		switch providerType {
		case "firebase":
			projectID := stringValue(provider, "projectId")
			if !firebaseProjectIDExpression.MatchString(projectID) {
				issues = append(issues, errorIssue("firebase_project_id_invalid", base+"/projectId", "The Firebase project ID is invalid."))
			}
			expectedIssuer := "https://securetoken.google.com/" + projectID
			if issuer := stringValue(provider, "issuer"); issuer != "" && issuer != expectedIssuer {
				issues = append(issues, errorIssue("firebase_issuer_override_invalid", base+"/issuer", "A Firebase issuer override must equal the issuer derived from its project ID."))
			}
			if audiences := stringArray(provider, "audiences"); len(audiences) != 0 && (len(audiences) != 1 || audiences[0] != projectID) {
				issues = append(issues, errorIssue("firebase_audience_override_invalid", base+"/audiences", "A Firebase audience override must equal its project ID."))
			}
			if sourceCount != 0 {
				issues = append(issues, errorIssue("preset_identity_key_source_invalid", base, "Firebase uses its fixed public-certificate endpoint and cannot override the verification-key source."))
			}
			if len(algorithms) != 0 && !slices.Equal(algorithms, []string{"RS256"}) {
				issues = append(issues, errorIssue("preset_identity_algorithm_invalid", base+"/allowedAlgorithms", "Firebase accepts only RS256."))
			}
		case "supabase":
			if !canonicalIdentityHTTPSOrigin(stringValue(provider, "projectUrl")) {
				issues = append(issues, errorIssue("supabase_project_url_invalid", base+"/projectUrl", "The Supabase project URL must be one canonical HTTPS origin."))
			}
			if sourceCount != 0 {
				issues = append(issues, errorIssue("preset_identity_key_source_invalid", base, "Supabase derives its JWKS endpoint and cannot override the verification-key source."))
			}
			if len(algorithms) != 0 && !onlyIdentityAlgorithms(algorithms, "RS256", "ES256") {
				issues = append(issues, errorIssue("preset_identity_algorithm_invalid", base+"/allowedAlgorithms", "Supabase accepts only RS256 and ES256."))
			}
		case "clerk":
			if symmetricSecret != "" {
				issues = append(issues, errorIssue("preset_identity_key_source_invalid", base+"/symmetricSecretRef", "Clerk accepts only its JWKS endpoint, an explicit JWKS URL, or one static public key."))
			}
			if len(algorithms) != 0 && !slices.Equal(algorithms, []string{"RS256"}) {
				issues = append(issues, errorIssue("preset_identity_algorithm_invalid", base+"/allowedAlgorithms", "Clerk accepts only RS256."))
			}
		case "generic_oidc":
			if symmetricSecret != "" || populatedCount(jwksURL, staticPublicKey) != 1 {
				issues = append(issues, errorIssue("identity_key_source_invalid", base, "A generic OIDC provider requires exactly one JWKS URL or static public-key secret."))
			}
			if len(algorithms) == 0 || !onlyIdentityAlgorithms(algorithms, "RS256", "RS384", "RS512", "ES256", "ES384") {
				issues = append(issues, errorIssue("identity_algorithm_source_mismatch", base+"/allowedAlgorithms", "A generic OIDC public-key source requires one or more asymmetric algorithms."))
			}
		case "custom_jwt":
			if sourceCount != 1 {
				issues = append(issues, errorIssue("identity_key_source_invalid", base, "A custom JWT provider requires exactly one JWKS URL, static public-key secret, or symmetric secret."))
			}
			if symmetricSecret == "" && (len(algorithms) == 0 || !onlyIdentityAlgorithms(algorithms, "RS256", "RS384", "RS512", "ES256", "ES384")) {
				issues = append(issues, errorIssue("identity_algorithm_source_mismatch", base+"/allowedAlgorithms", "A JWKS or static public-key source requires one or more asymmetric algorithms."))
			}
		}
		if hasHS256 && providerType != "custom_jwt" {
			issues = append(issues, errorIssue("symmetric_provider_not_explicit", base+"/allowedAlgorithms", "HS256 is permitted only for an explicitly configured custom JWT provider."))
		}
		if symmetricSecret != "" && (providerType != "custom_jwt" || !hs256Only || !acknowledgeSymmetricRisk) {
			issues = append(issues, errorIssue("symmetric_identity_source_invalid", base+"/symmetricSecretRef", "A symmetric identity key is allowed only for an acknowledged custom JWT provider using exactly HS256."))
		}
		if hasHS256 && (providerType != "custom_jwt" || symmetricSecret == "" || !hs256Only || !acknowledgeSymmetricRisk) {
			issues = append(issues, errorIssue("hs256_identity_configuration_invalid", base+"/allowedAlgorithms", "HS256 requires an acknowledged custom JWT provider with one symmetric secret source and no asymmetric algorithms."))
		}
		if mappings, ok := provider["claimMappings"].(map[string]any); ok {
			for _, claim := range sortedObjectKeys(mappings) {
				expression, _ := mappings[claim].(string)
				issues = append(issues, validator.celIssues(validator.claimCEL, expression, base+"/claimMappings/"+pointerToken(claim), nil)...)
			}
		}
	}
	return issues
}

func populatedCount(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

func onlyIdentityAlgorithms(values []string, allowed ...string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func canonicalIdentityHTTPSURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == raw
}

func canonicalIdentityHTTPSOrigin(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") {
		return false
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed.String() == strings.TrimSuffix(raw, "/")
}

// canonicalBrowserHTTPSOrigin accepts only the exact serialization browsers
// place in the Origin header. Exact storage is security-significant because
// request-time enforcement uses byte-for-byte membership rather than URL
// equivalence or normalization.
func canonicalBrowserHTTPSOrigin(raw string) bool {
	return weborigin.Secure(raw)
}

func canonicalBrowserOrigin(raw, environmentKind string) bool {
	return weborigin.Secure(raw) || environmentKind == "development" && weborigin.LoopbackHTTP(raw)
}

func attestationSemanticIssues(policies map[string]map[string]any, environmentKind string) []Issue {
	issues := make([]Issue, 0)
	requiredPolicyByPlatform := make(map[string]string)
	for _, policyID := range sortedMapKeys(policies) {
		policy := policies[policyID]
		base := "/spec/attestationPolicies/" + pointerToken(policyID)
		if duration, ok := stringField(policy, "maxAge"); ok {
			parsed, err := parseConfigDuration(duration)
			if err != nil || parsed < time.Minute || parsed > 30*24*time.Hour {
				issues = append(issues, errorIssue("attestation_age_out_of_bounds", base+"/maxAge", "Attestation maximum age must be between one minute and 30 days."))
			}
		}
		platforms := objectValue(policy, "platforms")
		for _, platform := range sortedObjectKeys(platforms) {
			selection, _ := platforms[platform].(map[string]any)
			provider := stringValue(selection, "provider")
			mode := stringValue(selection, "mode")
			selectionPath := base + "/platforms/" + pointerToken(platform)
			typedSelection, typedSelectionOK := decodePlatformAttestation(selection)
			if mode == "required" {
				if _, exists := requiredPolicyByPlatform[platform]; exists {
					issues = append(issues, errorIssue("attestation_required_policy_ambiguous", selectionPath+"/mode", "A client platform may have only one required attestation policy."))
				} else {
					requiredPolicyByPlatform[platform] = policyID
				}
			}
			if !providerAllowedOnPlatform(provider, platform) {
				issues = append(issues, errorIssue("attestation_provider_platform_mismatch", selectionPath+"/provider", "The attestation provider is not valid for this platform."))
			}
			allowDangerous, _ := selection["dangerousAllowInProduction"].(bool)
			if environmentKind == "production" && provider == "debug" && mode != "disabled" && !allowDangerous {
				issues = append(issues, errorIssue("debug_attestation_forbidden", selectionPath+"/provider", "Debug attestation in production requires explicit dangerous acknowledgement."))
			}
			if provider == "debug" && mode != "disabled" && stringValue(selection, "secretRef") == "" {
				issues = append(issues, errorIssue("debug_attestation_secret_required", selectionPath+"/secretRef", "Enabled debug attestation requires a server-side public-key secret reference."))
			}
			if !typedSelectionOK || !runtimeAttestationProviderConfiguration(typedSelection) {
				issues = append(issues, errorIssue("attestation_provider_configuration_invalid", selectionPath, "The attestation provider configuration is missing, mismatched, or invalid."))
			} else if mode != "disabled" && !runtimeAttestationTrustCapability(platform, typedSelection) {
				issues = append(issues, errorIssue("attestation_trust_unreachable", selectionPath+"/minimumTrustLevel", "The selected provider configuration cannot produce the required minimum trust level."))
			}
			if typedSelectionOK && provider == "app_attest" && typedSelection.AppAttest != nil &&
				environmentKind == "production" && typedSelection.AppAttest.Environment != "production" {
				issues = append(issues, errorIssue("app_attest_environment_forbidden", selectionPath+"/appAttest/environment", "Production environments require Apple's production App Attest trust environment."))
			}
			if typedSelectionOK && provider == "play_integrity" && typedSelection.PlayIntegrity != nil &&
				environmentKind == "production" && typedSelection.PlayIntegrity.AllowTestingResponses && !allowDangerous {
				issues = append(issues, errorIssue("play_integrity_testing_forbidden", selectionPath+"/playIntegrity/allowTestingResponses", "Play Integrity testing responses in production require explicit dangerous acknowledgement."))
			}
			if mode == "required" && stringValue(selection, "minimumTrustLevel") == "none" {
				issues = append(issues, errorIssue("attestation_trust_too_weak", selectionPath+"/minimumTrustLevel", "Required attestation must require a verified trust level."))
			}
			// Generic application identifiers are not yet bound into durable
			// verifier evidence. Provider-specific app identities live in their
			// typed configuration instead.
			if mode != "disabled" && len(stringArray(selection, "applicationIdentifiers")) != 0 {
				issues = append(issues, errorIssue("attestation_application_identifiers_unsupported", selectionPath+"/applicationIdentifiers", "Application identifier constraints are not supported until the selected verifier binds them into durable attestation evidence."))
			}
			origins := stringArray(selection, "allowedOrigins")
			if mode != "disabled" && platform == "web" {
				if len(origins) == 0 {
					issues = append(issues, errorIssue("attestation_allowed_origins_required", selectionPath+"/allowedOrigins", "Enabled web attestation requires at least one exact allowed HTTPS origin; development environments may use an exact loopback HTTP origin."))
				}
				for index, origin := range origins {
					if !canonicalBrowserOrigin(origin, environmentKind) {
						issues = append(issues, errorIssue("attestation_allowed_origin_invalid", fmt.Sprintf("%s/allowedOrigins/%d", selectionPath, index), "Allowed web origins must use exact canonical HTTPS serialization; development environments may use exact loopback HTTP origins."))
					}
				}
			} else if len(origins) != 0 {
				issues = append(issues, errorIssue("attestation_allowed_origins_forbidden", selectionPath+"/allowedOrigins", "Allowed origins are permitted only for enabled web attestation selections."))
			}
		}
	}
	return issues
}

func decodePlatformAttestation(selection map[string]any) (PlatformAttestation, bool) {
	encoded, err := json.Marshal(selection)
	if err != nil {
		return PlatformAttestation{}, false
	}
	var result PlatformAttestation
	if err := json.Unmarshal(encoded, &result); err != nil {
		return PlatformAttestation{}, false
	}
	return result, true
}

func providerAllowedOnPlatform(provider, platform string) bool {
	switch platform {
	case "ios", "react_native_ios", "watchos":
		return provider == "app_attest" || provider == "firebase_app_check" || provider == "debug"
	case "android", "react_native_android":
		return provider == "play_integrity" || provider == "firebase_app_check" || provider == "debug"
	case "web":
		return provider == "turnstile" || provider == "firebase_app_check" || provider == "debug"
	case "node":
		return provider == "debug"
	default:
		return false
	}
}

func upstreamSemanticIssues(upstreams map[string]map[string]any, environmentKind string) []Issue {
	issues := make([]Issue, 0)
	for _, upstreamID := range sortedMapKeys(upstreams) {
		upstream := upstreams[upstreamID]
		base := "/spec/upstreams/" + pointerToken(upstreamID)
		destinationPolicy := objectValue(upstream, "destinationPolicy")
		allowPrivate, _ := destinationPolicy["allowPrivateNetworks"].(bool)
		privateCIDRs, cidrErr := configuredPrivateCIDRs(allowPrivate, stringArray(destinationPolicy, "allowedCidrs"))
		if cidrErr != nil {
			issues = append(issues, errorIssue(
				"upstream_private_cidrs_invalid",
				base+"/destinationPolicy/allowedCidrs",
				"Private destination CIDRs must be distinct, non-overlapping canonical subnets of RFC 1918 IPv4 space or IPv6 ULA space and require the explicit private-network opt-in.",
			))
		}
		parsed, urlIssues := validateUpstreamURL(stringValue(upstream, "baseUrl"), base+"/baseUrl")
		issues = append(issues, urlIssues...)
		if parsed != nil {
			port := parsed.Port()
			if port == "" {
				if parsed.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			if !numberArrayContains(objectValue(upstream, "destinationPolicy"), "allowedPorts", port) {
				issues = append(issues, errorIssue("upstream_port_not_allowed", base+"/destinationPolicy/allowedPorts", "The upstream base URL port must be explicitly allowed."))
			}
			if cidrErr == nil && upstreamtarget.ValidateDestination(
				stringValue(upstream, "baseUrl"),
				upstreamtarget.DestinationPolicy{AllowPrivate: allowPrivate, AllowedCIDRs: privateCIDRs},
			) != nil {
				issues = append(issues, errorIssue(
					"upstream_private_destination",
					base+"/baseUrl",
					"A literal private upstream address must be contained by an explicit private destination CIDR; special-use destinations are always forbidden.",
				))
			}
		}
		if allowRedirects, _ := destinationPolicy["allowRedirects"].(bool); allowRedirects {
			issues = append(issues, errorIssue("upstream_redirects_unsupported", base+"/destinationPolicy/allowRedirects", "Upstream redirects are not supported because each destination must be selected and validated by configuration."))
		}
		if dnsPinning, _ := destinationPolicy["dnsPinning"].(bool); !dnsPinning {
			issues = append(issues, errorIssue("upstream_dns_pinning_required", base+"/destinationPolicy/dnsPinning", "DNS destination validation must remain enabled."))
		}
		authentication := objectValue(upstream, "authentication")
		if environmentKind == "production" && stringValue(authentication, "type") == "none" {
			issues = append(issues, warningIssue("upstream_authentication_disabled", base+"/authentication/type", "This production upstream has no configured authentication."))
		}
		credentialHeaders := make([]string, 0, 8)
		switch stringValue(authentication, "type") {
		case "header":
			credentialHeaders = append(credentialHeaders, stringValue(authentication, "headerName"))
		case "headers":
			seen := make(map[string]struct{})
			for index, header := range objectArray(authentication, "headers") {
				name := stringValue(header, "headerName")
				canonical := http.CanonicalHeaderKey(name)
				if _, duplicate := seen[canonical]; duplicate {
					issues = append(issues, errorIssue(
						"upstream_authentication_header_duplicate",
						fmt.Sprintf("%s/authentication/headers/%d/headerName", base, index),
						"Configured authentication header names must be unique ignoring case.",
					))
				}
				seen[canonical] = struct{}{}
				credentialHeaders = append(credentialHeaders, name)
			}
		case "basic":
			if !runtimeBasicUsernameValid(stringValue(authentication, "username")) {
				issues = append(issues, errorIssue(
					"upstream_basic_username_invalid", base+"/authentication/username",
					"A Basic authentication username must be bounded visible ASCII without spaces, controls, or a colon.",
				))
			}
		}
		if headers, ok := upstream["staticHeaders"].(map[string]any); ok {
			for _, header := range sortedObjectKeys(headers) {
				if sensitiveHeader(header) {
					issues = append(issues, errorIssue("plaintext_credential_header", base+"/staticHeaders/"+pointerToken(header), "Credential-bearing headers must use a server-side secret reference."))
				}
				for _, credentialHeader := range credentialHeaders {
					if strings.EqualFold(header, credentialHeader) {
						issues = append(issues, errorIssue(
							"upstream_authentication_header_collision",
							base+"/staticHeaders/"+pointerToken(header),
							"A static header cannot replace a scoped authentication header.",
						))
					}
				}
			}
		}
		timeouts := objectValue(upstream, "timeouts")
		total, totalErr := parseConfigDuration(stringValue(timeouts, "total"))
		for _, name := range []string{"connect", "responseHeader", "firstByte", "idle"} {
			value, err := parseConfigDuration(stringValue(timeouts, name))
			if err != nil || totalErr != nil || value > total || value <= 0 || total > 10*time.Minute {
				issues = append(issues, errorIssue("upstream_timeout_invalid", base+"/timeouts/"+name, "Upstream timeouts must be positive, bounded, and no longer than the total timeout."))
			}
		}
	}
	return issues
}

func validateUpstreamURL(raw, path string) (*url.URL, []Issue) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		upstreamtarget.ValidateBaseURL(raw) != nil {
		return nil, []Issue{errorIssue("upstream_url_invalid", path, "The upstream URL must be an absolute HTTP(S) URL without credentials, query, or fragment.")}
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") || strings.HasSuffix(hostname, ".home.arpa") {
		return nil, []Issue{errorIssue("upstream_private_destination", path, "Private and local upstream destinations are not permitted.")}
	}
	return parsed, nil
}

func sensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token":
		return true
	default:
		return false
	}
}

func inputAccountingProfileSemanticIssues(profiles map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	for _, profileID := range sortedMapKeys(profiles) {
		profile := profiles[profileID]
		base := "/spec/inputAccountingProfiles/" + pointerToken(profileID)
		if !runtimeInputAccountingPhysicalModel(stringValue(profile, "physicalModel")) {
			issues = append(issues, errorIssue(
				"input_accounting_physical_model_invalid",
				base+"/physicalModel",
				"An input-accounting profile must name one exact bounded physical model without surrounding whitespace or control characters.",
			))
		}
		parsed, ok := rawInputAccountingProfile(profile)
		if !ok || !inputAccountingProfileContextPossible(parsed) {
			issues = append(issues, errorIssue(
				"input_accounting_profile_context_impossible",
				base+"/maximumContextTokens",
				"Request framing, one mandatory message or item, the protocol's minimal rewritten body, and output must fit the physical model context without overflowing int64 accounting.",
			))
		}
	}
	return issues
}

func modelSemanticIssues(models, upstreams, pricing, inputAccounting map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	for _, modelID := range sortedMapKeys(models) {
		model := models[modelID]
		base := "/spec/models/" + pointerToken(modelID)
		if !runtimeInputAccountingPhysicalModel(stringValue(model, "upstreamModel")) {
			issues = append(issues, errorIssue(
				"model_physical_model_invalid",
				base+"/upstreamModel",
				"A model must name one bounded physical model without surrounding whitespace or Unicode control characters.",
			))
		}
		upstream, ok := upstreams[stringValue(model, "upstream")]
		if !ok {
			issues = append(issues, errorIssue("upstream_reference_missing", base+"/upstream", "The referenced upstream does not exist."))
		} else {
			for _, capability := range stringArray(model, "capabilities") {
				requiredType, known := protocol.RequiredUpstreamType(capability)
				if !known || stringValue(upstream, "type") != requiredType {
					issues = append(issues, errorIssue(
						"model_upstream_protocol_mismatch",
						base+"/capabilities",
						"Every model capability must use its matching OpenAI-compatible, Anthropic, or generic upstream family.",
					))
					break
				}
			}
		}
		if pricingRef := stringValue(model, "pricingRef"); pricingRef != "" {
			catalog, ok := pricing[pricingRef]
			if !ok {
				issues = append(issues, errorIssue("pricing_reference_missing", base+"/pricingRef", "The referenced pricing catalog does not exist."))
			} else if !catalogContainsModel(catalog, modelID) {
				issues = append(issues, errorIssue("pricing_entry_missing", base+"/pricingRef", "The pricing catalog has no entry for this model."))
			}
		}
		if inputAccountingRef := stringValue(model, "inputAccountingRef"); inputAccountingRef != "" {
			profile, ok := inputAccounting[inputAccountingRef]
			if !ok {
				issues = append(issues, errorIssue(
					"input_accounting_reference_missing",
					base+"/inputAccountingRef",
					"The referenced input-accounting profile does not exist.",
				))
			} else if stringValue(profile, "physicalModel") != stringValue(model, "upstreamModel") ||
				!inputAccountingProtocolSupported(stringValue(profile, "protocol")) ||
				stringValue(profile, "method") != inputAccountingMethod ||
				!slices.Contains(stringArray(model, "capabilities"), stringValue(profile, "protocol")) {
				issues = append(issues, errorIssue(
					"input_accounting_reference_mismatch",
					base+"/inputAccountingRef",
					"The input-accounting profile must exactly match the model's physical model and structured-protocol capability.",
				))
			}
		}
	}
	return issues
}

func pricingSemanticIssues(catalogs, models map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	for _, catalogID := range sortedMapKeys(catalogs) {
		catalog := catalogs[catalogID]
		base := "/spec/pricingCatalogs/" + pointerToken(catalogID) + "/entries"
		seen := make(map[string]struct{})
		for index, entry := range objectArray(catalog, "entries") {
			modelID := stringValue(entry, "model")
			if _, ok := models[modelID]; !ok {
				issues = append(issues, errorIssue("model_reference_missing", fmt.Sprintf("%s/%d/model", base, index), "The referenced model does not exist."))
			}
			if _, ok := seen[modelID]; ok {
				issues = append(issues, errorIssue("duplicate_pricing_entry", fmt.Sprintf("%s/%d/model", base, index), "A pricing catalog may contain only one entry per model."))
			}
			seen[modelID] = struct{}{}
		}
	}
	return issues
}

func catalogContainsModel(catalog map[string]any, modelID string) bool {
	for _, entry := range objectArray(catalog, "entries") {
		if stringValue(entry, "model") == modelID {
			return true
		}
	}
	return false
}

func limitSemanticIssues(plans map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	for _, planID := range sortedMapKeys(plans) {
		plan := plans[planID]
		base := "/spec/limitPlans/" + pointerToken(planID) + "/limits"
		seenIdentities := make(map[immutableLimitIdentity]int)
		for index, limit := range objectArray(plan, "limits") {
			path := fmt.Sprintf("%s/%d", base, index)
			algorithm := stringValue(limit, "algorithm")
			metric := stringValue(limit, "metric")
			var valid bool
			switch algorithm {
			case "calendar":
				valid = hasFields(limit, "window", "maximum") && !hasAnyField(limit, "capacity", "refillPerSecond", "perRequestMaximum")
			case "token_bucket":
				valid = hasFields(limit, "capacity", "refillPerSecond") && !hasAnyField(limit, "window", "timezone", "maximum", "perRequestMaximum")
			case "concurrency":
				valid = (metric == "concurrent_requests" || metric == "concurrent_streams") && hasFields(limit, "maximum") && !hasAnyField(limit, "window", "timezone", "capacity", "refillPerSecond", "perRequestMaximum")
			case "per_request":
				valid = hasFields(limit, "perRequestMaximum") && !hasAnyField(limit, "window", "timezone", "maximum", "capacity", "refillPerSecond")
			default:
				valid = false
			}
			if !valid {
				issues = append(issues, errorIssue("limit_algorithm_fields_invalid", path, "Limit fields must match exactly one supported algorithm."))
			}

			maximum, _ := integerField(limit, "maximum")
			perRequestMaximum, _ := integerField(limit, "perRequestMaximum")
			capacity, _ := integerField(limit, "capacity")
			refill := RefillRate{}
			if raw, ok := limit["refillPerSecond"].(json.Number); ok {
				refill, _ = parseJSONRefillRate(raw)
			}
			hard, _ := limit["hard"].(bool)
			_, identity, executable := normalizeExecutableLimit(Limit{
				Metric: metric, Algorithm: algorithm, Scope: stringArray(limit, "scope"),
				Window: stringValue(limit, "window"), Timezone: stringValue(limit, "timezone"), Maximum: maximum,
				PerRequestMaximum: perRequestMaximum, Capacity: capacity,
				RefillPerSecond: refill, Hard: hard,
			})
			if !executable {
				issues = append(issues, errorIssue(
					"limit_capability_unsupported",
					path,
					"This release can activate only hard logical_requests calendar limits, hard input_tokens/output_tokens/total_tokens calendar limits, hard cost_nano_usd calendar limits, hard logical_requests/input_tokens/output_tokens/total_tokens token_bucket limits, hard input_tokens/output_tokens/total_tokens/request_bytes/image_units/tool_calls per_request limits, or hard concurrent_requests/concurrent_streams concurrency limits; input_tokens and total_tokens additionally require trusted input accounting on every reachable route, request_bytes/image_units/tool_calls additionally require exact request measurement on every reachable route, token_bucket limits require capacity from 1 through 9223372 and refillPerSecond from 0.000001 through 1000000 exactly representable with at most six decimal places, calendar limits require a bounded minute/hour/day/week/month window, a valid server-configured IANA timezone, and positive maximum, per_request limits require a positive perRequestMaximum, concurrency limits require a positive maximum, and every executable limit requires an explicit nonempty scope.",
				))
				continue
			}
			if _, duplicate := seenIdentities[identity]; duplicate {
				issues = append(issues, errorIssue(
					"duplicate_limit_rule",
					path,
					"A limit plan cannot repeat the same immutable metric, algorithm, window, timezone, and canonical scope identity.",
				))
				continue
			}
			seenIdentities[identity] = index
		}
	}
	return issues
}

func (validator *Validator) featureSemanticIssues(
	features, models, upstreams, attestations, limitPlans map[string]map[string]any,
) []Issue {
	issues := make([]Issue, 0)
	requiresCostPricing := rawPlansRequireCostPricing(limitPlans)
	for _, featureID := range sortedMapKeys(features) {
		feature := features[featureID]
		base := "/spec/features/" + pointerToken(featureID)
		protocolID := stringValue(feature, "protocol")
		if !protocol.ProtocolExecutable(protocolID) {
			issues = append(issues, errorIssue(
				"protocol_endpoint_unavailable",
				base+"/protocol",
				"The selected protocol has no executable adapter and public endpoint in this server build.",
			))
		}
		if _, ok := attestations[stringValue(feature, "attestationPolicy")]; !ok {
			issues = append(issues, errorIssue("attestation_policy_reference_missing", base+"/attestationPolicy", "The referenced attestation policy does not exist."))
		}
		access := objectValue(feature, "access")
		issues = append(issues, validator.celIssues(validator.policyCEL, stringValue(access, "expression"), base+"/access/expression", cel.BoolType)...)
		limitPlan := objectValue(feature, "limitPlan")
		limitExpression := stringValue(limitPlan, "expression")
		issues = append(issues, validator.celIssues(validator.policyCEL, limitExpression, base+"/limitPlan/expression", cel.StringType)...)
		if matches := constantIdentifierExpression.FindStringSubmatch(strings.TrimSpace(limitExpression)); len(matches) == 2 {
			if _, ok := limitPlans[matches[1]]; !ok {
				issues = append(issues, errorIssue("limit_plan_reference_missing", base+"/limitPlan/expression", "The constant limit-plan expression references a missing plan."))
			}
		}
		if protocolID == "opaque_http" {
			if opaquePolicy, ok := feature["opaqueHttp"].(map[string]any); !ok {
				issues = append(issues, errorIssue("opaque_http_policy_missing", base+"/opaqueHttp", "Opaque HTTP features require an explicit method, path, and body policy."))
			} else {
				issues = append(issues, opaqueHTTPPolicySemanticIssues(opaquePolicy, base+"/opaqueHttp")...)
			}
		} else if _, ok := feature["opaqueHttp"]; ok {
			issues = append(issues, errorIssue("opaque_http_policy_unexpected", base+"/opaqueHttp", "Opaque HTTP policy is valid only for opaque HTTP features."))
		}
		if output, ok := feature["output"].(map[string]any); ok {
			if !protocolRequiresOutputPolicy(protocolID) {
				issues = append(issues, errorIssue("output_policy_unexpected", base+"/output", "Non-generative protocols cannot configure output-token limits."))
			}
			defaultMaximum, _ := integerField(output, "defaultMaximumTokens")
			absoluteMaximum, _ := integerField(output, "absoluteMaximumTokens")
			if defaultMaximum > absoluteMaximum {
				issues = append(issues, errorIssue("output_default_exceeds_absolute", base+"/output/defaultMaximumTokens", "The default output maximum cannot exceed the absolute maximum."))
			}
		} else if protocolRequiresOutputPolicy(protocolID) {
			issues = append(issues, errorIssue("output_policy_required", base+"/output", "Token-generating protocols require a server-owned output limit."))
		}
		routes, routeIssues := indexObjects(objectArray(feature, "routes"), base+"/routes")
		issues = append(issues, routeIssues...)
		hasFallback := false
		stickyByPriority := make(map[int64]string, len(routes))
		for _, routeID := range sortedMapKeys(routes) {
			route := routes[routeID]
			routePath := base + "/routes/" + pointerToken(routeID)
			if protocolID == "opaque_http" {
				if _, ok := integerField(route, "maxResponseBytes"); !ok {
					issues = append(issues, errorIssue(
						"opaque_http_response_limit_missing",
						routePath+"/maxResponseBytes",
						"Every opaque HTTP route requires an explicit positive response byte limit.",
					))
				}
			} else if hasAnyField(route, "maxResponseBytes", "streamingAllowed", "retryUnsafeMethods") {
				issues = append(issues, errorIssue(
					"opaque_http_route_policy_unexpected",
					routePath,
					"Opaque HTTP response, streaming, and unsafe-method replay policy is valid only for opaque HTTP features.",
				))
			}
			if retryPolicy, ok := route["retryPolicy"].(map[string]any); ok {
				initialBackoff, initialOK := integerField(retryPolicy, "initialBackoffMilliseconds")
				maximumBackoff, maximumOK := integerField(retryPolicy, "maximumBackoffMilliseconds")
				if initialOK && maximumOK && (maximumBackoff < initialBackoff ||
					(initialBackoff == 0 && maximumBackoff != 0)) {
					issues = append(issues, errorIssue(
						"route_retry_backoff_invalid",
						routePath+"/retryPolicy/maximumBackoffMilliseconds",
						"Maximum retry backoff must be at least the initial backoff, and both must be zero when backoff is disabled.",
					))
				}
			}
			when := strings.TrimSpace(stringValue(route, "when"))
			issues = append(issues, validator.celIssues(validator.policyCEL, when, routePath+"/when", cel.BoolType)...)
			priority, _ := integerField(route, "priority")
			stickyBy := stringValue(route, "stickyBy")
			if existing, ok := stickyByPriority[priority]; ok && existing != stickyBy {
				issues = append(issues, errorIssue("route_sticky_group_mismatch", routePath+"/stickyBy", "Routes at one priority must use the same deterministic selection key."))
			} else {
				stickyByPriority[priority] = stickyBy
			}
			if when == "true" {
				hasFallback = true
			}
			modelID := stringValue(route, "model")
			model, ok := models[modelID]
			if !ok {
				issues = append(issues, errorIssue("model_reference_missing", routePath+"/model", "The referenced model does not exist."))
				continue
			}
			if !slices.Contains(stringArray(model, "capabilities"), protocolID) {
				issues = append(issues, errorIssue("model_protocol_unsupported", routePath+"/model", "The selected model does not advertise this feature protocol."))
			}
			if routeTimeouts, configured := route["timeouts"].(map[string]any); configured {
				if upstream, exists := upstreams[stringValue(model, "upstream")]; exists {
					issues = append(issues, routeTimeoutSemanticIssues(
						routeTimeouts, objectValue(upstream, "timeouts"), routePath+"/timeouts",
					)...)
				}
			}
			if requiresCostPricing && stringValue(model, "pricingRef") == "" {
				issues = append(issues, errorIssue("pricing_required_for_cost_limit", routePath+"/model", "Every routed model requires pricing when a cost limit is configured."))
			}
		}
		if !hasFallback {
			issues = append(issues, warningIssue("route_fallback_missing", base+"/routes", "No unconditional route exists; some valid requests may have no route."))
		}
	}
	return issues
}

func routeTimeoutSemanticIssues(overrides, inherited map[string]any, base string) []Issue {
	names := []string{"connect", "responseHeader", "firstByte", "idle", "total"}
	values := make(map[string]time.Duration, len(names))
	for _, name := range names {
		value, err := parseConfigDuration(stringValue(inherited, name))
		if err != nil || value <= 0 {
			return []Issue{errorIssue(
				"route_timeout_invalid", base,
				"Route timeout overrides require a valid fully defaulted upstream timeout policy.",
			)}
		}
		values[name] = value
	}
	for _, name := range names {
		if _, configured := overrides[name]; !configured {
			continue
		}
		value, err := parseConfigDuration(stringValue(overrides, name))
		if err != nil || value <= 0 {
			return []Issue{errorIssue(
				"route_timeout_invalid", base+"/"+name,
				"Route timeout overrides must be positive bounded durations.",
			)}
		}
		values[name] = value
	}
	total := values["total"]
	if total > 10*time.Minute {
		return []Issue{errorIssue(
			"route_timeout_invalid", base+"/total",
			"The effective route total timeout cannot exceed ten minutes.",
		)}
	}
	for _, name := range []string{"connect", "responseHeader", "firstByte", "idle"} {
		if values[name] > total {
			return []Issue{errorIssue(
				"route_timeout_invalid", base+"/"+name,
				"Each effective route timeout must be no longer than the effective total timeout.",
			)}
		}
	}
	return nil
}

func opaqueHTTPPolicySemanticIssues(policy map[string]any, base string) []Issue {
	issues := make([]Issue, 0)
	prefixes := stringArray(policy, "pathPrefixes")
	templates := stringArray(policy, "pathTemplates")
	if len(prefixes) > 0 && len(templates) > 0 {
		issues = append(issues, errorIssue(
			"opaque_http_path_policy_conflict", base,
			"Opaque HTTP pathTemplates and compatibility-only pathPrefixes cannot be configured together.",
		))
	}
	seenPrefixes := make(map[string]struct{})
	for index, prefix := range prefixes {
		path := fmt.Sprintf("%s/pathPrefixes/%d", base, index)
		if !runtimeCanonicalUpstreamPath(prefix) {
			issues = append(issues, errorIssue(
				"opaque_http_path_prefix_invalid", path,
				"Opaque HTTP path prefixes must be canonical bounded provider-relative paths without escaping, a query, or a fragment.",
			))
		}
		if _, duplicate := seenPrefixes[prefix]; duplicate {
			issues = append(issues, errorIssue(
				"opaque_http_path_prefix_duplicate", path,
				"Opaque HTTP path prefixes must be unique.",
			))
		}
		seenPrefixes[prefix] = struct{}{}
	}
	for index, template := range templates {
		path := fmt.Sprintf("%s/pathTemplates/%d", base, index)
		if !protocol.ValidOpaqueHTTPPathTemplate(template) {
			issues = append(issues, errorIssue(
				"opaque_http_path_template_invalid", path,
				"Opaque HTTP path templates must be canonical exact-depth provider-relative paths; captures must be unique whole segments such as {resource_id}, and catch-alls, escaping, queries, fragments, and traversal are forbidden.",
			))
			continue
		}
		for previous := 0; previous < index; previous++ {
			if protocol.OpaqueHTTPPathTemplatesOverlap(templates[previous], template) {
				issues = append(issues, errorIssue(
					"opaque_http_path_template_ambiguous", path,
					"Opaque HTTP path templates must be pairwise disjoint so one provider path cannot match multiple literal or captured templates.",
				))
				break
			}
		}
	}
	seenHeaders := make(map[string]struct{})
	for index, header := range stringArray(policy, "allowedRequestHeaders") {
		path := fmt.Sprintf("%s/allowedRequestHeaders/%d", base, index)
		canonical := http.CanonicalHeaderKey(header)
		if !runtimeHeaderNamePattern.MatchString(header) || runtimeForwardHeaderForbidden(canonical) {
			issues = append(issues, errorIssue(
				"opaque_http_request_header_forbidden", path,
				"Opaque HTTP request-header forwarding cannot include credentials, Latchway controls, forwarding metadata, compression, or hop-by-hop headers.",
			))
		}
		if _, duplicate := seenHeaders[canonical]; duplicate {
			issues = append(issues, errorIssue(
				"opaque_http_request_header_duplicate", path,
				"Opaque HTTP request-header names must be unique case-insensitively.",
			))
		}
		seenHeaders[canonical] = struct{}{}
	}
	return issues
}

func rawPlansRequireCostPricing(plans map[string]map[string]any) bool {
	for _, plan := range plans {
		for _, limit := range objectArray(plan, "limits") {
			if stringValue(limit, "metric") == "cost_nano_usd" {
				return true
			}
		}
	}
	return false
}

func rawInputAccountingProfile(profile map[string]any) (InputAccountingProfile, bool) {
	maximumFramingTokensPerRequest, requestOK := integerField(profile, "maximumFramingTokensPerRequest")
	maximumFramingTokensPerMessage, messageOK := integerField(profile, "maximumFramingTokensPerMessage")
	maximumContextTokens, contextOK := integerField(profile, "maximumContextTokens")
	if !requestOK || !messageOK || !contextOK {
		return InputAccountingProfile{}, false
	}
	return InputAccountingProfile{
		ID:                             stringValue(profile, "id"),
		Protocol:                       stringValue(profile, "protocol"),
		Method:                         stringValue(profile, "method"),
		PhysicalModel:                  stringValue(profile, "physicalModel"),
		MaximumFramingTokensPerRequest: maximumFramingTokensPerRequest,
		MaximumFramingTokensPerMessage: maximumFramingTokensPerMessage,
		MaximumContextTokens:           maximumContextTokens,
	}, true
}

func (validator *Validator) celIssues(environment *cel.Env, expression, path string, expected *cel.Type) []Issue {
	ast, compileIssues := environment.Compile(expression)
	if compileIssues != nil && compileIssues.Err() != nil {
		return []Issue{errorIssue("cel_invalid", path, "The CEL expression could not be parsed or type-checked.")}
	}
	if expected != nil {
		actual := ast.OutputType()
		if actual.Kind() != cel.DynKind && !expected.IsAssignableType(actual) {
			return []Issue{errorIssue("cel_result_type_invalid", path, "The CEL expression returns the wrong policy type.")}
		}
	}
	return nil
}

func sessionSemanticIssues(session map[string]any) []Issue {
	issues := make([]Issue, 0)
	access, accessErr := parseConfigDuration(stringValue(session, "accessTokenTtl"))
	challenge, challengeErr := parseConfigDuration(stringValue(session, "challengeTtl"))
	refresh, refreshErr := parseConfigDuration(stringValue(session, "refreshTokenTtl"))
	if accessErr != nil || access < time.Minute || access > time.Hour {
		issues = append(issues, errorIssue("access_token_ttl_out_of_bounds", "/spec/session/accessTokenTtl", "Access-token TTL must be between one minute and one hour."))
	}
	if challengeErr != nil || challenge < 30*time.Second || challenge > 10*time.Minute {
		issues = append(issues, errorIssue("challenge_ttl_out_of_bounds", "/spec/session/challengeTtl", "Challenge TTL must be between 30 seconds and ten minutes."))
	}
	if refreshErr != nil || refresh < time.Hour || refresh > 90*24*time.Hour {
		issues = append(issues, errorIssue("refresh_token_ttl_out_of_bounds", "/spec/session/refreshTokenTtl", "Refresh-token TTL must be between one hour and 90 days."))
	}
	if accessErr == nil && challengeErr == nil && challenge > access {
		issues = append(issues, errorIssue("challenge_ttl_exceeds_access_ttl", "/spec/session/challengeTtl", "Challenge TTL cannot exceed access-token TTL."))
	}
	if accessErr == nil && refreshErr == nil && refresh <= access {
		issues = append(issues, errorIssue("refresh_ttl_too_short", "/spec/session/refreshTokenTtl", "Refresh-token TTL must exceed access-token TTL."))
	}
	return issues
}

func privacySemanticIssues(privacy map[string]any) []Issue {
	prompt, _ := privacy["storePromptBodies"].(bool)
	response, _ := privacy["storeResponseBodies"].(bool)
	_, retention := privacy["bodyRetention"]
	if prompt || response {
		return []Issue{errorIssue(
			"body_storage_unsupported_v1",
			"/spec/privacy",
			"Prompt and response body storage is reserved but unsupported in Latchway v1; both storage flags must remain false.",
		)}
	}
	if retention {
		duration, err := parseConfigDuration(stringValue(privacy, "bodyRetention"))
		if err != nil || duration < time.Minute || duration > 30*24*time.Hour {
			return []Issue{errorIssue("body_retention_out_of_bounds", "/spec/privacy/bodyRetention", "Body retention must be between one minute and 30 days.")}
		}
	}
	return nil
}

func secretReferenceIssues(root map[string]any, secretNames map[string]struct{}) []Issue {
	issues := make([]Issue, 0)
	check := func(reference, path string) {
		if reference == "" {
			return
		}
		name := strings.TrimPrefix(reference, "secret/")
		if _, ok := secretNames[name]; !ok {
			issues = append(issues, errorIssue("secret_reference_missing", path, "The referenced server-side secret does not exist in this environment."))
		}
	}

	spec := objectValue(root, "spec")
	for index, provider := range objectArray(spec, "identityProviders") {
		base := fmt.Sprintf("/spec/identityProviders/%d", index)
		check(stringValue(provider, "staticPublicKeySecretRef"), base+"/staticPublicKeySecretRef")
		check(stringValue(provider, "symmetricSecretRef"), base+"/symmetricSecretRef")
	}
	for index, policy := range objectArray(spec, "attestationPolicies") {
		platforms := objectValue(policy, "platforms")
		for _, platform := range sortedObjectKeys(platforms) {
			selection := objectValue(platforms, platform)
			check(stringValue(selection, "secretRef"), fmt.Sprintf("/spec/attestationPolicies/%d/platforms/%s/secretRef", index, pointerToken(platform)))
		}
	}
	for index, upstream := range objectArray(spec, "upstreams") {
		authentication := objectValue(upstream, "authentication")
		check(stringValue(authentication, "secretRef"), fmt.Sprintf("/spec/upstreams/%d/authentication/secretRef", index))
		for headerIndex, header := range objectArray(authentication, "headers") {
			check(
				stringValue(header, "secretRef"),
				fmt.Sprintf("/spec/upstreams/%d/authentication/headers/%d/secretRef", index, headerIndex),
			)
		}
	}
	return issues
}

func deduplicateIssues(issues []Issue) []Issue {
	result := make([]Issue, 0, len(issues))
	seen := make(map[string]struct{}, len(issues))
	for _, issue := range issues {
		key := issue.Severity + "\x00" + issue.Code + "\x00" + issue.Path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, issue)
		if len(result) == 1_000 {
			break
		}
	}
	return result
}

func pointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func stringArray(parent map[string]any, key string) []string {
	values, _ := parent[key].([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringField(parent map[string]any, key string) (string, bool) {
	value, ok := parent[key].(string)
	return value, ok
}

func integerField(parent map[string]any, key string) (int64, bool) {
	value, ok := parent[key].(json.Number)
	if !ok {
		return 0, false
	}
	return parseJSONInteger(value)
}

func numberArrayContains(parent map[string]any, key, expected string) bool {
	values, _ := parent[key].([]any)
	for _, value := range values {
		if number, ok := value.(json.Number); ok && string(number) == expected {
			return true
		}
	}
	return false
}

func hasFields(parent map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := parent[key]; !ok {
			return false
		}
	}
	return true
}

func hasAnyField(parent map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := parent[key]; ok {
			return true
		}
	}
	return false
}

func parseConfigDuration(value string) (time.Duration, error) {
	units := []struct {
		suffix string
		value  time.Duration
	}{
		{suffix: "ms", value: time.Millisecond},
		{suffix: "s", value: time.Second},
		{suffix: "m", value: time.Minute},
		{suffix: "h", value: time.Hour},
		{suffix: "d", value: 24 * time.Hour},
	}
	for _, unit := range units {
		if !strings.HasSuffix(value, unit.suffix) {
			continue
		}
		number := strings.TrimSuffix(value, unit.suffix)
		parsed, err := strconv.ParseInt(number, 10, 64)
		if err != nil || parsed <= 0 || parsed > int64((time.Duration(1<<63-1))/unit.value) {
			return 0, ErrInvalid
		}
		return time.Duration(parsed) * unit.value, nil
	}
	return 0, ErrInvalid
}
