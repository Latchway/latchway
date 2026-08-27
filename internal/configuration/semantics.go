package configuration

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	upstreamtarget "github.com/latchway/latchway/internal/upstream"
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
	upstreams, upstreamIssues := indexObjects(objectArray(spec, "upstreams"), "/spec/upstreams")
	issues = append(issues, upstreamIssues...)
	models, modelIssues := indexObjects(objectArray(spec, "models"), "/spec/models")
	issues = append(issues, modelIssues...)
	pricing, pricingIssues := indexObjects(objectArray(spec, "pricingCatalogs"), "/spec/pricingCatalogs")
	issues = append(issues, pricingIssues...)
	limitPlans, limitPlanIssues := indexObjects(objectArray(spec, "limitPlans"), "/spec/limitPlans")
	issues = append(issues, limitPlanIssues...)
	features, featureIssues := indexObjects(objectArray(spec, "features"), "/spec/features")
	issues = append(issues, featureIssues...)

	issues = append(issues, validator.identityIssues(identities)...)
	issues = append(issues, attestationSemanticIssues(attestations, environment.EnvironmentKind)...)
	issues = append(issues, upstreamSemanticIssues(upstreams, environment.EnvironmentKind)...)
	issues = append(issues, modelSemanticIssues(models, upstreams, pricing)...)
	issues = append(issues, pricingSemanticIssues(pricing, models)...)
	issues = append(issues, limitSemanticIssues(limitPlans)...)
	issues = append(issues, validator.featureSemanticIssues(features, models, attestations, limitPlans, pricing)...)
	issues = append(issues, sessionSemanticIssues(objectValue(spec, "session"))...)
	issues = append(issues, privacySemanticIssues(objectValue(spec, "privacy"))...)
	issues = append(issues, secretReferenceIssues(root, environment.SecretNames)...)
	return deduplicateIssues(issues)
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
			if mode == "required" && stringValue(selection, "minimumTrustLevel") == "none" {
				issues = append(issues, errorIssue("attestation_trust_too_weak", selectionPath+"/minimumTrustLevel", "Required attestation must require a verified trust level."))
			}
			// The current verifier set does not bind either value into durable
			// attestation evidence. Reject enabled constraints at validation time so
			// an activated policy cannot place every client into a permanent
			// request-time step-up loop.
			if mode != "disabled" && len(stringArray(selection, "applicationIdentifiers")) != 0 {
				issues = append(issues, errorIssue("attestation_application_identifiers_unsupported", selectionPath+"/applicationIdentifiers", "Application identifier constraints are not supported until the selected verifier binds them into durable attestation evidence."))
			}
			if mode != "disabled" && len(stringArray(selection, "allowedOrigins")) != 0 {
				issues = append(issues, errorIssue("attestation_allowed_origins_unsupported", selectionPath+"/allowedOrigins", "Allowed-origin constraints are not supported until the selected verifier binds them into durable attestation evidence."))
			}
		}
	}
	return issues
}

func providerAllowedOnPlatform(provider, platform string) bool {
	switch platform {
	case "ios", "react_native_ios":
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
		}
		destinationPolicy := objectValue(upstream, "destinationPolicy")
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
		if headers, ok := upstream["staticHeaders"].(map[string]any); ok {
			for _, header := range sortedObjectKeys(headers) {
				if sensitiveHeader(header) {
					issues = append(issues, errorIssue("plaintext_credential_header", base+"/staticHeaders/"+pointerToken(header), "Credential-bearing headers must use a server-side secret reference."))
				}
			}
		}
		timeouts := objectValue(upstream, "timeouts")
		total, totalErr := parseConfigDuration(stringValue(timeouts, "total"))
		for _, name := range []string{"connect", "firstByte", "idle"} {
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
	if address := net.ParseIP(hostname); address != nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast()) {
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

func modelSemanticIssues(models, upstreams, pricing map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	for _, modelID := range sortedMapKeys(models) {
		model := models[modelID]
		base := "/spec/models/" + pointerToken(modelID)
		if _, ok := upstreams[stringValue(model, "upstream")]; !ok {
			issues = append(issues, errorIssue("upstream_reference_missing", base+"/upstream", "The referenced upstream does not exist."))
		}
		if pricingRef := stringValue(model, "pricingRef"); pricingRef != "" {
			catalog, ok := pricing[pricingRef]
			if !ok {
				issues = append(issues, errorIssue("pricing_reference_missing", base+"/pricingRef", "The referenced pricing catalog does not exist."))
			} else if !catalogContainsModel(catalog, modelID) {
				issues = append(issues, errorIssue("pricing_entry_missing", base+"/pricingRef", "The pricing catalog has no entry for this model."))
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
			valid := true
			switch algorithm {
			case "calendar":
				valid = hasFields(limit, "window", "maximum") && !hasAnyField(limit, "capacity", "refillPerSecond", "perRequestMaximum")
			case "token_bucket":
				valid = hasFields(limit, "capacity", "refillPerSecond") && !hasAnyField(limit, "window", "maximum", "perRequestMaximum")
			case "concurrency":
				valid = (metric == "concurrent_requests" || metric == "concurrent_streams") && hasFields(limit, "maximum") && !hasAnyField(limit, "window", "capacity", "refillPerSecond", "perRequestMaximum")
			case "per_request":
				valid = hasFields(limit, "perRequestMaximum") && !hasAnyField(limit, "window", "maximum", "capacity", "refillPerSecond")
			default:
				valid = false
			}
			if !valid {
				issues = append(issues, errorIssue("limit_algorithm_fields_invalid", path, "Limit fields must match exactly one supported algorithm."))
			}

			maximum, _ := integerField(limit, "maximum")
			perRequestMaximum, _ := integerField(limit, "perRequestMaximum")
			capacity, _ := integerField(limit, "capacity")
			refill, _ := limit["refillPerSecond"].(json.Number)
			hard, _ := limit["hard"].(bool)
			_, identity, executable := normalizeExecutableLimit(Limit{
				Metric: metric, Algorithm: algorithm, Scope: stringArray(limit, "scope"),
				Window: stringValue(limit, "window"), Maximum: maximum,
				PerRequestMaximum: perRequestMaximum, Capacity: capacity,
				RefillPerSecond: refill, Hard: hard,
			})
			if !executable {
				issues = append(issues, errorIssue(
					"limit_capability_unsupported",
					path,
					"This release can activate only hard logical_requests calendar limits, hard output_tokens calendar limits, hard output_tokens per_request limits, or hard concurrent_requests/concurrent_streams concurrency limits; calendar limits require a supported window and positive maximum, per_request limits require a positive perRequestMaximum, concurrency limits require a positive maximum, and every executable limit requires an explicit nonempty scope.",
				))
				continue
			}
			if _, duplicate := seenIdentities[identity]; duplicate {
				issues = append(issues, errorIssue(
					"duplicate_limit_rule",
					path,
					"A limit plan cannot repeat the same immutable metric, algorithm, window, and canonical scope identity.",
				))
				continue
			}
			seenIdentities[identity] = index
		}
	}
	return issues
}

func (validator *Validator) featureSemanticIssues(features, models, attestations, limitPlans, pricing map[string]map[string]any) []Issue {
	issues := make([]Issue, 0)
	costLimits := false
	for _, plan := range limitPlans {
		for _, limit := range objectArray(plan, "limits") {
			if stringValue(limit, "metric") == "cost_nano_usd" {
				costLimits = true
			}
		}
	}
	for _, featureID := range sortedMapKeys(features) {
		feature := features[featureID]
		base := "/spec/features/" + pointerToken(featureID)
		protocol := stringValue(feature, "protocol")
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
		if protocol == "opaque_http" {
			if _, ok := feature["opaqueHttp"]; !ok {
				issues = append(issues, errorIssue("opaque_http_policy_missing", base+"/opaqueHttp", "Opaque HTTP features require an explicit method, path, and body policy."))
			}
		} else if _, ok := feature["opaqueHttp"]; ok {
			issues = append(issues, errorIssue("opaque_http_policy_unexpected", base+"/opaqueHttp", "Opaque HTTP policy is valid only for opaque HTTP features."))
		}
		if output, ok := feature["output"].(map[string]any); ok {
			defaultMaximum, _ := integerField(output, "defaultMaximumTokens")
			absoluteMaximum, _ := integerField(output, "absoluteMaximumTokens")
			if defaultMaximum > absoluteMaximum {
				issues = append(issues, errorIssue("output_default_exceeds_absolute", base+"/output/defaultMaximumTokens", "The default output maximum cannot exceed the absolute maximum."))
			}
		} else if protocolRequiresOutputPolicy(protocol) {
			issues = append(issues, errorIssue("output_policy_required", base+"/output", "Token-generating protocols require a server-owned output limit."))
		}
		routes, routeIssues := indexObjects(objectArray(feature, "routes"), base+"/routes")
		issues = append(issues, routeIssues...)
		hasFallback := false
		stickyByPriority := make(map[int64]string, len(routes))
		for _, routeID := range sortedMapKeys(routes) {
			route := routes[routeID]
			routePath := base + "/routes/" + pointerToken(routeID)
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
			if !slices.Contains(stringArray(model, "capabilities"), protocol) {
				issues = append(issues, errorIssue("model_protocol_unsupported", routePath+"/model", "The selected model does not advertise this feature protocol."))
			}
			if costLimits && stringValue(model, "pricingRef") == "" {
				issues = append(issues, errorIssue("pricing_required_for_cost_limit", routePath+"/model", "Every routed model requires pricing when a cost limit is configured."))
			}
		}
		if !hasFallback {
			issues = append(issues, warningIssue("route_fallback_missing", base+"/routes", "No unconditional route exists; some valid requests may have no route."))
		}
	}
	_ = pricing
	return issues
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
	if (prompt || response) && !retention {
		return []Issue{errorIssue("body_retention_required", "/spec/privacy/bodyRetention", "Body storage requires an explicit bounded retention period.")}
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
	var visit func(any, string)
	visit = func(value any, path string) {
		switch current := value.(type) {
		case map[string]any:
			for _, key := range sortedObjectKeys(current) {
				childPath := path + "/" + pointerToken(key)
				child := current[key]
				if strings.HasSuffix(strings.ToLower(key), "secretref") {
					reference, _ := child.(string)
					name := strings.TrimPrefix(reference, "secret/")
					if _, ok := secretNames[name]; !ok {
						issues = append(issues, errorIssue("secret_reference_missing", childPath, "The referenced server-side secret does not exist in this environment."))
					}
				}
				visit(child, childPath)
			}
		case []any:
			for index, child := range current {
				visit(child, fmt.Sprintf("%s/%d", path, index))
			}
		}
	}
	visit(root, "")
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
