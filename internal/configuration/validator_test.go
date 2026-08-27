package configuration

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func TestValidatorCompilesStrictNormalizedConfiguration(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}
	checkedAt := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	report, compiled := validator.Validate(validConfigurationDocument(t), testEnvironment(), checkedAt)
	if !report.Valid {
		t.Fatalf("valid configuration rejected: %+v", report.Issues)
	}
	if !report.CheckedAt.Equal(checkedAt) || len(compiled) == 0 {
		t.Fatalf("unexpected validation result: report=%+v compiled=%q", report, compiled)
	}
	value, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatalf("decode compiled configuration: %v", err)
	}
	spec := objectValue(value.(map[string]any), "spec")
	session := objectValue(spec, "session")
	if stringValue(session, "challengeTtl") != "5m" || stringValue(session, "accessTokenTtl") != "10m" || stringValue(session, "refreshTokenTtl") != "30d" {
		t.Fatalf("compiled session defaults = %#v", session)
	}
	model := objectArray(spec, "models")[0]
	if got := stringArray(model, "capabilities"); len(got) != 3 || got[0] != "openai_responses" {
		t.Fatalf("inferred model capabilities = %v", got)
	}
	limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
	if stringValue(limit, "algorithm") != "calendar" {
		t.Fatalf("inferred limit algorithm = %#v", limit["algorithm"])
	}
}

func TestValidatorRejectsSchemaReferencesAndBadPolicy(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	document["unexpected"] = true
	encoded, _ := json.Marshal(document)
	issues := validator.SchemaIssues(encoded)
	if !hasIssue(issues, "schema_additionalproperties") && !hasIssue(issues, "schema_additional_properties") {
		t.Fatalf("unknown member issues = %+v", issues)
	}

	document = configurationObject(t)
	spec := objectValue(document, "spec")
	upstream := objectArray(spec, "upstreams")[0]
	upstream["authentication"] = map[string]any{"type": "bearer", "secretRef": "secret/missing"}
	feature := objectArray(spec, "features")[0]
	objectValue(feature, "access")["expression"] = "claims.administrator"
	objectArray(feature, "routes")[0]["model"] = "missing-model"
	encoded, _ = json.Marshal(document)
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil {
		t.Fatalf("invalid configuration compiled: report=%+v compiled=%q", report, compiled)
	}
	for _, code := range []string{"cel_invalid", "model_reference_missing", "secret_reference_missing"} {
		if !hasIssue(report.Issues, code) {
			t.Errorf("missing %s in %+v", code, report.Issues)
		}
	}
}

func TestValidatorRejectsUnsupportedUpstreamDestinationRelaxation(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		field string
		value any
		code  string
	}{
		{name: "redirects", field: "allowRedirects", value: true, code: "upstream_redirects_unsupported"},
		{name: "DNS validation", field: "dnsPinning", value: false, code: "upstream_dns_pinning_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
			destination := map[string]any{test.field: test.value}
			upstream["destinationPolicy"] = destination
			encoded, _ := json.Marshal(document)
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("unsafe destination policy compiled: %+v", report.Issues)
			}
		})
	}
}

func TestValidatorNeverEmitsAnUnloadableRuntimeSnapshot(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
	authentication := objectValue(upstream, "authentication")
	// The canonical schema permits this irrelevant member for a "none"
	// strategy. Runtime compilation rejects it so activation cannot create an
	// active revision that every data-plane snapshot load would reject.
	authentication["headerName"] = "X-Provider-Key"
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "runtime_configuration_invalid") {
		t.Fatalf("unloadable configuration compiled: report=%+v compiled=%s", report, compiled)
	}

	valid := validConfigurationDocument(t)
	report, compiled = validator.Validate(valid, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("valid configuration did not compile: %+v", report.Issues)
	}
	if _, err := newActiveSnapshot("validation", "validation", valid, compiled); err != nil {
		t.Fatalf("validator emitted an unloadable snapshot: %v", err)
	}
}

func TestValidatorRequiresOutputPolicyForTokenGeneratingProtocols(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"openai_responses", "openai_chat", "anthropic_messages"} {
		t.Run(protocol, func(t *testing.T) {
			document := configurationObject(t)
			spec := objectValue(document, "spec")
			feature := objectArray(spec, "features")[0]
			feature["protocol"] = protocol
			delete(feature, "output")
			objectArray(spec, "models")[0]["capabilities"] = []any{protocol}
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, "output_policy_required") {
				t.Fatalf("token-generating feature without output policy compiled: %+v", report.Issues)
			}
		})
	}
}

func TestValidatorRejectsMixedStickyKeysWithinOnePriority(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	feature := objectArray(objectValue(document, "spec"), "features")[0]
	routes := objectArray(feature, "routes")
	second := deepClone(routes[0]).(map[string]any)
	second["id"] = "secondary"
	second["stickyBy"] = "user"
	feature["routes"] = append(routes, second)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "route_sticky_group_mismatch") {
		t.Fatalf("ambiguous weighted group compiled: %+v", report.Issues)
	}
}

func TestValidatorRequiresClerkAudience(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	spec := objectValue(document, "spec")
	spec["identityProviders"] = []any{map[string]any{
		"id": "clerk", "type": "clerk", "issuer": "https://clerk.example.test",
	}}
	encoded, _ := json.Marshal(document)
	issues := validator.SchemaIssues(encoded)
	if !hasIssue(issues, "schema_required") && !hasIssue(issues, "schema_allof") {
		t.Fatalf("Clerk provider without audiences was not rejected: %+v", issues)
	}

	objectArray(spec, "identityProviders")[0]["audiences"] = []any{"latchway-client"}
	encoded, _ = json.Marshal(document)
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("Clerk provider with issuer and audience was rejected: %+v", report.Issues)
	}
}

func TestValidatorRequiresDebugAttestationKeySecret(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	selection := objectValue(
		objectValue(objectArray(objectValue(document, "spec"), "attestationPolicies")[0], "platforms"),
		"ios",
	)
	selection["provider"] = "debug"
	selection["minimumTrustLevel"] = "debug"
	selection["dangerousAllowInProduction"] = true
	encoded, _ := json.Marshal(document)
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "debug_attestation_secret_required") {
		t.Fatalf("enabled debug attestation without a key secret was not rejected: %+v", report.Issues)
	}

	selection["secretRef"] = "secret/present"
	encoded, _ = json.Marshal(document)
	report, compiled = validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("debug attestation with explicit server-side key secret was rejected: %+v", report.Issues)
	}
}

func TestValidatorRestrictsSymmetricIdentityKeysToExplicitHS256(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	validProvider := map[string]any{
		"id":                       "custom",
		"type":                     "custom_jwt",
		"issuer":                   "https://issuer.example.test",
		"audiences":                []any{"latchway-client"},
		"allowedAlgorithms":        []any{"HS256"},
		"symmetricSecretRef":       "secret/present",
		"acknowledgeSymmetricRisk": true,
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "generic OIDC symmetric", mutate: func(provider map[string]any) { provider["type"] = "generic_oidc" }},
		{name: "asymmetric algorithm with symmetric source", mutate: func(provider map[string]any) { provider["allowedAlgorithms"] = []any{"RS256"} }},
		{name: "mixed algorithms", mutate: func(provider map[string]any) { provider["allowedAlgorithms"] = []any{"HS256", "RS256"} }},
		{name: "risk not acknowledged", mutate: func(provider map[string]any) { provider["acknowledgeSymmetricRisk"] = false }},
		{name: "HS256 with asymmetric source", mutate: func(provider map[string]any) {
			delete(provider, "symmetricSecretRef")
			provider["staticPublicKeySecretRef"] = "secret/present"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			provider := deepClone(validProvider).(map[string]any)
			test.mutate(provider)
			objectValue(document, "spec")["identityProviders"] = []any{provider}
			encoded, _ := json.Marshal(document)
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil {
				t.Fatalf("unsafe symmetric identity configuration compiled: %+v", report.Issues)
			}
		})
	}

	document := configurationObject(t)
	objectValue(document, "spec")["identityProviders"] = []any{deepClone(validProvider)}
	encoded, _ := json.Marshal(document)
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("explicit custom JWT HS256 configuration was rejected: %+v", report.Issues)
	}

	semanticIssues := validator.identityIssues(map[string]map[string]any{
		"custom": {
			"id": "custom", "type": "custom_jwt", "allowedAlgorithms": []any{"RS256"},
			"symmetricSecretRef": "secret/present", "acknowledgeSymmetricRisk": true,
		},
	})
	if !hasIssue(semanticIssues, "symmetric_identity_source_invalid") {
		t.Fatalf("semantic defense did not reject asymmetric use of a symmetric source: %+v", semanticIssues)
	}
}

func TestValidatorEnforcesIdentityProviderKeySourceMatrix(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		provider map[string]any
		valid    bool
	}{
		{name: "Firebase derived certificates", valid: true, provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production"}},
		{name: "Firebase explicit fixed algorithm", valid: true, provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "allowedAlgorithms": []any{"RS256"}}},
		{name: "Supabase derived JWKS", valid: true, provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co"}},
		{name: "Supabase asymmetric algorithms", valid: true, provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co", "allowedAlgorithms": []any{"ES256", "RS256"}}},
		{name: "Clerk derived JWKS", valid: true, provider: map[string]any{"id": "c", "type": "clerk", "issuer": "https://clerk.example.test", "audiences": []any{"client"}}},
		{name: "Clerk explicit JWKS", valid: true, provider: map[string]any{"id": "c", "type": "clerk", "issuer": "https://clerk.example.test", "audiences": []any{"client"}, "jwksUrl": "https://clerk.example.test/keys"}},
		{name: "Clerk static public key", valid: true, provider: map[string]any{"id": "c", "type": "clerk", "issuer": "https://clerk.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}, "staticPublicKeySecretRef": "secret/present"}},
		{name: "generic OIDC JWKS", valid: true, provider: map[string]any{"id": "o", "type": "generic_oidc", "issuer": "https://oidc.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256", "ES256"}, "jwksUrl": "https://oidc.example.test/keys"}},
		{name: "generic OIDC static public key", valid: true, provider: map[string]any{"id": "o", "type": "generic_oidc", "issuer": "https://oidc.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS512"}, "staticPublicKeySecretRef": "secret/present"}},
		{name: "custom JWT JWKS", valid: true, provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"ES384"}, "jwksUrl": "https://jwt.example.test/keys"}},
		{name: "custom JWT static public key", valid: true, provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}, "staticPublicKeySecretRef": "secret/present"}},
		{name: "custom JWT symmetric key", valid: true, provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"HS256"}, "symmetricSecretRef": "secret/present", "acknowledgeSymmetricRisk": true}},
		{name: "Firebase JWKS override", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "jwksUrl": "https://keys.example.test/jwks"}},
		{name: "Firebase static override", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "staticPublicKeySecretRef": "secret/present"}},
		{name: "Firebase algorithm override", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "allowedAlgorithms": []any{"ES256"}}},
		{name: "Supabase JWKS override", provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co", "jwksUrl": "https://keys.example.test/jwks"}},
		{name: "Supabase static override", provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co", "staticPublicKeySecretRef": "secret/present"}},
		{name: "Supabase unsupported algorithm", provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co", "allowedAlgorithms": []any{"RS384"}}},
		{name: "Clerk symmetric source", provider: map[string]any{"id": "c", "type": "clerk", "issuer": "https://clerk.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"HS256"}, "symmetricSecretRef": "secret/present", "acknowledgeSymmetricRisk": true}},
		{name: "Clerk ambiguous public sources", provider: map[string]any{"id": "c", "type": "clerk", "issuer": "https://clerk.example.test", "audiences": []any{"client"}, "jwksUrl": "https://clerk.example.test/keys", "staticPublicKeySecretRef": "secret/present"}},
		{name: "Clerk unsupported algorithm", provider: map[string]any{"id": "c", "type": "clerk", "issuer": "https://clerk.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"ES256"}}},
		{name: "generic OIDC missing key source", provider: map[string]any{"id": "o", "type": "generic_oidc", "issuer": "https://oidc.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}}},
		{name: "generic OIDC symmetric source", provider: map[string]any{"id": "o", "type": "generic_oidc", "issuer": "https://oidc.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"HS256"}, "symmetricSecretRef": "secret/present", "acknowledgeSymmetricRisk": true}},
		{name: "generic OIDC ambiguous public sources", provider: map[string]any{"id": "o", "type": "generic_oidc", "issuer": "https://oidc.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}, "jwksUrl": "https://oidc.example.test/keys", "staticPublicKeySecretRef": "secret/present"}},
		{name: "custom JWT missing key source", provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}}},
		{name: "custom JWT ambiguous public sources", provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}, "jwksUrl": "https://jwt.example.test/keys", "staticPublicKeySecretRef": "secret/present"}},
		{name: "custom JWT HS256 JWKS", provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"HS256"}, "jwksUrl": "https://jwt.example.test/keys", "acknowledgeSymmetricRisk": true}},
		{name: "custom JWT asymmetric symmetric-source mismatch", provider: map[string]any{"id": "j", "type": "custom_jwt", "issuer": "https://jwt.example.test", "audiences": []any{"client"}, "allowedAlgorithms": []any{"RS256"}, "symmetricSecretRef": "secret/present", "acknowledgeSymmetricRisk": true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			document := configurationObject(t)
			objectValue(document, "spec")["identityProviders"] = []any{deepClone(test.provider)}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid != test.valid || (len(compiled) != 0) != test.valid {
				t.Fatalf("valid = %t, compiled = %t, issues = %+v", report.Valid, len(compiled) != 0, report.Issues)
			}
		})
	}
}

func TestIdentitySemanticMatrixDefendsCompiledProviders(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		provider map[string]any
		code     string
	}{
		{name: "preset source", provider: map[string]any{"id": "f", "type": "firebase", "jwksUrl": "https://keys.example.test/jwks"}, code: "preset_identity_key_source_invalid"},
		{name: "preset algorithm", provider: map[string]any{"id": "s", "type": "supabase", "allowedAlgorithms": []any{"RS384"}}, code: "preset_identity_algorithm_invalid"},
		{name: "ambiguous source", provider: map[string]any{"id": "c", "type": "clerk", "jwksUrl": "https://keys.example.test/jwks", "staticPublicKeySecretRef": "secret/present"}, code: "identity_key_source_ambiguous"},
		{name: "generic source required", provider: map[string]any{"id": "o", "type": "generic_oidc", "allowedAlgorithms": []any{"RS256"}}, code: "identity_key_source_invalid"},
		{name: "asymmetric source algorithm", provider: map[string]any{"id": "j", "type": "custom_jwt", "allowedAlgorithms": []any{"HS256"}, "jwksUrl": "https://keys.example.test/jwks"}, code: "identity_algorithm_source_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := validator.identityIssues(map[string]map[string]any{stringValue(test.provider, "id"): test.provider})
			if !hasIssue(issues, test.code) {
				t.Fatalf("missing %s in %+v", test.code, issues)
			}
		})
	}
}

func TestValidatorAlignsIdentityRuntimeConstraints(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	validGeneric := map[string]any{
		"id": "o", "type": "generic_oidc",
		"issuer": "https://identity.example.test/tenant/", "audiences": []any{"client"},
		"allowedAlgorithms": []any{"RS256"}, "jwksUrl": "https://identity.example.test/tenant/keys",
		"subjectClaim": "profile.identity.subject", "requiredClaims": []any{"profile.roles.primary"},
	}
	tests := []struct {
		name     string
		provider map[string]any
		valid    bool
		code     string
	}{
		{name: "canonical segmented generic provider", provider: validGeneric, valid: true},
		{name: "issuer query", provider: withProviderField(validGeneric, "issuer", "https://identity.example.test/tenant?key=value"), code: "identity_issuer_url_invalid"},
		{name: "issuer credentials", provider: withProviderField(validGeneric, "issuer", "https://user@identity.example.test/tenant"), code: "identity_issuer_url_invalid"},
		{name: "JWKS query", provider: withProviderField(validGeneric, "jwksUrl", "https://identity.example.test/keys?version=1"), code: "identity_jwks_url_invalid"},
		{name: "JWKS fragment", provider: withProviderField(validGeneric, "jwksUrl", "https://identity.example.test/keys#current"), code: "identity_jwks_url_invalid"},
		{name: "empty subject path segment", provider: withProviderField(validGeneric, "subjectClaim", "profile..subject")},
		{name: "numeric subject path segment", provider: withProviderField(validGeneric, "subjectClaim", "profile.1subject")},
		{name: "invalid required claim segment", provider: withProviderField(validGeneric, "requiredClaims", []any{"profile.-role"})},
		{name: "valid Firebase project ID", valid: true, provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production"}},
		{name: "valid explicit Firebase controls", valid: true, provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "issuer": "https://securetoken.google.com/habits-production", "audiences": []any{"habits-production"}}},
		{name: "short Firebase project ID", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "short"}},
		{name: "uppercase Firebase project ID", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "Habits-production"}},
		{name: "trailing-hyphen Firebase project ID", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production-"}},
		{name: "Firebase issuer mismatch", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "issuer": "https://securetoken.google.com/other-project"}, code: "firebase_issuer_override_invalid"},
		{name: "Firebase audience mismatch", provider: map[string]any{"id": "f", "type": "firebase", "projectId": "habits-production", "audiences": []any{"other-project"}}, code: "firebase_audience_override_invalid"},
		{name: "canonical Supabase origin", valid: true, provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co"}},
		{name: "canonical Supabase origin trailing slash", valid: true, provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co/"}},
		{name: "Supabase project path", provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co/auth/v1"}, code: "supabase_project_url_invalid"},
		{name: "Supabase project query", provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://project.supabase.co?tenant=value"}, code: "supabase_project_url_invalid"},
		{name: "Supabase project credentials", provider: map[string]any{"id": "s", "type": "supabase", "projectUrl": "https://user@project.supabase.co"}, code: "supabase_project_url_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			objectValue(document, "spec")["identityProviders"] = []any{deepClone(test.provider)}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid != test.valid || (len(compiled) != 0) != test.valid {
				t.Fatalf("valid = %t, compiled = %t, issues = %+v", report.Valid, len(compiled) != 0, report.Issues)
			}
			if test.code != "" && !hasIssue(report.Issues, test.code) {
				t.Fatalf("missing %s in %+v", test.code, report.Issues)
			}
		})
	}
}

func TestValidatorRequiresUnambiguousPlatformAttestationAndSupportsDebugNode(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	spec := objectValue(document, "spec")
	policies := objectArray(spec, "attestationPolicies")
	platforms := objectValue(policies[0], "platforms")
	platforms["node"] = map[string]any{
		"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
		"secretRef": "secret/present", "dangerousAllowInProduction": true,
	}
	encoded, _ := json.Marshal(document)
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("debug Node attestation was rejected: %+v", report.Issues)
	}

	invalidNode := deepClone(document).(map[string]any)
	invalidNodePolicies := objectArray(objectValue(invalidNode, "spec"), "attestationPolicies")
	objectValue(invalidNodePolicies[0], "platforms")["node"] = map[string]any{
		"provider": "turnstile", "mode": "required", "minimumTrustLevel": "web_risk_verified",
	}
	encoded, _ = json.Marshal(invalidNode)
	report, compiled = validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "attestation_provider_platform_mismatch") {
		t.Fatalf("non-debug Node attestation was accepted: %+v", report.Issues)
	}

	ambiguous := deepClone(document).(map[string]any)
	ambiguousSpec := objectValue(ambiguous, "spec")
	ambiguousPolicies := objectArray(ambiguousSpec, "attestationPolicies")
	ambiguousSpec["attestationPolicies"] = append(ambiguousPolicies, map[string]any{
		"id": "second", "platforms": map[string]any{
			"ios": map[string]any{"provider": "app_attest", "mode": "required"},
		},
	})
	encoded, _ = json.Marshal(ambiguous)
	report, compiled = validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "attestation_required_policy_ambiguous") {
		t.Fatalf("ambiguous required platform policies were accepted: %+v", report.Issues)
	}
}

func withProviderField(provider map[string]any, field string, value any) map[string]any {
	result := deepClone(provider).(map[string]any)
	result[field] = value
	return result
}

func TestActiveSnapshotLookupsAreDeepCopies(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	configuration := configurationObject(t)
	spec := objectValue(configuration, "spec")
	upstreamObject := objectArray(spec, "upstreams")[0]
	upstreamObject["staticHeaders"] = map[string]any{"X-Provider-Tenant": "configured"}
	limitObject := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
	limitObject["scope"] = []any{"user", "feature"}
	featureObject := objectArray(spec, "features")[0]
	featureObject["output"] = map[string]any{"defaultMaximumTokens": json.Number("800"), "absoluteMaximumTokens": json.Number("1500")}
	routeObject := objectArray(featureObject, "routes")[0]
	routeObject["fallbackOn"] = []any{"status_503"}
	document, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("configuration rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", document, compiled)
	if err != nil {
		t.Fatal(err)
	}
	session := snapshot.SessionPolicy()
	if session.ChallengeTTL != 5*time.Minute || session.AccessTokenTTL != 10*time.Minute || session.RefreshTokenTTL != 30*24*time.Hour || session.MaximumClockSkew != time.Minute {
		t.Fatalf("session policy = %+v", session)
	}
	provider, ok := snapshot.IdentityProvider("firebase")
	if !ok {
		t.Fatal("identity provider missing")
	}
	provider.ClaimMappings["plan"] = "changed"
	provider.RequiredClaims = append(provider.RequiredClaims, "changed")
	providerAgain, _ := snapshot.IdentityProvider("firebase")
	if providerAgain.ClaimMappings["plan"] != "claims.subscription_tier" || len(providerAgain.RequiredClaims) != 0 {
		t.Fatalf("identity provider was mutable: %+v", providerAgain)
	}
	policy, ok := snapshot.AttestationPolicy("native")
	if !ok {
		t.Fatal("attestation policy missing")
	}
	selection := policy.Platforms["ios"]
	selection.Provider = "debug"
	policy.Platforms["ios"] = selection
	selected, ok := snapshot.SelectAttestation("native", "ios")
	if !ok || selected.Provider != "app_attest" {
		t.Fatalf("attestation selection was mutable: %+v", selected)
	}
	requiredPolicy, requiredSelection, ok := snapshot.RequiredAttestationForPlatform("ios")
	if !ok || requiredPolicy.ID != "native" || requiredSelection.Provider != "app_attest" || requiredSelection.Mode != "required" {
		t.Fatalf("required platform attestation selection = policy=%+v selection=%+v ok=%t", requiredPolicy, requiredSelection, ok)
	}
	requiredSelection.ApplicationIdentifiers = append(requiredSelection.ApplicationIdentifiers, "changed")
	requiredPolicy.Platforms["ios"] = requiredSelection
	requiredAgain, selectionAgain, ok := snapshot.RequiredAttestationForPlatform("ios")
	if !ok || requiredAgain.ID != "native" || selectionAgain.Provider != "app_attest" || len(selectionAgain.ApplicationIdentifiers) != 0 {
		t.Fatalf("required platform selection was mutable: policy=%+v selection=%+v", requiredAgain, selectionAgain)
	}
	if _, _, ok := snapshot.RequiredAttestationForPlatform("node"); ok {
		t.Fatal("platform without one required attestation policy was accepted")
	}
	ambiguous := snapshot
	ambiguous.attestations = map[string]AttestationPolicy{
		"native": snapshot.attestations["native"].clone(),
		"second": {
			ID: "second", MaxAge: time.Hour,
			Platforms: map[string]PlatformAttestation{
				"ios": {Provider: "app_attest", Mode: "required", MinimumTrustLevel: "app_verified"},
			},
		},
	}
	if _, _, ok := ambiguous.RequiredAttestationForPlatform("ios"); ok {
		t.Fatal("multiple required attestation policies were treated as unambiguous")
	}
	upstream, ok := snapshot.Upstream("primary")
	if !ok || upstream.BaseURL != "https://api.example.test/v1" || upstream.Timeouts.Total != 2*time.Minute || len(upstream.DestinationPolicy.AllowedPorts) != 1 || upstream.DestinationPolicy.AllowedPorts[0] != 443 || upstream.StaticHeaders["X-Provider-Tenant"] != "configured" {
		t.Fatalf("upstream snapshot = %+v ok=%t", upstream, ok)
	}
	upstream.DestinationPolicy.AllowedPorts[0] = 80
	upstream.StaticHeaders["X-Provider-Tenant"] = "changed"
	upstreamAgain, _ := snapshot.Upstream("primary")
	if upstreamAgain.DestinationPolicy.AllowedPorts[0] != 443 || upstreamAgain.StaticHeaders["X-Provider-Tenant"] != "configured" {
		t.Fatalf("upstream snapshot was mutable: %+v", upstreamAgain)
	}
	model, ok := snapshot.Model("fast")
	if !ok || model.UpstreamID != "primary" || model.UpstreamModel != "configured-fast-model" || !slices.Contains(model.Capabilities, "openai_chat") {
		t.Fatalf("model snapshot = %+v ok=%t", model, ok)
	}
	model.Capabilities[0] = "changed"
	modelAgain, _ := snapshot.Model("fast")
	if slices.Contains(modelAgain.Capabilities, "changed") {
		t.Fatalf("model snapshot was mutable: %+v", modelAgain)
	}
	plan, ok := snapshot.LimitPlan("free")
	if !ok || len(plan.Limits) != 1 || plan.Limits[0].Metric != "logical_requests" || plan.Limits[0].Algorithm != "calendar" || plan.Limits[0].Maximum != 5 || !slices.Equal(plan.Limits[0].Scope, []string{"user", "feature"}) {
		t.Fatalf("limit plan snapshot = %+v ok=%t", plan, ok)
	}
	plan.Limits[0].Scope[0] = "changed"
	planAgain, _ := snapshot.LimitPlan("free")
	if planAgain.Limits[0].Scope[0] != "user" {
		t.Fatalf("limit plan snapshot was mutable: %+v", planAgain)
	}
	feature, ok := snapshot.Feature("assistant")
	if !ok || feature.Protocol != "openai_responses" || feature.Output == nil || feature.Output.DefaultMaximumTokens != 800 || feature.Output.AbsoluteMaximumTokens != 1500 || len(feature.Routes) != 1 || !slices.Equal(feature.Routes[0].FallbackOn, []string{"status_503"}) {
		t.Fatalf("feature snapshot = %+v ok=%t", feature, ok)
	}
	feature.Output.DefaultMaximumTokens = 1
	feature.Routes[0].FallbackOn[0] = "changed"
	featureAgain, _ := snapshot.Feature("assistant")
	if featureAgain.Output.DefaultMaximumTokens != 800 || featureAgain.Routes[0].FallbackOn[0] != "status_503" {
		t.Fatalf("feature snapshot was mutable: %+v", featureAgain)
	}
	compiledCopy := snapshot.CompiledJSON()
	compiledCopy[0] = '['
	if bytes.Equal(compiledCopy, snapshot.CompiledJSON()) {
		t.Fatal("compiled JSON was not defensively copied")
	}
}

func TestStructuralDiffNeverIncludesValues(t *testing.T) {
	t.Parallel()

	from := configurationObject(t)
	to := configurationObject(t)
	fromUpstream := objectArray(objectValue(from, "spec"), "upstreams")[0]
	toUpstream := objectArray(objectValue(to, "spec"), "upstreams")[0]
	fromUpstream["authentication"] = map[string]any{"type": "bearer", "secretRef": "secret/old-credential"}
	toUpstream["authentication"] = map[string]any{"type": "bearer", "secretRef": "secret/new-credential"}
	fromUpstream["staticHeaders"] = map[string]any{"X-Private-Tenant": "old-value"}
	toUpstream["staticHeaders"] = map[string]any{"X-Private-Tenant": "new-value"}
	fromJSON, _ := json.Marshal(from)
	toJSON, _ := json.Marshal(to)
	changes, err := structuralDiff(fromJSON, toJSON)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(changes)
	text := string(encoded)
	for _, forbidden := range []string{"old-credential", "new-credential", "old-value", "new-value", "X-Private-Tenant"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("diff leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, "values are redacted") || !strings.Contains(text, "[redacted]") {
		t.Fatalf("diff lacks structural redaction markers: %s", text)
	}
}

func validConfigurationDocument(t *testing.T) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(configurationObject(t))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func configurationObject(t *testing.T) map[string]any {
	t.Helper()
	value, err := jsonsafe.Decode([]byte(`{
		"apiVersion":"latchway.dev/v1alpha1",
		"kind":"EnvironmentConfig",
		"metadata":{"organization":"example","application":"habits","environment":"production"},
		"spec":{
			"identityProviders":[{"id":"firebase","type":"firebase","projectId":"habits-production","claimMappings":{"plan":"claims.subscription_tier"}}],
			"attestationPolicies":[{"id":"native","platforms":{"ios":{"provider":"app_attest","mode":"required"},"android":{"provider":"play_integrity","mode":"required"}}}],
			"upstreams":[{"id":"primary","type":"openai_compatible","baseUrl":"https://api.example.test/v1","authentication":{"type":"none"}}],
			"models":[{"id":"fast","upstream":"primary","upstreamModel":"configured-fast-model"}],
			"limitPlans":[{"id":"free","limits":[{"metric":"logical_requests","window":"1d","maximum":5}]}],
			"features":[{"id":"assistant","protocol":"openai_responses","attestationPolicy":"native","access":{"expression":"principal.authenticated"},"limitPlan":{"expression":"'free'"},"output":{"defaultMaximumTokens":800,"absoluteMaximumTokens":1500},"routes":[{"id":"primary","when":"true","model":"fast","priority":10}]}]
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

func testEnvironment() EnvironmentDescriptor {
	return EnvironmentDescriptor{
		TenantScope: TenantScope{
			OrganizationID: "org_00000000000000000000000000",
			ApplicationID:  "app_00000000000000000000000000",
			EnvironmentID:  "env_00000000000000000000000000",
		},
		OrganizationSlug: "example", ApplicationSlug: "habits",
		EnvironmentSlug: "production", EnvironmentKind: "production",
		SecretNames: map[string]struct{}{"present": {}},
	}
}

func hasIssue(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
