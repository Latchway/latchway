package configuration

import (
	"bytes"
	"encoding/json"
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
	if stringValue(session, "challengeTtl") != "5m" || stringValue(session, "accessTokenTtl") != "15m" || stringValue(session, "refreshTokenTtl") != "30d" {
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

func TestActiveSnapshotLookupsAreDeepCopies(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := validConfigurationDocument(t)
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("configuration rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", document, compiled)
	if err != nil {
		t.Fatal(err)
	}
	session := snapshot.SessionPolicy()
	if session.ChallengeTTL != 5*time.Minute || session.AccessTokenTTL != 15*time.Minute || session.RefreshTokenTTL != 30*24*time.Hour || session.MaximumClockSkew != time.Minute {
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
			"features":[{"id":"assistant","protocol":"openai_responses","attestationPolicy":"native","access":{"expression":"principal.authenticated"},"limitPlan":{"expression":"'free'"},"routes":[{"id":"primary","when":"true","model":"fast","priority":10}]}]
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
