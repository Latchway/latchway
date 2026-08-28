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
	if profiles := objectArray(spec, "inputAccountingProfiles"); len(profiles) != 0 {
		t.Fatalf("compiled input-accounting default = %#v", profiles)
	}
	session := objectValue(spec, "session")
	if stringValue(session, "challengeTtl") != "5m" || stringValue(session, "accessTokenTtl") != "10m" || stringValue(session, "refreshTokenTtl") != "30d" {
		t.Fatalf("compiled session defaults = %#v", session)
	}
	model := objectArray(spec, "models")[0]
	if got := stringArray(model, "capabilities"); len(got) != 3 || got[0] != "openai_responses" {
		t.Fatalf("inferred model capabilities = %v", got)
	}
	limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
	if stringValue(limit, "algorithm") != "calendar" || limit["hard"] != true ||
		!slices.Equal(stringArray(limit, "scope"), []string{"user", "feature"}) {
		t.Fatalf("normalized executable limit = %#v", limit)
	}
}

func TestValidatorActivatesEveryExecutableProtocol(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, protocolID := range []string{
		"openai_responses", "openai_embeddings", "anthropic_messages", "opaque_http",
	} {
		t.Run(protocolID, func(t *testing.T) {
			document := configurationObject(t)
			spec := objectValue(document, "spec")
			feature := objectArray(spec, "features")[0]
			feature["protocol"] = protocolID
			objectArray(spec, "models")[0]["capabilities"] = []any{protocolID}
			if protocolID == "openai_embeddings" {
				delete(feature, "output")
			}
			if protocolID == "anthropic_messages" {
				objectArray(spec, "upstreams")[0]["type"] = "anthropic"
			}
			if protocolID == "opaque_http" {
				delete(feature, "output")
				feature["opaqueHttp"] = map[string]any{
					"allowedMethods": []any{"POST"}, "pathPrefixes": []any{"/safe"},
					"maxBodyBytes": json.Number("1024"),
				}
				objectArray(feature, "routes")[0]["maxResponseBytes"] = json.Number("4096")
				objectArray(spec, "upstreams")[0]["type"] = "generic"
			}
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
				t.Fatalf("protocol configuration is not schema-valid: %+v", issues)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if !report.Valid || len(compiled) == 0 {
				t.Fatalf("executable protocol did not activate: report=%+v compiled=%s", report, compiled)
			}

			// Independently exercise the persisted compiled-snapshot boundary.
			normalized := deepClone(document).(map[string]any)
			applyDefaults(normalized)
			compiled, marshalErr = json.Marshal(normalized)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, snapshotErr := newActiveSnapshot(
				"validation", "validation", encoded, compiled,
			)
			if snapshotErr != nil {
				t.Fatalf("executable protocol failed runtime snapshot load: %v", snapshotErr)
			}
		})
	}
}

func TestValidatorEnforcesClosedOpaqueHTTPRouteAndForwardingPolicy(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		code   string
	}{
		{
			name: "missing response bound",
			mutate: func(_ map[string]any, route map[string]any) {
				delete(route, "maxResponseBytes")
			},
			code: "opaque_http_response_limit_missing",
		},
		{
			name: "noncanonical provider prefix",
			mutate: func(feature map[string]any, _ map[string]any) {
				objectValue(feature, "opaqueHttp")["pathPrefixes"] = []any{"/v2/../private"}
			},
			code: "opaque_http_path_prefix_invalid",
		},
		{
			name: "provider credential forwarding",
			mutate: func(feature map[string]any, _ map[string]any) {
				objectValue(feature, "opaqueHttp")["allowedRequestHeaders"] = []any{"X-Api-Key"}
			},
			code: "opaque_http_request_header_forbidden",
		},
		{
			name: "case-insensitive duplicate forwarding header",
			mutate: func(feature map[string]any, _ map[string]any) {
				objectValue(feature, "opaqueHttp")["allowedRequestHeaders"] = []any{"X-Trace", "x-trace"}
			},
			code: "opaque_http_request_header_duplicate",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			spec := objectValue(document, "spec")
			feature := objectArray(spec, "features")[0]
			feature["protocol"] = "opaque_http"
			delete(feature, "output")
			feature["opaqueHttp"] = map[string]any{
				"allowedMethods": []any{"GET", "POST"},
				"pathPrefixes":   []any{"/v2"}, "maxBodyBytes": json.Number("1024"),
				"allowedRequestHeaders": []any{"Content-Type", "X-Trace"},
			}
			route := objectArray(feature, "routes")[0]
			route["maxResponseBytes"] = json.Number("4096")
			objectArray(spec, "models")[0]["capabilities"] = []any{"opaque_http"}
			objectArray(spec, "upstreams")[0]["type"] = "generic"
			test.mutate(feature, route)
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("unsafe opaque policy compiled: report=%+v compiled=%s", report, compiled)
			}
		})
	}

	document := configurationObject(t)
	spec := objectValue(document, "spec")
	route := objectArray(objectArray(spec, "features")[0], "routes")[0]
	route["maxResponseBytes"] = json.Number("4096")
	encoded, _ := json.Marshal(document)
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "opaque_http_route_policy_unexpected") {
		t.Fatalf("structured route accepted opaque policy: report=%+v compiled=%s", report, compiled)
	}
}

func TestValidatorBindsStructuredProtocolsToUpstreamFamiliesAndOutputPolicies(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		protocolID string
		upstream   string
		code       string
	}{
		{
			name: "Anthropic over OpenAI upstream", protocolID: "anthropic_messages",
			upstream: "openai_compatible", code: "model_upstream_protocol_mismatch",
		},
		{
			name: "OpenAI over Anthropic upstream", protocolID: "openai_responses",
			upstream: "anthropic", code: "model_upstream_protocol_mismatch",
		},
		{
			name: "Embeddings with output policy", protocolID: "openai_embeddings",
			upstream: "openai_compatible", code: "output_policy_unexpected",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			spec := objectValue(document, "spec")
			feature := objectArray(spec, "features")[0]
			feature["protocol"] = test.protocolID
			objectArray(spec, "models")[0]["capabilities"] = []any{test.protocolID}
			objectArray(spec, "upstreams")[0]["type"] = test.upstream
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
				t.Fatalf("unsafe combination was not schema-valid: %+v", issues)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("unsafe combination activated: report=%+v compiled=%s", report, compiled)
			}
		})
	}
}

func TestValidatorRejectsPathologicalNumberLexemesBeforeSchemaArithmetic(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  string
	}{
		{name: "positive exponent bomb", raw: "1e1000001"},
		{name: "negative exponent bomb", raw: "1e-1000001"},
		{name: "oversized mantissa", raw: strings.Repeat("9", maximumSchemaNumberBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
			plan["limits"] = []any{
				map[string]any{
					"metric": "logical_requests", "scope": []any{"user"},
					"capacity": json.Number("10"), "refillPerSecond": json.Number(test.raw),
				},
			}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}

			issues := validator.SchemaIssues(encoded)
			if len(issues) != 1 || issues[0].Code != "schema_number_unsafe" ||
				issues[0].Path != "/spec/limitPlans/0/limits/0/refillPerSecond" ||
				strings.Contains(issues[0].Message, test.raw) {
				t.Fatalf("SchemaIssues(%s) = %+v", test.name, issues)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || len(report.Issues) != 1 ||
				report.Issues[0].Code != "schema_number_unsafe" {
				t.Fatalf("Validate(%s) = report %+v, compiled %q", test.name, report, compiled)
			}
		})
	}
}

func TestValidatorRequiresExplicitLimitScopeAtActivation(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		limit map[string]any
	}{
		{
			name: "logical request calendar",
			limit: map[string]any{
				"metric": "logical_requests", "window": "1d", "maximum": json.Number("5"),
			},
		},
		{
			name: "output token per request",
			limit: map[string]any{
				"metric": "output_tokens", "perRequestMaximum": json.Number("100"),
			},
		},
		{
			name: "concurrent stream",
			limit: map[string]any{
				"metric": "concurrent_streams", "maximum": json.Number("5"),
			},
		},
		{
			name: "logical request token bucket",
			limit: map[string]any{
				"metric": "logical_requests", "capacity": json.Number("10"),
				"refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "output token bucket",
			limit: map[string]any{
				"metric": "output_tokens", "capacity": json.Number("10"),
				"refillPerSecond": json.Number("1"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			objectArray(objectValue(document, "spec"), "limitPlans")[0]["limits"] = []any{test.limit}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			issues := validator.SchemaIssues(encoded)
			if len(issues) != 0 {
				t.Fatalf("missing scope must remain draft-schema-valid: %+v", issues)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, "limit_capability_unsupported") {
				t.Fatalf("missing scope activated: report=%+v compiled=%q", report, compiled)
			}
		})
	}
}

func TestValidatorCapabilityGatesSchemaValidLimitAlgorithmsAndMetrics(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		limit map[string]any
	}{
		{
			name: "input token bucket",
			limit: map[string]any{
				"metric": "input_tokens", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "total token bucket",
			limit: map[string]any{
				"metric": "total_tokens", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "cost token bucket",
			limit: map[string]any{
				"metric": "cost_nano_usd", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "soft logical request token bucket",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("1"), "hard": false,
			},
		},
		{
			name: "logical request token bucket excessive capacity",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("9223373"), "refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "logical request token bucket sub-micro refill",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("0.0000001"),
			},
		},
		{
			name: "logical request token bucket excessive refill",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("1000000.000001"),
			},
		},
		{
			name: "output token bucket excessive capacity",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("9223373"), "refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "output token bucket excessive refill",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("1000000.000001"),
			},
		},
		{
			name: "logical request token bucket overflowing scaled refill",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"user"},
				"capacity": json.Number("10"), "refillPerSecond": json.Number("9223372036854.775808"),
			},
		},
		{
			name: "concurrency on logical requests",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "concurrency", "scope": []any{"application"},
				"maximum": json.Number("5"),
			},
		},
		{
			name: "logical requests per request",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "per_request", "scope": []any{"user"},
				"perRequestMaximum": json.Number("100"),
			},
		},
		{
			name: "soft request limit",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "calendar", "scope": []any{"user"},
				"window": "1d", "maximum": json.Number("100"), "hard": false,
			},
		},
		{
			name: "overflowing calendar amount",
			limit: map[string]any{
				"metric": "logical_requests", "algorithm": "calendar", "scope": []any{"user"},
				"window": "9223372036854775808d", "maximum": json.Number("100"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
			plan["limits"] = []any{test.limit}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
				t.Fatalf("future contract shape is not schema-valid: %+v", issues)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, "limit_capability_unsupported") {
				t.Fatalf("unsupported limit activated: report=%+v compiled=%q", report, compiled)
			}
			for _, issue := range report.Issues {
				if issue.Code == "limit_capability_unsupported" &&
					(!strings.Contains(issue.Message, "logical_requests token_bucket") ||
						!strings.Contains(issue.Message, "output_tokens token_bucket") ||
						!strings.Contains(issue.Message, "capacity from 1 through 9223372") ||
						!strings.Contains(issue.Message, "through 1000000") ||
						!strings.Contains(issue.Message, "output_tokens calendar") ||
						!strings.Contains(issue.Message, "input_tokens calendar") ||
						!strings.Contains(issue.Message, "total_tokens calendar") ||
						!strings.Contains(issue.Message, "output_tokens per_request") ||
						!strings.Contains(issue.Message, "cost_nano_usd calendar") ||
						!strings.Contains(issue.Message, "concurrent_requests/concurrent_streams concurrency")) {
					t.Fatalf("stale capability wording: %q", issue.Message)
				}
			}
		})
	}
}

func TestValidatorActivatesBoundedHardCostCalendarWithZeroInputPricing(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	spec := objectValue(document, "spec")
	objectArray(spec, "models")[0]["pricingRef"] = "standard"
	spec["pricingCatalogs"] = []any{map[string]any{
		"id": "standard", "currency": "USD",
		"entries": []any{map[string]any{
			"model": "fast", "inputNanoUsdPerMillion": json.Number("0"),
			"outputNanoUsdPerMillion": json.Number("2500000"),
			"requestNanoUsd":          json.Number("100"),
		}},
	}}
	objectArray(spec, "limitPlans")[0]["limits"] = []any{map[string]any{
		"metric": "cost_nano_usd", "algorithm": "calendar",
		"scope": []any{"feature", "user"}, "window": "1d",
		"maximum": json.Number("1000000000"), "hard": true,
	}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("bounded hard cost configuration rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled,
	)
	if err != nil {
		t.Fatalf("load bounded hard cost snapshot: %v", err)
	}
	plan, ok := snapshot.LimitPlan("free")
	if !ok || len(plan.Limits) != 1 || plan.Limits[0].Metric != "cost_nano_usd" ||
		plan.Limits[0].Algorithm != "calendar" || plan.Limits[0].Maximum != 1_000_000_000 {
		t.Fatalf("active hard cost plan = %+v ok=%t", plan, ok)
	}
}

func TestValidatorIncludesOverrideReachablePlansInHardCostPricingGate(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	spec := objectValue(document, "spec")
	models := objectArray(spec, "models")
	costModel := models[0]
	costModel["pricingRef"] = "standard"
	nonCostModel := deepClone(costModel).(map[string]any)
	nonCostModel["id"] = "legacy"
	nonCostModel["upstreamModel"] = "configured-legacy-model"
	spec["models"] = append(models, nonCostModel)
	spec["pricingCatalogs"] = []any{map[string]any{
		"id": "standard", "currency": "USD",
		"entries": []any{
			map[string]any{
				"model": "fast", "inputNanoUsdPerMillion": json.Number("0"),
				"outputNanoUsdPerMillion": json.Number("1"), "requestNanoUsd": json.Number("0"),
			},
			map[string]any{
				"model": "legacy", "inputNanoUsdPerMillion": json.Number("1000"),
				"outputNanoUsdPerMillion": json.Number("2000"), "requestNanoUsd": json.Number("0"),
			},
		},
	}}
	plans := objectArray(spec, "limitPlans")
	plans[0]["limits"] = []any{map[string]any{
		"metric": "cost_nano_usd", "algorithm": "calendar", "scope": []any{"user"},
		"window": "1d", "maximum": json.Number("1000"), "hard": true,
	}}
	nonCostPlan := map[string]any{
		"id": "requests",
		"limits": []any{map[string]any{
			"metric": "logical_requests", "algorithm": "calendar", "scope": []any{"user"},
			"window": "1d", "maximum": json.Number("10"), "hard": true,
		}},
	}
	spec["limitPlans"] = append(plans, nonCostPlan)
	features := objectArray(spec, "features")
	nonCostFeature := deepClone(features[0]).(map[string]any)
	nonCostFeature["id"] = "legacy_assistant"
	objectValue(nonCostFeature, "limitPlan")["expression"] = "'requests'"
	route := objectArray(nonCostFeature, "routes")[0]
	route["id"] = "legacy"
	route["model"] = "legacy"
	spec["features"] = append(features, nonCostFeature)

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil ||
		!hasIssue(report.Issues, "input_accounting_required_for_cost_limit") {
		t.Fatalf("override-reachable cost plan bypassed conservative pricing: %+v", report.Issues)
	}

	objectArray(objectArray(spec, "pricingCatalogs")[0], "entries")[1]["inputNanoUsdPerMillion"] = json.Number("0")
	safe, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	safeReport, safeCompiled := validator.Validate(safe, testEnvironment(), time.Now())
	if !safeReport.Valid || len(safeCompiled) == 0 {
		t.Fatalf("override-safe configured pricing was rejected: %+v", safeReport.Issues)
	}
}

func TestValidatorRejectsHardCostWithoutConservativeConfiguredInputPrice(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		pricingRef string
		inputRate  json.Number
		code       string
	}{
		{name: "missing pricing", code: "pricing_required_for_cost_limit"},
		{name: "input priced", pricingRef: "standard", inputRate: json.Number("1"), code: "input_accounting_required_for_cost_limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			spec := objectValue(document, "spec")
			objectArray(spec, "limitPlans")[0]["limits"] = []any{map[string]any{
				"metric": "cost_nano_usd", "algorithm": "calendar", "scope": []any{"user"},
				"window": "1d", "maximum": json.Number("100"), "hard": true,
			}}
			if test.pricingRef != "" {
				objectArray(spec, "models")[0]["pricingRef"] = test.pricingRef
				spec["pricingCatalogs"] = []any{map[string]any{
					"id": test.pricingRef, "currency": "USD",
					"entries": []any{map[string]any{
						"model": "fast", "inputNanoUsdPerMillion": test.inputRate,
						"outputNanoUsdPerMillion": json.Number("0"), "requestNanoUsd": json.Number("0"),
					}},
				}}
			}
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("unsafe hard cost configuration activated: report=%+v compiled=%q", report, compiled)
			}
		})
	}
}

func TestValidatorActivatesCanonicalLogicalRequestTokenBucket(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
	plan["limits"] = []any{
		map[string]any{
			"metric": "logical_requests", "scope": []any{"feature", "user"},
			"capacity": json.Number("9223372.0"), "refillPerSecond": json.Number("1.000000e6"),
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
		t.Fatalf("valid token bucket failed schema validation: %+v", issues)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("valid token bucket rejected: report=%+v compiled=%s", report, compiled)
	}
	value, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	limit := objectArray(objectArray(objectValue(value.(map[string]any), "spec"), "limitPlans")[0], "limits")[0]
	refill, ok := limit["refillPerSecond"].(json.Number)
	if !ok || refill.String() != "1000000" || stringValue(limit, "algorithm") != "token_bucket" ||
		limit["hard"] != true || !slices.Equal(stringArray(limit, "scope"), []string{"user", "feature"}) {
		t.Fatalf("compiled token bucket = %#v", limit)
	}
	snapshot, err := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled)
	if err != nil {
		t.Fatalf("newActiveSnapshot() error = %v", err)
	}
	runtimePlan, ok := snapshot.LimitPlan("free")
	wantRate := RefillRate{Numerator: maximumExecutableTokenBucketRefillPerSecond, Denominator: 1}
	if !ok || len(runtimePlan.Limits) != 1 || runtimePlan.Limits[0].Metric != "logical_requests" ||
		runtimePlan.Limits[0].Algorithm != "token_bucket" || runtimePlan.Limits[0].Capacity != maximumExecutableTokenBucketCapacity ||
		runtimePlan.Limits[0].RefillPerSecond != wantRate || !runtimePlan.Limits[0].Hard {
		t.Fatalf("runtime token bucket = %+v ok=%t", runtimePlan, ok)
	}
	runtimePlan.Limits[0].Scope[0] = "changed"
	runtimeAgain, _ := snapshot.LimitPlan("free")
	if !slices.Equal(runtimeAgain.Limits[0].Scope, []string{"user", "feature"}) || runtimeAgain.Limits[0].RefillPerSecond != wantRate {
		t.Fatalf("runtime token bucket plan was not defensively copied: %+v", runtimeAgain)
	}
}

func TestValidatorActivatesCanonicalOutputTokenBucket(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
	plan["limits"] = []any{
		map[string]any{
			"metric": "output_tokens", "scope": []any{"feature", "user"},
			"capacity": json.Number("9223372.0"), "refillPerSecond": json.Number("1.000000e6"),
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
		t.Fatalf("valid output-token bucket failed schema validation: %+v", issues)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("valid output-token bucket rejected: report=%+v compiled=%s", report, compiled)
	}
	value, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	limit := objectArray(objectArray(objectValue(value.(map[string]any), "spec"), "limitPlans")[0], "limits")[0]
	refill, ok := limit["refillPerSecond"].(json.Number)
	if !ok || refill.String() != "1000000" || stringValue(limit, "algorithm") != "token_bucket" ||
		limit["hard"] != true || !slices.Equal(stringArray(limit, "scope"), []string{"user", "feature"}) {
		t.Fatalf("compiled output-token bucket = %#v", limit)
	}
	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled,
	)
	if err != nil {
		t.Fatalf("newActiveSnapshot() error = %v", err)
	}
	runtimePlan, ok := snapshot.LimitPlan("free")
	wantRate := RefillRate{Numerator: maximumExecutableTokenBucketRefillPerSecond, Denominator: 1}
	if !ok || len(runtimePlan.Limits) != 1 || runtimePlan.Limits[0].Metric != "output_tokens" ||
		runtimePlan.Limits[0].Algorithm != "token_bucket" ||
		runtimePlan.Limits[0].Capacity != maximumExecutableTokenBucketCapacity ||
		runtimePlan.Limits[0].RefillPerSecond != wantRate || !runtimePlan.Limits[0].Hard {
		t.Fatalf("runtime output-token bucket = %+v ok=%t", runtimePlan, ok)
	}
	runtimePlan.Limits[0].Scope[0] = "changed"
	runtimeAgain, _ := snapshot.LimitPlan("free")
	if !slices.Equal(runtimeAgain.Limits[0].Scope, []string{"user", "feature"}) ||
		runtimeAgain.Limits[0].RefillPerSecond != wantRate {
		t.Fatalf("runtime output-token bucket plan was not defensively copied: %+v", runtimeAgain)
	}
}

func TestValidatorActivatesExplicitAndDefaultConcurrencyLimits(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
	plan["limits"] = []any{
		map[string]any{
			"metric": "concurrent_requests", "algorithm": "concurrency",
			"scope": []any{"feature", "organization", "user"}, "maximum": json.Number("9223372036854775807.0"),
		},
		map[string]any{
			"metric": "concurrent_streams", "scope": []any{"model", "user"},
			"maximum": json.Number("4.096e3"),
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
		t.Fatalf("valid concurrency limits failed schema validation: %+v", issues)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("valid concurrency limits rejected: %+v", report.Issues)
	}
	value, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	limits := objectArray(objectArray(objectValue(value.(map[string]any), "spec"), "limitPlans")[0], "limits")
	if len(limits) != 2 ||
		stringValue(limits[0], "algorithm") != "concurrency" ||
		!slices.Equal(stringArray(limits[0], "scope"), []string{"organization", "user", "feature"}) ||
		stringValue(limits[1], "algorithm") != "concurrency" ||
		!slices.Equal(stringArray(limits[1], "scope"), []string{"user", "model"}) {
		t.Fatalf("compiled concurrency limits = %#v", limits)
	}
	snapshot, err := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled)
	if err != nil {
		t.Fatalf("newActiveSnapshot() error = %v", err)
	}
	runtimePlan, ok := snapshot.LimitPlan("free")
	if !ok || len(runtimePlan.Limits) != 2 ||
		runtimePlan.Limits[0].Metric != "concurrent_requests" || runtimePlan.Limits[0].Algorithm != "concurrency" ||
		runtimePlan.Limits[0].Maximum != 9223372036854775807 ||
		runtimePlan.Limits[1].Metric != "concurrent_streams" || runtimePlan.Limits[1].Algorithm != "concurrency" ||
		runtimePlan.Limits[1].Maximum != 4096 {
		t.Fatalf("runtime concurrency plan = %+v ok=%t", runtimePlan, ok)
	}
	runtimePlan.Limits[0].Scope[0] = "changed"
	runtimeAgain, _ := snapshot.LimitPlan("free")
	if !slices.Equal(runtimeAgain.Limits[0].Scope, []string{"organization", "user", "feature"}) {
		t.Fatalf("runtime concurrency plan aliased returned scope: %+v", runtimeAgain)
	}
}

func TestValidatorActivatesMixedBoundedRequestAndOutputTokenLimits(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
	plan["limits"] = []any{
		map[string]any{
			"metric": "output_tokens", "algorithm": "per_request",
			"scope":             []any{"model", "organization", "user"},
			"perRequestMaximum": json.Number("4.096e3"),
		},
		map[string]any{
			"metric": "logical_requests", "scope": []any{"feature", "user"},
			"window": "1d", "maximum": json.Number("5"),
		},
		map[string]any{
			"metric": "output_tokens", "scope": []any{"upstream", "route", "application"},
			"window": "12mo", "maximum": json.Number("100000.0"),
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("supported multi-rule plan rejected: %+v", report.Issues)
	}
	value, err := jsonsafe.Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	limits := objectArray(objectArray(objectValue(value.(map[string]any), "spec"), "limitPlans")[0], "limits")
	if len(limits) != 3 ||
		stringValue(limits[0], "algorithm") != "per_request" ||
		!slices.Equal(stringArray(limits[0], "scope"), []string{"organization", "user", "model"}) ||
		stringValue(limits[1], "algorithm") != "calendar" ||
		!slices.Equal(stringArray(limits[1], "scope"), []string{"user", "feature"}) ||
		stringValue(limits[2], "algorithm") != "calendar" ||
		!slices.Equal(stringArray(limits[2], "scope"), []string{"application", "route", "upstream"}) {
		t.Fatalf("compiled multi-rule limits = %#v", limits)
	}
	snapshot, err := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled)
	if err != nil {
		t.Fatalf("newActiveSnapshot() error = %v", err)
	}
	runtimePlan, ok := snapshot.LimitPlan("free")
	if !ok || len(runtimePlan.Limits) != 3 ||
		runtimePlan.Limits[0].Metric != "output_tokens" || runtimePlan.Limits[0].Algorithm != "per_request" || runtimePlan.Limits[0].PerRequestMaximum != 4096 ||
		runtimePlan.Limits[1].Metric != "logical_requests" || runtimePlan.Limits[1].Maximum != 5 ||
		runtimePlan.Limits[2].Metric != "output_tokens" || runtimePlan.Limits[2].Algorithm != "calendar" || runtimePlan.Limits[2].Window != "12mo" || runtimePlan.Limits[2].Maximum != 100000 {
		t.Fatalf("runtime mixed plan = %+v ok=%t", runtimePlan, ok)
	}
	runtimePlan.Limits[0].Scope[0] = "changed"
	runtimeAgain, _ := snapshot.LimitPlan("free")
	if !slices.Equal(runtimeAgain.Limits[0].Scope, []string{"organization", "user", "model"}) {
		t.Fatalf("runtime mixed plan aliased returned scope: %+v", runtimeAgain)
	}
}

func TestValidatorActivatesOutputTokenPerRequestOnlyPlan(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	plan := objectArray(objectValue(document, "spec"), "limitPlans")[0]
	plan["limits"] = []any{
		map[string]any{
			"metric":            "output_tokens",
			"scope":             []any{"model", "upstream", "route", "feature", "installation", "user", "environment", "application", "organization"},
			"perRequestMaximum": json.Number("9223372036854775807"),
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("per-request-only plan rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", encoded, compiled)
	if err != nil {
		t.Fatal(err)
	}
	runtimePlan, ok := snapshot.LimitPlan("free")
	if !ok || len(runtimePlan.Limits) != 1 || runtimePlan.Limits[0].Algorithm != "per_request" ||
		runtimePlan.Limits[0].PerRequestMaximum != 9223372036854775807 ||
		!slices.Equal(runtimePlan.Limits[0].Scope, executableLimitScopeOrder) {
		t.Fatalf("per-request-only runtime plan = %+v ok=%t", runtimePlan, ok)
	}
}

func TestValidatorRejectsExecutableLimitFieldShapeMismatches(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		limit map[string]any
	}{
		{
			name: "calendar with per request maximum",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "calendar", "scope": []any{"user"},
				"window": "1d", "maximum": json.Number("100"), "perRequestMaximum": json.Number("10"),
			},
		},
		{
			name: "calendar missing maximum",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "calendar", "scope": []any{"user"},
				"window": "1d", "perRequestMaximum": json.Number("10"),
			},
		},
		{
			name: "per request with window",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "per_request", "scope": []any{"user"},
				"window": "1d", "perRequestMaximum": json.Number("10"),
			},
		},
		{
			name: "per request with maximum",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "per_request", "scope": []any{"user"},
				"maximum": json.Number("100"), "perRequestMaximum": json.Number("10"),
			},
		},
		{
			name: "per request with token bucket fields",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "per_request", "scope": []any{"user"},
				"perRequestMaximum": json.Number("10"), "capacity": json.Number("10"), "refillPerSecond": json.Number("1"),
			},
		},
		{
			name: "concurrency with window",
			limit: map[string]any{
				"metric": "concurrent_requests", "algorithm": "concurrency", "scope": []any{"user"},
				"window": "1d", "maximum": json.Number("10"),
			},
		},
		{
			name: "concurrency with per request maximum",
			limit: map[string]any{
				"metric": "concurrent_streams", "algorithm": "concurrency", "scope": []any{"user"},
				"maximum": json.Number("10"), "perRequestMaximum": json.Number("10"),
			},
		},
		{
			name: "concurrency with token bucket fields",
			limit: map[string]any{
				"metric": "concurrent_requests", "algorithm": "concurrency", "scope": []any{"user"},
				"maximum": json.Number("10"), "capacity": json.Number("10"), "refillPerSecond": json.Number("1"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			objectArray(objectValue(document, "spec"), "limitPlans")[0]["limits"] = []any{test.limit}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
				t.Fatalf("field-shape mismatch must remain schema-valid: %+v", issues)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, "limit_algorithm_fields_invalid") || !hasIssue(report.Issues, "limit_capability_unsupported") {
				t.Fatalf("field-shape mismatch activated: report=%+v compiled=%q", report, compiled)
			}
		})
	}
}

func TestValidatorRejectsNonPositiveFractionalAndOutOfRangeLimitIntegers(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		limit map[string]any
	}{
		{
			name: "negative integral decimal",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "calendar", "scope": []any{"user"},
				"window": "1d", "maximum": json.Number("-1.0"),
			},
		},
		{
			name: "fractional per request maximum",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "per_request", "scope": []any{"user"},
				"perRequestMaximum": json.Number("4096.5"),
			},
		},
		{
			name: "out of int64 range exponent",
			limit: map[string]any{
				"metric": "output_tokens", "algorithm": "per_request", "scope": []any{"user"},
				"perRequestMaximum": json.Number("9.223372036854775808e18"),
			},
		},
		{
			name: "fractional concurrency maximum",
			limit: map[string]any{
				"metric": "concurrent_requests", "algorithm": "concurrency", "scope": []any{"user"},
				"maximum": json.Number("1.5"),
			},
		},
		{
			name: "out of range concurrency maximum",
			limit: map[string]any{
				"metric": "concurrent_streams", "algorithm": "concurrency", "scope": []any{"user"},
				"maximum": json.Number("9.223372036854775808e18"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			objectArray(objectValue(document, "spec"), "limitPlans")[0]["limits"] = []any{test.limit}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if issues := validator.SchemaIssues(encoded); len(issues) == 0 {
				t.Fatal("invalid integer value passed the public schema")
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil {
				t.Fatalf("invalid integer value activated: report=%+v compiled=%q", report, compiled)
			}
		})
	}
}

func TestValidatorRejectsDuplicateImmutableLimitIdentityByMetricAndAlgorithm(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		limits []any
	}{
		{
			name: "logical request calendar",
			limits: []any{
				map[string]any{"metric": "logical_requests", "scope": []any{"feature", "user"}, "window": "1d", "maximum": json.Number("5")},
				map[string]any{"metric": "logical_requests", "scope": []any{"user", "feature"}, "window": "1d", "maximum": json.Number("10")},
			},
		},
		{
			name: "logical request token bucket",
			limits: []any{
				map[string]any{
					"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"feature", "user"},
					"capacity": json.Number("10"), "refillPerSecond": json.Number("0.5"),
				},
				map[string]any{
					"metric": "logical_requests", "algorithm": "token_bucket", "scope": []any{"user", "feature"},
					"capacity": json.Number("20"), "refillPerSecond": json.Number("0.25"),
				},
			},
		},
		{
			name: "output token bucket",
			limits: []any{
				map[string]any{
					"metric": "output_tokens", "algorithm": "token_bucket", "scope": []any{"feature", "user"},
					"capacity": json.Number("10"), "refillPerSecond": json.Number("0.5"),
				},
				map[string]any{
					"metric": "output_tokens", "algorithm": "token_bucket", "scope": []any{"user", "feature"},
					"capacity": json.Number("20"), "refillPerSecond": json.Number("0.25"),
				},
			},
		},
		{
			name: "output token calendar",
			limits: []any{
				map[string]any{"metric": "output_tokens", "scope": []any{"model", "user"}, "window": "1d", "maximum": json.Number("100")},
				map[string]any{"metric": "output_tokens", "scope": []any{"user", "model"}, "window": "1d", "maximum": json.Number("200")},
			},
		},
		{
			name: "output token per request",
			limits: []any{
				map[string]any{"metric": "output_tokens", "scope": []any{"model", "user"}, "perRequestMaximum": json.Number("100")},
				map[string]any{"metric": "output_tokens", "scope": []any{"user", "model"}, "perRequestMaximum": json.Number("200")},
			},
		},
		{
			name: "request concurrency",
			limits: []any{
				map[string]any{"metric": "concurrent_requests", "scope": []any{"feature", "user"}, "maximum": json.Number("10")},
				map[string]any{"metric": "concurrent_requests", "algorithm": "concurrency", "scope": []any{"user", "feature"}, "maximum": json.Number("20")},
			},
		},
		{
			name: "stream concurrency",
			limits: []any{
				map[string]any{"metric": "concurrent_streams", "scope": []any{"model", "user"}, "maximum": json.Number("100")},
				map[string]any{"metric": "concurrent_streams", "algorithm": "concurrency", "scope": []any{"user", "model"}, "maximum": json.Number("200")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			duplicate := configurationObject(t)
			objectArray(objectValue(duplicate, "spec"), "limitPlans")[0]["limits"] = test.limits
			duplicateJSON, err := json.Marshal(duplicate)
			if err != nil {
				t.Fatal(err)
			}
			if issues := validator.SchemaIssues(duplicateJSON); len(issues) != 0 {
				t.Fatalf("duplicate immutable identities should remain schema-valid: %+v", issues)
			}
			report, compiled := validator.Validate(duplicateJSON, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, "duplicate_limit_rule") {
				t.Fatalf("duplicate immutable identity activated: report=%+v compiled=%q", report, compiled)
			}
		})
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

func TestSecretReferenceIssuesInspectOnlySchemaDefinedReferenceFields(t *testing.T) {
	t.Parallel()
	root := map[string]any{
		"description": "secret/not-a-reference",
		"spec": map[string]any{
			"identityProviders": []any{map[string]any{
				"staticPublicKeySecretRef": "secret/missing-a",
				"symmetricSecretRef":       "secret/present",
			}},
			"attestationPolicies": []any{map[string]any{
				"platforms": map[string]any{"ios": map[string]any{"secretRef": "secret/missing-b"}},
			}},
			"upstreams": []any{map[string]any{
				"authentication": map[string]any{"secretRef": "secret/missing-c"},
				"staticHeaders":  map[string]any{"secretRef": "secret/not-a-reference"},
			}},
		},
	}
	issues := secretReferenceIssues(root, map[string]struct{}{"present": {}})
	if len(issues) != 3 || !hasIssue(issues, "secret_reference_missing") {
		t.Fatalf("schema-defined secret reference issues = %+v", issues)
	}
	for _, issue := range issues {
		if issue.Path != "/spec/identityProviders/0/staticPublicKeySecretRef" &&
			issue.Path != "/spec/attestationPolicies/0/platforms/ios/secretRef" &&
			issue.Path != "/spec/upstreams/0/authentication/secretRef" {
			t.Fatalf("ordinary text treated as a secret reference: %+v", issues)
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
	delete(selection, "appAttest")
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
		"secretRef": "secret/present",
		"turnstile": map[string]any{
			"allowedHostnames": []any{"app.example.test"}, "expectedAction": "latchway_session",
		},
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
			"ios": map[string]any{
				"provider": "app_attest", "mode": "required",
				"appAttest": map[string]any{
					"appIdPrefix": "TEAM1234", "bundleId": "com.example.habits", "environment": "production",
					"allowedValidationCategories": []any{json.Number("1")}, "allowedBundleVersions": []any{"1.0"},
				},
			},
		},
	})
	encoded, _ = json.Marshal(ambiguous)
	report, compiled = validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "attestation_required_policy_ambiguous") {
		t.Fatalf("ambiguous required platform policies were accepted: %+v", report.Issues)
	}
}

func TestValidatorRejectsUnverifiableEnabledAttestationApplicationConstraints(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		mode  string
		field string
		value []any
		code  string
	}{
		{
			name: "required application identifier", mode: "required",
			field: "applicationIdentifiers", value: []any{"TEAMID.com.example.app"},
			code: "attestation_application_identifiers_unsupported",
		},
		{
			name: "preferred web origin", mode: "preferred",
			field: "allowedOrigins", value: []any{"https://app.example.test"},
			code: "attestation_allowed_origins_forbidden",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			selection := objectValue(
				objectValue(objectArray(objectValue(document, "spec"), "attestationPolicies")[0], "platforms"),
				"ios",
			)
			selection["mode"] = test.mode
			selection[test.field] = test.value
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("unverifiable enabled constraint compiled: %+v", report.Issues)
			}
		})
	}

	// Constraints on a disabled selection are inert and therefore do not add an
	// attestation requirement to the sealed-session baseline.
	disabled := configurationObject(t)
	disabledSelection := objectValue(
		objectValue(objectArray(objectValue(disabled, "spec"), "attestationPolicies")[0], "platforms"),
		"ios",
	)
	disabledSelection["mode"] = "disabled"
	disabledSelection["applicationIdentifiers"] = []any{"TEAMID.com.example.app"}
	disabledJSON, err := json.Marshal(disabled)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(disabledJSON, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("inert disabled constraint was rejected: %+v", report.Issues)
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
	routeObject["fallbackOn"] = []any{"status_408"}
	routeObject["retryPolicy"] = map[string]any{
		"maxAttempts": json.Number("3"), "initialBackoffMilliseconds": json.Number("25"),
		"maximumBackoffMilliseconds": json.Number("100"), "jitterRatio": json.Number("0.25"),
		"retryOn": []any{"connect_error", "status_408"},
	}
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
	if !ok || feature.Protocol != "openai_chat" || feature.Output == nil || feature.Output.DefaultMaximumTokens != 800 || feature.Output.AbsoluteMaximumTokens != 1500 || len(feature.Routes) != 1 || !slices.Equal(feature.Routes[0].FallbackOn, []string{"status_408"}) ||
		feature.Routes[0].RetryPolicy == nil || feature.Routes[0].RetryPolicy.MaxAttempts != 3 ||
		feature.Routes[0].RetryPolicy.InitialBackoff != 25*time.Millisecond ||
		feature.Routes[0].RetryPolicy.MaximumBackoff != 100*time.Millisecond ||
		feature.Routes[0].RetryPolicy.JitterRatio != 0.25 ||
		!slices.Equal(feature.Routes[0].RetryPolicy.RetryOn, []string{"connect_error", "status_408"}) {
		t.Fatalf("feature snapshot = %+v ok=%t", feature, ok)
	}
	feature.Output.DefaultMaximumTokens = 1
	feature.Routes[0].FallbackOn[0] = "changed"
	feature.Routes[0].RetryPolicy.RetryOn[0] = "changed"
	feature.Routes[0].RetryPolicy.MaxAttempts = 8
	featureAgain, _ := snapshot.Feature("assistant")
	if featureAgain.Output.DefaultMaximumTokens != 800 || featureAgain.Routes[0].FallbackOn[0] != "status_408" ||
		featureAgain.Routes[0].RetryPolicy == nil || featureAgain.Routes[0].RetryPolicy.MaxAttempts != 3 ||
		featureAgain.Routes[0].RetryPolicy.RetryOn[0] != "connect_error" {
		t.Fatalf("feature snapshot was mutable: %+v", featureAgain)
	}
	compiledCopy := snapshot.CompiledJSON()
	compiledCopy[0] = '['
	if bytes.Equal(compiledCopy, snapshot.CompiledJSON()) {
		t.Fatal("compiled JSON was not defensively copied")
	}
}

func TestValidatorRejectsIncoherentRouteRetryBackoff(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	document := configurationObject(t)
	route := objectArray(objectArray(objectValue(document, "spec"), "features")[0], "routes")[0]
	route["retryPolicy"] = map[string]any{
		"maxAttempts": json.Number("2"), "initialBackoffMilliseconds": json.Number("100"),
		"maximumBackoffMilliseconds": json.Number("10"), "retryOn": []any{"status_503"},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
	if report.Valid || compiled != nil || !hasIssue(report.Issues, "route_retry_backoff_invalid") {
		t.Fatalf("incoherent retry backoff accepted: report=%+v compiled=%s", report, compiled)
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
			"attestationPolicies":[{"id":"native","platforms":{"ios":{"provider":"app_attest","mode":"required","appAttest":{"appIdPrefix":"TEAM1234","bundleId":"com.example.habits","environment":"production","allowedValidationCategories":[1],"allowedBundleVersions":["1.0"]}},"android":{"provider":"play_integrity","mode":"required","playIntegrity":{"packageName":"com.example.habits","cloudProjectNumber":123456789,"certificateSha256Digests":["AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"],"minimumDeviceIntegrity":"device","requireLicensed":true,"allowTestingResponses":false,"minimumVersionCode":1,"maximumVersionCode":0,"credentialSource":"metadata"}}}}],
			"upstreams":[{"id":"primary","type":"openai_compatible","baseUrl":"https://api.example.test/v1","authentication":{"type":"none"}}],
			"models":[{"id":"fast","upstream":"primary","upstreamModel":"configured-fast-model"}],
			"limitPlans":[{"id":"free","limits":[{"metric":"logical_requests","scope":["user","feature"],"window":"1d","maximum":5}]}],
			"features":[{"id":"assistant","protocol":"openai_chat","attestationPolicy":"native","access":{"expression":"principal.authenticated"},"limitPlan":{"expression":"'free'"},"output":{"defaultMaximumTokens":800,"absoluteMaximumTokens":1500},"routes":[{"id":"primary","when":"true","model":"fast","priority":10}]}]
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
