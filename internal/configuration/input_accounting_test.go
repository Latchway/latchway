package configuration

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
)

func TestValidatorActivatesTrustedInputAndTotalTokenAlgorithms(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	documentObject := configurationObject(t)
	configureInputAccountingFixture(documentObject, "input_tokens", "total_tokens")
	planObject := objectArray(objectValue(documentObject, "spec"), "limitPlans")[0]
	limits := planObject["limits"].([]any)
	for _, metric := range []string{"input_tokens", "total_tokens"} {
		limits = append(limits,
			map[string]any{
				"metric": metric, "algorithm": "token_bucket", "scope": []any{"user", "feature"},
				"capacity": json.Number("1000000"), "refillPerSecond": json.Number("3.5"), "hard": true,
			},
			map[string]any{
				"metric": metric, "algorithm": "per_request", "scope": []any{"user", "feature"},
				"perRequestMaximum": json.Number("1000000"), "hard": true,
			},
		)
	}
	planObject["limits"] = limits
	profile := objectArray(objectValue(documentObject, "spec"), "inputAccountingProfiles")[0]
	profile["maximumFramingTokensPerRequest"] = json.Number("7.0")
	profile["maximumFramingTokensPerMessage"] = json.Number("4e0")
	document, err := json.Marshal(documentObject)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("trusted input/total configuration rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot(
		"rev_00000000000000000000000000",
		"env_00000000000000000000000000",
		document,
		compiled,
	)
	if err != nil {
		t.Fatalf("newActiveSnapshot() error = %v", err)
	}
	wantProfile := InputAccountingProfile{
		ID:                             "chat_profile",
		Protocol:                       inputAccountingProtocol,
		Method:                         inputAccountingMethod,
		PhysicalModel:                  "configured-fast-model",
		MaximumFramingTokensPerRequest: 7,
		MaximumFramingTokensPerMessage: 4,
		MaximumContextTokens:           128_000,
	}
	gotProfile, ok := snapshot.InputAccountingProfile("chat_profile")
	if !ok || gotProfile != wantProfile {
		t.Fatalf("input-accounting profile = %+v ok=%t, want %+v", gotProfile, ok, wantProfile)
	}
	gotProfile.PhysicalModel = "mutated"
	gotAgain, _ := snapshot.InputAccountingProfile("chat_profile")
	if gotAgain != wantProfile {
		t.Fatalf("input-accounting getter aliased snapshot state: %+v", gotAgain)
	}
	model, ok := snapshot.Model("fast")
	if !ok || model.InputAccountingRef != "chat_profile" {
		t.Fatalf("compiled model input accounting ref = %+v ok=%t", model, ok)
	}
	plan, ok := snapshot.LimitPlan("free")
	if !ok || len(plan.Limits) != 6 {
		t.Fatalf("compiled input/total plan = %+v ok=%t", plan, ok)
	}
	wantShapes := map[string]bool{
		"input_tokens/calendar":     true,
		"total_tokens/calendar":     true,
		"input_tokens/token_bucket": true,
		"total_tokens/token_bucket": true,
		"input_tokens/per_request":  true,
		"total_tokens/per_request":  true,
	}
	for _, limit := range plan.Limits {
		key := limit.Metric + "/" + limit.Algorithm
		if !wantShapes[key] {
			t.Fatalf("unexpected compiled input/total shape %q: %+v", key, plan.Limits)
		}
		delete(wantShapes, key)
	}
	if len(wantShapes) != 0 {
		t.Fatalf("missing compiled input/total shapes: %+v", wantShapes)
	}
}

func TestValidatorActivatesProtocolMatchedStructuredProfiles(t *testing.T) {
	t.Parallel()
	for _, protocolID := range []string{
		protocol.OpenAIChatID,
		protocol.OpenAIResponsesID,
		protocol.OpenAIEmbeddingsID,
		protocol.AnthropicMessagesID,
	} {
		protocolID := protocolID
		t.Run(protocolID, func(t *testing.T) {
			t.Parallel()
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			root := configurationObject(t)
			configureInputAccountingFixture(root, "input_tokens", "total_tokens")
			spec := objectValue(root, "spec")
			profile := inputAccountingProfileObject(root)
			profile["protocol"] = protocolID
			model := objectArray(spec, "models")[0]
			model["capabilities"] = []any{protocolID}
			feature := objectArray(spec, "features")[0]
			feature["protocol"] = protocolID
			if protocolID == protocol.OpenAIEmbeddingsID {
				delete(feature, "output")
			}
			if protocolID == protocol.AnthropicMessagesID {
				objectArray(spec, "upstreams")[0]["type"] = "anthropic"
			}
			encoded, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if !report.Valid || len(compiled) == 0 {
				t.Fatalf("structured profile rejected: %+v", report.Issues)
			}
			snapshot, err := newActiveSnapshot(
				"rev_00000000000000000000000000", "env_00000000000000000000000000",
				encoded, compiled,
			)
			if err != nil {
				t.Fatalf("load structured snapshot: %v", err)
			}
			got, ok := snapshot.InputAccountingProfile("chat_profile")
			if !ok || got.Protocol != protocolID {
				t.Fatalf("compiled structured profile = %+v ok=%t", got, ok)
			}
		})
	}
}

func TestValidatorDefersTrustedTokenProofUntilPlanAndRouteSelection(t *testing.T) {
	t.Parallel()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		metric, algorithm string
	}{
		{metric: "input_tokens", algorithm: "token_bucket"},
		{metric: "total_tokens", algorithm: "token_bucket"},
		{metric: "input_tokens", algorithm: "per_request"},
		{metric: "total_tokens", algorithm: "per_request"},
	} {
		test := test
		t.Run(test.metric+"_"+test.algorithm, func(t *testing.T) {
			document := configurationObject(t)
			limit := map[string]any{
				"metric": test.metric, "algorithm": test.algorithm,
				"scope": []any{"user", "feature"}, "hard": true,
			}
			if test.algorithm == "token_bucket" {
				limit["capacity"] = json.Number("100")
				limit["refillPerSecond"] = json.Number("1")
			} else {
				limit["perRequestMaximum"] = json.Number("100")
			}
			objectArray(objectValue(document, "spec"), "limitPlans")[0]["limits"] = []any{limit}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if !report.Valid || len(compiled) == 0 {
				t.Fatalf("mixed-protocol-safe %s/%s configuration rejected: %+v", test.metric, test.algorithm, report.Issues)
			}
		})
	}
}

func TestInputAccountingProfileSchemaIsStrictAndBounded(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown field", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["future"] = true
		}},
		{name: "missing id", mutate: func(root map[string]any) {
			delete(inputAccountingProfileObject(root), "id")
		}},
		{name: "missing method", mutate: func(root map[string]any) {
			delete(inputAccountingProfileObject(root), "method")
		}},
		{name: "opaque protocol", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["protocol"] = "opaque_http"
		}},
		{name: "wrong method", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["method"] = "heuristic"
		}},
		{name: "empty physical model", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["physicalModel"] = ""
		}},
		{name: "negative request framing", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumFramingTokensPerRequest"] = json.Number("-1")
		}},
		{name: "negative message framing", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumFramingTokensPerMessage"] = json.Number("-1")
		}},
		{name: "zero context", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumContextTokens"] = json.Number("0")
		}},
		{name: "fractional framing", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumFramingTokensPerRequest"] = json.Number("1.5")
		}},
		{name: "int64 overflow", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumContextTokens"] = json.Number("9223372036854775808")
		}},
		{name: "invalid model reference", mutate: func(root map[string]any) {
			objectArray(objectValue(root, "spec"), "models")[0]["inputAccountingRef"] = "Invalid"
		}},
		{name: "too many profiles", mutate: func(root map[string]any) {
			spec := objectValue(root, "spec")
			base := inputAccountingProfileObject(root)
			profiles := make([]any, 0, maximumInputAccountingProfiles+1)
			for index := 0; index <= maximumInputAccountingProfiles; index++ {
				profile := deepClone(base).(map[string]any)
				profile["id"] = fmt.Sprintf("profile_%03d", index)
				profiles = append(profiles, profile)
			}
			spec["inputAccountingProfiles"] = profiles
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := configurationObject(t)
			configureInputAccountingFixture(root, "input_tokens")
			test.mutate(root)
			encoded, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if issues := validator.SchemaIssues(encoded); len(issues) == 0 {
				t.Fatalf("schema accepted invalid input-accounting shape: %s", encoded)
			}
		})
	}
}

func TestValidatorRejectsInvalidInputAccountingReferences(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		code   string
		mutate func(map[string]any)
	}{
		{name: "duplicate profile id", code: "duplicate_identifier", mutate: func(root map[string]any) {
			spec := objectValue(root, "spec")
			profiles := objectArray(spec, "inputAccountingProfiles")
			spec["inputAccountingProfiles"] = append(profiles, deepClone(profiles[0]).(map[string]any))
		}},
		{name: "missing reference", code: "input_accounting_reference_missing", mutate: func(root map[string]any) {
			objectArray(objectValue(root, "spec"), "models")[0]["inputAccountingRef"] = "missing"
		}},
		{name: "physical model mismatch", code: "input_accounting_reference_mismatch", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["physicalModel"] = "different-physical-model"
		}},
		{name: "model capability mismatch", code: "input_accounting_reference_mismatch", mutate: func(root map[string]any) {
			objectArray(objectValue(root, "spec"), "models")[0]["capabilities"] = []any{"openai_responses"}
		}},
		{name: "unsafe physical model", code: "input_accounting_physical_model_invalid", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["physicalModel"] = " configured-fast-model"
		}},
		{name: "profile physical model contains internal tab", code: "input_accounting_physical_model_invalid", mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["physicalModel"] = "configured\tfast-model"
		}},
		{name: "model physical model contains internal control", code: "model_physical_model_invalid", mutate: func(root map[string]any) {
			objectArray(objectValue(root, "spec"), "models")[0]["upstreamModel"] = "configured\u0085fast-model"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := configurationObject(t)
			configureInputAccountingFixture(root, "input_tokens")
			test.mutate(root)
			encoded, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("invalid input-accounting reference activated: %+v", report.Issues)
			}
		})
	}
}

func TestValidatorRejectsImpossibleInputAccountingContexts(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name                string
		code                string
		deferUntilSelection bool
		mutate              func(map[string]any)
	}{
		{name: "framing sum overflow", code: "input_accounting_profile_context_impossible", mutate: func(root map[string]any) {
			profile := inputAccountingProfileObject(root)
			profile["maximumFramingTokensPerRequest"] = json.Number("9223372036854775807")
			profile["maximumFramingTokensPerMessage"] = json.Number("1")
			profile["maximumContextTokens"] = json.Number("9223372036854775807")
		}},
		{name: "framing consumes context", code: "input_accounting_profile_context_impossible", mutate: func(root map[string]any) {
			profile := inputAccountingProfileObject(root)
			profile["maximumFramingTokensPerRequest"] = json.Number("127996")
			profile["maximumFramingTokensPerMessage"] = json.Number("4")
			profile["maximumContextTokens"] = json.Number("128000")
		}},
		{name: "profile cannot fit minimal chat body", code: "input_accounting_profile_context_impossible", mutate: func(root map[string]any) {
			profile := inputAccountingProfileObject(root)
			profile["maximumFramingTokensPerRequest"] = json.Number("0")
			profile["maximumFramingTokensPerMessage"] = json.Number("0")
			profile["maximumContextTokens"] = json.Number("2")
		}},
		{name: "route leaves no body byte", deferUntilSelection: true, mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumContextTokens"] = json.Number("1512")
		}},
		{name: "route cannot fit minimal chat body", deferUntilSelection: true, mutate: func(root map[string]any) {
			inputAccountingProfileObject(root)["maximumContextTokens"] = json.Number("1513")
		}},
		{name: "route accounting overflows", deferUntilSelection: true, mutate: func(root map[string]any) {
			profile := inputAccountingProfileObject(root)
			profile["maximumFramingTokensPerRequest"] = json.Number("9223372036854774807")
			profile["maximumFramingTokensPerMessage"] = json.Number("1")
			profile["maximumContextTokens"] = json.Number("9223372036854775807")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := configurationObject(t)
			configureInputAccountingFixture(root, "input_tokens")
			test.mutate(root)
			encoded, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			report, compiled := validator.Validate(encoded, testEnvironment(), time.Now())
			if test.deferUntilSelection {
				if !report.Valid || len(compiled) == 0 {
					t.Fatalf("request-specific context was rejected before route selection: %+v", report.Issues)
				}
				return
			}
			if report.Valid || compiled != nil || !hasIssue(report.Issues, test.code) {
				t.Fatalf("impossible input-accounting context activated: %+v", report.Issues)
			}
		})
	}
}

func TestValidatorAllowsUnrelatedMixedProtocolRoutes(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := configurationObject(t)
	configureInputAccountingFixture(root, "input_tokens")
	spec := objectValue(root, "spec")
	models := objectArray(spec, "models")
	legacyModel := deepClone(models[0]).(map[string]any)
	legacyModel["id"] = "legacy"
	legacyModel["upstreamModel"] = "configured-legacy-model"
	delete(legacyModel, "inputAccountingRef")
	legacyModel["capabilities"] = []any{"openai_responses"}
	spec["models"] = append(models, legacyModel)
	plans := objectArray(spec, "limitPlans")
	spec["limitPlans"] = append(plans, map[string]any{
		"id": "requests",
		"limits": []any{map[string]any{
			"metric": "logical_requests", "algorithm": "calendar", "scope": []any{"user"},
			"window": "1d", "maximum": json.Number("10"), "hard": true,
		}},
	})
	features := objectArray(spec, "features")
	legacyFeature := deepClone(features[0]).(map[string]any)
	legacyFeature["id"] = "legacy_assistant"
	legacyFeature["protocol"] = "openai_responses"
	objectValue(legacyFeature, "limitPlan")["expression"] = "'requests'"
	legacyRoute := objectArray(legacyFeature, "routes")[0]
	legacyRoute["id"] = "legacy"
	legacyRoute["model"] = "legacy"
	spec["features"] = append(features, legacyFeature)

	mixed, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(mixed, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("unrelated mixed-protocol route was rejected: %+v", report.Issues)
	}

	legacyFeature["protocol"] = inputAccountingProtocol
	legacyModel["capabilities"] = []any{inputAccountingProtocol}
	legacyModel["inputAccountingRef"] = "legacy_profile"
	legacyProfile := deepClone(inputAccountingProfileObject(root)).(map[string]any)
	legacyProfile["id"] = "legacy_profile"
	legacyProfile["physicalModel"] = "configured-legacy-model"
	spec["inputAccountingProfiles"] = append(objectArray(spec, "inputAccountingProfiles"), legacyProfile)
	safe, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	safeReport, safeCompiled := validator.Validate(safe, testEnvironment(), time.Now())
	if !safeReport.Valid || len(safeCompiled) == 0 {
		t.Fatalf("fully accounted override routes rejected: %+v", safeReport.Issues)
	}
}

func TestValidatorAllowsInputPricedHardCostWithTrustedProfile(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := configurationObject(t)
	configureInputAccountingFixture(root, "cost_nano_usd")
	spec := objectValue(root, "spec")
	model := objectArray(spec, "models")[0]
	model["pricingRef"] = "standard"
	spec["pricingCatalogs"] = []any{map[string]any{
		"id": "standard", "currency": "USD",
		"entries": []any{map[string]any{
			"model": "fast", "inputNanoUsdPerMillion": json.Number("2500"),
			"outputNanoUsdPerMillion": json.Number("5000"), "requestNanoUsd": json.Number("10"),
		}},
	}}
	document, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("input-priced hard cost with trusted profile rejected: %+v", report.Issues)
	}
}

func TestActiveSnapshotRejectsCorruptInputAccountingState(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := configurationObject(t)
	configureInputAccountingFixture(root, "input_tokens")
	document, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	report, compiled := validator.Validate(document, testEnvironment(), time.Now())
	if !report.Valid {
		t.Fatalf("input-accounting fixture rejected: %+v", report.Issues)
	}
	tests := []struct {
		name     string
		accepted bool
		mutate   func(map[string]any)
	}{
		{name: "duplicate profile", mutate: func(spec map[string]any) {
			profiles := objectArray(spec, "inputAccountingProfiles")
			spec["inputAccountingProfiles"] = append(profiles, deepClone(profiles[0]).(map[string]any))
		}},
		{name: "unknown profile field", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["future"] = true
		}},
		{name: "missing profile method", mutate: func(spec map[string]any) {
			delete(objectArray(spec, "inputAccountingProfiles")[0], "method")
		}},
		{name: "wrong profile protocol", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["protocol"] = "openai_responses"
		}},
		{name: "wrong profile method", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["method"] = "heuristic"
		}},
		{name: "unsafe physical model", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["physicalModel"] = " configured-fast-model"
		}},
		{name: "profile physical model internal tab", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["physicalModel"] = "configured\tfast-model"
		}},
		{name: "model physical model internal control", mutate: func(spec map[string]any) {
			objectArray(spec, "models")[0]["upstreamModel"] = "configured\u0085fast-model"
		}},
		{name: "negative framing", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["maximumFramingTokensPerRequest"] = json.Number("-1")
		}},
		{name: "fractional framing", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["maximumFramingTokensPerMessage"] = json.Number("1.5")
		}},
		{name: "zero context", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["maximumContextTokens"] = json.Number("0")
		}},
		{name: "profile framing overflow", mutate: func(spec map[string]any) {
			profile := objectArray(spec, "inputAccountingProfiles")[0]
			profile["maximumFramingTokensPerRequest"] = json.Number("9223372036854775807")
			profile["maximumFramingTokensPerMessage"] = json.Number("1")
			profile["maximumContextTokens"] = json.Number("9223372036854775807")
		}},
		{name: "profile framing consumes context", mutate: func(spec map[string]any) {
			profile := objectArray(spec, "inputAccountingProfiles")[0]
			profile["maximumFramingTokensPerRequest"] = json.Number("127996")
			profile["maximumFramingTokensPerMessage"] = json.Number("4")
			profile["maximumContextTokens"] = json.Number("128000")
		}},
		{name: "profile cannot fit minimal chat body", mutate: func(spec map[string]any) {
			profile := objectArray(spec, "inputAccountingProfiles")[0]
			profile["maximumFramingTokensPerRequest"] = json.Number("0")
			profile["maximumFramingTokensPerMessage"] = json.Number("0")
			profile["maximumContextTokens"] = json.Number("2")
		}},
		{name: "route leaves no body byte", accepted: true, mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["maximumContextTokens"] = json.Number("1512")
		}},
		{name: "route cannot fit minimal chat body", accepted: true, mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["maximumContextTokens"] = json.Number("1513")
		}},
		{name: "route accounting overflow", accepted: true, mutate: func(spec map[string]any) {
			profile := objectArray(spec, "inputAccountingProfiles")[0]
			profile["maximumFramingTokensPerRequest"] = json.Number("9223372036854774807")
			profile["maximumFramingTokensPerMessage"] = json.Number("1")
			profile["maximumContextTokens"] = json.Number("9223372036854775807")
		}},
		{name: "model physical mismatch", mutate: func(spec map[string]any) {
			objectArray(spec, "inputAccountingProfiles")[0]["physicalModel"] = "other"
		}},
		{name: "missing model ref", mutate: func(spec map[string]any) {
			objectArray(spec, "models")[0]["inputAccountingRef"] = "missing"
		}},
		{name: "null model ref", mutate: func(spec map[string]any) {
			objectArray(spec, "models")[0]["inputAccountingRef"] = nil
		}},
		{name: "removed model ref", accepted: true, mutate: func(spec map[string]any) {
			delete(objectArray(spec, "models")[0], "inputAccountingRef")
		}},
		{name: "too many profiles", mutate: func(spec map[string]any) {
			base := objectArray(spec, "inputAccountingProfiles")[0]
			profiles := make([]any, 0, maximumInputAccountingProfiles+1)
			for index := 0; index <= maximumInputAccountingProfiles; index++ {
				profile := deepClone(base).(map[string]any)
				profile["id"] = fmt.Sprintf("profile_%03d", index)
				profiles = append(profiles, profile)
			}
			spec["inputAccountingProfiles"] = profiles
			objectArray(spec, "models")[0]["inputAccountingRef"] = "profile_000"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, decodeErr := jsonsafe.Decode(compiled)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			compiledRoot := decoded.(map[string]any)
			test.mutate(objectValue(compiledRoot, "spec"))
			corrupt, marshalErr := json.Marshal(compiledRoot)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, snapshotErr := newActiveSnapshot(
				"rev_00000000000000000000000000",
				"env_00000000000000000000000000",
				document,
				corrupt,
			)
			if test.accepted && snapshotErr != nil {
				t.Fatalf("selection-time-safe snapshot was rejected: %v", snapshotErr)
			}
			if !test.accepted && snapshotErr == nil {
				t.Fatal("corrupt input-accounting snapshot was accepted")
			}
		})
	}
}

func TestCompiledInputAccountingRejectsDuplicateMembersAndRefs(t *testing.T) {
	t.Parallel()

	profile := `{"id":"chat_profile","protocol":"openai_chat","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical","maximumFramingTokensPerRequest":1,"maximumFramingTokensPerRequest":2,"maximumFramingTokensPerMessage":3,"maximumContextTokens":100}`
	var decodedProfile compiledInputAccountingProfile
	if err := json.Unmarshal([]byte(profile), &decodedProfile); err == nil {
		t.Fatalf("duplicate profile member accepted: %+v", decodedProfile)
	}
	model := `{"id":"fast","upstream":"primary","upstreamModel":"physical","inputAccountingRef":"one","inputAccountingRef":"two","capabilities":["openai_chat"]}`
	var decodedModel compiledModel
	if err := json.Unmarshal([]byte(model), &decodedModel); err == nil {
		t.Fatalf("duplicate input-accounting reference accepted: %+v", decodedModel)
	}
}

func TestCompiledInputAccountingMarshalUsesCanonicalMemberNames(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(compiledModel{
		ID: "fast", UpstreamID: "primary", UpstreamModel: "physical",
		InputAccountingRef: "chat_profile", Capabilities: []string{"openai_chat"},
		hasInputAccountingRef: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	object := decoded.(map[string]any)
	for _, member := range []string{"id", "upstream", "upstreamModel", "inputAccountingRef", "capabilities"} {
		if _, ok := object[member]; !ok {
			t.Fatalf("canonical model member %q missing from %s", member, encoded)
		}
	}
	for _, member := range []string{"ID", "UpstreamID", "UpstreamModel", "InputAccountingRef", "hasInputAccountingRef"} {
		if _, ok := object[member]; ok {
			t.Fatalf("internal model member %q leaked into %s", member, encoded)
		}
	}

	encodedProfile, err := json.Marshal(compiledInputAccountingProfile{InputAccountingProfile: InputAccountingProfile{
		ID: "chat_profile", Protocol: inputAccountingProtocol, Method: inputAccountingMethod,
		PhysicalModel: "physical", MaximumFramingTokensPerRequest: 8,
		MaximumFramingTokensPerMessage: 4, MaximumContextTokens: 128_000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	decodedProfile, err := jsonsafe.Decode(encodedProfile)
	if err != nil {
		t.Fatal(err)
	}
	profileObject := decodedProfile.(map[string]any)
	for _, member := range []string{
		"id", "protocol", "method", "physicalModel", "maximumFramingTokensPerRequest",
		"maximumFramingTokensPerMessage", "maximumContextTokens",
	} {
		if _, ok := profileObject[member]; !ok {
			t.Fatalf("canonical profile member %q missing from %s", member, encodedProfile)
		}
	}
	if _, ok := profileObject["MaximumContextTokens"]; ok {
		t.Fatalf("Go profile member leaked into %s", encodedProfile)
	}
}

func TestRuntimeInputAccountingAcceptsExactInt64Boundary(t *testing.T) {
	t.Parallel()

	raw := fmt.Sprintf(
		`{"id":"chat_profile","protocol":"%s","method":"%s","physicalModel":"physical","maximumFramingTokensPerRequest":0,"maximumFramingTokensPerMessage":1,"maximumContextTokens":%d}`,
		inputAccountingProtocol,
		inputAccountingMethod,
		int64(math.MaxInt64),
	)
	var compiled compiledInputAccountingProfile
	if err := json.Unmarshal([]byte(raw), &compiled); err != nil {
		t.Fatalf("decode int64-bound profile: %v", err)
	}
	profile, err := runtimeInputAccountingProfile(compiled)
	if err != nil || profile.MaximumContextTokens != math.MaxInt64 {
		t.Fatalf("runtime int64-bound profile = %+v error=%v", profile, err)
	}
}

func configureInputAccountingFixture(root map[string]any, metrics ...string) {
	spec := objectValue(root, "spec")
	spec["inputAccountingProfiles"] = []any{map[string]any{
		"id": "chat_profile", "protocol": inputAccountingProtocol, "method": inputAccountingMethod,
		"physicalModel":                  "configured-fast-model",
		"maximumFramingTokensPerRequest": json.Number("8"),
		"maximumFramingTokensPerMessage": json.Number("4"),
		"maximumContextTokens":           json.Number("128000"),
	}}
	model := objectArray(spec, "models")[0]
	model["inputAccountingRef"] = "chat_profile"
	model["capabilities"] = []any{inputAccountingProtocol}
	feature := objectArray(spec, "features")[0]
	feature["protocol"] = inputAccountingProtocol
	limits := make([]any, 0, len(metrics))
	for _, metric := range metrics {
		limits = append(limits, map[string]any{
			"metric": metric, "algorithm": "calendar", "scope": []any{"user", "feature"},
			"window": "1d", "maximum": json.Number("1000000"), "hard": true,
		})
	}
	objectArray(spec, "limitPlans")[0]["limits"] = limits
}

func inputAccountingProfileObject(root map[string]any) map[string]any {
	return objectArray(objectValue(root, "spec"), "inputAccountingProfiles")[0]
}
