package configuration

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func FuzzActiveSnapshotCompilation(f *testing.F) {
	validator, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	source := []byte(`{
		"apiVersion":"latchway.dev/v1alpha1",
		"kind":"EnvironmentConfig",
		"metadata":{"organization":"example","application":"habits","environment":"production"},
		"spec":{
			"identityProviders":[{"id":"firebase","type":"firebase","projectId":"habits-production"}],
			"attestationPolicies":[{"id":"native","platforms":{"ios":{"provider":"app_attest","mode":"required"}}}],
			"upstreams":[{"id":"primary","type":"openai_compatible","baseUrl":"https://api.example.test/v1","authentication":{"type":"none"}}],
			"models":[{"id":"fast","upstream":"primary","upstreamModel":"physical-fast","pricingRef":"standard"}],
			"pricingCatalogs":[{"id":"standard","currency":"USD","effectiveAt":"2026-08-27T12:34:56Z","entries":[{"model":"fast","inputNanoUsdPerMillion":1000.0,"outputNanoUsdPerMillion":2e3}]}],
			"limitPlans":[{"id":"free","limits":[{"metric":"logical_requests","scope":["user","feature"],"window":"1d","maximum":5}]}],
			"features":[{"id":"assistant","protocol":"openai_chat","attestationPolicy":"native","access":{"expression":"principal.authenticated"},"limitPlan":{"expression":"'free'"},"output":{"defaultMaximumTokens":100,"absoluteMaximumTokens":200},"routes":[{"id":"primary","when":"true","model":"fast","priority":1}]}]
		}
	}`)
	report, compiled := validator.Validate(source, testEnvironment(), time.Unix(0, 0).UTC())
	if !report.Valid {
		f.Fatalf("seed configuration rejected: %+v", report.Issues)
	}
	f.Add([]byte(compiled))
	addExecutableLimitSeed := func(name string, limit map[string]any) {
		f.Helper()
		value, err := jsonsafe.Decode(source)
		if err != nil {
			f.Fatalf("decode %s seed: %v", name, err)
		}
		root := value.(map[string]any)
		objectArray(objectValue(root, "spec"), "limitPlans")[0]["limits"] = []any{limit}
		candidateSource, err := json.Marshal(root)
		if err != nil {
			f.Fatalf("marshal %s seed: %v", name, err)
		}
		report, candidateCompiled := validator.Validate(candidateSource, testEnvironment(), time.Unix(0, 0).UTC())
		if !report.Valid {
			f.Fatalf("%s seed configuration rejected: %+v", name, report.Issues)
		}
		f.Add([]byte(candidateCompiled))
	}
	addExecutableLimitSeed("explicit request concurrency", map[string]any{
		"metric": "concurrent_requests", "algorithm": "concurrency",
		"scope": []any{"feature", "user"}, "maximum": json.Number("9223372036854775807.0"),
	})
	addExecutableLimitSeed("default stream concurrency", map[string]any{
		"metric": "concurrent_streams", "scope": []any{"model", "user"},
		"maximum": json.Number("4.096e3"),
	})
	addExecutableLimitSeed("canonical logical request token bucket", map[string]any{
		"metric": "logical_requests", "scope": []any{"feature", "user"},
		"capacity": json.Number("9223372.0"), "refillPerSecond": json.Number("1.000000e6"),
	})
	addExecutableLimitSeed("canonical output token bucket", map[string]any{
		"metric": "output_tokens", "scope": []any{"model", "user"},
		"capacity": json.Number("9223372.0"), "refillPerSecond": json.Number("1.000000e6"),
	})
	value, err := jsonsafe.Decode(source)
	if err != nil {
		f.Fatalf("decode trusted input seed: %v", err)
	}
	inputRoot := value.(map[string]any)
	inputSpec := objectValue(inputRoot, "spec")
	inputSpec["inputAccountingProfiles"] = []any{map[string]any{
		"id": "chat_profile", "protocol": inputAccountingProtocol, "method": inputAccountingMethod,
		"physicalModel":                  "physical-fast",
		"maximumFramingTokensPerRequest": json.Number("8"),
		"maximumFramingTokensPerMessage": json.Number("4"),
		"maximumContextTokens":           json.Number("128000"),
	}}
	inputModel := objectArray(inputSpec, "models")[0]
	inputModel["inputAccountingRef"] = "chat_profile"
	inputModel["capabilities"] = []any{inputAccountingProtocol}
	objectArray(inputSpec, "limitPlans")[0]["limits"] = []any{map[string]any{
		"metric": "input_tokens", "algorithm": "calendar", "scope": []any{"user", "feature"},
		"window": "1d", "maximum": json.Number("1000000"), "hard": true,
	}}
	inputSource, err := json.Marshal(inputRoot)
	if err != nil {
		f.Fatalf("marshal trusted input seed: %v", err)
	}
	inputReport, inputCompiled := validator.Validate(inputSource, testEnvironment(), time.Unix(0, 0).UTC())
	if !inputReport.Valid {
		f.Fatalf("trusted input seed rejected: %+v", inputReport.Issues)
	}
	f.Add([]byte(inputCompiled))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"spec":{"features":[]}}`))

	f.Fuzz(func(t *testing.T, candidate []byte) {
		if len(candidate) > 1<<20 {
			t.Skip()
		}
		snapshot, snapshotErr := newActiveSnapshot(
			"rev_00000000000000000000000000",
			"env_00000000000000000000000000",
			source,
			candidate,
		)
		if snapshotErr != nil {
			return
		}
		first := snapshot.CompiledJSON()
		if len(first) == 0 {
			t.Fatal("accepted snapshot has empty compiled document")
		}
		first[0] ^= 0xff
		if bytes.Equal(first, snapshot.CompiledJSON()) {
			t.Fatal("compiled snapshot aliases returned bytes")
		}
	})
}
