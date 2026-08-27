package configuration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func TestCompiledLimitRefillRateRequiresCanonicalExactNumber(t *testing.T) {
	t.Parallel()

	rate, ok := compiledLimitRefillRate(json.RawMessage("0.333333"), true)
	if !ok || rate != (RefillRate{Numerator: 333333, Denominator: 1_000_000}) {
		t.Fatalf("canonical compiled refill = (%+v, %t)", rate, ok)
	}
	if absent, absentOK := compiledLimitRefillRate(nil, false); !absentOK || absent != (RefillRate{}) {
		t.Fatalf("absent compiled refill = (%+v, %t)", absent, absentOK)
	}

	for _, raw := range []string{
		"", "null", `"1"`, "{}", "[]", "1e", "1e0", "1.0", "0", "-1",
		"0.0000001", "9223372036854.775808",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if got, accepted := compiledLimitRefillRate(json.RawMessage(raw), true); accepted {
				t.Fatalf("corrupt compiled refill %q accepted as %+v", raw, got)
			}
		})
	}
}

func TestCompiledLimitRejectsDuplicateJSONMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "metric",
			raw:  `{"metric":"logical_requests","metric":"logical_requests","algorithm":"token_bucket","scope":["user"],"capacity":10,"refillPerSecond":1,"hard":true}`,
		},
		{
			name: "algorithm",
			raw:  `{"metric":"logical_requests","algorithm":"calendar","algorithm":"token_bucket","scope":["user"],"capacity":10,"refillPerSecond":1,"hard":true}`,
		},
		{
			name: "capacity",
			raw:  `{"metric":"logical_requests","algorithm":"token_bucket","scope":["user"],"capacity":9,"capacity":10,"refillPerSecond":1,"hard":true}`,
		},
		{
			name: "refill",
			raw:  `{"metric":"logical_requests","algorithm":"token_bucket","scope":["user"],"capacity":10,"refillPerSecond":0.5,"refillPerSecond":1,"hard":true}`,
		},
		{
			name: "scope",
			raw:  `{"metric":"logical_requests","algorithm":"token_bucket","scope":["feature"],"scope":["user"],"capacity":10,"refillPerSecond":1,"hard":true}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var limit compiledLimit
			if err := json.Unmarshal([]byte(test.raw), &limit); err == nil {
				t.Fatalf("duplicate compiled %s member accepted as %+v", test.name, limit)
			}
		})
	}
}

func TestActiveSnapshotRejectsCorruptRuntimeConfiguration(t *testing.T) {
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
	asLogicalTokenBucket := func(spec map[string]any) map[string]any {
		limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
		limit["metric"] = "logical_requests"
		limit["algorithm"] = "token_bucket"
		delete(limit, "window")
		delete(limit, "maximum")
		limit["capacity"] = json.Number("10")
		limit["refillPerSecond"] = json.Number("1")
		return limit
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "missing attestation policy set",
			mutate: func(spec map[string]any) {
				spec["attestationPolicies"] = []any{}
			},
		},
		{
			name: "duplicate attestation policy",
			mutate: func(spec map[string]any) {
				policies := objectArray(spec, "attestationPolicies")
				spec["attestationPolicies"] = append(policies, deepClone(policies[0]).(map[string]any))
			},
		},
		{
			name: "missing attestation policy identifier",
			mutate: func(spec map[string]any) {
				delete(objectArray(spec, "attestationPolicies")[0], "id")
			},
		},
		{
			name: "invalid attestation policy identifier",
			mutate: func(spec map[string]any) {
				objectArray(spec, "attestationPolicies")[0]["id"] = "Native"
			},
		},
		{
			name: "missing compiled attestation maximum age",
			mutate: func(spec map[string]any) {
				delete(objectArray(spec, "attestationPolicies")[0], "maxAge")
			},
		},
		{
			name: "attestation maximum age below minimum",
			mutate: func(spec map[string]any) {
				objectArray(spec, "attestationPolicies")[0]["maxAge"] = "59s"
			},
		},
		{
			name: "missing attestation platforms",
			mutate: func(spec map[string]any) {
				objectArray(spec, "attestationPolicies")[0]["platforms"] = map[string]any{}
			},
		},
		{
			name: "unknown attestation platform",
			mutate: func(spec map[string]any) {
				platforms := objectValue(objectArray(spec, "attestationPolicies")[0], "platforms")
				platforms["desktop"] = deepClone(platforms["ios"])
			},
		},
		{
			name: "missing attestation mode",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				delete(selection, "mode")
			},
		},
		{
			name: "invalid attestation mode",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["mode"] = "future"
			},
		},
		{
			name: "missing attestation provider",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				delete(selection, "provider")
			},
		},
		{
			name: "unknown attestation provider",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["provider"] = "unknown"
			},
		},
		{
			name: "provider incompatible with attestation platform",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["provider"] = "play_integrity"
			},
		},
		{
			name: "missing compiled attestation trust",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				delete(selection, "minimumTrustLevel")
			},
		},
		{
			name: "invalid attestation trust",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["minimumTrustLevel"] = "rooted"
			},
		},
		{
			name: "required attestation with no trust",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["minimumTrustLevel"] = "none"
			},
		},
		{
			name: "enabled debug attestation without verifier secret",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["provider"] = "debug"
				selection["minimumTrustLevel"] = "debug"
				delete(selection, "secretRef")
			},
		},
		{
			name: "ambiguous required attestation policy",
			mutate: func(spec map[string]any) {
				policies := objectArray(spec, "attestationPolicies")
				second := deepClone(policies[0]).(map[string]any)
				second["id"] = "other"
				spec["attestationPolicies"] = append(policies, second)
			},
		},
		{
			name: "duplicate upstream",
			mutate: func(spec map[string]any) {
				upstreams := objectArray(spec, "upstreams")
				spec["upstreams"] = append(upstreams, deepClone(upstreams[0]).(map[string]any))
			},
		},
		{
			name: "upstream base URL with dot segment",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["baseUrl"] = "https://api.example.test/base/../admin"
			},
		},
		{
			name: "upstream base URL with doubled slash",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["baseUrl"] = "https://api.example.test/base//child"
			},
		},
		{
			name: "upstream base URL with backslash",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["baseUrl"] = `https://api.example.test/base\child`
			},
		},
		{
			name: "upstream base URL requiring escaping",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["baseUrl"] = "https://api.example.test/base path"
			},
		},
		{
			name: "model references missing upstream",
			mutate: func(spec map[string]any) {
				objectArray(spec, "models")[0]["upstream"] = "missing"
			},
		},
		{
			name: "private networks enabled",
			mutate: func(spec map[string]any) {
				upstream := objectArray(spec, "upstreams")[0]
				objectValue(upstream, "destinationPolicy")["allowPrivateNetworks"] = true
			},
		},
		{
			name: "redirects enabled",
			mutate: func(spec map[string]any) {
				upstream := objectArray(spec, "upstreams")[0]
				objectValue(upstream, "destinationPolicy")["allowRedirects"] = true
			},
		},
		{
			name: "DNS pinning disabled",
			mutate: func(spec map[string]any) {
				upstream := objectArray(spec, "upstreams")[0]
				objectValue(upstream, "destinationPolicy")["dnsPinning"] = false
			},
		},
		{
			name: "duplicate allowed port",
			mutate: func(spec map[string]any) {
				upstream := objectArray(spec, "upstreams")[0]
				objectValue(upstream, "destinationPolicy")["allowedPorts"] = []any{json.Number("443"), json.Number("443")}
			},
		},
		{
			name: "forbidden static header",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["staticHeaders"] = map[string]any{"Authorization": "plaintext"}
			},
		},
		{
			name: "enabled application identifier without durable verifier binding",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["applicationIdentifiers"] = []any{"TEAMID.com.example.app"}
			},
		},
		{
			name: "enabled origin without durable verifier binding",
			mutate: func(spec map[string]any) {
				selection := objectValue(objectValue(objectArray(spec, "attestationPolicies")[0], "platforms"), "ios")
				selection["allowedOrigins"] = []any{"https://app.example.test"}
			},
		},
		{
			name: "response-obscuring static compression",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["staticHeaders"] = map[string]any{"Accept-Encoding": "gzip"}
			},
		},
		{
			name: "response-obscuring credential header",
			mutate: func(spec map[string]any) {
				objectArray(spec, "upstreams")[0]["authentication"] = map[string]any{
					"type": "header", "secretRef": "secret/present", "headerName": "Accept-Encoding",
				}
			},
		},
		{
			name: "static header collides with fixed credential header",
			mutate: func(spec map[string]any) {
				upstream := objectArray(spec, "upstreams")[0]
				upstream["authentication"] = map[string]any{
					"type": "header", "secretRef": "secret/present", "headerName": "X-Provider-Tenant",
				}
				upstream["staticHeaders"] = map[string]any{"X-Provider-Tenant": "plaintext"}
			},
		},
		{
			name: "DPoP proof header allowed by opaque policy",
			mutate: func(spec map[string]any) {
				feature := objectArray(spec, "features")[0]
				feature["protocol"] = "opaque_http"
				feature["opaqueHttp"] = map[string]any{
					"allowedMethods": []any{"POST"}, "pathPrefixes": []any{"/v1"},
					"maxBodyBytes": json.Number("1024"), "allowedRequestHeaders": []any{"DPoP"},
				}
				objectArray(spec, "models")[0]["capabilities"] = []any{"opaque_http"}
			},
		},
		{
			name: "opaque path prefix with non-canonical URL spelling",
			mutate: func(spec map[string]any) {
				feature := objectArray(spec, "features")[0]
				feature["protocol"] = "opaque_http"
				feature["opaqueHttp"] = map[string]any{
					"allowedMethods": []any{"POST"}, "pathPrefixes": []any{"/v1 unsafe"},
					"maxBodyBytes": json.Number("1024"), "allowedRequestHeaders": []any{"Content-Type"},
				}
				objectArray(spec, "models")[0]["capabilities"] = []any{"opaque_http"}
			},
		},
		{
			name: "response-obscuring compression allowed by opaque policy",
			mutate: func(spec map[string]any) {
				feature := objectArray(spec, "features")[0]
				feature["protocol"] = "opaque_http"
				feature["opaqueHttp"] = map[string]any{
					"allowedMethods": []any{"POST"}, "pathPrefixes": []any{"/v1"},
					"maxBodyBytes": json.Number("1024"), "allowedRequestHeaders": []any{"Accept-Encoding"},
				}
				objectArray(spec, "models")[0]["capabilities"] = []any{"opaque_http"}
			},
		},
		{
			name: "calendar maximum removed",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				delete(limit, "maximum")
			},
		},
		{
			name: "concurrency maximum removed",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				delete(limit, "maximum")
			},
		},
		{
			name: "concurrency null maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["maximum"] = nil
			},
		},
		{
			name: "concurrency zero maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["maximum"] = json.Number("0")
			},
		},
		{
			name: "concurrency quoted maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_streams"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["maximum"] = "10"
			},
		},
		{
			name: "concurrency fractional maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_streams"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["maximum"] = json.Number("1.5")
			},
		},
		{
			name: "concurrency out of range maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["maximum"] = json.Number("9.223372036854775808e18")
			},
		},
		{
			name: "concurrency with window",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
			},
		},
		{
			name: "concurrency with per request maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_streams"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["perRequestMaximum"] = json.Number("10")
			},
		},
		{
			name: "concurrency with token bucket fields",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["capacity"] = json.Number("10")
				limit["refillPerSecond"] = json.Number("1")
			},
		},
		{
			name: "concurrency with explicit zero forbidden fields",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_streams"
				limit["algorithm"] = "concurrency"
				limit["window"] = ""
				limit["perRequestMaximum"] = json.Number("0")
				limit["capacity"] = json.Number("0")
				limit["refillPerSecond"] = nil
			},
		},
		{
			name: "concurrency with unsupported metric",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "cost_nano_usd"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
			},
		},
		{
			name: "soft concurrency limit",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "concurrent_requests"
				limit["algorithm"] = "concurrency"
				delete(limit, "window")
				limit["hard"] = false
			},
		},
		{
			name: "output calendar with per request field",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["perRequestMaximum"] = json.Number("1")
			},
		},
		{
			name: "negative integral decimal calendar maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["maximum"] = json.Number("-1.0")
			},
		},
		{
			name: "fractional calendar maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["maximum"] = json.Number("5.5")
			},
		},
		{
			name: "quoted calendar maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["maximum"] = "100"
			},
		},
		{
			name: "out of int64 range per request maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["algorithm"] = "per_request"
				delete(limit, "window")
				delete(limit, "maximum")
				limit["perRequestMaximum"] = json.Number("9.223372036854775808e18")
			},
		},
		{
			name: "quoted per request maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["algorithm"] = "per_request"
				delete(limit, "window")
				delete(limit, "maximum")
				limit["perRequestMaximum"] = "4.096e3"
			},
		},
		{
			name: "output per request with explicit zero calendar maximum",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["algorithm"] = "per_request"
				delete(limit, "window")
				limit["maximum"] = json.Number("0")
				limit["perRequestMaximum"] = json.Number("100")
			},
		},
		{
			name: "output per request with explicit null refill",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "output_tokens"
				limit["algorithm"] = "per_request"
				delete(limit, "window")
				delete(limit, "maximum")
				limit["perRequestMaximum"] = json.Number("100")
				limit["refillPerSecond"] = nil
			},
		},
		{
			name: "logical requests per request",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["algorithm"] = "per_request"
				delete(limit, "window")
				delete(limit, "maximum")
				limit["perRequestMaximum"] = json.Number("100")
			},
		},
		{
			name: "unsupported limit metric",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "input_tokens"
			},
		},
		{
			name: "token bucket missing capacity",
			mutate: func(spec map[string]any) {
				delete(asLogicalTokenBucket(spec), "capacity")
			},
		},
		{
			name: "token bucket null capacity",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["capacity"] = nil
			},
		},
		{
			name: "token bucket quoted capacity",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["capacity"] = "10"
			},
		},
		{
			name: "token bucket fractional capacity",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["capacity"] = json.Number("10.5")
			},
		},
		{
			name: "token bucket capacity above executable bound",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["capacity"] = json.Number("9223373")
			},
		},
		{
			name: "token bucket missing refill",
			mutate: func(spec map[string]any) {
				delete(asLogicalTokenBucket(spec), "refillPerSecond")
			},
		},
		{
			name: "token bucket null refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = nil
			},
		},
		{
			name: "token bucket quoted refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = "1"
			},
		},
		{
			name: "token bucket noncanonical exponent refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = json.Number("1e0")
			},
		},
		{
			name: "token bucket noncanonical trailing-zero refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = json.Number("1.0")
			},
		},
		{
			name: "token bucket zero refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = json.Number("0")
			},
		},
		{
			name: "token bucket sub-micro refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = json.Number("0.0000001")
			},
		},
		{
			name: "token bucket refill above executable bound",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = json.Number("1000000.000001")
			},
		},
		{
			name: "token bucket overflowing scaled refill",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["refillPerSecond"] = json.Number("9223372036854.775808")
			},
		},
		{
			name: "token bucket with calendar field",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["window"] = "1d"
			},
		},
		{
			name: "token bucket with maximum field",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["maximum"] = json.Number("1")
			},
		},
		{
			name: "soft token bucket",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["hard"] = false
			},
		},
		{
			name: "unsupported output token bucket",
			mutate: func(spec map[string]any) {
				asLogicalTokenBucket(spec)["metric"] = "output_tokens"
			},
		},
		{
			name: "soft limit",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["hard"] = false
			},
		},
		{
			name: "empty limit scope",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["scope"] = []any{}
			},
		},
		{
			name: "overflowing calendar window",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["window"] = "9223372036854775808d"
			},
		},
		{
			name: "duplicate limit scope",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["scope"] = []any{"user", "user"}
			},
		},
		{
			name: "duplicate immutable limit identity",
			mutate: func(spec map[string]any) {
				plan := objectArray(spec, "limitPlans")[0]
				limits := plan["limits"].([]any)
				duplicate := deepClone(limits[0]).(map[string]any)
				duplicate["scope"] = []any{"feature", "user"}
				duplicate["maximum"] = json.Number("10")
				plan["limits"] = append(limits, duplicate)
			},
		},
		{
			name: "duplicate output per request identity",
			mutate: func(spec map[string]any) {
				plan := objectArray(spec, "limitPlans")[0]
				first := objectArray(plan, "limits")[0]
				first["metric"] = "output_tokens"
				first["algorithm"] = "per_request"
				first["scope"] = []any{"model", "user"}
				delete(first, "window")
				delete(first, "maximum")
				first["perRequestMaximum"] = json.Number("100")
				duplicate := deepClone(first).(map[string]any)
				duplicate["scope"] = []any{"user", "model"}
				duplicate["perRequestMaximum"] = json.Number("200")
				plan["limits"] = []any{first, duplicate}
			},
		},
		{
			name: "duplicate concurrency identity with changed maximum",
			mutate: func(spec map[string]any) {
				plan := objectArray(spec, "limitPlans")[0]
				first := objectArray(plan, "limits")[0]
				first["metric"] = "concurrent_requests"
				first["algorithm"] = "concurrency"
				first["scope"] = []any{"feature", "user"}
				delete(first, "window")
				first["maximum"] = json.Number("10")
				duplicate := deepClone(first).(map[string]any)
				duplicate["scope"] = []any{"user", "feature"}
				duplicate["maximum"] = json.Number("20")
				plan["limits"] = []any{first, duplicate}
			},
		},
		{
			name: "more than 128 executable limits",
			mutate: func(spec map[string]any) {
				plan := objectArray(spec, "limitPlans")[0]
				first := objectArray(plan, "limits")[0]
				limits := make([]any, maximumExecutableLimitRules+1)
				for index := range limits {
					limits[index] = deepClone(first)
				}
				plan["limits"] = limits
			},
		},
		{
			name: "feature route capability mismatch",
			mutate: func(spec map[string]any) {
				objectArray(spec, "models")[0]["capabilities"] = []any{"openai_chat"}
			},
		},
		{
			name: "duplicate model capability",
			mutate: func(spec map[string]any) {
				objectArray(spec, "models")[0]["capabilities"] = []any{"openai_responses", "openai_responses"}
			},
		},
		{
			name: "unknown fallback condition",
			mutate: func(spec map[string]any) {
				feature := objectArray(spec, "features")[0]
				objectArray(feature, "routes")[0]["fallbackOn"] = []any{"unknown"}
			},
		},
		{
			name: "mixed sticky selection within weighted priority",
			mutate: func(spec map[string]any) {
				feature := objectArray(spec, "features")[0]
				routes := objectArray(feature, "routes")
				second := deepClone(routes[0]).(map[string]any)
				second["id"] = "secondary"
				second["stickyBy"] = "user"
				feature["routes"] = append(routes, second)
			},
		},
		{
			name: "missing output policy for token-generating protocol",
			mutate: func(spec map[string]any) {
				delete(objectArray(spec, "features")[0], "output")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, decodeErr := jsonsafe.Decode(compiled)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			root := value.(map[string]any)
			test.mutate(objectValue(root, "spec"))
			corrupt, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, snapshotErr := newActiveSnapshot("rev_00000000000000000000000000", "env_00000000000000000000000000", document, corrupt); snapshotErr == nil {
				t.Fatal("corrupt runtime configuration was accepted")
			}
		})
	}
}
