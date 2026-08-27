package configuration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

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
			name: "unsupported limit metric",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["metric"] = "input_tokens"
			},
		},
		{
			name: "unsupported token bucket",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				limit["algorithm"] = "token_bucket"
				delete(limit, "window")
				delete(limit, "maximum")
				limit["capacity"] = json.Number("10")
				limit["refillPerSecond"] = json.Number("1")
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
