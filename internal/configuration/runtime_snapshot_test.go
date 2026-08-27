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
			name: "duplicate upstream",
			mutate: func(spec map[string]any) {
				upstreams := objectArray(spec, "upstreams")
				spec["upstreams"] = append(upstreams, deepClone(upstreams[0]).(map[string]any))
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
			name: "calendar maximum removed",
			mutate: func(spec map[string]any) {
				limit := objectArray(objectArray(spec, "limitPlans")[0], "limits")[0]
				delete(limit, "maximum")
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
