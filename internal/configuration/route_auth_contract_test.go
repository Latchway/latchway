package configuration

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func TestRouteAuthContractAcceptsOnlyExactAuthenticationVariants(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name           string
		authentication map[string]any
		want           UpstreamAuthentication
	}{
		{
			name: "none", authentication: map[string]any{"type": "none"},
			want: UpstreamAuthentication{Type: "none"},
		},
		{
			name: "bearer",
			authentication: map[string]any{
				"type": "bearer", "secretRef": "secret/present",
			},
			want: UpstreamAuthentication{Type: "bearer", SecretRef: "secret/present"},
		},
		{
			name: "header",
			authentication: map[string]any{
				"type": "header", "headerName": "X-Vendor-Token", "secretRef": "secret/present",
			},
			want: UpstreamAuthentication{
				Type: "header", HeaderName: "X-Vendor-Token", SecretRef: "secret/present",
			},
		},
		{
			name: "basic",
			authentication: map[string]any{
				"type": "basic", "username": "client!name~", "secretRef": "secret/present",
			},
			want: UpstreamAuthentication{
				Type: "basic", Username: "client!name~", SecretRef: "secret/present",
			},
		},
		{
			name: "headers",
			authentication: map[string]any{
				"type": "headers",
				"headers": []any{
					map[string]any{"headerName": "X-Vendor-Key", "secretRef": "secret/present"},
					map[string]any{"headerName": "X-Vendor-Tenant", "secretRef": "secret/secondary"},
				},
			},
			want: UpstreamAuthentication{
				Type: "headers",
				Headers: []UpstreamAuthenticationHeader{
					{HeaderName: "X-Vendor-Key", SecretRef: "secret/present"},
					{HeaderName: "X-Vendor-Tenant", SecretRef: "secret/secondary"},
				},
			},
		},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			objectArray(objectValue(document, "spec"), "upstreams")[0]["authentication"] = test.authentication
			environment := routeAuthTestEnvironment()
			_, snapshot := routeAuthCompile(t, document, environment)
			upstream, ok := snapshot.Upstream("primary")
			if !ok || !reflect.DeepEqual(upstream.Authentication, test.want) {
				t.Fatalf("compiled authentication = %+v, ok=%t; want %+v", upstream.Authentication, ok, test.want)
			}
			if len(upstream.Authentication.Headers) != 0 {
				upstream.Authentication.Headers[0].SecretRef = "secret/mutated"
				again, _ := snapshot.Upstream("primary")
				if reflect.DeepEqual(upstream.Authentication.Headers, again.Authentication.Headers) {
					t.Fatal("upstream authentication header slice was not cloned")
				}
			}
		})
	}

	invalid := []struct {
		name           string
		authentication map[string]any
	}{
		{name: "none with secret", authentication: map[string]any{"type": "none", "secretRef": "secret/present"}},
		{name: "bearer with header", authentication: map[string]any{"type": "bearer", "secretRef": "secret/present", "headerName": "X-Key"}},
		{name: "header without name", authentication: map[string]any{"type": "header", "secretRef": "secret/present"}},
		{name: "basic without username", authentication: map[string]any{"type": "basic", "secretRef": "secret/present"}},
		{name: "headers with top-level secret", authentication: map[string]any{
			"type": "headers", "secretRef": "secret/present",
			"headers": []any{map[string]any{"headerName": "X-Key", "secretRef": "secret/present"}},
		}},
		{name: "empty headers", authentication: map[string]any{"type": "headers", "headers": []any{}}},
	}
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range invalid {
		t.Run("invalid_"+test.name, func(t *testing.T) {
			document := configurationObject(t)
			objectArray(objectValue(document, "spec"), "upstreams")[0]["authentication"] = test.authentication
			encoded := routeAuthMarshal(t, document)
			if issues := validator.SchemaIssues(encoded); len(issues) == 0 {
				t.Fatalf("schema accepted inexact %s authentication", test.name)
			}

			baseDocument := configurationObject(t)
			compiled, _ := routeAuthCompile(t, baseDocument, routeAuthTestEnvironment())
			compiledRoot := routeAuthDecoded(t, compiled)
			objectArray(objectValue(compiledRoot, "spec"), "upstreams")[0]["authentication"] = test.authentication
			if _, err := newActiveSnapshot(
				"revision", "environment", routeAuthMarshal(t, baseDocument), routeAuthMarshal(t, compiledRoot),
			); err == nil {
				t.Fatalf("runtime accepted inexact %s authentication", test.name)
			}
		})
	}
}

func TestRouteAuthContractRuntimeRejectsMultiHeaderCollisions(t *testing.T) {
	t.Parallel()

	document := configurationObject(t)
	upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
	upstream["authentication"] = map[string]any{
		"type": "headers",
		"headers": []any{
			map[string]any{"headerName": "X-Vendor-Key", "secretRef": "secret/present"},
			map[string]any{"headerName": "X-Vendor-Tenant", "secretRef": "secret/secondary"},
		},
	}
	compiled, _ := routeAuthCompile(t, document, routeAuthTestEnvironment())
	for name, mutate := range map[string]func(map[string]any, []map[string]any){
		"duplicate": func(_ map[string]any, headers []map[string]any) {
			headers[1]["headerName"] = "x-vendor-key"
		},
		"static collision": func(upstream map[string]any, _ []map[string]any) {
			upstream["staticHeaders"] = map[string]any{"x-vendor-key": "public-value"}
		},
		"internal header": func(_ map[string]any, headers []map[string]any) {
			headers[0]["headerName"] = "X-Latchway-Internal"
		},
		"hop-by-hop header": func(_ map[string]any, headers []map[string]any) {
			headers[0]["headerName"] = "Connection"
		},
	} {
		t.Run(name, func(t *testing.T) {
			corrupt := routeAuthDecoded(t, compiled)
			corruptUpstream := objectArray(objectValue(corrupt, "spec"), "upstreams")[0]
			authentication := objectValue(corruptUpstream, "authentication")
			headers := objectArray(authentication, "headers")
			mutate(corruptUpstream, headers)
			if _, err := newActiveSnapshot(
				"revision", "environment", routeAuthMarshal(t, document), routeAuthMarshal(t, corrupt),
			); err == nil {
				t.Fatalf("runtime accepted %s", name)
			}
		})
	}
}

func TestRouteAuthContractBasicUsernameGrammarAtSchemaRuntimeAndSemantics(t *testing.T) {
	t.Parallel()

	for _, username := range []string{"client", "client!name~", strings.Repeat("a", 256)} {
		if !runtimeBasicUsernameValid(username) {
			t.Errorf("runtime rejected valid Basic username %q", username)
		}
	}
	for name, username := range map[string]string{
		"empty": "", "space": "client name", "colon": "client:name", "tab": "client\tname",
		"non-ascii": "clïent", "too-long": strings.Repeat("a", 257),
	} {
		t.Run(name, func(t *testing.T) {
			if runtimeBasicUsernameValid(username) {
				t.Fatalf("runtime accepted invalid Basic username %q", username)
			}
			document := configurationObject(t)
			upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
			upstream["authentication"] = map[string]any{
				"type": "basic", "username": username, "secretRef": "secret/present",
			}
			validator, err := NewValidator()
			if err != nil {
				t.Fatal(err)
			}
			if issues := validator.SchemaIssues(routeAuthMarshal(t, document)); len(issues) == 0 {
				t.Fatal("schema accepted invalid Basic username")
			}

			applyDefaults(document)
			issues := upstreamSemanticIssues(map[string]map[string]any{"primary": upstream}, "production")
			if !hasIssue(issues, "upstream_basic_username_invalid") {
				t.Fatalf("semantic validation missed invalid Basic username: %+v", issues)
			}
		})
	}
}

func TestRouteAuthContractRejectsMultiHeaderCollisionsAndChecksNestedSecrets(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	baseHeaders := []any{
		map[string]any{"headerName": "X-Vendor-Key", "secretRef": "secret/present"},
		map[string]any{"headerName": "X-Vendor-Tenant", "secretRef": "secret/secondary"},
	}
	tests := []struct {
		name   string
		mutate func(map[string]any, []any)
		code   string
		path   string
	}{
		{
			name: "case-insensitive duplicate",
			mutate: func(_ map[string]any, headers []any) {
				object := headers[1].(map[string]any)
				object["headerName"] = "x-vendor-key"
			},
			code: "upstream_authentication_header_duplicate",
		},
		{
			name: "static header collision",
			mutate: func(upstream map[string]any, _ []any) {
				upstream["staticHeaders"] = map[string]any{"x-vendor-key": "public-value"}
			},
			code: "upstream_authentication_header_collision",
		},
		{
			name: "internal control header",
			mutate: func(_ map[string]any, headers []any) {
				headers[0].(map[string]any)["headerName"] = "X-Latchway-Internal"
			},
			code: "runtime_configuration_invalid",
		},
		{
			name: "hop-by-hop header",
			mutate: func(_ map[string]any, headers []any) {
				headers[0].(map[string]any)["headerName"] = "Connection"
			},
			code: "runtime_configuration_invalid",
		},
		{
			name: "nested secret reference",
			mutate: func(_ map[string]any, headers []any) {
				headers[1].(map[string]any)["secretRef"] = "secret/missing-nested"
			},
			code: "secret_reference_missing",
			path: "/spec/upstreams/0/authentication/headers/1/secretRef",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := configurationObject(t)
			upstream := objectArray(objectValue(document, "spec"), "upstreams")[0]
			headers := deepClone(baseHeaders).([]any)
			upstream["authentication"] = map[string]any{"type": "headers", "headers": headers}
			test.mutate(upstream, headers)
			encoded := routeAuthMarshal(t, document)
			if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
				t.Fatalf("collision must reach semantic/runtime boundary, schema issues: %+v", issues)
			}
			report, compiled := validator.Validate(encoded, routeAuthTestEnvironment(), time.Now())
			if report.Valid || compiled != nil || !routeAuthHasIssueAt(report.Issues, test.code, test.path) {
				t.Fatalf("unsafe multi-header configuration accepted: report=%+v compiled=%s", report, compiled)
			}
		})
	}
}

func TestRouteAuthContractDefaultsResponseHeaderAndMigratesLegacySnapshot(t *testing.T) {
	t.Parallel()

	document := configurationObject(t)
	compiled, snapshot := routeAuthCompile(t, document, routeAuthTestEnvironment())
	upstream, ok := snapshot.Upstream("primary")
	if !ok || upstream.Timeouts != (UpstreamTimeouts{
		Connect: 5 * time.Second, ResponseHeader: 30 * time.Second,
		FirstByte: 30 * time.Second, Idle: time.Minute, Total: 2 * time.Minute,
	}) {
		t.Fatalf("default upstream timeouts = %+v, ok=%t", upstream.Timeouts, ok)
	}
	compiledRoot := routeAuthDecoded(t, compiled)
	timeouts := objectValue(objectArray(objectValue(compiledRoot, "spec"), "upstreams")[0], "timeouts")
	if stringValue(timeouts, "responseHeader") != "30s" {
		t.Fatalf("compiled response-header default = %#v", timeouts)
	}
	delete(timeouts, "responseHeader")
	legacy, err := newActiveSnapshot(
		"legacy", "environment", routeAuthMarshal(t, document), routeAuthMarshal(t, compiledRoot),
	)
	if err != nil {
		t.Fatalf("load legacy compiled snapshot: %v", err)
	}
	legacyUpstream, ok := legacy.Upstream("primary")
	if !ok || legacyUpstream.Timeouts.ResponseHeader != 30*time.Second ||
		legacyUpstream.Timeouts.FirstByte != time.Minute || legacyUpstream.Timeouts.Idle != time.Minute {
		t.Fatalf("legacy timeout migration = %+v, ok=%t", legacyUpstream.Timeouts, ok)
	}
}

func TestRouteAuthContractRouteTimeoutOverlayIsEffectiveAndCloned(t *testing.T) {
	t.Parallel()

	document := configurationObject(t)
	route := objectArray(objectArray(objectValue(document, "spec"), "features")[0], "routes")[0]
	route["timeouts"] = map[string]any{"firstByte": "45s", "total": "90s"}
	_, snapshot := routeAuthCompile(t, document, routeAuthTestEnvironment())
	feature, ok := snapshot.Feature("assistant")
	want := UpstreamTimeouts{
		Connect: 5 * time.Second, ResponseHeader: 30 * time.Second,
		FirstByte: 45 * time.Second, Idle: time.Minute, Total: 90 * time.Second,
	}
	if !ok || len(feature.Routes) != 1 || feature.Routes[0].Timeouts == nil ||
		*feature.Routes[0].Timeouts != want {
		t.Fatalf("effective route timeout overlay = %+v, ok=%t", feature.Routes, ok)
	}
	feature.Routes[0].Timeouts.Connect = 89 * time.Second
	again, _ := snapshot.Feature("assistant")
	if again.Routes[0].Timeouts == nil || *again.Routes[0].Timeouts != want {
		t.Fatalf("route timeout pointer leaked mutable snapshot state: %+v", again.Routes[0].Timeouts)
	}
}

func TestRouteAuthContractRejectsInvalidEffectiveRouteTimeouts(t *testing.T) {
	t.Parallel()

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for name, overrides := range map[string]map[string]any{
		"inherited stages exceed reduced total": {"total": "20s"},
		"overridden stage exceeds total":        {"firstByte": "3m"},
	} {
		t.Run(name, func(t *testing.T) {
			document := configurationObject(t)
			route := objectArray(objectArray(objectValue(document, "spec"), "features")[0], "routes")[0]
			route["timeouts"] = overrides
			report, compiled := validator.Validate(routeAuthMarshal(t, document), routeAuthTestEnvironment(), time.Now())
			if report.Valid || compiled != nil || !hasIssue(report.Issues, "route_timeout_invalid") {
				t.Fatalf("invalid effective route timeouts compiled: report=%+v compiled=%s", report, compiled)
			}
		})
	}
}

func TestRouteAuthContractEnforcesRouteRequestBoundsAtSchemaAndRuntime(t *testing.T) {
	t.Parallel()

	document := configurationObject(t)
	route := objectArray(objectArray(objectValue(document, "spec"), "features")[0], "routes")[0]
	route["maxRequestBodyBytes"] = json.Number("104857600")
	route["maxRequestHeaderBytes"] = json.Number("32768")
	compiled, snapshot := routeAuthCompile(t, document, routeAuthTestEnvironment())
	feature, ok := snapshot.Feature("assistant")
	if !ok || feature.Routes[0].MaximumRequestBodyBytes != 104857600 ||
		feature.Routes[0].MaximumRequestHeaderBytes != 32768 {
		t.Fatalf("route request bounds = %+v, ok=%t", feature.Routes, ok)
	}

	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string]struct {
		field string
		value json.Number
	}{
		"zero body":     {field: "maxRequestBodyBytes", value: "0"},
		"large body":    {field: "maxRequestBodyBytes", value: "104857601"},
		"zero headers":  {field: "maxRequestHeaderBytes", value: "0"},
		"large headers": {field: "maxRequestHeaderBytes", value: "32769"},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := configurationObject(t)
			invalidRoute := objectArray(objectArray(objectValue(invalid, "spec"), "features")[0], "routes")[0]
			invalidRoute[mutation.field] = mutation.value
			if issues := validator.SchemaIssues(routeAuthMarshal(t, invalid)); len(issues) == 0 {
				t.Fatalf("schema accepted %s=%s", mutation.field, mutation.value)
			}
		})
	}

	for name, mutation := range map[string]struct {
		field string
		value json.Number
	}{
		"runtime body":    {field: "maxRequestBodyBytes", value: "104857601"},
		"runtime headers": {field: "maxRequestHeaderBytes", value: "32769"},
	} {
		t.Run(name, func(t *testing.T) {
			corrupt := routeAuthDecoded(t, compiled)
			corruptRoute := objectArray(objectArray(objectValue(corrupt, "spec"), "features")[0], "routes")[0]
			corruptRoute[mutation.field] = mutation.value
			if _, err := newActiveSnapshot(
				"revision", "environment", routeAuthMarshal(t, document), routeAuthMarshal(t, corrupt),
			); err == nil {
				t.Fatalf("runtime accepted %s=%s", mutation.field, mutation.value)
			}
		})
	}
}

func TestRouteAuthContractCompilesFirstByteTimeoutRetryCondition(t *testing.T) {
	t.Parallel()

	document := configurationObject(t)
	route := objectArray(objectArray(objectValue(document, "spec"), "features")[0], "routes")[0]
	route["fallbackOn"] = []any{"first_byte_timeout"}
	route["retryPolicy"] = map[string]any{
		"maxAttempts": json.Number("2"), "retryOn": []any{"first_byte_timeout"},
	}
	_, snapshot := routeAuthCompile(t, document, routeAuthTestEnvironment())
	feature, ok := snapshot.Feature("assistant")
	if !ok || len(feature.Routes) != 1 || !reflect.DeepEqual(feature.Routes[0].FallbackOn, []string{"first_byte_timeout"}) ||
		feature.Routes[0].RetryPolicy == nil ||
		!reflect.DeepEqual(feature.Routes[0].RetryPolicy.RetryOn, []string{"first_byte_timeout"}) {
		t.Fatalf("first-byte retry contract = %+v, ok=%t", feature.Routes, ok)
	}
}

func routeAuthCompile(
	t *testing.T,
	document map[string]any,
	environment EnvironmentDescriptor,
) (json.RawMessage, ActiveSnapshot) {
	t.Helper()
	validator, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	encoded := routeAuthMarshal(t, document)
	if issues := validator.SchemaIssues(encoded); len(issues) != 0 {
		t.Fatalf("schema rejected route/auth fixture: %+v", issues)
	}
	report, compiled := validator.Validate(encoded, environment, time.Now())
	if !report.Valid || len(compiled) == 0 {
		t.Fatalf("route/auth fixture rejected: %+v", report.Issues)
	}
	snapshot, err := newActiveSnapshot("revision", "environment", encoded, compiled)
	if err != nil {
		t.Fatalf("load route/auth fixture: %v", err)
	}
	return compiled, snapshot
}

func routeAuthTestEnvironment() EnvironmentDescriptor {
	environment := testEnvironment()
	environment.SecretNames = map[string]struct{}{"present": {}, "secondary": {}}
	return environment
}

func routeAuthMarshal(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func routeAuthDecoded(t *testing.T, encoded json.RawMessage) map[string]any {
	t.Helper()
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func routeAuthHasIssueAt(issues []Issue, code, path string) bool {
	for _, issue := range issues {
		if issue.Code == code && (path == "" || issue.Path == path) {
			return true
		}
	}
	return false
}
