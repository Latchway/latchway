package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeConfigurationDocumentAcceptsBoundedYAMLAndJSON(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"yaml": "apiVersion: latchway.dev/v1alpha1\nkind: EnvironmentConfig\nspec:\n  limits:\n    - maximum: 12\n      enabled: true\n",
		"json": `{"apiVersion":"latchway.dev/v1alpha1","kind":"EnvironmentConfig","spec":{"limits":[{"maximum":12,"enabled":true}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			document, err := decodeConfigurationDocument(strings.NewReader(input), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(encoded), `"maximum":12`) || !strings.Contains(string(encoded), `"enabled":true`) {
				t.Fatalf("decoded configuration = %s", encoded)
			}
		})
	}
}

func TestDecodeConfigurationDocumentRejectsUnsafeYAMLBeforeNetwork(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"duplicate":      "kind: EnvironmentConfig\nkind: Other\n",
		"alias":          "defaults: &defaults\n  enabled: true\nspec: *defaults\n",
		"custom tag":     "kind: !unsafe EnvironmentConfig\n",
		"timestamp":      "created: 2026-09-01T00:00:00Z\n",
		"merge key":      "defaults: &defaults {enabled: true}\nspec:\n  <<: *defaults\n",
		"multiple docs":  "kind: EnvironmentConfig\n---\nkind: Other\n",
		"non-string key": "1: value\n",
		"non-finite":     "value: .inf\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfigurationDocument(strings.NewReader(input), 1<<20); err == nil {
				t.Fatalf("unsafe YAML accepted: %s", input)
			}
		})
	}
	if _, err := decodeConfigurationDocument(strings.NewReader(strings.Repeat("x", 33)), 32); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

func TestEncodeConfigurationYAMLIsStableAndRoundTripsTypes(t *testing.T) {
	t.Parallel()

	document := map[string]any{
		"spec": map[string]any{"enabled": true, "maximum": json.Number("12"), "nothing": nil},
		"kind": "EnvironmentConfig",
	}
	first, err := encodeConfigurationYAML(document)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeConfigurationYAML(document)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || strings.Index(string(first), "kind:") > strings.Index(string(first), "spec:") {
		t.Fatalf("configuration YAML is not stable:\n%s", first)
	}
	decoded, err := decodeConfigurationDocument(strings.NewReader(string(first)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"maximum":12`) || !strings.Contains(string(encoded), `"enabled":true`) {
		t.Fatalf("round-tripped configuration = %s", encoded)
	}
}

func TestConfigurationDocumentPreservesExactNumbers(t *testing.T) {
	t.Parallel()

	const exact = "0.12345678901234567890123456789"
	document, err := decodeConfigurationDocument(strings.NewReader("value: "+exact+"\n"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := document["value"].(json.Number)
	if !ok || value.String() != exact {
		t.Fatalf("exact YAML number = %T(%v)", document["value"], document["value"])
	}
	encoded, err := encodeConfigurationYAML(document)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "value: "+exact+"\n" {
		t.Fatalf("exact YAML output = %q", encoded)
	}
}

func TestConfigPullExportsRedactionSafeYAMLThroughCanonicalAPI(t *testing.T) {
	token := strings.Repeat("configuration-export-token-", 2)
	t.Setenv("TEST_LATCHWAY_CONFIG_EXPORT_TOKEN", token)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/admin/v1/environments/"+controlTestEnvironment+"/config" ||
			request.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("configuration export request = %s %s", request.Method, request.URL.Path)
		}
		return controlHTTPResponse(request, http.StatusOK, revisionJSON("active"), http.Header{"ETag": []string{`"active-etag"`}}), nil
	})}
	var output bytes.Buffer
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "config", "pull",
		"--environment", controlTestEnvironment, "--format", "yaml",
		"--api-token-env", "TEST_LATCHWAY_CONFIG_EXPORT_TOKEN",
	}, &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != "apiVersion: latchway.dev/v1alpha1\n" || strings.Contains(output.String(), token) {
		t.Fatalf("configuration YAML output = %q", output.String())
	}

	requests := 0
	invalidClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return nil, nil
	})}
	err = executeWithOptions(context.Background(), []string{
		"config", "pull", "--environment", controlTestEnvironment, "--format", "toml",
		"--api-token-env", "TEST_LATCHWAY_CONFIG_EXPORT_TOKEN",
	}, &options{output: "table", stdout: io.Discard, stderr: io.Discard, adminHTTPClient: invalidClient})
	if err == nil || requests != 0 {
		t.Fatalf("invalid format error=%v requests=%d", err, requests)
	}
}

func TestConfigPullJSONPreservesIntegerPrecision(t *testing.T) {
	token := strings.Repeat("configuration-json-export-token-", 2)
	t.Setenv("TEST_LATCHWAY_CONFIG_JSON_EXPORT_TOKEN", token)
	body := strings.Replace(
		revisionJSON("active"),
		`"apiVersion":"latchway.dev/v1alpha1"`,
		`"apiVersion":"latchway.dev/v1alpha1","maximum":9223372036854775807`,
		1,
	)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return controlHTTPResponse(request, http.StatusOK, body, http.Header{"ETag": []string{`"active-etag"`}}), nil
	})}
	var output bytes.Buffer
	err := executeWithOptions(context.Background(), []string{
		"--server", "http://127.0.0.1:8080", "config", "pull",
		"--environment", controlTestEnvironment, "--format", "json",
		"--api-token-env", "TEST_LATCHWAY_CONFIG_JSON_EXPORT_TOKEN",
	}, &options{output: "table", stdout: &output, stderr: io.Discard, adminHTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"maximum": 9223372036854775807`) || strings.Contains(output.String(), token) {
		t.Fatalf("configuration JSON output = %q", output.String())
	}
}
