package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/internal/protocol"
)

func TestValidateFixtureURLRequiresExactRFC1918Address(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		value     string
		wantError bool
	}{
		{name: "RFC1918", value: "http://10.239.100.10:19090/v1"},
		{name: "loopback", value: "http://127.0.0.1:19090/v1", wantError: true},
		{name: "apparently public", value: "http://11.239.100.10:19090/v1", wantError: true},
		{name: "hostname", value: "http://fixture:19090/v1", wantError: true},
		{name: "missing port", value: "http://10.239.100.10/v1", wantError: true},
		{name: "wrong path", value: "http://10.239.100.10:19090", wantError: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateFixtureURL(test.value)
			if (err != nil) != test.wantError {
				t.Fatalf("validateFixtureURL() error = %v, wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestLoadConfigurationUsesExactPrivateCIDRAllowlist(t *testing.T) {
	t.Parallel()
	value := loadConfiguration("http://10.239.100.10:19090/v1", "10.239.100.10/32")
	spec := value["spec"].(map[string]any)
	upstreams := spec["upstreams"].([]any)
	upstream := upstreams[0].(map[string]any)
	policy := upstream["destinationPolicy"].(map[string]any)
	if policy["allowPrivateNetworks"] != true || policy["allowRedirects"] != false || policy["dnsPinning"] != true {
		t.Fatalf("unexpected private destination policy: %#v", policy)
	}
	cidrs := policy["allowedCidrs"].([]any)
	if len(cidrs) != 1 || cidrs[0] != "10.239.100.10/32" {
		t.Fatalf("allowed CIDRs = %#v, want exact fixture /32", cidrs)
	}
}

func TestBuildLoadConfigRetainsContractFloors(t *testing.T) {
	t.Parallel()
	value := buildLoadConfig(validLoadOptions(), "http://10.239.100.10:19090/v1")
	targets := value["targets"].(map[string]any)
	if targets["non_stream_rps"] != 100 || targets["sse_concurrency"] != 500 || targets["idle_memory_mib"] != 256 {
		t.Fatalf("load target floors changed: %#v", targets)
	}
	metadata := value["metadata"].(map[string]any)
	if metadata["local_docker_image_id"] == "" || metadata["release_oci_reference"] != nil || metadata["operator"] != "scripts/run-local-load-gates.sh" {
		t.Fatalf("load evidence metadata is incomplete: %#v", metadata)
	}
	environment := value["environment"].(map[string]any)
	if environment["postgresql_cpu_millicores"] != int64(4000) ||
		environment["postgresql_memory_bytes"] != int64(4<<30) ||
		environment["postgresql_memory_swap_bytes"] != int64(4<<30) ||
		environment["postgresql_max_connections"] != 100 ||
		environment["gateway_db_pool_max_connections"] != 32 {
		t.Fatalf("load environment omitted exact PostgreSQL/pool facts: %#v", environment)
	}
}

func TestBuildLoadConfigBindsReleaseIndexAndExecutedPlatformChild(t *testing.T) {
	t.Parallel()
	values := validLoadOptions()
	values.localDockerImageID = ""
	values.releaseOCIReference = "ghcr.io/latchway/latchway@sha256:" + strings.Repeat("a", 64)
	values.releaseOCIPlatformReference = "ghcr.io/latchway/latchway@sha256:" + strings.Repeat("b", 64)
	value := buildLoadConfig(values, "http://10.239.100.10:19090/v1")
	metadata := value["metadata"].(map[string]any)
	if metadata["local_docker_image_id"] != nil ||
		metadata["release_oci_reference"] != values.releaseOCIReference ||
		metadata["release_oci_platform_reference"] != values.releaseOCIPlatformReference ||
		metadata["operator"] != ".github/workflows/release-load-evidence.yml" {
		t.Fatalf("release load metadata is not exact: %#v", metadata)
	}
}

func TestLoadQuotaFixtureMatchesTrustedPreflightAndTerminalArithmetic(t *testing.T) {
	t.Parallel()
	value := buildLoadConfig(validLoadOptions(), "http://10.239.100.10:19090/v1")
	nonStream := value["non_stream_request"].(map[string]any)
	body, err := json.Marshal(nonStream["body"])
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"http://gateway.invalid/v1/chat/completions", bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	adapter := openaichat.Adapter{}
	applied, err := adapter.ApplyFeature(request.Context(), request, protocol.FeatureDecision{
		PhysicalModel: upstreamModel, DefaultOutputTokens: 8, MaximumOutputTokens: 8,
	})
	if err != nil || applied != loadOutputReservation {
		t.Fatalf("ApplyFeature() output=%d error=%v", applied, err)
	}
	preflight, err := adapter.PreflightInput(request.Context(), request, protocol.TrustedInputProfile{
		ID: "fixture-bytes", Protocol: protocol.OpenAIChatID,
		Method:        protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel: upstreamModel, MaximumFramingTokensPerRequest: 8,
		MaximumFramingTokensPerMessage: 4, MaximumContextTokens: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if preflight.InputTokenBound != loadInputReservation ||
		preflight.OutputTokenBound != loadOutputReservation ||
		preflight.TotalTokenBound != loadTotalReservation {
		t.Fatalf("trusted fixture reservation = %+v", preflight)
	}

	quota := value["quota"].(map[string]any)
	facts := quota["fixture"].(map[string]any)
	if facts["input_reservation_per_request"] != preflight.InputTokenBound ||
		facts["output_reservation_per_request"] != preflight.OutputTokenBound ||
		facts["total_reservation_per_request"] != preflight.TotalTokenBound {
		t.Fatalf("recorded fixture bounds do not match trusted preflight: %#v", facts)
	}
	terminal := quota["non_stream_terminal_limits"].([]any)
	if len(terminal) != 4 {
		t.Fatalf("terminal limits = %#v", terminal)
	}
	requestCount := int64(1 + loadOverheadWarmup + loadOverheadSamples +
		loadNonStreamRPS*loadNonStreamDurationSeconds)
	wantUsed := map[string]int64{
		"logical_requests": requestCount,
		"input_tokens":     requestCount * fixtureInputTokens,
		"output_tokens":    requestCount * fixtureOutputTokens,
		"total_tokens":     requestCount * fixtureTotalTokens,
	}
	wantMinimum := map[string]int64{
		"logical_requests": requestCount,
		"input_tokens":     requestCount * loadInputReservation,
		"output_tokens":    requestCount * loadOutputReservation,
		"total_tokens":     requestCount * loadTotalReservation,
	}
	for _, raw := range terminal {
		limit := raw.(map[string]any)
		metric := limit["metric"].(string)
		if limit["maximum"].(int64) < wantMinimum[metric] ||
			limit["used"] != wantUsed[metric] || limit["reserved"] != 0 ||
			limit["remaining"] != limit["maximum"].(int64)-wantUsed[metric] {
			t.Fatalf("terminal %s limit = %#v", metric, limit)
		}
	}
}

func validLoadOptions() options {
	return options{
		gatewayURL:         "http://127.0.0.1:8080",
		localDockerImageID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		postgresIdentity:   "PostgreSQL 18.6 Alpine local image sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		postgresNetwork:    "same isolated bridge 10.239.100.0/24",
		postgresCPUMilli:   4000,
		postgresMemory:     4 << 30,
		postgresMemorySwap: 4 << 30,
		postgresMaxConns:   100,
		gatewayDBPool:      32,
	}
}

func TestValidLocalDockerImageID(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		value     string
		wantValid bool
	}{
		{name: "local ID", value: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", wantValid: true},
		{name: "registry reference", value: "ghcr.io/latchway/latchway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "uppercase digest", value: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "short digest", value: "sha256:aaaa"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validLocalDockerImageID(test.value); got != test.wantValid {
				t.Fatalf("validLocalDockerImageID(%q) = %t, want %t", test.value, got, test.wantValid)
			}
		})
	}
}
