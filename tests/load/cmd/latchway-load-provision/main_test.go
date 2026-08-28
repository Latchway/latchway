package main

import (
	"testing"
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
	value := buildLoadConfig(options{
		gatewayURL:         "http://127.0.0.1:8080",
		localDockerImageID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "http://10.239.100.10:19090/v1")
	targets := value["targets"].(map[string]any)
	if targets["non_stream_rps"] != 100 || targets["sse_concurrency"] != 500 || targets["idle_memory_mib"] != 256 {
		t.Fatalf("load target floors changed: %#v", targets)
	}
	metadata := value["metadata"].(map[string]any)
	if metadata["local_docker_image_id"] == "" || metadata["release_oci_reference"] != nil || metadata["operator"] != "scripts/run-local-load-gates.sh" {
		t.Fatalf("load evidence metadata is incomplete: %#v", metadata)
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
