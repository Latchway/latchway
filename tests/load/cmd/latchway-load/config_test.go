package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testImageHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestExampleConfigIsStrictAndMeetsContractFloor(t *testing.T) {
	path := filepath.Join("..", "..", "config", "v1.example.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeConfig(contents)
	if err != nil {
		t.Fatalf("decode example config: %v", err)
	}
	if cfg.Targets.NonStreamRPS != 100 || cfg.Targets.SSEConcurrency != 500 || cfg.Targets.IdleMemoryMiB != 256 ||
		cfg.Targets.P50Milliseconds != 5 || cfg.Targets.P95Milliseconds != 15 || cfg.Targets.P99Milliseconds != 30 {
		t.Fatalf("example config does not preserve v1 target floor: %+v", cfg.Targets)
	}
	if cfg.Quota.ContentionRequest.Method != "POST" || cfg.NonStream.Method != "POST" || cfg.Stream.Method != "POST" {
		t.Fatal("example request methods are not canonical")
	}
	if err := cfg.validate(filepath.Dir(path)); err == nil {
		t.Fatal("example config placeholders must be replaced before a run")
	}
}

func TestSelectedGatesCannotCallSubsetComplete(t *testing.T) {
	selected, complete, err := selectedGates("preflight,overhead")
	if err != nil || complete || len(selected) != 2 {
		t.Fatalf("subset=%v complete=%t error=%v", selected, complete, err)
	}
	selected, complete, err = selectedGates("all")
	if err != nil || !complete || len(selected) != len(allGateNames) {
		t.Fatalf("all=%v complete=%t error=%v", selected, complete, err)
	}
}

func TestImageEvidenceDistinguishesLocalAndReleaseArtifacts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		metadata  evidenceMetadata
		wantError string
	}{
		{
			name:     "local Docker image ID",
			metadata: evidenceMetadata{LocalDockerImageID: "sha256:" + testImageHash},
		},
		{
			name:     "release OCI reference",
			metadata: evidenceMetadata{ReleaseOCIReference: "ghcr.io/latchway/latchway@sha256:" + testImageHash},
		},
		{
			name:      "local ID in release field",
			metadata:  evidenceMetadata{ReleaseOCIReference: "sha256:" + testImageHash},
			wantError: "fully qualified registry repository",
		},
		{
			name:      "release reference in local field",
			metadata:  evidenceMetadata{LocalDockerImageID: "ghcr.io/latchway/latchway@sha256:" + testImageHash},
			wantError: "local_docker_image_id",
		},
		{
			name: "both evidence forms",
			metadata: evidenceMetadata{
				LocalDockerImageID:  "sha256:" + testImageHash,
				ReleaseOCIReference: "ghcr.io/latchway/latchway@sha256:" + testImageHash,
			},
			wantError: "exactly one",
		},
		{
			name:      "no image evidence",
			metadata:  evidenceMetadata{},
			wantError: "exactly one",
		},
		{
			name:      "mutable release tag",
			metadata:  evidenceMetadata{ReleaseOCIReference: "ghcr.io/latchway/latchway:v1"},
			wantError: "fully qualified registry repository",
		},
		{
			name:      "unqualified release repository",
			metadata:  evidenceMetadata{ReleaseOCIReference: "latchway/latchway@sha256:" + testImageHash},
			wantError: "fully qualified registry repository",
		},
		{
			name:      "uppercase release digest",
			metadata:  evidenceMetadata{ReleaseOCIReference: "ghcr.io/latchway/latchway@sha256:" + strings.ToUpper(testImageHash)},
			wantError: "fully qualified registry repository",
		},
		{
			name:      "tag plus digest",
			metadata:  evidenceMetadata{ReleaseOCIReference: "ghcr.io/latchway/latchway:v1@sha256:" + testImageHash},
			wantError: "fully qualified registry repository",
		},
		{
			name:      "registry URL",
			metadata:  evidenceMetadata{ReleaseOCIReference: "https://ghcr.io/latchway/latchway@sha256:" + testImageHash},
			wantError: "fully qualified registry repository",
		},
		{
			name:      "invalid registry port",
			metadata:  evidenceMetadata{ReleaseOCIReference: "registry.example:70000/latchway/latchway@sha256:" + testImageHash},
			wantError: "fully qualified registry repository",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.metadata.validateImageEvidence()
			if test.wantError == "" && err != nil {
				t.Fatalf("validateImageEvidence() error = %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("validateImageEvidence() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestReportSerializesUnambiguousImageEvidenceField(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(report{Metadata: evidenceMetadata{LocalDockerImageID: "sha256:" + testImageHash}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"local_docker_image_id"`)) ||
		bytes.Contains(encoded, []byte(`"release_oci_reference"`)) ||
		bytes.Contains(encoded, []byte(`"image_digest"`)) {
		t.Fatalf("report image evidence fields are ambiguous: %s", encoded)
	}
}

func TestConfigValidationAcceptsExplicitLocalOrReleaseImageEvidence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		metadata evidenceMetadata
	}{
		{
			name:     "local",
			metadata: evidenceMetadata{LocalDockerImageID: "sha256:" + testImageHash},
		},
		{
			name:     "release",
			metadata: evidenceMetadata{ReleaseOCIReference: "registry.cloudflare.com/0123456789abcdef0123456789abcdef/latchway@sha256:" + testImageHash},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := validTestConfig(t)
			cfg.Metadata = test.metadata
			cfg.Metadata.Deployment = "isolated evidence environment"
			cfg.Metadata.Operator = "load-test-runner"
			if err := cfg.validate(t.TempDir()); err != nil {
				t.Fatalf("validate() error = %v", err)
			}
		})
	}
}

func TestAmbiguousLegacyImageDigestFieldIsRejected(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "config", "v1.example.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(contents, []byte(`"release_oci_reference"`), []byte(`"image_digest"`), 1)
	if _, err := decodeConfig(legacy); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decodeConfig() error = %v, want ambiguous legacy field rejection", err)
	}
}

func validTestConfig(t *testing.T) config {
	t.Helper()
	path := filepath.Join("..", "..", "config", "v1.example.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeConfig(contents)
	if err != nil {
		t.Fatalf("decode example config: %v", err)
	}
	cfg.Environment.Label = "load-test"
	cfg.Environment.PostgreSQL = "PostgreSQL 18.6 on isolated network"
	return cfg
}
