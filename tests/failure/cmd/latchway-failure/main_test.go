package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionedFailureMatrixIsStrictAndCoversEveryLiveFaultClass(t *testing.T) {
	path := filepath.Join("..", "..", "matrix.json")
	matrixValue, err := loadMatrix(path)
	if err != nil {
		t.Fatalf("load matrix: %v", err)
	}
	automated := 0
	external := 0
	for _, scenario := range matrixValue.Scenarios {
		switch scenario.Kind {
		case "automated":
			automated++
		case "external":
			external++
		}
	}
	if automated < 9 || external != 6 {
		t.Fatalf("matrix coverage automated=%d external=%d, want at least 9/6", automated, external)
	}
}

func TestExternalEvidenceRequiresDistinctIndexAndExecutedPlatformChild(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	payload := []byte("bounded fault observation\n")
	if err := os.WriteFile(filepath.Join(directory, "observation.log"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	now := time.Now().UTC()
	evidence := externalEvidence{
		SchemaVersion: 1,
		ScenarioID:    "live-process-kill-after-reservation",
		Status:        "passed",
		Commit:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		StartedAt:     now.Add(-time.Minute),
		FinishedAt:    now,
		Environment: map[string]string{
			"image_digest":          "ghcr.io/latchway/latchway@sha256:" + stringOf('b', 64),
			"platform_image_digest": "ghcr.io/latchway/latchway@sha256:" + stringOf('c', 64),
			"platform":              "linux/amd64",
			"postgresql":            "isolated PostgreSQL 18",
			"fault_tool":            "docker kill",
			"operator":              "protected workflow",
		},
		Assertions: []externalAssertion{{Name: "process_sigkill_observed", Passed: true, Detail: "exit 137"}},
		Artifacts:  []externalArtifact{{Path: "observation.log", SHA256: hex.EncodeToString(digest[:])}},
	}
	if err := validateExternalDocument(directory, evidence.ScenarioID, evidence.Commit, evidence); err != nil {
		t.Fatalf("valid index/platform binding rejected: %v", err)
	}
	evidence.Environment["platform_image_digest"] = evidence.Environment["image_digest"]
	if err := validateExternalDocument(directory, evidence.ScenarioID, evidence.Commit, evidence); err == nil {
		t.Fatal("index digest substituted for executed platform child")
	}
	delete(evidence.Environment, "platform_image_digest")
	if err := validateExternalDocument(directory, evidence.ScenarioID, evidence.Commit, evidence); err == nil {
		t.Fatal("missing executed platform child accepted")
	}
}

func stringOf(character byte, count int) string {
	value := make([]byte, count)
	for index := range value {
		value[index] = character
	}
	return string(value)
}

func TestGoTestLogRequiresAConcretePassingTest(t *testing.T) {
	passing := []byte("{\"Action\":\"pass\",\"Test\":\"TestExactGate\"}\n{\"Action\":\"pass\"}\n")
	skipped := []byte("{\"Action\":\"skip\",\"Test\":\"TestExactGate\"}\n{\"Action\":\"pass\"}\n")
	partial := []byte("{\"Action\":\"pass\",\"Test\":\"TestExactGate\"}\n")
	if !goTestLogProvesPass(passing, "TestExactGate") ||
		goTestLogProvesPass(skipped, "TestExactGate") ||
		goTestLogProvesPass(partial, "TestExactGate|TestSecondGate") {
		t.Fatal("go test evidence accepted a skip or rejected a concrete passing test")
	}
}

func TestGoTestEvidenceSeparatesJSONStdoutFromRedactedStderr(t *testing.T) {
	databaseURL := "postgres://user:very-secret-password@127.0.0.1:5432/latchway"
	stdout := []byte("{\"Action\":\"pass\",\"Test\":\"TestExactGate\"}\n")
	stderr := []byte("go: downloading example.invalid/module\ndiagnostic " + databaseURL + " very-secret-password\n")
	log, err := goTestEvidenceLog(stdout, stderr, []string{"LATCHWAY_TEST_DATABASE_URL=" + databaseURL})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(log, []byte(databaseURL)) || bytes.Contains(log, []byte("very-secret-password")) ||
		!bytes.Contains(log, []byte("[REDACTED]")) {
		t.Fatalf("combined evidence was not redaction-safe: %s", log)
	}
	decoder := json.NewDecoder(bytes.NewReader(log))
	for decoded := 0; ; decoded++ {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			if !errors.Is(err, io.EOF) || decoded != 2 {
				t.Fatalf("combined evidence event count = %d: %v", decoded, err)
			}
			break
		}
	}
	if !goTestLogProvesPass(log, "TestExactGate") {
		t.Fatal("leading stderr diagnostics obscured a concrete passing JSON event")
	}
	if _, err := goTestEvidenceLog([]byte("not JSON\n"), stderr, nil); err == nil {
		t.Fatal("malformed go test JSON stdout was ignored")
	}
}

func TestBoundedBufferReportsTruncationWithoutBlockingTheCommand(t *testing.T) {
	buffer := &boundedBuffer{maximum: 4}
	if written, err := buffer.Write([]byte("123456")); err != nil || written != 6 {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	if !buffer.truncated || string(buffer.Bytes()) != "1234" {
		t.Fatalf("bounded buffer = %q truncated=%t", buffer.Bytes(), buffer.truncated)
	}
}
