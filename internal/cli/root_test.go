package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := Execute(context.Background(), []string{"--output", "json", "version"}, &stdout, &stderr); err != nil {
		t.Fatalf("Execute() error: %v, stderr: %s", err, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["protocol_version"] != "1" {
		t.Fatalf("protocol_version = %v", result["protocol_version"])
	}
}

func TestRejectsUnknownOutput(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	err := Execute(context.Background(), []string{"--output", "xml", "version"}, &output, &output)
	if err == nil {
		t.Fatal("unsupported output format accepted")
	}
}
