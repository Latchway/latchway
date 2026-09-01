package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/diagnostics"
)

func TestWriteSupportBundleIsExclusivePrivateAndStructurallyRedacted(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "support.json")
	report := diagnostics.Run(context.Background(), nil, "api", diagnostics.Dependencies{})
	bundle := diagnostics.Bundle(report, "local_cli")
	if err := writeSupportBundle(path, bundle); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("support bundle mode = %o, want 600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded diagnostics.SupportBundle
	if err := json.Unmarshal(contents, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Redaction.Mode != "structural_allowlist" || decoded.Source != "local_cli" {
		t.Fatalf("support bundle = %+v", decoded)
	}
	for _, forbidden := range []string{
		"provider-secret-value", "identity-token-value", "request-body-value", "attestation-evidence-value",
	} {
		if strings.Contains(string(contents), forbidden) {
			t.Fatalf("support bundle contained %q", forbidden)
		}
	}
	if err := writeSupportBundle(path, bundle); err == nil {
		t.Fatal("support bundle overwrote an existing file")
	}
}
