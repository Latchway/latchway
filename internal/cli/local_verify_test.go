package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/localverify"
)

func TestPrintLocalVerificationFormatsStableEvidence(t *testing.T) {
	t.Parallel()
	report := localverify.Report{Version: 1, Kind: "local", State: "passed", Checks: []localverify.Check{
		{Name: "database_connectivity", State: "passed", Detail: "PostgreSQL accepted a bounded connection."},
	}}
	var jsonOutput bytes.Buffer
	if err := printLocalVerification(&options{output: "json", stdout: &jsonOutput}, report); err != nil {
		t.Fatal(err)
	}
	var decoded localverify.Report
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if decoded.Version != report.Version || decoded.Kind != report.Kind || decoded.State != report.State ||
		len(decoded.Checks) != 1 || decoded.Checks[0] != report.Checks[0] {
		t.Fatalf("JSON report = %+v, want %+v", decoded, report)
	}

	var tableOutput bytes.Buffer
	if err := printLocalVerification(&options{output: "table", stdout: &tableOutput}, report); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"kind: local", "state: passed", "database_connectivity", "PostgreSQL accepted"} {
		if !strings.Contains(tableOutput.String(), fragment) {
			t.Fatalf("table output omitted %q: %s", fragment, tableOutput.String())
		}
	}
}

func TestWriteLocalVerificationJUnitAtomicallyAndPrivately(t *testing.T) {
	t.Parallel()
	report := localverify.Report{Version: 1, Kind: "local", State: "passed", Checks: []localverify.Check{
		{Name: "ephemeral_cleanup", State: "passed", Detail: "The isolated schema was deleted."},
	}}
	want, err := report.MarshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "local-verify.xml")
	if err := writeLocalVerificationJUnit(path, report); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("JUnit output = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("JUnit mode = %#o, want 0600", info.Mode().Perm())
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".local-verify.xml.tmp-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary JUnit files = %v, error = %v", matches, err)
	}
}

func TestVerifyLocalRequiresNamedDatabaseEnvironment(t *testing.T) {
	t.Setenv("LATCHWAY_TEST_EMPTY_DATABASE_URL", "")
	var output bytes.Buffer
	err := Execute(
		context.Background(),
		[]string{"verify", "local", "--database-url-env", "LATCHWAY_TEST_EMPTY_DATABASE_URL"},
		&output,
		&output,
	)
	if err == nil || !strings.Contains(err.Error(), "LATCHWAY_TEST_EMPTY_DATABASE_URL is empty") {
		t.Fatalf("Execute() error = %v", err)
	}
}
