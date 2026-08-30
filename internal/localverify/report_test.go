package localverify

import (
	"bytes"
	"testing"
)

func TestMarshalJUnitIsDeterministicAndCountsOutcomes(t *testing.T) {
	t.Parallel()
	report := Report{Version: 1, Kind: "local", State: "failed", Checks: []Check{
		{Name: "database_connectivity", State: "passed", Detail: "PostgreSQL accepted a bounded connection."},
		{Name: "streaming", State: "failed", Detail: "The SSE response was invalid."},
		{Name: "cleanup", State: "skipped", Detail: "Setup did not complete."},
	}}
	first, err := report.MarshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	second, err := report.MarshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("JUnit output changed between identical reports")
	}
	for _, fragment := range [][]byte{
		[]byte(`tests="3"`), []byte(`failures="1"`), []byte(`skipped="1"`),
		[]byte(`name="streaming"`), []byte(`The SSE response was invalid.`),
	} {
		if !bytes.Contains(first, fragment) {
			t.Fatalf("JUnit output omitted %q: %s", fragment, first)
		}
	}
}

func TestReportErrorTracksFailures(t *testing.T) {
	t.Parallel()
	report := newReport()
	report.add("database_connectivity", "passed", "ok")
	if err := report.Error(); err != nil {
		t.Fatalf("passing report error = %v", err)
	}
	report.add("migrations", "failed", "failed")
	if err := report.Error(); err == nil {
		t.Fatal("failed report returned nil error")
	}
}
