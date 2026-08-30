package database

import (
	"context"
	"strings"
	"testing"
)

func TestMigrationEntries(t *testing.T) {
	t.Parallel()

	entries, err := migrationEntries()
	if err != nil {
		t.Fatalf("migrationEntries() error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].version >= entries[i].version {
			t.Fatalf("migrations not strictly ordered: %+v", entries)
		}
	}
}

func TestOpenInSchemaRejectsUnsafeNamesBeforeParsingOrConnecting(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{"", "public,attacker", "MixedCase", "../public", strings.Repeat("a", 64)} {
		if _, err := OpenInSchema(context.Background(), "not a database URL", schema, 2); err == nil ||
			!strings.Contains(err.Error(), "schema name") {
			t.Fatalf("OpenInSchema(%q) error = %v, want schema-name rejection", schema, err)
		}
	}
}
