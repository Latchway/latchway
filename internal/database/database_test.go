package database

import "testing"

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
