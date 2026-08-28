package migrations

import (
	"strings"
	"testing"
)

func TestSecretNameContractMigration(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000010_secret_name_contract.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"DROP CONSTRAINT secret_records_name_check",
		"CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$')",
		"COMMENT ON CONSTRAINT secret_records_name_check",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("secret-name migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{"DELETE FROM SECRET_RECORDS", "UPDATE SECRET_RECORDS", "NOT VALID"} {
		if strings.Contains(strings.ToUpper(text), forbidden) {
			t.Errorf("secret-name migration contains unsafe legacy rewrite %q", forbidden)
		}
	}
}
