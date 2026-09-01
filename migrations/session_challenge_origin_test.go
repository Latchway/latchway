package migrations

import (
	"strings"
	"testing"
)

func TestSessionChallengeOriginMigrationInvalidatesUnboundRowsAndPinsScope(t *testing.T) {
	t.Parallel()
	contents, err := Files.ReadFile("000025_session_challenge_origin.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(contents))
	for _, required := range []string{
		"delete from session_challenge_consumptions",
		"delete from session_challenges",
		"add column browser_origin text not null",
		"session_challenges_browser_origin_scope_check",
		"platform = 'web'",
		"platform <> 'web' and browser_origin = ''",
		"char_length(browser_origin) between 9 and 2048",
		"comment on column session_challenges.browser_origin",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("schema-25 migration is missing %q", required)
		}
	}
	if strings.Index(sql, "delete from session_challenges") > strings.Index(sql, "add column browser_origin") {
		t.Fatal("schema-25 made origin mandatory before invalidating unverifiable challenges")
	}
	for _, forbidden := range []string{
		"update session_challenges",
		"drop table session_challenges",
		"drop table attestation_events",
		"default 'https://",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("schema-25 migration contains unsafe inference or destruction %q", forbidden)
		}
	}
}
