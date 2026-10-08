package configuration

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func mergeJSON(t *testing.T, value string) json.RawMessage {
	t.Helper()
	if !json.Valid([]byte(value)) {
		t.Fatalf("invalid fixture %s", value)
	}
	return json.RawMessage(value)
}

func TestThreeWayMergeCombinesIndependentChanges(t *testing.T) {
	t.Parallel()
	base := mergeJSON(t, `{"spec":{"features":[{"id":"chat","plan":"free"},{"id":"summarize","plan":"free"}],"session":{"accessTokenTtl":"10m"}}}`)
	draft := mergeJSON(t, `{"spec":{"features":[{"id":"chat","plan":"paid"},{"id":"summarize","plan":"free"},{"id":"translate","plan":"free"}],"session":{"accessTokenTtl":"10m"}}}`)
	live := mergeJSON(t, `{"spec":{"features":[{"id":"chat","plan":"free"}],"session":{"accessTokenTtl":"15m"}}}`)
	merged, conflicts, err := threeWayMerge(base, draft, live, nil)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("threeWayMerge() conflicts=%v err=%v", conflicts, err)
	}
	want := `{"spec":{"features":[{"id":"chat","plan":"paid"},{"id":"translate","plan":"free"}],"session":{"accessTokenTtl":"15m"}}}`
	if string(merged) != want {
		t.Fatalf("merged = %s\nwant     %s", merged, want)
	}
}

func TestThreeWayMergeReportsAndResolvesConflicts(t *testing.T) {
	t.Parallel()
	base := mergeJSON(t, `{"spec":{"features":[{"id":"chat","plan":"free","model":"a"}],"upstreams":[{"id":"openai","authentication":{"secretRef":"one"}}]}}`)
	draft := mergeJSON(t, `{"spec":{"features":[{"id":"chat","plan":"paid","model":"b"}],"upstreams":[{"id":"openai","authentication":{"secretRef":"two"}}]}}`)
	live := mergeJSON(t, `{"spec":{"features":[{"id":"chat","plan":"team","model":"a"}],"upstreams":[{"id":"openai","authentication":{"secretRef":"three"}}]}}`)
	_, conflicts, err := threeWayMerge(base, draft, live, nil)
	want := []string{"/spec/features/chat/plan", "/spec/upstreams/openai/authentication"}
	if err != nil || !slices.Equal(conflicts, want) {
		t.Fatalf("conflicts=%v err=%v, want %v", conflicts, err, want)
	}
	merged, conflicts, err := threeWayMerge(base, draft, live, map[string]string{
		"/spec/features/chat/plan": MergeTakeLive, "/spec/upstreams/openai/authentication": MergeTakeDraft,
	})
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("resolved conflicts=%v err=%v", conflicts, err)
	}
	if string(merged) != `{"spec":{"features":[{"id":"chat","model":"b","plan":"team"}],"upstreams":[{"authentication":{"secretRef":"two"},"id":"openai"}]}}` {
		t.Fatalf("resolved merge = %s", merged)
	}
	if _, _, err := threeWayMerge(base, draft, live, map[string]string{"/spec/features/chat/model": MergeTakeLive}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resolution for a non-conflicting path error = %v, want ErrInvalid", err)
	}
}

func TestThreeWayMergeKeepsOrderedArraysAtomic(t *testing.T) {
	t.Parallel()
	base := mergeJSON(t, `{"routes":[{"id":"primary"},{"id":"backup"}]}`)
	reordered := mergeJSON(t, `{"routes":[{"id":"backup"},{"id":"primary"}]}`)
	appended := mergeJSON(t, `{"routes":[{"id":"primary"},{"id":"backup"},{"id":"third"}]}`)
	if _, conflicts, err := threeWayMerge(base, reordered, appended, nil); err != nil || !slices.Equal(conflicts, []string{"/routes"}) {
		t.Fatalf("reordered vs appended conflicts=%v err=%v", conflicts, err)
	}
	inserted := mergeJSON(t, `{"routes":[{"id":"first"},{"id":"primary"},{"id":"backup"}]}`)
	if _, conflicts, err := threeWayMerge(base, inserted, appended, nil); err != nil || !slices.Equal(conflicts, []string{"/routes"}) {
		t.Fatalf("inserted vs appended conflicts=%v err=%v", conflicts, err)
	}
	removed := mergeJSON(t, `{"routes":[{"id":"primary"}]}`)
	merged, conflicts, err := threeWayMerge(base, removed, appended, nil)
	if err != nil || len(conflicts) != 0 || string(merged) != `{"routes":[{"id":"primary"},{"id":"third"}]}` {
		t.Fatalf("removed vs appended merged=%s conflicts=%v err=%v", merged, conflicts, err)
	}
}

func TestThreeWayMergeDeleteAgainstChangeConflicts(t *testing.T) {
	t.Parallel()
	base := mergeJSON(t, `{"features":[{"id":"chat","plan":"free"}]}`)
	deleted := mergeJSON(t, `{"features":[]}`)
	changed := mergeJSON(t, `{"features":[{"id":"chat","plan":"paid"}]}`)
	_, conflicts, err := threeWayMerge(base, deleted, changed, nil)
	if err != nil || !slices.Equal(conflicts, []string{"/features/chat"}) {
		t.Fatalf("delete vs change conflicts=%v err=%v", conflicts, err)
	}
	merged, _, err := threeWayMerge(base, deleted, changed, map[string]string{"/features/chat": MergeTakeDraft})
	if err != nil || string(merged) != `{"features":[]}` {
		t.Fatalf("take draft deletion merged=%s err=%v", merged, err)
	}
}

func TestPromoteDocumentKeepsTargetBindings(t *testing.T) {
	t.Parallel()
	source := mergeJSON(t, `{"apiVersion":"latchway.dev/v1","kind":"EnvironmentConfiguration",
		"metadata":{"organization":"acme","application":"mobile","environment":"staging","labels":{"tier":"staging"}},
		"spec":{"features":[{"id":"chat"}],"models":[{"id":"fast"}],
		"upstreams":[{"id":"openai","baseUrl":"https://staging.example"},{"id":"anthropic","baseUrl":"https://api.anthropic.com"}],
		"identityProviders":[{"id":"firebase","projectId":"acme-staging"}]}}`)
	target := mergeJSON(t, `{"apiVersion":"latchway.dev/v1","kind":"EnvironmentConfiguration",
		"metadata":{"organization":"acme","application":"mobile","environment":"production","description":"Production"},
		"spec":{"features":[{"id":"old"}],"upstreams":[{"id":"openai","baseUrl":"https://api.openai.com"},{"id":"internal","baseUrl":"https://llm.internal"}],
		"identityProviders":[{"id":"firebase","projectId":"acme-production"}]}}`)
	environment := EnvironmentDescriptor{OrganizationSlug: "acme", ApplicationSlug: "mobile", EnvironmentSlug: "production"}
	document, report, err := promoteDocument(source, target, environment)
	if err != nil {
		t.Fatal(err)
	}
	var promoted map[string]any
	if err := json.Unmarshal(document, &promoted); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(promoted["spec"])
	if string(encoded) != `{"features":[{"id":"chat"}],"identityProviders":[{"id":"firebase","projectId":"acme-production"}],"models":[{"id":"fast"}],"upstreams":[{"baseUrl":"https://api.openai.com","id":"openai"},{"baseUrl":"https://api.anthropic.com","id":"anthropic"},{"baseUrl":"https://llm.internal","id":"internal"}]}` {
		t.Fatalf("promoted spec = %s", encoded)
	}
	metadata, _ := json.Marshal(promoted["metadata"])
	if string(metadata) != `{"application":"mobile","description":"Production","environment":"production","organization":"acme"}` {
		t.Fatalf("promoted metadata = %s", metadata)
	}
	if !slices.Equal(report.Copied, []string{"/spec/features", "/spec/models"}) ||
		!slices.Equal(report.Kept, []string{"/metadata", "/spec/identityProviders/firebase", "/spec/upstreams/openai", "/spec/upstreams/internal"}) ||
		!slices.Equal(report.Review, []string{"/spec/upstreams/anthropic"}) {
		t.Fatalf("promotion report = %+v", report)
	}

	fresh, freshReport, err := promoteDocument(source, nil, environment)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fresh, &promoted); err != nil {
		t.Fatal(err)
	}
	metadata, _ = json.Marshal(promoted["metadata"])
	if string(metadata) != `{"application":"mobile","environment":"production","labels":{"tier":"staging"},"organization":"acme"}` ||
		!slices.Equal(freshReport.Review, []string{"/spec/identityProviders/firebase", "/spec/upstreams/openai", "/spec/upstreams/anthropic"}) {
		t.Fatalf("fresh promotion metadata=%s report=%+v", metadata, freshReport)
	}
}

func TestValidActivationNote(t *testing.T) {
	t.Parallel()
	for note, valid := range map[string]bool{
		"Raise the free plan to 50k tokens.": true,
		"Line one\nLine two":                 true,
		"   ":                                false,
		"bell\a":                             false,
		"carriage\rreturn":                   false,
	} {
		if ValidActivationNote(note) != valid {
			t.Fatalf("ValidActivationNote(%q) = %t", note, !valid)
		}
	}
	long := make([]rune, 501)
	for index := range long {
		long[index] = 'x'
	}
	if ValidActivationNote(string(long)) {
		t.Fatal("ValidActivationNote accepted 501 characters")
	}
}
