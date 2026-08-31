package protocol

import "testing"

func TestOpaqueHTTPPathTemplatesAreCanonicalExactDepthMatchers(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{
		"/v1/weather/current",
		"/v1/users/{user_id}",
		"/v1/users/{user_id}/events/{event_id}",
		"/v1/users/{user_id}/",
	} {
		if !ValidOpaqueHTTPPathTemplate(valid) {
			t.Errorf("valid template %q rejected", valid)
		}
	}
	for _, invalid := range []string{
		"", "/", "v1/{id}", "/v1//{id}", "/v1/../private", "/v1/%2fprivate",
		"/v1/{ID}", "/v1/{id-name}", "/v1/pre-{id}", "/v1/{id}/post-{name}",
		"/v1/{id}/{id}", "/v1/*", "/v1/{rest...}", "/v1/{id}?admin=true",
		"https://provider.example/v1/{id}",
	} {
		if ValidOpaqueHTTPPathTemplate(invalid) {
			t.Errorf("unsafe template %q accepted", invalid)
		}
	}

	tests := []struct {
		path     string
		template string
		matches  bool
	}{
		{path: "/v1/users/alice", template: "/v1/users/{user_id}", matches: true},
		{path: "/v1/users/me", template: "/v1/users/{user_id}", matches: true},
		{path: "/v1/users/alice/events/evt_1", template: "/v1/users/{user_id}/events/{event_id}", matches: true},
		{path: "/v1/users/alice/events", template: "/v1/users/{user_id}", matches: false},
		{path: "/v1/users/alice/", template: "/v1/users/{user_id}", matches: false},
		{path: "/v1/users/alice/", template: "/v1/users/{user_id}/", matches: true},
		{path: "/v1/users/%2e%2e", template: "/v1/users/{user_id}", matches: false},
		{path: "/v1/users/alice?admin=true", template: "/v1/users/{user_id}", matches: false},
	}
	for _, test := range tests {
		if got := OpaqueHTTPPathMatchesTemplate(test.path, test.template); got != test.matches {
			t.Errorf("OpaqueHTTPPathMatchesTemplate(%q, %q) = %t, want %t", test.path, test.template, got, test.matches)
		}
	}
}

func TestOpaqueHTTPPathTemplateOverlapRejectsAmbiguousCaptures(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		left, right string
		overlap     bool
	}{
		{left: "/v1/users/{id}", right: "/v1/users/{name}", overlap: true},
		{left: "/v1/users/{id}", right: "/v1/users/me", overlap: true},
		{left: "/v1/{kind}/{id}", right: "/v1/users/{name}", overlap: true},
		{left: "/v1/users/{id}", right: "/v1/groups/{id}", overlap: false},
		{left: "/v1/users/{id}", right: "/v1/users/{id}/events", overlap: false},
		{left: "/v1/users/{id}", right: "/v1/users/{id}/", overlap: false},
	} {
		if got := OpaqueHTTPPathTemplatesOverlap(test.left, test.right); got != test.overlap {
			t.Errorf("OpaqueHTTPPathTemplatesOverlap(%q, %q) = %t, want %t", test.left, test.right, got, test.overlap)
		}
	}
	if !ValidOpaqueHTTPPathTemplates([]string{
		"/v1/users/{id}", "/v1/groups/{id}", "/v1/users/{id}/events",
	}) {
		t.Fatal("disjoint template set rejected")
	}
	for _, invalid := range [][]string{
		nil,
		{"/v1/users/{id}", "/v1/users/{name}"},
		{"/v1/users/{id}", "/v1/users/me"},
		{"/v1/users/{id}", "/v1/users/{id}"},
	} {
		if ValidOpaqueHTTPPathTemplates(invalid) {
			t.Fatalf("ambiguous template set accepted: %#v", invalid)
		}
	}
}
