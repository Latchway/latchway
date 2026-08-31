package protocol

import "testing"

func FuzzOpaqueHTTPPathTemplateMatcherFailsClosed(f *testing.F) {
	f.Add("/v1/users/alice", "/v1/users/{user_id}")
	f.Add("/v1/users/alice/events", "/v1/users/{user_id}")
	f.Add("/v1/%2fprivate", "/v1/{resource_id}")
	f.Add("/v1/users/alice", "/v1/*")

	f.Fuzz(func(t *testing.T, providerPath, template string) {
		matched := OpaqueHTTPPathMatchesTemplate(providerPath, template)
		if matched && (!ValidOpaqueHTTPProviderPath(providerPath) || !ValidOpaqueHTTPPathTemplate(template)) {
			t.Fatalf("invalid path/template matched: path=%q template=%q", providerPath, template)
		}
		if OpaqueHTTPPathTemplatesOverlap(template, providerPath) !=
			OpaqueHTTPPathTemplatesOverlap(providerPath, template) {
			t.Fatalf("template overlap is order-dependent: %q / %q", template, providerPath)
		}
	})
}
