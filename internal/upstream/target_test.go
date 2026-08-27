package upstream

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestDestinationPolicy(t *testing.T) {
	t.Parallel()

	for _, blocked := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "2001:db8::1"} {
		if (DestinationPolicy{}).allowed(netip.MustParseAddr(blocked)) {
			t.Fatalf("blocked address accepted: %s", blocked)
		}
	}
	if !(DestinationPolicy{}).allowed(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
	allowlisted := DestinationPolicy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}}
	if !allowlisted.allowed(netip.MustParseAddr("10.2.3.4")) || allowlisted.allowed(netip.MustParseAddr("10.3.3.4")) {
		t.Fatal("CIDR allowlist not enforced")
	}
}

func TestResolveRejectsMixedDNSAnswers(t *testing.T) {
	t.Parallel()

	dialer := protectedDialer{
		resolver: staticResolver{"api.example": {netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}},
	}
	if _, err := dialer.resolve(context.Background(), "api.example"); err == nil {
		t.Fatal("mixed public/private DNS answer accepted")
	}
}

func TestTargetResolveURLAndRedirectPolicy(t *testing.T) {
	t.Parallel()

	target, err := NewTarget("https://api.example/base", DestinationPolicy{}, Timeouts{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := target.ResolveURL("/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resolved.String(), "https://api.example/base/v1/chat/completions"; got != want {
		t.Fatalf("resolved URL = %q, want %q", got, want)
	}
	redirectRequest, _ := http.NewRequest(http.MethodGet, "https://other.example", nil)
	if err := target.client.CheckRedirect(redirectRequest, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy error = %v", err)
	}
}

func TestTargetRejectsNonCanonicalRequestPaths(t *testing.T) {
	t.Parallel()

	target, err := NewTarget("https://api.example/base", DestinationPolicy{}, Timeouts{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	for _, requestPath := range []string{
		"",
		"relative/path",
		"/safe/../admin",
		"/safe/./child",
		"/safe//child",
		"/safe/%2e%2e/admin",
		"/safe/%2Fadmin",
		`/safe\admin`,
		"/safe?query=true",
		"/safe#fragment",
		"/safe path",
		`/safe"path`,
		"/safe{path}",
		"/café",
	} {
		if resolved, err := target.ResolveURL(requestPath); err == nil {
			t.Fatalf("non-canonical request path %q resolved to %q", requestPath, resolved)
		}
	}
	resolved, err := target.ResolveURL("/safe/child/")
	if err != nil || resolved.String() != "https://api.example/base/safe/child/" {
		t.Fatalf("canonical trailing slash path: resolved=%v err=%v", resolved, err)
	}
}

func TestTargetRejectsNonCanonicalBaseURLs(t *testing.T) {
	t.Parallel()

	for _, rawBaseURL := range []string{
		"https://api.example/base/../admin",
		"https://api.example/base/./child",
		"https://api.example/base//child",
		"https://api.example/base%2Fchild",
		"https://api.example/base?",
		"https://api.example/base?query=true",
		"https://api.example/base#fragment",
		"https://api.example/base path",
		"https://user:secret@api.example/base",
	} {
		if target, err := NewTarget(rawBaseURL, DestinationPolicy{}, Timeouts{}, staticResolver{}); err == nil {
			t.Fatalf("non-canonical base URL %q accepted: %#v", rawBaseURL, target)
		}
	}
}
