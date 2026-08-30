package upstream

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"testing"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestDestinationPolicy(t *testing.T) {
	t.Parallel()

	for _, blocked := range []string{
		"0.0.0.1", "127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "240.0.0.1", "255.255.255.255",
		"192.31.196.1", "192.52.193.1", "192.88.99.1", "192.175.48.1",
		"::1", "64:ff9b::1", "100::1", "fc00::1", "fec0::1", "2001::1", "2001:db8::1", "2002::1",
		"2620:4f:8000::1", "2d00::1", "3fff::1", "4000::1",
	} {
		if (DestinationPolicy{}).allowed(netip.MustParseAddr(blocked)) {
			t.Fatalf("blocked address accepted: %s", blocked)
		}
	}
	if !(DestinationPolicy{}).allowed(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
	if !(DestinationPolicy{}).allowed(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("allocated public IPv6 address rejected")
	}
	allowlisted := DestinationPolicy{
		AllowPrivate: true,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")},
	}
	if !allowlisted.allowed(netip.MustParseAddr("10.2.3.4")) ||
		allowlisted.allowed(netip.MustParseAddr("10.3.3.4")) ||
		!allowlisted.allowed(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("CIDR allowlist not enforced")
	}
	hardBlockedOverride := DestinationPolicy{
		AllowPrivate: true,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")},
	}
	if hardBlockedOverride.allowed(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("allowlist overrode an unconditional special-use block")
	}
	ipv6MetadataOverride := DestinationPolicy{
		AllowPrivate: true,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("fc00::/7")},
	}
	if ipv6MetadataOverride.allowed(netip.MustParseAddr("fd00:ec2::254")) {
		t.Fatal("allowlist overrode the IPv6 metadata-service block")
	}
}

func TestValidateDestinationPolicy(t *testing.T) {
	t.Parallel()

	valid := []DestinationPolicy{
		{},
		{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.1.2.3/32"),
			netip.MustParsePrefix("172.20.0.0/16"),
			netip.MustParsePrefix("192.168.40.0/24"),
			netip.MustParsePrefix("fd12:3456::/48"),
		}},
	}
	for index, policy := range valid {
		if err := ValidateDestinationPolicy(policy); err != nil {
			t.Fatalf("valid policy %d rejected: %v", index, err)
		}
	}

	tooMany := make([]netip.Prefix, 33)
	for index := range tooMany {
		tooMany[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(index), 1}), 32)
	}
	tests := []struct {
		name   string
		policy DestinationPolicy
	}{
		{name: "opt in without CIDR", policy: DestinationPolicy{AllowPrivate: true}},
		{name: "CIDR without opt in", policy: DestinationPolicy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}},
		{name: "unmasked", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.2.3.4/16")}}},
		{name: "loopback", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}},
		{name: "link local", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}}},
		{name: "metadata", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}}},
		{name: "carrier NAT", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}},
		{name: "documentation", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}},
		{name: "multicast", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4")}}},
		{name: "unspecified", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}}},
		{name: "public", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}}},
		{name: "mapped IPv4", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}}},
		{name: "overlap", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("10.2.3.4/32"),
		}}},
		{name: "too many", policy: DestinationPolicy{AllowPrivate: true, AllowedCIDRs: tooMany}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateDestinationPolicy(test.policy); err == nil {
				t.Fatalf("invalid policy accepted: %#v", test.policy)
			}
		})
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

func TestResolveRejectsEverySpecialUseOrUnallocatedDNSAnswer(t *testing.T) {
	t.Parallel()
	for _, address := range []string{
		"0.0.0.1", "192.31.196.1", "240.0.0.1", "64:ff9b::1", "2001::1", "2002::1",
		"2620:4f:8000::1", "2d00::1", "4000::1",
	} {
		dialer := protectedDialer{resolver: staticResolver{"api.example": {netip.MustParseAddr(address)}}}
		if _, err := dialer.resolve(context.Background(), "api.example"); err == nil {
			t.Fatalf("special-use DNS answer accepted: %s", address)
		}
	}
}

func TestResolveAllowsOnlyExplicitPrivateDNSAnswersAndRechecksEveryLookup(t *testing.T) {
	t.Parallel()

	policy := DestinationPolicy{
		AllowPrivate: true,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
	}
	dialer := protectedDialer{
		resolver: &sequenceResolver{answers: [][]netip.Addr{
			{netip.MustParseAddr("1.1.1.1")},
			{netip.MustParseAddr("10.20.30.40")},
			{netip.MustParseAddr("10.20.31.40")},
		}},
		policy: policy,
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := dialer.resolve(context.Background(), "api.example"); err != nil {
			t.Fatalf("approved lookup %d rejected: %v", attempt, err)
		}
	}
	if _, err := dialer.resolve(context.Background(), "api.example"); err == nil {
		t.Fatal("rebound private DNS answer outside the allowlist was accepted")
	}
}

func TestTargetValidatesLiteralDestinationAgainstPrivateAllowlist(t *testing.T) {
	t.Parallel()

	policy := DestinationPolicy{
		AllowPrivate: true,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.30.40/32")},
	}
	for _, rawURL := range []string{
		"https://10.20.30.40/v1", "https://10.20.30.40./v1",
		"https://1.1.1.1/v1", "https://api.example/v1",
	} {
		if target, err := NewTarget(rawURL, policy, Timeouts{}, staticResolver{}); err != nil || target == nil {
			t.Fatalf("approved target %q rejected: target=%#v err=%v", rawURL, target, err)
		}
	}
	for _, rawURL := range []string{
		"https://10.20.30.41/v1",
		"https://10.20.30.41./v1",
		"https://127.0.0.1/v1",
		"https://169.254.169.254/v1",
		"https://100.64.0.1/v1",
		"https://192.0.2.1/v1",
		"https://[::1]/v1",
		"https://[fe80::1]/v1",
	} {
		if target, err := NewTarget(rawURL, policy, Timeouts{}, staticResolver{}); err == nil || target != nil {
			t.Fatalf("blocked target %q accepted: %#v", rawURL, target)
		}
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

type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	next    int
}

func (resolver *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.next >= len(resolver.answers) {
		return nil, nil
	}
	answer := append([]netip.Addr(nil), resolver.answers[resolver.next]...)
	resolver.next++
	return answer, nil
}
