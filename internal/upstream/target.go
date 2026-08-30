// Package upstream resolves administrator-configured destinations while
// enforcing SSRF and credential-boundary controls.
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// Resolver is the DNS capability used by the protected dialer.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// DestinationPolicy defines the explicit exceptions to default SSRF blocks.
type DestinationPolicy struct {
	AllowPrivate bool
	AllowedCIDRs []netip.Prefix
}

// Timeouts bounds connection setup and response waits. Stream idle and total
// timeouts are enforced by the proxy loop rather than http.Transport.
type Timeouts struct {
	Connect        time.Duration
	TLSHandshake   time.Duration
	ResponseHeader time.Duration
	IdleConnection time.Duration
}

// Target is an immutable, administrator-configured upstream origin.
type Target struct {
	baseURL   *url.URL
	transport *http.Transport
	client    *http.Client
}

// NewTarget validates an origin and constructs a DNS-rebinding-resistant
// transport. Redirects are disabled by the returned client.
func NewTarget(rawBaseURL string, policy DestinationPolicy, timeouts Timeouts, resolver Resolver) (*Target, error) {
	baseURL, err := parseBaseURL(rawBaseURL)
	if err != nil {
		return nil, err
	}
	policy.AllowedCIDRs = append([]netip.Prefix(nil), policy.AllowedCIDRs...)
	if err := validateDestination(baseURL, policy); err != nil {
		return nil, err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeouts.Connect <= 0 {
		timeouts.Connect = 5 * time.Second
	}
	if timeouts.TLSHandshake <= 0 {
		timeouts.TLSHandshake = 5 * time.Second
	}
	if timeouts.ResponseHeader <= 0 {
		timeouts.ResponseHeader = 30 * time.Second
	}
	if timeouts.IdleConnection <= 0 {
		timeouts.IdleConnection = 90 * time.Second
	}

	dialer := &protectedDialer{
		resolver: resolver,
		policy:   policy,
		dialer: net.Dialer{
			Timeout:   timeouts.Connect,
			KeepAlive: 30 * time.Second,
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       timeouts.IdleConnection,
		TLSHandshakeTimeout:   timeouts.TLSHandshake,
		ResponseHeaderTimeout: timeouts.ResponseHeader,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Target{baseURL: baseURL, transport: transport, client: client}, nil
}

// ValidateBaseURL applies the exact URL rules used by NewTarget without
// constructing a transport. Configuration activation uses this to ensure that
// every accepted snapshot can be instantiated by the data plane.
func ValidateBaseURL(rawBaseURL string) error {
	_, err := parseBaseURL(rawBaseURL)
	return err
}

// ValidateDestination applies the complete construction-time URL and private
// network policy checks without constructing a transport or resolving DNS.
// Hostname answers are independently checked by the protected dialer on every
// connection, which keeps this validation safe against DNS rebinding.
func ValidateDestination(rawBaseURL string, policy DestinationPolicy) error {
	baseURL, err := parseBaseURL(rawBaseURL)
	if err != nil {
		return err
	}
	return validateDestination(baseURL, policy)
}

// ValidateDestinationPolicy accepts only explicit, non-overlapping subnets of
// the RFC 1918 IPv4 ranges or the IPv6 unique-local range. An allowlist cannot
// exist independently of the opt-in flag, and the flag cannot be enabled
// without at least one bounded exception.
func ValidateDestinationPolicy(policy DestinationPolicy) error {
	if !policy.AllowPrivate {
		if len(policy.AllowedCIDRs) != 0 {
			return errors.New("private destination CIDRs require the private-network opt-in")
		}
		return nil
	}
	if len(policy.AllowedCIDRs) == 0 || len(policy.AllowedCIDRs) > 32 {
		return errors.New("private-network access requires between one and 32 CIDRs")
	}
	for index, prefix := range policy.AllowedCIDRs {
		if !validPrivateDestinationPrefix(prefix) {
			return fmt.Errorf("private destination CIDR %d is not a canonical RFC 1918 or IPv6 ULA subnet", index)
		}
		for prior := 0; prior < index; prior++ {
			if prefixesOverlap(prefix, policy.AllowedCIDRs[prior]) {
				return fmt.Errorf("private destination CIDRs %d and %d overlap", prior, index)
			}
		}
	}
	return nil
}

func validateDestination(baseURL *url.URL, policy DestinationPolicy) error {
	if err := ValidateDestinationPolicy(policy); err != nil {
		return err
	}
	host := strings.TrimSuffix(baseURL.Hostname(), ".")
	if address, err := netip.ParseAddr(host); err == nil && !policy.allowed(address.Unmap()) {
		return errors.New("upstream address is blocked by destination policy")
	}
	return nil
}

func validPrivateDestinationPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return false
	}
	for _, privateRange := range privateDestinationPrefixes {
		if prefix.Addr().BitLen() == privateRange.Addr().BitLen() &&
			prefix.Bits() >= privateRange.Bits() && privateRange.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func prefixesOverlap(first, second netip.Prefix) bool {
	return first.IsValid() && second.IsValid() &&
		(first.Contains(second.Addr()) || second.Contains(first.Addr()))
}

func parseBaseURL(rawBaseURL string) (*url.URL, error) {
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream base URL: %w", err)
	}
	if err := validateBaseURL(baseURL); err != nil {
		return nil, err
	}
	return baseURL, nil
}

// CloseIdleConnections closes pooled upstream connections.
func (t *Target) CloseIdleConnections() { t.transport.CloseIdleConnections() }

// ResolveURL joins a server-selected path below the configured base path.
func (t *Target) ResolveURL(requestPath string) (*url.URL, error) {
	if !canonicalUpstreamPath(requestPath, false) {
		return nil, errors.New("canonical absolute upstream request path is required")
	}
	resolved := *t.baseURL
	basePath := strings.TrimSuffix(resolved.Path, "/")
	if basePath == "" {
		resolved.Path = requestPath
	} else {
		resolved.Path = basePath + requestPath
	}
	if !canonicalUpstreamPath(resolved.Path, false) {
		return nil, errors.New("resolved upstream path is not canonical")
	}
	resolved.RawPath = ""
	resolved.RawQuery = ""
	resolved.ForceQuery = false
	resolved.Fragment = ""
	return &resolved, nil
}

func validateBaseURL(baseURL *url.URL) error {
	if baseURL == nil || baseURL.Opaque != "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return errors.New("upstream base URL must use HTTP or HTTPS")
	}
	if baseURL.Hostname() == "" || baseURL.User != nil {
		return errors.New("upstream base URL must have a host and no userinfo")
	}
	if baseURL.RawPath != "" || baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" ||
		!canonicalUpstreamPath(baseURL.Path, true) {
		return errors.New("upstream base URL cannot contain query or fragment")
	}
	if port := baseURL.Port(); port != "" {
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			return errors.New("upstream base URL has an invalid port")
		}
	}
	return nil
}

// canonicalUpstreamPath deliberately accepts only an unescaped, normalized
// ASCII path. This prevents a prefix check on one spelling from dispatching a
// different path after dot-segment cleaning or percent-decoding.
func canonicalUpstreamPath(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	if len(value) > 2048 || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\%?#") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] >= 0x7f {
			return false
		}
	}
	if (&url.URL{Path: value}).EscapedPath() != value {
		return false
	}
	canonical := path.Clean(value)
	if strings.HasSuffix(value, "/") && canonical != "/" {
		canonical += "/"
	}
	return canonical == value
}

type protectedDialer struct {
	resolver Resolver
	policy   DestinationPolicy
	dialer   net.Dialer
}

func (d *protectedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse upstream address: %w", err)
	}
	addresses, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, address := range addresses {
		connection, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("connect to approved upstream address: %w", errors.Join(failures...))
}

func (d *protectedDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if !d.policy.allowed(parsed) {
			return nil, errors.New("upstream address is blocked by destination policy")
		}
		return []netip.Addr{parsed}, nil
	}
	resolved, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream host: %w", err)
	}
	if len(resolved) == 0 {
		return nil, errors.New("upstream host resolved to no addresses")
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, resolvedIP := range resolved {
		address := resolvedIP.Unmap()
		if !address.IsValid() {
			return nil, errors.New("upstream host resolved to an invalid address")
		}
		if !d.policy.allowed(address) {
			return nil, errors.New("upstream host resolved to a blocked address")
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func (p DestinationPolicy) allowed(address netip.Addr) bool {
	address = address.Unmap()
	if hardBlockedDestination(address) {
		return false
	}
	if isPublicDestination(address) {
		return true
	}
	if !p.AllowPrivate || !address.IsPrivate() {
		return false
	}
	for _, prefix := range p.AllowedCIDRs {
		if validPrivateDestinationPrefix(prefix) && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func isPublicDestination(address netip.Addr) bool {
	if hardBlockedDestination(address) || address.IsPrivate() {
		return false
	}
	// IsGlobalUnicast also accepts reserved, unallocated IPv6 space. IANA says
	// unlisted portions of 2000::/3 remain reserved for future allocation, so
	// admit only a currently allocated global-unicast prefix. Special-purpose
	// sub-prefixes remain denied by hardBlockedDestination above.
	if address.Is6() {
		allocated := false
		for _, prefix := range allocatedGlobalIPv6Prefixes {
			if prefix.Contains(address) {
				allocated = true
				break
			}
		}
		if !allocated {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

func hardBlockedDestination(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return true
	}
	for _, prefix := range additionalBlockedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var privateDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var additionalBlockedPrefixes = []netip.Prefix{
	// Go's IsGlobalUnicast intentionally describes address shape rather than
	// public routability, so it returns true for portions of these special-use
	// ranges. They must never cross Latchway's default Internet-only boundary.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// Conservatively deny the complete IANA special-purpose blocks, including
	// globally reachable anycast/tunnel assignments: none are valid HTTPS API
	// origins for the gateway's public-Internet destination policy.
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

// allocatedGlobalIPv6Prefixes mirrors the ALLOCATED entries in IANA's IPv6
// Global Unicast Address Space registry as of 2025-10-10. The IANA and 6to4
// special-purpose blocks are deliberately omitted because they are denied
// above even where a more-specific address is globally reachable.
var allocatedGlobalIPv6Prefixes = []netip.Prefix{
	netip.MustParsePrefix("2001:200::/23"),
	netip.MustParsePrefix("2001:400::/23"),
	netip.MustParsePrefix("2001:600::/23"),
	netip.MustParsePrefix("2001:800::/22"),
	netip.MustParsePrefix("2001:c00::/23"),
	netip.MustParsePrefix("2001:e00::/23"),
	netip.MustParsePrefix("2001:1200::/23"),
	netip.MustParsePrefix("2001:1400::/22"),
	netip.MustParsePrefix("2001:1800::/23"),
	netip.MustParsePrefix("2001:1a00::/23"),
	netip.MustParsePrefix("2001:1c00::/22"),
	netip.MustParsePrefix("2001:2000::/19"),
	netip.MustParsePrefix("2001:4000::/23"),
	netip.MustParsePrefix("2001:4200::/23"),
	netip.MustParsePrefix("2001:4400::/23"),
	netip.MustParsePrefix("2001:4600::/23"),
	netip.MustParsePrefix("2001:4800::/23"),
	netip.MustParsePrefix("2001:4a00::/23"),
	netip.MustParsePrefix("2001:4c00::/23"),
	netip.MustParsePrefix("2001:5000::/20"),
	netip.MustParsePrefix("2001:8000::/19"),
	netip.MustParsePrefix("2001:a000::/20"),
	netip.MustParsePrefix("2001:b000::/20"),
	netip.MustParsePrefix("2003::/18"),
	netip.MustParsePrefix("2400::/12"),
	netip.MustParsePrefix("2410::/12"),
	netip.MustParsePrefix("2600::/12"),
	netip.MustParsePrefix("2610::/23"),
	netip.MustParsePrefix("2620::/23"),
	netip.MustParsePrefix("2630::/12"),
	netip.MustParsePrefix("2800::/12"),
	netip.MustParsePrefix("2a00::/12"),
	netip.MustParsePrefix("2a10::/12"),
	netip.MustParsePrefix("2c00::/12"),
}
