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
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return false
	}
	if len(p.AllowedCIDRs) > 0 {
		for _, prefix := range p.AllowedCIDRs {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	if p.AllowPrivate {
		return true
	}
	return isPublicDestination(address)
}

func isPublicDestination(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range additionalBlockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var additionalBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}
