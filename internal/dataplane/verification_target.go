package dataplane

import (
	"errors"
	"net/netip"
	"net/url"
	"sync/atomic"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/upstream"
)

// NewIsolatedVerificationTargetFactory constructs a target factory that keeps
// production configuration public while dispatching only to exact private
// addresses owned by the local verification harness. The replacement map is
// intentionally accepted only by this explicit constructor; the normal server
// runtime always uses TargetCache and can never activate this routing path.
func NewIsolatedVerificationTargetFactory(replacements map[string]string) (TargetFactory, error) {
	if len(replacements) == 0 || len(replacements) > 8 {
		return nil, errors.New("isolated verification target map is invalid")
	}
	copied := make(map[string]string, len(replacements))
	for configured, replacement := range replacements {
		if upstream.ValidateDestination(configured, upstream.DestinationPolicy{}) != nil {
			return nil, errors.New("isolated verification configured target is invalid")
		}
		parsed, err := url.Parse(replacement)
		if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.String() != replacement {
			return nil, errors.New("isolated verification replacement target is invalid")
		}
		address, err := netip.ParseAddr(parsed.Hostname())
		if err != nil || !address.Unmap().IsPrivate() || address.Unmap().IsLoopback() ||
			address.Unmap().IsUnspecified() || address.Unmap().IsMulticast() {
			return nil, errors.New("isolated verification replacement must use an exact private address")
		}
		address = address.Unmap()
		policy := upstream.DestinationPolicy{
			AllowPrivate: true,
			AllowedCIDRs: []netip.Prefix{
				netip.PrefixFrom(address, address.BitLen()),
			},
		}
		if upstream.ValidateDestination(replacement, policy) != nil {
			return nil, errors.New("isolated verification replacement target is invalid")
		}
		copied[configured] = replacement
	}
	return &isolatedVerificationTargetFactory{replacements: copied}, nil
}

type isolatedVerificationTargetFactory struct {
	replacements map[string]string
}

func (factory *isolatedVerificationTargetFactory) Acquire(config configuration.Upstream) (TargetLease, error) {
	if factory == nil {
		return nil, errTargetConfiguration
	}
	if _, err := protectedTargetKey(config); err != nil {
		return nil, err
	}
	replacement, ok := factory.replacements[config.BaseURL]
	if !ok {
		return nil, errTargetConfiguration
	}
	parsed, err := url.Parse(replacement)
	if err != nil {
		return nil, errTargetConfiguration
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil {
		return nil, errTargetConfiguration
	}
	address = address.Unmap()
	target, err := upstream.NewTarget(replacement, upstream.DestinationPolicy{
		AllowPrivate: true,
		AllowedCIDRs: []netip.Prefix{
			netip.PrefixFrom(address, address.BitLen()),
		},
	}, upstream.Timeouts{
		Connect: config.Timeouts.Connect, TLSHandshake: config.Timeouts.Connect,
		ResponseHeader: config.Timeouts.FirstByte, IdleConnection: config.Timeouts.Idle,
	}, nil)
	if err != nil {
		return nil, errTargetConfiguration
	}
	return &isolatedVerificationTargetLease{
		protectedDispatchTarget: &protectedDispatchTarget{target: target},
	}, nil
}

type isolatedVerificationTargetLease struct {
	*protectedDispatchTarget
	released atomic.Bool
}

func (lease *isolatedVerificationTargetLease) Release() {
	if lease == nil || !lease.released.CompareAndSwap(false, true) {
		return
	}
	lease.CloseIdleConnections()
}
