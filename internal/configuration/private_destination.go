package configuration

import (
	"errors"
	"net/netip"

	upstreamtarget "github.com/latchway/latchway/internal/upstream"
)

func configuredPrivateCIDRs(allowPrivate bool, rawCIDRs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, len(rawCIDRs))
	for index, raw := range rawCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.String() != raw || prefix != prefix.Masked() {
			return nil, errors.New("private destination CIDR is not canonical")
		}
		prefixes[index] = prefix
	}
	if err := upstreamtarget.ValidateDestinationPolicy(upstreamtarget.DestinationPolicy{
		AllowPrivate: allowPrivate,
		AllowedCIDRs: prefixes,
	}); err != nil {
		return nil, err
	}
	return prefixes, nil
}
