// Package openaiusage implements shared, bounded parsing of optional fields in
// final OpenAI-compatible usage objects.
package openaiusage

import (
	"encoding/json"

	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/protocol"
)

// ReportedCost extracts usage.cost as an exact USD amount in integer
// nano-USD. Missing, invalid, sub-nano, negative, and overflowing values are
// data, not protocol failures: the selected upstream policy decides whether
// omission or invalidity must force conservative unknown-cost settlement.
// cost_details is deliberately not summed or treated as authoritative.
func ReportedCost(usage map[string]any) protocol.ProviderReportedCost {
	value, present := usage["cost"]
	if !present {
		return protocol.ProviderReportedCost{}
	}
	result := protocol.ProviderReportedCost{Present: true}
	number, ok := value.(json.Number)
	if !ok {
		return result
	}
	nanoUSD, err := pricing.ParseUSDDecimalNanoUSD(number.String())
	if err != nil {
		return result
	}
	result.NanoUSD = nanoUSD
	result.Known = true
	return result
}
