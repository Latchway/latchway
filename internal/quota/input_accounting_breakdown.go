package quota

import "encoding/json"

// The optional breakdown is diagnostic metadata. The existing proof remains
// authoritative and keeps its historical fingerprint serialization unchanged.
func inputAccountingBreakdownJSON(binding *InputPreflightBinding) ([]byte, error) {
	if binding == nil || binding.Breakdown == nil {
		return nil, nil
	}
	if !binding.Breakdown.Validate(binding.InputTokenBound, binding.Protocol) {
		return nil, ErrInvalidInput
	}
	return json.Marshal(binding.Breakdown)
}
