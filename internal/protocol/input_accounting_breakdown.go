package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"

	"github.com/latchway/latchway/internal/jsonsafe"
)

// InputAccountingBreakdown explains an existing trusted input bound without
// changing enforcement or its historical body/profile fingerprint. Version 1
// uses only aggregate sizes and allowances, never prompt or schema contents.
type InputAccountingBreakdown struct {
	Version                        int64 `json:"version"`
	RewrittenRequestBytes          int64 `json:"rewritten_request_bytes"`
	FramingUnitCount               int64 `json:"framing_unit_count"`
	MaximumFramingTokensPerRequest int64 `json:"maximum_framing_tokens_per_request"`
	MaximumFramingTokensPerUnit    int64 `json:"maximum_framing_tokens_per_unit"`
	ExpandedSchemaBytes            int64 `json:"expanded_schema_bytes"`
}

// Validate checks bounded components and an overflow-safe equality with the
// already trusted final bound. It does not establish tokenizer accuracy.
func (value InputAccountingBreakdown) Validate(inputBound int64, protocolID string) bool {
	switch protocolID {
	case OpenAIChatID, OpenAIResponsesID:
	case OpenAIEmbeddingsID, AnthropicMessagesID:
		if value.ExpandedSchemaBytes != 0 {
			return false
		}
	default:
		return false
	}
	if value.Version != 1 || value.RewrittenRequestBytes <= 0 || value.RewrittenRequestBytes > MaximumMeasuredRequestBytes ||
		value.FramingUnitCount <= 0 || value.FramingUnitCount > 4096 ||
		value.ExpandedSchemaBytes < 0 || value.ExpandedSchemaBytes > 4*1024*1024 ||
		value.MaximumFramingTokensPerRequest < 0 || value.MaximumFramingTokensPerUnit < 0 ||
		value.MaximumFramingTokensPerUnit > math.MaxInt64/value.FramingUnitCount {
		return false
	}
	bound := value.RewrittenRequestBytes
	for _, component := range []int64{value.MaximumFramingTokensPerRequest, value.FramingUnitCount * value.MaximumFramingTokensPerUnit, value.ExpandedSchemaBytes} {
		if bound > math.MaxInt64-component {
			return false
		}
		bound += component
	}
	return inputBound == bound
}

// Matches verifies diagnostics against the exact preflight and immutable
// profile. Callers keep enforcing the existing trusted preflight separately.
func (value InputAccountingBreakdown) Matches(profile TrustedInputProfile, preflight TrustedInputPreflight) bool {
	return value.Validate(preflight.InputTokenBound, preflight.Protocol) &&
		value.RewrittenRequestBytes == preflight.RequestBytes && value.FramingUnitCount == preflight.MessageCount &&
		value.ExpandedSchemaBytes == preflight.ExpandedSchemaBytes &&
		value.MaximumFramingTokensPerRequest == profile.MaximumFramingTokensPerRequest &&
		value.MaximumFramingTokensPerUnit == profile.MaximumFramingTokensPerMessage
}

// WithAccountingBreakdown adds validated, content-free diagnostics to a proof.
func (preflight TrustedInputPreflight) WithAccountingBreakdown(profile TrustedInputProfile) (TrustedInputPreflight, error) {
	value := InputAccountingBreakdown{
		Version: 1, RewrittenRequestBytes: preflight.RequestBytes, FramingUnitCount: preflight.MessageCount,
		MaximumFramingTokensPerRequest: profile.MaximumFramingTokensPerRequest,
		MaximumFramingTokensPerUnit:    profile.MaximumFramingTokensPerMessage,
		ExpandedSchemaBytes:            preflight.ExpandedSchemaBytes,
	}
	if !value.Matches(profile, preflight) {
		return TrustedInputPreflight{}, errors.New("invalid input accounting breakdown")
	}
	preflight.Breakdown = &value
	return preflight, nil
}

// DecodeInputAccountingBreakdown accepts SQL NULL for historical attempts and
// otherwise requires the exact versioned shape and coherent aggregate bound.
func DecodeInputAccountingBreakdown(raw []byte, inputBound int64, protocolID string) (*InputAccountingBreakdown, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 2048 {
		return nil, errors.New("input accounting breakdown is too large")
	}
	decoded, err := jsonsafe.Decode(raw)
	object, ok := decoded.(map[string]any)
	if err != nil || !ok || len(object) != 6 {
		return nil, errors.New("invalid input accounting breakdown document")
	}
	for _, field := range []string{"version", "rewritten_request_bytes", "framing_unit_count", "maximum_framing_tokens_per_request", "maximum_framing_tokens_per_unit", "expanded_schema_bytes"} {
		if _, ok := object[field].(json.Number); !ok {
			return nil, errors.New("input accounting breakdown requires integer components")
		}
	}
	var value InputAccountingBreakdown
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || !value.Validate(inputBound, protocolID) {
		return nil, errors.New("invalid input accounting breakdown values")
	}
	return &value, nil
}
