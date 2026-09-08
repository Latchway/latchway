package protocol

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestInputAccountingBreakdownRejectsInvalidComponents(t *testing.T) {
	base := InputAccountingBreakdown{Version: 1, RewrittenRequestBytes: 100, FramingUnitCount: 2,
		MaximumFramingTokensPerRequest: 16, MaximumFramingTokensPerUnit: 8, ExpandedSchemaBytes: 268}
	if !base.Validate(400, OpenAIChatID) || !base.Validate(400, OpenAIResponsesID) {
		t.Fatal("valid Chat/Responses breakdown was rejected")
	}
	for _, mutate := range []func(*InputAccountingBreakdown){
		func(v *InputAccountingBreakdown) { v.Version = 2 },
		func(v *InputAccountingBreakdown) { v.RewrittenRequestBytes = 0 },
		func(v *InputAccountingBreakdown) { v.RewrittenRequestBytes = MaximumMeasuredRequestBytes + 1 },
		func(v *InputAccountingBreakdown) { v.FramingUnitCount = 4097 },
		func(v *InputAccountingBreakdown) { v.ExpandedSchemaBytes = -1 },
		func(v *InputAccountingBreakdown) { v.ExpandedSchemaBytes = 4*1024*1024 + 1 },
		func(v *InputAccountingBreakdown) { v.MaximumFramingTokensPerRequest = math.MaxInt64 },
		func(v *InputAccountingBreakdown) { v.MaximumFramingTokensPerUnit = math.MaxInt64 },
	} {
		candidate := base
		mutate(&candidate)
		if candidate.Validate(400, OpenAIChatID) {
			t.Fatalf("invalid aggregate components accepted: %+v", candidate)
		}
	}
	if base.Validate(399, OpenAIChatID) || base.Validate(400, OpenAIEmbeddingsID) || base.Validate(400, AnthropicMessagesID) || base.Validate(400, OpaqueHTTPID) {
		t.Fatal("mismatched bound or unsupported schema protocol accepted")
	}
}

func TestDecodeInputAccountingBreakdownHistoricalAndStrictShape(t *testing.T) {
	base := `{"version":1,"rewritten_request_bytes":100,"framing_unit_count":2,"maximum_framing_tokens_per_request":16,"maximum_framing_tokens_per_unit":8,"expanded_schema_bytes":268}`
	if value, err := DecodeInputAccountingBreakdown(nil, 0, ""); err != nil || value != nil {
		t.Fatal("historical absent breakdown must remain absent")
	}
	decoded, err := DecodeInputAccountingBreakdown([]byte(base), 400, OpenAIChatID)
	if err != nil || decoded == nil || decoded.ExpandedSchemaBytes != 268 {
		t.Fatalf("decode valid breakdown: %+v %v", decoded, err)
	}
	for _, raw := range []string{
		`null`, `[]`, `{}`, base + `{}`,
		strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(base, `"version":1`, `"unknown":1`, 1),
		strings.Replace(base, `"version":1`, `"version":1.0`, 1),
		strings.Replace(base, `"version":1`, `"version":"1"`, 1),
		strings.Replace(base, `"maximum_framing_tokens_per_unit":8`, `"maximum_framing_tokens_per_unit":null`, 1),
		strings.Replace(base, `"expanded_schema_bytes":268`, `"expanded_schema_bytes":267`, 1),
	} {
		if _, err := DecodeInputAccountingBreakdown([]byte(raw), 400, OpenAIChatID); err == nil {
			t.Fatalf("malformed breakdown accepted: %s", raw)
		}
	}
	encoded, err := json.Marshal(decoded)
	if err != nil || string(encoded) != base {
		t.Fatalf("content-free shape changed: %s %v", encoded, err)
	}
}
