package configuration

import (
	"encoding/json"
	"testing"
)

func FuzzCompiledInputAccountingProfile(f *testing.F) {
	f.Add([]byte(`{"id":"chat_profile","protocol":"openai_chat","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical-fast","maximumFramingTokensPerRequest":8,"maximumFramingTokensPerMessage":4,"maximumContextTokens":128000}`))
	f.Add([]byte(`{"id":"responses_profile","protocol":"openai_responses","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical-fast","maximumFramingTokensPerRequest":8,"maximumFramingTokensPerMessage":4,"maximumContextTokens":128000}`))
	f.Add([]byte(`{"id":"embeddings_profile","protocol":"openai_embeddings","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical-fast","maximumFramingTokensPerRequest":8,"maximumFramingTokensPerMessage":4,"maximumContextTokens":128000}`))
	f.Add([]byte(`{"id":"anthropic_profile","protocol":"anthropic_messages","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical-fast","maximumFramingTokensPerRequest":8,"maximumFramingTokensPerMessage":4,"maximumContextTokens":128000}`))
	f.Add([]byte(`{"id":"chat_profile","protocol":"openai_chat","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical-fast","maximumFramingTokensPerRequest":0.0,"maximumFramingTokensPerMessage":4e0,"maximumContextTokens":9223372036854775807}`))
	f.Add([]byte(`{"id":"chat_profile","protocol":"openai_chat","method":"utf8_byte_bpe_declared_framing_v1","physicalModel":"physical-fast","maximumFramingTokensPerRequest":9223372036854775807,"maximumFramingTokensPerMessage":1,"maximumContextTokens":9223372036854775807}`))
	f.Add([]byte(`{"id":"chat_profile","id":"other","protocol":"openai_chat"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, candidate []byte) {
		if len(candidate) > 64<<10 {
			t.Skip()
		}
		var compiled compiledInputAccountingProfile
		if err := json.Unmarshal(candidate, &compiled); err != nil {
			return
		}
		profile, err := runtimeInputAccountingProfile(compiled)
		if err != nil {
			return
		}
		if profile.ID == "" || !inputAccountingProtocolSupported(profile.Protocol) ||
			profile.Method != inputAccountingMethod || profile.PhysicalModel == "" ||
			profile.MaximumFramingTokensPerRequest < 0 || profile.MaximumFramingTokensPerMessage < 0 ||
			profile.MaximumContextTokens <= 0 || !inputAccountingProfileContextPossible(profile) {
			t.Fatalf("runtime accepted invalid input-accounting profile: %+v", profile)
		}
	})
}
