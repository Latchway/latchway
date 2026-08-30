package protocol

import (
	"encoding/hex"
	"testing"
)

func TestTrustedInputProfileDigestBindsEveryFieldDeterministically(t *testing.T) {
	t.Parallel()

	profile := TrustedInputProfile{
		ID:                             "gpt_5_chat",
		Protocol:                       "openai_chat",
		Method:                         TrustedInputMethodUTF8ByteBPEDeclaredFramingV1,
		PhysicalModel:                  "gpt-5.1",
		MaximumFramingTokensPerRequest: 9,
		MaximumFramingTokensPerMessage: 4,
		MaximumContextTokens:           131_072,
	}
	first := profile.Digest()
	second := profile.Digest()
	if first != second {
		t.Fatal("identical trusted input profiles produced different digests")
	}
	const wantHex = "8470d8c593dcde211cbbb7370e0cda80c15c1c21a2226dde2a78f2bf600fd84a"
	if got := hex.EncodeToString(first[:]); got != wantHex {
		t.Fatalf("trusted input profile digest = %s, want %s", got, wantHex)
	}

	tests := []struct {
		name   string
		mutate func(*TrustedInputProfile)
	}{
		{name: "id", mutate: func(value *TrustedInputProfile) { value.ID += "_other" }},
		{name: "protocol", mutate: func(value *TrustedInputProfile) { value.Protocol += "_other" }},
		{name: "method", mutate: func(value *TrustedInputProfile) { value.Method += "_other" }},
		{name: "physical model", mutate: func(value *TrustedInputProfile) { value.PhysicalModel += "-other" }},
		{name: "request framing", mutate: func(value *TrustedInputProfile) { value.MaximumFramingTokensPerRequest++ }},
		{name: "message framing", mutate: func(value *TrustedInputProfile) { value.MaximumFramingTokensPerMessage++ }},
		{name: "context", mutate: func(value *TrustedInputProfile) { value.MaximumContextTokens++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := profile
			test.mutate(&changed)
			if changed.Digest() == first {
				t.Fatalf("%s was omitted from the profile digest", test.name)
			}
		})
	}
}
