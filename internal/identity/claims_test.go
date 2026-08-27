package identity

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDecodeNormalizedClaimsReturnsValidatedDeepCopy(t *testing.T) {
	t.Parallel()

	encoded := []byte(`{"plan":"premium","roles":["member","tester"],"score":42}`)
	first, err := DecodeNormalizedClaims(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first["score"].(json.Number); !ok {
		t.Fatalf("numeric claim lost exact JSON representation: %T", first["score"])
	}
	first["plan"] = "forged"
	first["roles"].([]any)[0] = "owner"
	second, err := DecodeNormalizedClaims(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if second["plan"] != "premium" || second["roles"].([]any)[0] != "member" {
		t.Fatal("decoded normalized claims retained a caller mutation")
	}

	for _, invalid := range [][]byte{
		[]byte(`{"plan":{"raw":"premium"}}`),
		[]byte(`{"Plan":"premium"}`),
		[]byte(`[]`),
	} {
		if _, err := DecodeNormalizedClaims(invalid); !errors.Is(err, ErrCredentialInvalid) {
			t.Fatalf("invalid normalized claims error = %v", err)
		}
	}
}
