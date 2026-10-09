package adminauth

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	t.Parallel()
	secret := TOTPSecretFromBytes([]byte("12345678901234567890"))
	// RFC 6238 Appendix B SHA-1 values, truncated to six digits.
	for unix, code := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		step, ok := MatchTOTP(secret, code, time.Unix(unix, 0))
		if !ok || step != unix/30 {
			t.Errorf("MatchTOTP(%d, %s) = %d, %v", unix, code, step, ok)
		}
	}
	if _, ok := MatchTOTP(secret, "287082", time.Unix(59+90, 0)); ok {
		t.Error("a code three periods old matched")
	}
	if _, ok := MatchTOTP(secret, "287082", time.Unix(59+30, 0)); !ok {
		t.Error("a code one period old did not match within skew")
	}
	for _, malformed := range []string{"", "28708", "2870822", "28708a", "28 708"} {
		if _, ok := MatchTOTP(secret, malformed, time.Unix(59, 0)); ok {
			t.Errorf("malformed code %q matched", malformed)
		}
	}
}

func TestTOTPSecretEncodingAndRedaction(t *testing.T) {
	t.Parallel()
	secret, err := NewTOTPSecret(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret.Bytes()) != 20 || len(secret.Base32()) != 32 || strings.Contains(secret.Base32(), "=") {
		t.Fatalf("unexpected key encoding %d/%q", len(secret.Bytes()), secret.Base32())
	}
	uri := secret.URI("Latchway (example.test)", "owner@example.test")
	if !strings.HasPrefix(uri, "otpauth://totp/Latchway%20%28example.test%29:owner@example.test?") || !strings.Contains(uri, "secret="+secret.Base32()) {
		t.Fatalf("uri = %s", uri)
	}
	if printed := fmt.Sprintf("%v %+v %s", secret, secret, secret); strings.Contains(printed, secret.Base32()) {
		t.Fatalf("secret leaked through formatting: %s", printed)
	}
}

func TestRecoveryCodes(t *testing.T) {
	t.Parallel()
	codes, err := NewRecoveryCodes(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 14 || strings.Count(code, "-") != 2 || seen[code] {
			t.Fatalf("bad or duplicate recovery code %q", code)
		}
		seen[code] = true
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes", len(codes))
	}
	first := HashRecoveryCode(codes[0])
	if variant := HashRecoveryCode(" " + strings.ToUpper(codes[0]) + " "); !bytes.Equal(first[:], variant[:]) {
		t.Fatal("recovery code hashing is not case and whitespace insensitive")
	}
}
