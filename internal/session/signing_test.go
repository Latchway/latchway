package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSigningKeyFormattingIsAlwaysRedacted(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	publicJWK := publicJWKFromKey("gsk_formatting-test", &privateKey.PublicKey)
	key := signingKey{material: &signingKeyMaterial{
		kid:       "gsk_formatting-test",
		private:   privateKey,
		notBefore: time.Unix(1_787_820_000, 0).UTC(),
		notAfter:  time.Unix(1_787_906_400, 0).UTC(),
	}}

	formats := []string{"%#v", "%+v", "%v", "%s", "%q", "%x"}
	for _, format := range formats {
		format := format
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			if got := fmt.Sprintf(format, key); got != "[REDACTED]" {
				t.Fatalf("value format %q = %q", format, got)
			}
			if got := fmt.Sprintf(format, &key); got != "[REDACTED]" {
				t.Fatalf("pointer format %q = %q", format, got)
			}
		})
	}

	// fmt treats %p specially and bypasses Formatter. The opaque one-pointer
	// value therefore exposes only an address-shaped diagnostic, never key
	// material or metadata, whether formatted as a value or pointer.
	for label, formatted := range map[string]string{
		"value":   fmt.Sprintf("%p", key),
		"pointer": fmt.Sprintf("%p", &key),
	} {
		for _, sensitive := range []string{key.material.kid, publicJWK.X, publicJWK.Y, key.material.private.D.String()} {
			if sensitive != "" && strings.Contains(formatted, sensitive) {
				t.Fatalf("%%p %s formatting exposed signing-key material: %q", label, formatted)
			}
		}
	}
}
