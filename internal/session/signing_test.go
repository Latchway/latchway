package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSigningJWKCodecPreservesStoredFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := publicJWKFromKey("gsk_codec-test", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePublicSigningJWK(encoded)
	if err != nil || decoded != jwk {
		t.Fatalf("stored public JWK changed: %v", err)
	}
	parsed, err := decoded.publicKey()
	if err != nil || !parsed.Equal(&key.PublicKey) {
		t.Fatalf("stored key changed: %v", err)
	}
	for name, invalid := range map[string]string{
		"duplicate":    strings.TrimSuffix(string(encoded), "}") + `,"x":"` + jwk.X + `"}`,
		"private":      strings.TrimSuffix(string(encoded), "}") + `,"d":"forbidden"}`,
		"remote":       strings.TrimSuffix(string(encoded), "}") + `,"jku":"https://attacker.invalid"}`,
		"padded":       strings.Replace(string(encoded), jwk.X, jwk.X+"=", 1),
		"newline":      strings.Replace(string(encoded), jwk.X, jwk.X[:8]+`\n`+jwk.X[8:], 1),
		"algorithm":    strings.Replace(string(encoded), "ES256", "RS256", 1),
		"curve":        strings.Replace(string(encoded), "P-256", "P-384", 1),
		"short key ID": strings.Replace(string(encoded), jwk.Kid, "short", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePublicSigningJWK([]byte(invalid)); !errors.Is(err, ErrSigningKeyUnavailable) {
				t.Fatalf("invalid stored key did not return stable error: %v", err)
			}
		})
	}
}

func TestSigningKeyFormattingIsAlwaysRedacted(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	publicJWK, err := publicJWKFromKey("gsk_formatting-test", &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public signing JWK: %v", err)
	}
	privateScalar, err := privateKey.Bytes()
	if err != nil {
		t.Fatalf("encode private signing key: %v", err)
	}
	defer clear(privateScalar)
	encodedPrivateScalar := base64.RawURLEncoding.EncodeToString(privateScalar)
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
		for _, sensitive := range []string{key.material.kid, publicJWK.X, publicJWK.Y, encodedPrivateScalar} {
			if sensitive != "" && strings.Contains(formatted, sensitive) {
				t.Fatalf("%%p %s formatting exposed signing-key material: %q", label, formatted)
			}
		}
	}
}
