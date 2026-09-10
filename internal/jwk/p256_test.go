package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestParseP256Conformance(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(encoded[1:33])
	y := base64.RawURLEncoding.EncodeToString(encoded[33:])
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	one := base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 1))
	// With 32 bytes, the final alphabet index has two unused bits. Flipping
	// one of those bits must not introduce an alternative spelling of a key.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lastIndex := strings.IndexByte(alphabet, x[len(x)-1])
	noncanonical := x[:len(x)-1] + string(alphabet[lastIndex|1])
	tests := []struct {
		name, x, y string
		valid      bool
	}{
		{"valid", x, y, true},
		{"empty x", "", y, false},
		{"empty y", x, "", false},
		{"padded", x + "=", y, false},
		{"newline", x[:8] + "\n" + x[8:], y, false},
		{"carriage return", x, y[:8] + "\r" + y[8:], false},
		{"trailing bits", noncanonical, y, false},
		{"31 bytes", base64.RawURLEncoding.EncodeToString(encoded[2:33]), y, false},
		{"33 bytes", base64.RawURLEncoding.EncodeToString(encoded[:33]), y, false},
		{"zero x", zero, y, false},
		{"zero y", x, zero, false},
		{"off curve", one, one, false},
		{"oversized", strings.Repeat("A", 4096), y, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseP256(test.x, test.y)
			legacy, legacyErr := legacyParseP256(test.x, test.y)
			if (err == nil) != test.valid || (err == nil) != (legacyErr == nil) {
				t.Fatalf("acceptance mismatch: new=%v previous=%v valid=%t", err, legacyErr, test.valid)
			}
			if err == nil && (!got.Equal(legacy) || !got.Equal(&key.PublicKey)) {
				t.Fatal("public key changed")
			}
		})
	}
}

func FuzzParseP256Compatibility(f *testing.F) {
	// P-256 generator coordinates are public, deterministic test material.
	f.Add("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY", "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU")
	f.Add("", "")
	f.Add(strings.Repeat("A", 43), strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, x, y string) {
		if len(x) > 4096 || len(y) > 4096 {
			t.Skip()
		}
		current, currentErr := ParseP256(x, y)
		previous, previousErr := legacyParseP256(x, y)
		if (currentErr == nil) != (previousErr == nil) {
			t.Fatalf("acceptance changed: new=%v previous=%v", currentErr, previousErr)
		}
		if currentErr == nil && !current.Equal(previous) {
			t.Fatal("public key changed")
		}
	})
}

// This is the prior DPoP coordinate decoder, retained only as an independent
// differential oracle. Its accepted set matched the prior signing-key decoder.
func legacyParseP256(x, y string) (*ecdsa.PublicKey, error) {
	coordinates := make([][]byte, 2)
	var zero [32]byte
	for index, text := range []string{x, y} {
		decoded, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != text ||
			subtle.ConstantTimeCompare(decoded, zero[:]) == 1 {
			return nil, errors.New("invalid")
		}
		coordinates[index] = decoded
	}
	encoded := append([]byte{4}, coordinates[0]...)
	encoded = append(encoded, coordinates[1]...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
}
