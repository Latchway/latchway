package attestation

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestParseDebugPublicKeysAcceptsStrictVersionedDocument(t *testing.T) {
	publicKey, _ := deterministicDebugKey()
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	document := []byte(`{"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"` + encoded + `"}]}`)

	keys, err := ParseDebugPublicKeys(document)
	if err != nil {
		t.Fatalf("parse debug public keys: %v", err)
	}
	if len(keys) != 1 || !bytes.Equal(keys["fixture-key-01"], publicKey) {
		t.Fatalf("parsed keys = %#v", keys)
	}
	keys["fixture-key-01"][0] ^= 0xff
	if bytes.Equal(keys["fixture-key-01"], publicKey) {
		t.Fatal("parsed key aliases the caller's source key")
	}
}

func TestParseDebugPublicKeysRejectsAmbiguousOrUnsafeDocuments(t *testing.T) {
	publicKey, privateKey := deterministicDebugKey()
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	privateEncoded := base64.RawURLEncoding.EncodeToString(privateKey)
	tests := []struct {
		name     string
		document string
	}{
		{name: "empty", document: ""},
		{name: "array root", document: `[]`},
		{name: "unknown root member", document: `{"version":1,"keys":[],"trusted":true}`},
		{name: "wrong version", document: `{"version":2,"keys":[]}`},
		{name: "fractional version", document: `{"version":1.0,"keys":[]}`},
		{name: "empty key set", document: `{"version":1,"keys":[]}`},
		{name: "unknown key member", document: `{"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"` + encoded + `","trusted":true}]}`},
		{name: "short key ID", document: `{"version":1,"keys":[{"key_id":"short","public_key":"` + encoded + `"}]}`},
		{name: "padded public key", document: `{"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"` + base64.URLEncoding.EncodeToString(publicKey) + `"}]}`},
		{name: "private key", document: `{"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"` + privateEncoded + `"}]}`},
		{name: "duplicate key ID", document: `{"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"` + encoded + `"},{"key_id":"fixture-key-01","public_key":"` + encoded + `"}]}`},
		{name: "duplicate JSON member", document: `{"version":1,"version":1,"keys":[{"key_id":"fixture-key-01","public_key":"` + encoded + `"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseDebugPublicKeys([]byte(test.document)); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	oversized := bytes.Repeat([]byte{'x'}, maxDebugPublicKeySetBytes+1)
	if _, err := ParseDebugPublicKeys(oversized); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("oversized document error = %v", err)
	}
}
