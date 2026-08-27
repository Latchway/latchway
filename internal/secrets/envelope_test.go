package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestEnvironmentMasterKeyRoundTrip(t *testing.T) {
	t.Parallel()

	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x4f}, 32))
	provider, err := NewEnvironmentMasterKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	aad := AssociatedData{
		OrganizationID: "org_example",
		EnvironmentID:  "env_example",
		SecretID:       "sec_example",
		SecretVersion:  1,
	}
	plaintext := []byte("provider credential")
	first, err := provider.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) || bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("secret encryption reused nonce or ciphertext")
	}
	decrypted, err := provider.Decrypt(first, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted plaintext differs")
	}
}

func TestEnvironmentMasterKeyRejectsTampering(t *testing.T) {
	t.Parallel()

	encoded := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x8a}, 32))
	provider, err := NewEnvironmentMasterKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	aad := AssociatedData{OrganizationID: "org_a", EnvironmentID: "env_a", SecretID: "sec_a", SecretVersion: 1}
	envelope, err := provider.Encrypt([]byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("ciphertext", func(t *testing.T) {
		tampered := envelope
		tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
		tampered.Ciphertext[0] ^= 0xff
		if _, err := provider.Decrypt(tampered, aad); err == nil {
			t.Fatal("tampered ciphertext authenticated")
		}
	})

	t.Run("associated data", func(t *testing.T) {
		wrongAAD := aad
		wrongAAD.EnvironmentID = "env_b"
		if _, err := provider.Decrypt(envelope, wrongAAD); err == nil {
			t.Fatal("wrong associated data authenticated")
		}
	})
}

func TestEnvironmentMasterKeyRejectsInvalidLength(t *testing.T) {
	t.Parallel()

	if _, err := NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("short master key accepted")
	}
}

func TestIdentitySubjectHMACKeyIsDeterministicSeparatedAndCleared(t *testing.T) {
	t.Parallel()

	rawMasterKey := bytes.Repeat([]byte{0x93}, 32)
	encoded := base64.StdEncoding.EncodeToString(rawMasterKey)
	first, err := NewEnvironmentMasterKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEnvironmentMasterKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	var firstRetained, secondRetained []byte
	var firstCopy, secondCopy []byte
	if err := first.UseIdentitySubjectHMACKey(func(key []byte) error {
		firstRetained = key
		firstCopy = append([]byte(nil), key...)
		return nil
	}); err != nil {
		t.Fatalf("derive first identity key: %v", err)
	}
	if err := second.UseIdentitySubjectHMACKey(func(key []byte) error {
		secondRetained = key
		secondCopy = append([]byte(nil), key...)
		return nil
	}); err != nil {
		t.Fatalf("derive second identity key: %v", err)
	}
	if len(firstCopy) != 32 || !bytes.Equal(firstCopy, secondCopy) {
		t.Fatalf("identity derivation is not deterministic: first=%x second=%x", firstCopy, secondCopy)
	}
	if bytes.Equal(firstCopy, rawMasterKey) || bytes.Equal(firstCopy, first.derivationRoot[:]) {
		t.Fatal("identity key was not separated from the raw or root derivation key")
	}
	var otherDomain []byte
	if err := first.useDerivedKey("latchway/test/other-domain/v1", func(key []byte) error {
		otherDomain = append([]byte(nil), key...)
		return nil
	}); err != nil {
		t.Fatalf("derive other-domain key: %v", err)
	}
	if bytes.Equal(firstCopy, otherDomain) {
		t.Fatal("distinct derivation domains produced the same key")
	}
	if !allZero(firstRetained) || !allZero(secondRetained) {
		t.Fatal("callback-scoped derived-key buffers were retained")
	}
	clear(firstCopy)
	clear(secondCopy)
	clear(otherDomain)
	clear(rawMasterKey)
}

func TestIdentitySubjectHMACKeyFailsClosedAndClearsOnErrorOrPanic(t *testing.T) {
	t.Parallel()

	provider, err := NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.UseIdentitySubjectHMACKey(nil); err != ErrDerivedKeyUnavailable {
		t.Fatalf("nil callback error = %v", err)
	}

	var retained []byte
	err = provider.UseIdentitySubjectHMACKey(func(key []byte) error {
		retained = key
		return errors.New("derived key was " + base64.StdEncoding.EncodeToString(key))
	})
	if err != ErrDerivedKeyUnavailable || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(retained)) || !allZero(retained) {
		t.Fatalf("callback error was not fail-closed and cleared: err=%v key=%x", err, retained)
	}

	retained = nil
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("derived-key callback panic was swallowed")
			}
		}()
		_ = provider.UseIdentitySubjectHMACKey(func(key []byte) error {
			retained = key
			panic("test panic")
		})
	}()
	if !allZero(retained) {
		t.Fatalf("panic path retained derived-key bytes: %x", retained)
	}

	for _, format := range []string{"%#v", "%+v", "%v", "%s", "%q", "%x"} {
		if got := fmt.Sprintf(format, provider); got != "[REDACTED]" {
			t.Fatalf("provider pointer format %q = %q", format, got)
		}
		if got := fmt.Sprintf(format, *provider); got != "[REDACTED]" {
			t.Fatalf("provider value format %q = %q", format, got)
		}
	}
	for _, formatted := range []string{fmt.Sprintf("%p", provider), fmt.Sprintf("%p", *provider)} {
		if strings.Contains(formatted, provider.KeyID()) || strings.Contains(formatted, base64.StdEncoding.EncodeToString(provider.derivationRoot[:])) {
			t.Fatalf("provider pointer formatting exposed key metadata: %q", formatted)
		}
	}
}
