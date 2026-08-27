package secrets

import (
	"bytes"
	"encoding/base64"
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
