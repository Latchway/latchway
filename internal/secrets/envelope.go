// Package secrets implements authenticated envelope encryption for provider
// credentials. Plaintext values never implement fmt.Stringer or JSON encoding.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	MasterKeyEnvironment = "LATCHWAY_MASTER_KEY"
	formatVersion        = 1
	algorithm            = "AES-256-GCM"
)

// AssociatedData binds ciphertext to one immutable secret version and tenant.
type AssociatedData struct {
	OrganizationID string `json:"organization_id"`
	EnvironmentID  string `json:"environment_id"`
	SecretID       string `json:"secret_id"`
	SecretVersion  int64  `json:"secret_version"`
	FormatVersion  int    `json:"format_version"`
}

// Envelope contains only encrypted data and non-secret metadata.
type Envelope struct {
	FormatVersion int
	Algorithm     string
	KeyID         string
	Nonce         []byte
	Ciphertext    []byte
}

// Provider seals and opens versioned secret values.
type Provider interface {
	Encrypt(plaintext []byte, associatedData AssociatedData) (Envelope, error)
	Decrypt(envelope Envelope, associatedData AssociatedData) ([]byte, error)
	KeyID() string
}

// EnvironmentMasterKey uses a process-provided 32-byte AES key.
type EnvironmentMasterKey struct {
	aead   cipher.AEAD
	keyID  string
	random io.Reader
}

// NewEnvironmentMasterKey parses an unpadded or padded base64 32-byte key.
func NewEnvironmentMasterKey(encoded string) (*EnvironmentMasterKey, error) {
	key, err := decodeMasterKey(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize master-key cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize master-key AEAD")
	}
	digest := sha256.Sum256(key)
	return &EnvironmentMasterKey{
		aead:   aead,
		keyID:  "env_" + base64.RawURLEncoding.EncodeToString(digest[:12]),
		random: rand.Reader,
	}, nil
}

// NewEnvironmentMasterKeyFromEnv loads the key without retaining its encoded
// representation.
func NewEnvironmentMasterKeyFromEnv() (*EnvironmentMasterKey, error) {
	encoded := os.Getenv(MasterKeyEnvironment)
	if encoded == "" {
		return nil, fmt.Errorf("%s is required when encrypted secrets exist", MasterKeyEnvironment)
	}
	return NewEnvironmentMasterKey(encoded)
}

// KeyID returns a non-secret identifier used to select the decryption key.
func (p *EnvironmentMasterKey) KeyID() string { return p.keyID }

// Encrypt seals a plaintext value with tenant- and version-bound data.
func (p *EnvironmentMasterKey) Encrypt(plaintext []byte, associatedData AssociatedData) (Envelope, error) {
	encodedAAD, err := associatedData.bytes()
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(p.random, nonce); err != nil {
		return Envelope{}, errors.New("generate secret nonce")
	}
	ciphertext := p.aead.Seal(nil, nonce, plaintext, encodedAAD)
	return Envelope{
		FormatVersion: formatVersion,
		Algorithm:     algorithm,
		KeyID:         p.keyID,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
	}, nil
}

// Decrypt authenticates metadata before returning a fresh plaintext buffer.
func (p *EnvironmentMasterKey) Decrypt(envelope Envelope, associatedData AssociatedData) ([]byte, error) {
	if envelope.FormatVersion != formatVersion || envelope.Algorithm != algorithm || envelope.KeyID != p.keyID {
		return nil, errors.New("unsupported secret envelope")
	}
	if len(envelope.Nonce) != p.aead.NonceSize() || len(envelope.Ciphertext) < p.aead.Overhead() {
		return nil, errors.New("invalid secret envelope")
	}
	encodedAAD, err := associatedData.bytes()
	if err != nil {
		return nil, err
	}
	plaintext, err := p.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, encodedAAD)
	if err != nil {
		return nil, errors.New("secret authentication failed")
	}
	return plaintext, nil
}

func (a AssociatedData) bytes() ([]byte, error) {
	if a.OrganizationID == "" || a.EnvironmentID == "" || a.SecretID == "" || a.SecretVersion <= 0 {
		return nil, errors.New("complete secret associated data is required")
	}
	if a.FormatVersion == 0 {
		a.FormatVersion = formatVersion
	}
	if a.FormatVersion != formatVersion {
		return nil, errors.New("unsupported associated-data version")
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		return nil, errors.New("encode secret associated data")
	}
	return encoded, nil
}

func decodeMasterKey(encoded string) ([]byte, error) {
	key, rawErr := base64.RawStdEncoding.DecodeString(encoded)
	if rawErr != nil {
		key, rawErr = base64.StdEncoding.DecodeString(encoded)
	}
	if rawErr != nil || len(key) != 32 {
		return nil, errors.New("LATCHWAY_MASTER_KEY must be base64-encoded 32 random bytes")
	}
	return key, nil
}
