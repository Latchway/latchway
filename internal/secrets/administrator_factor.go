package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// administratorFactorDomain separates sealed administrator second-factor
// secrets from provider secrets and every other derived key.
const administratorFactorDomain = "latchway/admin/second-factor/v1"

// SealAdministratorFactor encrypts an administrator's second-factor secret
// (for example a TOTP key) with a key derived from the master key, bound to
// that administrator so a sealed value cannot be moved to another account.
func (p *EnvironmentMasterKey) SealAdministratorFactor(plaintext []byte, adminUserID string) (Envelope, error) {
	if adminUserID == "" {
		return Envelope{}, errors.New("administrator is required")
	}
	var envelope Envelope
	err := p.useDerivedKey(administratorFactorDomain, func(key []byte) error {
		aead, err := administratorFactorAEAD(key)
		if err != nil {
			return err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(p.random, nonce); err != nil {
			return err
		}
		envelope = Envelope{
			FormatVersion: formatVersion, Algorithm: algorithm, KeyID: p.keyID,
			Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, administratorFactorAAD(adminUserID)),
		}
		return nil
	})
	if err != nil {
		return Envelope{}, errors.New("seal administrator factor")
	}
	return envelope, nil
}

// OpenAdministratorFactor authenticates and decrypts a sealed second-factor
// secret for the administrator it was sealed for.
func (p *EnvironmentMasterKey) OpenAdministratorFactor(envelope Envelope, adminUserID string) ([]byte, error) {
	if adminUserID == "" || p == nil || p.environmentMasterKeyMaterial == nil {
		return nil, errors.New("administrator factor is unavailable")
	}
	if envelope.FormatVersion != formatVersion || envelope.Algorithm != algorithm || envelope.KeyID != p.keyID {
		return nil, errors.New("unsupported administrator factor envelope")
	}
	var plaintext []byte
	err := p.useDerivedKey(administratorFactorDomain, func(key []byte) error {
		aead, err := administratorFactorAEAD(key)
		if err != nil {
			return err
		}
		if len(envelope.Nonce) != aead.NonceSize() || len(envelope.Ciphertext) < aead.Overhead() {
			return errors.New("invalid administrator factor envelope")
		}
		opened, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, administratorFactorAAD(adminUserID))
		if err != nil {
			return err
		}
		plaintext = opened
		return nil
	})
	if err != nil {
		return nil, errors.New("administrator factor authentication failed")
	}
	return plaintext, nil
}

func administratorFactorAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func administratorFactorAAD(adminUserID string) []byte {
	return []byte(administratorFactorDomain + "\x00" + adminUserID)
}
