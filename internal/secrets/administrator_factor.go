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

// organizationSSOSecretDomain separates sealed single sign-on client secrets
// the same way.
const organizationSSOSecretDomain = "latchway/admin/sso-client-secret/v1"

// SealAdministratorFactor encrypts an administrator's second-factor secret
// (for example a TOTP key) with a key derived from the master key, bound to
// that administrator so a sealed value cannot be moved to another account.
func (p *EnvironmentMasterKey) SealAdministratorFactor(plaintext []byte, adminUserID string) (Envelope, error) {
	envelope, err := p.sealBound(administratorFactorDomain, plaintext, adminUserID)
	if err != nil {
		return Envelope{}, errors.New("seal administrator factor")
	}
	return envelope, nil
}

// OpenAdministratorFactor authenticates and decrypts a sealed second-factor
// secret for the administrator it was sealed for.
func (p *EnvironmentMasterKey) OpenAdministratorFactor(envelope Envelope, adminUserID string) ([]byte, error) {
	plaintext, err := p.openBound(administratorFactorDomain, envelope, adminUserID)
	if err != nil {
		return nil, errors.New("administrator factor authentication failed")
	}
	return plaintext, nil
}

// SealOrganizationSSOSecret encrypts an organization's identity-provider client
// secret, bound to that organization.
func (p *EnvironmentMasterKey) SealOrganizationSSOSecret(plaintext []byte, organizationID string) (Envelope, error) {
	envelope, err := p.sealBound(organizationSSOSecretDomain, plaintext, organizationID)
	if err != nil {
		return Envelope{}, errors.New("seal single sign-on client secret")
	}
	return envelope, nil
}

// OpenOrganizationSSOSecret authenticates and decrypts a client secret for the
// organization it was sealed for.
func (p *EnvironmentMasterKey) OpenOrganizationSSOSecret(envelope Envelope, organizationID string) ([]byte, error) {
	plaintext, err := p.openBound(organizationSSOSecretDomain, envelope, organizationID)
	if err != nil {
		return nil, errors.New("single sign-on client secret authentication failed")
	}
	return plaintext, nil
}

// sealBound encrypts plaintext under the key derived for domain, with the
// domain and binding as associated data.
func (p *EnvironmentMasterKey) sealBound(domain string, plaintext []byte, binding string) (Envelope, error) {
	if binding == "" {
		return Envelope{}, errors.New("binding is required")
	}
	var envelope Envelope
	err := p.useDerivedKey(domain, func(key []byte) error {
		aead, err := boundAEAD(key)
		if err != nil {
			return err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(p.random, nonce); err != nil {
			return err
		}
		envelope = Envelope{
			FormatVersion: formatVersion, Algorithm: algorithm, KeyID: p.keyID,
			Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, boundAAD(domain, binding)),
		}
		return nil
	})
	return envelope, err
}

func (p *EnvironmentMasterKey) openBound(domain string, envelope Envelope, binding string) ([]byte, error) {
	if binding == "" || p == nil || p.environmentMasterKeyMaterial == nil {
		return nil, errors.New("sealed value is unavailable")
	}
	if envelope.FormatVersion != formatVersion || envelope.Algorithm != algorithm || envelope.KeyID != p.keyID {
		return nil, errors.New("unsupported sealed envelope")
	}
	var plaintext []byte
	err := p.useDerivedKey(domain, func(key []byte) error {
		aead, err := boundAEAD(key)
		if err != nil {
			return err
		}
		if len(envelope.Nonce) != aead.NonceSize() || len(envelope.Ciphertext) < aead.Overhead() {
			return errors.New("invalid sealed envelope")
		}
		opened, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, boundAAD(domain, binding))
		if err != nil {
			return err
		}
		plaintext = opened
		return nil
	})
	return plaintext, err
}

func boundAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func boundAAD(domain, binding string) []byte {
	return []byte(domain + "\x00" + binding)
}
