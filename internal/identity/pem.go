package identity

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

const maxPublicKeyPEMBytes = 64 << 10

// ParsePublicKeyPEM parses one configured public key or certificate. Private
// key blocks, chains, trailing data, and unsafe key sizes are rejected.
func ParsePublicKeyPEM(input []byte) (any, error) {
	if len(input) == 0 || len(input) > maxPublicKeyPEMBytes {
		return nil, fmt.Errorf("%w: public key PEM size", ErrConfiguration)
	}
	block, remainder := pem.Decode(input)
	if block == nil || len(strings.TrimSpace(string(remainder))) != 0 || len(block.Headers) != 0 {
		return nil, fmt.Errorf("%w: public key PEM", ErrConfiguration)
	}
	var key any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		var certificate *x509.Certificate
		certificate, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			key = certificate.PublicKey
		}
	default:
		return nil, fmt.Errorf("%w: public key PEM block type", ErrConfiguration)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: parse public key PEM", ErrConfiguration)
	}
	if err := validateAsymmetricKey(key); err != nil {
		return nil, err
	}
	return key, nil
}
