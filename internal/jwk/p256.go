// Package jwk contains the shared, deliberately constrained key codec used by
// DPoP and gateway signing keys. Wire member and algorithm policy stays with the
// caller; cryptographic point validation stays with Go's crypto/ecdsa package.
package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// ParseP256 validates canonical, fixed-width public coordinates. Both client
// proof keys and stored gateway signing keys reject zero coordinates, padding,
// ignored whitespace, and noncanonical trailing bits before point parsing.
func ParseP256(x, y string) (*ecdsa.PublicKey, error) {
	var encoded [65]byte
	var zero [32]byte
	encoded[0] = 4
	for index, coordinate := range []string{x, y} {
		if len(coordinate) != base64.RawURLEncoding.EncodedLen(32) {
			return nil, errors.New("invalid P-256 public key")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(coordinate)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != coordinate ||
			subtle.ConstantTimeCompare(decoded, zero[:]) == 1 {
			return nil, errors.New("invalid P-256 public key")
		}
		copy(encoded[1+32*index:], decoded)
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded[:])
	if err != nil {
		return nil, errors.New("invalid P-256 public key")
	}
	return key, nil
}
