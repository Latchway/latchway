package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
)

type staticKey struct {
	key any
	alg string
}

// StaticKeySource is an immutable public-key set. A key with an empty ID is
// accepted only when it is the sole key and the token also omits kid.
type StaticKeySource struct {
	keys map[string]staticKey
}

func NewStaticKeySource(keys map[string]any) (*StaticKeySource, error) {
	if len(keys) == 0 || len(keys) > 100 {
		return nil, fmt.Errorf("%w: static key count", ErrConfiguration)
	}
	result := &StaticKeySource{keys: make(map[string]staticKey, len(keys))}
	for kid, key := range keys {
		if len(kid) > 256 || strings.ContainsAny(kid, "\r\n\x00") {
			return nil, fmt.Errorf("%w: static key ID", ErrConfiguration)
		}
		if len(keys) > 1 && kid == "" {
			return nil, fmt.Errorf("%w: multiple static keys require IDs", ErrConfiguration)
		}
		if err := validateAsymmetricKey(key); err != nil {
			return nil, err
		}
		result.keys[kid] = staticKey{key: key}
	}
	return result, nil
}

func (source *StaticKeySource) Key(_ context.Context, kid, algorithm string) (any, error) {
	if source == nil {
		return nil, ErrKeyUnavailable
	}
	record, ok := source.keys[kid]
	if !ok || (record.alg != "" && record.alg != algorithm) || !keySupportsAlgorithm(record.key, algorithm) {
		return nil, ErrKeyUnavailable
	}
	return record.key, nil
}

// SymmetricKeySource requires an explicit risk acknowledgement and supports
// only HS256. The key is defensively copied and never format-exposed.
type SymmetricKeySource struct {
	key []byte
}

func NewSymmetricKeySource(key []byte, acknowledgeRisk bool) (*SymmetricKeySource, error) {
	if !acknowledgeRisk || len(key) < 32 || len(key) > 4096 {
		return nil, fmt.Errorf("%w: HS256 requires an acknowledged 32+ byte secret", ErrConfiguration)
	}
	copyOfKey := make([]byte, len(key))
	copy(copyOfKey, key)
	return &SymmetricKeySource{key: copyOfKey}, nil
}

func (source *SymmetricKeySource) Key(_ context.Context, kid, algorithm string) (any, error) {
	if source == nil || algorithm != "HS256" || kid != "" {
		return nil, ErrKeyUnavailable
	}
	key := make([]byte, len(source.key))
	copy(key, source.key)
	return key, nil
}

func validateAsymmetricKey(key any) error {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		if typed == nil || typed.N == nil || typed.N.BitLen() < 2048 || typed.N.BitLen() > 8192 || typed.E < 3 || typed.E%2 == 0 {
			return fmt.Errorf("%w: unsafe RSA public key", ErrConfiguration)
		}
	case *ecdsa.PublicKey:
		if typed == nil {
			return fmt.Errorf("%w: unsafe ECDSA public key", ErrConfiguration)
		}
		if _, err := typed.Bytes(); err != nil {
			return fmt.Errorf("%w: unsafe ECDSA public key", ErrConfiguration)
		}
		bits := typed.Curve.Params().BitSize
		if bits != 256 && bits != 384 {
			return fmt.Errorf("%w: unsupported ECDSA curve", ErrConfiguration)
		}
	default:
		return fmt.Errorf("%w: unsupported public key type", ErrConfiguration)
	}
	return nil
}

func keySupportsAlgorithm(key any, algorithm string) bool {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return typed != nil && (algorithm == "RS256" || algorithm == "RS384" || algorithm == "RS512")
	case *ecdsa.PublicKey:
		if typed == nil || typed.Curve == nil {
			return false
		}
		return (algorithm == "ES256" && typed.Curve.Params().BitSize == 256) || (algorithm == "ES384" && typed.Curve.Params().BitSize == 384)
	case []byte:
		return algorithm == "HS256" && len(typed) >= 32
	default:
		return false
	}
}

func mapKeyError(err error) error {
	if errors.Is(err, ErrKeyUnavailable) {
		return err
	}
	return fmt.Errorf("%w: key source failure", ErrKeyUnavailable)
}
