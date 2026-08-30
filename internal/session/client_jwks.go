package session

import (
	"context"
	"errors"

	"github.com/latchway/latchway/internal/clientapi"
)

type signingJWKSReader interface {
	PublicJWKS(context.Context) (JWKS, error)
}

type clientJWKSProvider struct {
	reader signingJWKSReader
}

// NewClientJWKSProvider exposes only the public session-signing members in the
// transport's locked response type.
func NewClientJWKSProvider(manager *SigningKeyManager) (clientapi.JWKSProvider, error) {
	if manager == nil {
		return nil, errors.New("client JWKS signing-key manager is nil")
	}
	return newClientJWKSProvider(manager)
}

func newClientJWKSProvider(reader signingJWKSReader) (clientapi.JWKSProvider, error) {
	if reader == nil {
		return nil, errors.New("client JWKS reader is nil")
	}
	return &clientJWKSProvider{reader: reader}, nil
}

func (provider *clientJWKSProvider) PublicJWKS(ctx context.Context) (clientapi.JWKS, error) {
	if provider == nil || provider.reader == nil {
		return clientapi.JWKS{}, ErrSigningKeyUnavailable
	}
	keys, err := provider.reader.PublicJWKS(ctx)
	if err != nil {
		return clientapi.JWKS{}, err
	}
	result := clientapi.JWKS{Keys: make([]clientapi.PublicJWK, len(keys.Keys))}
	for index, key := range keys.Keys {
		result.Keys[index] = clientapi.PublicJWK{
			Kty: key.Kty, Crv: key.Crv, X: key.X, Y: key.Y,
			Kid: key.Kid, Use: key.Use, Alg: key.Alg,
		}
	}
	return result, nil
}
