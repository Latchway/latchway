package session

import (
	"context"
	"errors"
	"testing"
)

type fakeSigningJWKSReader struct {
	keys JWKS
	err  error
}

func (reader fakeSigningJWKSReader) PublicJWKS(context.Context) (JWKS, error) {
	return reader.keys, reader.err
}

func TestClientJWKSProviderCopiesOnlyPublicMembers(t *testing.T) {
	provider, err := newClientJWKSProvider(fakeSigningJWKSReader{keys: JWKS{Keys: []PublicSigningJWK{{
		Kty: "EC", Crv: "P-256", X: "x-coordinate", Y: "y-coordinate",
		Kid: "gateway-key", Use: "sig", Alg: "ES256",
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := provider.PublicJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].Kid != "gateway-key" || keys.Keys[0].Alg != "ES256" || keys.Keys[0].X != "x-coordinate" {
		t.Fatalf("client JWKS = %#v", keys)
	}
}

func TestClientJWKSProviderFailsClosed(t *testing.T) {
	if _, err := newClientJWKSProvider(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
	provider, err := newClientJWKSProvider(fakeSigningJWKSReader{err: errors.New("database detail")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.PublicJWKS(context.Background()); err == nil {
		t.Fatal("reader error was swallowed")
	}
}
