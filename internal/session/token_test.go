package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

type staticAccessTokenKeys struct {
	key signingKey
}

func (keys staticAccessTokenKeys) Active(context.Context) (signingKey, error) {
	return keys.key, nil
}

func (keys staticAccessTokenKeys) PublicKey(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
	if kid != keys.key.KeyID() {
		return nil, ErrSigningKeyUnavailable
	}
	privateKey := keys.key.privateKey()
	return &privateKey.PublicKey, nil
}

func TestAccessTokenVerifierHonorsExplicitZeroClockSkew(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	now := time.Unix(1_787_820_000, 0).UTC()
	keys := staticAccessTokenKeys{key: signingKey{material: &signingKeyMaterial{
		kid:       "gsk_explicit-zero-skew",
		private:   privateKey,
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(24 * time.Hour),
	}}}
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now.Add(time.Second) },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	issued, err := issuer.Issue(context.Background(), AccessIssueInput{
		OrganizationID:    mustTokenID(t, id.Organization),
		ApplicationID:     mustTokenID(t, id.Application),
		EnvironmentID:     mustTokenID(t, id.Environment),
		ApplicationUserID: mustTokenID(t, id.ApplicationUser),
		InstallationID:    mustTokenID(t, id.Installation),
		SessionGrantID:    mustTokenID(t, id.SessionGrant),
		IdentityProvider:  "firebase",
		TrustLevel:        "app_verified",
		PolicyRevisionID:  mustTokenID(t, id.ConfigRevision),
		DPoPJKT:           base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("issue future access token: %v", err)
	}

	defaultVerifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct default-skew verifier: %v", err)
	}
	if _, err := defaultVerifier.Verify(context.Background(), issued.Token); err != nil {
		t.Fatalf("default skew rejected token one second in the future: %v", err)
	}

	zeroSkewVerifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		ClockSkew: 0, ClockSkewSet: true, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct zero-skew verifier: %v", err)
	}
	if _, err := zeroSkewVerifier.Verify(context.Background(), issued.Token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("explicit zero skew accepted token one second in the future: %v", err)
	}
}

func TestAccessIssueIdentityProviderMatchesLockedIdentifierBounds(t *testing.T) {
	t.Parallel()

	base := AccessIssueInput{
		OrganizationID: mustTokenID(t, id.Organization), ApplicationID: mustTokenID(t, id.Application),
		EnvironmentID: mustTokenID(t, id.Environment), ApplicationUserID: mustTokenID(t, id.ApplicationUser),
		InstallationID: mustTokenID(t, id.Installation), SessionGrantID: mustTokenID(t, id.SessionGrant),
		TrustLevel: "app_verified", PolicyRevisionID: mustTokenID(t, id.ConfigRevision),
		DPoPJKT: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	for _, providerID := range []string{"a", "a" + strings.Repeat("0", 62)} {
		input := base
		input.IdentityProvider = providerID
		if err := input.validate(); err != nil {
			t.Errorf("locked Identifier %q was rejected: %v", providerID, err)
		}
	}
	for _, providerID := range []string{"", "A", "a.", "a" + strings.Repeat("0", 63)} {
		input := base
		input.IdentityProvider = providerID
		if err := input.validate(); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("out-of-contract identity provider %q error = %v", providerID, err)
		}
	}
}

func TestPreparedAccessIssuerFormattingIsRedacted(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	now := time.Unix(1_787_820_000, 0).UTC()
	keys := staticAccessTokenKeys{key: signingKey{material: &signingKeyMaterial{
		kid:       "gsk_prepared-formatting",
		private:   privateKey,
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(24 * time.Hour),
	}}}
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	prepared, err := issuer.Prepare(context.Background())
	if err != nil {
		t.Fatalf("prepare access-token issuer: %v", err)
	}
	for _, format := range []string{"%#v", "%+v", "%v", "%s", "%q", "%x"} {
		if got := fmt.Sprintf(format, prepared); got != "[REDACTED]" {
			t.Fatalf("prepared issuer format %q = %q", format, got)
		}
	}
	formattedPointer := fmt.Sprintf("%p", prepared)
	for _, sensitive := range []string{keys.key.KeyID(), privateKey.D.String()} {
		if strings.Contains(formattedPointer, sensitive) {
			t.Fatalf("prepared issuer pointer formatting exposed signing material: %q", formattedPointer)
		}
	}
}

func TestAccessTokenIssuerAllowsOnlyCanonicalSecureOrLoopbackOrigins(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"https://gateway.example.test",
		"https://gateway.example.test/",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		if !canonicalIssuer(origin) {
			t.Errorf("canonical issuer rejected %q", origin)
		}
	}
	for _, origin := range []string{
		"http://gateway.example.test",
		"https://gateway.example.test/client",
		"https://gateway.example.test?query=value",
		"https://user@gateway.example.test",
		"ftp://localhost:8080",
	} {
		if canonicalIssuer(origin) {
			t.Errorf("unsafe or non-origin issuer accepted %q", origin)
		}
	}
}

func mustTokenID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}
