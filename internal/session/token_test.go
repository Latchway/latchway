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
		return nil, ErrSigningKeyNotFound
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

func TestAccessPrincipalExpiredWithinVerifierLeewayStaysExpired(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	issuedAt := time.Unix(1_787_820_000, 0).UTC()
	keys := staticAccessTokenKeys{key: signingKey{material: &signingKeyMaterial{
		kid: "gsk_expiry-leeway", private: privateKey,
		notBefore: issuedAt.Add(-time.Hour), notAfter: issuedAt.Add(24 * time.Hour),
	}}}
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Lifetime: time.Minute, Now: func() time.Time { return issuedAt },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	issued, err := issuer.Issue(context.Background(), AccessIssueInput{
		OrganizationID: mustTokenID(t, id.Organization), ApplicationID: mustTokenID(t, id.Application),
		EnvironmentID: mustTokenID(t, id.Environment), ApplicationUserID: mustTokenID(t, id.ApplicationUser),
		InstallationID: mustTokenID(t, id.Installation), SessionGrantID: mustTokenID(t, id.SessionGrant),
		IdentityProvider: "firebase", TrustLevel: "app_verified",
		PolicyRevisionID: mustTokenID(t, id.ConfigRevision),
		DPoPJKT:          base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	requestTime := issued.ExpiresAt.Add(30 * time.Second)
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		ClockSkew: time.Minute, ClockSkewSet: true, Now: func() time.Time { return requestTime },
	})
	if err != nil {
		t.Fatalf("construct leeway verifier: %v", err)
	}
	principal, err := verifier.Verify(context.Background(), issued.Token)
	if err != nil {
		t.Fatalf("verifier should parse a token inside signature-validation leeway: %v", err)
	}
	if err := validateAccessPrincipal(principal, requestTime); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("request authorization expiry error=%v, want token expired", err)
	}
	if code := mapAccessRequestError(ErrTokenExpired); code != "session_expired" {
		t.Fatalf("expired access mapping=%q", code)
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

func TestAccessIssueAcceptsDelegatedDirectAttestedTrust(t *testing.T) {
	t.Parallel()

	input := AccessIssueInput{
		OrganizationID: mustTokenID(t, id.Organization), ApplicationID: mustTokenID(t, id.Application),
		EnvironmentID: mustTokenID(t, id.Environment), ApplicationUserID: mustTokenID(t, id.ApplicationUser),
		InstallationID: mustTokenID(t, id.Installation), InstallationFamilyID: mustTokenID(t, id.InstallationFamily),
		ComponentID: mustTokenID(t, id.ClientComponent), ComponentDefinitionID: "ios-action-extension",
		ComponentKind: "action_extension", TrustSource: "delegated_direct_attested",
		AttestationProvider: "app_attest", ParentComponentID: mustTokenID(t, id.ClientComponent),
		ParentAttestationProvider: "app_attest", DelegationID: mustTokenID(t, id.ComponentDelegation),
		Features: []string{"assistant"}, SessionGrantID: mustTokenID(t, id.SessionGrant),
		IdentityProvider: "firebase", TrustLevel: "app_verified",
		PolicyRevisionID: mustTokenID(t, id.ConfigRevision),
		DPoPJKT:          base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	if err := input.validate(); err != nil {
		t.Fatalf("delegated direct-attestation token input rejected: %v", err)
	}
	input.TrustSource = "delegated_unverified"
	if err := input.validate(); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("unknown trust source error = %v, want ErrTokenInvalid", err)
	}
}

func TestComponentAccessTokenOmitsLegacyInstallationClaim(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	now := time.Unix(1_787_820_000, 0).UTC()
	keys := staticAccessTokenKeys{key: signingKey{material: &signingKeyMaterial{
		kid: "gsk-component-final-model", private: privateKey,
		notBefore: now.Add(-time.Hour), notAfter: now.Add(24 * time.Hour),
	}}}
	issuer, err := NewAccessTokenIssuer(AccessTokenIssuerConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token issuer: %v", err)
	}
	input := AccessIssueInput{
		OrganizationID: mustTokenID(t, id.Organization), ApplicationID: mustTokenID(t, id.Application),
		EnvironmentID: mustTokenID(t, id.Environment), ApplicationUserID: mustTokenID(t, id.ApplicationUser),
		InstallationID: mustTokenID(t, id.Installation), InstallationFamilyID: mustTokenID(t, id.InstallationFamily),
		ComponentID: mustTokenID(t, id.ClientComponent), ComponentDefinitionID: "ios-main",
		ComponentKind: "main_app", ComponentIsRoot: true, TrustSource: "direct_attested",
		AttestationProvider: "app_attest", Features: []string{"assistant"},
		SessionGrantID: mustTokenID(t, id.SessionGrant), IdentityProvider: "firebase",
		TrustLevel: "device_verified", PolicyRevisionID: mustTokenID(t, id.ConfigRevision),
		DPoPJKT: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	issued, err := issuer.Issue(context.Background(), input)
	if err != nil {
		t.Fatalf("issue component access token: %v", err)
	}
	_, payload, err := preflightAccessToken(issued.Token.Reveal())
	if err != nil {
		t.Fatalf("decode component access token: %v", err)
	}
	if _, exists := payload["installation_id"]; exists {
		t.Fatal("wire-2 component token retained the legacy installation_id claim")
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierConfig{
		Keys: keys, Issuer: "https://gateway.example.test", Audience: "latchway-data-plane",
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("construct access-token verifier: %v", err)
	}
	principal, err := verifier.Verify(context.Background(), issued.Token)
	if err != nil {
		t.Fatalf("verify component access token: %v", err)
	}
	if principal.InstallationID != "" || principal.ComponentID != input.ComponentID ||
		principal.InstallationFamilyID != input.InstallationFamilyID {
		t.Fatalf("unexpected final-model component principal: %#v", principal)
	}

	claimInput := input
	claimInput.InstallationID = ""
	if err := claimInput.validateSignedClaims(); err != nil {
		t.Fatalf("final-model component claims rejected: %v", err)
	}
	claimInput.InstallationID = input.InstallationID
	if err := claimInput.validateSignedClaims(); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("legacy installation claim on component token error = %v, want token invalid", err)
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
	privateScalar, err := privateKey.Bytes()
	if err != nil {
		t.Fatalf("encode private signing key: %v", err)
	}
	defer clear(privateScalar)
	encodedPrivateScalar := base64.RawURLEncoding.EncodeToString(privateScalar)
	for _, format := range []string{"%#v", "%+v", "%v", "%s", "%q", "%x"} {
		if got := fmt.Sprintf(format, prepared); got != "[REDACTED]" {
			t.Fatalf("prepared issuer format %q = %q", format, got)
		}
	}
	formattedPointer := fmt.Sprintf("%p", prepared)
	for _, sensitive := range []string{keys.key.KeyID(), encodedPrivateScalar} {
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
