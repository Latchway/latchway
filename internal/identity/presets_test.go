package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestFirebasePresetDerivesOfficialVerificationParameters(t *testing.T) {
	key := mustRSAKey(t)
	certificatePEM := certificatePEMForKey(t, key, verifierTestNow)
	document, err := json.Marshal(map[string]string{"google-key": certificatePEM})
	if err != nil {
		t.Fatalf("marshal Firebase certificate map: %v", err)
	}
	handler := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != firebasePublicCertificatesURL {
			t.Fatalf("unexpected Firebase key URL: %s", request.URL)
		}
		return jsonResponse(http.StatusOK, string(document), map[string]string{"Cache-Control": "max-age=300"}), nil
	})
	verifier, err := NewFirebaseVerifier(FirebasePreset{
		PresetCommon: PresetCommon{
			Client: &http.Client{Transport: handler}, Now: func() time.Time { return verifierTestNow },
			Mapper: PathMapper{"email_verified": "email_verified"},
		},
		ProjectID: "latchway-production",
	})
	if err != nil {
		t.Fatalf("construct Firebase verifier: %v", err)
	}
	claims := validClaims()
	claims["iss"] = "https://securetoken.google.com/latchway-production"
	claims["aud"] = "latchway-production"
	claims["email_verified"] = true
	raw := signToken(t, jwt.SigningMethodRS256, key, "google-key", claims)
	principal := verifyPreset(t, verifier, raw)
	if principal.ProviderID != "firebase" || principal.Claims["email_verified"] != true {
		t.Fatalf("unexpected Firebase principal: %#v", principal)
	}
	delete(claims, "auth_time")
	assertVerifyError(t, verifier, signToken(t, jwt.SigningMethodRS256, key, "google-key", claims), ErrCredentialInvalid)
}

func TestSupabasePresetSupportsAsymmetricAndAcknowledgedLegacyTokens(t *testing.T) {
	key := mustRSAKey(t)
	handler := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://project-ref.supabase.co/auth/v1/.well-known/jwks.json" {
			t.Fatalf("unexpected Supabase key URL: %s", request.URL)
		}
		return jsonResponse(http.StatusOK, jwksJSON(t, rsaJWK("supabase-key", "RS256", &key.PublicKey)), nil), nil
	})
	common := PresetCommon{Client: &http.Client{Transport: handler}, Now: func() time.Time { return verifierTestNow }}
	verifier, err := NewSupabaseVerifier(SupabasePreset{PresetCommon: common, ProjectURL: "https://project-ref.supabase.co"})
	if err != nil {
		t.Fatalf("construct Supabase verifier: %v", err)
	}
	claims := validClaims()
	claims["iss"] = "https://project-ref.supabase.co/auth/v1"
	claims["aud"] = "authenticated"
	verifyPreset(t, verifier, signToken(t, jwt.SigningMethodRS256, key, "supabase-key", claims))

	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, err := NewSupabaseHS256Verifier(SupabasePreset{PresetCommon: common, ProjectURL: "https://project-ref.supabase.co"}, secret, false); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("legacy HS256 must require acknowledgement: %v", err)
	}
	hsVerifier, err := NewSupabaseHS256Verifier(SupabasePreset{PresetCommon: common, ProjectURL: "https://project-ref.supabase.co"}, secret, true)
	if err != nil {
		t.Fatalf("construct legacy Supabase verifier: %v", err)
	}
	verifyPreset(t, hsVerifier, signToken(t, jwt.SigningMethodHS256, secret, "", claims))
}

func TestPresetCommonPreservesExplicitZeroClockSkew(t *testing.T) {
	verifier, err := NewSupabaseVerifier(SupabasePreset{
		PresetCommon: PresetCommon{ClockSkewSet: true},
		ProjectURL:   "https://project-ref.supabase.co",
	})
	if err != nil {
		t.Fatalf("construct explicit-zero-skew preset: %v", err)
	}
	if verifier.clockSkew != 0 {
		t.Fatalf("preset clock skew = %s, want exact zero", verifier.clockSkew)
	}
}

func TestClerkPresetValidatesSessionAndAuthorizedParty(t *testing.T) {
	key := mustRSAKey(t)
	verifier, err := NewClerkVerifier(ClerkPreset{
		PresetCommon:      PresetCommon{Now: func() time.Time { return verifierTestNow }},
		Issuer:            "https://clerk.example.test",
		Audiences:         []string{"latchway-app"},
		AuthorizedParties: []string{"https://app.example.test"},
		StaticPublicKey:   &key.PublicKey,
		StaticKeyID:       "clerk-key",
	})
	if err != nil {
		t.Fatalf("construct Clerk verifier: %v", err)
	}
	claims := validClaims()
	claims["iss"] = "https://clerk.example.test"
	claims["aud"] = "latchway-app"
	claims["sid"] = "sess_123"
	claims["azp"] = "https://app.example.test"
	verifyPreset(t, verifier, signToken(t, jwt.SigningMethodRS256, key, "clerk-key", claims))
	claims["azp"] = "https://attacker.example.test"
	assertVerifyError(t, verifier, signToken(t, jwt.SigningMethodRS256, key, "clerk-key", claims), ErrCredentialInvalid)
}

func TestPresetConfigurationRejectsUnsafeDerivation(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "Firebase path injection", run: func() error {
			_, err := NewFirebaseVerifier(FirebasePreset{ProjectID: "../../attacker"})
			return err
		}},
		{name: "Supabase non HTTPS", run: func() error {
			_, err := NewSupabaseVerifier(SupabasePreset{ProjectURL: "http://project.supabase.co"})
			return err
		}},
		{name: "Supabase path", run: func() error {
			_, err := NewSupabaseVerifier(SupabasePreset{ProjectURL: "https://project.supabase.co/attacker"})
			return err
		}},
		{name: "Supabase symmetric in asymmetric preset", run: func() error {
			_, err := NewSupabaseVerifier(SupabasePreset{ProjectURL: "https://project.supabase.co", AllowedAlgorithms: []string{"HS256"}})
			return err
		}},
		{name: "Clerk two key sources", run: func() error {
			key := mustRSAKey(t)
			_, err := NewClerkVerifier(ClerkPreset{
				Issuer: "https://clerk.example.test", Audiences: []string{"app"},
				JWKSURL: "https://keys.example.test/jwks", StaticPublicKey: &key.PublicKey,
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("expected configuration error, got %v", err)
			}
		})
	}
}

func TestParsePublicKeyPEMAcceptsPublicFormatsAndRejectsPrivateMaterial(t *testing.T) {
	rsaKey := mustRSAKey(t)
	pkix, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}
	inputs := [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)}),
		[]byte(certificatePEMForKey(t, rsaKey, verifierTestNow)),
	}
	for index, input := range inputs {
		parsed, err := ParsePublicKeyPEM(input)
		if err != nil {
			t.Fatalf("parse public format %d: %v", index, err)
		}
		if parsed.(*rsa.PublicKey).N.Cmp(rsaKey.N) != 0 {
			t.Fatalf("parsed wrong public key for format %d", index)
		}
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	if _, err := ParsePublicKeyPEM(privatePEM); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("private key material must be rejected: %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecPKIX, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	if _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecPKIX})); err != nil {
		t.Fatalf("parse ECDSA key: %v", err)
	}
}

func certificatePEMForKey(t *testing.T, key *rsa.PrivateKey, now time.Time) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "identity fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func verifyPreset(t *testing.T, verifier *JWTVerifier, raw string) VerifiedPrincipal {
	t.Helper()
	credential, err := NewRawIdentityCredential(raw)
	if err != nil {
		t.Fatalf("construct credential: %v", err)
	}
	principal, err := verifier.Verify(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify preset token: %v", err)
	}
	return principal
}
