package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var verifierTestNow = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func TestJWTVerifierValidatesAndNormalizesRS256(t *testing.T) {
	privateKey := mustRSAKey(t)
	verifier := mustJWTVerifier(t, VerifierConfig{
		ProviderID:        "oidc_test",
		Issuer:            "https://issuer.example.test",
		Audiences:         []string{"latchway-api", "alternate"},
		AllowedAlgorithms: []string{"RS256"},
		AuthorizedParties: []string{"https://app.example.test"},
		RequiredClaims:    []string{"email_verified", "profile.plan"},
		Mapper: PathMapper{
			"plan":           "profile.plan",
			"email_verified": "email_verified",
			"roles":          "roles",
		},
		Keys: mustStaticKeys(t, map[string]any{"primary": &privateKey.PublicKey}),
		Now:  func() time.Time { return verifierTestNow },
	})
	claims := validClaims()
	claims["azp"] = "https://app.example.test"
	claims["profile"] = map[string]any{"plan": "pro", "ignored": "not-retained"}
	claims["email_verified"] = true
	claims["roles"] = []string{"writer", "reader"}
	token := signToken(t, jwt.SigningMethodRS256, privateKey, "primary", claims)
	credential, err := NewRawIdentityCredential(token)
	if err != nil {
		t.Fatalf("construct credential: %v", err)
	}

	principal, err := verifier.Verify(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if principal.ProviderID != "oidc_test" || principal.Issuer != "https://issuer.example.test" || principal.Subject != "user-123" {
		t.Fatalf("unexpected principal identity: %#v", principal)
	}
	if !principal.AuthenticatedAt.Equal(verifierTestNow.Add(-10*time.Minute)) || !principal.ExpiresAt.Equal(verifierTestNow.Add(time.Hour)) {
		t.Fatalf("unexpected principal times: %#v", principal)
	}
	if len(principal.Audience) != 1 || principal.Audience[0] != "latchway-api" {
		t.Fatalf("unexpected audience: %#v", principal.Audience)
	}
	if fmt.Sprint(principal.Claims["roles"]) != "[writer reader]" || principal.Claims["plan"] != "pro" || principal.Claims["email_verified"] != true {
		t.Fatalf("unexpected normalized claims: %#v", principal.Claims)
	}
	if _, leaked := principal.Claims["ignored"]; leaked {
		t.Fatal("unconfigured claim leaked into normalized principal")
	}
}

func TestJWTVerifierSupportsES256AndExplicitHS256(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	esVerifier := mustJWTVerifier(t, VerifierConfig{
		ProviderID: "es_test", Issuer: "https://issuer.example.test", Audiences: []string{"latchway-api"},
		AllowedAlgorithms: []string{"ES256"}, Keys: mustStaticKeys(t, map[string]any{"ec": &ecdsaKey.PublicKey}),
		Now: func() time.Time { return verifierTestNow },
	})
	verifySigned(t, esVerifier, signToken(t, jwt.SigningMethodES256, ecdsaKey, "ec", validClaims()))

	secret := []byte("0123456789abcdef0123456789abcdef")
	if _, err := NewSymmetricKeySource(secret, false); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected explicit symmetric-risk acknowledgement, got %v", err)
	}
	hsSource, err := NewSymmetricKeySource(secret, true)
	if err != nil {
		t.Fatalf("construct symmetric source: %v", err)
	}
	hsVerifier := mustJWTVerifier(t, VerifierConfig{
		ProviderID: "hs_test", Issuer: "https://issuer.example.test", Audiences: []string{"latchway-api"},
		AllowedAlgorithms: []string{"HS256"}, Keys: hsSource,
		Now: func() time.Time { return verifierTestNow },
	})
	verifySigned(t, hsVerifier, signToken(t, jwt.SigningMethodHS256, secret, "", validClaims()))
}

func TestJWTVerifierHonorsExplicitZeroClockSkew(t *testing.T) {
	key := mustRSAKey(t)
	keys := mustStaticKeys(t, map[string]any{"key-1": &key.PublicKey})
	base := VerifierConfig{
		ProviderID: "oidc_test", Issuer: "https://issuer.example.test", Audiences: []string{"latchway-api"},
		AllowedAlgorithms: []string{"RS256"}, Keys: keys, Now: func() time.Time { return verifierTestNow },
	}
	claims := validClaims()
	claims["iat"] = verifierTestNow.Add(time.Second).Unix()
	claims["nbf"] = verifierTestNow.Add(time.Second).Unix()
	raw := signToken(t, jwt.SigningMethodRS256, key, "key-1", claims)

	defaultVerifier := mustJWTVerifier(t, base)
	verifySigned(t, defaultVerifier, raw)

	base.ClockSkewSet = true
	zeroSkewVerifier := mustJWTVerifier(t, base)
	assertVerifyError(t, zeroSkewVerifier, raw, ErrCredentialInvalid)
}

func TestJWTVerifierRejectsInvalidRegisteredClaims(t *testing.T) {
	key := mustRSAKey(t)
	verifier := mustJWTVerifier(t, VerifierConfig{
		ProviderID: "oidc_test", Issuer: "https://issuer.example.test", Audiences: []string{"latchway-api"},
		AllowedAlgorithms: []string{"RS256"}, MaxTokenLifetime: 2 * time.Hour,
		AuthorizedParties: []string{"app-1"}, RequiredClaims: []string{"email"},
		Keys: mustStaticKeys(t, map[string]any{"key-1": &key.PublicKey}), Now: func() time.Time { return verifierTestNow },
	})

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{name: "issuer", mutate: func(c map[string]any) { c["iss"] = "https://attacker.example" }, want: ErrCredentialInvalid},
		{name: "audience", mutate: func(c map[string]any) { c["aud"] = "other-api" }, want: ErrCredentialInvalid},
		{name: "missing expiration", mutate: func(c map[string]any) { delete(c, "exp") }, want: ErrCredentialInvalid},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = verifierTestNow.Add(-time.Hour).Unix() }, want: ErrCredentialExpired},
		{name: "missing issued at", mutate: func(c map[string]any) { delete(c, "iat") }, want: ErrCredentialInvalid},
		{name: "future issued at", mutate: func(c map[string]any) { c["iat"] = verifierTestNow.Add(10 * time.Minute).Unix() }, want: ErrCredentialInvalid},
		{name: "future not before", mutate: func(c map[string]any) { c["nbf"] = verifierTestNow.Add(10 * time.Minute).Unix() }, want: ErrCredentialInvalid},
		{name: "excessive lifetime", mutate: func(c map[string]any) { c["exp"] = verifierTestNow.Add(3 * time.Hour).Unix() }, want: ErrCredentialInvalid},
		{name: "empty subject", mutate: func(c map[string]any) { c["sub"] = "  " }, want: ErrCredentialInvalid},
		{name: "missing authorized party", mutate: func(c map[string]any) { delete(c, "azp") }, want: ErrCredentialInvalid},
		{name: "wrong authorized party", mutate: func(c map[string]any) { c["azp"] = "attacker" }, want: ErrCredentialInvalid},
		{name: "missing required claim", mutate: func(c map[string]any) { delete(c, "email") }, want: ErrCredentialInvalid},
		{name: "empty required claim", mutate: func(c map[string]any) { c["email"] = "" }, want: ErrCredentialInvalid},
		{name: "future auth time", mutate: func(c map[string]any) { c["auth_time"] = verifierTestNow.Add(10 * time.Minute).Unix() }, want: ErrCredentialInvalid},
		{name: "auth time after expiry", mutate: func(c map[string]any) { c["auth_time"] = verifierTestNow.Add(2 * time.Hour).Unix() }, want: ErrCredentialInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validClaims()
			claims["azp"] = "app-1"
			claims["email"] = "user@example.test"
			test.mutate(claims)
			credential, err := NewRawIdentityCredential(signToken(t, jwt.SigningMethodRS256, key, "key-1", claims))
			if err != nil {
				t.Fatalf("construct credential: %v", err)
			}
			_, err = verifier.Verify(context.Background(), credential)
			if !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestJWTVerifierRejectsAlgorithmConfusionAndTokenSelectedKeys(t *testing.T) {
	key := mustRSAKey(t)
	verifier := mustJWTVerifier(t, VerifierConfig{
		ProviderID: "oidc_test", Issuer: "https://issuer.example.test", Audiences: []string{"latchway-api"},
		AllowedAlgorithms: []string{"RS256"}, Keys: mustStaticKeys(t, map[string]any{"trusted": &key.PublicKey}),
		Now: func() time.Time { return verifierTestNow },
	})

	hmacToken := signToken(t, jwt.SigningMethodHS256, []byte("0123456789abcdef0123456789abcdef"), "trusted", validClaims())
	assertVerifyError(t, verifier, hmacToken, ErrCredentialInvalid)
	assertVerifyError(t, verifier, signToken(t, jwt.SigningMethodRS256, key, "unknown", validClaims()), ErrKeyUnavailable)

	for _, field := range []string{"jku", "jwk", "x5u"} {
		t.Run(field, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(validClaims()))
			token.Header["kid"] = "trusted"
			token.Header[field] = "https://attacker.example/key"
			raw, err := token.SignedString(key)
			if err != nil {
				t.Fatalf("sign token: %v", err)
			}
			assertVerifyError(t, verifier, raw, ErrCredentialInvalid)
		})
	}
}

func TestJWTVerifierRejectsDuplicateAndNonCanonicalJWTJSON(t *testing.T) {
	key := mustRSAKey(t)
	verifier := mustJWTVerifier(t, VerifierConfig{
		ProviderID: "oidc_test", Issuer: "https://issuer.example.test", Audiences: []string{"latchway-api"},
		AllowedAlgorithms: []string{"RS256"}, Keys: mustStaticKeys(t, map[string]any{"trusted": &key.PublicKey}),
		Now: func() time.Time { return verifierTestNow },
	})
	header := `{"alg":"RS256","kid":"trusted","alg":"HS256"}`
	payloadBytes, err := json.Marshal(validClaims())
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	assertVerifyError(t, verifier, signRawRS256(t, key, header, string(payloadBytes)), ErrCredentialInvalid)

	payload := fmt.Sprintf(`{"iss":"https://issuer.example.test","aud":"latchway-api","sub":"user-123","sub":"attacker","iat":%d,"nbf":%d,"exp":%d,"auth_time":%d}`,
		verifierTestNow.Add(-time.Minute).Unix(), verifierTestNow.Add(-time.Minute).Unix(), verifierTestNow.Add(time.Hour).Unix(), verifierTestNow.Add(-10*time.Minute).Unix())
	assertVerifyError(t, verifier, signRawRS256(t, key, `{"alg":"RS256","kid":"trusted"}`, payload), ErrCredentialInvalid)

	valid := signToken(t, jwt.SigningMethodRS256, key, "trusted", validClaims())
	parts := strings.Split(valid, ".")
	parts[0] += "="
	assertVerifyError(t, verifier, strings.Join(parts, "."), ErrCredentialInvalid)
}

func TestJWTVerifierConfigurationAndClaimMapperAreBounded(t *testing.T) {
	key := mustRSAKey(t)
	keys := mustStaticKeys(t, map[string]any{"key": &key.PublicKey})
	base := VerifierConfig{
		ProviderID: "oidc_test", Issuer: "https://issuer.example.test", Audiences: []string{"api"},
		AllowedAlgorithms: []string{"RS256"}, Keys: keys,
	}
	tests := []struct {
		name   string
		mutate func(*VerifierConfig)
	}{
		{name: "non HTTPS issuer", mutate: func(c *VerifierConfig) { c.Issuer = "http://issuer.example.test" }},
		{name: "issuer query", mutate: func(c *VerifierConfig) { c.Issuer += "?key=value" }},
		{name: "duplicate audience", mutate: func(c *VerifierConfig) { c.Audiences = []string{"api", "api"} }},
		{name: "duplicate algorithm", mutate: func(c *VerifierConfig) { c.AllowedAlgorithms = []string{"RS256", "RS256"} }},
		{name: "mixed symmetric", mutate: func(c *VerifierConfig) { c.AllowedAlgorithms = []string{"RS256", "HS256"} }},
		{name: "duplicate authorized party", mutate: func(c *VerifierConfig) { c.AuthorizedParties = []string{"app", "app"} }},
		{name: "duplicate required claim", mutate: func(c *VerifierConfig) { c.RequiredClaims = []string{"email", "email"} }},
		{name: "invalid mapping", mutate: func(c *VerifierConfig) { c.Mapper = PathMapper{"Bad": "email"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := NewJWTVerifier(config); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("expected configuration error, got %v", err)
			}
		})
	}
}

func TestRawIdentityCredentialIsRedactedAndBounded(t *testing.T) {
	const raw = "secret.identity.credential"
	credential, err := NewRawIdentityCredential(raw)
	if err != nil {
		t.Fatalf("construct credential: %v", err)
	}
	if strings.Contains(fmt.Sprint(credential), raw) || strings.Contains(fmt.Sprintf("%#v", credential), raw) {
		t.Fatal("credential formatting disclosed the raw value")
	}
	if _, err := NewRawIdentityCredential(strings.Repeat("x", maxIdentityCredentialBytes)); err != nil {
		t.Fatalf("OpenAPI-maximum identity credential was rejected: %v", err)
	}
	for _, invalid := range []string{"", "line\nbreak", strings.Repeat("x", maxIdentityCredentialBytes+1)} {
		if _, err := NewRawIdentityCredential(invalid); !errors.Is(err, ErrCredentialInvalid) {
			t.Fatalf("expected invalid credential for bounded input, got %v", err)
		}
	}
}

func TestStaticKeySourceRequiresExactKeyID(t *testing.T) {
	key := mustRSAKey(t)
	named := mustStaticKeys(t, map[string]any{"named": &key.PublicKey})
	if _, err := named.Key(context.Background(), "", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("a named key must not accept a missing kid: %v", err)
	}
	unnamed := mustStaticKeys(t, map[string]any{"": &key.PublicKey})
	if _, err := unnamed.Key(context.Background(), "", "RS256"); err != nil {
		t.Fatalf("a sole explicitly unnamed key should accept an omitted kid: %v", err)
	}
	if _, err := unnamed.Key(context.Background(), "named", "RS256"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("an unnamed key must not accept a supplied kid: %v", err)
	}
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":       "https://issuer.example.test",
		"aud":       "latchway-api",
		"sub":       "user-123",
		"iat":       verifierTestNow.Add(-time.Minute).Unix(),
		"nbf":       verifierTestNow.Add(-time.Minute).Unix(),
		"exp":       verifierTestNow.Add(time.Hour).Unix(),
		"auth_time": verifierTestNow.Add(-10 * time.Minute).Unix(),
	}
}

func mustJWTVerifier(t *testing.T, config VerifierConfig) *JWTVerifier {
	t.Helper()
	verifier, err := NewJWTVerifier(config)
	if err != nil {
		t.Fatalf("construct verifier: %v", err)
	}
	return verifier
}

func mustStaticKeys(t *testing.T, keys map[string]any) *StaticKeySource {
	t.Helper()
	source, err := NewStaticKeySource(keys)
	if err != nil {
		t.Fatalf("construct static keys: %v", err)
	}
	return source
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func signToken(t *testing.T, method jwt.SigningMethod, key any, kid string, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims(claims))
	if kid != "" {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

func signRawRS256(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign raw token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func verifySigned(t *testing.T, verifier *JWTVerifier, raw string) {
	t.Helper()
	credential, err := NewRawIdentityCredential(raw)
	if err != nil {
		t.Fatalf("construct credential: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), credential); err != nil {
		t.Fatalf("verify signed token: %v", err)
	}
}

func assertVerifyError(t *testing.T, verifier *JWTVerifier, raw string, target error) {
	t.Helper()
	credential, err := NewRawIdentityCredential(raw)
	if err != nil {
		if errors.Is(err, target) {
			return
		}
		t.Fatalf("construct credential: %v", err)
	}
	_, err = verifier.Verify(context.Background(), credential)
	if !errors.Is(err, target) {
		t.Fatalf("expected %v, got %v", target, err)
	}
}
