package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/identity"
)

func TestCoordinatorBuildsStaticSecretVerifierWithAllConfiguredControls(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	provider := configuration.IdentityProvider{
		ID: "custom", Type: "custom_jwt", Issuer: "https://identity.example.test",
		Audiences: []string{"latchway-app"}, AuthorizedParties: []string{"mobile-app"},
		AllowedAlgorithms: []string{"RS256"}, StaticPublicKeySecretRef: "secret/identity-key",
		SubjectClaim: "uid", RequiredClaims: []string{"tenant"},
		ClaimMappings: map[string]string{"plan": "claims.plan"},
	}
	coordinator := &clientCoordinator{now: func() time.Time { return now }}
	verifier, err := coordinator.buildSecretIdentityVerifier(provider, publicPEM)
	if err != nil {
		t.Fatalf("construct static verifier: %v", err)
	}
	claims := jwt.MapClaims{
		"iss": provider.Issuer, "aud": provider.Audiences[0], "sub": "ignored-subject",
		"uid": "application-user", "tenant": "production", "azp": "mobile-app",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"plan": "pro",
	}
	credential := signedIdentityCredential(t, jwt.SigningMethodRS256, privateKey, claims)
	principal, err := verifier.Verify(context.Background(), credential)
	if err != nil {
		t.Fatalf("verify static identity token: %v", err)
	}
	if principal.Subject != "application-user" || principal.Claims["plan"] != "pro" {
		t.Fatalf("principal = %#v", principal)
	}
	delete(claims, "tenant")
	credential = signedIdentityCredential(t, jwt.SigningMethodRS256, privateKey, claims)
	if _, err := verifier.Verify(context.Background(), credential); !errors.Is(err, identity.ErrCredentialInvalid) {
		t.Fatalf("missing configured claim error = %v", err)
	}
}

func TestCoordinatorSymmetricVerifierUsesOnlyCallbackMaterial(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	provider := configuration.IdentityProvider{
		ID: "legacy", Type: "custom_jwt", Issuer: "https://identity.example.test",
		Audiences: []string{"latchway-app"}, AllowedAlgorithms: []string{"HS256"},
		SymmetricSecretRef: "secret/legacy-hmac", AcknowledgeSymmetricRisk: true,
		SubjectClaim: "sub",
	}
	material := []byte("0123456789abcdef0123456789abcdef")
	coordinator := &clientCoordinator{now: func() time.Time { return now }}
	verifier, err := coordinator.buildSecretIdentityVerifier(provider, material)
	if err != nil {
		t.Fatalf("construct symmetric verifier: %v", err)
	}
	claims := jwt.MapClaims{
		"iss": provider.Issuer, "aud": provider.Audiences[0], "sub": "application-user",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	credential := signedIdentityCredential(t, jwt.SigningMethodHS256, material, claims)
	if _, err := verifier.Verify(context.Background(), credential); err != nil {
		t.Fatalf("verify symmetric identity token: %v", err)
	}
	clear(material)
	if _, err := verifier.Verify(context.Background(), credential); !errors.Is(err, identity.ErrCredentialInvalid) {
		t.Fatalf("verifier retained a usable copy after callback material clearing: %v", err)
	}
}

func TestCoordinatorRejectsEveryAmbiguousIdentitySourcePair(t *testing.T) {
	coordinator := &clientCoordinator{}
	tests := []struct {
		name     string
		provider configuration.IdentityProvider
	}{
		{name: "Clerk JWKS and static", provider: configuration.IdentityProvider{ID: "clerk", Type: "clerk", JWKSURL: "https://keys.example.test/jwks", StaticPublicKeySecretRef: "secret/public"}},
		{name: "Clerk JWKS and symmetric", provider: configuration.IdentityProvider{ID: "clerk", Type: "clerk", JWKSURL: "https://keys.example.test/jwks", SymmetricSecretRef: "secret/symmetric"}},
		{name: "Clerk static and symmetric", provider: configuration.IdentityProvider{ID: "clerk", Type: "clerk", StaticPublicKeySecretRef: "secret/public", SymmetricSecretRef: "secret/symmetric"}},
		{name: "generic JWKS and static", provider: configuration.IdentityProvider{ID: "generic", Type: "generic_oidc", JWKSURL: "https://keys.example.test/jwks", StaticPublicKeySecretRef: "secret/public"}},
		{name: "generic JWKS and symmetric", provider: configuration.IdentityProvider{ID: "generic", Type: "generic_oidc", JWKSURL: "https://keys.example.test/jwks", SymmetricSecretRef: "secret/symmetric"}},
		{name: "generic static and symmetric", provider: configuration.IdentityProvider{ID: "generic", Type: "generic_oidc", StaticPublicKeySecretRef: "secret/public", SymmetricSecretRef: "secret/symmetric"}},
		{name: "custom JWKS and static", provider: configuration.IdentityProvider{ID: "custom", Type: "custom_jwt", JWKSURL: "https://keys.example.test/jwks", StaticPublicKeySecretRef: "secret/public"}},
		{name: "custom JWKS and symmetric", provider: configuration.IdentityProvider{ID: "custom", Type: "custom_jwt", JWKSURL: "https://keys.example.test/jwks", SymmetricSecretRef: "secret/symmetric"}},
		{name: "custom static and symmetric", provider: configuration.IdentityProvider{ID: "custom", Type: "custom_jwt", StaticPublicKeySecretRef: "secret/public", SymmetricSecretRef: "secret/symmetric"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := coordinator.identityVerifier(clientEnvironment{}, configuration.ActiveSnapshot{}, test.provider)
			if !errors.Is(err, identity.ErrConfiguration) {
				t.Fatalf("ambiguous source error = %v", err)
			}
		})
	}
}

func TestCoordinatorRuntimeIdentitySourceMatrix(t *testing.T) {
	tests := []struct {
		name     string
		provider configuration.IdentityProvider
		wantErr  bool
	}{
		{name: "Firebase derived source", provider: configuration.IdentityProvider{Type: "firebase"}},
		{name: "Firebase override", provider: configuration.IdentityProvider{Type: "firebase", JWKSURL: "https://keys.example.test/jwks"}, wantErr: true},
		{name: "Supabase derived source", provider: configuration.IdentityProvider{Type: "supabase"}},
		{name: "Supabase static override", provider: configuration.IdentityProvider{Type: "supabase", StaticPublicKeySecretRef: "secret/public"}, wantErr: true},
		{name: "Clerk derived source", provider: configuration.IdentityProvider{Type: "clerk"}},
		{name: "Clerk explicit JWKS", provider: configuration.IdentityProvider{Type: "clerk", JWKSURL: "https://keys.example.test/jwks"}},
		{name: "Clerk static source", provider: configuration.IdentityProvider{Type: "clerk", StaticPublicKeySecretRef: "secret/public"}},
		{name: "Clerk JWKS and static", provider: configuration.IdentityProvider{Type: "clerk", JWKSURL: "https://keys.example.test/jwks", StaticPublicKeySecretRef: "secret/public"}, wantErr: true},
		{name: "Clerk JWKS and symmetric", provider: configuration.IdentityProvider{Type: "clerk", JWKSURL: "https://keys.example.test/jwks", SymmetricSecretRef: "secret/symmetric"}, wantErr: true},
		{name: "generic JWKS", provider: configuration.IdentityProvider{Type: "generic_oidc", JWKSURL: "https://keys.example.test/jwks"}},
		{name: "generic static", provider: configuration.IdentityProvider{Type: "generic_oidc", StaticPublicKeySecretRef: "secret/public"}},
		{name: "generic missing source", provider: configuration.IdentityProvider{Type: "generic_oidc"}, wantErr: true},
		{name: "generic JWKS and static", provider: configuration.IdentityProvider{Type: "generic_oidc", JWKSURL: "https://keys.example.test/jwks", StaticPublicKeySecretRef: "secret/public"}, wantErr: true},
		{name: "generic JWKS and symmetric", provider: configuration.IdentityProvider{Type: "generic_oidc", JWKSURL: "https://keys.example.test/jwks", SymmetricSecretRef: "secret/symmetric"}, wantErr: true},
		{name: "custom JWKS", provider: configuration.IdentityProvider{Type: "custom_jwt", JWKSURL: "https://keys.example.test/jwks"}},
		{name: "custom static", provider: configuration.IdentityProvider{Type: "custom_jwt", StaticPublicKeySecretRef: "secret/public"}},
		{name: "custom symmetric", provider: configuration.IdentityProvider{Type: "custom_jwt", SymmetricSecretRef: "secret/symmetric"}},
		{name: "custom missing source", provider: configuration.IdentityProvider{Type: "custom_jwt"}, wantErr: true},
		{name: "custom JWKS and static", provider: configuration.IdentityProvider{Type: "custom_jwt", JWKSURL: "https://keys.example.test/jwks", StaticPublicKeySecretRef: "secret/public"}, wantErr: true},
		{name: "custom JWKS and symmetric", provider: configuration.IdentityProvider{Type: "custom_jwt", JWKSURL: "https://keys.example.test/jwks", SymmetricSecretRef: "secret/symmetric"}, wantErr: true},
		{name: "custom static and symmetric", provider: configuration.IdentityProvider{Type: "custom_jwt", StaticPublicKeySecretRef: "secret/public", SymmetricSecretRef: "secret/symmetric"}, wantErr: true},
		{name: "unknown provider", provider: configuration.IdentityProvider{Type: "legacy", JWKSURL: "https://keys.example.test/jwks"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateIdentityKeySources(test.provider)
			if test.wantErr && !errors.Is(err, identity.ErrConfiguration) {
				t.Fatalf("error = %v, want identity configuration error", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCoordinatorPrevalidatesExchangeDPoPBindingsAndCurrentSkew(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	target := mustCoordinatorURL(t, "https://gateway.example.test/client/v1/sessions")
	privateKey, _, jkt := newChallengeKey(t)
	proof := signedSessionDPoP(t, privateKey, http.MethodPost, target, now, "coordinator-exchange")
	input := clientapi.ExchangeInput{Metadata: clientapi.RequestMetadata{
		HTTPMethod: http.MethodPost, TargetURL: *target,
		DPoPProof: clientapi.NewSensitiveString(proof.value),
	}}
	if _, err := prevalidateExchangeDPoP(input, jkt, now, 0); err != nil {
		t.Fatalf("valid exchange proof error = %v", err)
	}

	wrongTarget := input
	wrongTarget.Metadata.TargetURL = *mustCoordinatorURL(t, "https://gateway.example.test/client/v1/sessions/refresh")
	if _, err := prevalidateExchangeDPoP(wrongTarget, jkt, now, 0); !dpop.IsCode(err, "dpop_invalid") {
		t.Fatalf("wrong trusted target error = %v", err)
	}

	_, _, wrongJKT := newChallengeKey(t)
	if _, err := prevalidateExchangeDPoP(input, wrongJKT, now, 0); !dpop.IsCode(err, "dpop_invalid") {
		t.Fatalf("wrong challenge key error = %v", err)
	}

	futureProof := signedSessionDPoP(t, privateKey, http.MethodPost, target, now.Add(30*time.Second), "coordinator-future-exchange")
	futureInput := input
	futureInput.Metadata.DPoPProof = clientapi.NewSensitiveString(futureProof.value)
	if _, err := prevalidateExchangeDPoP(futureInput, jkt, now, 0); !dpop.IsCode(err, "dpop_invalid") {
		t.Fatalf("future proof without current skew error = %v", err)
	}
	if _, err := prevalidateExchangeDPoP(futureInput, jkt, now, 30*time.Second); err != nil {
		t.Fatalf("future proof within current skew error = %v", err)
	}
}

func mustCoordinatorURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return parsed
}

func TestPlatformOriginAuthorityFailsClosed(t *testing.T) {
	web := configuration.PlatformAttestation{
		Provider: "turnstile", Mode: "required",
		AllowedOrigins: []string{"https://app.example.test", "https://admin.example.test:8443"},
	}
	if !platformOriginAllowed(web, "web", "https://app.example.test") {
		t.Fatal("configured exact web origin was rejected")
	}
	for _, origin := range []string{"", "https://APP.example.test", "https://app.example.test/", "https://other.example.test"} {
		if platformOriginAllowed(web, "web", origin) {
			t.Fatalf("unconfigured or noncanonical web origin %q was accepted", origin)
		}
	}
	native := configuration.PlatformAttestation{Provider: "app_attest", Mode: "required"}
	if !platformOriginAllowed(native, "ios", "") || platformOriginAllowed(native, "ios", "https://app.example.test") {
		t.Fatal("native Origin authority did not require absence")
	}
	native.AllowedOrigins = []string{"https://app.example.test"}
	if platformOriginAllowed(native, "ios", "") {
		t.Fatal("corrupt native allowed-origin policy was accepted")
	}
	web.AllowedOrigins = append(web.AllowedOrigins, web.AllowedOrigins[0])
	if platformOriginAllowed(web, "web", "https://app.example.test") {
		t.Fatal("duplicate configured web origin was accepted")
	}
}

func TestCoordinatorRejectsSymmetricAlgorithmOrProviderMismatch(t *testing.T) {
	coordinator := &clientCoordinator{now: time.Now}
	base := configuration.IdentityProvider{
		ID: "legacy", Type: "custom_jwt", Issuer: "https://identity.example.test",
		Audiences: []string{"latchway-app"}, AllowedAlgorithms: []string{"HS256"},
		SymmetricSecretRef: "secret/legacy-hmac", AcknowledgeSymmetricRisk: true,
		SubjectClaim: "sub",
	}
	tests := []struct {
		name string
		edit func(*configuration.IdentityProvider)
	}{
		{name: "generic provider", edit: func(provider *configuration.IdentityProvider) { provider.Type = "generic_oidc" }},
		{name: "Supabase provider", edit: func(provider *configuration.IdentityProvider) {
			provider.Type = "supabase"
			provider.ProjectURL = "https://project.supabase.co"
		}},
		{name: "declared asymmetric algorithm", edit: func(provider *configuration.IdentityProvider) { provider.AllowedAlgorithms = []string{"RS256"} }},
		{name: "mixed algorithms", edit: func(provider *configuration.IdentityProvider) {
			provider.AllowedAlgorithms = []string{"HS256", "RS256"}
		}},
		{name: "risk not acknowledged", edit: func(provider *configuration.IdentityProvider) { provider.AcknowledgeSymmetricRisk = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := base
			test.edit(&provider)
			if _, err := coordinator.buildSecretIdentityVerifier(provider, []byte("0123456789abcdef0123456789abcdef")); !errors.Is(err, identity.ErrConfiguration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestClientGrantRequiresExactPositiveDurations(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	issued := IssuedSession{
		Access: IssuedAccess{
			Token:    AccessToken{value: string(make([]byte, 64))},
			IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		},
		Refresh:          RefreshToken{value: "0123456789abcdef0123456789abcdef"},
		RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	grant, err := clientGrant(issued)
	if err != nil {
		t.Fatalf("construct client grant: %v", err)
	}
	if grant.ExpiresIn != 600 || grant.RefreshExpiresIn != 86400 {
		t.Fatalf("grant durations = access %d refresh %d", grant.ExpiresIn, grant.RefreshExpiresIn)
	}
	issued.Access.ExpiresAt = issued.Access.ExpiresAt.Add(time.Nanosecond)
	if _, err := clientGrant(issued); err == nil {
		t.Fatal("fractional-second expiry was accepted")
	}
}

func TestCoordinatorMapsSafeDependencyErrors(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "expired identity", got: mapIdentityError(identity.ErrCredentialExpired), want: "identity_token_expired"},
		{name: "identity key outage", got: mapIdentityError(identity.ErrKeyUnavailable), want: "server_not_ready"},
		{name: "blocked user", got: mapUserResolutionError(identity.ErrUserBlocked), want: "identity_token_invalid"},
		{name: "user database outage", got: mapUserResolutionError(errors.New("postgres unavailable")), want: "server_not_ready"},
		{name: "Play Integrity outage", got: mapAttestationError(fmt.Errorf("upstream detail: %w", attestation.ErrPlayIntegrityService)), want: "server_not_ready"},
		{name: "App Attest key store outage", got: mapAttestationError(fmt.Errorf("database detail: %w", attestation.ErrAppAttestKeyStore)), want: "server_not_ready"},
		{name: "invalid attestation", got: mapAttestationError(attestation.ErrInvalid), want: "attestation_invalid"},
		{name: "DPoP invalid", got: mapDPoPError(&dpop.Error{Code: "dpop_invalid"}), want: "dpop_invalid"},
		{name: "DPoP replay", got: mapSessionError(ErrDPoPReplayed), want: "dpop_replayed"},
		{name: "access replay input", got: mapAccessRequestError(ErrReplayInvalid), want: "dpop_invalid"},
		{name: "access token expiry", got: mapAccessRequestError(ErrTokenExpired), want: "session_expired"},
		{name: "challenge consumed", got: mapSessionError(ErrChallengeConsumed), want: "conflict"},
		{name: "refresh reuse", got: mapSessionError(ErrRefreshReused), want: "refresh_token_reused"},
		{name: "installation revoked", got: mapSessionError(ErrInstallationRevoked), want: "installation_revoked"},
		{name: "policy step up", got: mapSessionError(ErrAttestationStepUpRequired), want: "attestation_step_up_required"},
		{name: "unknown internal", got: mapSessionError(errors.New("database included sensitive detail")), want: "internal_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("code = %q, want %q", test.got, test.want)
			}
		})
	}
}

func TestAttestationTelemetryOutcomeIsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "invalid evidence", err: attestation.ErrInvalid, want: "rejected"},
		{name: "unsupported evidence", err: attestation.ErrUnsupported, want: "rejected"},
		{name: "configuration", err: attestation.ErrConfiguration, want: "unavailable"},
		{name: "provider outage", err: fmt.Errorf("redacted wrapper: %w", attestation.ErrPlayIntegrityService), want: "unavailable"},
		{name: "store outage", err: fmt.Errorf("redacted wrapper: %w", attestation.ErrAppAttestKeyStore), want: "unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := attestationTelemetryOutcome(test.err); got != test.want {
				t.Fatalf("outcome=%q, want %q", got, test.want)
			}
		})
	}
}

func signedIdentityCredential(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) identity.RawIdentityCredential {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign identity token: %v", err)
	}
	credential, err := identity.NewRawIdentityCredential(raw)
	if err != nil {
		t.Fatalf("construct identity credential: %v", err)
	}
	return credential
}
