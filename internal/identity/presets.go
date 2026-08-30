package identity

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const firebasePublicCertificatesURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

var firebaseProjectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// PresetCommon contains provider-independent verifier controls.
type PresetCommon struct {
	ProviderID        string
	Mapper            ClaimMapper
	SubjectClaim      string
	RequiredClaims    []string
	AuthorizedParties []string
	Client            *http.Client
	SharedCache       RemoteKeyDocumentCache
	Now               func() time.Time
	ClockSkew         time.Duration
	ClockSkewSet      bool
	MaxTokenLifetime  time.Duration
}

// FirebasePreset configures Firebase Authentication ID-token verification.
type FirebasePreset struct {
	PresetCommon
	ProjectID string
}

// NewFirebaseVerifier derives only the official issuer, audience, algorithm,
// and public-certificate endpoint from a validated Google project ID.
func NewFirebaseVerifier(config FirebasePreset) (*JWTVerifier, error) {
	if !firebaseProjectIDPattern.MatchString(config.ProjectID) {
		return nil, fmt.Errorf("%w: Firebase project ID", ErrConfiguration)
	}
	providerID := config.ProviderID
	if providerID == "" {
		providerID = "firebase"
	}
	issuer := "https://securetoken.google.com/" + config.ProjectID
	keys, err := NewRemoteKeySource(remoteConfig(config.PresetCommon, issuer, firebasePublicCertificatesURL, RemoteKeyFormatX509Certificate))
	if err != nil {
		return nil, err
	}
	return NewJWTVerifier(VerifierConfig{
		ProviderID: providerID, Issuer: issuer,
		Audiences: []string{config.ProjectID}, AllowedAlgorithms: []string{"RS256"},
		AuthorizedParties: config.AuthorizedParties, SubjectClaim: config.SubjectClaim,
		RequiredClaims: mergeRequiredClaims([]string{"auth_time"}, config.RequiredClaims),
		Mapper:         config.Mapper, Keys: keys,
		ClockSkew: config.ClockSkew, ClockSkewSet: config.ClockSkewSet,
		MaxTokenLifetime: config.MaxTokenLifetime, Now: config.Now,
	})
}

// SupabasePreset configures asymmetric Supabase Auth JWT verification.
type SupabasePreset struct {
	PresetCommon
	ProjectURL        string
	Issuer            string
	Audiences         []string
	AllowedAlgorithms []string
}

// NewSupabaseVerifier derives the Auth issuer and JWKS endpoint from the fixed
// project origin. Symmetric algorithms are deliberately rejected here.
func NewSupabaseVerifier(config SupabasePreset) (*JWTVerifier, error) {
	origin, err := projectOrigin(config.ProjectURL)
	if err != nil {
		return nil, fmt.Errorf("%w: Supabase project URL", ErrConfiguration)
	}
	issuer := strings.TrimSuffix(origin.String(), "/") + "/auth/v1"
	if config.Issuer != "" {
		issuer = config.Issuer
	}
	audiences := config.Audiences
	if len(audiences) == 0 {
		audiences = []string{"authenticated"}
	}
	algorithms := config.AllowedAlgorithms
	if len(algorithms) == 0 {
		algorithms = []string{"RS256", "ES256"}
	}
	for _, algorithm := range algorithms {
		if algorithm != "RS256" && algorithm != "ES256" {
			return nil, fmt.Errorf("%w: Supabase asymmetric algorithm", ErrConfiguration)
		}
	}
	providerID := config.ProviderID
	if providerID == "" {
		providerID = "supabase"
	}
	keys, err := NewRemoteKeySource(remoteConfig(config.PresetCommon, issuer, strings.TrimSuffix(origin.String(), "/")+"/auth/v1/.well-known/jwks.json", RemoteKeyFormatJWKS))
	if err != nil {
		return nil, err
	}
	return NewJWTVerifier(VerifierConfig{
		ProviderID: providerID, Issuer: issuer, Audiences: audiences, AllowedAlgorithms: algorithms,
		AuthorizedParties: config.AuthorizedParties, SubjectClaim: config.SubjectClaim,
		RequiredClaims: config.RequiredClaims, Mapper: config.Mapper, Keys: keys,
		ClockSkew: config.ClockSkew, ClockSkewSet: config.ClockSkewSet,
		MaxTokenLifetime: config.MaxTokenLifetime, Now: config.Now,
	})
}

// NewSupabaseHS256Verifier is the explicit legacy symmetric path. No secret is
// fetched from Supabase; the caller must resolve it from protected storage.
func NewSupabaseHS256Verifier(config SupabasePreset, secret []byte, acknowledgeRisk bool) (*JWTVerifier, error) {
	origin, err := projectOrigin(config.ProjectURL)
	if err != nil {
		return nil, fmt.Errorf("%w: Supabase project URL", ErrConfiguration)
	}
	issuer := strings.TrimSuffix(origin.String(), "/") + "/auth/v1"
	if config.Issuer != "" {
		issuer = config.Issuer
	}
	audiences := config.Audiences
	if len(audiences) == 0 {
		audiences = []string{"authenticated"}
	}
	providerID := config.ProviderID
	if providerID == "" {
		providerID = "supabase"
	}
	keys, err := NewSymmetricKeySource(secret, acknowledgeRisk)
	if err != nil {
		return nil, err
	}
	return NewJWTVerifier(VerifierConfig{
		ProviderID: providerID, Issuer: issuer, Audiences: audiences, AllowedAlgorithms: []string{"HS256"},
		AuthorizedParties: config.AuthorizedParties, SubjectClaim: config.SubjectClaim,
		RequiredClaims: config.RequiredClaims, Mapper: config.Mapper, Keys: keys,
		ClockSkew: config.ClockSkew, ClockSkewSet: config.ClockSkewSet,
		MaxTokenLifetime: config.MaxTokenLifetime, Now: config.Now,
	})
}

// ClerkPreset configures Clerk session-token verification using either a
// fixed JWKS endpoint or one explicitly configured public key.
type ClerkPreset struct {
	PresetCommon
	Issuer            string
	Audiences         []string
	AuthorizedParties []string
	JWKSURL           string
	StaticPublicKey   any
	StaticKeyID       string
}

func NewClerkVerifier(config ClerkPreset) (*JWTVerifier, error) {
	issuer, err := canonicalHTTPSURL(config.Issuer, false)
	if err != nil {
		return nil, fmt.Errorf("%w: Clerk issuer", ErrConfiguration)
	}
	if len(config.Audiences) == 0 {
		return nil, fmt.Errorf("%w: Clerk audience", ErrConfiguration)
	}
	providerID := config.ProviderID
	if providerID == "" {
		providerID = "clerk"
	}
	var keys VerificationKeySource
	if config.StaticPublicKey != nil {
		if config.JWKSURL != "" {
			return nil, fmt.Errorf("%w: Clerk key source", ErrConfiguration)
		}
		keys, err = NewStaticKeySource(map[string]any{config.StaticKeyID: config.StaticPublicKey})
	} else {
		keyURL := config.JWKSURL
		if keyURL == "" {
			keyURL = strings.TrimSuffix(issuer, "/") + "/.well-known/jwks.json"
		}
		keys, err = NewRemoteKeySource(remoteConfig(config.PresetCommon, issuer, keyURL, RemoteKeyFormatJWKS))
	}
	if err != nil {
		return nil, err
	}
	return NewJWTVerifier(VerifierConfig{
		ProviderID: providerID, Issuer: issuer, Audiences: config.Audiences, AllowedAlgorithms: []string{"RS256"},
		AuthorizedParties: firstNonEmptyStrings(config.AuthorizedParties, config.PresetCommon.AuthorizedParties),
		SubjectClaim:      config.SubjectClaim,
		RequiredClaims:    mergeRequiredClaims([]string{"sid"}, config.RequiredClaims),
		Mapper:            config.Mapper,
		Keys:              keys, ClockSkew: config.ClockSkew, ClockSkewSet: config.ClockSkewSet,
		MaxTokenLifetime: config.MaxTokenLifetime, Now: config.Now,
	})
}

func mergeRequiredClaims(mandatory, configured []string) []string {
	result := make([]string, 0, len(mandatory)+len(configured))
	seen := make(map[string]struct{}, len(mandatory)+len(configured))
	for _, claims := range [][]string{mandatory, configured} {
		for _, claim := range claims {
			if _, exists := seen[claim]; exists {
				continue
			}
			seen[claim] = struct{}{}
			result = append(result, claim)
		}
	}
	return result
}

func firstNonEmptyStrings(preferred, fallback []string) []string {
	if len(preferred) != 0 {
		return preferred
	}
	return fallback
}

// NewStaticPublicKeyVerifier binds a generic verifier to a configured public
// key. It never accepts symmetric methods.
func NewStaticPublicKeyVerifier(config VerifierConfig, keyID string, publicKey any) (*JWTVerifier, error) {
	for _, algorithm := range config.AllowedAlgorithms {
		if algorithm == "HS256" {
			return nil, fmt.Errorf("%w: static public-key algorithm", ErrConfiguration)
		}
	}
	keys, err := NewStaticKeySource(map[string]any{keyID: publicKey})
	if err != nil {
		return nil, err
	}
	config.Keys = keys
	return NewJWTVerifier(config)
}

// NewExplicitHS256Verifier binds a generic verifier to an operator-provided
// secret only after risk acknowledgement.
func NewExplicitHS256Verifier(config VerifierConfig, secret []byte, acknowledgeRisk bool) (*JWTVerifier, error) {
	keys, err := NewSymmetricKeySource(secret, acknowledgeRisk)
	if err != nil {
		return nil, err
	}
	config.AllowedAlgorithms = []string{"HS256"}
	config.Keys = keys
	return NewJWTVerifier(config)
}

func remoteConfig(common PresetCommon, issuer, endpoint string, format RemoteKeyFormat) RemoteKeySourceConfig {
	return RemoteKeySourceConfig{
		URL: endpoint, Issuer: issuer, Format: format,
		Client: common.Client, SharedCache: common.SharedCache, Now: common.Now,
	}
}

func projectOrigin(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") {
		return nil, ErrConfiguration
	}
	parsed.Path = ""
	parsed.RawPath = ""
	if parsed.String() != strings.TrimSuffix(raw, "/") {
		return nil, ErrConfiguration
	}
	return parsed, nil
}

func canonicalHTTPSURL(raw string, requireOrigin bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrConfiguration
	}
	if requireOrigin && parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return "", ErrConfiguration
	}
	if parsed.String() != raw {
		return "", ErrConfiguration
	}
	return raw, nil
}
