package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	maxJWTHeaderBytes  = 4 << 10
	maxJWTPayloadBytes = 24 << 10
)

var (
	providerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
	claimPathPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}(\.[A-Za-z][A-Za-z0-9_-]{0,127})*$`)
	allowedJWTAlgs    = map[string]struct{}{"RS256": {}, "RS384": {}, "RS512": {}, "ES256": {}, "ES384": {}, "HS256": {}}
)

type VerifierConfig struct {
	ProviderID        string
	Issuer            string
	Audiences         []string
	AllowedAlgorithms []string
	AuthorizedParties []string
	SubjectClaim      string
	ClockSkew         time.Duration
	MaxTokenLifetime  time.Duration
	RequiredClaims    []string
	Mapper            ClaimMapper
	Keys              VerificationKeySource
	Now               func() time.Time
}

type JWTVerifier struct {
	id                string
	issuer            string
	audiences         []string
	algorithms        []string
	algorithmSet      map[string]struct{}
	authorizedParties map[string]struct{}
	subjectClaim      string
	clockSkew         time.Duration
	maxTokenLifetime  time.Duration
	requiredClaims    []string
	mapper            ClaimMapper
	keys              VerificationKeySource
	now               func() time.Time
}

func NewJWTVerifier(config VerifierConfig) (*JWTVerifier, error) {
	if !providerIDPattern.MatchString(config.ProviderID) || len(config.Issuer) > 2048 || len(config.Audiences) == 0 || len(config.Audiences) > 32 || len(config.AllowedAlgorithms) == 0 || len(config.AllowedAlgorithms) > 6 || config.Keys == nil {
		return nil, ErrConfiguration
	}
	issuerURL, err := url.Parse(config.Issuer)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Hostname() == "" || issuerURL.User != nil || issuerURL.RawQuery != "" || issuerURL.Fragment != "" || issuerURL.String() != config.Issuer {
		return nil, fmt.Errorf("%w: issuer URL", ErrConfiguration)
	}
	if config.SubjectClaim == "" {
		config.SubjectClaim = "sub"
	}
	if !claimPathPattern.MatchString(config.SubjectClaim) {
		return nil, fmt.Errorf("%w: subject claim", ErrConfiguration)
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = 60 * time.Second
	}
	if config.ClockSkew < 0 || config.ClockSkew > 5*time.Minute {
		return nil, fmt.Errorf("%w: clock skew", ErrConfiguration)
	}
	if config.MaxTokenLifetime == 0 {
		config.MaxTokenLifetime = 24 * time.Hour
	}
	if config.MaxTokenLifetime < time.Minute || config.MaxTokenLifetime > 7*24*time.Hour {
		return nil, fmt.Errorf("%w: maximum token lifetime", ErrConfiguration)
	}
	if config.Mapper == nil {
		config.Mapper = PathMapper{}
	}
	if mapper, ok := config.Mapper.(PathMapper); ok {
		if err := mapper.validate(); err != nil {
			return nil, err
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	algorithmSet := make(map[string]struct{}, len(config.AllowedAlgorithms))
	algorithms := make([]string, 0, len(config.AllowedAlgorithms))
	for _, algorithm := range config.AllowedAlgorithms {
		if _, ok := allowedJWTAlgs[algorithm]; !ok {
			return nil, fmt.Errorf("%w: algorithm %s", ErrConfiguration, algorithm)
		}
		if _, duplicate := algorithmSet[algorithm]; duplicate {
			return nil, fmt.Errorf("%w: duplicate algorithm", ErrConfiguration)
		}
		algorithmSet[algorithm] = struct{}{}
		algorithms = append(algorithms, algorithm)
	}
	if _, symmetric := algorithmSet["HS256"]; symmetric && len(algorithmSet) != 1 {
		return nil, fmt.Errorf("%w: symmetric and asymmetric algorithms cannot be mixed", ErrConfiguration)
	}
	audiences := make([]string, 0, len(config.Audiences))
	audienceSet := make(map[string]struct{}, len(config.Audiences))
	for _, audience := range config.Audiences {
		if audience == "" || len(audience) > 256 {
			return nil, fmt.Errorf("%w: audience", ErrConfiguration)
		}
		if _, duplicate := audienceSet[audience]; duplicate {
			return nil, fmt.Errorf("%w: duplicate audience", ErrConfiguration)
		}
		audienceSet[audience] = struct{}{}
		audiences = append(audiences, audience)
	}
	authorizedParties := make(map[string]struct{}, len(config.AuthorizedParties))
	for _, party := range config.AuthorizedParties {
		if party == "" || len(party) > 256 {
			return nil, fmt.Errorf("%w: authorized party", ErrConfiguration)
		}
		if _, duplicate := authorizedParties[party]; duplicate {
			return nil, fmt.Errorf("%w: duplicate authorized party", ErrConfiguration)
		}
		authorizedParties[party] = struct{}{}
	}
	if len(config.RequiredClaims) > 32 {
		return nil, fmt.Errorf("%w: required claims", ErrConfiguration)
	}
	required := make([]string, 0, len(config.RequiredClaims))
	requiredSet := make(map[string]struct{}, len(config.RequiredClaims))
	for _, claim := range config.RequiredClaims {
		if !claimPathPattern.MatchString(claim) {
			return nil, fmt.Errorf("%w: required claim", ErrConfiguration)
		}
		if _, duplicate := requiredSet[claim]; duplicate {
			return nil, fmt.Errorf("%w: duplicate required claim", ErrConfiguration)
		}
		requiredSet[claim] = struct{}{}
		required = append(required, claim)
	}
	return &JWTVerifier{
		id: config.ProviderID, issuer: config.Issuer, audiences: audiences,
		algorithms: algorithms, algorithmSet: algorithmSet,
		authorizedParties: authorizedParties, subjectClaim: config.SubjectClaim,
		clockSkew: config.ClockSkew, maxTokenLifetime: config.MaxTokenLifetime,
		requiredClaims: required, mapper: config.Mapper, keys: config.Keys, now: config.Now,
	}, nil
}

func (verifier *JWTVerifier) ID() string { return verifier.id }

func (verifier *JWTVerifier) Verify(ctx context.Context, credential RawIdentityCredential) (VerifiedPrincipal, error) {
	header, _, err := preflightJWT(credential.reveal())
	if err != nil {
		return VerifiedPrincipal{}, err
	}
	algorithm, _ := header["alg"].(string)
	if _, ok := verifier.algorithmSet[algorithm]; !ok {
		return VerifiedPrincipal{}, invalidCredential("algorithm is not allowed")
	}
	kid, _ := header["kid"].(string)
	claims := jwt.MapClaims{}
	now := verifier.now().UTC()
	parser := jwt.NewParser(
		jwt.WithValidMethods(verifier.algorithms),
		jwt.WithIssuer(verifier.issuer),
		jwt.WithAudience(verifier.audiences...),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(verifier.clockSkew),
		jwt.WithStrictDecoding(),
		jwt.WithJSONNumber(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	token, err := parser.ParseWithClaims(credential.reveal(), claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != algorithm {
			return nil, invalidCredential("protected algorithm changed")
		}
		key, keyErr := verifier.keys.Key(ctx, kid, algorithm)
		if keyErr != nil {
			return nil, mapKeyError(keyErr)
		}
		if !keySupportsAlgorithm(key, algorithm) {
			return nil, ErrKeyUnavailable
		}
		return key, nil
	})
	if err != nil || token == nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return VerifiedPrincipal{}, ErrCredentialExpired
		}
		if errors.Is(err, ErrKeyUnavailable) {
			return VerifiedPrincipal{}, ErrKeyUnavailable
		}
		return VerifiedPrincipal{}, invalidCredential("signature or registered claims")
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil || issuedAt.IsZero() {
		return VerifiedPrincipal{}, invalidCredential("issued-at claim is required")
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil || expiresAt.IsZero() || expiresAt.Time.Sub(issuedAt.Time) > verifier.maxTokenLifetime || !expiresAt.Time.After(issuedAt.Time) {
		return VerifiedPrincipal{}, invalidCredential("token lifetime is invalid")
	}
	for _, claim := range verifier.requiredClaims {
		value, ok := claimAtPath(map[string]any(claims), claim)
		if !ok || emptyClaimValue(value) {
			return VerifiedPrincipal{}, invalidCredential("required claim is missing")
		}
	}
	subjectValue, ok := claimAtPath(map[string]any(claims), verifier.subjectClaim)
	subject, subjectOK := subjectValue.(string)
	if !ok || !subjectOK || strings.TrimSpace(subject) == "" || len(subject) > 2048 || strings.ContainsAny(subject, "\r\n\x00") {
		return VerifiedPrincipal{}, invalidCredential("subject is invalid")
	}
	if len(verifier.authorizedParties) > 0 {
		party, ok := claims["azp"].(string)
		if !ok {
			return VerifiedPrincipal{}, invalidCredential("authorized party is missing")
		}
		if _, allowed := verifier.authorizedParties[party]; !allowed {
			return VerifiedPrincipal{}, invalidCredential("authorized party is not allowed")
		}
	}
	authenticatedAt := issuedAt.Time
	if value, present := claims["auth_time"]; present {
		parsed, parseErr := numericDate(value)
		if parseErr != nil || parsed.After(now.Add(verifier.clockSkew)) || !expiresAt.Time.After(parsed) {
			return VerifiedPrincipal{}, invalidCredential("authentication time is invalid")
		}
		authenticatedAt = parsed
	}
	audience, err := claims.GetAudience()
	if err != nil || len(audience) == 0 {
		return VerifiedPrincipal{}, invalidCredential("audience is invalid")
	}
	mapped, err := verifier.mapper.Map(map[string]any(claims))
	if err != nil {
		return VerifiedPrincipal{}, err
	}
	mapped, err = validateNormalizedClaims(mapped)
	if err != nil {
		return VerifiedPrincipal{}, err
	}
	principal := VerifiedPrincipal{
		ProviderID: verifier.id, Issuer: verifier.issuer, Subject: subject,
		Audience: append([]string(nil), audience...), AuthenticatedAt: authenticatedAt.UTC(),
		ExpiresAt: expiresAt.Time.UTC(), Claims: mapped,
	}
	if err := principal.validate(); err != nil {
		return VerifiedPrincipal{}, err
	}
	return principal, nil
}

func emptyClaimValue(value any) bool {
	if value == nil {
		return true
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text) == ""
	}
	return false
}

func preflightJWT(raw string) (map[string]any, map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxIdentityCredentialBytes {
		return nil, nil, ErrCredentialInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, invalidCredential("compact JWT format")
	}
	headerBytes, err := decodeJWTPart(parts[0], maxJWTHeaderBytes)
	if err != nil {
		return nil, nil, invalidCredential("protected header encoding")
	}
	payloadBytes, err := decodeJWTPart(parts[1], maxJWTPayloadBytes)
	if err != nil {
		return nil, nil, invalidCredential("payload encoding")
	}
	if _, err := decodeJWTPart(parts[2], 8<<10); err != nil {
		return nil, nil, invalidCredential("signature encoding")
	}
	headerValue, err := jsonsafe.Decode(headerBytes)
	if err != nil {
		return nil, nil, invalidCredential("protected header JSON")
	}
	header, ok := headerValue.(map[string]any)
	if !ok {
		return nil, nil, invalidCredential("protected header object")
	}
	algorithm, ok := header["alg"].(string)
	if !ok || algorithm == "" || algorithm == "none" {
		return nil, nil, invalidCredential("protected algorithm")
	}
	if kid, present := header["kid"]; present {
		value, valid := kid.(string)
		if !valid || value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, nil, invalidCredential("key ID")
		}
	}
	if typ, present := header["typ"]; present {
		value, valid := typ.(string)
		if !valid || !strings.EqualFold(value, "JWT") {
			return nil, nil, invalidCredential("header type")
		}
	}
	for _, forbidden := range []string{"jku", "jwk", "x5u"} {
		if _, present := header[forbidden]; present {
			return nil, nil, invalidCredential("token-selected key material")
		}
	}
	if critical, present := header["crit"]; present {
		values, valid := critical.([]any)
		if !valid || len(values) != 0 {
			return nil, nil, invalidCredential("unsupported critical header")
		}
	}
	payloadValue, err := jsonsafe.Decode(payloadBytes)
	if err != nil {
		return nil, nil, invalidCredential("payload JSON")
	}
	payload, ok := payloadValue.(map[string]any)
	if !ok {
		return nil, nil, invalidCredential("payload object")
	}
	return header, payload, nil
}

func decodeJWTPart(encoded string, maximum int) ([]byte, error) {
	if strings.Contains(encoded, "=") || len(encoded) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, ErrCredentialInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, ErrCredentialInvalid
	}
	return decoded, nil
}

func numericDate(value any) (time.Time, error) {
	var number json.Number
	switch typed := value.(type) {
	case json.Number:
		number = typed
	case float64:
		number = json.Number(fmt.Sprintf("%v", typed))
	default:
		return time.Time{}, ErrCredentialInvalid
	}
	seconds, err := number.Int64()
	if err != nil || seconds <= 0 {
		return time.Time{}, ErrCredentialInvalid
	}
	return time.Unix(seconds, 0).UTC(), nil
}
