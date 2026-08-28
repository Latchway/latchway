package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/identity"
	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	firebaseAppCheckProvider       = "firebase_app_check"
	firebaseAppCheckJWKSURL        = "https://firebaseappcheck.googleapis.com/v1/jwks"
	firebaseAppCheckIssuerPrefix   = "https://firebaseappcheck.googleapis.com/"
	firebaseAppCheckEvidenceDomain = "latchway/firebase-app-check-evidence/v1"

	maxFirebaseAppCheckTokenBytes    = 16 << 10
	maxFirebaseAppCheckHeaderBytes   = 4 << 10
	maxFirebaseAppCheckApplications  = 32
	defaultFirebaseAppCheckTimeout   = 10 * time.Second
	maximumFirebaseAppCheckTimeout   = 30 * time.Second
	defaultFirebaseAppCheckSkew      = 30 * time.Second
	maximumFirebaseAppCheckSkew      = 5 * time.Minute
	defaultFirebaseAppCheckLifetime  = 7 * 24 * time.Hour
	maximumFirebaseAppCheckLifetime  = 7 * 24 * time.Hour
	defaultFirebaseAppCheckResult    = 10 * time.Minute
	maximumFirebaseAppCheckResult    = 24 * time.Hour
	firebaseAppCheckMaximumJWKSCache = 6 * time.Hour
)

var (
	ErrFirebaseAppCheckService   = errors.New("firebase app check service is unavailable")
	firebaseProjectNumberPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

// FirebaseAppCheckConfig contains only server-owned application expectations.
// Google's key URL, issuer prefix, audience prefix, and RS256 algorithm are
// fixed by the constructor and cannot be selected by untrusted evidence.
type FirebaseAppCheckConfig struct {
	ApplicationID    string
	EnvironmentID    string
	ProjectNumber    string
	AllowedAppIDs    []string
	Transport        http.RoundTripper
	Timeout          time.Duration
	Now              func() time.Time
	ClockSkew        time.Duration
	ClockSkewSet     bool
	MaxTokenLifetime time.Duration
	ResultLifetime   time.Duration
}

type FirebaseAppCheckVerifier struct {
	applicationID    string
	environmentID    string
	projectNumber    string
	allowedAppIDs    map[string]struct{}
	jwt              *identity.JWTVerifier
	now              func() time.Time
	clockSkew        time.Duration
	maxTokenLifetime time.Duration
	resultLifetime   time.Duration
}

func NewFirebaseAppCheckVerifier(config FirebaseAppCheckConfig) (*FirebaseAppCheckVerifier, error) {
	if !applicationPattern.MatchString(config.ApplicationID) ||
		!environmentPattern.MatchString(config.EnvironmentID) ||
		!validFirebaseProjectNumber(config.ProjectNumber) ||
		len(config.AllowedAppIDs) == 0 || len(config.AllowedAppIDs) > maxFirebaseAppCheckApplications ||
		(config.Transport != nil && nilPlayIntegrityDependency(config.Transport)) {
		return nil, ErrConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = defaultFirebaseAppCheckTimeout
	}
	if config.Timeout < time.Second || config.Timeout > maximumFirebaseAppCheckTimeout {
		return nil, ErrConfiguration
	}
	if !config.ClockSkewSet && config.ClockSkew == 0 {
		config.ClockSkew = defaultFirebaseAppCheckSkew
	}
	if config.ClockSkew < 0 || config.ClockSkew > maximumFirebaseAppCheckSkew {
		return nil, ErrConfiguration
	}
	if config.MaxTokenLifetime == 0 {
		config.MaxTokenLifetime = defaultFirebaseAppCheckLifetime
	}
	if config.MaxTokenLifetime < time.Minute || config.MaxTokenLifetime > maximumFirebaseAppCheckLifetime {
		return nil, ErrConfiguration
	}
	if config.ResultLifetime == 0 {
		config.ResultLifetime = defaultFirebaseAppCheckResult
	}
	if config.ResultLifetime < time.Minute || config.ResultLifetime > maximumFirebaseAppCheckResult {
		return nil, ErrConfiguration
	}

	allowedAppIDs := make(map[string]struct{}, len(config.AllowedAppIDs))
	for _, appID := range config.AllowedAppIDs {
		if !validFirebaseAppID(appID) {
			return nil, ErrConfiguration
		}
		if _, duplicate := allowedAppIDs[appID]; duplicate {
			return nil, ErrConfiguration
		}
		allowedAppIDs[appID] = struct{}{}
	}

	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	keys, err := identity.NewRemoteKeySource(identity.RemoteKeySourceConfig{
		URL: firebaseAppCheckJWKSURL, Format: identity.RemoteKeyFormatJWKS,
		Client: client, Now: config.Now, DefaultTTL: 5 * time.Minute,
		MaximumTTL: firebaseAppCheckMaximumJWKSCache, StaleGrace: 15 * time.Minute,
		ForcedRefreshMinimum: 10 * time.Second,
	})
	if err != nil {
		return nil, ErrConfiguration
	}
	issuer := firebaseAppCheckIssuerPrefix + config.ProjectNumber
	jwtVerifier, err := identity.NewJWTVerifier(identity.VerifierConfig{
		ProviderID: firebaseAppCheckProvider, Issuer: issuer,
		Audiences:         []string{"projects/" + config.ProjectNumber},
		AllowedAlgorithms: []string{"RS256"}, RequiredClaims: []string{"sub"},
		ClockSkew: config.ClockSkew, ClockSkewSet: true,
		MaxTokenLifetime: config.MaxTokenLifetime, Keys: keys, Now: config.Now,
	})
	if err != nil {
		return nil, ErrConfiguration
	}
	return &FirebaseAppCheckVerifier{
		applicationID: config.ApplicationID, environmentID: config.EnvironmentID,
		projectNumber: config.ProjectNumber, allowedAppIDs: allowedAppIDs,
		jwt: jwtVerifier, now: config.Now, clockSkew: config.ClockSkew,
		maxTokenLifetime: config.MaxTokenLifetime, resultLifetime: config.ResultLifetime,
	}, nil
}

func (*FirebaseAppCheckVerifier) ID() string { return firebaseAppCheckProvider }

func (verifier *FirebaseAppCheckVerifier) Verify(
	ctx context.Context,
	evidence Evidence,
	binding Binding,
) (Result, error) {
	if verifier == nil || evidence.provider != firebaseAppCheckProvider {
		return Result{}, ErrUnsupported
	}
	if ctx == nil {
		return Result{}, invalid("firebase app check context")
	}
	if verifier.jwt == nil || verifier.now == nil || verifier.projectNumber == "" ||
		len(verifier.allowedAppIDs) == 0 {
		return Result{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := binding.Validate(); err != nil {
		return Result{}, err
	}
	if binding.ApplicationID != verifier.applicationID || binding.Environment != verifier.environmentID ||
		!firebaseAppCheckPlatform(binding.Platform) {
		return Result{}, invalid("firebase app check binding scope")
	}
	if len(evidence.payload) != 1 {
		return Result{}, invalid("firebase app check evidence shape")
	}
	token, ok := evidence.payload["token"].(string)
	if !ok || !validFirebaseAppCheckToken(token) {
		return Result{}, invalid("firebase app check token")
	}
	now := verifier.now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return Result{}, ErrConfiguration
	}
	if err := preflightFirebaseAppCheckJWT(token); err != nil {
		return Result{}, err
	}
	if err := validateFirebaseAppCheckJWTDates(token, now, verifier.clockSkew, verifier.maxTokenLifetime); err != nil {
		return Result{}, err
	}
	credential, err := identity.NewRawIdentityCredential(token)
	if err != nil {
		return Result{}, invalid("firebase app check token")
	}
	principal, err := verifier.jwt.Verify(ctx, credential)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		if errors.Is(err, identity.ErrKeyUnavailable) {
			return Result{}, ErrFirebaseAppCheckService
		}
		return Result{}, invalid("firebase app check token verification")
	}
	expectedIssuer := firebaseAppCheckIssuerPrefix + verifier.projectNumber
	expectedAudience := "projects/" + verifier.projectNumber
	if principal.Issuer != expectedIssuer || len(principal.Audience) != 1 ||
		principal.Audience[0] != expectedAudience {
		return Result{}, invalid("firebase app check token scope")
	}
	if _, allowed := verifier.allowedAppIDs[principal.Subject]; !allowed {
		return Result{}, invalid("firebase app check application")
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		return Result{}, err
	}
	expiresAt := now.Add(verifier.resultLifetime)
	if principal.ExpiresAt.Before(expiresAt) {
		expiresAt = principal.ExpiresAt
	}
	if !expiresAt.After(now) {
		return Result{}, invalid("firebase app check token expiry")
	}
	signals := map[string]any{
		"app_identity_valid": true,
		"verified_app_id":    principal.Subject,
		"project_number":     verifier.projectNumber,
	}
	// A standard App Check JWT authenticates the configured Firebase app ID but
	// has no clientDataHash-style claim. The sealed Result is scoped to the
	// atomically consumed Latchway binding and deliberately claims app trust,
	// never device or hardware-backed trust.
	return newResult(
		firebaseAppCheckProvider, "app_verified", now, expiresAt, signals,
		firebaseAppCheckEvidenceHash(token), bindingHash,
	)
}

func validFirebaseProjectNumber(projectNumber string) bool {
	if !firebaseProjectNumberPattern.MatchString(projectNumber) {
		return false
	}
	_, err := strconv.ParseUint(projectNumber, 10, 64)
	return err == nil
}

func validFirebaseAppID(appID string) bool {
	if len(appID) < 5 || len(appID) > 256 || strings.TrimSpace(appID) != appID ||
		strings.ContainsAny(appID, "\r\n\x00") {
		return false
	}
	for _, character := range appID {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func firebaseAppCheckPlatform(platform string) bool {
	switch platform {
	case "ios", "android", "web", "react_native_ios", "react_native_android":
		return true
	default:
		return false
	}
}

func validFirebaseAppCheckToken(token string) bool {
	if len(token) < 16 || len(token) > maxFirebaseAppCheckTokenBytes {
		return false
	}
	for _, character := range token {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func preflightFirebaseAppCheckJWT(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return invalid("firebase app check JWT format")
	}
	headerBytes, err := decodeCanonicalJWTPart(parts[0], maxFirebaseAppCheckHeaderBytes)
	if err != nil {
		return invalid("firebase app check JWT header")
	}
	headerValue, err := jsonsafe.Decode(headerBytes)
	if err != nil {
		return invalid("firebase app check JWT header")
	}
	header, ok := headerValue.(map[string]any)
	if !ok || len(header) == 0 || len(header) > 16 || header["alg"] != "RS256" || header["typ"] != "JWT" {
		return invalid("firebase app check JWT header")
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" || len(kid) > 256 || strings.ContainsAny(kid, "\r\n\x00") {
		return invalid("firebase app check JWT key")
	}
	for _, forbidden := range []string{"jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "b64", "crit"} {
		if _, exists := header[forbidden]; exists {
			return invalid("firebase app check JWT header")
		}
	}
	payloadBytes, err := decodeCanonicalJWTPart(parts[1], maxFirebaseAppCheckTokenBytes)
	if err != nil {
		return invalid("firebase app check JWT payload")
	}
	payloadValue, err := jsonsafe.Decode(payloadBytes)
	if err != nil {
		return invalid("firebase app check JWT payload")
	}
	if payload, ok := payloadValue.(map[string]any); !ok || len(payload) == 0 || len(payload) > 128 {
		return invalid("firebase app check JWT payload")
	}
	if _, err := decodeCanonicalJWTPart(parts[2], 8<<10); err != nil {
		return invalid("firebase app check JWT signature")
	}
	return nil
}

func validateFirebaseAppCheckJWTDates(
	token string,
	now time.Time,
	clockSkew time.Duration,
	maximumLifetime time.Duration,
) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || now.IsZero() || clockSkew < 0 || maximumLifetime <= 0 {
		return invalid("firebase app check JWT dates")
	}
	payloadBytes, err := decodeCanonicalJWTPart(parts[1], maxFirebaseAppCheckTokenBytes)
	if err != nil {
		return invalid("firebase app check JWT dates")
	}
	value, err := jsonsafe.Decode(payloadBytes)
	if err != nil {
		return invalid("firebase app check JWT dates")
	}
	claims, ok := value.(map[string]any)
	if !ok {
		return invalid("firebase app check JWT dates")
	}
	expiresAt, expOK := firebaseAppCheckNumericDate(claims["exp"])
	issuedAt, iatOK := firebaseAppCheckNumericDate(claims["iat"])
	if !expOK || !iatOK || !expiresAt.After(issuedAt) ||
		expiresAt.Sub(issuedAt) > maximumLifetime ||
		issuedAt.After(now.Add(clockSkew)) || !expiresAt.After(now.Add(-clockSkew)) {
		return invalid("firebase app check JWT dates")
	}
	if rawNotBefore, present := claims["nbf"]; present {
		notBefore, nbfOK := firebaseAppCheckNumericDate(rawNotBefore)
		if !nbfOK || !notBefore.Before(expiresAt) || notBefore.After(now.Add(clockSkew)) {
			return invalid("firebase app check JWT dates")
		}
	}
	return nil
}

func firebaseAppCheckNumericDate(value any) (time.Time, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || seconds < 0 || seconds > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

func decodeCanonicalJWTPart(value string, maximum int) ([]byte, error) {
	if value == "" || strings.ContainsRune(value, '=') || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, ErrInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func firebaseAppCheckEvidenceHash(token string) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte(firebaseAppCheckEvidenceDomain))
	digest.Write([]byte{0})
	digest.Write([]byte(strconv.Itoa(len(token))))
	digest.Write([]byte{0})
	digest.Write([]byte(token))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (FirebaseAppCheckVerifier) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "FirebaseAppCheckVerifier{[REDACTED]}")
}

func (FirebaseAppCheckVerifier) LogValue() slog.Value {
	return slog.StringValue("FirebaseAppCheckVerifier{[REDACTED]}")
}

var _ Verifier = (*FirebaseAppCheckVerifier)(nil)
