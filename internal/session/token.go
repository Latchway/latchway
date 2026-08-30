package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
)

const maxAccessTokenBytes = 16 << 10

var sessionIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

type AccessToken struct {
	value string
}

func NewAccessToken(value string) (AccessToken, error) {
	if len(value) < 64 || len(value) > maxAccessTokenBytes || strings.ContainsAny(value, "\r\n\x00") {
		return AccessToken{}, ErrTokenInvalid
	}
	return AccessToken{value: value}, nil
}

func (AccessToken) String() string       { return "[REDACTED]" }
func (AccessToken) GoString() string     { return "session.AccessToken{[REDACTED]}" }
func (token AccessToken) Reveal() string { return token.value }

type Confirmation struct {
	JKT string `json:"jkt"`
}

type accessTrustClaims struct {
	Source                    string `json:"source"`
	AttestationProvider       string `json:"attestation_provider,omitempty"`
	ParentComponentID         string `json:"parent_component_id,omitempty"`
	ParentAttestationProvider string `json:"parent_attestation_provider,omitempty"`
	DelegationID              string `json:"delegation_id,omitempty"`
}

type accessTokenClaims struct {
	OrganizationID        string             `json:"organization_id"`
	ApplicationID         string             `json:"application_id"`
	EnvironmentID         string             `json:"environment_id"`
	InstallationID        string             `json:"installation_id"`
	InstallationFamilyID  string             `json:"installation_family_id,omitempty"`
	ComponentID           string             `json:"component_id,omitempty"`
	ComponentDefinitionID string             `json:"component_definition_id,omitempty"`
	ComponentKind         string             `json:"component_kind,omitempty"`
	ComponentIsRoot       bool               `json:"component_is_root,omitempty"`
	Trust                 *accessTrustClaims `json:"trust,omitempty"`
	Features              []string           `json:"features,omitempty"`
	SessionGrantID        string             `json:"session_grant_id"`
	IdentityProvider      string             `json:"identity_provider"`
	AttestationLevel      string             `json:"attestation_level"`
	PolicyRevision        string             `json:"policy_revision"`
	Confirmation          Confirmation       `json:"cnf"`
	jwt.RegisteredClaims
}

type AccessIssueInput struct {
	OrganizationID            string
	ApplicationID             string
	EnvironmentID             string
	ApplicationUserID         string
	InstallationID            string
	InstallationFamilyID      string
	ComponentID               string
	ComponentDefinitionID     string
	ComponentKind             string
	ComponentIsRoot           bool
	TrustSource               string
	AttestationProvider       string
	ParentComponentID         string
	ParentAttestationProvider string
	DelegationID              string
	Features                  []string
	SessionGrantID            string
	IdentityProvider          string
	TrustLevel                string
	PolicyRevisionID          string
	DPoPJKT                   string
}

func (input AccessIssueInput) validate() error {
	if id.Validate(input.OrganizationID, id.Organization) != nil || id.Validate(input.ApplicationID, id.Application) != nil || id.Validate(input.EnvironmentID, id.Environment) != nil || id.Validate(input.ApplicationUserID, id.ApplicationUser) != nil || id.Validate(input.InstallationID, id.Installation) != nil || id.Validate(input.SessionGrantID, id.SessionGrant) != nil || id.Validate(input.PolicyRevisionID, id.ConfigRevision) != nil {
		return ErrTokenInvalid
	}
	if !sessionIdentifierPattern.MatchString(input.IdentityProvider) || !trustLevelPattern.MatchString(input.TrustLevel) || !validThumbprint(input.DPoPJKT) {
		return ErrTokenInvalid
	}
	componentAware := input.InstallationFamilyID != "" || input.ComponentID != "" ||
		input.ComponentDefinitionID != "" || input.ComponentKind != "" || input.TrustSource != "" ||
		len(input.Features) != 0
	if componentAware {
		if id.Validate(input.InstallationFamilyID, id.InstallationFamily) != nil ||
			id.Validate(input.ComponentID, id.ClientComponent) != nil ||
			!sessionIdentifierPattern.MatchString(input.ComponentDefinitionID) ||
			!componentKindPattern.MatchString(input.ComponentKind) ||
			!trustSourcePattern.MatchString(input.TrustSource) ||
			!sessionIdentifierList(input.Features) {
			return ErrTokenInvalid
		}
		if input.AttestationProvider != "" && !sessionIdentifierPattern.MatchString(input.AttestationProvider) {
			return ErrTokenInvalid
		}
		if input.ComponentIsRoot {
			if input.ParentComponentID != "" || input.ParentAttestationProvider != "" || input.DelegationID != "" {
				return ErrTokenInvalid
			}
		} else if id.Validate(input.ParentComponentID, id.ClientComponent) != nil ||
			id.Validate(input.DelegationID, id.ComponentDelegation) != nil {
			return ErrTokenInvalid
		}
		if input.ParentAttestationProvider != "" && !sessionIdentifierPattern.MatchString(input.ParentAttestationProvider) {
			return ErrTokenInvalid
		}
	}
	return nil
}

var trustLevelPattern = regexp.MustCompile(`^(none|identity_only|web_risk_verified|app_verified|device_verified|strong_device_verified|debug)$`)
var trustSourcePattern = regexp.MustCompile(`^(direct_attested|delegated_from_attested_root|delegated_identity_only|identity_only|web_risk_verified|debug)$`)
var componentKindPattern = regexp.MustCompile(`^(main_app|widget|share_extension|app_intent_extension|notification_service_extension|action_extension|sso_extension|watch_extension|android_app|wear_app|browser|node_process)$`)

func sessionIdentifierList(values []string) bool {
	if len(values) == 0 || len(values) > 256 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !sessionIdentifierPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

type IssuedAccess struct {
	Token     AccessToken
	JTIHash   [sha256.Size]byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type ActiveKeyProvider interface {
	Active(context.Context) (signingKey, error)
}

type AccessTokenIssuerConfig struct {
	Keys      ActiveKeyProvider
	Issuer    string
	Audience  string
	Lifetime  time.Duration
	ClockSkew time.Duration
	Now       func() time.Time
	Random    io.Reader
}

type AccessTokenIssuer struct {
	keys      ActiveKeyProvider
	issuer    string
	audience  string
	lifetime  time.Duration
	clockSkew time.Duration
	now       func() time.Time
	random    io.Reader
}

type preparedAccessTokenIssuer struct {
	issuer *AccessTokenIssuer
	key    signingKey
}

func (*preparedAccessTokenIssuer) preparedAccessIssuer() {}

func (*preparedAccessTokenIssuer) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

func NewAccessTokenIssuer(config AccessTokenIssuerConfig) (*AccessTokenIssuer, error) {
	if config.Keys == nil || !canonicalIssuer(config.Issuer) || config.Audience == "" || len(config.Audience) > 256 {
		return nil, errors.New("access-token issuer configuration is invalid")
	}
	if config.Lifetime == 0 {
		config.Lifetime = 10 * time.Minute
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = time.Minute
	}
	if config.Lifetime < time.Minute || config.Lifetime > time.Hour || config.ClockSkew < 0 || config.ClockSkew > 5*time.Minute {
		return nil, errors.New("access-token lifetime configuration is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &AccessTokenIssuer{
		keys: config.Keys, issuer: config.Issuer, audience: config.Audience,
		lifetime: config.Lifetime, clockSkew: config.ClockSkew, now: config.Now, random: config.Random,
	}, nil
}

func (issuer *AccessTokenIssuer) Issue(ctx context.Context, input AccessIssueInput) (IssuedAccess, error) {
	return issuer.IssueFor(ctx, input, issuer.lifetime)
}

// Prepare resolves and, when necessary, rotates the active signing key before
// a caller opens its own database transaction. The returned issuer performs no
// database work, preventing session mutations from holding one pool connection
// while waiting for another connection to load signing material.
func (issuer *AccessTokenIssuer) Prepare(ctx context.Context) (PreparedAccessIssuer, error) {
	key, err := issuer.keys.Active(ctx)
	if err != nil || key.privateKey() == nil {
		return nil, ErrSigningKeyUnavailable
	}
	return &preparedAccessTokenIssuer{issuer: issuer, key: key}, nil
}

// IssueFor issues a token with the bounded lifetime selected by the immutable
// environment policy. The issuer's configured lifetime remains the default
// used by Issue.
func (issuer *AccessTokenIssuer) IssueFor(ctx context.Context, input AccessIssueInput, lifetime time.Duration) (IssuedAccess, error) {
	prepared, err := issuer.Prepare(ctx)
	if err != nil {
		return IssuedAccess{}, err
	}
	return prepared.IssueFor(input, lifetime)
}

func (prepared *preparedAccessTokenIssuer) IssueFor(input AccessIssueInput, lifetime time.Duration) (IssuedAccess, error) {
	if prepared == nil || prepared.issuer == nil || prepared.key.privateKey() == nil {
		return IssuedAccess{}, ErrSigningKeyUnavailable
	}
	issuer := prepared.issuer
	if err := input.validate(); err != nil {
		return IssuedAccess{}, err
	}
	if lifetime < time.Minute || lifetime > time.Hour {
		return IssuedAccess{}, ErrTokenInvalid
	}
	key := prepared.key
	privateKey := key.privateKey()
	now := issuer.now().UTC().Truncate(time.Second)
	expiresAt := now.Add(lifetime)
	if now.Before(key.NotBefore().Add(-issuer.clockSkew)) || expiresAt.After(key.NotAfter()) {
		return IssuedAccess{}, ErrSigningKeyUnavailable
	}
	jtiBytes := make([]byte, 32)
	if _, err := io.ReadFull(issuer.random, jtiBytes); err != nil {
		return IssuedAccess{}, errors.New("generate access-token identifier")
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)
	claims := accessTokenClaims{
		OrganizationID: input.OrganizationID, ApplicationID: input.ApplicationID,
		EnvironmentID: input.EnvironmentID, InstallationID: input.InstallationID,
		SessionGrantID: input.SessionGrantID, IdentityProvider: input.IdentityProvider,
		AttestationLevel: input.TrustLevel, PolicyRevision: input.PolicyRevisionID,
		Confirmation: Confirmation{JKT: input.DPoPJKT},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer.issuer, Subject: input.ApplicationUserID, Audience: jwt.ClaimStrings{issuer.audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt), IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), ID: jti,
		},
	}
	if input.ComponentID != "" {
		claims.InstallationFamilyID = input.InstallationFamilyID
		claims.ComponentID = input.ComponentID
		claims.ComponentDefinitionID = input.ComponentDefinitionID
		claims.ComponentKind = input.ComponentKind
		claims.ComponentIsRoot = input.ComponentIsRoot
		claims.Trust = &accessTrustClaims{
			Source: input.TrustSource, AttestationProvider: input.AttestationProvider,
			ParentComponentID:         input.ParentComponentID,
			ParentAttestationProvider: input.ParentAttestationProvider,
			DelegationID:              input.DelegationID,
		}
		claims.Features = append([]string(nil), input.Features...)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = key.KeyID()
	token.Header["typ"] = "JWT"
	raw, err := token.SignedString(privateKey)
	if err != nil {
		return IssuedAccess{}, errors.New("sign access token")
	}
	accessToken, err := NewAccessToken(raw)
	if err != nil {
		return IssuedAccess{}, err
	}
	return IssuedAccess{Token: accessToken, JTIHash: sha256.Sum256([]byte(jti)), IssuedAt: now, ExpiresAt: expiresAt}, nil
}

type PublicKeyProvider interface {
	PublicKey(context.Context, string) (*ecdsa.PublicKey, error)
}

type AccessTokenVerifierConfig struct {
	Keys         PublicKeyProvider
	Issuer       string
	Audience     string
	ClockSkew    time.Duration
	ClockSkewSet bool
	MaxLifetime  time.Duration
	Now          func() time.Time
}

type AccessTokenVerifier struct {
	keys        PublicKeyProvider
	issuer      string
	audience    string
	clockSkew   time.Duration
	maxLifetime time.Duration
	now         func() time.Time
}

func NewAccessTokenVerifier(config AccessTokenVerifierConfig) (*AccessTokenVerifier, error) {
	if config.Keys == nil || !canonicalIssuer(config.Issuer) || config.Audience == "" || len(config.Audience) > 256 {
		return nil, errors.New("access-token verifier configuration is invalid")
	}
	if !config.ClockSkewSet && config.ClockSkew == 0 {
		config.ClockSkew = time.Minute
	}
	if config.MaxLifetime == 0 {
		config.MaxLifetime = time.Hour
	}
	if config.ClockSkew < 0 || config.ClockSkew > 5*time.Minute || config.MaxLifetime < time.Minute || config.MaxLifetime > time.Hour {
		return nil, errors.New("access-token verifier durations are invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &AccessTokenVerifier{keys: config.Keys, issuer: config.Issuer, audience: config.Audience, clockSkew: config.ClockSkew, maxLifetime: config.MaxLifetime, now: config.Now}, nil
}

// AccessPrincipal contains signed claims only. Callers must still load the
// session grant, user, and installation from PostgreSQL before authorization.
type AccessPrincipal struct {
	OrganizationID            string
	ApplicationID             string
	EnvironmentID             string
	ApplicationUserID         string
	InstallationID            string
	InstallationFamilyID      string
	ComponentID               string
	ComponentDefinitionID     string
	ComponentKind             string
	ComponentIsRoot           bool
	TrustSource               string
	AttestationProvider       string
	ParentComponentID         string
	ParentAttestationProvider string
	DelegationID              string
	Features                  []string
	SessionGrantID            string
	IdentityProvider          string
	TrustLevel                string
	PolicyRevisionID          string
	DPoPJKT                   string
	JTIHash                   [sha256.Size]byte
	IssuedAt                  time.Time
	ExpiresAt                 time.Time

	tokenHash [sha256.Size]byte
	seal      [sha256.Size]byte
}

func (verifier *AccessTokenVerifier) Verify(ctx context.Context, token AccessToken) (AccessPrincipal, error) {
	header, payload, err := preflightAccessToken(token.value)
	if err != nil {
		return AccessPrincipal{}, err
	}
	kid := textMember(header, "kid")
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok || len(cnf) != 1 || !validThumbprint(textMember(cnf, "jkt")) {
		return AccessPrincipal{}, ErrTokenInvalid
	}
	now := verifier.now().UTC()
	claims := accessTokenClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(verifier.issuer),
		jwt.WithAudience(verifier.audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithLeeway(verifier.clockSkew), jwt.WithStrictDecoding(), jwt.WithJSONNumber(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	parsed, err := parser.ParseWithClaims(token.value, &claims, func(parsedToken *jwt.Token) (any, error) {
		if parsedToken.Method != jwt.SigningMethodES256 {
			return nil, ErrTokenInvalid
		}
		key, keyErr := verifier.keys.PublicKey(ctx, kid)
		if errors.Is(keyErr, ErrSigningKeyNotFound) {
			return nil, ErrTokenInvalid
		}
		if keyErr != nil {
			return nil, ErrSigningKeyUnavailable
		}
		return key, nil
	})
	if err != nil || parsed == nil || !parsed.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return AccessPrincipal{}, ErrTokenExpired
		}
		if errors.Is(err, ErrSigningKeyUnavailable) {
			return AccessPrincipal{}, ErrSigningKeyUnavailable
		}
		return AccessPrincipal{}, ErrTokenInvalid
	}
	if err := validateAccessClaims(claims, verifier.maxLifetime); err != nil {
		return AccessPrincipal{}, err
	}
	principal := AccessPrincipal{
		OrganizationID: claims.OrganizationID, ApplicationID: claims.ApplicationID,
		EnvironmentID: claims.EnvironmentID, ApplicationUserID: claims.Subject,
		InstallationID: claims.InstallationID, SessionGrantID: claims.SessionGrantID,
		IdentityProvider: claims.IdentityProvider, TrustLevel: claims.AttestationLevel,
		PolicyRevisionID: claims.PolicyRevision, DPoPJKT: claims.Confirmation.JKT,
		JTIHash: sha256.Sum256([]byte(claims.ID)), IssuedAt: claims.IssuedAt.UTC(),
		ExpiresAt: claims.ExpiresAt.UTC(), tokenHash: sha256.Sum256([]byte(token.value)),
	}
	if claims.ComponentID != "" && claims.Trust != nil {
		principal.InstallationFamilyID = claims.InstallationFamilyID
		principal.ComponentID = claims.ComponentID
		principal.ComponentDefinitionID = claims.ComponentDefinitionID
		principal.ComponentKind = claims.ComponentKind
		principal.ComponentIsRoot = claims.ComponentIsRoot
		principal.TrustSource = claims.Trust.Source
		principal.AttestationProvider = claims.Trust.AttestationProvider
		principal.ParentComponentID = claims.Trust.ParentComponentID
		principal.ParentAttestationProvider = claims.Trust.ParentAttestationProvider
		principal.DelegationID = claims.Trust.DelegationID
		principal.Features = append([]string(nil), claims.Features...)
	}
	principal.seal = accessPrincipalSeal(principal)
	return principal, nil
}

func accessPrincipalSeal(principal AccessPrincipal) [sha256.Size]byte {
	payload := make([]byte, 0, 1024)
	for _, value := range []string{
		principal.OrganizationID, principal.ApplicationID, principal.EnvironmentID,
		principal.ApplicationUserID, principal.InstallationID, principal.SessionGrantID,
		principal.InstallationFamilyID, principal.ComponentID, principal.ComponentDefinitionID,
		principal.ComponentKind, principal.TrustSource, principal.AttestationProvider,
		principal.ParentComponentID, principal.ParentAttestationProvider, principal.DelegationID,
		principal.IdentityProvider, principal.TrustLevel, principal.PolicyRevisionID,
		principal.DPoPJKT, principal.IssuedAt.UTC().Format(time.RFC3339Nano),
		principal.ExpiresAt.UTC().Format(time.RFC3339Nano),
	} {
		payload = append(payload, value...)
		payload = append(payload, 0)
	}
	if principal.ComponentIsRoot {
		payload = append(payload, '1', 0)
	} else {
		payload = append(payload, '0', 0)
	}
	for _, feature := range principal.Features {
		payload = append(payload, feature...)
		payload = append(payload, 0)
	}
	payload = append(payload, principal.JTIHash[:]...)
	payload = append(payload, principal.tokenHash[:]...)
	return sha256.Sum256(payload)
}

func accessPrincipalSealValid(principal AccessPrincipal) bool {
	expected := accessPrincipalSeal(principal)
	return subtle.ConstantTimeCompare(principal.seal[:], expected[:]) == 1
}

func validateAccessClaims(claims accessTokenClaims, maximumLifetime time.Duration) error {
	input := AccessIssueInput{
		OrganizationID: claims.OrganizationID, ApplicationID: claims.ApplicationID,
		EnvironmentID: claims.EnvironmentID, ApplicationUserID: claims.Subject,
		InstallationID: claims.InstallationID, SessionGrantID: claims.SessionGrantID,
		InstallationFamilyID: claims.InstallationFamilyID,
		ComponentID:          claims.ComponentID, ComponentDefinitionID: claims.ComponentDefinitionID,
		ComponentKind: claims.ComponentKind, ComponentIsRoot: claims.ComponentIsRoot,
		IdentityProvider: claims.IdentityProvider, TrustLevel: claims.AttestationLevel,
		PolicyRevisionID: claims.PolicyRevision, DPoPJKT: claims.Confirmation.JKT,
	}
	if claims.Trust != nil {
		input.TrustSource = claims.Trust.Source
		input.AttestationProvider = claims.Trust.AttestationProvider
		input.ParentComponentID = claims.Trust.ParentComponentID
		input.ParentAttestationProvider = claims.Trust.ParentAttestationProvider
		input.DelegationID = claims.Trust.DelegationID
	}
	input.Features = append([]string(nil), claims.Features...)
	if input.validate() != nil || claims.IssuedAt == nil || claims.ExpiresAt == nil || claims.ID == "" || len(claims.ID) > 128 || strings.ContainsAny(claims.ID, "\r\n\x00") {
		return ErrTokenInvalid
	}
	issuedAt := claims.IssuedAt.UTC()
	expiresAt := claims.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > maximumLifetime {
		return ErrTokenInvalid
	}
	return nil
}

func preflightAccessToken(raw string) (map[string]any, map[string]any, error) {
	if len(raw) < 64 || len(raw) > maxAccessTokenBytes {
		return nil, nil, ErrTokenInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, ErrTokenInvalid
	}
	decoded := make([][]byte, 3)
	for index, part := range parts {
		if part == "" || strings.Contains(part, "=") {
			return nil, nil, ErrTokenInvalid
		}
		value, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(value) != part {
			return nil, nil, ErrTokenInvalid
		}
		decoded[index] = value
	}
	if len(decoded[0]) > 4096 || len(decoded[1]) > 12<<10 || len(decoded[2]) != 64 {
		return nil, nil, ErrTokenInvalid
	}
	headerValue, err := jsonsafe.Decode(decoded[0])
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}
	header, ok := headerValue.(map[string]any)
	if !ok || len(header) != 3 || textMember(header, "alg") != "ES256" || textMember(header, "typ") != "JWT" || len(textMember(header, "kid")) < 8 {
		return nil, nil, ErrTokenInvalid
	}
	payloadValue, err := jsonsafe.Decode(decoded[1])
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}
	payload, ok := payloadValue.(map[string]any)
	if !ok {
		return nil, nil, ErrTokenInvalid
	}
	return header, payload, nil
}

func canonicalIssuer(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.String() != raw {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	if strings.EqualFold(parsed.Hostname(), "localhost") {
		return true
	}
	address := net.ParseIP(parsed.Hostname())
	return address != nil && address.IsLoopback()
}

func validThumbprint(value string) bool {
	if len(value) != 43 || strings.Contains(value, "=") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}
