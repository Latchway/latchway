package adminauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrInvalidAdminInput indicates malformed domain input.
	ErrInvalidAdminInput = errors.New("invalid admin authentication input")
	// ErrBootstrapAlreadyInitialized indicates a different unconsumed bootstrap
	// token has already been installed.
	ErrBootstrapAlreadyInitialized = errors.New("bootstrap token already initialized")
	// ErrBootstrapDisabled indicates that bootstrap was consumed or an owner
	// already exists.
	ErrBootstrapDisabled = errors.New("bootstrap is permanently disabled")
	// ErrBootstrapTokenInvalid avoids exposing stored bootstrap state.
	ErrBootstrapTokenInvalid = errors.New("bootstrap token is invalid")
	// ErrBootstrapTokenExpired indicates an unconsumed token passed its bound.
	ErrBootstrapTokenExpired = errors.New("bootstrap token is expired")
	// ErrAdminAuthentication indicates invalid, expired, revoked, or disabled
	// administrative credentials.
	ErrAdminAuthentication = errors.New("admin authentication failed")
	// ErrAdminNotFound indicates that a requested administrative resource does
	// not exist.
	ErrAdminNotFound = errors.New("admin resource not found")
	// ErrAdminConflict indicates that an administrator lifecycle mutation
	// conflicts with an existing account or membership.
	ErrAdminConflict = errors.New("admin resource conflict")
	// ErrLastActiveOwner protects every organization from losing its final
	// usable owner through a concurrent role or status mutation.
	ErrLastActiveOwner = errors.New("cannot remove the last active owner")
)

var slugPattern = regexp.MustCompile("^[a-z][a-z0-9-]{1,62}$")

// BootstrapOwnerInput is the complete transaction that consumes the one-time
// token and creates the first organization owner.
type BootstrapOwnerInput struct {
	OrganizationSlug string
	OrganizationName string
	Email            string
	DisplayName      string
	PasswordHash     PasswordHash
	RequestID        string
}

func (input BootstrapOwnerInput) validate() error {
	if !slugPattern.MatchString(input.OrganizationSlug) {
		return fmt.Errorf("%w: organization slug", ErrInvalidAdminInput)
	}
	if err := validateDisplayName(input.OrganizationName); err != nil {
		return fmt.Errorf("%w: organization name", ErrInvalidAdminInput)
	}
	if _, err := NormalizeEmail(input.Email); err != nil {
		return err
	}
	if err := validateDisplayName(input.DisplayName); err != nil {
		return fmt.Errorf("%w: display name", ErrInvalidAdminInput)
	}
	if input.PasswordHash.encoded == "" {
		return fmt.Errorf("%w: password hash", ErrInvalidAdminInput)
	}
	if _, err := ParsePasswordHash(input.PasswordHash.Encoded()); err != nil {
		return fmt.Errorf("%w: password hash", ErrInvalidAdminInput)
	}
	if validateRequestID(input.RequestID) != nil {
		return fmt.Errorf("%w: request ID", ErrInvalidAdminInput)
	}
	return nil
}

// BootstrapResult returns only non-secret resources.
type BootstrapResult struct {
	OrganizationID    string
	AdminUserID       string
	AdminMembershipID string
}

// NormalizeEmail returns the case-insensitive identity key retained alongside
// the administrator's display email.
func NormalizeEmail(email string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if len(normalized) < 3 || len(normalized) > 320 ||
		strings.Count(normalized, "@") != 1 ||
		strings.HasPrefix(normalized, "@") ||
		strings.HasSuffix(normalized, "@") ||
		strings.ContainsAny(normalized, "\r\n\x00") {
		return "", fmt.Errorf("%w: email", ErrInvalidAdminInput)
	}
	return normalized, nil
}

func validateDisplayName(value string) error {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 200 || strings.ContainsAny(value, "\r\n\x00") {
		return ErrInvalidAdminInput
	}
	return nil
}

// CreateSessionInput requests a bounded organization-scoped cookie session.
type CreateSessionInput struct {
	OrganizationID string
	AdminUserID    string
	Lifetime       time.Duration
	RequestID      string
}

func (input CreateSessionInput) validate() error {
	if err := id.Validate(input.OrganizationID, id.Organization); err != nil {
		return fmt.Errorf("%w: organization ID", ErrInvalidAdminInput)
	}
	if err := id.Validate(input.AdminUserID, id.AdminUser); err != nil {
		return fmt.Errorf("%w: admin user ID", ErrInvalidAdminInput)
	}
	if input.Lifetime < 5*time.Minute || input.Lifetime > 30*24*time.Hour {
		return fmt.Errorf("%w: session lifetime", ErrInvalidAdminInput)
	}
	if validateRequestID(input.RequestID) != nil {
		return fmt.Errorf("%w: request ID", ErrInvalidAdminInput)
	}
	return nil
}

// IssuedSession contains one-time cookie material. SecretToken formatting is
// redacted; Reveal is required to transmit it.
type IssuedSession struct {
	SessionID string
	Token     SecretToken
	CSRFToken SecretToken
	ExpiresAt time.Time
}

// CreateAPITokenInput requests a scoped opaque administrative credential.
type CreateAPITokenInput struct {
	OrganizationID       string
	AdminUserID          string
	CreatedByAdminUserID string
	Name                 string
	Scope                CapabilitySet
	ExpiresAt            *time.Time
	RequestID            string
}

func (input CreateAPITokenInput) validate(now time.Time) error {
	if err := id.Validate(input.OrganizationID, id.Organization); err != nil {
		return fmt.Errorf("%w: organization ID", ErrInvalidAdminInput)
	}
	if err := id.Validate(input.AdminUserID, id.AdminUser); err != nil {
		return fmt.Errorf("%w: admin user ID", ErrInvalidAdminInput)
	}
	if err := id.Validate(input.CreatedByAdminUserID, id.AdminUser); err != nil {
		return fmt.Errorf("%w: creator admin user ID", ErrInvalidAdminInput)
	}
	name := strings.TrimSpace(input.Name)
	if len(name) == 0 || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") {
		return fmt.Errorf("%w: token name", ErrInvalidAdminInput)
	}
	if len(input.Scope.values) == 0 {
		return ErrEmptyTokenScope
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(now) {
		return fmt.Errorf("%w: token expiry", ErrInvalidAdminInput)
	}
	if validateRequestID(input.RequestID) != nil {
		return fmt.Errorf("%w: request ID", ErrInvalidAdminInput)
	}
	return nil
}

// IssuedAPIToken contains a one-time API credential.
type IssuedAPIToken struct {
	APITokenID string
	Token      SecretToken
	CreatedAt  time.Time
	ExpiresAt  *time.Time
}

// APITokenMetadata is the non-secret administrative token representation.
type APITokenMetadata struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
}

// AuthenticationMethod identifies how an admin principal authenticated.
type AuthenticationMethod string

const (
	AuthenticationSession  AuthenticationMethod = "session"
	AuthenticationAPIToken AuthenticationMethod = "api_token"
)

// Principal is the active organization membership produced by credential
// authentication.
type Principal struct {
	OrganizationID      string
	AdminUserID         string
	Role                Role
	Method              AuthenticationMethod
	CredentialID        string
	CredentialExpiresAt *time.Time
	scope               *CapabilitySet
}

// Allows evaluates membership role and optional API-token scope.
func (principal Principal) Allows(capability Capability, context AuthorizationContext) bool {
	if principal.scope == nil {
		return principal.Role.Allows(capability, context)
	}
	return principal.scope.Allows(principal.Role, capability, context)
}

func capabilitiesFromStrings(values []string) (CapabilitySet, error) {
	capabilities := make([]Capability, len(values))
	for index, value := range values {
		capabilities[index] = Capability(value)
	}
	return NewCapabilitySet(capabilities...)
}
