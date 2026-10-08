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

var deviceSummaryPattern = regexp.MustCompile(`^[A-Za-z0-9 .()/-]{1,80}$`)

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
	// DeviceSummary is an optional coarse "Browser on OS" description; see
	// DeviceSummaryFromUserAgent. Raw User-Agent strings are never stored.
	DeviceSummary string
	// SignInMethod is how the administrator proved who they are; empty means
	// SignInPassword.
	SignInMethod SignInMethod
}

// SignInMethod records how a console session was signed in.
type SignInMethod string

const (
	SignInPassword SignInMethod = "password"
	SignInPasskey  SignInMethod = "passkey"
	// SignInSSO sessions rely on the organization's identity provider for any
	// further factors, so the two-factor requirement doesn't apply to them.
	SignInSSO SignInMethod = "sso"
)

func (method SignInMethod) orDefault() SignInMethod {
	if method == "" {
		return SignInPassword
	}
	return method
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
	if input.DeviceSummary != "" && !deviceSummaryPattern.MatchString(input.DeviceSummary) {
		return fmt.Errorf("%w: device summary", ErrInvalidAdminInput)
	}
	switch input.SignInMethod.orDefault() {
	case SignInPassword, SignInPasskey, SignInSSO:
	default:
		return fmt.Errorf("%w: sign-in method", ErrInvalidAdminInput)
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
// Administrator is present only in the organization-wide owner listing.
type APITokenMetadata struct {
	ID            string                     `json:"id"`
	Name          string                     `json:"name"`
	Scopes        []string                   `json:"scopes"`
	CreatedAt     time.Time                  `json:"created_at"`
	ExpiresAt     *time.Time                 `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time                 `json:"last_used_at,omitempty"`
	Revoked       bool                       `json:"revoked"`
	Administrator *AdminSessionAdministrator `json:"administrator,omitempty"`
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
	// PasswordResetRequired marks a session whose administrator must choose a
	// new password before using anything but sign-out and the password change.
	PasswordResetRequired bool
	// TwoFactorEnrollmentRequired marks a session in an organization that
	// requires a second factor the administrator hasn't set up yet.
	TwoFactorEnrollmentRequired bool
	// SignInMethod is how a console session was signed in.
	SignInMethod SignInMethod
	scope        *CapabilitySet
	// applicationRoles raise the organization role for single applications.
	applicationRoles map[string]Role
}

// Allows evaluates the organization role and optional API-token scope. It is
// the check for organization-wide actions; actions on one application use
// AllowsIn, which also counts application roles.
func (principal Principal) Allows(capability Capability, context AuthorizationContext) bool {
	return principal.allowsAs(principal.Role, capability, context)
}

func (principal Principal) allowsAs(role Role, capability Capability, context AuthorizationContext) bool {
	if principal.scope == nil {
		return role.Allows(capability, context)
	}
	return principal.scope.Allows(role, capability, context)
}

// RoleIn is the administrator's role for one application: the organization
// role, raised by an application role when that is higher. Application roles
// never lower it.
func (principal Principal) RoleIn(applicationID string) Role {
	if raised, ok := principal.applicationRoles[applicationID]; ok && raised.rank() > principal.Role.rank() {
		return raised
	}
	return principal.Role
}

// AllowsIn evaluates a capability for one application.
func (principal Principal) AllowsIn(capability Capability, applicationID string, context AuthorizationContext) bool {
	return principal.allowsAs(principal.RoleIn(applicationID), capability, context)
}

// AllowsSomewhere reports whether the capability is allowed in the
// organization or in at least one application. It is a cheap first check
// before the target, and so its application, is loaded.
func (principal Principal) AllowsSomewhere(capability Capability, context AuthorizationContext) bool {
	if principal.Allows(capability, context) {
		return true
	}
	for applicationID := range principal.applicationRoles {
		if principal.AllowsIn(capability, applicationID, context) {
			return true
		}
	}
	return false
}

// ApplicationRoles returns a copy of the application roles that raise this
// principal's organization role.
func (principal Principal) ApplicationRoles() map[string]Role {
	roles := make(map[string]Role, len(principal.applicationRoles))
	for applicationID, role := range principal.applicationRoles {
		roles[applicationID] = role
	}
	return roles
}

// WithApplicationRoles returns the principal with application roles set.
func (principal Principal) WithApplicationRoles(roles map[string]Role) Principal {
	principal.applicationRoles = make(map[string]Role, len(roles))
	for applicationID, role := range roles {
		principal.applicationRoles[applicationID] = role
	}
	return principal
}

func capabilitiesFromStrings(values []string) (CapabilitySet, error) {
	capabilities := make([]Capability, len(values))
	for index, value := range values {
		capabilities[index] = Capability(value)
	}
	return NewCapabilitySet(capabilities...)
}
