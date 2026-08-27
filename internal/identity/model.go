// Package identity verifies application-owned identities and normalizes only
// explicitly configured claims before any attestation or session operation.
package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxIdentityCredentialBytes = 64 << 10

var (
	ErrCredentialInvalid = errors.New("identity credential is invalid")
	ErrCredentialExpired = errors.New("identity credential is expired")
	ErrKeyUnavailable    = errors.New("identity verification key is unavailable")
	ErrConfiguration     = errors.New("identity verifier configuration is invalid")
	ErrUserBlocked       = errors.New("application user is blocked")
	ErrUserNotFound      = errors.New("application user was not found")
	ErrIdentityScope     = errors.New("identity application scope is unavailable")
)

// RawIdentityCredential is deliberately redacted when formatted. Reveal is
// restricted to the verifier boundary; persistence code accepts only a
// VerifiedPrincipal.
type RawIdentityCredential struct {
	value string
}

func NewRawIdentityCredential(value string) (RawIdentityCredential, error) {
	if len(value) == 0 || len(value) > maxIdentityCredentialBytes || strings.ContainsAny(value, "\r\n\x00") {
		return RawIdentityCredential{}, ErrCredentialInvalid
	}
	return RawIdentityCredential{value: value}, nil
}

func (RawIdentityCredential) String() string   { return "[REDACTED]" }
func (RawIdentityCredential) GoString() string { return "identity.RawIdentityCredential{[REDACTED]}" }

func (credential RawIdentityCredential) reveal() string { return credential.value }

// VerifiedPrincipal is the provider-independent result consumed by the user
// resolver. Claims contains only explicitly mapped normalized values.
type VerifiedPrincipal struct {
	ProviderID      string
	Issuer          string
	Subject         string
	Audience        []string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Claims          map[string]any
}

func (principal VerifiedPrincipal) validate() error {
	if !providerIDPattern.MatchString(principal.ProviderID) || principal.Issuer == "" || principal.Subject == "" {
		return ErrCredentialInvalid
	}
	if len(principal.Subject) > 2048 || len(principal.Audience) == 0 || principal.AuthenticatedAt.IsZero() || principal.ExpiresAt.IsZero() || !principal.ExpiresAt.After(principal.AuthenticatedAt) {
		return ErrCredentialInvalid
	}
	if principal.Claims == nil {
		return ErrCredentialInvalid
	}
	return nil
}

// IdentityVerifier authenticates one configured identity-provider credential.
type IdentityVerifier interface {
	ID() string
	Verify(context.Context, RawIdentityCredential) (VerifiedPrincipal, error)
}

// VerificationKeySource resolves a server-configured key for a protected JWT
// header. Implementations must never derive a URL or secret from token claims.
type VerificationKeySource interface {
	Key(context.Context, string, string) (any, error)
}

func invalidCredential(reason string) error {
	return fmt.Errorf("%w: %s", ErrCredentialInvalid, reason)
}
