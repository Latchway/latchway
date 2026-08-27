// Package configuration owns immutable environment configuration revisions,
// their validation and compilation, and the active revision pointer.
package configuration

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalid              = errors.New("invalid configuration operation")
	ErrForbidden            = errors.New("configuration operation forbidden")
	ErrNotFound             = errors.New("configuration revision not found")
	ErrConflict             = errors.New("configuration revision conflict")
	ErrETagMismatch         = errors.New("configuration revision ETag mismatch")
	ErrConfigurationInvalid = errors.New("configuration validation failed")
)

const (
	StateDraft      = "draft"
	StateValid      = "valid"
	StateActive     = "active"
	StateSuperseded = "superseded"
	StateInvalid    = "invalid"
)

// TenantScope selects one application environment without relying on values
// supplied by an untrusted configuration document.
type TenantScope struct {
	OrganizationID string
	ApplicationID  string
	EnvironmentID  string
}

// EnvironmentDescriptor is the authoritative database identity used during
// metadata and environment-specific policy validation.
type EnvironmentDescriptor struct {
	TenantScope
	OrganizationSlug string
	ApplicationSlug  string
	EnvironmentSlug  string
	EnvironmentKind  string
	SecretNames      map[string]struct{}
}

// Revision is the redaction-safe Admin API representation of one revision.
// ETag and compiled state are deliberately transported out of band.
type Revision struct {
	ID            string            `json:"id"`
	EnvironmentID string            `json:"environment_id"`
	State         string            `json:"state"`
	Version       int64             `json:"version"`
	Document      json.RawMessage   `json:"document"`
	Validation    *ValidationReport `json:"validation,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	CreatedBy     string            `json:"created_by"`
	ActivatedAt   *time.Time        `json:"activated_at,omitempty"`
	ETag          string            `json:"-"`

	organizationID string
	applicationID  string
	baseRevisionID string
	compiled       json.RawMessage
	storedState    string
	editVersion    int64
}

// CreateInput creates either an explicit draft or a copy of the current
// active revision. Exactly one of Document and BaseRevisionID must be set.
type CreateInput struct {
	EnvironmentID  string
	BaseRevisionID string
	Document       json.RawMessage
	Description    string
}

// PageRequest is a descending keyset page over (created_at, revision_id).
type PageRequest struct {
	Before   time.Time
	BeforeID string
	Size     int32
}

// Issue is deterministic, redaction-safe validation output.
type Issue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

// ValidationReport is persisted with the revision that was checked.
type ValidationReport struct {
	Valid     bool      `json:"valid"`
	CheckedAt time.Time `json:"checked_at"`
	Issues    []Issue   `json:"issues"`
}

// ValidationFailure carries safe field-level issues while preserving a
// stable sentinel for HTTP error mapping.
type ValidationFailure struct {
	Issues []Issue
}

func (failure *ValidationFailure) Error() string { return ErrConfigurationInvalid.Error() }
func (failure *ValidationFailure) Unwrap() error { return ErrConfigurationInvalid }

// Plan describes structure only. It never includes before or after values.
type Plan struct {
	FromRevisionID string       `json:"from_revision_id"`
	ToRevisionID   string       `json:"to_revision_id"`
	Changes        []PlanChange `json:"changes"`
	Warnings       []Issue      `json:"warnings"`
}

// PlanChange identifies a value-redacted structural change.
type PlanChange struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
	Summary   string `json:"summary,omitempty"`
}

const (
	defaultAccessTokenTTL  = 15 * time.Minute
	defaultChallengeTTL    = 5 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultClockSkew       = 60 * time.Second
	defaultAttestationAge  = 24 * time.Hour
)

// SessionPolicy is the bounded, fully defaulted policy used by session code.
type SessionPolicy struct {
	AccessTokenTTL   time.Duration
	ChallengeTTL     time.Duration
	RefreshTokenTTL  time.Duration
	MaximumClockSkew time.Duration
}

// IdentityProvider is an immutable typed view of a compiled provider. Secret
// references are identifiers only; secret values never enter a snapshot.
type IdentityProvider struct {
	ID                       string            `json:"id"`
	Type                     string            `json:"type"`
	ProjectID                string            `json:"projectId,omitempty"`
	ProjectURL               string            `json:"projectUrl,omitempty"`
	Issuer                   string            `json:"issuer,omitempty"`
	Audiences                []string          `json:"audiences,omitempty"`
	AuthorizedParties        []string          `json:"authorizedParties,omitempty"`
	AllowedAlgorithms        []string          `json:"allowedAlgorithms,omitempty"`
	JWKSURL                  string            `json:"jwksUrl,omitempty"`
	StaticPublicKeySecretRef string            `json:"staticPublicKeySecretRef,omitempty"`
	SymmetricSecretRef       string            `json:"symmetricSecretRef,omitempty"`
	AcknowledgeSymmetricRisk bool              `json:"acknowledgeSymmetricRisk"`
	SubjectClaim             string            `json:"subjectClaim"`
	ClockSkewSeconds         int               `json:"clockSkewSeconds"`
	RequiredClaims           []string          `json:"requiredClaims,omitempty"`
	ClaimMappings            map[string]string `json:"claimMappings,omitempty"`
}

func (provider IdentityProvider) clone() IdentityProvider {
	provider.Audiences = append([]string(nil), provider.Audiences...)
	provider.AuthorizedParties = append([]string(nil), provider.AuthorizedParties...)
	provider.AllowedAlgorithms = append([]string(nil), provider.AllowedAlgorithms...)
	provider.RequiredClaims = append([]string(nil), provider.RequiredClaims...)
	provider.ClaimMappings = cloneStringMap(provider.ClaimMappings)
	return provider
}

// PlatformAttestation is a compiled provider selection for one client
// platform. Its SecretRef names server-side material but never contains it.
type PlatformAttestation struct {
	Provider                   string   `json:"provider"`
	Mode                       string   `json:"mode"`
	MinimumTrustLevel          string   `json:"minimumTrustLevel,omitempty"`
	ApplicationIdentifiers     []string `json:"applicationIdentifiers,omitempty"`
	AllowedOrigins             []string `json:"allowedOrigins,omitempty"`
	SecretRef                  string   `json:"secretRef,omitempty"`
	DangerousAllowInProduction bool     `json:"dangerousAllowInProduction"`
}

func (selection PlatformAttestation) clone() PlatformAttestation {
	selection.ApplicationIdentifiers = append([]string(nil), selection.ApplicationIdentifiers...)
	selection.AllowedOrigins = append([]string(nil), selection.AllowedOrigins...)
	return selection
}

// AttestationPolicy is an immutable typed policy indexed by platform.
type AttestationPolicy struct {
	ID        string                         `json:"id"`
	MaxAge    time.Duration                  `json:"-"`
	Platforms map[string]PlatformAttestation `json:"-"`
}

func (policy AttestationPolicy) clone() AttestationPolicy {
	policy.Platforms = make(map[string]PlatformAttestation, len(policy.Platforms))
	for platform, selection := range policy.Platforms {
		policy.Platforms[platform] = selection.clone()
	}
	return policy
}

// ActiveSnapshot is an immutable, deep-copying view of the exact compiled
// document selected by the active pointer.
type ActiveSnapshot struct {
	RevisionID    string
	EnvironmentID string

	document     json.RawMessage
	compiled     json.RawMessage
	session      SessionPolicy
	identities   map[string]IdentityProvider
	attestations map[string]AttestationPolicy
}

// DocumentJSON returns a copy of the immutable source document.
func (snapshot ActiveSnapshot) DocumentJSON() json.RawMessage {
	return append(json.RawMessage(nil), snapshot.document...)
}

// CompiledJSON returns a copy of the normalized compiled document.
func (snapshot ActiveSnapshot) CompiledJSON() json.RawMessage {
	return append(json.RawMessage(nil), snapshot.compiled...)
}

// SessionPolicy returns a value copy of the fully defaulted session policy.
func (snapshot ActiveSnapshot) SessionPolicy() SessionPolicy { return snapshot.session }

// IdentityProvider returns a deep copy of a configured provider.
func (snapshot ActiveSnapshot) IdentityProvider(providerID string) (IdentityProvider, bool) {
	provider, ok := snapshot.identities[providerID]
	return provider.clone(), ok
}

// AttestationPolicy returns a deep copy of a configured policy.
func (snapshot ActiveSnapshot) AttestationPolicy(policyID string) (AttestationPolicy, bool) {
	policy, ok := snapshot.attestations[policyID]
	return policy.clone(), ok
}

// SelectAttestation returns the exact provider selection for a policy and
// platform without exposing mutable snapshot state.
func (snapshot ActiveSnapshot) SelectAttestation(policyID, platform string) (PlatformAttestation, bool) {
	policy, ok := snapshot.attestations[policyID]
	if !ok {
		return PlatformAttestation{}, false
	}
	selection, ok := policy.Platforms[platform]
	return selection.clone(), ok
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
