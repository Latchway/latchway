// Package clientapi implements the public client and signing-key HTTP
// contract. Security-sensitive verification and persistence are supplied by a
// coordinator so the transport cannot manufacture a successful session.
package clientapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/requestidentity"
)

// SensitiveString carries a credential or proof without exposing it through
// ordinary formatting. Reveal is deliberately explicit for cryptographic
// verification and response encoding at the final wire boundary.
type SensitiveString struct {
	material *sensitiveStringMaterial
}

type sensitiveStringMaterial struct {
	value string
}

// NewSensitiveString makes an immutable credential value. Endpoint-specific
// length and syntax checks remain at the transport and coordinator boundaries.
func NewSensitiveString(value string) SensitiveString {
	return SensitiveString{material: &sensitiveStringMaterial{value: value}}
}

// Reveal returns the contained value to trusted verification or encoding code.
func (value SensitiveString) Reveal() string {
	if value.material == nil {
		return ""
	}
	return value.material.value
}

// Format prevents proofs, identity credentials, and session tokens from
// reaching logs through fmt verbs such as %#v or %+v.
func (SensitiveString) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

// EvidencePayload is a bounded defensive copy of provider-specific
// attestation evidence. Its contents are never formatted.
type EvidencePayload struct {
	material *evidencePayloadMaterial
}

type evidencePayloadMaterial struct {
	encoded []byte
}

func newEvidencePayload(value map[string]any) (EvidencePayload, error) {
	if value == nil || len(value) > maximumEvidenceMembers {
		return EvidencePayload{}, errors.New("invalid attestation evidence object")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maximumEvidenceBytes {
		return EvidencePayload{}, errors.New("invalid attestation evidence encoding")
	}
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		return EvidencePayload{}, errors.New("invalid attestation evidence JSON")
	}
	if _, ok := decoded.(map[string]any); !ok {
		return EvidencePayload{}, errors.New("attestation evidence is not an object")
	}
	return EvidencePayload{material: &evidencePayloadMaterial{encoded: append([]byte(nil), encoded...)}}, nil
}

// Object returns a defensive copy for a trusted provider verifier.
func (payload EvidencePayload) Object() (map[string]any, error) {
	if payload.material == nil {
		return nil, errors.New("attestation evidence payload is unavailable")
	}
	decoded, err := jsonsafe.Decode(append([]byte(nil), payload.material.encoded...))
	if err != nil {
		return nil, errors.New("attestation evidence payload is unavailable")
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("attestation evidence payload is unavailable")
	}
	return object, nil
}

// Format prevents provider evidence from reaching logs through fmt.
func (EvidencePayload) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

// RequestMetadata contains the server-owned logical request ID, verified
// transport declarations, and the server-constructed request target.
// RequestID never derives from an inbound correlation header. TargetURL never
// derives from inbound Host or forwarding headers.
type RequestMetadata struct {
	RequestID  string
	SDK        string
	SDKVersion string
	HTTPMethod string
	TargetURL  url.URL
	DPoPProof  SensitiveString
}

type ChallengeInput struct {
	Metadata         RequestMetadata
	ApplicationID    string
	Environment      string
	IdentityProvider string
	IdentityToken    SensitiveString
	Platform         string
}

type AttestationEvidence struct {
	Provider string
	Payload  EvidencePayload
}

type InstallationMetadata struct {
	AppVersion  string
	OSVersion   string
	DeviceModel string
}

type ExchangeInput struct {
	Metadata     RequestMetadata
	ChallengeID  string
	Attestation  AttestationEvidence
	Installation InstallationMetadata
}

type RefreshInput struct {
	Metadata         RequestMetadata
	RefreshToken     SensitiveString
	IdentityToken    SensitiveString
	HasIdentityToken bool
	Attestation      *AttestationEvidence
}

// RevokeInstallationInput contains the DPoP access credential and the
// server-constructed request metadata needed to authenticate revocation of
// the installation named by that credential. Neither sensitive value is
// exposed through ordinary formatting.
type RevokeInstallationInput struct {
	Metadata    RequestMetadata
	AccessToken SensitiveString
}

// FeatureQuotaInput contains the authenticated credential and canonical
// server-owned request identity needed to resolve one feature's effective
// quota. LogicalRequestID remains opaque so callers cannot substitute a
// client correlation hint for the authoritative request identity.
type FeatureQuotaInput struct {
	Metadata         RequestMetadata
	LogicalRequestID requestidentity.LogicalID
	AccessToken      SensitiveString
	Feature          string
}

// FeatureQuotaLimit is one safe, effective hard-limit projection. Optional
// counters use pointers so absence remains distinct from zero.
type FeatureQuotaLimit struct {
	Metric    string
	Maximum   *int64
	Used      *int64
	Reserved  *int64
	Remaining *int64
	ResetsAt  *time.Time
	Hard      bool
}

// FeatureQuotaResult is the provider-owned snapshot returned to the client
// transport. The transport validates and defensively copies it before JSON
// encoding.
type FeatureQuotaResult struct {
	Feature    string
	ObservedAt time.Time
	Limits     []FeatureQuotaLimit
}

// FeatureQuotaProvider authenticates the DPoP-bound session and returns only
// the effective quota projection safe for the current principal. It is kept
// separate from Coordinator because quota reads are data-plane operations,
// not session lifecycle operations.
type FeatureQuotaProvider interface {
	FeatureQuota(context.Context, FeatureQuotaInput) (FeatureQuotaResult, error)
}

type AttestationRequirement struct {
	Provider        string
	Mode            string
	ClientDataHash  string
	ProviderOptions map[string]any
}

type ChallengeResult struct {
	ChallengeID    string
	ChallengeNonce string
	BindingVersion int
	IssuedAt       int64
	ExpiresAt      time.Time
	Attestation    AttestationRequirement
}

type InstallationSummary struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	DPoPJKT  string `json:"dpop_jkt"`
	Status   string `json:"status"`
}

type TrustSummary struct {
	Provider   string    `json:"provider"`
	Level      string    `json:"level"`
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type GrantResult struct {
	AccessToken      SensitiveString
	ExpiresIn        int
	RefreshToken     SensitiveString
	RefreshExpiresIn int
	Installation     InstallationSummary
	Trust            TrustSummary
}

// Coordinator is the fail-closed application boundary behind the client wire
// handlers. Implementations verify identity, DPoP, attestation, configuration,
// and durable session state before returning a result.
type Coordinator interface {
	CreateChallenge(context.Context, ChallengeInput) (ChallengeResult, error)
	ExchangeSession(context.Context, ExchangeInput) (GrantResult, error)
	RefreshSession(context.Context, RefreshInput) (GrantResult, error)
	RevokeCurrentInstallation(context.Context, RevokeInstallationInput) error
}

type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type JWKS struct {
	Keys []PublicJWK `json:"keys"`
}

// JWKSProvider returns only public session-signing members. The transport
// validates the result again before publication.
type JWKSProvider interface {
	PublicJWKS(context.Context) (JWKS, error)
}

// DependencyError lets a trusted dependency select a registered,
// redaction-safe client problem. Detail text is intentionally not
// dependency-controlled.
type DependencyError struct {
	Code              string
	RetryAfterSeconds int
	DPoPNonce         string
}

func (failure *DependencyError) Error() string {
	if failure == nil {
		return "client dependency failure"
	}
	return failure.Code
}
