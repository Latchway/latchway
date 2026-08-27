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
	defaultAccessTokenTTL  = 10 * time.Minute
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

// UpstreamAuthentication identifies how server-held credentials are applied.
// SecretRef is only a name; decrypted secret material never enters a snapshot.
type UpstreamAuthentication struct {
	Type       string
	SecretRef  string
	HeaderName string
}

// UpstreamTimeouts are the fully defaulted transport limits for one target.
type UpstreamTimeouts struct {
	Connect   time.Duration
	FirstByte time.Duration
	Idle      time.Duration
	Total     time.Duration
}

// UpstreamDestinationPolicy contains the validated, server-owned SSRF policy.
// Version 1 keeps private-network access disabled even if persisted state is
// corrupted; explicit CIDR exceptions are not part of the current contract.
type UpstreamDestinationPolicy struct {
	AllowedPorts         []int
	AllowRedirects       bool
	AllowPrivateNetworks bool
	DNSPinning           bool
}

func (policy UpstreamDestinationPolicy) clone() UpstreamDestinationPolicy {
	policy.AllowedPorts = append([]int(nil), policy.AllowedPorts...)
	return policy
}

// Upstream is an immutable target description selected only by active config.
type Upstream struct {
	ID                         string
	Type                       string
	BaseURL                    string
	DangerousAllowInsecureHTTP bool
	Authentication             UpstreamAuthentication
	Timeouts                   UpstreamTimeouts
	DestinationPolicy          UpstreamDestinationPolicy
	StaticHeaders              map[string]string
}

func (upstream Upstream) clone() Upstream {
	upstream.DestinationPolicy = upstream.DestinationPolicy.clone()
	upstream.StaticHeaders = cloneStringMap(upstream.StaticHeaders)
	return upstream
}

// Model maps a client-facing feature route to one physical provider model.
type Model struct {
	ID            string
	UpstreamID    string
	UpstreamModel string
	PricingRef    string
	Capabilities  []string
}

func (model Model) clone() Model {
	model.Capabilities = append([]string(nil), model.Capabilities...)
	return model
}

// PricingEntry is the immutable integer-price schedule for one configured
// model. Prices are nano-USD per one million tokens plus an optional fixed
// request charge, so pricing never depends on binary floating point.
type PricingEntry struct {
	ModelID                 string
	InputNanoUSDPerMillion  int64
	OutputNanoUSDPerMillion int64
	RequestNanoUSD          int64
}

// PricingCatalog is one versioned USD price schedule. A nil EffectiveAt means
// the catalog is immediately effective; a non-nil value is the exact
// configured instant. Snapshot compilation deliberately does not consult a
// clock when preserving this policy.
type PricingCatalog struct {
	ID          string
	Currency    string
	EffectiveAt *time.Time
	Entries     []PricingEntry
}

func (catalog PricingCatalog) clone() PricingCatalog {
	if catalog.EffectiveAt != nil {
		effectiveAt := *catalog.EffectiveAt
		catalog.EffectiveAt = &effectiveAt
	}
	catalog.Entries = append([]PricingEntry(nil), catalog.Entries...)
	return catalog
}

// Entry returns the price entry for a model from a detached catalog value.
func (catalog PricingCatalog) Entry(modelID string) (PricingEntry, bool) {
	for _, entry := range catalog.Entries {
		if entry.ModelID == modelID {
			return entry, true
		}
	}
	return PricingEntry{}, false
}

// Limit is the normalized shape of one configured quota rule. Numeric fields
// are retained as integers or decimal text so enforced budgets never depend on
// binary floating-point arithmetic.
type Limit struct {
	Metric            string
	Algorithm         string
	Scope             []string
	Window            string
	Maximum           int64
	PerRequestMaximum int64
	Capacity          int64
	RefillPerSecond   json.Number
	Hard              bool
}

func (limit Limit) clone() Limit {
	limit.Scope = append([]string(nil), limit.Scope...)
	return limit
}

// LimitPlan is the immutable set of rules selected by a feature policy.
type LimitPlan struct {
	ID     string
	Limits []Limit
}

func (plan LimitPlan) clone() LimitPlan {
	plan.Limits = append([]Limit(nil), plan.Limits...)
	for index := range plan.Limits {
		plan.Limits[index] = plan.Limits[index].clone()
	}
	return plan
}

// OutputPolicy defines the server-owned default and absolute output clamp.
type OutputPolicy struct {
	DefaultMaximumTokens  int64
	AbsoluteMaximumTokens int64
}

// Route is one policy-guarded model choice within a feature.
type Route struct {
	ID         string
	When       string
	ModelID    string
	Priority   int64
	Weight     int64
	StickyBy   string
	FallbackOn []string
}

func (route Route) clone() Route {
	route.FallbackOn = append([]string(nil), route.FallbackOn...)
	return route
}

// OpaqueHTTPPolicy is the explicit request boundary for generic HTTP routes.
type OpaqueHTTPPolicy struct {
	AllowedMethods        []string
	PathPrefixes          []string
	MaximumBodyBytes      int64
	AllowedRequestHeaders []string
}

func (policy OpaqueHTTPPolicy) clone() OpaqueHTTPPolicy {
	policy.AllowedMethods = append([]string(nil), policy.AllowedMethods...)
	policy.PathPrefixes = append([]string(nil), policy.PathPrefixes...)
	policy.AllowedRequestHeaders = append([]string(nil), policy.AllowedRequestHeaders...)
	return policy
}

// Feature is the complete, immutable application-facing data-plane policy.
// CEL source is retained for bounded compilation by the policy resolver; raw
// client input can never introduce or replace these expressions.
type Feature struct {
	ID                  string
	Protocol            string
	AttestationPolicyID string
	AccessExpression    string
	LimitPlanExpression string
	Output              *OutputPolicy
	Routes              []Route
	OpaqueHTTP          *OpaqueHTTPPolicy
}

func (feature Feature) clone() Feature {
	if feature.Output != nil {
		output := *feature.Output
		feature.Output = &output
	}
	if feature.OpaqueHTTP != nil {
		opaque := feature.OpaqueHTTP.clone()
		feature.OpaqueHTTP = &opaque
	}
	feature.Routes = append([]Route(nil), feature.Routes...)
	for index := range feature.Routes {
		feature.Routes[index] = feature.Routes[index].clone()
	}
	return feature
}

func (policy AttestationPolicy) clone() AttestationPolicy {
	platforms := make(map[string]PlatformAttestation, len(policy.Platforms))
	for platform, selection := range policy.Platforms {
		platforms[platform] = selection.clone()
	}
	policy.Platforms = platforms
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
	upstreams    map[string]Upstream
	models       map[string]Model
	pricing      map[string]PricingCatalog
	limitPlans   map[string]LimitPlan
	features     map[string]Feature
}

// PolicyRevision returns the immutable cache identity for data-plane policy.
func (snapshot ActiveSnapshot) PolicyRevision() string { return snapshot.RevisionID }

// PolicyEnvironment returns the authoritative environment bound to the policy.
func (snapshot ActiveSnapshot) PolicyEnvironment() string { return snapshot.EnvironmentID }

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

// Upstream returns a deep copy of one configured server-owned target.
func (snapshot ActiveSnapshot) Upstream(upstreamID string) (Upstream, bool) {
	upstream, ok := snapshot.upstreams[upstreamID]
	return upstream.clone(), ok
}

// Model returns a deep copy of one configured physical model mapping.
func (snapshot ActiveSnapshot) Model(modelID string) (Model, bool) {
	model, ok := snapshot.models[modelID]
	return model.clone(), ok
}

// PricingCatalog returns a deep copy of one configured USD catalog.
func (snapshot ActiveSnapshot) PricingCatalog(catalogID string) (PricingCatalog, bool) {
	catalog, ok := snapshot.pricing[catalogID]
	return catalog.clone(), ok
}

// PricingEntry returns a value copy of one model entry in a catalog. It does
// not evaluate the catalog's EffectiveAt policy; time-sensitive callers must
// resolve the catalog and compare that timestamp using their trusted clock.
func (snapshot ActiveSnapshot) PricingEntry(catalogID, modelID string) (PricingEntry, bool) {
	catalog, ok := snapshot.pricing[catalogID]
	if !ok {
		return PricingEntry{}, false
	}
	return catalog.Entry(modelID)
}

// LimitPlan returns a deep copy of one configured quota plan.
func (snapshot ActiveSnapshot) LimitPlan(planID string) (LimitPlan, bool) {
	plan, ok := snapshot.limitPlans[planID]
	return plan.clone(), ok
}

// Feature returns a deep copy of one application-facing feature policy.
func (snapshot ActiveSnapshot) Feature(featureID string) (Feature, bool) {
	feature, ok := snapshot.features[featureID]
	return feature.clone(), ok
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

// RequiredAttestationForPlatform returns the only required attestation policy
// configured for a platform. Challenge creation has no policy identifier on
// the client wire request, so zero or multiple eligible policies are
// deliberately ambiguous and fail closed. Preferred and disabled selections
// are not eligible for the initial sealed-session exchange.
func (snapshot ActiveSnapshot) RequiredAttestationForPlatform(platform string) (AttestationPolicy, PlatformAttestation, bool) {
	var matchedPolicy AttestationPolicy
	var matchedSelection PlatformAttestation
	found := false
	for _, policy := range snapshot.attestations {
		selection, ok := policy.Platforms[platform]
		if !ok || selection.Mode != "required" {
			continue
		}
		if found {
			return AttestationPolicy{}, PlatformAttestation{}, false
		}
		matchedPolicy = policy.clone()
		matchedSelection = selection.clone()
		found = true
	}
	return matchedPolicy, matchedSelection, found
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
