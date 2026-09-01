// Package policy evaluates bounded, server-owned feature policy independently
// from HTTP transport, protocol inspection, quota persistence, and dispatch.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/limitscope"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/useroverride"
	"github.com/latchway/latchway/internal/weborigin"
)

var (
	ErrFeatureNotFound   = errors.New("feature not found")
	ErrFeatureNotAllowed = errors.New("feature not allowed")
	ErrLimitPlanNotFound = errors.New("limit plan not found")
	ErrRouteNotFound     = errors.New("route not found")
	ErrInvalidInput      = errors.New("invalid policy input")
	ErrConfiguration     = errors.New("invalid active policy configuration")
)

const (
	maximumRuntimeCost      = 10_000
	maximumActivationDepth  = 32
	maximumActivationValues = 4_096
	maximumActivationBytes  = 128 << 10
	maximumCachedFeatures   = 1_024
)

var policyIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// ProtocolRequestMetadata is the complete allowlist of adapter-derived values
// that may enter feature CEL. Feature and protocol are deliberately private:
// ResolvePlan binds them from the immutable Feature after lookup, so a caller
// cannot smuggle either server-owned value into policy. Model, plan, route,
// headers, and trusted accounting proofs have no representation here.
type ProtocolRequestMetadata struct {
	Streaming            bool
	EstimatedInputTokens int64
	MaximumOutputTokens  int64
	feature              string
	protocol             string
}

// EnvironmentFacts contains the allowlisted environment state supplied by the
// trusted server composition layer. Kind must exactly match the durable value
// loaded into the session authorization.
type EnvironmentFacts struct {
	Kind string
}

type authorizationFacts struct {
	organizationID           string
	applicationID            string
	environmentID            string
	policyRevisionID         string
	userOverrideID           string
	limitPlanOverride        string
	userID                   string
	installationID           string
	installationFamilyID     string
	installationFamilyStatus string
	componentID              string
	componentDefinitionID    string
	componentKind            string
	componentIsRoot          bool
	trustSource              string
	installationPlatform     string
	identityProvider         string
	trustLevel               string
	attestationProvider      string
	claims                   map[string]any
	identityExpiresAt        time.Time
	attestedAt               time.Time
	attestationExpiresAt     time.Time
	accessExpiresAt          time.Time
}

// Input is an opaque, immutable policy activation. Production callers can
// create one only through NewInput, which consumes a tamper-evident
// session.Authorization and the opaque logical identity installed by the
// server request middleware.
type Input struct {
	authorization    authorizationFacts
	request          ProtocolRequestMetadata
	environment      EnvironmentFacts
	logicalRequestID string
	unauthenticated  bool
}

// SimulationFacts is the bounded, server-owned input accepted by the
// administrative route simulator. It deliberately requires canonical tenant
// identifiers and the exact revision selected by the configuration store so a
// caller cannot use simulation to bypass the production snapshot boundary.
// Production data-plane callers continue to use NewInput and a sealed session
// authorization.
type SimulationFacts struct {
	OrganizationID           string
	ApplicationID            string
	EnvironmentID            string
	EnvironmentKind          string
	PolicyRevisionID         string
	UserOverrideID           string
	LimitPlanOverride        string
	ApplicationUserID        string
	InstallationID           string
	InstallationFamilyID     string
	InstallationFamilyStatus string
	ComponentID              string
	ComponentDefinitionID    string
	ComponentKind            string
	ComponentIsRoot          bool
	TrustSource              string
	LogicalRequestID         string
	InstallationPlatform     string
	IdentityProvider         string
	TrustLevel               string
	AttestationProvider      string
	Authenticated            bool
	NormalizedClaims         map[string]any
	Streaming                bool
	EstimatedInputTokens     int64
	MaximumOutputTokens      int64
	EvaluatedAt              time.Time
}

// NewSimulationInput constructs a synthetic policy activation exclusively for
// authenticated control-plane explanation. It shares ResolvePlan, CEL,
// attestation, weighted selection, and fallback ordering with production while
// issuing no session and performing no upstream dispatch.
func NewSimulationInput(facts SimulationFacts) (Input, error) {
	evaluatedAt := facts.EvaluatedAt.UTC()
	if evaluatedAt.IsZero() ||
		id.Validate(facts.OrganizationID, id.Organization) != nil ||
		id.Validate(facts.ApplicationID, id.Application) != nil ||
		id.Validate(facts.EnvironmentID, id.Environment) != nil ||
		id.Validate(facts.PolicyRevisionID, id.ConfigRevision) != nil ||
		id.Validate(facts.ApplicationUserID, id.ApplicationUser) != nil ||
		id.Validate(facts.InstallationID, id.Installation) != nil ||
		id.Validate(facts.LogicalRequestID, id.LogicalRequest) != nil ||
		!validEnvironmentKind(facts.EnvironmentKind) ||
		!validPlatform(facts.InstallationPlatform) ||
		!policyIdentifierPattern.MatchString(facts.IdentityProvider) ||
		!validTrustLevel(facts.TrustLevel) ||
		!validAttestationProvider(facts.AttestationProvider) ||
		facts.NormalizedClaims == nil {
		return Input{}, ErrInvalidInput
	}

	// Thirty days is only a synthetic evaluation horizon. The configured
	// attestation policy's maxAge is still enforced from EvaluatedAt, and the
	// result is never usable as a session authorization.
	horizon := evaluatedAt.Add(30 * 24 * time.Hour)
	input := Input{
		authorization: authorizationFacts{
			organizationID: facts.OrganizationID, applicationID: facts.ApplicationID,
			environmentID: facts.EnvironmentID, policyRevisionID: facts.PolicyRevisionID,
			userOverrideID: facts.UserOverrideID, limitPlanOverride: facts.LimitPlanOverride,
			userID: facts.ApplicationUserID, installationID: facts.InstallationID,
			installationFamilyID:     facts.InstallationFamilyID,
			installationFamilyStatus: facts.InstallationFamilyStatus,
			componentID:              facts.ComponentID, componentDefinitionID: facts.ComponentDefinitionID,
			componentKind: facts.ComponentKind, componentIsRoot: facts.ComponentIsRoot,
			trustSource:          facts.TrustSource,
			installationPlatform: facts.InstallationPlatform, identityProvider: facts.IdentityProvider,
			trustLevel: facts.TrustLevel, attestationProvider: facts.AttestationProvider,
			claims: cloneClaims(facts.NormalizedClaims), identityExpiresAt: horizon,
			attestedAt: evaluatedAt, attestationExpiresAt: horizon, accessExpiresAt: horizon,
		},
		request: ProtocolRequestMetadata{
			Streaming: facts.Streaming, EstimatedInputTokens: facts.EstimatedInputTokens,
			MaximumOutputTokens: facts.MaximumOutputTokens,
		},
		environment:      EnvironmentFacts{Kind: facts.EnvironmentKind},
		logicalRequestID: facts.LogicalRequestID,
		unauthenticated:  !facts.Authenticated,
	}
	if !validInput(input) {
		return Input{}, ErrInvalidInput
	}
	if _, err := boundedActivation(input); err != nil {
		return Input{}, err
	}
	return input, nil
}

// NewInput builds the only production policy boundary. Client request IDs and
// raw strings are intentionally not accepted: logicalID can only originate in
// requestidentity middleware and must be reused for routing and quota work.
func NewInput(authorization session.Authorization, logicalID requestidentity.LogicalID, request ProtocolRequestMetadata, environment EnvironmentFacts) (Input, error) {
	return newInputAt(authorization, logicalID, request, environment, time.Now().UTC())
}

func newInputAt(authorization session.Authorization, logicalID requestidentity.LogicalID, request ProtocolRequestMetadata, environment EnvironmentFacts, now time.Time) (Input, error) {
	snapshot, err := authorization.ValidatedSnapshot(now)
	if err != nil {
		return Input{}, err
	}
	if !validEnvironmentKind(environment.Kind) || environment.Kind != snapshot.EnvironmentKind {
		return Input{}, ErrInvalidInput
	}
	return inputFromAuthorization(snapshot, logicalID, request, environment)
}

func inputFromAuthorization(authorization session.Authorization, logicalID requestidentity.LogicalID, request ProtocolRequestMetadata, environment EnvironmentFacts) (Input, error) {
	logicalRequestID := logicalID.String()
	if id.Validate(logicalRequestID, id.LogicalRequest) != nil {
		return Input{}, ErrInvalidInput
	}
	return Input{
		authorization: authorizationFacts{
			organizationID: authorization.OrganizationID, applicationID: authorization.ApplicationID,
			environmentID: authorization.EnvironmentID, policyRevisionID: authorization.PolicyRevisionID,
			userOverrideID: authorization.UserOverrideID, limitPlanOverride: authorization.LimitPlanOverride,
			userID: authorization.ApplicationUserID, installationID: authorization.InstallationID,
			installationFamilyID:     authorization.InstallationFamilyID,
			installationFamilyStatus: authorization.InstallationFamilyStatus,
			componentID:              authorization.ComponentID,
			componentDefinitionID:    authorization.ComponentDefinitionID,
			componentKind:            authorization.ComponentKind, componentIsRoot: authorization.ComponentIsRoot,
			trustSource:          authorization.TrustSource,
			installationPlatform: authorization.InstallationPlatform, identityProvider: authorization.IdentityProvider,
			trustLevel: authorization.TrustLevel, attestationProvider: authorization.AttestationProvider,
			claims: cloneClaims(authorization.NormalizedClaims), identityExpiresAt: authorization.IdentityExpiresAt,
			attestedAt: authorization.AttestedAt, attestationExpiresAt: authorization.AttestationExpiresAt,
			accessExpiresAt: authorization.AccessExpiresAt,
		},
		request: request, environment: environment, logicalRequestID: logicalRequestID,
	}, nil
}

// LogicalRequestID returns the server-generated request identity that must be
// reused by quota reservation, attempts, diagnostics and response metadata.
func (input Input) LogicalRequestID() string { return input.logicalRequestID }

// ApplicationUserID returns the durable internal principal selected by the
// authorization store; it is never copied from a token or request body.
func (input Input) ApplicationUserID() string { return input.authorization.userID }

// InstallationID returns the durable installation selected by authorization.
func (input Input) InstallationID() string { return input.authorization.installationID }

// Decision is the complete server-owned physical choice for one request.
type Decision struct {
	Feature   configuration.Feature
	LimitPlan configuration.LimitPlan
	Route     configuration.Route
	Model     configuration.Model
	Upstream  configuration.Upstream
	Scopes    QuotaScopeFacts
}

// QuotaScopeFacts are derived only inside the policy boundary after a sealed
// session authorization has been validated. NormalizedClaims contains opaque
// domain-separated digests keyed by configured normalized claim name; raw
// normalized claim values never cross into quota, replay, or persistence.
type QuotaScopeFacts struct {
	Platform              string
	InstallationFamilyID  string
	ClientComponentID     string
	ComponentDefinitionID string
	ComponentKind         string
	TrustSource           string
	NormalizedClaims      map[string]string
}

// RouteDecision is one server-owned physical candidate in a deterministic
// route plan. Candidates are ordered for dispatch, but moving to the next
// candidate is permitted only when the current route's FallbackOn policy
// accepts the executor's typed terminal outcome.
type RouteDecision struct {
	Route    configuration.Route
	Model    configuration.Model
	Upstream configuration.Upstream
}

// DecisionPlan captures access, limit-plan, and every matched physical route
// from one immutable policy evaluation. The first candidate is the primary
// route. Later candidates are inert until a bounded executor applies the
// preceding candidate's fallback policy.
type DecisionPlan struct {
	Feature    configuration.Feature
	LimitPlan  configuration.LimitPlan
	Candidates []RouteDecision
	Scopes     QuotaScopeFacts
}

// QuotaProjection is the request-shape-independent feature and limit plan
// selected for a quota snapshot. Each returned value is deeply detached from
// the immutable configuration snapshot and the resolver's compiled cache.
type QuotaProjection struct {
	Feature   configuration.Feature
	LimitPlan configuration.LimitPlan
	Scopes    QuotaScopeFacts
}

// Snapshot is the minimum immutable configuration surface required by policy
// resolution. configuration.ActiveSnapshot is its production implementation.
type Snapshot interface {
	PolicyRevision() string
	PolicyEnvironment() string
	Feature(string) (configuration.Feature, bool)
	AttestationPolicy(string) (configuration.AttestationPolicy, bool)
	RequiredAttestationForPlatform(string) (configuration.AttestationPolicy, configuration.PlatformAttestation, bool)
	LimitPlan(string) (configuration.LimitPlan, bool)
	Model(string) (configuration.Model, bool)
	Upstream(string) (configuration.Upstream, bool)
}

var _ Snapshot = configuration.ActiveSnapshot{}

type compiledFeature struct {
	access                    cel.Program
	limitPlan                 cel.Program
	accessNeedsRequestSize    bool
	limitPlanNeedsRequestSize bool
	routes                    []compiledRoute
}

type compiledRoute struct {
	configuration.Route
	when cel.Program
}

type cacheKey struct {
	revisionID    string
	environmentID string
	featureID     string
	fingerprint   [sha256.Size]byte
}

// Resolver compiles bounded CEL once per immutable feature revision and is
// safe for concurrent request resolution.
type Resolver struct {
	environment *cel.Env
	now         func() time.Time
	// validateAuthorization is fixed by newResolver. Keeping the dependency
	// private preserves the sealed session boundary while allowing this package's
	// tests to prove single-call and single-clock behavior without manufacturing
	// session seals outside the session package.
	validateAuthorization func(session.Authorization, time.Time) (session.Authorization, error)

	mu    sync.RWMutex
	cache map[cacheKey]*compiledFeature
}

// NewResolver constructs the exact policy environment used by configuration
// validation and adds runtime cost and cancellation enforcement to programs.
func NewResolver() (*Resolver, error) {
	return newResolver(time.Now)
}

func newResolver(now func() time.Time) (*Resolver, error) {
	if now == nil {
		return nil, fmt.Errorf("%w: policy clock", ErrConfiguration)
	}
	environment, err := cel.NewEnv(
		cel.Variable("principal", cel.DynType),
		cel.Variable("client", cel.DynType),
		cel.Variable("installation", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("environment", cel.DynType),
		cel.ParserExpressionSizeLimit(4096),
		cel.ParserRecursionLimit(64),
		cel.ExpressionNestingDepthLimit(32),
		cel.ExpressionNodeLimit(1_000),
		cel.RegexProgramSizeLimit(1_000),
		cel.ExtendedValidations(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: construct CEL environment", ErrConfiguration)
	}
	return &Resolver{
		environment: environment,
		now:         now,
		validateAuthorization: func(authorization session.Authorization, at time.Time) (session.Authorization, error) {
			return authorization.ValidatedSnapshot(at)
		},
		cache: make(map[cacheKey]*compiledFeature),
	}, nil
}

// Resolve evaluates one complete deterministic route plan and returns its
// primary physical decision. The full ordered plan is available through
// ResolvePlan so production dispatch and route simulation can share exactly
// the same policy evaluation.
func (resolver *Resolver) Resolve(ctx context.Context, snapshot Snapshot, featureID string, input Input) (Decision, error) {
	plan, err := resolver.ResolvePlan(ctx, snapshot, featureID, input)
	if err != nil {
		return Decision{}, err
	}
	if len(plan.Candidates) == 0 {
		return Decision{}, ErrRouteNotFound
	}
	primary := plan.Candidates[0]
	return Decision{
		Feature: plan.Feature, LimitPlan: plan.LimitPlan,
		Route: primary.Route, Model: primary.Model, Upstream: primary.Upstream,
		Scopes: cloneQuotaScopeFacts(plan.Scopes),
	}, nil
}

// ResolvePlan evaluates access, limit-plan selection, and every route
// predicate exactly once, then returns a detached deterministic weighted
// ordering across all matching priority groups. It fails closed when any
// matched candidate cannot resolve its configured model, capability, or
// upstream from the same immutable snapshot.
func (resolver *Resolver) ResolvePlan(
	ctx context.Context,
	snapshot Snapshot,
	featureID string,
	input Input,
) (DecisionPlan, error) {
	if resolver == nil || resolver.environment == nil || resolver.now == nil || resolver.cache == nil || ctx == nil ||
		snapshot == nil || !policyIdentifierPattern.MatchString(featureID) {
		return DecisionPlan{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return DecisionPlan{}, err
	}
	// Protected policy resolution always operates on durable, server-owned
	// identities. Validate them even when the selected route does not happen to
	// use a particular sticky key so later quota and persistence layers cannot be
	// wired to an untrusted correlation hint by accident.
	if !validInput(input) {
		return DecisionPlan{}, ErrInvalidInput
	}
	now := resolver.now().UTC()
	if now.IsZero() || !input.authorization.accessExpiresAt.After(now) || !input.authorization.identityExpiresAt.After(now) {
		return DecisionPlan{}, session.ErrTokenExpired
	}
	feature, ok := snapshot.Feature(featureID)
	if !ok {
		return DecisionPlan{}, ErrFeatureNotFound
	}
	input, err := bindRequestFeature(input, featureID, feature)
	if err != nil {
		return DecisionPlan{}, err
	}
	if err := enforceFeatureAttestation(snapshot, feature, input.authorization, now); err != nil {
		return DecisionPlan{}, err
	}
	activation, err := boundedActivation(input)
	if err != nil {
		return DecisionPlan{}, err
	}
	compiled, err := resolver.compiled(snapshot, feature)
	if err != nil {
		return DecisionPlan{}, err
	}
	allowed, err := evaluateBool(ctx, compiled.access, activation)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return DecisionPlan{}, ctxErr
		}
		return DecisionPlan{}, ErrFeatureNotAllowed
	}
	if !allowed {
		return DecisionPlan{}, ErrFeatureNotAllowed
	}
	planID, err := selectLimitPlanID(ctx, compiled.limitPlan, activation, input.authorization.limitPlanOverride)
	if err != nil {
		return DecisionPlan{}, err
	}
	plan, err := resolveLimitPlan(snapshot, planID)
	if err != nil {
		return DecisionPlan{}, err
	}
	scopes, err := quotaScopeFacts(input.authorization, plan)
	if err != nil {
		return DecisionPlan{}, err
	}
	matched := make([]configuration.Route, 0, len(compiled.routes))
	for _, route := range compiled.routes {
		matches, evalErr := evaluateBool(ctx, route.when, activation)
		if evalErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return DecisionPlan{}, ctxErr
			}
			return DecisionPlan{}, fmt.Errorf("%w: evaluate route %s", ErrConfiguration, route.ID)
		}
		if matches {
			matched = append(matched, cloneRoute(route.Route))
		}
	}
	ordered, err := orderRoutes(feature.ID, matched, input)
	if err != nil {
		return DecisionPlan{}, err
	}
	candidates := make([]RouteDecision, 0, len(ordered))
	for _, route := range ordered {
		model, found := snapshot.Model(route.ModelID)
		if !found || !slices.Contains(model.Capabilities, feature.Protocol) {
			return DecisionPlan{}, ErrRouteNotFound
		}
		upstream, found := snapshot.Upstream(model.UpstreamID)
		if !found {
			return DecisionPlan{}, ErrRouteNotFound
		}
		if route.Timeouts != nil {
			upstream.Timeouts = *route.Timeouts
		}
		candidates = append(candidates, RouteDecision{
			Route: cloneRoute(route), Model: cloneModel(model), Upstream: cloneUpstream(upstream),
		})
	}
	return DecisionPlan{
		Feature: cloneFeature(feature), LimitPlan: cloneLimitPlan(plan), Candidates: candidates,
		Scopes: scopes,
	}, nil
}

// ResolveQuota binds the immutable feature/protocol and evaluates streaming in
// both states. A quota snapshot has no concrete request body, so policy that
// uses estimated input or requested output size cannot produce a truthful
// projection. Access and the complete selected limit plan must otherwise be
// identical before return. Physical routing is not evaluated or selected.
func (resolver *Resolver) ResolveQuota(
	ctx context.Context,
	snapshot Snapshot,
	featureID string,
	authorization session.Authorization,
	logicalID requestidentity.LogicalID,
	environment EnvironmentFacts,
) (QuotaProjection, error) {
	if resolver == nil || resolver.environment == nil || resolver.now == nil ||
		resolver.validateAuthorization == nil || resolver.cache == nil || ctx == nil ||
		snapshot == nil || !policyIdentifierPattern.MatchString(featureID) {
		return QuotaProjection{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return QuotaProjection{}, err
	}

	// This is the only clock read in the quota operation. Session validation,
	// attestation freshness, and both CEL activations share this exact instant.
	now := resolver.now().UTC()
	validated, err := resolver.validateAuthorization(authorization, now)
	if err != nil {
		return QuotaProjection{}, err
	}
	if !validEnvironmentKind(environment.Kind) || environment.Kind != validated.EnvironmentKind {
		return QuotaProjection{}, ErrInvalidInput
	}
	nonStreaming, err := inputFromAuthorization(
		validated, logicalID, ProtocolRequestMetadata{Streaming: false}, environment,
	)
	if err != nil || !validInput(nonStreaming) {
		return QuotaProjection{}, ErrInvalidInput
	}
	feature, ok := snapshot.Feature(featureID)
	if !ok {
		return QuotaProjection{}, ErrFeatureNotFound
	}
	nonStreaming, err = bindRequestFeature(nonStreaming, featureID, feature)
	if err != nil {
		return QuotaProjection{}, err
	}
	streaming := nonStreaming
	streaming.request.Streaming = true
	// Feature attestation is request-shape invariant. Enforce it once against
	// the same validated authorization and instant shared by both activations.
	if err := enforceFeatureAttestation(snapshot, feature, nonStreaming.authorization, now); err != nil {
		return QuotaProjection{}, err
	}
	compiled, err := resolver.compiled(snapshot, feature)
	if err != nil {
		return QuotaProjection{}, err
	}
	if compiled.accessNeedsRequestSize ||
		(nonStreaming.authorization.limitPlanOverride == "" && compiled.limitPlanNeedsRequestSize) {
		// A quota snapshot has no concrete request body. Never report access or a
		// selected plan by silently substituting zero for unavailable token facts.
		return QuotaProjection{}, ErrConfiguration
	}
	nonStreamingActivation, err := boundedActivation(nonStreaming)
	if err != nil {
		return QuotaProjection{}, err
	}
	streamingActivation, err := boundedActivation(streaming)
	if err != nil {
		return QuotaProjection{}, err
	}
	nonStreamingAllowed, err := evaluateBool(ctx, compiled.access, nonStreamingActivation)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return QuotaProjection{}, contextErr
		}
		return QuotaProjection{}, ErrConfiguration
	}
	streamingAllowed, err := evaluateBool(ctx, compiled.access, streamingActivation)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return QuotaProjection{}, contextErr
		}
		return QuotaProjection{}, ErrConfiguration
	}
	if !nonStreamingAllowed && !streamingAllowed {
		return QuotaProjection{}, ErrFeatureNotAllowed
	}
	if nonStreamingAllowed != streamingAllowed {
		return QuotaProjection{}, ErrConfiguration
	}

	nonStreamingPlanID, streamingPlanID := nonStreaming.authorization.limitPlanOverride,
		streaming.authorization.limitPlanOverride
	if nonStreamingPlanID == "" {
		nonStreamingPlanID, err = selectLimitPlanID(
			ctx, compiled.limitPlan, nonStreamingActivation, "",
		)
		if err != nil {
			return QuotaProjection{}, err
		}
		streamingPlanID, err = selectLimitPlanID(
			ctx, compiled.limitPlan, streamingActivation, "",
		)
		if err != nil {
			return QuotaProjection{}, err
		}
	}
	if nonStreamingPlanID != streamingPlanID {
		return QuotaProjection{}, ErrConfiguration
	}
	nonStreamingPlan, err := resolveLimitPlan(snapshot, nonStreamingPlanID)
	if err != nil {
		return QuotaProjection{}, err
	}
	streamingPlan, err := resolveLimitPlan(snapshot, streamingPlanID)
	if err != nil {
		return QuotaProjection{}, err
	}
	if !reflect.DeepEqual(nonStreamingPlan, streamingPlan) {
		return QuotaProjection{}, ErrConfiguration
	}
	scopes, err := quotaScopeFacts(nonStreaming.authorization, nonStreamingPlan)
	if err != nil {
		return QuotaProjection{}, err
	}
	return QuotaProjection{
		Feature:   cloneFeature(feature),
		LimitPlan: cloneLimitPlan(nonStreamingPlan),
		Scopes:    scopes,
	}, nil
}

func quotaScopeFacts(
	authorization authorizationFacts,
	plan configuration.LimitPlan,
) (QuotaScopeFacts, error) {
	if !validPlatform(authorization.installationPlatform) || authorization.claims == nil {
		return QuotaScopeFacts{}, ErrInvalidInput
	}
	selectors := make(map[string]struct{})
	for _, limit := range plan.Limits {
		for _, dimension := range limit.Scope {
			name, claim := limitscope.NormalizedClaimName(dimension)
			if claim {
				selectors[name] = struct{}{}
			} else if strings.HasPrefix(dimension, limitscope.NormalizedClaimPrefix) {
				return QuotaScopeFacts{}, ErrConfiguration
			}
		}
	}
	digests := make(map[string]string, len(selectors))
	for name := range selectors {
		value, present := authorization.claims[name]
		digest, ok := limitscope.ClaimDigest(name, value, present)
		if !ok {
			return QuotaScopeFacts{}, ErrInvalidInput
		}
		digests[name] = digest
	}
	return QuotaScopeFacts{
		Platform:              authorization.installationPlatform,
		InstallationFamilyID:  authorization.installationFamilyID,
		ClientComponentID:     authorization.componentID,
		ComponentDefinitionID: authorization.componentDefinitionID,
		ComponentKind:         authorization.componentKind,
		TrustSource:           authorization.trustSource,
		NormalizedClaims:      digests,
	}, nil
}

func cloneQuotaScopeFacts(input QuotaScopeFacts) QuotaScopeFacts {
	result := QuotaScopeFacts{
		Platform:              input.Platform,
		InstallationFamilyID:  input.InstallationFamilyID,
		ClientComponentID:     input.ClientComponentID,
		ComponentDefinitionID: input.ComponentDefinitionID,
		ComponentKind:         input.ComponentKind,
		TrustSource:           input.TrustSource,
	}
	if input.NormalizedClaims != nil {
		result.NormalizedClaims = make(map[string]string, len(input.NormalizedClaims))
		for name, digest := range input.NormalizedClaims {
			result.NormalizedClaims[name] = digest
		}
	}
	return result
}

func validInput(input Input) bool {
	componentAware := input.authorization.installationFamilyID != "" || input.authorization.installationFamilyStatus != "" ||
		input.authorization.componentID != "" || input.authorization.componentDefinitionID != "" ||
		input.authorization.componentKind != "" || input.authorization.trustSource != ""
	componentValid := !componentAware ||
		(id.Validate(input.authorization.installationFamilyID, id.InstallationFamily) == nil &&
			input.authorization.installationFamilyStatus == "active" &&
			id.Validate(input.authorization.componentID, id.ClientComponent) == nil &&
			policyIdentifierPattern.MatchString(input.authorization.componentDefinitionID) &&
			policyIdentifierPattern.MatchString(input.authorization.componentKind) &&
			policyIdentifierPattern.MatchString(input.authorization.trustSource))
	return componentValid && id.Validate(input.authorization.organizationID, id.Organization) == nil &&
		id.Validate(input.authorization.applicationID, id.Application) == nil &&
		id.Validate(input.authorization.environmentID, id.Environment) == nil &&
		id.Validate(input.authorization.userID, id.ApplicationUser) == nil &&
		id.Validate(input.authorization.installationID, id.Installation) == nil &&
		id.Validate(input.logicalRequestID, id.LogicalRequest) == nil &&
		(useroverride.Selection{
			ID: input.authorization.userOverrideID, LimitPlan: input.authorization.limitPlanOverride,
		}).Validate() == nil &&
		validEnvironmentKind(input.environment.Kind) && input.authorization.claims != nil &&
		validUnboundRequestMetadata(input.request)
}

func validUnboundRequestMetadata(request ProtocolRequestMetadata) bool {
	return request.feature == "" && request.protocol == "" &&
		request.EstimatedInputTokens >= 0 &&
		request.EstimatedInputTokens <= protocol.MaximumPolicyRequestTokens &&
		request.MaximumOutputTokens >= 0 &&
		request.MaximumOutputTokens <= protocol.MaximumPolicyRequestTokens
}

func bindRequestFeature(
	input Input,
	requestedFeature string,
	feature configuration.Feature,
) (Input, error) {
	if !validUnboundRequestMetadata(input.request) || feature.ID != requestedFeature ||
		!policyIdentifierPattern.MatchString(feature.ID) ||
		!protocol.ProtocolExecutable(feature.Protocol) {
		return Input{}, ErrConfiguration
	}
	input.request.feature = feature.ID
	input.request.protocol = feature.Protocol
	return input, nil
}

func selectLimitPlanID(
	ctx context.Context,
	program cel.Program,
	activation map[string]any,
	override string,
) (string, error) {
	if override != "" {
		if !policyIdentifierPattern.MatchString(override) {
			return "", ErrLimitPlanNotFound
		}
		return override, nil
	}
	planID, err := evaluateString(ctx, program, activation)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return "", contextErr
		}
		return "", ErrConfiguration
	}
	if !policyIdentifierPattern.MatchString(planID) {
		return "", ErrLimitPlanNotFound
	}
	return planID, nil
}

func resolveLimitPlan(snapshot Snapshot, planID string) (configuration.LimitPlan, error) {
	if !policyIdentifierPattern.MatchString(planID) {
		return configuration.LimitPlan{}, ErrLimitPlanNotFound
	}
	plan, ok := snapshot.LimitPlan(planID)
	if !ok {
		return configuration.LimitPlan{}, ErrLimitPlanNotFound
	}
	if plan.ID != planID || len(plan.Limits) == 0 || len(plan.Limits) > 128 {
		return configuration.LimitPlan{}, ErrConfiguration
	}
	return cloneLimitPlan(plan), nil
}

func enforceFeatureAttestation(snapshot Snapshot, feature configuration.Feature, authorization authorizationFacts, now time.Time) error {
	if authorization.environmentID != snapshot.PolicyEnvironment() ||
		id.Validate(authorization.policyRevisionID, id.ConfigRevision) != nil ||
		authorization.policyRevisionID != snapshot.PolicyRevision() ||
		!policyIdentifierPattern.MatchString(authorization.identityProvider) ||
		!validPlatform(authorization.installationPlatform) ||
		!validAttestationProvider(authorization.attestationProvider) ||
		!validTrustLevel(authorization.trustLevel) {
		return session.ErrAttestationStepUpRequired
	}
	if !policyIdentifierPattern.MatchString(feature.AttestationPolicyID) {
		return ErrConfiguration
	}
	policy, ok := snapshot.AttestationPolicy(feature.AttestationPolicyID)
	if !ok || policy.ID != feature.AttestationPolicyID || !validRuntimeAttestationPolicy(policy) {
		return ErrConfiguration
	}
	selection, ok := policy.Platforms[authorization.installationPlatform]
	if !ok {
		return ErrConfiguration
	}

	switch selection.Mode {
	case "disabled":
		return sealedSessionAttestationFresh(authorization, now)
	case "preferred":
		// Preferred is advisory. Matching evidence that satisfies the target is
		// accepted directly; otherwise fall back to the still-valid sealed-session
		// baseline. This avoids the paradox where unrelated evidence succeeds but
		// weaker evidence from the preferred provider creates an endless step-up.
		if selection.Provider == authorization.attestationProvider &&
			session.TrustSatisfies(authorization.trustLevel, selection.MinimumTrustLevel) &&
			configuredAttestationFresh(policy, authorization, now) == nil {
			return nil
		}
		return sealedSessionAttestationFresh(authorization, now)
	case "required":
		if selection.MinimumTrustLevel == "none" {
			return ErrConfiguration
		}
		// Challenge issuance permits only one required policy per platform.
		// Recheck that invariant against the exact immutable revision bound to
		// this grant; otherwise the grant cannot prove which required feature
		// policy produced its trust.
		requiredPolicy, requiredSelection, unique := snapshot.RequiredAttestationForPlatform(authorization.installationPlatform)
		if !unique || requiredPolicy.ID != policy.ID || requiredPolicy.MaxAge != policy.MaxAge ||
			requiredSelection.Provider != selection.Provider || requiredSelection.Mode != selection.Mode ||
			requiredSelection.MinimumTrustLevel != selection.MinimumTrustLevel ||
			!slices.Equal(requiredSelection.ApplicationIdentifiers, selection.ApplicationIdentifiers) ||
			!slices.Equal(requiredSelection.AllowedOrigins, selection.AllowedOrigins) {
			return ErrConfiguration
		}
		// A provider or assurance mismatch requires a new, stronger challenge.
		// Evaluate those before age so a stale weak proof cannot be reported as
		// refreshable under the wrong policy.
		if selection.Provider != authorization.attestationProvider ||
			!session.TrustSatisfies(authorization.trustLevel, selection.MinimumTrustLevel) {
			return session.ErrAttestationStepUpRequired
		}
		return configuredAttestationFresh(policy, authorization, now)
	default:
		return ErrConfiguration
	}
}

func validRuntimeAttestationPolicy(policy configuration.AttestationPolicy) bool {
	if !policyIdentifierPattern.MatchString(policy.ID) || policy.MaxAge < time.Minute ||
		policy.MaxAge > 30*24*time.Hour || len(policy.Platforms) == 0 || len(policy.Platforms) > 7 {
		return false
	}
	for platform, selection := range policy.Platforms {
		if !validPlatform(platform) ||
			!providerAllowedOnPlatform(selection.Provider, platform) ||
			!slices.Contains([]string{"disabled", "preferred", "required"}, selection.Mode) ||
			!validTrustLevel(selection.MinimumTrustLevel) ||
			(selection.Mode == "required" && selection.MinimumTrustLevel == "none") ||
			(selection.Mode != "disabled" && len(selection.ApplicationIdentifiers) != 0) ||
			!validRuntimeAttestationOrigins(platform, selection) {
			return false
		}
	}
	return true
}

func validRuntimeAttestationOrigins(platform string, selection configuration.PlatformAttestation) bool {
	if selection.Mode == "disabled" || platform != "web" {
		return len(selection.AllowedOrigins) == 0
	}
	if len(selection.AllowedOrigins) == 0 || len(selection.AllowedOrigins) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(selection.AllowedOrigins))
	for _, origin := range selection.AllowedOrigins {
		if !weborigin.Canonical(origin) {
			return false
		}
		if _, duplicate := seen[origin]; duplicate {
			return false
		}
		seen[origin] = struct{}{}
	}
	return true
}

func sealedSessionAttestationFresh(authorization authorizationFacts, now time.Time) error {
	if authorization.attestedAt.IsZero() || authorization.attestedAt.After(now) ||
		!authorization.attestationExpiresAt.After(authorization.attestedAt) ||
		!authorization.attestationExpiresAt.After(now) {
		return session.ErrAttestationRefreshNeeded
	}
	return nil
}

func configuredAttestationFresh(policy configuration.AttestationPolicy, authorization authorizationFacts, now time.Time) error {
	if err := sealedSessionAttestationFresh(authorization, now); err != nil {
		return err
	}
	if !authorization.attestedAt.Add(policy.MaxAge).After(now) {
		return session.ErrAttestationRefreshNeeded
	}
	return nil
}

func validTrustLevel(level string) bool {
	return session.TrustSatisfies(level, level)
}

func validAttestationProvider(provider string) bool {
	return slices.Contains([]string{"app_attest", "play_integrity", "firebase_app_check", "turnstile", "debug"}, provider)
}

func validPlatform(platform string) bool {
	return slices.Contains([]string{"ios", "android", "web", "react_native_ios", "react_native_android", "watchos", "node"}, platform)
}

func providerAllowedOnPlatform(provider, platform string) bool {
	switch platform {
	case "ios", "react_native_ios", "watchos":
		return provider == "app_attest" || provider == "firebase_app_check" || provider == "debug"
	case "android", "react_native_android":
		return provider == "play_integrity" || provider == "firebase_app_check" || provider == "debug"
	case "web":
		return provider == "turnstile" || provider == "firebase_app_check" || provider == "debug"
	case "node":
		return provider == "debug"
	default:
		return false
	}
}

func validEnvironmentKind(kind string) bool {
	return kind == "development" || kind == "staging" || kind == "production"
}

func (resolver *Resolver) compiled(snapshot Snapshot, feature configuration.Feature) (*compiledFeature, error) {
	encoded, err := json.Marshal(feature)
	if err != nil {
		return nil, fmt.Errorf("%w: fingerprint feature", ErrConfiguration)
	}
	key := cacheKey{
		revisionID: snapshot.PolicyRevision(), environmentID: snapshot.PolicyEnvironment(),
		featureID: feature.ID, fingerprint: sha256.Sum256(encoded),
	}
	resolver.mu.RLock()
	cached := resolver.cache[key]
	resolver.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	access, accessNeedsRequestSize, err := resolver.compileProgram(feature.AccessExpression, cel.BoolType)
	if err != nil {
		return nil, err
	}
	limitPlan, limitPlanNeedsRequestSize, err := resolver.compileProgram(feature.LimitPlanExpression, cel.StringType)
	if err != nil {
		return nil, err
	}
	compiled := &compiledFeature{
		access: access, limitPlan: limitPlan,
		accessNeedsRequestSize:    accessNeedsRequestSize,
		limitPlanNeedsRequestSize: limitPlanNeedsRequestSize,
		routes:                    make([]compiledRoute, 0, len(feature.Routes)),
	}
	for _, route := range feature.Routes {
		when, _, compileErr := resolver.compileProgram(route.When, cel.BoolType)
		if compileErr != nil {
			return nil, compileErr
		}
		// The compiled cache must own every mutable child. Resolve returns the
		// feature separately, so retaining its FallbackOn slice here would let a
		// caller mutate cached routing policy (and introduce a data race).
		compiled.routes = append(compiled.routes, compiledRoute{Route: cloneRoute(route), when: when})
	}
	resolver.mu.Lock()
	if len(resolver.cache) >= maximumCachedFeatures {
		clear(resolver.cache)
	}
	if existing := resolver.cache[key]; existing != nil {
		compiled = existing
	} else {
		resolver.cache[key] = compiled
	}
	resolver.mu.Unlock()
	return compiled, nil
}

func (resolver *Resolver) compileProgram(expression string, expected *cel.Type) (cel.Program, bool, error) {
	ast, issues := resolver.environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, false, fmt.Errorf("%w: compile CEL expression", ErrConfiguration)
	}
	actual := ast.OutputType()
	if actual == nil || (actual.Kind() != cel.DynKind && !expected.IsAssignableType(actual)) {
		return nil, false, fmt.Errorf("%w: CEL result type", ErrConfiguration)
	}
	needsRequestSize := expressionNeedsRequestSize(ast)
	program, err := resolver.environment.Program(
		ast,
		cel.CostLimit(maximumRuntimeCost),
		cel.InterruptCheckFrequency(100),
		cel.EvalOptions(cel.OptOptimize),
	)
	if err != nil {
		return nil, false, fmt.Errorf("%w: compile CEL program", ErrConfiguration)
	}
	return program, needsRequestSize, nil
}

func expressionNeedsRequestSize(checked *cel.Ast) bool {
	if checked == nil || checked.NativeRep() == nil {
		return true
	}
	root := celast.NavigateAST(checked.NativeRep())
	requestIdentifiers := celast.MatchDescendants(root, func(expression celast.NavigableExpr) bool {
		return expression.Kind() == celast.IdentKind && expression.AsIdent() == "request"
	})
	for _, identifier := range requestIdentifiers {
		parent, ok := identifier.Parent()
		if !ok {
			return true
		}
		if parent.Kind() == celast.SelectKind {
			selection := parent.AsSelect()
			if selection.Operand().ID() == identifier.ID() {
				if requestFieldNeedsSize(selection.FieldName()) {
					return true
				}
				continue
			}
		}
		if parent.Kind() == celast.CallKind {
			call := parent.AsCall()
			arguments := call.Args()
			if (call.FunctionName() == operators.Index || call.FunctionName() == operators.OptIndex) &&
				len(arguments) == 2 && arguments[0].ID() == identifier.ID() {
				if arguments[1].Kind() != celast.LiteralKind {
					return true
				}
				field, stringKey := arguments[1].AsLiteral().(types.String)
				if !stringKey || requestFieldNeedsSize(string(field)) {
					return true
				}
				continue
			}
		}
		// Whole-object and dynamic access can observe unavailable size facts.
		return true
	}
	return false
}

func requestFieldNeedsSize(field string) bool {
	switch field {
	case "feature", "protocol", "streaming":
		return false
	case "estimated_input_tokens", "maximum_output_tokens":
		return true
	default:
		return true
	}
}

func evaluateBool(ctx context.Context, program cel.Program, activation map[string]any) (bool, error) {
	value, _, err := program.ContextEval(ctx, activation)
	if err != nil || value == nil || types.IsError(value) || types.IsUnknown(value) {
		return false, ErrConfiguration
	}
	native, err := value.ConvertToNative(reflect.TypeFor[bool]())
	if err != nil {
		return false, ErrConfiguration
	}
	result, ok := native.(bool)
	if !ok {
		return false, ErrConfiguration
	}
	return result, nil
}

func evaluateString(ctx context.Context, program cel.Program, activation map[string]any) (string, error) {
	value, _, err := program.ContextEval(ctx, activation)
	if err != nil || value == nil || types.IsError(value) || types.IsUnknown(value) {
		return "", ErrConfiguration
	}
	native, err := value.ConvertToNative(reflect.TypeFor[string]())
	if err != nil {
		return "", ErrConfiguration
	}
	result, ok := native.(string)
	if !ok {
		return "", ErrConfiguration
	}
	return result, nil
}

func orderRoutes(featureID string, matched []configuration.Route, input Input) ([]configuration.Route, error) {
	if !policyIdentifierPattern.MatchString(featureID) || len(matched) == 0 || len(matched) > 32 {
		return nil, ErrRouteNotFound
	}
	grouped := append([]configuration.Route(nil), matched...)
	slices.SortFunc(grouped, func(left, right configuration.Route) int {
		if left.Priority < right.Priority {
			return -1
		}
		if left.Priority > right.Priority {
			return 1
		}
		return stringCompare(left.ID, right.ID)
	})
	ordered := make([]configuration.Route, 0, len(grouped))
	seen := make(map[string]struct{}, len(grouped))
	for start := 0; start < len(grouped); {
		priority := grouped[start].Priority
		end := start + 1
		for end < len(grouped) && grouped[end].Priority == priority {
			end++
		}
		for _, route := range grouped[start:end] {
			if !policyIdentifierPattern.MatchString(route.ID) ||
				!policyIdentifierPattern.MatchString(route.ModelID) || route.Priority < 0 {
				return nil, ErrRouteNotFound
			}
			if _, duplicate := seen[route.ID]; duplicate {
				return nil, ErrRouteNotFound
			}
			seen[route.ID] = struct{}{}
		}
		groupOrder, err := weightedRouteOrder(featureID, grouped[start:end], input)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, groupOrder...)
		start = end
	}
	return ordered, nil
}

func weightedRouteOrder(
	featureID string,
	candidates []configuration.Route,
	input Input,
) ([]configuration.Route, error) {
	if len(candidates) == 0 {
		return nil, ErrRouteNotFound
	}
	stickyBy := candidates[0].StickyBy
	var selectionKey string
	switch stickyBy {
	case "none":
		selectionKey = input.logicalRequestID
		if id.Validate(selectionKey, id.LogicalRequest) != nil {
			return nil, ErrInvalidInput
		}
	case "user":
		selectionKey = input.authorization.userID
		if id.Validate(selectionKey, id.ApplicationUser) != nil {
			return nil, ErrInvalidInput
		}
	case "installation":
		selectionKey = input.authorization.installationID
		if id.Validate(selectionKey, id.Installation) != nil {
			return nil, ErrInvalidInput
		}
	default:
		return nil, ErrRouteNotFound
	}
	if selectionKey == "" || len(selectionKey) > 256 {
		return nil, ErrInvalidInput
	}
	remaining := append([]configuration.Route(nil), candidates...)
	result := make([]configuration.Route, 0, len(remaining))
	for round := 0; len(remaining) > 0; round++ {
		var totalWeight uint64
		for _, route := range remaining {
			if route.StickyBy != stickyBy || route.Weight <= 0 ||
				uint64(route.Weight) > math.MaxUint64-totalWeight {
				return nil, ErrRouteNotFound
			}
			totalWeight += uint64(route.Weight)
		}
		if totalWeight == 0 {
			return nil, ErrRouteNotFound
		}
		digest := routeOrderDigest(featureID, stickyBy, selectionKey, round)
		selected := binary.BigEndian.Uint64(digest[:8]) % totalWeight
		selectedIndex := -1
		for index, route := range remaining {
			weight := uint64(route.Weight)
			if selected < weight {
				selectedIndex = index
				break
			}
			selected -= weight
		}
		if selectedIndex < 0 {
			return nil, ErrRouteNotFound
		}
		result = append(result, cloneRoute(remaining[selectedIndex]))
		remaining = slices.Delete(remaining, selectedIndex, selectedIndex+1)
	}
	return result, nil
}

func routeOrderDigest(featureID, stickyBy, selectionKey string, round int) [sha256.Size]byte {
	// Preserve the established primary-route mapping exactly. Additional draws
	// use a domain-separated counter so weighted selection without replacement
	// does not reuse one pseudo-random value at every round.
	if round == 0 {
		return sha256.Sum256([]byte(featureID + "\x00" + stickyBy + "\x00" + selectionKey))
	}
	return sha256.Sum256([]byte(
		"latchway/route-order/v1\x00" + featureID + "\x00" + stickyBy + "\x00" +
			selectionKey + "\x00" + strconv.Itoa(round),
	))
}

func boundedActivation(input Input) (map[string]any, error) {
	state := activationState{}
	activation := make(map[string]any, 4)
	principal := map[string]any{
		"user_id":       input.authorization.userID,
		"authenticated": !input.unauthenticated,
		"claims":        cloneClaims(input.authorization.claims),
	}
	client := map[string]any{
		"family": map[string]any{
			"id":     input.authorization.installationFamilyID,
			"status": input.authorization.installationFamilyStatus,
		},
		"component": map[string]any{
			"id":            input.authorization.componentID,
			"definition_id": input.authorization.componentDefinitionID,
			"kind":          input.authorization.componentKind,
			"is_root":       input.authorization.componentIsRoot,
			"platform":      input.authorization.installationPlatform,
		},
		"trust": map[string]any{
			"source":               input.authorization.trustSource,
			"attestation_provider": input.authorization.attestationProvider,
			"delegated":            strings.HasPrefix(input.authorization.trustSource, "delegated_"),
			"direct_attestation": input.authorization.trustSource == "direct_attested" ||
				input.authorization.trustSource == "delegated_direct_attested",
			"verified_at": input.authorization.attestedAt,
			"expires_at":  input.authorization.attestationExpiresAt,
		},
	}
	installation := map[string]any{
		"platform":    input.authorization.installationPlatform,
		"trust_level": input.authorization.trustLevel,
	}
	request := map[string]any{
		"feature":                input.request.feature,
		"protocol":               input.request.protocol,
		"streaming":              input.request.Streaming,
		"estimated_input_tokens": input.request.EstimatedInputTokens,
		"maximum_output_tokens":  input.request.MaximumOutputTokens,
	}
	environment := map[string]any{"kind": input.environment.Kind}
	for name, value := range map[string]map[string]any{
		"principal": principal, "client": client, "installation": installation,
		"request": request, "environment": environment,
	} {
		converted, err := state.convert(value, 0)
		if err != nil {
			return nil, ErrInvalidInput
		}
		activation[name] = converted
	}
	return activation, nil
}

type activationState struct {
	values int
	bytes  int
}

func (state *activationState) convert(value any, depth int) (any, error) {
	if depth > maximumActivationDepth || state.values >= maximumActivationValues || state.bytes > maximumActivationBytes {
		return nil, ErrInvalidInput
	}
	state.values++
	switch typed := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, nil
	case string:
		state.bytes += len(typed)
		if state.bytes > maximumActivationBytes {
			return nil, ErrInvalidInput
		}
		return typed, nil
	case time.Time:
		if typed.IsZero() {
			return nil, ErrInvalidInput
		}
		return typed.UTC(), nil
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, ErrInvalidInput
		}
		return typed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, ErrInvalidInput
		}
		return typed, nil
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return integer, nil
		}
		if unsigned, err := strconv.ParseUint(typed.String(), 10, 64); err == nil {
			return unsigned, nil
		}
		decimal, err := typed.Float64()
		if err != nil || math.IsNaN(decimal) || math.IsInf(decimal, 0) {
			return nil, ErrInvalidInput
		}
		return decimal, nil
	case map[string]any:
		if len(typed) > maximumActivationValues-state.values {
			return nil, ErrInvalidInput
		}
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			state.bytes += len(key)
			if key == "" || len(key) > 128 || state.bytes > maximumActivationBytes {
				return nil, ErrInvalidInput
			}
			converted, err := state.convert(child, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case []any:
		if len(typed) > maximumActivationValues-state.values {
			return nil, ErrInvalidInput
		}
		result := make([]any, len(typed))
		for index, child := range typed {
			converted, err := state.convert(child, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	default:
		return nil, ErrInvalidInput
	}
}

func stringCompare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func cloneRoute(route configuration.Route) configuration.Route {
	route.FallbackOn = append([]string(nil), route.FallbackOn...)
	if route.RetryPolicy != nil {
		cloned := *route.RetryPolicy
		cloned.RetryOn = append([]string(nil), route.RetryPolicy.RetryOn...)
		route.RetryPolicy = &cloned
	}
	if route.Timeouts != nil {
		cloned := *route.Timeouts
		route.Timeouts = &cloned
	}
	return route
}

func cloneModel(model configuration.Model) configuration.Model {
	model.Capabilities = append([]string(nil), model.Capabilities...)
	return model
}

func cloneUpstream(upstream configuration.Upstream) configuration.Upstream {
	upstream.Authentication.Headers = append(
		[]configuration.UpstreamAuthenticationHeader(nil), upstream.Authentication.Headers...,
	)
	upstream.DestinationPolicy.AllowedPorts = append(
		[]int(nil), upstream.DestinationPolicy.AllowedPorts...,
	)
	upstream.DestinationPolicy.AllowedCIDRs = append(
		[]netip.Prefix(nil), upstream.DestinationPolicy.AllowedCIDRs...,
	)
	if upstream.StaticHeaders != nil {
		headers := make(map[string]string, len(upstream.StaticHeaders))
		for name, value := range upstream.StaticHeaders {
			headers[name] = value
		}
		upstream.StaticHeaders = headers
	}
	return upstream
}

func cloneFeature(feature configuration.Feature) configuration.Feature {
	if feature.Output != nil {
		output := *feature.Output
		feature.Output = &output
	}
	if feature.OpaqueHTTP != nil {
		opaque := *feature.OpaqueHTTP
		opaque.AllowedMethods = append([]string(nil), opaque.AllowedMethods...)
		opaque.PathPrefixes = append([]string(nil), opaque.PathPrefixes...)
		opaque.PathTemplates = append([]string(nil), opaque.PathTemplates...)
		opaque.AllowedRequestHeaders = append([]string(nil), opaque.AllowedRequestHeaders...)
		feature.OpaqueHTTP = &opaque
	}
	feature.Routes = append([]configuration.Route(nil), feature.Routes...)
	for index := range feature.Routes {
		feature.Routes[index] = cloneRoute(feature.Routes[index])
	}
	return feature
}

func cloneLimitPlan(plan configuration.LimitPlan) configuration.LimitPlan {
	plan.Limits = append([]configuration.Limit(nil), plan.Limits...)
	for index := range plan.Limits {
		plan.Limits[index].Scope = append([]string(nil), plan.Limits[index].Scope...)
	}
	return plan
}

func cloneClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	result := make(map[string]any, len(claims))
	for name, value := range claims {
		switch typed := value.(type) {
		case []any:
			result[name] = append([]any(nil), typed...)
		default:
			result[name] = typed
		}
	}
	return result
}
