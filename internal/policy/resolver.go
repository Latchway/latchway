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
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/session"
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

// ProtocolRequestMetadata is the complete allowlist of request-derived values
// that may enter feature CEL. In particular, model, plan, route and headers
// have no representation here and therefore cannot be smuggled into policy.
type ProtocolRequestMetadata struct {
	Streaming bool
}

// EnvironmentFacts contains the allowlisted environment state supplied by the
// trusted server composition layer. Kind must exactly match the durable value
// loaded into the session authorization.
type EnvironmentFacts struct {
	Kind string
}

type authorizationFacts struct {
	organizationID       string
	applicationID        string
	environmentID        string
	policyRevisionID     string
	userID               string
	installationID       string
	installationPlatform string
	identityProvider     string
	trustLevel           string
	attestationProvider  string
	claims               map[string]any
	identityExpiresAt    time.Time
	attestedAt           time.Time
	attestationExpiresAt time.Time
	accessExpiresAt      time.Time
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
			userID: authorization.ApplicationUserID, installationID: authorization.InstallationID,
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
	access    cel.Program
	limitPlan cel.Program
	routes    []compiledRoute
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
	return &Resolver{environment: environment, now: now, cache: make(map[cacheKey]*compiledFeature)}, nil
}

// Resolve evaluates access, limit-plan selection, and route predicates, then
// resolves the selected physical model and upstream from the same snapshot.
func (resolver *Resolver) Resolve(ctx context.Context, snapshot Snapshot, featureID string, input Input) (Decision, error) {
	if resolver == nil || resolver.environment == nil || resolver.now == nil || resolver.cache == nil || ctx == nil ||
		snapshot == nil || !policyIdentifierPattern.MatchString(featureID) {
		return Decision{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	// Protected policy resolution always operates on durable, server-owned
	// identities. Validate them even when the selected route does not happen to
	// use a particular sticky key so later quota and persistence layers cannot be
	// wired to an untrusted correlation hint by accident.
	if id.Validate(input.authorization.organizationID, id.Organization) != nil ||
		id.Validate(input.authorization.applicationID, id.Application) != nil ||
		id.Validate(input.authorization.environmentID, id.Environment) != nil ||
		id.Validate(input.authorization.userID, id.ApplicationUser) != nil ||
		id.Validate(input.authorization.installationID, id.Installation) != nil ||
		id.Validate(input.logicalRequestID, id.LogicalRequest) != nil ||
		!validEnvironmentKind(input.environment.Kind) || input.authorization.claims == nil {
		return Decision{}, ErrInvalidInput
	}
	now := resolver.now().UTC()
	if now.IsZero() || !input.authorization.accessExpiresAt.After(now) || !input.authorization.identityExpiresAt.After(now) {
		return Decision{}, session.ErrTokenExpired
	}
	feature, ok := snapshot.Feature(featureID)
	if !ok {
		return Decision{}, ErrFeatureNotFound
	}
	if err := enforceFeatureAttestation(snapshot, feature, input.authorization, now); err != nil {
		return Decision{}, err
	}
	activation, err := boundedActivation(input)
	if err != nil {
		return Decision{}, err
	}
	compiled, err := resolver.compiled(snapshot, feature)
	if err != nil {
		return Decision{}, err
	}
	allowed, err := evaluateBool(ctx, compiled.access, activation)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Decision{}, ctxErr
		}
		return Decision{}, ErrFeatureNotAllowed
	}
	if !allowed {
		return Decision{}, ErrFeatureNotAllowed
	}
	planID, err := evaluateString(ctx, compiled.limitPlan, activation)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Decision{}, ctxErr
		}
		return Decision{}, ErrConfiguration
	}
	if !policyIdentifierPattern.MatchString(planID) {
		return Decision{}, ErrLimitPlanNotFound
	}
	plan, ok := snapshot.LimitPlan(planID)
	if !ok {
		return Decision{}, ErrLimitPlanNotFound
	}
	matched := make([]configuration.Route, 0, len(compiled.routes))
	for _, route := range compiled.routes {
		matches, evalErr := evaluateBool(ctx, route.when, activation)
		if evalErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Decision{}, ctxErr
			}
			return Decision{}, fmt.Errorf("%w: evaluate route %s", ErrConfiguration, route.ID)
		}
		if matches {
			matched = append(matched, cloneRoute(route.Route))
		}
	}
	route, err := selectRoute(feature.ID, matched, input)
	if err != nil {
		return Decision{}, err
	}
	model, ok := snapshot.Model(route.ModelID)
	if !ok || !slices.Contains(model.Capabilities, feature.Protocol) {
		return Decision{}, ErrRouteNotFound
	}
	upstream, ok := snapshot.Upstream(model.UpstreamID)
	if !ok {
		return Decision{}, ErrRouteNotFound
	}
	return Decision{Feature: feature, LimitPlan: plan, Route: route, Model: model, Upstream: upstream}, nil
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
		policy.MaxAge > 30*24*time.Hour || len(policy.Platforms) == 0 || len(policy.Platforms) > 6 {
		return false
	}
	for platform, selection := range policy.Platforms {
		if !validPlatform(platform) ||
			!providerAllowedOnPlatform(selection.Provider, platform) ||
			!slices.Contains([]string{"disabled", "preferred", "required"}, selection.Mode) ||
			!validTrustLevel(selection.MinimumTrustLevel) ||
			(selection.Mode == "required" && selection.MinimumTrustLevel == "none") ||
			(selection.Mode != "disabled" && (len(selection.ApplicationIdentifiers) != 0 || len(selection.AllowedOrigins) != 0)) {
			return false
		}
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
	return slices.Contains([]string{"ios", "android", "web", "react_native_ios", "react_native_android", "node"}, platform)
}

func providerAllowedOnPlatform(provider, platform string) bool {
	switch platform {
	case "ios", "react_native_ios":
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
	access, err := resolver.compileProgram(feature.AccessExpression, cel.BoolType)
	if err != nil {
		return nil, err
	}
	limitPlan, err := resolver.compileProgram(feature.LimitPlanExpression, cel.StringType)
	if err != nil {
		return nil, err
	}
	compiled := &compiledFeature{access: access, limitPlan: limitPlan, routes: make([]compiledRoute, 0, len(feature.Routes))}
	for _, route := range feature.Routes {
		when, compileErr := resolver.compileProgram(route.When, cel.BoolType)
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

func (resolver *Resolver) compileProgram(expression string, expected *cel.Type) (cel.Program, error) {
	ast, issues := resolver.environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("%w: compile CEL expression", ErrConfiguration)
	}
	actual := ast.OutputType()
	if actual == nil || (actual.Kind() != cel.DynKind && !expected.IsAssignableType(actual)) {
		return nil, fmt.Errorf("%w: CEL result type", ErrConfiguration)
	}
	program, err := resolver.environment.Program(
		ast,
		cel.CostLimit(maximumRuntimeCost),
		cel.InterruptCheckFrequency(100),
		cel.EvalOptions(cel.OptOptimize),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: compile CEL program", ErrConfiguration)
	}
	return program, nil
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

func selectRoute(featureID string, matched []configuration.Route, input Input) (configuration.Route, error) {
	if len(matched) == 0 {
		return configuration.Route{}, ErrRouteNotFound
	}
	minimumPriority := matched[0].Priority
	for _, route := range matched[1:] {
		if route.Priority < minimumPriority {
			minimumPriority = route.Priority
		}
	}
	candidates := make([]configuration.Route, 0, len(matched))
	for _, route := range matched {
		if route.Priority == minimumPriority {
			candidates = append(candidates, route)
		}
	}
	slices.SortFunc(candidates, func(left, right configuration.Route) int {
		return stringCompare(left.ID, right.ID)
	})
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	stickyBy := candidates[0].StickyBy
	var totalWeight uint64
	for _, route := range candidates {
		if route.StickyBy != stickyBy || route.Weight <= 0 || uint64(route.Weight) > math.MaxUint64-totalWeight {
			return configuration.Route{}, ErrRouteNotFound
		}
		totalWeight += uint64(route.Weight)
	}
	var selectionKey string
	switch stickyBy {
	case "none":
		selectionKey = input.logicalRequestID
		if id.Validate(selectionKey, id.LogicalRequest) != nil {
			return configuration.Route{}, ErrInvalidInput
		}
	case "user":
		selectionKey = input.authorization.userID
		if id.Validate(selectionKey, id.ApplicationUser) != nil {
			return configuration.Route{}, ErrInvalidInput
		}
	case "installation":
		selectionKey = input.authorization.installationID
		if id.Validate(selectionKey, id.Installation) != nil {
			return configuration.Route{}, ErrInvalidInput
		}
	default:
		return configuration.Route{}, ErrRouteNotFound
	}
	if selectionKey == "" || len(selectionKey) > 256 || totalWeight == 0 {
		return configuration.Route{}, ErrInvalidInput
	}
	digest := sha256.Sum256([]byte(featureID + "\x00" + stickyBy + "\x00" + selectionKey))
	selected := binary.BigEndian.Uint64(digest[:8]) % totalWeight
	for _, route := range candidates {
		weight := uint64(route.Weight)
		if selected < weight {
			return route, nil
		}
		selected -= weight
	}
	return configuration.Route{}, ErrRouteNotFound
}

func boundedActivation(input Input) (map[string]any, error) {
	state := activationState{}
	activation := make(map[string]any, 4)
	principal := map[string]any{
		"authenticated": true,
		"claims":        cloneClaims(input.authorization.claims),
	}
	installation := map[string]any{
		"platform":    input.authorization.installationPlatform,
		"trust_level": input.authorization.trustLevel,
	}
	request := map[string]any{"streaming": input.request.Streaming}
	environment := map[string]any{"kind": input.environment.Kind}
	for name, value := range map[string]map[string]any{
		"principal": principal, "installation": installation,
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
	return route
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
