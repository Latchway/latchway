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

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/id"
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

// Input contains only server-verified values exposed to configured CEL. The
// explicit selection keys never enter CEL automatically; they drive stable
// weighted routing and must come from authoritative identifiers.
type Input struct {
	Principal    map[string]any
	Installation map[string]any
	Request      map[string]any
	Environment  map[string]any

	UserID           string
	InstallationID   string
	LogicalRequestID string
}

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

	mu    sync.RWMutex
	cache map[cacheKey]*compiledFeature
}

// NewResolver constructs the exact policy environment used by configuration
// validation and adds runtime cost and cancellation enforcement to programs.
func NewResolver() (*Resolver, error) {
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
	return &Resolver{environment: environment, cache: make(map[cacheKey]*compiledFeature)}, nil
}

// Resolve evaluates access, limit-plan selection, and route predicates, then
// resolves the selected physical model and upstream from the same snapshot.
func (resolver *Resolver) Resolve(ctx context.Context, snapshot Snapshot, featureID string, input Input) (Decision, error) {
	if resolver == nil || resolver.environment == nil || resolver.cache == nil || ctx == nil ||
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
	if id.Validate(input.UserID, id.ApplicationUser) != nil ||
		id.Validate(input.InstallationID, id.Installation) != nil ||
		id.Validate(input.LogicalRequestID, id.LogicalRequest) != nil {
		return Decision{}, ErrInvalidInput
	}
	feature, ok := snapshot.Feature(featureID)
	if !ok {
		return Decision{}, ErrFeatureNotFound
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
		selectionKey = input.LogicalRequestID
		if id.Validate(selectionKey, id.LogicalRequest) != nil {
			return configuration.Route{}, ErrInvalidInput
		}
	case "user":
		selectionKey = input.UserID
		if id.Validate(selectionKey, id.ApplicationUser) != nil {
			return configuration.Route{}, ErrInvalidInput
		}
	case "installation":
		selectionKey = input.InstallationID
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
	for name, value := range map[string]map[string]any{
		"principal": input.Principal, "installation": input.Installation,
		"request": input.Request, "environment": input.Environment,
	} {
		if value == nil {
			value = map[string]any{}
		}
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
