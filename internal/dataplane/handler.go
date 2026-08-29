// Package dataplane composes authenticated client requests, immutable policy,
// quota lifecycle accounting, protected upstream dispatch, and bounded
// response relay. Protocols without a registered executable adapter remain
// unavailable even when their future wire shapes are present in the schema.
package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/adapters/protocol/anthropicmessages"
	"github.com/latchway/latchway/adapters/protocol/opaquehttp"
	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/adapters/protocol/openaiembeddings"
	"github.com/latchway/latchway/adapters/protocol/openairesponses"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/problem"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/telemetry"
	"github.com/latchway/latchway/internal/upstream"
	"github.com/latchway/latchway/internal/weborigin"
)

const (
	defaultMaximumResponseBody            = int64(32 << 20)
	maximumRequestBodyLimit               = int64(100 << 20)
	maximumResponseBodyLimit              = int64(100 << 20)
	defaultClientWriteTimeout             = 30 * time.Second
	defaultPersistenceTimeout             = 5 * time.Second
	maximumDecisionLimitRules             = 128
	maximumDecisionCalendarTimezoneLength = 64
	// These bounds mirror quota's exact fixed-point envelope so detached policy
	// values fail closed before reaching durable reservation state.
	maximumDecisionTokenBucketCapacity        = int64(9_223_372)
	maximumDecisionTokenBucketRefillPerSecond = int64(1_000_000)
	maximumQuotaRetryAfterSeconds             = math.MaxInt32
)

var (
	errInvalidConfiguration = errors.New("invalid data-plane configuration")
	errUnsupportedLimitPlan = errors.New("unsupported data-plane limit plan")
	errDispatchNotOwned     = errors.New("logical request dispatch is already owned")
	errDispatchNotConsumed  = errors.New("upstream dispatch did not provide a response")
	errTargetConfiguration  = errors.New("invalid protected upstream target")
	errPricingUnavailable   = errors.New("configured pricing unavailable")
	errUpstreamDispatch     = errors.New("upstream dispatch failed")
	errUpstreamProtocol     = errors.New("upstream protocol observation failed")
	errUpstreamRelay        = errors.New("upstream response relay failed")
	decisionWindowPattern   = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d|w|mo)$`)
	decisionTimezonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$`)
)

var decisionScopeOrder = []string{
	"organization",
	"application",
	"environment",
	"user",
	"installation",
	"feature",
	"route",
	"upstream",
	"model",
}

var decisionWindowMaximum = map[string]int64{
	"m":  366 * 24 * 60,
	"h":  366 * 24,
	"d":  366,
	"w":  52,
	"mo": 12,
}

// Config contains only trusted server dependencies and runtime bounds.
type Config struct {
	AccessTokens  AccessTokenVerifier
	Sessions      SessionAuthorizer
	Configuration SnapshotLoader
	Policies      PolicyDecisionEngine
	Quotas        QuotaStore
	Secrets       SecretStore
	// Adapter replaces one matching built-in adapter for focused tests and
	// compatibility injection. Adapters supplies the complete bounded registry;
	// callers must set at most one of these fields.
	Adapter   protocol.Adapter
	Adapters  []protocol.Adapter
	Targets   TargetFactory
	Relayer   ResponseRelayer
	Telemetry *telemetry.Registry

	PublicOrigin             string
	MaximumRequestBodyBytes  int64
	MaximumResponseBodyBytes int64
	ClientWriteTimeout       time.Duration
	PersistenceTimeout       time.Duration
	Now                      func() time.Time
}

// Handler serves the bounded protected protocol endpoint registry.
// It must be mounted behind requestidentity middleware.
type Handler struct {
	accessTokens  AccessTokenVerifier
	sessions      SessionAuthorizer
	configuration SnapshotLoader
	policies      PolicyDecisionEngine
	quotas        QuotaStore
	secrets       SecretStore
	endpoints     endpointRegistry
	targets       TargetFactory
	relayer       ResponseRelayer
	telemetry     *telemetry.Registry

	maximumResponseBody int64
	clientWriteTimeout  time.Duration
	persistenceTimeout  time.Duration
	now                 func() time.Time
	retrySleep          func(context.Context, time.Duration) error
	ownedTargets        *TargetCache
}

func New(config Config) (*Handler, error) {
	if nilDependency(config.AccessTokens) || nilDependency(config.Sessions) ||
		nilDependency(config.Configuration) || nilDependency(config.Policies) ||
		nilDependency(config.Quotas) || nilDependency(config.Secrets) {
		return nil, errInvalidConfiguration
	}
	origin, err := canonicalPublicOrigin(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if config.MaximumRequestBodyBytes < 0 || config.MaximumRequestBodyBytes > maximumRequestBodyLimit {
		return nil, errInvalidConfiguration
	}
	if !nilDependency(config.Adapter) && len(config.Adapters) != 0 {
		return nil, errInvalidConfiguration
	}
	adapters := append([]protocol.Adapter(nil), config.Adapters...)
	if len(adapters) == 0 {
		adapters = defaultProtocolAdapters(config.MaximumRequestBodyBytes)
		if !nilDependency(config.Adapter) {
			replaced := false
			for index := range adapters {
				if adapters[index].ID() == config.Adapter.ID() {
					adapters[index] = config.Adapter
					replaced = true
					break
				}
			}
			if !replaced {
				return nil, errInvalidConfiguration
			}
		}
	}
	endpoints, err := newEndpointRegistry(origin, adapters)
	if err != nil {
		return nil, err
	}
	var ownedTargets *TargetCache
	if nilDependency(config.Targets) {
		ownedTargets = NewTargetCache()
		config.Targets = ownedTargets
	}
	if nilDependency(config.Relayer) {
		config.Relayer = responseRelayer{}
	}
	if config.MaximumResponseBodyBytes == 0 {
		config.MaximumResponseBodyBytes = defaultMaximumResponseBody
	}
	if config.MaximumResponseBodyBytes < 1 || config.MaximumResponseBodyBytes > maximumResponseBodyLimit {
		return nil, errInvalidConfiguration
	}
	if config.ClientWriteTimeout == 0 {
		config.ClientWriteTimeout = defaultClientWriteTimeout
	}
	if config.ClientWriteTimeout <= 0 || config.ClientWriteTimeout > 5*time.Minute {
		return nil, errInvalidConfiguration
	}
	if config.PersistenceTimeout == 0 {
		config.PersistenceTimeout = defaultPersistenceTimeout
	}
	if config.PersistenceTimeout <= 0 || config.PersistenceTimeout > 30*time.Second {
		return nil, errInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Handler{
		accessTokens: config.AccessTokens, sessions: config.Sessions,
		configuration: config.Configuration, policies: config.Policies,
		quotas: config.Quotas, secrets: config.Secrets, endpoints: endpoints,
		targets: config.Targets, relayer: config.Relayer, telemetry: config.Telemetry,
		maximumResponseBody: config.MaximumResponseBodyBytes,
		clientWriteTimeout:  config.ClientWriteTimeout, persistenceTimeout: config.PersistenceTimeout,
		now: config.Now, retrySleep: sleepForRetry, ownedTargets: ownedTargets,
	}, nil
}

func defaultProtocolAdapters(maximumBodyBytes int64) []protocol.Adapter {
	return []protocol.Adapter{
		openairesponses.Adapter{MaximumBodyBytes: maximumBodyBytes},
		openaichat.Adapter{MaximumBodyBytes: maximumBodyBytes},
		openaiembeddings.Adapter{MaximumBodyBytes: maximumBodyBytes},
		anthropicmessages.Adapter{MaximumBodyBytes: maximumBodyBytes},
		opaquehttp.Adapter{MaximumBodyBytes: maximumBodyBytes},
	}
}

func (handler *Handler) Handler() http.Handler { return handler }

// Close retires the default handler-owned target cache. Explicit TargetFactory
// instances remain owned by their caller. Close is idempotent and does not
// interrupt active RoundTrips; their targets retire when the final lease is
// released.
func (handler *Handler) Close() error {
	if handler == nil || handler.ownedTargets == nil {
		return nil
	}
	return handler.ownedTargets.Close()
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if nilDependency(writer) {
		return
	}
	requestID := selectCorrelationID(request)
	writer.Header().Set("X-Latchway-Request-ID", requestID)

	if handler == nil || request == nil {
		writeProblem(writer, requestID, "server_not_ready", "", 0)
		return
	}
	browserOrigin, originErr := weborigin.Read(request.Header)
	if originErr != nil {
		handler.writeViolation(writer, requestID, requestViolation("header.Origin", "Origin must be exactly one canonical HTTPS browser origin."))
		return
	}
	if browserOrigin != "" {
		weborigin.SetResponseHeaders(writer.Header(), browserOrigin)
	}
	if request.Method == http.MethodOptions {
		handler.servePreflight(writer, request, requestID, browserOrigin)
		return
	}
	endpoint, violation := handler.endpoints.match(request)
	if violation != nil {
		handler.writeViolation(writer, requestID, violation)
		return
	}
	logicalID, ok := requestidentity.FromContext(request.Context())
	if !ok {
		writeProblem(writer, requestID, "server_not_ready", "", 0)
		return
	}
	declaration, violation := parseDeclaration(request)
	if violation != nil {
		handler.writeViolation(writer, requestID, violation)
		return
	}
	if endpoint.protocolID == protocol.OpaqueHTTPID && endpoint.opaqueRoute != declaration.feature {
		handler.writeViolation(writer, requestID, requestViolation(
			"header.X-Latchway-Feature",
			"The opaque HTTP path feature must exactly match X-Latchway-Feature.",
		))
		return
	}

	identityCtx, finishIdentity := handler.startStage(request.Context(), "identity verification", telemetry.Labels{})
	principal, err := handler.accessTokens.Verify(identityCtx, declaration.accessToken)
	finishIdentity(handler.telemetryOutcome(err))
	if err != nil {
		if handler.telemetry != nil {
			handler.telemetry.RecordIdentityFailure(request.Context(), telemetry.Labels{Outcome: handler.telemetryOutcome(err)})
		}
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	dpopCtx, finishDPoP := handler.startStage(request.Context(), "DPoP verification", telemetry.Labels{})
	authorization, err := handler.sessions.AuthorizeAccess(dpopCtx, session.AccessRequestInput{
		AccessToken: declaration.accessToken,
		Principal:   principal,
		DPoPProof:   declaration.dpopProof,
		HTTPMethod:  endpoint.publicMethod,
		RequestURI:  cloneURL(endpoint.publicURL),
		Origin:      browserOrigin,
	})
	finishDPoP(handler.telemetryOutcome(err))
	if err != nil {
		if handler.telemetry != nil && isDPoPFailure(err) {
			handler.telemetry.RecordDPoPFailure(request.Context(), telemetry.Labels{Outcome: handler.telemetryOutcome(err)})
		}
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	if !sdkMatchesPlatform(declaration.sdk, authorization.InstallationPlatform) {
		handler.writeViolation(writer, requestID, requestViolation(
			"header.X-Latchway-SDK", "The SDK identifier is incompatible with the authorized installation.",
		))
		return
	}

	snapshot, err := handler.configuration.ActiveSnapshot(request.Context(), configuration.TenantScope{
		OrganizationID: authorization.OrganizationID,
		ApplicationID:  authorization.ApplicationID,
		EnvironmentID:  authorization.EnvironmentID,
	})
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	if snapshot.PolicyRevision() != authorization.PolicyRevisionID ||
		snapshot.PolicyEnvironment() != authorization.EnvironmentID {
		handler.writeMappedError(writer, requestID, declaration.feature, policy.ErrConfiguration)
		return
	}

	metadata, err := endpoint.adapter.InspectRequest(request.Context(), request)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	replay, err := captureReplayableRequest(request)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	policyCtx, finishPolicy := handler.startStage(request.Context(), "policy evaluation", telemetry.Labels{
		Application: authorization.ApplicationID, Environment: authorization.EnvironmentID,
		Feature: declaration.feature, Platform: authorization.InstallationPlatform,
		AttestationLevel: authorization.TrustLevel,
	})
	plan, err := handler.policies.ResolvePlan(
		policyCtx, snapshot, declaration.feature, authorization, logicalID, metadata,
	)
	finishPolicy(handler.telemetryOutcome(err))
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	routeCtx, finishRoute := handler.startStage(request.Context(), "route selection", telemetry.Labels{
		Application: authorization.ApplicationID, Environment: authorization.EnvironmentID,
		Feature: declaration.feature, Platform: authorization.InstallationPlatform,
		AttestationLevel: authorization.TrustLevel, Plan: plan.LimitPlan.ID,
	})
	validatedPlan, err := validateDecisionPlan(declaration.feature, plan, endpoint.protocolID)
	if err != nil {
		finishRoute(handler.telemetryOutcome(err))
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	primary := validatedPlan.candidates[0]
	pricingAt := handler.now().UTC()
	prepared, err := handler.prepareExecutionAttempt(
		routeCtx, replay, endpoint, snapshot, primary.decision, primary.validated, pricingAt,
	)
	finishRoute(handler.telemetryOutcome(err))
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}

	requestLabels := telemetry.Labels{
		Application: authorization.ApplicationID, Environment: authorization.EnvironmentID,
		Feature: prepared.decision.Feature.ID, Route: prepared.decision.Route.ID,
		Upstream: prepared.decision.Upstream.ID, ModelAlias: prepared.decision.Model.ID,
		Platform: authorization.InstallationPlatform, AttestationLevel: authorization.TrustLevel,
		Plan: prepared.decision.LimitPlan.ID,
	}
	quotaCtx, finishQuota := handler.startStage(request.Context(), "quota reservation", requestLabels)
	reservation, err := handler.quotas.Reserve(quotaCtx, quota.ReserveInput{
		LogicalRequestID: logicalID,
		OrganizationID:   authorization.OrganizationID, ApplicationID: authorization.ApplicationID,
		EnvironmentID: authorization.EnvironmentID, ApplicationUserID: authorization.ApplicationUserID,
		InstallationID: authorization.InstallationID, SessionGrantID: authorization.SessionGrantID,
		ConfigRevisionID: snapshot.PolicyRevision(), FeatureKey: prepared.decision.Feature.ID,
		Protocol: prepared.decision.Feature.Protocol, ClientRequestID: declaration.clientRequestID,
		LimitPlanKey: prepared.decision.LimitPlan.ID, RouteKey: prepared.decision.Route.ID,
		UpstreamKey: prepared.decision.Upstream.ID, ModelKey: prepared.decision.Model.ID,
		PhysicalModel: prepared.decision.Model.UpstreamModel, Pricing: prepared.pricing.quotaSelection,
		InputPreflight: quotaInputPreflightBinding(prepared.inputPreflight),
		Streaming:      metadata.Streaming, Rules: prepared.rules,
	})
	finishQuota(handler.telemetryOutcome(err))
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	if handler.telemetry != nil {
		handler.telemetry.AddActiveReservations(request.Context(), requestLabels, 1)
		defer handler.telemetry.AddActiveReservations(context.WithoutCancel(request.Context()), requestLabels, -1)
		if metadata.Streaming {
			handler.telemetry.AddActiveStreams(request.Context(), requestLabels, 1)
			defer handler.telemetry.AddActiveStreams(context.WithoutCancel(request.Context()), requestLabels, -1)
		}
	}

	result := handler.executeReserved(
		prepared.request.Context(), writer, prepared.request, endpoint, authorization,
		prepared.decision, reservation, prepared.inputPreflight,
	)
	candidateIndex := 0
	routeAttempts := int64(1)
	totalAttempts := int64(1)
	current := prepared
	retryExecution := false
	var retryPrevious quota.Attempt
	var retryPreviousOutcome quota.Outcome
	for {
		if !result.beginInvoked {
			if result.err == nil {
				result.err = errDispatchNotConsumed
			}
			var lifecycleErr error
			if !retryExecution {
				lifecycleErr = handler.releaseReservation(request.Context(), reservation, failureCode(result.err))
			} else {
				lifecycleErr = handler.settleFinalAttempt(request.Context(), retryPrevious, retryPreviousOutcome)
			}
			if lifecycleErr != nil {
				result.err = lifecycleErr
			}
			handler.writeMappedError(writer, requestID, declaration.feature, result.err)
			return
		}
		if !result.dispatchOwner {
			if result.err == nil {
				result.err = errDispatchNotOwned
			}
			if retryExecution && retryBeginDefinitelyCreatedNoAttempt(result.err) {
				if finalErr := handler.settleFinalAttempt(request.Context(), retryPrevious, retryPreviousOutcome); finalErr != nil {
					result.err = finalErr
				}
			}
			handler.writeMappedError(writer, requestID, declaration.feature, result.err)
			return
		}
		if result.err == nil && !result.relay.ClientStarted {
			result.err = errDispatchNotConsumed
		}
		var outcome quota.Outcome
		result, outcome = calculateAttemptOutcome(current, result)
		condition, retryable := fallbackCondition(request.Context(), result)
		handler.recordAttempt(request.Context(), authorization, current.decision, result, outcome, condition)

		nextCandidateIndex := candidateIndex
		nextRouteAttempts := routeAttempts
		retryDelay := time.Duration(0)
		retrySelected := false
		sameRouteRetry := false
		retryPolicyInvalid := false
		if retryable && totalAttempts < maximumLogicalAttempts &&
			opaqueReplayAllowed(endpoint, current.decision.Route) {
			if routeAllowsRetry(current.decision.Route, condition, routeAttempts) {
				var delayOK bool
				retryDelay, delayOK = routeRetryBackoff(
					logicalID.String(), current.decision.Route, routeAttempts,
				)
				if !delayOK {
					result.err = policy.ErrConfiguration
					retryPolicyInvalid = true
				} else if retryDelayFitsContext(request.Context(), retryDelay) {
					nextRouteAttempts++
					retrySelected = true
					sameRouteRetry = true
				}
			}
			if !retrySelected && !retryPolicyInvalid && routeAllowsFallback(current.decision.Route, condition) &&
				candidateIndex+1 < len(validatedPlan.candidates) &&
				opaqueReplayAllowed(endpoint, validatedPlan.candidates[candidateIndex+1].decision.Route) {
				nextCandidateIndex++
				nextRouteAttempts = 1
				retrySelected = true
			}
		}
		if retrySelected {
			nextCandidate := validatedPlan.candidates[nextCandidateIndex]
			next, prepareErr := handler.prepareExecutionAttempt(
				request.Context(), replay, endpoint, snapshot,
				nextCandidate.decision, nextCandidate.validated, pricingAt,
			)
			if prepareErr != nil {
				settlementErr := handler.settleFinalAttempt(request.Context(), result.attempt, outcome)
				if settlementErr != nil {
					prepareErr = settlementErr
				}
				handler.writeMappedError(writer, requestID, declaration.feature, prepareErr)
				return
			}
			retryInput, retryErr := retryAttemptInput(next)
			if retryErr != nil {
				if finalErr := handler.settleFinalAttempt(request.Context(), result.attempt, outcome); finalErr != nil {
					retryErr = finalErr
				}
				handler.writeMappedError(writer, requestID, declaration.feature, retryErr)
				return
			}
			if settlementErr := handler.settleForRetry(request.Context(), result.attempt, outcome); settlementErr != nil {
				handler.writeMappedError(writer, requestID, declaration.feature, settlementErr)
				return
			}
			retryPrevious = result.attempt
			retryPreviousOutcome = outcome
			if sameRouteRetry && handler.retrySleep == nil {
				retryErr = errInvalidConfiguration
			} else if sameRouteRetry {
				retryErr = handler.retrySleep(request.Context(), retryDelay)
			} else if request.Context().Err() != nil {
				retryErr = request.Context().Err()
			}
			// Preparation and durable settlement can consume enough of the total
			// request budget that a retry delay which fit when selected no longer
			// fits when the sleep begins. If the request itself is still live,
			// treat only that same-route retry as unavailable and continue with an
			// immediately eligible fallback. The prior attempt is already settled
			// for retry, so the fallback still reserves exactly one next attempt.
			if sameRouteRetry && errors.Is(retryErr, context.DeadlineExceeded) &&
				request.Context().Err() == nil &&
				routeAllowsFallback(current.decision.Route, condition) &&
				candidateIndex+1 < len(validatedPlan.candidates) &&
				opaqueReplayAllowed(endpoint, validatedPlan.candidates[candidateIndex+1].decision.Route) {
				fallbackIndex := candidateIndex + 1
				fallbackCandidate := validatedPlan.candidates[fallbackIndex]
				fallbackNext, fallbackErr := handler.prepareExecutionAttempt(
					request.Context(), replay, endpoint, snapshot,
					fallbackCandidate.decision, fallbackCandidate.validated, pricingAt,
				)
				var fallbackRetryInput quota.RetryAttemptInput
				if fallbackErr == nil {
					fallbackRetryInput, fallbackErr = retryAttemptInput(fallbackNext)
				}
				if fallbackErr == nil && request.Context().Err() != nil {
					fallbackErr = request.Context().Err()
				}
				if fallbackErr == nil {
					next = fallbackNext
					retryInput = fallbackRetryInput
					nextCandidateIndex = fallbackIndex
					nextRouteAttempts = 1
					sameRouteRetry = false
					retryErr = nil
				} else {
					retryErr = fallbackErr
				}
			}
			if retryErr != nil || request.Context().Err() != nil {
				if retryErr == nil {
					retryErr = request.Context().Err()
				}
				if finalErr := handler.settleFinalAttempt(request.Context(), retryPrevious, retryPreviousOutcome); finalErr != nil {
					retryErr = finalErr
				}
				handler.writeMappedError(writer, requestID, declaration.feature, retryErr)
				return
			}
			candidateIndex = nextCandidateIndex
			routeAttempts = nextRouteAttempts
			totalAttempts++
			current = next
			retryExecution = true
			result = handler.executeRetry(
				next.request.Context(), writer, next.request, endpoint, authorization,
				next.decision, retryPrevious, retryInput, next.inputPreflight,
			)
			continue
		}

		settlementErr := handler.settleFinalAttempt(request.Context(), result.attempt, outcome)
		if result.relay.ClientStarted {
			return
		}
		if settlementErr != nil {
			handler.writeMappedError(writer, requestID, declaration.feature, settlementErr)
			return
		}
		if result.err != nil {
			handler.writeMappedError(writer, requestID, declaration.feature, result.err)
			return
		}
		// A successful bounded relay always commits provider response headers,
		// even for an empty body. Reaching this point means the relayer violated
		// its contract and must not be treated as a successful attempt.
		handler.writeMappedError(writer, requestID, declaration.feature, errDispatchNotConsumed)
		return
	}
}

type executionResult struct {
	attempt       quota.Attempt
	relay         upstream.RelayOutcome
	startedAt     time.Time
	firstByteAt   time.Time
	err           error
	beginInvoked  bool
	dispatchOwner bool
}

type preparedExecutionAttempt struct {
	request              *http.Request
	decision             policy.Decision
	rules                []quota.Rule
	pricing              configuredPricing
	appliedOutputMaximum int64
	inputPreflight       *protocol.TrustedInputPreflight
	hardCost             hardCostReservation
}

func retryAttemptInput(prepared preparedExecutionAttempt) (quota.RetryAttemptInput, error) {
	units := make(map[string]int64, 4)
	for _, rule := range prepared.rules {
		switch rule.Metric {
		case quota.InputTokensMetric, quota.OutputTokensMetric, quota.TotalTokensMetric, quota.CostNanoUSDMetric:
			if existing, duplicate := units[rule.Metric]; duplicate && existing != rule.ReservedUnits {
				return quota.RetryAttemptInput{}, policy.ErrConfiguration
			}
			units[rule.Metric] = rule.ReservedUnits
		}
	}
	allocations := make([]quota.AttemptAllocation, 0, len(units))
	for _, metric := range []string{
		quota.InputTokensMetric,
		quota.OutputTokensMetric,
		quota.TotalTokensMetric,
		quota.CostNanoUSDMetric,
	} {
		if value, ok := units[metric]; ok {
			allocations = append(allocations, quota.AttemptAllocation{Metric: metric, Units: value})
		}
	}
	inputNanoUSDPerMillion := int64(0)
	if _, hasCost := units[quota.CostNanoUSDMetric]; hasCost {
		inputNanoUSDPerMillion = prepared.pricing.rates.InputNanoUSDPerMillion
	}
	return quota.RetryAttemptInput{
		RouteKey:               prepared.decision.Route.ID,
		UpstreamKey:            prepared.decision.Upstream.ID,
		ModelKey:               prepared.decision.Model.ID,
		PhysicalModel:          prepared.decision.Model.UpstreamModel,
		Pricing:                prepared.pricing.quotaSelection,
		InputNanoUSDPerMillion: inputNanoUSDPerMillion,
		InputPreflight:         quotaInputPreflightBinding(prepared.inputPreflight),
		Allocations:            allocations,
	}, nil
}

func retryBeginDefinitelyCreatedNoAttempt(err error) bool {
	return errors.Is(err, quota.ErrExceeded) ||
		errors.Is(err, quota.ErrConcurrencyExceeded) ||
		errors.Is(err, quota.ErrExpired) ||
		errors.Is(err, quota.ErrInvalidInput)
}

func calculateAttemptOutcome(
	prepared preparedExecutionAttempt,
	result executionResult,
) (executionResult, quota.Outcome) {
	providerUsageOverBound := providerUsageExceedsTrustedBounds(
		result.relay.Usage, prepared.appliedOutputMaximum, prepared.inputPreflight,
	)
	if providerUsageOverBound {
		result.err = fmt.Errorf(
			"%w: provider-reported usage exceeds the trusted request bounds",
			errUpstreamProtocol,
		)
		// The provider measurement cannot be reconciled with the exact request
		// bound. Settle every stateful reservation conservatively instead of
		// passing an impossible measurement that could leave durable capacity
		// pending or undercharge a failed attempt.
		result.relay.Usage = protocol.Usage{}
	}
	var calculatedCost quota.Cost
	if !providerUsageOverBound {
		calculatedCost, result.err = calculateConfiguredCost(
			prepared.pricing, result.relay.Usage, result.err,
		)
	}
	calculatedCost = boundedSettlementCost(calculatedCost, prepared.hardCost)
	return result, quotaOutcome(result.relay, calculatedCost, result.err)
}

func (handler *Handler) prepareExecutionAttempt(
	ctx context.Context,
	replay replayableRequest,
	endpoint endpointMatch,
	snapshot configuration.ActiveSnapshot,
	decision policy.Decision,
	validated validatedDecision,
	pricingAt time.Time,
) (preparedExecutionAttempt, error) {
	adapter := endpoint.adapter
	if ctx == nil || nilDependency(adapter) || pricingAt.IsZero() {
		return preparedExecutionAttempt{}, errInvalidConfiguration
	}
	selectedPricing, err := resolveConfiguredPricing(snapshot, decision.Model, pricingAt)
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	attemptRequest, err := replay.New(ctx)
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	featureDecision, err := protocolFeatureDecision(endpoint, decision, validated)
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	appliedOutputMaximum, err := adapter.ApplyFeature(attemptRequest.Context(), attemptRequest, featureDecision)
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	if !validAppliedOutputMaximum(adapter.Capabilities(), validated, appliedOutputMaximum) {
		return preparedExecutionAttempt{}, errInvalidConfiguration
	}
	var inputPreflight *protocol.TrustedInputPreflight
	if trustedInputPreflightRequired(validated.rules, selectedPricing) {
		profile, profileErr := resolveTrustedInputProfile(snapshot, decision)
		preflighter, supportsPreflight := adapter.(protocol.InputPreflighter)
		if profileErr != nil || !supportsPreflight || !adapter.Capabilities().TrustedInputPreflight {
			return preparedExecutionAttempt{}, policy.ErrConfiguration
		}
		preflight, preflightErr := preflighter.PreflightInput(attemptRequest.Context(), attemptRequest, profile)
		if preflightErr != nil {
			return preparedExecutionAttempt{}, preflightErr
		}
		if err := validateTrustedInputPreflight(profile, decision, appliedOutputMaximum, preflight); err != nil {
			return preparedExecutionAttempt{}, err
		}
		if err := verifyAndRebindPreflightBody(attemptRequest, preflight); err != nil {
			return preparedExecutionAttempt{}, err
		}
		inputPreflight = &preflight
	}
	hardCost, err := assignDecisionReservationUnits(
		validated.rules, selectedPricing, appliedOutputMaximum, inputPreflight,
	)
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	return preparedExecutionAttempt{
		request: attemptRequest, decision: decision, rules: validated.rules, pricing: selectedPricing,
		appliedOutputMaximum: appliedOutputMaximum, inputPreflight: inputPreflight,
		hardCost: hardCost,
	}, nil
}

func protocolFeatureDecision(
	endpoint endpointMatch,
	decision policy.Decision,
	validated validatedDecision,
) (protocol.FeatureDecision, error) {
	result := protocol.FeatureDecision{
		PhysicalModel:       decision.Model.UpstreamModel,
		DefaultOutputTokens: validated.defaultOutputTokens,
		MaximumOutputTokens: validated.maximumOutputTokens,
	}
	if endpoint.protocolID != protocol.OpaqueHTTPID {
		return result, nil
	}
	if decision.Feature.OpaqueHTTP == nil || decision.Route.MaximumResponseBytes <= 0 ||
		endpoint.providerPath == "" || endpoint.providerPath != endpoint.opaquePath {
		return protocol.FeatureDecision{}, policy.ErrConfiguration
	}
	policy := decision.Feature.OpaqueHTTP
	result.OpaqueHTTP = &protocol.OpaqueHTTPDecision{
		FeatureID:             decision.Feature.ID,
		ProviderPath:          endpoint.providerPath,
		AllowedMethods:        append([]string(nil), policy.AllowedMethods...),
		PathPrefixes:          append([]string(nil), policy.PathPrefixes...),
		MaximumBodyBytes:      policy.MaximumBodyBytes,
		AllowedRequestHeaders: append([]string(nil), policy.AllowedRequestHeaders...),
		MaximumResponseBytes:  decision.Route.MaximumResponseBytes,
		StreamingAllowed:      decision.Route.StreamingAllowed,
	}
	return result, nil
}

func (handler *Handler) executeReserved(
	ctx context.Context,
	writer http.ResponseWriter,
	incoming *http.Request,
	endpoint endpointMatch,
	authorization session.Authorization,
	decision policy.Decision,
	reservation quota.Reservation,
	inputPreflight *protocol.TrustedInputPreflight,
) executionResult {
	ctx, finish := handler.startStage(ctx, "upstream attempt", attemptTelemetryLabels(decision))
	result := handler.executeAttempt(
		ctx, writer, incoming, endpoint, authorization, decision, inputPreflight,
		func(beginContext context.Context) (quota.Attempt, bool, error) {
			return handler.quotas.BeginAttempt(beginContext, reservation)
		},
	)
	finish(handler.telemetryOutcome(result.err))
	return result
}

func (handler *Handler) executeRetry(
	ctx context.Context,
	writer http.ResponseWriter,
	incoming *http.Request,
	endpoint endpointMatch,
	authorization session.Authorization,
	decision policy.Decision,
	previous quota.Attempt,
	retry quota.RetryAttemptInput,
	inputPreflight *protocol.TrustedInputPreflight,
) executionResult {
	ctx, finish := handler.startStage(ctx, "upstream attempt", attemptTelemetryLabels(decision))
	result := handler.executeAttempt(
		ctx, writer, incoming, endpoint, authorization, decision, inputPreflight,
		func(beginContext context.Context) (quota.Attempt, bool, error) {
			return handler.quotas.BeginRetryAttempt(beginContext, previous, retry)
		},
	)
	finish(handler.telemetryOutcome(result.err))
	return result
}

type beginExecutionAttempt func(context.Context) (quota.Attempt, bool, error)

func (handler *Handler) executeAttempt(
	ctx context.Context,
	writer http.ResponseWriter,
	incoming *http.Request,
	endpoint endpointMatch,
	authorization session.Authorization,
	decision policy.Decision,
	inputPreflight *protocol.TrustedInputPreflight,
	begin beginExecutionAttempt,
) executionResult {
	if !validTargetTimeouts(decision.Upstream.Timeouts) {
		return executionResult{err: errTargetConfiguration}
	}
	if begin == nil {
		return executionResult{err: errInvalidConfiguration}
	}
	if inputPreflight != nil {
		if err := verifyAndRebindPreflightBody(incoming, *inputPreflight); err != nil {
			return executionResult{err: err}
		}
	}
	executionContext, cancelExecution := context.WithTimeout(ctx, decision.Upstream.Timeouts.Total)
	defer cancelExecution()

	lease, err := handler.targets.Acquire(decision.Upstream)
	if err != nil || nilDependency(lease) {
		return executionResult{err: fmt.Errorf("%w: resolve target", errTargetConfiguration)}
	}
	defer lease.Release()
	prepared, err := lease.Prepare(
		incoming, endpoint.providerPath, protocolForwardedHeaders(endpoint.protocolID, decision.Feature), decision.Upstream.StaticHeaders,
	)
	if err != nil {
		return executionResult{err: fmt.Errorf("%w: prepare request", errTargetConfiguration)}
	}

	dispatch := func(beforeRoundTrip func() error, consume func(*upstream.DispatchedResponse) error) error {
		response, err := lease.DispatchWithBeforeRoundTrip(executionContext, prepared, beforeRoundTrip)
		if err != nil {
			return err
		}
		return consume(response)
	}
	authentication := decision.Upstream.Authentication
	switch authentication.Type {
	case "none":
		return handler.dispatchAttempt(executionContext, writer, endpoint.adapter, decision, begin, dispatch)
	case "bearer", "header":
		var result executionResult
		callbackCalled := false
		secretErr := handler.secrets.Use(executionContext, secrets.Scope{
			OrganizationID: authorization.OrganizationID,
			ApplicationID:  authorization.ApplicationID,
			EnvironmentID:  authorization.EnvironmentID,
		}, authentication.SecretRef, func(credential []byte) error {
			callbackCalled = true
			credentialDispatch := func(beforeRoundTrip func() error, consume func(*upstream.DispatchedResponse) error) error {
				if authentication.Type == "bearer" {
					return lease.WithBearerDispatchWithBeforeRoundTrip(
						executionContext, prepared, credential, beforeRoundTrip, consume,
					)
				}
				return lease.WithHeaderDispatchWithBeforeRoundTrip(
					executionContext, prepared, authentication.HeaderName, credential, beforeRoundTrip, consume,
				)
			}
			result = handler.dispatchAttempt(
				executionContext, writer, endpoint.adapter, decision, begin, credentialDispatch,
			)
			// Never return a transport or observer error through the secret
			// boundary; Store.Use intentionally collapses callback errors.
			return nil
		})
		if secretErr != nil {
			if !callbackCalled {
				return executionResult{err: secretErr}
			}
			if result.err == nil {
				result.err = secretErr
			}
		}
		if !callbackCalled && secretErr == nil {
			return executionResult{err: errDispatchNotConsumed}
		}
		return result
	default:
		return executionResult{err: fmt.Errorf("%w: authentication", errTargetConfiguration)}
	}
}

func protocolForwardedHeaders(protocolID string, feature configuration.Feature) []string {
	if protocolID == protocol.OpaqueHTTPID && feature.OpaqueHTTP != nil {
		return append([]string(nil), feature.OpaqueHTTP.AllowedRequestHeaders...)
	}
	if protocolID == protocol.AnthropicMessagesID {
		return []string{"Content-Type", "Anthropic-Version"}
	}
	return []string{"Content-Type"}
}

func (handler *Handler) dispatchAttempt(
	ctx context.Context,
	writer http.ResponseWriter,
	adapter protocol.Adapter,
	decision policy.Decision,
	begin beginExecutionAttempt,
	dispatch func(func() error, func(*upstream.DispatchedResponse) error) error,
) executionResult {
	result := executionResult{startedAt: handler.now().UTC()}
	beforeRoundTrip := func() error {
		if result.beginInvoked {
			result.err = errDispatchNotConsumed
			return result.err
		}
		result.beginInvoked = true
		attempt, owner, err := begin(ctx)
		result.attempt = attempt
		result.dispatchOwner = owner
		if err != nil {
			result.dispatchOwner = false
			result.err = err
			return err
		}
		if !owner {
			result.err = errDispatchNotOwned
			return result.err
		}
		return nil
	}
	consumed := false
	dispatchErr := dispatch(beforeRoundTrip, func(response *upstream.DispatchedResponse) error {
		consumed = true
		if !result.beginInvoked || !result.dispatchOwner {
			result.err = errDispatchNotConsumed
			return result.err
		}
		result.relay, result.firstByteAt, result.err = handler.consumeResponse(
			ctx, writer, adapter, decision, result.attempt, response,
		)
		return result.err
	})
	if result.err == nil && dispatchErr != nil {
		result.err = fmt.Errorf("%w: %w", errUpstreamDispatch, dispatchErr)
	}
	if !consumed && result.err == nil {
		result.err = errDispatchNotConsumed
	}
	return result
}

func (handler *Handler) consumeResponse(
	ctx context.Context,
	writer http.ResponseWriter,
	adapter protocol.Adapter,
	decision policy.Decision,
	attempt quota.Attempt,
	response *upstream.DispatchedResponse,
) (upstream.RelayOutcome, time.Time, error) {
	if response == nil || response.Response == nil {
		return upstream.RelayOutcome{}, time.Time{}, errDispatchNotConsumed
	}
	defer response.Close()
	if nilDependency(adapter) {
		return upstream.RelayOutcome{StatusCode: response.StatusCode}, time.Time{}, errInvalidConfiguration
	}
	observer, err := adapter.ObserveResponse(ctx, response.Response)
	if err != nil {
		return upstream.RelayOutcome{StatusCode: response.StatusCode}, time.Time{}, fmt.Errorf("%w: %w", errUpstreamProtocol, err)
	}
	streamCtx, finishStream := handler.startStage(ctx, "streaming observation", attemptTelemetryLabels(decision))
	var firstByteAt time.Time
	outcome, err := handler.relayer.Relay(streamCtx, writer, response, observer, upstream.ResponseRelayConfig{
		IdleTimeout:        decision.Upstream.Timeouts.Idle,
		ClientWriteTimeout: handler.clientWriteTimeout,
		MaxBodyBytes:       handler.maximumResponseBytes(decision),
		OnFirstByte: func(firstByteContext context.Context) error {
			firstByteAt = handler.now().UTC()
			markContext, cancelMark := context.WithTimeout(firstByteContext, handler.persistenceTimeout)
			defer cancelMark()
			if err := handler.quotas.MarkFirstByte(markContext, attempt); err != nil {
				// Collapse storage and child-deadline details to the stable quota
				// dependency class. A first-byte accounting stall is not an
				// upstream timeout and its underlying error is never client-safe.
				return fmt.Errorf("mark first byte persistence: %w", quota.ErrDependency)
			}
			return nil
		},
	})
	finishStream(handler.telemetryOutcome(err))
	if err != nil {
		return outcome, firstByteAt, fmt.Errorf("%w: %w", errUpstreamRelay, err)
	}
	return outcome, firstByteAt, nil
}

func (handler *Handler) maximumResponseBytes(decision policy.Decision) int64 {
	maximum := handler.maximumResponseBody
	if decision.Feature.Protocol == protocol.OpaqueHTTPID && decision.Route.MaximumResponseBytes > 0 {
		maximum = min(maximum, decision.Route.MaximumResponseBytes)
	}
	return maximum
}

type validatedDecision struct {
	rules               []quota.Rule
	defaultOutputTokens int64
	maximumOutputTokens int64
}

type validatedExecutionCandidate struct {
	decision  policy.Decision
	validated validatedDecision
}

type validatedExecutionPlan struct {
	candidates []validatedExecutionCandidate
}

// configuredPricing is captured once from the immutable active snapshot and
// then carried through reservation and settlement. In particular, settlement
// never re-reads a potentially newer active catalog.
type configuredPricing struct {
	configured     bool
	quotaSelection quota.PricingSelection
	rates          pricing.Rates
	source         pricing.Source
}

// hardCostReservation records the exact conservative nano-USD reservation
// shared by every applicable hard-cost rule. active distinguishes a genuine
// zero-cost reservation from a request without a hard-cost policy.
type hardCostReservation struct {
	active  bool
	nanoUSD int64
}

func assignDecisionReservationUnits(
	rules []quota.Rule,
	selected configuredPricing,
	appliedOutputMaximum int64,
	inputPreflight *protocol.TrustedInputPreflight,
) (hardCostReservation, error) {
	if appliedOutputMaximum < 0 {
		return hardCostReservation{}, policy.ErrConfiguration
	}
	hasCostRule := false
	requiresInputBound := false
	for _, rule := range rules {
		switch rule.Metric {
		case quota.CostNanoUSDMetric:
			hasCostRule = true
		case quota.InputTokensMetric, quota.TotalTokensMetric:
			requiresInputBound = true
		}
	}
	if requiresInputBound && inputPreflight == nil {
		return hardCostReservation{}, policy.ErrConfiguration
	}
	if inputPreflight != nil &&
		(inputPreflight.InputTokenBound <= 0 ||
			inputPreflight.OutputTokenBound != appliedOutputMaximum ||
			inputPreflight.InputTokenBound > math.MaxInt64-inputPreflight.OutputTokenBound ||
			inputPreflight.TotalTokenBound != inputPreflight.InputTokenBound+inputPreflight.OutputTokenBound) {
		return hardCostReservation{}, policy.ErrConfiguration
	}
	var bound hardCostReservation
	if hasCostRule {
		if !selected.configured || (selected.rates.InputNanoUSDPerMillion != 0 && inputPreflight == nil) {
			return hardCostReservation{}, policy.ErrConfiguration
		}
		inputMaximum := int64(0)
		if inputPreflight != nil {
			inputMaximum = inputPreflight.InputTokenBound
		}
		calculated, err := pricing.Calculate(
			selected.rates,
			pricing.Usage{InputTokens: inputMaximum, OutputTokens: appliedOutputMaximum},
			selected.source,
		)
		if err != nil || !calculated.Known() {
			return hardCostReservation{}, fmt.Errorf(
				"%w: calculate hard cost reservation", errPricingUnavailable,
			)
		}
		bound = hardCostReservation{active: true, nanoUSD: calculated.CostNanoUSD()}
	}
	for index := range rules {
		switch rules[index].Metric {
		case quota.InputTokensMetric:
			rules[index].ReservedUnits = inputPreflight.InputTokenBound
		case quota.OutputTokensMetric:
			rules[index].ReservedUnits = appliedOutputMaximum
		case quota.TotalTokensMetric:
			rules[index].ReservedUnits = inputPreflight.TotalTokenBound
		case quota.CostNanoUSDMetric:
			rules[index].ReservedUnits = bound.nanoUSD
		}
	}
	return bound, nil
}

func validAppliedOutputMaximum(
	capabilities protocol.Capabilities,
	decision validatedDecision,
	applied int64,
) bool {
	if capabilities.OutputTokenClamp {
		return decision.defaultOutputTokens > 0 && decision.maximumOutputTokens > 0 &&
			decision.defaultOutputTokens <= decision.maximumOutputTokens &&
			applied > 0 && applied <= decision.maximumOutputTokens
	}
	return decision.defaultOutputTokens == 0 && decision.maximumOutputTokens == 0 && applied == 0
}

func trustedInputPreflightRequired(rules []quota.Rule, selected configuredPricing) bool {
	for _, rule := range rules {
		switch rule.Metric {
		case quota.InputTokensMetric, quota.TotalTokensMetric:
			return true
		case quota.CostNanoUSDMetric:
			if selected.configured && selected.rates.InputNanoUSDPerMillion != 0 {
				return true
			}
		}
	}
	return false
}

func resolveTrustedInputProfile(
	snapshot configuration.ActiveSnapshot,
	decision policy.Decision,
) (protocol.TrustedInputProfile, error) {
	model, ok := snapshot.Model(decision.Model.ID)
	if !ok || !reflect.DeepEqual(model, decision.Model) || model.InputAccountingRef == "" {
		return protocol.TrustedInputProfile{}, policy.ErrConfiguration
	}
	profile, ok := snapshot.InputAccountingProfile(model.InputAccountingRef)
	if !ok || profile.Protocol != decision.Feature.Protocol ||
		profile.PhysicalModel != model.UpstreamModel ||
		!slices.Contains(model.Capabilities, profile.Protocol) {
		return protocol.TrustedInputProfile{}, policy.ErrConfiguration
	}
	return protocol.TrustedInputProfile{
		ID:                             profile.ID,
		Protocol:                       profile.Protocol,
		Method:                         profile.Method,
		PhysicalModel:                  profile.PhysicalModel,
		MaximumFramingTokensPerRequest: profile.MaximumFramingTokensPerRequest,
		MaximumFramingTokensPerMessage: profile.MaximumFramingTokensPerMessage,
		MaximumContextTokens:           profile.MaximumContextTokens,
	}, nil
}

func validateTrustedInputPreflight(
	profile protocol.TrustedInputProfile,
	decision policy.Decision,
	appliedOutputMaximum int64,
	preflight protocol.TrustedInputPreflight,
) error {
	expectedInputBound, boundOK := trustedInputBoundFromProfile(profile, preflight)
	if preflight.ProfileID != profile.ID || preflight.ProfileDigest != profile.Digest() ||
		preflight.Protocol != profile.Protocol || preflight.Method != profile.Method ||
		preflight.Protocol != decision.Feature.Protocol ||
		preflight.PhysicalModel != decision.Model.UpstreamModel ||
		preflight.PhysicalModel != profile.PhysicalModel ||
		preflight.RequestBytes <= 0 || preflight.RequestBytes > maximumRequestBodyLimit ||
		preflight.MessageCount <= 0 || preflight.MessageCount > 4096 ||
		!boundOK || preflight.InputTokenBound != expectedInputBound ||
		preflight.OutputTokenBound != appliedOutputMaximum ||
		preflight.InputTokenBound > math.MaxInt64-preflight.OutputTokenBound ||
		preflight.TotalTokenBound != preflight.InputTokenBound+preflight.OutputTokenBound ||
		preflight.TotalTokenBound > profile.MaximumContextTokens {
		return policy.ErrConfiguration
	}
	return nil
}

func trustedInputBoundFromProfile(
	profile protocol.TrustedInputProfile,
	preflight protocol.TrustedInputPreflight,
) (int64, bool) {
	if preflight.RequestBytes <= 0 || preflight.MessageCount <= 0 || preflight.MessageCount > 4096 ||
		profile.MaximumFramingTokensPerRequest < 0 || profile.MaximumFramingTokensPerMessage < 0 ||
		profile.MaximumFramingTokensPerMessage != 0 &&
			preflight.MessageCount > math.MaxInt64/profile.MaximumFramingTokensPerMessage {
		return 0, false
	}
	messageFraming := preflight.MessageCount * profile.MaximumFramingTokensPerMessage
	if preflight.RequestBytes > math.MaxInt64-profile.MaximumFramingTokensPerRequest {
		return 0, false
	}
	bound := preflight.RequestBytes + profile.MaximumFramingTokensPerRequest
	if bound > math.MaxInt64-messageFraming {
		return 0, false
	}
	return bound + messageFraming, true
}

func verifyAndRebindPreflightBody(
	request *http.Request,
	preflight protocol.TrustedInputPreflight,
) error {
	if request == nil || request.Body == nil || preflight.RequestBytes <= 0 ||
		preflight.RequestBytes > maximumRequestBodyLimit || request.ContentLength != preflight.RequestBytes {
		return policy.ErrConfiguration
	}
	bytesLimit := preflight.RequestBytes + 1
	body, err := io.ReadAll(io.LimitReader(request.Body, bytesLimit))
	closeErr := request.Body.Close()
	if err != nil || closeErr != nil || int64(len(body)) != preflight.RequestBytes ||
		sha256.Sum256(body) != preflight.RewrittenBodySHA256 {
		return policy.ErrConfiguration
	}
	// Own and reinstall the exact bytes that were checked. The outbound request
	// is reconstructed only after this second verification and no caller gains
	// mutable access to the backing slice.
	owned := append([]byte(nil), body...)
	request.Body = io.NopCloser(bytes.NewReader(owned))
	request.ContentLength = int64(len(owned))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(owned)), nil
	}
	return nil
}

func quotaInputPreflightBinding(
	preflight *protocol.TrustedInputPreflight,
) *quota.InputPreflightBinding {
	if preflight == nil {
		return nil
	}
	return &quota.InputPreflightBinding{
		Method: preflight.Method, Protocol: preflight.Protocol, ProfileID: preflight.ProfileID,
		ProfileDigest: preflight.ProfileDigest, RewrittenBodySHA256: preflight.RewrittenBodySHA256,
		PhysicalModel: preflight.PhysicalModel, InputTokenBound: preflight.InputTokenBound,
		OutputTokenBound: preflight.OutputTokenBound, TotalTokenBound: preflight.TotalTokenBound,
	}
}

func providerUsageExceedsTrustedBounds(
	usage protocol.Usage,
	appliedOutputMaximum int64,
	inputPreflight *protocol.TrustedInputPreflight,
) bool {
	if !usage.Known {
		return false
	}
	if usage.OutputTokens > appliedOutputMaximum {
		return true
	}
	return inputPreflight != nil &&
		(usage.InputTokens > inputPreflight.InputTokenBound ||
			usage.TotalTokens > inputPreflight.TotalTokenBound)
}

func boundedSettlementCost(cost quota.Cost, bound hardCostReservation) quota.Cost {
	if bound.active && cost.Known && cost.NanoUSD > bound.nanoUSD {
		// A provider measurement above the pre-dispatch conservative bound is
		// not a charge this request can safely reconcile. Unknown cost makes the
		// quota store retain the full reservation and still terminalize it.
		return quota.Cost{}
	}
	return cost
}

func resolveConfiguredPricing(
	snapshot configuration.ActiveSnapshot,
	model configuration.Model,
	now time.Time,
) (configuredPricing, error) {
	if model.PricingRef == "" {
		return configuredPricing{}, nil
	}
	snapshotModel, ok := snapshot.Model(model.ID)
	if !ok || snapshotModel.ID != model.ID || snapshotModel.PricingRef != model.PricingRef {
		return configuredPricing{}, policy.ErrConfiguration
	}
	catalog, ok := snapshot.PricingCatalog(model.PricingRef)
	if !ok {
		return configuredPricing{}, policy.ErrConfiguration
	}
	entry, ok := snapshot.PricingEntry(model.PricingRef, model.ID)
	if !ok {
		return configuredPricing{}, policy.ErrConfiguration
	}
	return captureConfiguredPricing(
		model.PricingRef, snapshot.PolicyRevision(), model.ID, catalog, entry, now,
	)
}

func captureConfiguredPricing(
	pricingRef string,
	revision string,
	modelID string,
	catalog configuration.PricingCatalog,
	entry configuration.PricingEntry,
	now time.Time,
) (configuredPricing, error) {
	source, err := pricing.NewSource(pricingRef, revision)
	if err != nil || catalog.ID != pricingRef || catalog.Currency != pricing.CurrencyUSD ||
		len(catalog.Entries) == 0 ||
		entry.ModelID != modelID || entry.InputNanoUSDPerMillion < 0 ||
		entry.OutputNanoUSDPerMillion < 0 || entry.RequestNanoUSD < 0 {
		return configuredPricing{}, policy.ErrConfiguration
	}
	matchingEntries := 0
	for _, candidate := range catalog.Entries {
		if candidate.ModelID != modelID {
			continue
		}
		matchingEntries++
		if candidate != entry {
			return configuredPricing{}, policy.ErrConfiguration
		}
	}
	if matchingEntries != 1 {
		return configuredPricing{}, policy.ErrConfiguration
	}
	if catalog.EffectiveAfter(now) {
		return configuredPricing{}, errPricingUnavailable
	}
	return configuredPricing{
		configured: true,
		quotaSelection: quota.PricingSelection{
			CatalogID: catalog.ID,
			Currency:  catalog.Currency,
		},
		rates: pricing.Rates{
			InputNanoUSDPerMillion:  entry.InputNanoUSDPerMillion,
			OutputNanoUSDPerMillion: entry.OutputNanoUSDPerMillion,
			RequestNanoUSD:          entry.RequestNanoUSD,
		},
		source: source,
	}, nil
}

func calculateConfiguredCost(
	selected configuredPricing,
	usage protocol.Usage,
	executionErr error,
) (quota.Cost, error) {
	if !selected.configured || !usage.Known {
		return quota.Cost{}, executionErr
	}
	calculated, err := pricing.Calculate(selected.rates, pricing.Usage{
		InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens,
	}, selected.source)
	if err != nil {
		if executionErr == nil {
			executionErr = fmt.Errorf("%w: calculate configured cost", errPricingUnavailable)
		}
		return quota.Cost{}, executionErr
	}
	return quota.Cost{
		NanoUSD: calculated.CostNanoUSD(), Known: true,
		Confidence: quota.CalculatedCostConfidence,
	}, executionErr
}

func validateDecision(featureID string, decision policy.Decision, endpointProtocol string) (validatedDecision, error) {
	requiredUpstreamType, knownProtocol := protocol.RequiredUpstreamType(endpointProtocol)
	if decision.Route.ID == "" || decision.Route.ModelID != decision.Model.ID ||
		!validFallbackPolicy(decision.Route.FallbackOn) || !validRetryPolicy(decision.Route.RetryPolicy) ||
		!validRouteProtocolPolicy(decision.Feature.Protocol, decision.Route) ||
		decision.Model.ID == "" ||
		decision.Model.UpstreamID != decision.Upstream.ID || decision.Model.UpstreamModel == "" ||
		endpointProtocol == "" || decision.Feature.Protocol != endpointProtocol ||
		!protocol.ProtocolExecutable(endpointProtocol) || !knownProtocol ||
		!slices.Contains(decision.Model.Capabilities, endpointProtocol) ||
		decision.Upstream.ID == "" || decision.Upstream.Type != requiredUpstreamType ||
		!validUpstreamAuthentication(decision.Upstream.Authentication) ||
		!validTargetTimeouts(decision.Upstream.Timeouts) {
		return validatedDecision{}, policy.ErrConfiguration
	}
	return validateFeatureLimitPlan(featureID, decision.Feature, decision.LimitPlan)
}

func validateDecisionPlan(
	featureID string,
	plan policy.DecisionPlan,
	endpointProtocol string,
) (validatedExecutionPlan, error) {
	if len(plan.Candidates) == 0 || len(plan.Candidates) > 32 {
		return validatedExecutionPlan{}, policy.ErrConfiguration
	}
	validatedPlan := validatedExecutionPlan{
		candidates: make([]validatedExecutionCandidate, 0, len(plan.Candidates)),
	}
	var primaryValidation validatedDecision
	seenRoutes := make(map[string]struct{}, len(plan.Candidates))
	for index, candidate := range plan.Candidates {
		decision := policy.Decision{
			Feature: plan.Feature, LimitPlan: plan.LimitPlan,
			Route: candidate.Route, Model: candidate.Model, Upstream: candidate.Upstream,
		}
		validated, err := validateDecision(featureID, decision, endpointProtocol)
		if err != nil {
			return validatedExecutionPlan{}, err
		}
		if _, duplicate := seenRoutes[decision.Route.ID]; duplicate {
			return validatedExecutionPlan{}, policy.ErrConfiguration
		}
		seenRoutes[decision.Route.ID] = struct{}{}
		if index == 0 {
			primaryValidation = validated
		} else if !reflect.DeepEqual(primaryValidation, validated) {
			return validatedExecutionPlan{}, policy.ErrConfiguration
		}
		validatedPlan.candidates = append(validatedPlan.candidates, validatedExecutionCandidate{
			decision: decision, validated: validated,
		})
	}
	return validatedPlan, nil
}

// validateFeatureLimitPlan is the shared capability gate for protected
// request enforcement and the public quota projection. It intentionally does
// not accept route, model, or upstream state: callers that need physical
// dispatch must validate those separately before using the returned rules.
func validateFeatureLimitPlan(
	featureID string,
	feature configuration.Feature,
	limitPlan configuration.LimitPlan,
) (validatedDecision, error) {
	requiresOutput := protocolUsesOutputTokens(feature.Protocol)
	if feature.ID != featureID || !protocol.ProtocolExecutable(feature.Protocol) ||
		!validFeatureProtocolPolicy(feature) ||
		(requiresOutput && (feature.Output == nil || feature.Output.DefaultMaximumTokens <= 0 ||
			feature.Output.AbsoluteMaximumTokens <= 0 ||
			feature.Output.DefaultMaximumTokens > feature.Output.AbsoluteMaximumTokens)) ||
		(!requiresOutput && feature.Output != nil) ||
		limitPlan.ID == "" || len(limitPlan.Limits) == 0 ||
		len(limitPlan.Limits) > maximumDecisionLimitRules {
		return validatedDecision{}, policy.ErrConfiguration
	}
	rules := make([]quota.Rule, 0, len(limitPlan.Limits))
	seenIdentities := make(map[decisionLimitIdentity]struct{}, len(limitPlan.Limits))
	effectiveMaximum := int64(0)
	if requiresOutput {
		effectiveMaximum = feature.Output.AbsoluteMaximumTokens
	}
	for _, limit := range limitPlan.Limits {
		scope, ok := canonicalDecisionScope(limit.Scope)
		timezone := ""
		if limit.Algorithm == quota.CalendarAlgorithm {
			var timezoneOK bool
			timezone, timezoneOK = canonicalDecisionCalendarTimezone(limit.Timezone)
			ok = ok && timezoneOK
		} else if limit.Timezone != "" {
			ok = false
		}
		if !limit.Hard || !ok || !supportedDecisionLimit(limit) ||
			!protocolSupportsLimitMetric(feature.Protocol, limit.Metric) {
			return validatedDecision{}, errUnsupportedLimitPlan
		}
		identity := decisionLimitIdentity{
			metric: limit.Metric, algorithm: limit.Algorithm,
			window: limit.Window, timezone: timezone, scope: strings.Join(scope, "\x00"),
		}
		if _, duplicate := seenIdentities[identity]; duplicate {
			return validatedDecision{}, errUnsupportedLimitPlan
		}
		seenIdentities[identity] = struct{}{}
		rules = append(rules, quota.Rule{
			Metric: limit.Metric, Algorithm: limit.Algorithm, Scope: scope,
			Window: limit.Window, Timezone: timezone, Maximum: limit.Maximum,
			PerRequestMaximum: limit.PerRequestMaximum, Capacity: limit.Capacity,
			RefillNumerator:   limit.RefillPerSecond.Numerator,
			RefillDenominator: limit.RefillPerSecond.Denominator, Hard: limit.Hard,
		})
		if limit.Metric == quota.OutputTokensMetric {
			switch limit.Algorithm {
			case quota.PerRequestAlgorithm:
				effectiveMaximum = min(effectiveMaximum, limit.PerRequestMaximum)
			case quota.TokenBucketAlgorithm:
				effectiveMaximum = min(effectiveMaximum, limit.Capacity)
			}
		}
	}
	effectiveDefault := int64(0)
	if requiresOutput {
		effectiveDefault = min(feature.Output.DefaultMaximumTokens, effectiveMaximum)
	}
	return validatedDecision{
		rules: rules, defaultOutputTokens: effectiveDefault, maximumOutputTokens: effectiveMaximum,
	}, nil
}

func validFeatureProtocolPolicy(feature configuration.Feature) bool {
	if feature.Protocol != protocol.OpaqueHTTPID {
		return feature.OpaqueHTTP == nil
	}
	policy := feature.OpaqueHTTP
	if policy == nil || len(policy.AllowedMethods) == 0 || len(policy.AllowedMethods) > 5 ||
		len(policy.PathPrefixes) == 0 || len(policy.PathPrefixes) > 32 ||
		policy.MaximumBodyBytes < 0 || policy.MaximumBodyBytes > maximumRequestBodyLimit ||
		len(policy.AllowedRequestHeaders) > 32 {
		return false
	}
	seenMethods := make(map[string]struct{}, len(policy.AllowedMethods))
	for _, method := range policy.AllowedMethods {
		if !slices.Contains([]string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		}, method) {
			return false
		}
		if _, duplicate := seenMethods[method]; duplicate {
			return false
		}
		seenMethods[method] = struct{}{}
	}
	seenPrefixes := make(map[string]struct{}, len(policy.PathPrefixes))
	for _, prefix := range policy.PathPrefixes {
		if len(prefix) > 512 || strings.ContainsAny(prefix, "%?#") ||
			(prefix != "/" && !validOpaquePublicPath(prefix)) {
			return false
		}
		if _, duplicate := seenPrefixes[prefix]; duplicate {
			return false
		}
		seenPrefixes[prefix] = struct{}{}
	}
	seenHeaders := make(map[string]struct{}, len(policy.AllowedRequestHeaders))
	for _, name := range policy.AllowedRequestHeaders {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "Anthropic-Version" {
			return false
		}
		if _, duplicate := seenHeaders[canonical]; duplicate {
			return false
		}
		seenHeaders[canonical] = struct{}{}
	}
	_, err := upstream.ForwardHeaders(make(http.Header), policy.AllowedRequestHeaders)
	return err == nil
}

func validRouteProtocolPolicy(protocolID string, route configuration.Route) bool {
	if protocolID == protocol.OpaqueHTTPID {
		return route.MaximumResponseBytes > 0 && route.MaximumResponseBytes <= maximumResponseBodyLimit
	}
	return route.MaximumResponseBytes == 0 && !route.StreamingAllowed && !route.RetryUnsafeMethods
}

func protocolUsesOutputTokens(protocolID string) bool {
	return slices.Contains([]string{
		protocol.OpenAIResponsesID, protocol.OpenAIChatID, protocol.AnthropicMessagesID,
	}, protocolID)
}

func protocolSupportsLimitMetric(protocolID, metric string) bool {
	switch metric {
	case quota.InputTokensMetric, quota.TotalTokensMetric:
		return protocolSupportsTrustedInputPreflight(protocolID)
	case quota.OutputTokensMetric, quota.ConcurrentStreamsMetric:
		return protocolUsesOutputTokens(protocolID)
	default:
		return true
	}
}

func protocolSupportsTrustedInputPreflight(protocolID string) bool {
	switch protocolID {
	case protocol.OpenAIResponsesID, protocol.OpenAIChatID,
		protocol.OpenAIEmbeddingsID, protocol.AnthropicMessagesID:
		return true
	default:
		return false
	}
}

func supportedDecisionLimit(limit configuration.Limit) bool {
	noRefill := limit.RefillPerSecond == (configuration.RefillRate{})
	_, validTimezone := canonicalDecisionCalendarTimezone(limit.Timezone)
	switch {
	case limit.Metric == quota.LogicalRequestsMetric && limit.Algorithm == quota.CalendarAlgorithm:
		return validDecisionWindow(limit.Window) && validTimezone && limit.Maximum > 0 &&
			limit.PerRequestMaximum == 0 && limit.Capacity == 0 && noRefill
	case (limit.Metric == quota.LogicalRequestsMetric || limit.Metric == quota.InputTokensMetric ||
		limit.Metric == quota.OutputTokensMetric || limit.Metric == quota.TotalTokensMetric) &&
		limit.Algorithm == quota.TokenBucketAlgorithm:
		return limit.Window == "" && limit.Timezone == "" && limit.Maximum == 0 && limit.PerRequestMaximum == 0 &&
			limit.Capacity > 0 && limit.Capacity <= maximumDecisionTokenBucketCapacity &&
			validDecisionTokenBucketRefill(limit.RefillPerSecond)
	case (limit.Metric == quota.InputTokensMetric || limit.Metric == quota.OutputTokensMetric ||
		limit.Metric == quota.TotalTokensMetric) && limit.Algorithm == quota.CalendarAlgorithm:
		return validDecisionWindow(limit.Window) && validTimezone && limit.Maximum > 0 &&
			limit.PerRequestMaximum == 0 && limit.Capacity == 0 && noRefill
	case limit.Metric == quota.CostNanoUSDMetric && limit.Algorithm == quota.CalendarAlgorithm:
		return validDecisionWindow(limit.Window) && validTimezone && limit.Maximum > 0 &&
			limit.PerRequestMaximum == 0 && limit.Capacity == 0 && noRefill
	case (limit.Metric == quota.InputTokensMetric || limit.Metric == quota.OutputTokensMetric ||
		limit.Metric == quota.TotalTokensMetric) && limit.Algorithm == quota.PerRequestAlgorithm:
		return limit.Window == "" && limit.Timezone == "" && limit.Maximum == 0 && limit.PerRequestMaximum > 0 &&
			limit.Capacity == 0 && noRefill
	case (limit.Metric == quota.ConcurrentRequestsMetric || limit.Metric == quota.ConcurrentStreamsMetric) &&
		limit.Algorithm == quota.ConcurrencyAlgorithm:
		return limit.Window == "" && limit.Timezone == "" && limit.Maximum > 0 && limit.PerRequestMaximum == 0 &&
			limit.Capacity == 0 && noRefill
	default:
		return false
	}
}

func validDecisionTokenBucketRefill(rate configuration.RefillRate) bool {
	// Valid denominators divide one million, so this exact rational comparison
	// cannot overflow: maximum * denominator is at most one trillion.
	return rate.Valid() &&
		rate.Numerator <= maximumDecisionTokenBucketRefillPerSecond*rate.Denominator
}

type decisionLimitIdentity struct {
	metric    string
	algorithm string
	window    string
	timezone  string
	scope     string
}

func canonicalDecisionScope(input []string) ([]string, bool) {
	if len(input) == 0 || len(input) > len(decisionScopeOrder) {
		return nil, false
	}
	seen := make(map[string]struct{}, len(input))
	for _, dimension := range input {
		if !slices.Contains(decisionScopeOrder, dimension) {
			return nil, false
		}
		if _, duplicate := seen[dimension]; duplicate {
			return nil, false
		}
		seen[dimension] = struct{}{}
	}
	result := make([]string, 0, len(input))
	for _, dimension := range decisionScopeOrder {
		if _, ok := seen[dimension]; ok {
			result = append(result, dimension)
		}
	}
	return result, true
}

func validDecisionWindow(raw string) bool {
	matches := decisionWindowPattern.FindStringSubmatch(raw)
	if len(matches) != 3 {
		return false
	}
	amount, err := strconv.ParseInt(matches[1], 10, 64)
	maximum, ok := decisionWindowMaximum[matches[2]]
	return err == nil && ok && amount > 0 && amount <= maximum
}

func canonicalDecisionCalendarTimezone(raw string) (string, bool) {
	if raw == "" || raw == "UTC" {
		return "UTC", true
	}
	if raw == "Local" || len(raw) > maximumDecisionCalendarTimezoneLength ||
		!decisionTimezonePattern.MatchString(raw) {
		return "", false
	}
	location, err := time.LoadLocation(raw)
	return raw, err == nil && location.String() == raw
}

func (handler *Handler) startStage(ctx context.Context, stage string, labels telemetry.Labels) (context.Context, func(string)) {
	if handler == nil || handler.telemetry == nil {
		return ctx, func(string) {}
	}
	return handler.telemetry.StartStage(ctx, stage, labels)
}

func (handler *Handler) telemetryOutcome(err error) string {
	if err == nil {
		return "succeeded"
	}
	code, _ := errorCode(err, handler.now().UTC())
	switch code {
	case "server_not_ready", "upstream_unavailable", "upstream_timeout", "upstream_protocol_error", "pricing_unavailable":
		return "failed"
	default:
		return "denied"
	}
}

func attemptTelemetryLabels(decision policy.Decision) telemetry.Labels {
	return telemetry.Labels{
		Feature: decision.Feature.ID, Route: decision.Route.ID, Upstream: decision.Upstream.ID,
		ModelAlias: decision.Model.ID, Plan: decision.LimitPlan.ID,
	}
}

func (handler *Handler) recordAttempt(
	ctx context.Context,
	authorization session.Authorization,
	decision policy.Decision,
	result executionResult,
	outcome quota.Outcome,
	condition string,
) {
	if handler == nil || handler.telemetry == nil || !result.beginInvoked || !result.dispatchOwner {
		return
	}
	labels := attemptTelemetryLabels(decision)
	labels.Application = authorization.ApplicationID
	labels.Environment = authorization.EnvironmentID
	labels.Platform = authorization.InstallationPlatform
	labels.AttestationLevel = authorization.TrustLevel
	inputTokens, outputTokens, costNanoUSD := int64(-1), int64(-1), int64(-1)
	if outcome.Usage.Known {
		inputTokens, outputTokens = outcome.Usage.InputTokens, outcome.Usage.OutputTokens
	}
	if outcome.Cost.Known {
		costNanoUSD = outcome.Cost.NanoUSD
	}
	firstToken := time.Duration(-1)
	if !result.startedAt.IsZero() && !result.firstByteAt.IsZero() && !result.firstByteAt.Before(result.startedAt) {
		firstToken = result.firstByteAt.Sub(result.startedAt)
	}
	if condition == "" {
		condition = telemetry.RouteAttemptConditionNone
	}
	handler.telemetry.RecordUpstreamAttempt(ctx, labels, telemetry.RouteAttemptObservation{
		Condition: condition, Outcome: outcome.Status,
		CircuitState: telemetry.CircuitObservationNotConfigured,
	}, inputTokens, outputTokens, costNanoUSD, firstToken)
}

func isDPoPFailure(err error) bool {
	return dpop.IsCode(err, "dpop_nonce_required") || dpop.IsCode(err, "dpop_invalid") ||
		errors.Is(err, session.ErrDPoPReplayed) || errors.Is(err, session.ErrReplayInvalid)
}

func (handler *Handler) releaseReservation(parent context.Context, reservation quota.Reservation, failure string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), handler.persistenceTimeout)
	defer cancel()
	ctx, finish := handler.startStage(ctx, "quota settlement", telemetry.Labels{})
	err := handler.quotas.ReleaseBeforeDispatch(ctx, reservation, failure)
	finish(handler.telemetryOutcome(err))
	return err
}

func (handler *Handler) settleForRetry(parent context.Context, attempt quota.Attempt, outcome quota.Outcome) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), handler.persistenceTimeout)
	defer cancel()
	ctx, finish := handler.startStage(ctx, "quota settlement", telemetry.Labels{Outcome: outcome.Status})
	err := handler.quotas.SettleForRetry(ctx, attempt, outcome)
	finish(handler.telemetryOutcome(err))
	return err
}

func (handler *Handler) settleFinalAttempt(parent context.Context, attempt quota.Attempt, outcome quota.Outcome) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), handler.persistenceTimeout)
	defer cancel()
	ctx, finish := handler.startStage(ctx, "quota settlement", telemetry.Labels{Outcome: outcome.Status})
	err := handler.quotas.SettleFinalAttempt(ctx, attempt, outcome)
	finish(handler.telemetryOutcome(err))
	return err
}

func quotaOutcome(relay upstream.RelayOutcome, cost quota.Cost, executionErr error) quota.Outcome {
	httpStatus := relay.StatusCode
	if httpStatus < 100 || httpStatus > 599 {
		httpStatus = 0
	}
	usage := quota.Usage{
		InputTokens: relay.Usage.InputTokens, OutputTokens: relay.Usage.OutputTokens,
		TotalTokens: relay.Usage.TotalTokens, Known: relay.Usage.Known,
		Provenance: relay.Usage.Provenance,
	}
	if !usage.Known && usage.Provenance == "" {
		usage.Provenance = quota.UnknownUsageProvenance
	}
	if executionErr == nil && httpStatus >= http.StatusOK && httpStatus < http.StatusMultipleChoices {
		return quota.Outcome{Status: quota.AttemptSucceeded, HTTPStatus: httpStatus, Usage: usage, Cost: cost}
	}
	status := quota.AttemptFailed
	code := failureCode(executionErr)
	switch {
	case errors.Is(executionErr, context.Canceled):
		status = quota.AttemptCancelled
		code = "client_cancelled"
	case isUpstreamTimeout(executionErr):
		status = quota.AttemptTimedOut
		code = "upstream_timeout"
	}
	return quota.Outcome{Status: status, HTTPStatus: httpStatus, FailureCode: code, Usage: usage, Cost: cost}
}

func failureCode(err error) string {
	switch {
	case isUpstreamTimeout(err):
		return "upstream_timeout"
	case errors.Is(err, context.Canceled):
		return "client_cancelled"
	case errors.Is(err, upstream.ErrInvalidResponseRelay),
		errors.Is(err, upstream.ErrResponseBodyTooLarge),
		errors.Is(err, errUpstreamProtocol),
		errors.Is(err, errDispatchNotConsumed):
		return "upstream_protocol_error"
	case errors.Is(err, upstream.ErrUpstreamNonSuccess):
		return "upstream_non_success"
	case errors.Is(err, errPricingUnavailable):
		return "pricing_unavailable"
	case errors.Is(err, quota.ErrDependency), errors.Is(err, quota.ErrInvalidState):
		return "quota_state_unavailable"
	case errors.Is(err, policy.ErrConfiguration), errors.Is(err, quota.ErrInvalidInput),
		errors.Is(err, errInvalidConfiguration), errors.Is(err, errUnsupportedLimitPlan),
		errors.Is(err, errTargetConfiguration):
		return "configuration_invalid"
	default:
		return "upstream_unavailable"
	}
}

func (handler *Handler) writeViolation(writer http.ResponseWriter, requestID string, value *violation) {
	if value == nil {
		writeProblem(writer, requestID, "internal_error", "", 0)
		return
	}
	if value.allowValue != "" {
		writer.Header().Set("Allow", value.allowValue)
	}
	problem.Write(writer, requestID, problem.Error{
		Code: value.code, Detail: value.detail, Fields: value.fields,
		SupportedProtocolVersions: append([]int(nil), value.supported...),
	})
}

func (handler *Handler) writeMappedError(writer http.ResponseWriter, requestID, feature string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	code, retryAfter := errorCode(err, handler.now())
	writeProblem(writer, requestID, code, feature, retryAfter)
}

func errorCode(err error, now time.Time) (string, int) {
	var protocolError *protocol.Error
	var exceeded interface{ RetryAt() time.Time }
	switch {
	case errors.As(err, &protocolError):
		if protocolError.Code == "request_invalid" || protocolError.Code == "upstream_protocol_error" {
			return protocolError.Code, 0
		}
		return "internal_error", 0
	case dpop.IsCode(err, "dpop_nonce_required"):
		return "dpop_nonce_required", 0
	case dpop.IsCode(err, "dpop_invalid"):
		return "dpop_invalid", 0
	case errors.Is(err, session.ErrDPoPReplayed):
		return "dpop_replayed", 0
	case errors.Is(err, session.ErrReplayInvalid):
		return "dpop_invalid", 0
	case errors.Is(err, session.ErrTokenInvalid), errors.Is(err, session.ErrTokenExpired):
		return "session_expired", 0
	case errors.Is(err, session.ErrInstallationRevoked):
		return "installation_revoked", 0
	case errors.Is(err, session.ErrAttestationRefreshNeeded):
		return "attestation_stale", 0
	case errors.Is(err, session.ErrAttestationStepUpRequired):
		return "attestation_step_up_required", 0
	case errors.Is(err, session.ErrSessionRevoked), errors.Is(err, session.ErrSessionScope),
		errors.Is(err, session.ErrSessionInvalid):
		return "session_revoked", 0
	case errors.Is(err, session.ErrSigningKeyUnavailable):
		return "server_not_ready", 0
	case errors.Is(err, policy.ErrFeatureNotFound):
		return "feature_not_found", 0
	case errors.Is(err, policy.ErrFeatureNotAllowed):
		return "feature_not_allowed", 0
	case errors.Is(err, policy.ErrRouteNotFound):
		return "route_not_found", 0
	case errors.Is(err, policy.ErrConfiguration), errors.Is(err, policy.ErrInvalidInput),
		errors.Is(err, policy.ErrLimitPlanNotFound),
		errors.Is(err, errUnsupportedLimitPlan), errors.Is(err, errTargetConfiguration),
		errors.Is(err, quota.ErrInvalidInput):
		return "configuration_invalid", 0
	case errors.Is(err, quota.ErrConcurrencyExceeded):
		return "concurrency_exceeded", 0
	case errors.Is(err, quota.ErrExceeded):
		if errors.As(err, &exceeded) {
			return "quota_exceeded", quotaRetryAfterSeconds(exceeded.RetryAt(), now)
		}
		return "quota_exceeded", 0
	case errors.Is(err, quota.ErrDependency), errors.Is(err, quota.ErrInvalidState),
		errors.Is(err, quota.ErrNotFound), errors.Is(err, quota.ErrExpired),
		errors.Is(err, quota.ErrFinalized), errors.Is(err, configuration.ErrInvalid),
		errors.Is(err, configuration.ErrNotFound), errors.Is(err, secrets.ErrInvalid):
		return "server_not_ready", 0
	case errors.Is(err, secrets.ErrUnavailable):
		return "upstream_unavailable", 0
	case isUpstreamTimeout(err):
		return "upstream_timeout", 0
	case errors.Is(err, upstream.ErrInvalidResponseRelay), errors.Is(err, upstream.ErrResponseBodyTooLarge):
		return "upstream_protocol_error", 0
	case errors.Is(err, errUpstreamProtocol), errors.Is(err, errDispatchNotConsumed):
		return "upstream_protocol_error", 0
	case errors.Is(err, upstream.ErrUpstreamNonSuccess):
		return "upstream_unavailable", 0
	case errors.Is(err, errPricingUnavailable):
		return "pricing_unavailable", 0
	case errors.Is(err, errUpstreamDispatch), errors.Is(err, errUpstreamRelay):
		return "upstream_unavailable", 0
	case errors.Is(err, errDispatchNotOwned):
		return "conflict", 0
	default:
		return "server_not_ready", 0
	}
}

func quotaRetryAfterSeconds(retryAt, now time.Time) int {
	now = now.UTC()
	if !retryAt.After(now) {
		return 1
	}
	maximumDelay := time.Duration(maximumQuotaRetryAfterSeconds) * time.Second
	if !retryAt.Before(now.Add(maximumDelay)) {
		return maximumQuotaRetryAfterSeconds
	}
	delay := retryAt.Sub(now)
	seconds := delay / time.Second
	if delay%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return int(seconds)
}

func writeProblem(writer http.ResponseWriter, requestID, code, feature string, retryAfter int) {
	if !problemIncludesFeature(code) {
		feature = ""
	}
	problem.Write(writer, requestID, problem.Error{
		Code: code, Detail: safeProblemDetail(code), Feature: feature, RetryAfterSeconds: retryAfter,
	})
}

func problemIncludesFeature(code string) bool {
	switch code {
	case "feature_not_found", "feature_not_allowed", "quota_exceeded", "concurrency_exceeded", "route_not_found",
		"pricing_unavailable", "upstream_unavailable", "upstream_timeout", "upstream_protocol_error":
		return true
	default:
		return false
	}
}

func safeProblemDetail(code string) string {
	switch code {
	case "request_invalid":
		return "The request does not match the Latchway client protocol."
	case "dpop_missing":
		return "Exactly one DPoP proof is required."
	case "dpop_invalid":
		return "The DPoP proof could not be verified for this request."
	case "dpop_replayed":
		return "The DPoP proof has already been used."
	case "dpop_nonce_required":
		return "A fresh server DPoP nonce is required."
	case "session_expired":
		return "The Latchway session is expired."
	case "session_revoked":
		return "The Latchway session is no longer active."
	case "installation_revoked":
		return "The installation is no longer active."
	case "attestation_stale":
		return "Fresh application attestation is required."
	case "attestation_step_up_required":
		return "Stronger application attestation is required."
	case "feature_not_found":
		return "The requested application feature is not configured."
	case "feature_not_allowed":
		return "The current principal is not allowed to use this feature."
	case "quota_exceeded":
		return "The configured logical request quota has been reached."
	case "concurrency_exceeded":
		return "The configured concurrency limit has been reached."
	case "route_not_found":
		return "No configured upstream route is available."
	case "pricing_unavailable":
		return "The configured price for the selected model is not available."
	case "upstream_timeout":
		return "The upstream request exceeded its configured time limit."
	case "upstream_protocol_error":
		return "The upstream response did not satisfy the configured protocol."
	case "upstream_unavailable":
		return "The selected upstream is unavailable."
	case "configuration_invalid":
		return "The active data-plane configuration cannot be enforced."
	case "server_not_ready":
		return "The gateway is not ready to process protected requests."
	case "conflict":
		return "The logical request is already being processed."
	default:
		return "The protected request could not be completed."
	}
}

func selectCorrelationID(request *http.Request) string {
	if request == nil {
		return "request_unknown"
	}
	if current := middleware.GetReqID(request.Context()); validRequestID(current) {
		return current
	}
	if candidate := validClientRequestHint(request.Header); candidate != "" {
		return candidate
	}
	if logicalID, ok := requestidentity.FromContext(request.Context()); ok {
		return logicalID.String()
	}
	return "request_unknown"
}

func validRequestID(value string) bool {
	return len(value) >= 8 && len(value) <= 128 && requestHintPattern.MatchString(value)
}

func cloneURL(value url.URL) *url.URL {
	copy := value
	return &copy
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
