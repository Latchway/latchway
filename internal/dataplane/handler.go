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
	"github.com/latchway/latchway/internal/upstream"
)

const (
	defaultMaximumResponseBody = int64(32 << 20)
	maximumRequestBodyLimit    = int64(100 << 20)
	maximumResponseBodyLimit   = int64(100 << 20)
	defaultClientWriteTimeout  = 30 * time.Second
	defaultPersistenceTimeout  = 5 * time.Second
	maximumDecisionLimitRules  = 128
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
	decisionWindowPattern   = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d|mo)$`)
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
	Adapter  protocol.Adapter
	Adapters []protocol.Adapter
	Targets  TargetFactory
	Relayer  ResponseRelayer

	PublicOrigin             string
	MaximumRequestBodyBytes  int64
	MaximumResponseBodyBytes int64
	ClientWriteTimeout       time.Duration
	PersistenceTimeout       time.Duration
	Now                      func() time.Time
}

// Handler serves the bounded protected structured-protocol endpoint registry.
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

	maximumResponseBody int64
	clientWriteTimeout  time.Duration
	persistenceTimeout  time.Duration
	now                 func() time.Time
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
		targets: config.Targets, relayer: config.Relayer,
		maximumResponseBody: config.MaximumResponseBodyBytes,
		clientWriteTimeout:  config.ClientWriteTimeout, persistenceTimeout: config.PersistenceTimeout,
		now: config.Now, ownedTargets: ownedTargets,
	}, nil
}

func defaultProtocolAdapters(maximumBodyBytes int64) []protocol.Adapter {
	return []protocol.Adapter{
		openairesponses.Adapter{MaximumBodyBytes: maximumBodyBytes},
		openaichat.Adapter{MaximumBodyBytes: maximumBodyBytes},
		openaiembeddings.Adapter{MaximumBodyBytes: maximumBodyBytes},
		anthropicmessages.Adapter{MaximumBodyBytes: maximumBodyBytes},
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

	principal, err := handler.accessTokens.Verify(request.Context(), declaration.accessToken)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	authorization, err := handler.sessions.AuthorizeAccess(request.Context(), session.AccessRequestInput{
		AccessToken: declaration.accessToken,
		Principal:   principal,
		DPoPProof:   declaration.dpopProof,
		HTTPMethod:  endpoint.publicMethod,
		RequestURI:  cloneURL(endpoint.publicURL),
	})
	if err != nil {
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
	plan, err := handler.policies.ResolvePlan(
		request.Context(), snapshot, declaration.feature, authorization, logicalID, metadata,
	)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	decision, validated, err := validateDecisionPlan(declaration.feature, plan, endpoint.protocolID)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	prepared, err := handler.prepareExecutionAttempt(
		request.Context(), replay, endpoint.adapter, snapshot, decision, validated,
	)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}

	reservation, err := handler.quotas.Reserve(request.Context(), quota.ReserveInput{
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
		Streaming:      metadata.Streaming, Rules: validated.rules,
	})
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}

	result := handler.executeReserved(
		prepared.request.Context(), writer, prepared.request, endpoint, authorization,
		prepared.decision, reservation, prepared.inputPreflight,
	)
	if !result.beginInvoked {
		if result.err == nil {
			result.err = errDispatchNotConsumed
		}
		if releaseErr := handler.releaseReservation(reservation, failureCode(result.err)); releaseErr != nil {
			result.err = releaseErr
		}
		handler.writeMappedError(writer, requestID, declaration.feature, result.err)
		return
	}
	if result.err != nil && !result.dispatchOwner {
		handler.writeMappedError(writer, requestID, declaration.feature, result.err)
		return
	}
	if !result.dispatchOwner {
		handler.writeMappedError(writer, requestID, declaration.feature, errDispatchNotOwned)
		return
	}
	if result.err == nil && !result.relay.ClientStarted {
		result.err = errDispatchNotConsumed
	}
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
		// passing an impossible output measurement that would leave the durable
		// reservation pending.
		result.relay.Usage = protocol.Usage{}
	}
	var calculatedCost quota.Cost
	if !providerUsageOverBound {
		calculatedCost, result.err = calculateConfiguredCost(prepared.pricing, result.relay.Usage, result.err)
	}
	calculatedCost = boundedSettlementCost(calculatedCost, prepared.hardCost)

	settlementErr := handler.settleAttempt(result.attempt, result.relay, calculatedCost, result.err)
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
	// A successful bounded relay always commits provider response headers, even
	// for an empty response body. Reaching this point means the relayer violated
	// its contract and must not be treated as a successful attempt.
	handler.writeMappedError(writer, requestID, declaration.feature, errDispatchNotConsumed)
}

type executionResult struct {
	attempt       quota.Attempt
	relay         upstream.RelayOutcome
	err           error
	beginInvoked  bool
	dispatchOwner bool
}

type preparedExecutionAttempt struct {
	request              *http.Request
	decision             policy.Decision
	pricing              configuredPricing
	appliedOutputMaximum int64
	inputPreflight       *protocol.TrustedInputPreflight
	hardCost             hardCostReservation
}

func (handler *Handler) prepareExecutionAttempt(
	ctx context.Context,
	replay replayableRequest,
	adapter protocol.Adapter,
	snapshot configuration.ActiveSnapshot,
	decision policy.Decision,
	validated validatedDecision,
) (preparedExecutionAttempt, error) {
	if ctx == nil || nilDependency(adapter) {
		return preparedExecutionAttempt{}, errInvalidConfiguration
	}
	selectedPricing, err := resolveConfiguredPricing(snapshot, decision.Model, handler.now())
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	attemptRequest, err := replay.New(ctx)
	if err != nil {
		return preparedExecutionAttempt{}, err
	}
	appliedOutputMaximum, err := adapter.ApplyFeature(attemptRequest.Context(), attemptRequest, protocol.FeatureDecision{
		PhysicalModel:       decision.Model.UpstreamModel,
		DefaultOutputTokens: validated.defaultOutputTokens,
		MaximumOutputTokens: validated.maximumOutputTokens,
	})
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
		request: attemptRequest, decision: decision, pricing: selectedPricing,
		appliedOutputMaximum: appliedOutputMaximum, inputPreflight: inputPreflight,
		hardCost: hardCost,
	}, nil
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
	if !validTargetTimeouts(decision.Upstream.Timeouts) {
		return executionResult{err: errTargetConfiguration}
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
		incoming, endpoint.providerPath, protocolForwardedHeaders(endpoint.protocolID), decision.Upstream.StaticHeaders,
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
		return handler.dispatchReserved(executionContext, writer, endpoint.adapter, decision, reservation, dispatch)
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
			result = handler.dispatchReserved(
				executionContext, writer, endpoint.adapter, decision, reservation, credentialDispatch,
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

func protocolForwardedHeaders(protocolID string) []string {
	if protocolID == protocol.AnthropicMessagesID {
		return []string{"Content-Type", "Anthropic-Version"}
	}
	return []string{"Content-Type"}
}

func (handler *Handler) dispatchReserved(
	ctx context.Context,
	writer http.ResponseWriter,
	adapter protocol.Adapter,
	decision policy.Decision,
	reservation quota.Reservation,
	dispatch func(func() error, func(*upstream.DispatchedResponse) error) error,
) executionResult {
	result := executionResult{}
	beforeRoundTrip := func() error {
		if result.beginInvoked {
			result.err = errDispatchNotConsumed
			return result.err
		}
		result.beginInvoked = true
		attempt, owner, err := handler.quotas.BeginAttempt(ctx, reservation)
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
		result.relay, result.err = handler.consumeResponse(
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
) (upstream.RelayOutcome, error) {
	if response == nil || response.Response == nil {
		return upstream.RelayOutcome{}, errDispatchNotConsumed
	}
	defer response.Close()
	if nilDependency(adapter) {
		return upstream.RelayOutcome{StatusCode: response.StatusCode}, errInvalidConfiguration
	}
	observer, err := adapter.ObserveResponse(ctx, response.Response)
	if err != nil {
		return upstream.RelayOutcome{StatusCode: response.StatusCode}, fmt.Errorf("%w: %w", errUpstreamProtocol, err)
	}
	outcome, err := handler.relayer.Relay(ctx, writer, response, observer, upstream.ResponseRelayConfig{
		IdleTimeout:        decision.Upstream.Timeouts.Idle,
		ClientWriteTimeout: handler.clientWriteTimeout,
		MaxBodyBytes:       handler.maximumResponseBody,
		OnFirstByte: func(firstByteContext context.Context) error {
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
	if err != nil {
		return outcome, fmt.Errorf("%w: %w", errUpstreamRelay, err)
	}
	return outcome, nil
}

type validatedDecision struct {
	rules               []quota.Rule
	defaultOutputTokens int64
	maximumOutputTokens int64
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
	if !ok {
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
		len(decision.Route.FallbackOn) != 0 || decision.Model.ID == "" ||
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
) (policy.Decision, validatedDecision, error) {
	if len(plan.Candidates) == 0 || len(plan.Candidates) > 32 {
		return policy.Decision{}, validatedDecision{}, policy.ErrConfiguration
	}
	var primary policy.Decision
	var primaryValidation validatedDecision
	for index, candidate := range plan.Candidates {
		decision := policy.Decision{
			Feature: plan.Feature, LimitPlan: plan.LimitPlan,
			Route: candidate.Route, Model: candidate.Model, Upstream: candidate.Upstream,
		}
		validated, err := validateDecision(featureID, decision, endpointProtocol)
		if err != nil {
			return policy.Decision{}, validatedDecision{}, err
		}
		if index == 0 {
			primary = decision
			primaryValidation = validated
			continue
		}
		if !reflect.DeepEqual(primaryValidation, validated) {
			return policy.Decision{}, validatedDecision{}, policy.ErrConfiguration
		}
	}
	return primary, primaryValidation, nil
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
		feature.OpaqueHTTP != nil ||
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
		if !limit.Hard || !ok || !supportedDecisionLimit(limit) ||
			!protocolSupportsLimitMetric(feature.Protocol, limit.Metric) {
			return validatedDecision{}, errUnsupportedLimitPlan
		}
		identity := decisionLimitIdentity{
			metric: limit.Metric, algorithm: limit.Algorithm,
			window: limit.Window, scope: strings.Join(scope, "\x00"),
		}
		if _, duplicate := seenIdentities[identity]; duplicate {
			return validatedDecision{}, errUnsupportedLimitPlan
		}
		seenIdentities[identity] = struct{}{}
		rules = append(rules, quota.Rule{
			Metric: limit.Metric, Algorithm: limit.Algorithm, Scope: scope,
			Window: limit.Window, Maximum: limit.Maximum,
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

func protocolUsesOutputTokens(protocolID string) bool {
	return slices.Contains([]string{
		protocol.OpenAIResponsesID, protocol.OpenAIChatID, protocol.AnthropicMessagesID,
	}, protocolID)
}

func protocolSupportsLimitMetric(protocolID, metric string) bool {
	switch metric {
	case quota.InputTokensMetric, quota.TotalTokensMetric:
		return protocolID == protocol.OpenAIChatID
	case quota.OutputTokensMetric, quota.ConcurrentStreamsMetric:
		return protocolUsesOutputTokens(protocolID)
	default:
		return true
	}
}

func supportedDecisionLimit(limit configuration.Limit) bool {
	noRefill := limit.RefillPerSecond == (configuration.RefillRate{})
	switch {
	case limit.Metric == quota.LogicalRequestsMetric && limit.Algorithm == quota.CalendarAlgorithm:
		return validDecisionWindow(limit.Window) && limit.Maximum > 0 &&
			limit.PerRequestMaximum == 0 && limit.Capacity == 0 && noRefill
	case (limit.Metric == quota.LogicalRequestsMetric || limit.Metric == quota.OutputTokensMetric) &&
		limit.Algorithm == quota.TokenBucketAlgorithm:
		return limit.Window == "" && limit.Maximum == 0 && limit.PerRequestMaximum == 0 &&
			limit.Capacity > 0 && limit.Capacity <= maximumDecisionTokenBucketCapacity &&
			validDecisionTokenBucketRefill(limit.RefillPerSecond)
	case (limit.Metric == quota.InputTokensMetric || limit.Metric == quota.OutputTokensMetric ||
		limit.Metric == quota.TotalTokensMetric) && limit.Algorithm == quota.CalendarAlgorithm:
		return validDecisionWindow(limit.Window) && limit.Maximum > 0 &&
			limit.PerRequestMaximum == 0 && limit.Capacity == 0 && noRefill
	case limit.Metric == quota.CostNanoUSDMetric && limit.Algorithm == quota.CalendarAlgorithm:
		return validDecisionWindow(limit.Window) && limit.Maximum > 0 &&
			limit.PerRequestMaximum == 0 && limit.Capacity == 0 && noRefill
	case limit.Metric == quota.OutputTokensMetric && limit.Algorithm == quota.PerRequestAlgorithm:
		return limit.Window == "" && limit.Maximum == 0 && limit.PerRequestMaximum > 0 &&
			limit.Capacity == 0 && noRefill
	case (limit.Metric == quota.ConcurrentRequestsMetric || limit.Metric == quota.ConcurrentStreamsMetric) &&
		limit.Algorithm == quota.ConcurrencyAlgorithm:
		return limit.Window == "" && limit.Maximum > 0 && limit.PerRequestMaximum == 0 &&
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

func (handler *Handler) releaseReservation(reservation quota.Reservation, failure string) error {
	ctx, cancel := context.WithTimeout(context.Background(), handler.persistenceTimeout)
	defer cancel()
	return handler.quotas.ReleaseBeforeDispatch(ctx, reservation, failure)
}

func (handler *Handler) settleAttempt(
	attempt quota.Attempt,
	relay upstream.RelayOutcome,
	cost quota.Cost,
	executionErr error,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), handler.persistenceTimeout)
	defer cancel()
	return handler.quotas.Settle(ctx, attempt, quotaOutcome(relay, cost, executionErr))
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
	case errors.Is(executionErr, context.DeadlineExceeded), errors.Is(executionErr, upstream.ErrResponseIdleTimeout):
		status = quota.AttemptTimedOut
		code = "upstream_timeout"
	}
	return quota.Outcome{Status: status, HTTPStatus: httpStatus, FailureCode: code, Usage: usage, Cost: cost}
}

func failureCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, upstream.ErrResponseIdleTimeout):
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
	var exceeded *quota.ExceededError
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
	case errors.As(err, &exceeded):
		return "quota_exceeded", quotaRetryAfterSeconds(exceeded.RetryAt(), now)
	case errors.Is(err, quota.ErrDependency), errors.Is(err, quota.ErrInvalidState),
		errors.Is(err, quota.ErrNotFound), errors.Is(err, quota.ErrExpired),
		errors.Is(err, quota.ErrFinalized), errors.Is(err, configuration.ErrInvalid),
		errors.Is(err, configuration.ErrNotFound), errors.Is(err, secrets.ErrInvalid):
		return "server_not_ready", 0
	case errors.Is(err, secrets.ErrUnavailable):
		return "upstream_unavailable", 0
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, upstream.ErrResponseIdleTimeout):
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
