// Package dataplane composes authenticated client requests, immutable policy,
// quota lifecycle accounting, protected upstream dispatch, and bounded
// response relay. Opaque HTTP proxying is intentionally outside this package.
package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/policy"
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
)

var (
	errInvalidConfiguration = errors.New("invalid data-plane configuration")
	errUnsupportedLimitPlan = errors.New("unsupported data-plane limit plan")
	errDispatchNotOwned     = errors.New("logical request dispatch is already owned")
	errDispatchNotConsumed  = errors.New("upstream dispatch did not provide a response")
	errTargetConfiguration  = errors.New("invalid protected upstream target")
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
	Adapter       protocol.Adapter
	Targets       TargetFactory
	Relayer       ResponseRelayer

	PublicOrigin             string
	MaximumRequestBodyBytes  int64
	MaximumResponseBodyBytes int64
	ClientWriteTimeout       time.Duration
	PersistenceTimeout       time.Duration
	Now                      func() time.Time
}

// Handler serves only the authenticated OpenAI Chat Completions vertical
// slice. It must be mounted behind requestidentity middleware.
type Handler struct {
	accessTokens  AccessTokenVerifier
	sessions      SessionAuthorizer
	configuration SnapshotLoader
	policies      PolicyDecisionEngine
	quotas        QuotaStore
	secrets       SecretStore
	adapter       protocol.Adapter
	targets       TargetFactory
	relayer       ResponseRelayer

	publicRequestURL    url.URL
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
	if nilDependency(config.Adapter) {
		config.Adapter = openaichat.Adapter{MaximumBodyBytes: config.MaximumRequestBodyBytes}
	}
	if config.Adapter.ID() != openaichat.ID || !config.Adapter.Capabilities().Streaming ||
		!config.Adapter.Capabilities().ModelRewrite || !config.Adapter.Capabilities().OutputTokenClamp {
		return nil, errInvalidConfiguration
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
	publicRequestURL := url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: chatCompletionsPath}
	return &Handler{
		accessTokens: config.AccessTokens, sessions: config.Sessions,
		configuration: config.Configuration, policies: config.Policies,
		quotas: config.Quotas, secrets: config.Secrets, adapter: config.Adapter,
		targets: config.Targets, relayer: config.Relayer,
		publicRequestURL: publicRequestURL, maximumResponseBody: config.MaximumResponseBodyBytes,
		clientWriteTimeout: config.ClientWriteTimeout, persistenceTimeout: config.PersistenceTimeout,
		now: config.Now, ownedTargets: ownedTargets,
	}, nil
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
	if violation := validateEndpoint(request); violation != nil {
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
		HTTPMethod:  http.MethodPost,
		RequestURI:  cloneURL(handler.publicRequestURL),
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

	metadata, err := handler.adapter.InspectRequest(request.Context(), request)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	decision, err := handler.policies.Resolve(
		request.Context(), snapshot, declaration.feature, authorization, logicalID, metadata,
	)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	rules, err := validateDecision(declaration.feature, decision)
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}
	if err := handler.adapter.ApplyFeature(request.Context(), request, protocol.FeatureDecision{
		PhysicalModel:       decision.Model.UpstreamModel,
		DefaultOutputTokens: decision.Feature.Output.DefaultMaximumTokens,
		MaximumOutputTokens: decision.Feature.Output.AbsoluteMaximumTokens,
	}); err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}

	reservation, err := handler.quotas.Reserve(request.Context(), quota.ReserveInput{
		LogicalRequestID: logicalID,
		OrganizationID:   authorization.OrganizationID, ApplicationID: authorization.ApplicationID,
		EnvironmentID: authorization.EnvironmentID, ApplicationUserID: authorization.ApplicationUserID,
		InstallationID: authorization.InstallationID, SessionGrantID: authorization.SessionGrantID,
		ConfigRevisionID: snapshot.PolicyRevision(), FeatureKey: decision.Feature.ID,
		Protocol: decision.Feature.Protocol, ClientRequestID: declaration.clientRequestID,
		LimitPlanKey: decision.LimitPlan.ID, RouteKey: decision.Route.ID,
		UpstreamKey: decision.Upstream.ID, ModelKey: decision.Model.ID,
		PhysicalModel: decision.Model.UpstreamModel, Rules: rules,
	})
	if err != nil {
		handler.writeMappedError(writer, requestID, declaration.feature, err)
		return
	}

	result := handler.executeReserved(request.Context(), writer, request, authorization, decision, reservation)
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

	settlementErr := handler.settleAttempt(result.attempt, result.relay, result.err)
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

func (handler *Handler) executeReserved(
	ctx context.Context,
	writer http.ResponseWriter,
	incoming *http.Request,
	authorization session.Authorization,
	decision policy.Decision,
	reservation quota.Reservation,
) executionResult {
	if !validTargetTimeouts(decision.Upstream.Timeouts) {
		return executionResult{err: errTargetConfiguration}
	}
	executionContext, cancelExecution := context.WithTimeout(ctx, decision.Upstream.Timeouts.Total)
	defer cancelExecution()

	lease, err := handler.targets.Acquire(decision.Upstream)
	if err != nil || nilDependency(lease) {
		return executionResult{err: fmt.Errorf("%w: resolve target", errTargetConfiguration)}
	}
	defer lease.Release()
	prepared, err := lease.Prepare(
		incoming, providerChatPath, []string{"Content-Type"}, decision.Upstream.StaticHeaders,
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
		return handler.dispatchReserved(executionContext, writer, decision, reservation, dispatch)
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
			result = handler.dispatchReserved(executionContext, writer, decision, reservation, credentialDispatch)
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

func (handler *Handler) dispatchReserved(
	ctx context.Context,
	writer http.ResponseWriter,
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
		result.relay, result.err = handler.consumeResponse(ctx, writer, decision, result.attempt, response)
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
	decision policy.Decision,
	attempt quota.Attempt,
	response *upstream.DispatchedResponse,
) (upstream.RelayOutcome, error) {
	if response == nil || response.Response == nil {
		return upstream.RelayOutcome{}, errDispatchNotConsumed
	}
	defer response.Close()
	observer, err := handler.adapter.ObserveResponse(ctx, response.Response)
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

func validateDecision(featureID string, decision policy.Decision) ([]quota.Rule, error) {
	feature := decision.Feature
	if feature.ID != featureID || feature.Protocol != openaichat.ID || feature.Output == nil ||
		feature.OpaqueHTTP != nil || feature.Output.DefaultMaximumTokens <= 0 ||
		feature.Output.AbsoluteMaximumTokens <= 0 ||
		feature.Output.DefaultMaximumTokens > feature.Output.AbsoluteMaximumTokens ||
		decision.Route.ID == "" || decision.Route.ModelID != decision.Model.ID ||
		len(decision.Route.FallbackOn) != 0 || decision.Model.ID == "" ||
		decision.Model.UpstreamID != decision.Upstream.ID || decision.Model.UpstreamModel == "" ||
		!slices.Contains(decision.Model.Capabilities, openaichat.ID) ||
		decision.Upstream.ID == "" || decision.Upstream.Type != "openai_compatible" ||
		!validUpstreamAuthentication(decision.Upstream.Authentication) ||
		!validTargetTimeouts(decision.Upstream.Timeouts) || decision.LimitPlan.ID == "" ||
		len(decision.LimitPlan.Limits) == 0 || len(decision.LimitPlan.Limits) > maximumDecisionLimitRules {
		return nil, policy.ErrConfiguration
	}
	rules := make([]quota.Rule, 0, len(decision.LimitPlan.Limits))
	seenIdentities := make(map[decisionLimitIdentity]struct{}, len(decision.LimitPlan.Limits))
	for _, limit := range decision.LimitPlan.Limits {
		scope, ok := canonicalDecisionScope(limit.Scope)
		if limit.Metric != quota.LogicalRequestsMetric || limit.Algorithm != quota.CalendarAlgorithm ||
			!limit.Hard || !ok || !validDecisionWindow(limit.Window) || limit.Maximum <= 0 ||
			limit.PerRequestMaximum != 0 || limit.Capacity != 0 || limit.RefillPerSecond.String() != "" {
			return nil, errUnsupportedLimitPlan
		}
		identity := decisionLimitIdentity{
			metric: limit.Metric, algorithm: limit.Algorithm,
			window: limit.Window, scope: strings.Join(scope, "\x00"),
		}
		if _, duplicate := seenIdentities[identity]; duplicate {
			return nil, errUnsupportedLimitPlan
		}
		seenIdentities[identity] = struct{}{}
		rules = append(rules, quota.Rule{
			Metric: limit.Metric, Algorithm: limit.Algorithm, Scope: scope,
			Window: limit.Window, Maximum: limit.Maximum, Hard: limit.Hard,
		})
	}
	return rules, nil
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

func (handler *Handler) settleAttempt(attempt quota.Attempt, relay upstream.RelayOutcome, executionErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), handler.persistenceTimeout)
	defer cancel()
	return handler.quotas.Settle(ctx, attempt, quotaOutcome(relay, executionErr))
}

func quotaOutcome(relay upstream.RelayOutcome, executionErr error) quota.Outcome {
	httpStatus := relay.StatusCode
	if httpStatus < 100 || httpStatus > 599 {
		httpStatus = 0
	}
	if executionErr == nil && httpStatus >= http.StatusOK && httpStatus < http.StatusMultipleChoices {
		return quota.Outcome{Status: quota.AttemptSucceeded, HTTPStatus: httpStatus}
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
	return quota.Outcome{Status: status, HTTPStatus: httpStatus, FailureCode: code}
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
	case errors.Is(err, quota.ErrDependency), errors.Is(err, quota.ErrInvalidState):
		return "quota_state_unavailable"
	case errors.Is(err, errTargetConfiguration):
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
	case errors.As(err, &exceeded):
		delay := exceeded.RetryAt().Sub(now.UTC())
		seconds := int((delay + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		return "quota_exceeded", seconds
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
	case errors.Is(err, errUpstreamDispatch), errors.Is(err, errUpstreamRelay):
		return "upstream_unavailable", 0
	case errors.Is(err, errDispatchNotOwned):
		return "conflict", 0
	default:
		return "server_not_ready", 0
	}
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
	case "feature_not_found", "feature_not_allowed", "quota_exceeded", "route_not_found",
		"upstream_unavailable", "upstream_timeout", "upstream_protocol_error":
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
	case "route_not_found":
		return "No configured upstream route is available."
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
