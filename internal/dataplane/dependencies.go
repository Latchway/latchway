package dataplane

import (
	"context"
	"net/http"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/session"
	"github.com/latchway/latchway/internal/upstream"
)

// AccessTokenVerifier verifies only the gateway-issued access token. Durable
// session state and the request-bound proof are checked separately by
// SessionAuthorizer.
type AccessTokenVerifier interface {
	Verify(context.Context, session.AccessToken) (session.AccessPrincipal, error)
}

// SessionAuthorizer consumes the exact token, signed principal, DPoP proof,
// HTTP method, and configured public URL. Its production implementation is
// session.Store.
type SessionAuthorizer interface {
	AuthorizeAccess(context.Context, session.AccessRequestInput) (session.Authorization, error)
}

// SnapshotLoader resolves the one immutable active revision for an authorized
// tenant scope.
type SnapshotLoader interface {
	ActiveSnapshot(context.Context, configuration.TenantScope) (configuration.ActiveSnapshot, error)
}

// PolicyDecisionEngine is deliberately passed a sealed session.Authorization.
// The production engine below is the only implementation that converts it to
// policy.Input; tests may replace orchestration without weakening that type in
// production composition.
type PolicyDecisionEngine interface {
	Resolve(
		context.Context,
		configuration.ActiveSnapshot,
		string,
		session.Authorization,
		requestidentity.LogicalID,
		protocol.RequestMetadata,
	) (policy.Decision, error)
}

// PolicyResolver is the bounded CEL resolver surface used by PolicyEngine.
type PolicyResolver interface {
	Resolve(context.Context, policy.Snapshot, string, policy.Input) (policy.Decision, error)
}

// PolicyEngine converts sealed authorization and allowlisted request metadata
// into the opaque policy activation before invoking the bounded resolver.
type PolicyEngine struct {
	resolver PolicyResolver
}

func NewPolicyEngine(resolver PolicyResolver) (*PolicyEngine, error) {
	if nilDependency(resolver) {
		return nil, errInvalidConfiguration
	}
	return &PolicyEngine{resolver: resolver}, nil
}

func (engine *PolicyEngine) Resolve(
	ctx context.Context,
	snapshot configuration.ActiveSnapshot,
	featureID string,
	authorization session.Authorization,
	logicalID requestidentity.LogicalID,
	metadata protocol.RequestMetadata,
) (policy.Decision, error) {
	if engine == nil || nilDependency(engine.resolver) {
		return policy.Decision{}, errInvalidConfiguration
	}
	input, err := policy.NewInput(
		authorization,
		logicalID,
		policy.ProtocolRequestMetadata{Streaming: metadata.Streaming},
		policy.EnvironmentFacts{Kind: authorization.EnvironmentKind},
	)
	if err != nil {
		return policy.Decision{}, err
	}
	return engine.resolver.Resolve(ctx, snapshot, featureID, input)
}

// QuotaStore owns the durable reserve/execute/settle lifecycle. The concrete
// opaque handles prevent the data plane from inventing persisted state.
type QuotaStore interface {
	Reserve(context.Context, quota.ReserveInput) (quota.Reservation, error)
	BeginAttempt(context.Context, quota.Reservation) (quota.Attempt, bool, error)
	MarkFirstByte(context.Context, quota.Attempt) error
	Settle(context.Context, quota.Attempt, quota.Outcome) error
	ReleaseBeforeDispatch(context.Context, quota.Reservation, string) error
}

// SecretStore exposes plaintext only to one synchronous callback.
type SecretStore interface {
	Use(context.Context, secrets.Scope, string, func([]byte) error) error
}

// ProviderRequest is an opaque request capability owned by a DispatchTarget.
// The native capability cannot be replaced with an arbitrary URL after
// credential injection.
type ProviderRequest struct {
	native upstream.PreparedRequest
}

// DispatchTarget composes request reconstruction with the target-bound
// dispatch capabilities. Credentialled dispatch remains callback scoped until
// the response body has been fully consumed and closed.
type DispatchTarget interface {
	Prepare(*http.Request, string, []string, map[string]string) (ProviderRequest, error)
	DispatchWithBeforeRoundTrip(context.Context, ProviderRequest, func() error) (*upstream.DispatchedResponse, error)
	WithBearerDispatchWithBeforeRoundTrip(context.Context, ProviderRequest, []byte, func() error, func(*upstream.DispatchedResponse) error) error
	WithHeaderDispatchWithBeforeRoundTrip(context.Context, ProviderRequest, string, []byte, func() error, func(*upstream.DispatchedResponse) error) error
}

// TargetLease keeps a shared protected transport live for one request. Release
// is idempotent; a released lease rejects further dispatch work.
type TargetLease interface {
	DispatchTarget
	Release()
}

// TargetFactory acquires a bounded lease for an immutable server-selected
// upstream. The caller must release every successfully acquired lease.
type TargetFactory interface {
	Acquire(configuration.Upstream) (TargetLease, error)
}

// ResponseRelayer is the streaming boundary. The production implementation
// delegates directly to upstream.RelayResponse.
type ResponseRelayer interface {
	Relay(
		context.Context,
		http.ResponseWriter,
		*upstream.DispatchedResponse,
		protocol.ResponseObserver,
		upstream.ResponseRelayConfig,
	) (upstream.RelayOutcome, error)
}

type responseRelayer struct{}

func (responseRelayer) Relay(
	ctx context.Context,
	destination http.ResponseWriter,
	response *upstream.DispatchedResponse,
	observer protocol.ResponseObserver,
	config upstream.ResponseRelayConfig,
) (upstream.RelayOutcome, error) {
	return upstream.RelayResponse(ctx, destination, response, observer, config)
}
