package dataplane

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/latchway/latchway/internal/clientapi"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/frameworkcompat"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/session"
)

const (
	clientFeatureQuotaPrefix = "/client/v1/features/"
	clientFeatureQuotaSuffix = "/quota"
)

// FeatureQuotaConfig contains the trusted dependencies for the authenticated
// public quota projection. PublicOrigin is the sole authority used to build
// the DPoP request target; inbound Host and forwarding headers never enter
// this boundary.
type FeatureQuotaConfig struct {
	AccessTokens  AccessTokenVerifier
	Sessions      SessionAuthorizer
	Configuration SnapshotLoader
	Policies      QuotaProjectionResolver
	Quotas        QuotaSnapshotStore
	PublicOrigin  string
}

// FeatureQuotaProvider authenticates a protected client read, resolves one
// context-stable policy projection, and asks quota storage for a read-only
// point-in-time snapshot. It performs no route selection or upstream work.
type FeatureQuotaProvider struct {
	accessTokens  AccessTokenVerifier
	sessions      SessionAuthorizer
	configuration SnapshotLoader
	policies      QuotaProjectionResolver
	quotas        QuotaSnapshotStore
	origin        url.URL
}

var _ clientapi.FeatureQuotaProvider = (*FeatureQuotaProvider)(nil)

func NewFeatureQuotaProvider(config FeatureQuotaConfig) (*FeatureQuotaProvider, error) {
	if nilDependency(config.AccessTokens) || nilDependency(config.Sessions) ||
		nilDependency(config.Configuration) || nilDependency(config.Policies) ||
		nilDependency(config.Quotas) {
		return nil, errInvalidConfiguration
	}
	origin, err := canonicalPublicOrigin(config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	return &FeatureQuotaProvider{
		accessTokens: config.AccessTokens, sessions: config.Sessions,
		configuration: config.Configuration, policies: config.Policies,
		quotas: config.Quotas, origin: origin,
	}, nil
}

func (provider *FeatureQuotaProvider) FeatureQuota(
	ctx context.Context,
	input clientapi.FeatureQuotaInput,
) (clientapi.FeatureQuotaResult, error) {
	if provider == nil || nilDependency(provider.accessTokens) || nilDependency(provider.sessions) ||
		nilDependency(provider.configuration) || nilDependency(provider.policies) ||
		nilDependency(provider.quotas) || ctx == nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(errInvalidConfiguration)
	}
	if err := ctx.Err(); err != nil {
		return clientapi.FeatureQuotaResult{}, err
	}

	target, err := provider.validateInput(input)
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	accessToken, err := session.NewAccessToken(input.AccessToken.Reveal())
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(session.ErrTokenInvalid)
	}
	dpopProof, err := session.NewDPoPProof(input.Metadata.DPoPProof.Reveal())
	if err != nil {
		return clientapi.FeatureQuotaResult{}, &clientapi.DependencyError{Code: "dpop_invalid"}
	}
	principal, err := provider.accessTokens.Verify(ctx, accessToken)
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	authorization, err := provider.sessions.AuthorizeAccess(ctx, session.AccessRequestInput{
		AccessToken: accessToken,
		Principal:   principal,
		DPoPProof:   dpopProof,
		HTTPMethod:  http.MethodGet,
		RequestURI:  cloneURL(target),
		Origin:      input.Metadata.Origin,
	})
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	if !sdkMatchesPlatform(input.Metadata.SDK, authorization.InstallationPlatform) {
		return clientapi.FeatureQuotaResult{}, &clientapi.DependencyError{Code: "request_invalid"}
	}
	if authorization.ComponentID != "" && !slices.Contains(authorization.GrantedFeatures, input.Feature) {
		return clientapi.FeatureQuotaResult{}, &clientapi.DependencyError{Code: "component_feature_not_granted"}
	}

	snapshot, err := provider.configuration.ActiveSnapshot(ctx, configuration.TenantScope{
		OrganizationID: authorization.OrganizationID,
		ApplicationID:  authorization.ApplicationID,
		EnvironmentID:  authorization.EnvironmentID,
	})
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	if snapshot.PolicyRevision() != authorization.PolicyRevisionID ||
		snapshot.PolicyEnvironment() != authorization.EnvironmentID {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(policy.ErrConfiguration)
	}
	projection, err := provider.policies.ResolveQuota(
		ctx,
		snapshot,
		input.Feature,
		authorization,
		input.LogicalRequestID,
		policy.EnvironmentFacts{Kind: authorization.EnvironmentKind},
	)
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	validated, err := validateFeatureLimitPlan(input.Feature, projection.Feature, projection.LimitPlan)
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	for index := range validated.rules {
		if containsPhysicalScope(validated.rules[index].Scope) {
			return clientapi.FeatureQuotaResult{}, featureQuotaFailure(policy.ErrConfiguration)
		}
		if validated.rules[index].Metric == quota.OutputTokensMetric &&
			validated.rules[index].Algorithm == quota.PerRequestAlgorithm {
			// A request can be bounded by the feature absolute maximum, another
			// per-request rule, or a token-bucket capacity. Report the same
			// effective static cap that protected request enforcement applies.
			validated.rules[index].PerRequestMaximum = validated.maximumOutputTokens
		}
	}

	quotaSnapshot, err := provider.quotas.Snapshot(ctx, quota.SnapshotInput{
		OrganizationID:         authorization.OrganizationID,
		ApplicationID:          authorization.ApplicationID,
		EnvironmentID:          authorization.EnvironmentID,
		ApplicationUserID:      authorization.ApplicationUserID,
		InstallationID:         authorization.InstallationID,
		InstallationFamilyID:   projection.Scopes.InstallationFamilyID,
		ClientComponentID:      projection.Scopes.ClientComponentID,
		ComponentDefinitionID:  projection.Scopes.ComponentDefinitionID,
		ComponentKind:          projection.Scopes.ComponentKind,
		TrustSource:            projection.Scopes.TrustSource,
		ConfigRevisionID:       snapshot.PolicyRevision(),
		Platform:               projection.Scopes.Platform,
		NormalizedClaimDigests: cloneClaimDigests(projection.Scopes.NormalizedClaims),
		UserOverrideID:         authorization.UserOverrideID,
		LimitPlanOverride:      authorization.LimitPlanOverride,
		FeatureKey:             projection.Feature.ID,
		LimitPlanKey:           projection.LimitPlan.ID,
		Rules:                  validated.rules,
	})
	if err != nil {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(err)
	}
	if quotaSnapshot.Feature != projection.Feature.ID {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(quota.ErrInvalidState)
	}
	return featureQuotaResult(quotaSnapshot, validated.rules)
}

func (provider *FeatureQuotaProvider) validateInput(input clientapi.FeatureQuotaInput) (url.URL, error) {
	logicalID := input.LogicalRequestID.String()
	if !identifierPattern.MatchString(input.Feature) ||
		id.Validate(logicalID, id.LogicalRequest) != nil ||
		input.Metadata.RequestID != logicalID || input.Metadata.HTTPMethod != http.MethodGet ||
		!validSDK(input.Metadata.SDK) || !validSemVer(input.Metadata.SDKVersion) ||
		!validFrameworkMetadata(input.Metadata.SDK, input.Metadata.Framework, input.Metadata.FrameworkVersion) {
		return url.URL{}, errInvalidConfiguration
	}
	target := url.URL{
		Scheme: provider.origin.Scheme,
		Host:   provider.origin.Host,
		Path:   clientFeatureQuotaPrefix + input.Feature + clientFeatureQuotaSuffix,
	}
	provided := input.Metadata.TargetURL
	if provided.Scheme != target.Scheme || provided.Host != target.Host ||
		provided.Path != target.Path || provided.Opaque != "" || provided.User != nil ||
		provided.RawPath != "" || provided.RawQuery != "" || provided.ForceQuery ||
		provided.Fragment != "" || provided.RawFragment != "" {
		return url.URL{}, errInvalidConfiguration
	}
	return target, nil
}

func validFrameworkMetadata(sdk, framework, version string) bool {
	if framework == "" || version == "" {
		return framework == "" && version == ""
	}
	return frameworkcompat.Compatible(sdk, framework) && frameworkcompat.ValidVersion(version)
}

func containsPhysicalScope(scope []string) bool {
	for _, dimension := range scope {
		switch dimension {
		case "route", "upstream", "model":
			return true
		}
	}
	return false
}

func featureQuotaResult(snapshot quota.Snapshot, rules []quota.Rule) (clientapi.FeatureQuotaResult, error) {
	if snapshot.Feature == "" || snapshot.ObservedAt.IsZero() ||
		snapshot.ObservedAt.Location() != time.UTC || len(snapshot.Limits) != len(rules) {
		return clientapi.FeatureQuotaResult{}, featureQuotaFailure(quota.ErrInvalidState)
	}
	wantMetrics := make(map[string]int, len(rules))
	for _, rule := range rules {
		wantMetrics[rule.Metric]++
	}
	limits := make([]clientapi.FeatureQuotaLimit, len(snapshot.Limits))
	for index, limit := range snapshot.Limits {
		if !limit.Hard || wantMetrics[limit.Metric] == 0 {
			return clientapi.FeatureQuotaResult{}, featureQuotaFailure(quota.ErrInvalidState)
		}
		wantMetrics[limit.Metric]--
		limits[index] = clientapi.FeatureQuotaLimit{
			Metric: limit.Metric, Maximum: cloneInt64(limit.Maximum),
			Used: cloneInt64(limit.Used), Reserved: cloneInt64(limit.Reserved),
			Remaining: cloneInt64(limit.Remaining), ResetsAt: cloneTime(limit.ResetsAt),
			Hard: true,
		}
	}
	return clientapi.FeatureQuotaResult{
		Feature: snapshot.Feature, ObservedAt: snapshot.ObservedAt, Limits: limits,
	}, nil
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func featureQuotaFailure(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &clientapi.DependencyError{Code: "server_not_ready"}
	}
	code, _ := errorCode(err, time.Time{})
	switch code {
	case "dpop_invalid", "dpop_replayed", "session_expired", "session_revoked",
		"installation_revoked", "installation_family_revoked", "component_revoked",
		"component_feature_not_granted", "attestation_stale", "attestation_step_up_required",
		"feature_not_found", "feature_not_allowed", "configuration_invalid",
		"server_not_ready":
		return &clientapi.DependencyError{Code: code}
	default:
		return &clientapi.DependencyError{Code: "server_not_ready"}
	}
}
