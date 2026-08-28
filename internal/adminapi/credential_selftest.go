// Credential-aware administrative self-tests.
package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	maximumSelfTestCostNanoUSD = int64(1_000_000_000)
	maximumSelfTestBodyBytes   = int64(4 << 20)
	credentialSelfTestTimeout  = 45 * time.Second
)

var (
	selfTestIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	selfTestCheckNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

type credentialSelfTestRunner interface {
	Run(context.Context, credentialSelfTestInput) credentialSelfTestResult
}

type credentialSelfTestInput struct {
	Scope       configuration.TenantScope
	Kind        string
	UpstreamID  string
	ModelID     string
	MaxCostNano int64
}

type credentialSelfTestResult struct {
	State  string
	Checks []selfTestCheck
}

type activeSnapshotStore interface {
	ActiveSnapshot(context.Context, configuration.TenantScope) (configuration.ActiveSnapshot, error)
}

type credentialSelfTestSnapshot interface {
	Upstream(string) (configuration.Upstream, bool)
	Model(string) (configuration.Model, bool)
	InputAccountingProfile(string) (configuration.InputAccountingProfile, bool)
	PricingCatalog(string) (configuration.PricingCatalog, bool)
	PricingEntry(string, string) (configuration.PricingEntry, bool)
	PolicyRevision() string
}

type selfTestSnapshotLoader interface {
	CredentialSelfTestSnapshot(context.Context, configuration.TenantScope) (credentialSelfTestSnapshot, error)
}

type productionSelfTestSnapshotLoader struct {
	store activeSnapshotStore
}

func (loader productionSelfTestSnapshotLoader) CredentialSelfTestSnapshot(
	ctx context.Context,
	scope configuration.TenantScope,
) (credentialSelfTestSnapshot, error) {
	return loader.store.ActiveSnapshot(ctx, scope)
}

type productionCredentialSelfTests struct {
	configurations selfTestSnapshotLoader
	secrets        dataplane.SecretStore
	targets        dataplane.TargetFactory
	now            func() time.Time
}

// WithCredentialSelfTests enables the credential-aware upstream and
// OpenRouter diagnostics. Credentials remain inside Store.Use callbacks and
// every request uses the same protected target factory as the data plane.
func WithCredentialSelfTests(secretStore dataplane.SecretStore, targets dataplane.TargetFactory) Option {
	return func(api *API) error {
		if api == nil || isNilSelfTestDependency(secretStore) || isNilSelfTestDependency(targets) {
			return errors.New("credential self-test dependency is nil")
		}
		runner, err := newProductionCredentialSelfTests(
			productionSelfTestSnapshotLoader{store: api.configurations}, secretStore, targets,
		)
		if err != nil {
			return err
		}
		api.operations.selfTests = runner
		return nil
	}
}

func newProductionCredentialSelfTests(
	configurations selfTestSnapshotLoader,
	secretStore dataplane.SecretStore,
	targets dataplane.TargetFactory,
) (*productionCredentialSelfTests, error) {
	if isNilSelfTestDependency(configurations) || isNilSelfTestDependency(secretStore) ||
		isNilSelfTestDependency(targets) {
		return nil, errors.New("credential self-test dependency is nil")
	}
	return &productionCredentialSelfTests{
		configurations: configurations,
		secrets:        secretStore,
		targets:        targets,
		now:            time.Now,
	}, nil
}

func isNilSelfTestDependency(value any) bool {
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

func (runner *productionCredentialSelfTests) Run(
	ctx context.Context,
	input credentialSelfTestInput,
) credentialSelfTestResult {
	if runner == nil || ctx == nil || runner.now == nil ||
		(input.Kind != "upstream" && input.Kind != "openrouter") ||
		!selfTestIdentifierPattern.MatchString(input.UpstreamID) ||
		!selfTestIdentifierPattern.MatchString(input.ModelID) ||
		input.MaxCostNano < 1 || input.MaxCostNano > maximumSelfTestCostNanoUSD {
		return failedCredentialSelfTest(nil, "configuration", "The credential self-test request is invalid.")
	}
	runCtx, cancel := context.WithTimeout(ctx, credentialSelfTestTimeout)
	defer cancel()

	checks := make([]selfTestCheck, 0, 9)
	snapshot, err := runner.configurations.CredentialSelfTestSnapshot(runCtx, input.Scope)
	if err != nil {
		return failedCredentialSelfTest(checks, "active_configuration", "The active compiled configuration could not be loaded.")
	}
	checks = append(checks, passedSelfTestCheck("active_configuration", "The active compiled configuration was loaded."))

	configuredUpstream, ok := snapshot.Upstream(input.UpstreamID)
	if !ok {
		return failedCredentialSelfTest(checks, "selection", "The configured upstream was not found in the active revision.")
	}
	model, ok := snapshot.Model(input.ModelID)
	if !ok || model.UpstreamID != configuredUpstream.ID ||
		!slices.Contains(model.Capabilities, protocol.OpenAIChatID) {
		return failedCredentialSelfTest(checks, "selection", "The configured model is not an OpenAI Chat model on the selected upstream.")
	}
	if input.Kind == "openrouter" && !validOpenRouterTarget(configuredUpstream) {
		return failedCredentialSelfTest(checks, "selection", "The selected target is not the canonical HTTPS OpenRouter API.")
	}
	checks = append(checks, passedSelfTestCheck("selection", "The active upstream and physical model selection is valid."))

	profile, rates, source, err := credentialSelfTestAccounting(snapshot, model, runner.now().UTC())
	if err != nil {
		return failedCredentialSelfTest(checks, "budget", "Trusted input accounting and active configured pricing are required.")
	}
	nonStreaming, err := prepareCredentialChatRequest(runCtx, model.UpstreamModel, profile, rates, source, false)
	if err != nil {
		return failedCredentialSelfTest(checks, "budget", "The non-streaming request could not be bounded before dispatch.")
	}
	streaming, err := prepareCredentialChatRequest(runCtx, model.UpstreamModel, profile, rates, source, true)
	if err != nil {
		return failedCredentialSelfTest(checks, "budget", "The streaming request could not be bounded before dispatch.")
	}
	worstCaseCost, ok := checkedSelfTestAdd(nonStreaming.maximumCostNano, streaming.maximumCostNano)
	if !ok || worstCaseCost > input.MaxCostNano {
		return failedCredentialSelfTest(checks, "budget", "The configured two-request worst-case cost exceeds the operator ceiling.")
	}
	checks = append(checks, passedSelfTestCheck("budget", "Both requests are bounded by trusted input accounting and configured pricing before dispatch."))

	if input.Kind == "openrouter" {
		if err := runner.verifyOpenRouterKey(runCtx, input.Scope, configuredUpstream, worstCaseCost); err != nil {
			return failedCredentialSelfTest(checks, "key", "The OpenRouter credential or available-credit check failed.")
		}
		checks = append(checks, passedSelfTestCheck("key", "OpenRouter accepted the server-held credential and reported sufficient access."))
	}

	nonStreamingUsage, err := runner.dispatchChat(runCtx, input.Scope, configuredUpstream, nonStreaming)
	if err != nil {
		return failedCredentialSelfTest(checks, "non_streaming", "The bounded non-streaming provider request failed.")
	}
	checks = append(checks, passedSelfTestCheck("non_streaming", "A bounded non-streaming request completed with provider usage."))

	streamingUsage, err := runner.dispatchChat(runCtx, input.Scope, configuredUpstream, streaming)
	if err != nil {
		return failedCredentialSelfTest(checks, "streaming", "The bounded streaming provider request or final usage frame failed.")
	}
	checks = append(checks, passedSelfTestCheck("streaming", "A bounded stream completed and final-frame usage was extracted."))

	actualCost, ok := reportedCredentialSelfTestCost(rates, source, nonStreamingUsage, streamingUsage)
	if !ok || actualCost > worstCaseCost || actualCost > input.MaxCostNano ||
		nonStreamingUsage.OutputTokens > nonStreaming.outputMaximum ||
		streamingUsage.OutputTokens > streaming.outputMaximum ||
		nonStreamingUsage.InputTokens > nonStreaming.inputMaximum ||
		nonStreamingUsage.TotalTokens > nonStreaming.totalMaximum ||
		streamingUsage.InputTokens > streaming.inputMaximum ||
		streamingUsage.TotalTokens > streaming.totalMaximum {
		return failedCredentialSelfTest(checks, "usage", "Reported usage exceeded a trusted token or cost bound.")
	}
	checks = append(checks,
		passedSelfTestCheck("usage", "Input, output, total-token, and configured-cost reconciliation passed."),
		passedSelfTestCheck("output_clamp", "Both provider requests honored the one-token server clamp."),
	)

	if err := runner.verifyProviderErrorNormalization(runCtx, input.Scope, configuredUpstream); err != nil {
		return failedCredentialSelfTest(checks, "error_normalization", "The provider error normalization probe failed.")
	}
	checks = append(checks, passedSelfTestCheck("error_normalization", "A malformed provider request was reduced to a body-free safe rejection class."))
	return credentialSelfTestResult{State: "passed", Checks: checks}
}

type preparedCredentialChat struct {
	request         *http.Request
	adapter         openaichat.Adapter
	maximumCostNano int64
	inputMaximum    int64
	outputMaximum   int64
	totalMaximum    int64
}

func prepareCredentialChatRequest(
	ctx context.Context,
	physicalModel string,
	profile protocol.TrustedInputProfile,
	rates pricing.Rates,
	source pricing.Source,
	stream bool,
) (preparedCredentialChat, error) {
	body, err := json.Marshal(map[string]any{
		"model": physicalModel,
		"messages": []map[string]string{{
			"role": "user", "content": "Reply with OK.",
		}},
		"stream":     stream,
		"max_tokens": 1,
	})
	if err != nil {
		return preparedCredentialChat{}, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "https://latchway.invalid/v1/chat/completions", bytes.NewReader(body),
	)
	if err != nil {
		return preparedCredentialChat{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	adapter := openaichat.Adapter{MaximumBodyBytes: 64 << 10}
	applied, err := adapter.ApplyFeature(ctx, request, protocol.FeatureDecision{
		PhysicalModel: physicalModel, DefaultOutputTokens: 1, MaximumOutputTokens: 1,
	})
	if err != nil || applied != 1 {
		return preparedCredentialChat{}, errors.New("self-test output clamp is unavailable")
	}
	preflight, err := adapter.PreflightInput(ctx, request, profile)
	if err != nil || preflight.OutputTokenBound != applied {
		return preparedCredentialChat{}, errors.New("self-test trusted input preflight failed")
	}
	worst, err := pricing.Calculate(rates, pricing.Usage{
		InputTokens: preflight.InputTokenBound, OutputTokens: applied,
	}, source)
	if err != nil || !worst.Known() {
		return preparedCredentialChat{}, errors.New("self-test cost calculation failed")
	}
	return preparedCredentialChat{
		request: request, adapter: adapter, maximumCostNano: worst.CostNanoUSD(),
		inputMaximum: preflight.InputTokenBound, outputMaximum: applied,
		totalMaximum: preflight.TotalTokenBound,
	}, nil
}

func credentialSelfTestAccounting(
	snapshot credentialSelfTestSnapshot,
	model configuration.Model,
	now time.Time,
) (protocol.TrustedInputProfile, pricing.Rates, pricing.Source, error) {
	if model.PricingRef == "" || model.InputAccountingRef == "" {
		return protocol.TrustedInputProfile{}, pricing.Rates{}, pricing.Source{}, errors.New("accounting references are required")
	}
	profile, ok := snapshot.InputAccountingProfile(model.InputAccountingRef)
	if !ok || profile.Protocol != protocol.OpenAIChatID || profile.PhysicalModel != model.UpstreamModel {
		return protocol.TrustedInputProfile{}, pricing.Rates{}, pricing.Source{}, errors.New("trusted input profile is unavailable")
	}
	catalog, ok := snapshot.PricingCatalog(model.PricingRef)
	if !ok || catalog.ID != model.PricingRef || catalog.Currency != pricing.CurrencyUSD || catalog.EffectiveAfter(now) {
		return protocol.TrustedInputProfile{}, pricing.Rates{}, pricing.Source{}, errors.New("pricing catalog is unavailable")
	}
	entry, ok := snapshot.PricingEntry(model.PricingRef, model.ID)
	if !ok || entry.ModelID != model.ID || entry.InputNanoUSDPerMillion < 0 ||
		entry.OutputNanoUSDPerMillion < 0 || entry.RequestNanoUSD < 0 {
		return protocol.TrustedInputProfile{}, pricing.Rates{}, pricing.Source{}, errors.New("pricing entry is unavailable")
	}
	source, err := pricing.NewSource(catalog.ID, snapshot.PolicyRevision())
	if err != nil {
		return protocol.TrustedInputProfile{}, pricing.Rates{}, pricing.Source{}, err
	}
	return protocol.TrustedInputProfile{
			ID:                             profile.ID,
			Protocol:                       profile.Protocol,
			Method:                         profile.Method,
			PhysicalModel:                  profile.PhysicalModel,
			MaximumFramingTokensPerRequest: profile.MaximumFramingTokensPerRequest,
			MaximumFramingTokensPerMessage: profile.MaximumFramingTokensPerMessage,
			MaximumContextTokens:           profile.MaximumContextTokens,
		}, pricing.Rates{
			InputNanoUSDPerMillion:  entry.InputNanoUSDPerMillion,
			OutputNanoUSDPerMillion: entry.OutputNanoUSDPerMillion,
			RequestNanoUSD:          entry.RequestNanoUSD,
		}, source, nil
}

func validOpenRouterTarget(configured configuration.Upstream) bool {
	if configured.Type != "openai_compatible" || configured.DangerousAllowInsecureHTTP ||
		configured.Authentication.Type != "bearer" {
		return false
	}
	parsed, err := url.Parse(configured.BaseURL)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.User != nil ||
		!strings.EqualFold(parsed.Hostname(), "openrouter.ai") ||
		(parsed.Port() != "" && parsed.Port() != "443") || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	return strings.TrimSuffix(parsed.Path, "/") == "/api/v1"
}

func (runner *productionCredentialSelfTests) dispatchChat(
	ctx context.Context,
	scope configuration.TenantScope,
	configured configuration.Upstream,
	prepared preparedCredentialChat,
) (protocol.Usage, error) {
	var usage protocol.Usage
	err := runner.dispatch(ctx, scope, configured, prepared.request,
		protocol.OpenAIChatProviderPath, []string{"Content-Type"}, func(response *upstream.DispatchedResponse) error {
			observed, observeErr := observeCredentialChatResponse(ctx, prepared.adapter, response)
			usage = observed
			return observeErr
		})
	if err != nil || !validReportedSelfTestUsage(usage) {
		return protocol.Usage{}, errors.New("credential self-test chat dispatch failed")
	}
	return usage, nil
}

func observeCredentialChatResponse(
	ctx context.Context,
	adapter openaichat.Adapter,
	response *upstream.DispatchedResponse,
) (protocol.Usage, error) {
	if response == nil || response.Response == nil || response.Body == nil {
		return protocol.Usage{}, errors.New("provider response is unavailable")
	}
	defer response.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices ||
		response.ContentLength > maximumSelfTestBodyBytes {
		return protocol.Usage{}, errors.New("provider rejected the request")
	}
	observer, err := adapter.ObserveResponse(ctx, response.Response)
	if err != nil {
		return protocol.Usage{}, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumSelfTestBodyBytes+1))
	if err != nil || int64(len(body)) > maximumSelfTestBodyBytes {
		return protocol.Usage{}, errors.New("provider response exceeded the diagnostic limit")
	}
	if err := observer.Observe(body); err != nil {
		return protocol.Usage{}, err
	}
	return observer.Finalize()
}

func validReportedSelfTestUsage(usage protocol.Usage) bool {
	total, ok := checkedSelfTestAdd(usage.InputTokens, usage.OutputTokens)
	return usage.Known && usage.InputTokens > 0 && usage.OutputTokens >= 0 && ok && usage.TotalTokens == total
}

func reportedCredentialSelfTestCost(
	rates pricing.Rates,
	source pricing.Source,
	usages ...protocol.Usage,
) (int64, bool) {
	var total int64
	for _, usage := range usages {
		if !validReportedSelfTestUsage(usage) {
			return 0, false
		}
		result, err := pricing.Calculate(rates, pricing.Usage{
			InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens,
		}, source)
		if err != nil || !result.Known() {
			return 0, false
		}
		var ok bool
		total, ok = checkedSelfTestAdd(total, result.CostNanoUSD())
		if !ok {
			return 0, false
		}
	}
	return total, true
}

func (runner *productionCredentialSelfTests) verifyOpenRouterKey(
	ctx context.Context,
	scope configuration.TenantScope,
	configured configuration.Upstream,
	maximumCost int64,
) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://latchway.invalid/key", nil)
	if err != nil {
		return err
	}
	return runner.dispatch(ctx, scope, configured, request, "/key", nil,
		func(response *upstream.DispatchedResponse) error {
			if response == nil || response.Response == nil || response.Body == nil {
				return errors.New("OpenRouter key response is unavailable")
			}
			defer response.Close()
			if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices ||
				response.ContentLength > 64<<10 {
				return errors.New("OpenRouter rejected the credential")
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
			if err != nil || len(body) > 64<<10 {
				return errors.New("OpenRouter key response exceeded the limit")
			}
			return validateOpenRouterKeyInformation(body, maximumCost)
		})
}

func validateOpenRouterKeyInformation(body []byte, maximumCost int64) error {
	decoded, err := jsonsafe.Decode(body)
	if err != nil {
		return errors.New("OpenRouter key response is malformed")
	}
	envelope, ok := decoded.(map[string]any)
	if !ok {
		return errors.New("OpenRouter key response is malformed")
	}
	dataValue, present := envelope["data"]
	data, ok := dataValue.(map[string]any)
	if !present || !ok {
		return errors.New("OpenRouter key response omitted key information")
	}
	isFreeTier, ok := data["is_free_tier"].(bool)
	if !ok {
		return errors.New("OpenRouter key response omitted its access tier")
	}
	if isFreeTier {
		return nil
	}
	limit, hasLimit := data["limit"]
	remainingValue, hasRemaining := data["limit_remaining"]
	if hasLimit && hasRemaining && limit == nil && remainingValue == nil {
		return nil
	}
	remaining, ok := remainingValue.(json.Number)
	if !ok {
		return errors.New("OpenRouter key response omitted available credit")
	}
	remainingNano, ok := decimalUSDToNanoUSD(remaining.String())
	if !ok || remainingNano < maximumCost {
		return errors.New("OpenRouter key has insufficient available credit")
	}
	return nil
}

func decimalUSDToNanoUSD(value string) (int64, bool) {
	if value == "" || len(value) > 128 {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(value)
	if !ok || rational.Sign() < 0 {
		return 0, false
	}
	rational.Mul(rational, big.NewRat(1_000_000_000, 1))
	integer := new(big.Int).Quo(rational.Num(), rational.Denom())
	if !integer.IsInt64() {
		return 0, false
	}
	return integer.Int64(), true
}

func (runner *productionCredentialSelfTests) verifyProviderErrorNormalization(
	ctx context.Context,
	scope configuration.TenantScope,
	configured configuration.Upstream,
) error {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "https://latchway.invalid/v1/chat/completions", strings.NewReader(`{"model":}`),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	return runner.dispatch(ctx, scope, configured, request, protocol.OpenAIChatProviderPath,
		[]string{"Content-Type"}, func(response *upstream.DispatchedResponse) error {
			if response == nil || response.Response == nil || response.Body == nil {
				return errors.New("provider error response is unavailable")
			}
			defer response.Close()
			if response.StatusCode < http.StatusBadRequest || response.StatusCode >= http.StatusInternalServerError ||
				response.ContentLength > 64<<10 {
				return errors.New("provider error did not normalize to a safe rejection")
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
			if err != nil || len(body) > 64<<10 {
				return errors.New("provider error response exceeded the limit")
			}
			return nil
		})
}

func (runner *productionCredentialSelfTests) dispatch(
	ctx context.Context,
	scope configuration.TenantScope,
	configured configuration.Upstream,
	incoming *http.Request,
	providerPath string,
	forwardedHeaders []string,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if ctx == nil || incoming == nil || consume == nil {
		return errors.New("credential self-test dispatch is invalid")
	}
	lease, err := runner.targets.Acquire(configured)
	if err != nil || isNilSelfTestDependency(lease) {
		return errors.New("protected upstream target is unavailable")
	}
	defer lease.Release()
	prepared, err := lease.Prepare(incoming, providerPath, forwardedHeaders, configured.StaticHeaders)
	if err != nil {
		return errors.New("protected upstream request preparation failed")
	}
	beforeRoundTrip := func() error { return nil }
	authentication := configured.Authentication
	switch authentication.Type {
	case "none":
		response, err := lease.DispatchWithBeforeRoundTrip(ctx, prepared, beforeRoundTrip)
		if err != nil {
			return errors.New("protected upstream dispatch failed")
		}
		return consume(response)
	case "bearer", "header":
		callbackCalled := false
		var consumeErr error
		var transportErr error
		secretErr := runner.secrets.Use(ctx, secrets.Scope{
			OrganizationID: scope.OrganizationID,
			ApplicationID:  scope.ApplicationID,
			EnvironmentID:  scope.EnvironmentID,
		}, authentication.SecretRef, func(credential []byte) error {
			callbackCalled = true
			consumeResponse := func(response *upstream.DispatchedResponse) error {
				consumeErr = consume(response)
				return nil
			}
			if authentication.Type == "bearer" {
				transportErr = lease.WithBearerDispatchWithBeforeRoundTrip(
					ctx, prepared, credential, beforeRoundTrip, consumeResponse,
				)
			} else {
				transportErr = lease.WithHeaderDispatchWithBeforeRoundTrip(
					ctx, prepared, authentication.HeaderName, credential, beforeRoundTrip, consumeResponse,
				)
			}
			// The secret boundary deliberately sees no transport/provider error.
			return nil
		})
		if secretErr != nil || !callbackCalled || transportErr != nil || consumeErr != nil {
			return errors.New("server-held upstream credential or dispatch is unavailable")
		}
		return nil
	default:
		return errors.New("upstream authentication is invalid")
	}
}

func failedCredentialSelfTest(checks []selfTestCheck, name, detail string) credentialSelfTestResult {
	checks = append(checks, selfTestCheck{Name: name, State: "failed", SafeDetail: detail})
	return credentialSelfTestResult{State: "failed", Checks: checks}
}

func passedSelfTestCheck(name, detail string) selfTestCheck {
	return selfTestCheck{Name: name, State: "passed", SafeDetail: detail}
}

func checkedSelfTestAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

func validStoredSelfTest(run selfTestDocument) bool {
	if (run.Kind != "local" && run.Kind != "upstream" && run.Kind != "openrouter") ||
		(run.State != "passed" && run.State != "failed") || run.CreatedAt.IsZero() ||
		run.CompletedAt == nil || run.CompletedAt.IsZero() || run.CompletedAt.Before(run.CreatedAt) ||
		len(run.Checks) == 0 || len(run.Checks) > 32 {
		return false
	}
	for _, check := range run.Checks {
		if !selfTestCheckNamePattern.MatchString(check.Name) ||
			(check.State != "passed" && check.State != "failed" && check.State != "skipped") ||
			len(check.SafeDetail) > 2048 || !utf8.ValidString(check.SafeDetail) {
			return false
		}
	}
	return true
}

func (store *operationalStore) startCredentialSelfTest(
	ctx context.Context,
	principal adminauth.Principal,
	input startSelfTestInput,
) (selfTestDocument, error) {
	var applicationID string
	var createdAt time.Time
	err := store.pool.QueryRow(ctx, `
		SELECT environment.application_id, statement_timestamp()
		FROM environments AS environment
		JOIN applications AS application
		  ON application.organization_id = environment.organization_id
		 AND application.application_id = environment.application_id
		JOIN organizations AS organization
		  ON organization.organization_id = environment.organization_id
		WHERE environment.organization_id = $1 AND environment.environment_id = $2
		  AND organization.status = 'active' AND application.status = 'active'
		  AND environment.status = 'active'
	`, principal.OrganizationID, input.Environment).Scan(&applicationID, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return selfTestDocument{}, errOperationalNotFound
	}
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("inspect credential self-test environment: %w", err)
	}
	selfTestID, err := store.newID(id.Prefix("tst"))
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("generate self-test ID: %w", err)
	}
	jobID, err := store.newID(id.Job)
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("generate self-test job ID: %w", err)
	}
	result := store.selfTests.Run(ctx, credentialSelfTestInput{
		Scope: configuration.TenantScope{
			OrganizationID: principal.OrganizationID,
			ApplicationID:  applicationID,
			EnvironmentID:  input.Environment,
		},
		Kind: input.Kind, UpstreamID: input.Upstream, ModelID: input.Model,
		MaxCostNano: input.MaxCost,
	})
	if result.State != "passed" && result.State != "failed" {
		result = failedCredentialSelfTest(nil, "runner", "The credential self-test runner returned an invalid result.")
	}
	run := selfTestDocument{
		ID: selfTestID, Kind: input.Kind, State: result.State,
		CreatedAt: createdAt.UTC(), Checks: append([]selfTestCheck(nil), result.Checks...),
	}

	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := store.pool.BeginTx(persistCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("begin credential self-test result: %w", err)
	}
	defer rollbackOperational(tx)
	var completedAt time.Time
	if err := tx.QueryRow(persistCtx, `SELECT transaction_timestamp()`).Scan(&completedAt); err != nil {
		return selfTestDocument{}, fmt.Errorf("read credential self-test completion time: %w", err)
	}
	completedAt = completedAt.UTC()
	run.CompletedAt = &completedAt
	if !validStoredSelfTest(run) {
		return selfTestDocument{}, errOperationalCorrupt
	}
	payload, err := json.Marshal(run)
	if err != nil {
		return selfTestDocument{}, fmt.Errorf("encode credential self-test result: %w", err)
	}
	if _, err := tx.Exec(persistCtx, `
		INSERT INTO jobs (
		    job_id, organization_id, environment_id, job_type, idempotency_key,
		    payload, status, available_at, attempt_count, max_attempts,
		    created_at, updated_at, completed_at
		) VALUES (
		    $1, $2, $3, 'run_scheduled_self_test', $4,
		    $5, 'succeeded', $6, 1, 1, $7, $6, $6
		)
	`, jobID, principal.OrganizationID, input.Environment, "admin-self-test:"+selfTestID,
		payload, completedAt, createdAt.UTC()); err != nil {
		return selfTestDocument{}, mapOperationalDatabase("persist credential self-test", err)
	}
	stateChange, err := adminauth.NewPublicAuditChange("state", adminauth.AuditSet)
	if err != nil {
		return selfTestDocument{}, err
	}
	if err := store.audit(
		persistCtx, tx, principal, input.Environment, "admin.self_test_run", "self_test",
		selfTestID, input.RequestID, completedAt, []adminauth.AuditChange{stateChange},
	); err != nil {
		return selfTestDocument{}, err
	}
	if err := tx.Commit(persistCtx); err != nil {
		return selfTestDocument{}, mapOperationalCommit("commit credential self-test", err)
	}
	return run, nil
}
