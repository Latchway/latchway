// Package providerverify performs bounded, database-free provider credential
// verification. Credentials are accepted only through a scoped byte callback
// and are never included in reports or error text.
package providerverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/latchway/latchway/adapters/protocol/openaichat"
	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/pricing"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/upstream"
)

const (
	ModeOpenRouter = "openrouter"
	ModeOpenAIChat = "openai_chat"

	CostVerified   = "verified"
	CostUnverified = "unverified"

	openRouterBaseURL      = "https://openrouter.ai/api/v1"
	maximumResponseBytes   = int64(4 << 20)
	maximumMetadataBytes   = int64(64 << 10)
	maximumCredentialBytes = 32 << 10
	defaultTotalTimeout    = 45 * time.Second
	defaultConnectTimeout  = 5 * time.Second
	defaultHeaderTimeout   = 10 * time.Second
	maximumMaxCostNanoUSD  = int64(1_000_000_000)
	conservativeFraming    = int64(64)
	minimumContextTokens   = int64(4096)
	maximumModelBytes      = 256
)

var openRouterModelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$`)

// CredentialSource exposes credential material only for the duration of use.
// Implementations should clear or release their backing bytes after consume
// returns. consume must be called exactly once on success.
type CredentialSource func(context.Context, func([]byte) error) error

// Request is the complete database-free verification request. BaseURL must be
// empty for OpenRouter and a production HTTPS origin for generic OpenAI Chat.
type Request struct {
	Mode           string
	BaseURL        string
	Model          string
	MaxCostNanoUSD int64
	Credential     CredentialSource
	InputProfile   protocol.TrustedInputProfile
}

// Check contains only fixed, credential-free diagnostic text.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Usage is the safe normalized accounting result for one successful probe.
type Usage struct {
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	TotalTokens         int64 `json:"total_tokens"`
	ReportedCostNanoUSD int64 `json:"reported_cost_nano_usd,omitempty"`
}

// Report intentionally omits the base URL, model, credential, and all provider
// response bodies. A caller may persist this value without persisting secrets.
type Report struct {
	Passed                bool    `json:"passed"`
	Mode                  string  `json:"mode"`
	CostVerification      string  `json:"cost_verification"`
	MaximumCostNanoUSD    int64   `json:"maximum_cost_nano_usd,omitempty"`
	CalculatedCostNanoUSD int64   `json:"calculated_cost_nano_usd,omitempty"`
	ReportedCostNanoUSD   int64   `json:"reported_cost_nano_usd,omitempty"`
	NonStreaming          Usage   `json:"non_streaming"`
	Streaming             Usage   `json:"streaming"`
	Checks                []Check `json:"checks"`
}

// Error is a stable, body-free failure. Provider payloads and transport error
// strings never cross this boundary.
type Error struct{ Code string }

func (e *Error) Error() string { return "provider verification failed: " + e.Code }

type target interface {
	Do(context.Context, *http.Request, string, []byte, func(*http.Response) error) error
	Close()
}

type targetFactory func(string, upstream.Timeouts, upstream.Resolver) (target, error)

// Verifier owns no durable state and is safe for concurrent use.
type Verifier struct {
	resolver     upstream.Resolver
	newTarget    targetFactory
	totalTimeout time.Duration
	now          func() time.Time
}

// New constructs the production verifier. Its transport uses the production
// DNS-rebinding-resistant upstream.Target, blocks private/link-local addresses,
// requires TLS, disables redirects, and does not honor environment proxies.
func New() *Verifier {
	return &Verifier{newTarget: newProtectedTarget, totalTimeout: defaultTotalTimeout, now: time.Now}
}

// Verify runs key/model discovery where applicable, then bounded non-streaming,
// streaming, and error-normalization probes under one 45-second deadline.
func (v *Verifier) Verify(ctx context.Context, request Request) (Report, error) {
	mode, baseURL, err := validateRequest(request)
	if err != nil {
		return Report{}, safeError("invalid_request")
	}
	if v == nil || v.newTarget == nil || v.now == nil || v.totalTimeout <= 0 || ctx == nil {
		return Report{}, safeError("invalid_verifier")
	}
	runCtx, cancel := context.WithTimeout(ctx, minDuration(v.totalTimeout, defaultTotalTimeout))
	defer cancel()

	transport, err := v.newTarget(baseURL, upstream.Timeouts{
		Connect: defaultConnectTimeout, TLSHandshake: defaultConnectTimeout,
		ResponseHeader: defaultHeaderTimeout, IdleConnection: 30 * time.Second,
	}, v.resolver)
	if err != nil || transport == nil {
		return Report{}, safeError("protected_target")
	}
	defer transport.Close()

	var callbackMu sync.Mutex
	called := false
	sourceReturned := false
	var report Report
	var operationErr error
	sourceErr := request.Credential(runCtx, func(credential []byte) error {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if sourceReturned {
			return nil
		}
		if called || !validBearerCredential(credential) {
			operationErr = safeError("credential_unavailable")
			return nil
		}
		called = true
		material := append([]byte(nil), credential...)
		defer func() {
			for index := range material {
				material[index] = 0
			}
		}()
		report, operationErr = v.verify(runCtx, transport, request, mode, material)
		// Deliberately do not return an operational error through the credential
		// owner, because an implementation might log callback errors.
		return nil
	})
	callbackMu.Lock()
	sourceReturned = true
	callbackCalled := called
	result := report
	resultErr := operationErr
	callbackMu.Unlock()
	if sourceErr != nil || !callbackCalled {
		return Report{}, safeError("credential_unavailable")
	}
	if resultErr != nil {
		return Report{}, resultErr
	}
	return result, nil
}

func (v *Verifier) verify(ctx context.Context, transport target, request Request, mode string, credential []byte) (Report, error) {
	report := Report{Mode: mode, CostVerification: CostUnverified, Checks: make([]Check, 0, 8)}
	var rates pricing.Rates
	var maximumCost int64
	profile := request.InputProfile
	if mode == ModeOpenRouter {
		report.Checks = append(report.Checks, passed("target", "The canonical OpenRouter HTTPS target passed protected destination validation."))
		modelMetadata, err := fetchOpenRouterModel(ctx, transport, credential, request.Model)
		if err != nil {
			return Report{}, safeError("model_pricing")
		}
		rates = modelMetadata.Rates
		if profile == (protocol.TrustedInputProfile{}) {
			profile = conservativeProfile(request.Model, modelMetadata.ContextTokens)
		}
		report.Checks = append(report.Checks, passed("model_pricing", "Exact selected-model pricing and context metadata were validated."))
	} else {
		report.Checks = append(report.Checks, passed("target", "The generic HTTPS target passed protected destination validation."))
		if profile == (protocol.TrustedInputProfile{}) {
			profile = conservativeProfile(request.Model, minimumContextTokens)
		}
	}

	nonStreaming, err := prepareProbe(ctx, request.Model, profile, false, mode, rates)
	if err != nil {
		return Report{}, safeError("input_preflight")
	}
	streaming, err := prepareProbe(ctx, request.Model, profile, true, mode, rates)
	if err != nil {
		return Report{}, safeError("input_preflight")
	}
	if mode == ModeOpenRouter {
		maximumCost, err = addCosts(nonStreaming.MaximumCostNanoUSD, streaming.MaximumCostNanoUSD)
		if err != nil || maximumCost > request.MaxCostNanoUSD {
			return Report{}, safeError("cost_ceiling")
		}
		if err := verifyOpenRouterKey(ctx, transport, credential, maximumCost, v.now().UTC()); err != nil {
			return Report{}, safeError("key_information")
		}
		report.CostVerification = CostVerified
		report.MaximumCostNanoUSD = maximumCost
		report.Checks = append(report.Checks,
			passed("key_information", "The key is inference-capable, current, and has sufficient declared credit."),
			passed("input_preflight", "Both exact request bodies passed model-bound conservative input accounting and a one-token output clamp."),
			passed("cost_preflight", "The two-request worst-case cost was proved below the operator ceiling before dispatch."),
		)
	} else {
		report.Checks = append(report.Checks,
			passed("input_preflight", "Both exact request bodies passed model-bound conservative input accounting and a one-token output clamp."),
			passed("cost_preflight", "No trusted generic price source was supplied; monetary cost remains explicitly unverified."),
		)
	}

	nonUsage, err := dispatchProbe(ctx, transport, credential, nonStreaming)
	if err != nil {
		return Report{}, safeError("non_streaming")
	}
	streamUsage, err := dispatchProbe(ctx, transport, credential, streaming)
	if err != nil {
		return Report{}, safeError("streaming")
	}
	if err := validateUsage(nonUsage, nonStreaming); err != nil {
		return Report{}, safeError("usage")
	}
	if err := validateUsage(streamUsage, streaming); err != nil {
		return Report{}, safeError("usage")
	}
	report.NonStreaming = safeUsage(nonUsage)
	report.Streaming = safeUsage(streamUsage)
	report.Checks = append(report.Checks,
		passed("non_streaming", "A bounded non-streaming response supplied consistent final usage."),
		passed("streaming", "A bounded SSE stream terminated with consistent final-frame usage."),
	)

	if mode == ModeOpenRouter {
		calculated, reported, err := reconcileCosts(rates, nonUsage, streamUsage)
		if err != nil || calculated > maximumCost || reported > calculated || reported > request.MaxCostNanoUSD {
			return Report{}, safeError("cost_reconciliation")
		}
		report.CalculatedCostNanoUSD = calculated
		report.ReportedCostNanoUSD = reported
		report.Checks = append(report.Checks, passed("cost_reconciliation", "Provider-reported cost was exact and did not exceed the trusted calculated bound."))
	} else if invalidPresentCost(nonUsage) || invalidPresentCost(streamUsage) {
		return Report{}, safeError("usage")
	}

	if err := probeErrorNormalization(ctx, transport, credential); err != nil {
		return Report{}, safeError("error_normalization")
	}
	report.Checks = append(report.Checks, passed("error_normalization", "A malformed request produced a bounded body-free provider rejection class."))
	report.Passed = true
	return report, nil
}

func validateRequest(request Request) (string, string, error) {
	if request.Credential == nil || len(request.Model) == 0 || len(request.Model) > maximumModelBytes ||
		strings.TrimSpace(request.Model) != request.Model || strings.ContainsAny(request.Model, "\x00\r\n") {
		return "", "", errors.New("invalid")
	}
	switch request.Mode {
	case ModeOpenRouter:
		if request.BaseURL != "" && request.BaseURL != openRouterBaseURL {
			return "", "", errors.New("invalid")
		}
		if !openRouterModelPattern.MatchString(request.Model) || request.MaxCostNanoUSD < 1 || request.MaxCostNanoUSD > maximumMaxCostNanoUSD {
			return "", "", errors.New("invalid")
		}
		return ModeOpenRouter, openRouterBaseURL, nil
	case ModeOpenAIChat:
		if request.MaxCostNanoUSD != 0 || validateProductionHTTPS(request.BaseURL) != nil {
			return "", "", errors.New("invalid")
		}
		return ModeOpenAIChat, request.BaseURL, nil
	default:
		return "", "", errors.New("invalid")
	}
}

func validBearerCredential(credential []byte) bool {
	if len(credential) == 0 || len(credential) > maximumCredentialBytes || credential[0] == '=' {
		return false
	}
	padding := false
	for _, character := range credential {
		if character == '=' {
			padding = true
			continue
		}
		if padding || !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("-._~+/", rune(character))) {
			return false
		}
	}
	return true
}

func validateProductionHTTPS(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return errors.New("HTTPS origin required")
	}
	return upstream.ValidateDestination(raw, upstream.DestinationPolicy{})
}

type protectedTarget struct{ value *upstream.Target }

func newProtectedTarget(raw string, timeouts upstream.Timeouts, resolver upstream.Resolver) (target, error) {
	if err := validateProductionHTTPS(raw); err != nil {
		return nil, err
	}
	value, err := upstream.NewTarget(raw, upstream.DestinationPolicy{}, timeouts, resolver)
	if err != nil {
		return nil, err
	}
	return &protectedTarget{value: value}, nil
}

func (t *protectedTarget) Do(ctx context.Context, incoming *http.Request, path string, credential []byte, consume func(*http.Response) error) error {
	prepared, err := upstream.PrepareRequest(incoming, t.value, path, []string{"Accept", "Content-Type"}, nil)
	if err != nil {
		return errors.New("prepare failed")
	}
	var consumeErr error
	err = t.value.WithBearerDispatch(ctx, prepared, credential, func(response *upstream.DispatchedResponse) error {
		consumeErr = consume(response.Response)
		return nil
	})
	if err != nil || consumeErr != nil {
		return errors.New("dispatch failed")
	}
	return nil
}

func (t *protectedTarget) Close() { t.value.CloseIdleConnections() }

type preparedProbe struct {
	Request            *http.Request
	Adapter            openaichat.Adapter
	InputMaximum       int64
	OutputMaximum      int64
	TotalMaximum       int64
	MaximumCostNanoUSD int64
}

func prepareProbe(ctx context.Context, model string, profile protocol.TrustedInputProfile, stream bool, mode string, rates pricing.Rates) (preparedProbe, error) {
	body, err := json.Marshal(map[string]any{
		"model": model, "messages": []map[string]string{{"role": "user", "content": "Reply with OK."}},
		"stream": stream, "max_tokens": 1,
	})
	if err != nil {
		return preparedProbe{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://latchway.invalid/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return preparedProbe{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	adapter := openaichat.Adapter{MaximumBodyBytes: 64 << 10}
	applied, err := adapter.ApplyFeature(ctx, request, protocol.FeatureDecision{
		PhysicalModel: model, DefaultOutputTokens: 1, MaximumOutputTokens: 1,
	})
	if err != nil || applied != 1 {
		return preparedProbe{}, errors.New("clamp")
	}
	preflight, err := adapter.PreflightInput(ctx, request, profile)
	if err != nil || preflight.OutputTokenBound != 1 {
		return preparedProbe{}, errors.New("preflight")
	}
	if mode == ModeOpenRouter {
		preflight, err = applyOpenRouterPriceBoundary(request, profile, rates)
		if err != nil {
			return preparedProbe{}, err
		}
	}
	probe := preparedProbe{Request: request, Adapter: adapter, InputMaximum: preflight.InputTokenBound, OutputMaximum: 1, TotalMaximum: preflight.TotalTokenBound}
	if mode == ModeOpenRouter {
		result, err := calculateCost(rates, preflight.InputTokenBound, 1)
		if err != nil {
			return preparedProbe{}, err
		}
		probe.MaximumCostNanoUSD = result
	}
	return probe, nil
}

// applyOpenRouterPriceBoundary extends the adapter-approved text-only body
// with routing controls whose bytes are included in the same conservative
// one-byte-per-token proof. OpenRouter documents max_price in USD/million.
func applyOpenRouterPriceBoundary(request *http.Request, profile protocol.TrustedInputProfile, rates pricing.Rates) (protocol.TrustedInputPreflight, error) {
	raw, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return protocol.TrustedInputPreflight{}, errors.New("body")
	}
	value, err := jsonsafe.Decode(raw)
	root, ok := value.(map[string]any)
	if err != nil || !ok {
		return protocol.TrustedInputPreflight{}, errors.New("body")
	}
	root["provider"] = map[string]any{
		"sort": "price", "allow_fallbacks": false, "require_parameters": true,
		"max_price": map[string]any{
			"prompt":     json.Number(formatNanoUSD(rates.InputNanoUSDPerMillion)),
			"completion": json.Number(formatNanoUSD(rates.OutputNanoUSDPerMillion)),
			"request":    json.Number(formatNanoUSD(rates.RequestNanoUSD)),
		},
	}
	body, err := json.Marshal(root)
	if err != nil || len(body) > 64<<10 {
		return protocol.TrustedInputPreflight{}, errors.New("body")
	}
	input, err := boundedInput(profile, int64(len(body)), 1)
	if err != nil {
		return protocol.TrustedInputPreflight{}, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return protocol.TrustedInputPreflight{InputTokenBound: input, OutputTokenBound: 1, TotalTokenBound: input + 1}, nil
}

func conservativeProfile(model string, contextTokens int64) protocol.TrustedInputProfile {
	if contextTokens < minimumContextTokens {
		contextTokens = minimumContextTokens
	}
	return protocol.TrustedInputProfile{
		ID: "ephemeral-openai-chat", Protocol: protocol.OpenAIChatID,
		Method: protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1, PhysicalModel: model,
		MaximumFramingTokensPerRequest: conservativeFraming,
		MaximumFramingTokensPerMessage: conservativeFraming,
		MaximumContextTokens:           contextTokens,
	}
}

func boundedInput(profile protocol.TrustedInputProfile, requestBytes, messageCount int64) (int64, error) {
	if profile.Protocol != protocol.OpenAIChatID || profile.Method != protocol.TrustedInputMethodUTF8ByteBPEDeclaredFramingV1 ||
		profile.MaximumFramingTokensPerRequest < 0 || profile.MaximumFramingTokensPerMessage < 0 || profile.MaximumContextTokens <= 0 ||
		requestBytes < 0 || messageCount < 0 || messageCount > math.MaxInt64/maxInt64(1, profile.MaximumFramingTokensPerMessage) {
		return 0, errors.New("profile")
	}
	framing := messageCount * profile.MaximumFramingTokensPerMessage
	if requestBytes > math.MaxInt64-profile.MaximumFramingTokensPerRequest || requestBytes+profile.MaximumFramingTokensPerRequest > math.MaxInt64-framing {
		return 0, errors.New("profile")
	}
	input := requestBytes + profile.MaximumFramingTokensPerRequest + framing
	if input >= profile.MaximumContextTokens {
		return 0, errors.New("context")
	}
	return input, nil
}

func dispatchProbe(ctx context.Context, transport target, credential []byte, probe preparedProbe) (protocol.Usage, error) {
	var usage protocol.Usage
	err := transport.Do(ctx, probe.Request, protocol.OpenAIChatProviderPath, credential, func(response *http.Response) error {
		if response == nil || response.Body == nil || response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > maximumResponseBytes {
			return errors.New("response")
		}
		observer, err := probe.Adapter.ObserveResponse(ctx, response)
		if err != nil {
			return errors.New("response")
		}
		buffer := make([]byte, 32<<10)
		var total int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			count, readErr := response.Body.Read(buffer)
			total += int64(count)
			if total > maximumResponseBytes {
				return errors.New("body")
			}
			if count > 0 {
				if err := observer.Observe(buffer[:count]); err != nil {
					return errors.New("response")
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return errors.New("body")
			}
		}
		usage, err = observer.Finalize()
		if err != nil {
			return errors.New("response")
		}
		return nil
	})
	return usage, err
}

func validateUsage(usage protocol.Usage, probe preparedProbe) error {
	if !usage.Known || usage.InputTokens <= 0 || usage.OutputTokens < 0 || usage.InputTokens > probe.InputMaximum ||
		usage.OutputTokens > probe.OutputMaximum || usage.InputTokens > math.MaxInt64-usage.OutputTokens ||
		usage.TotalTokens != usage.InputTokens+usage.OutputTokens || usage.TotalTokens > probe.TotalMaximum {
		return errors.New("usage")
	}
	return nil
}

func probeErrorNormalization(ctx context.Context, transport target, credential []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://latchway.invalid/v1/chat/completions", strings.NewReader(`{"model":}`))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	return transport.Do(ctx, request, protocol.OpenAIChatProviderPath, credential, func(response *http.Response) error {
		if response == nil || response.Body == nil || response.StatusCode < 400 || response.StatusCode >= 500 || response.ContentLength > maximumMetadataBytes {
			return errors.New("normalization")
		}
		count, err := io.Copy(io.Discard, io.LimitReader(response.Body, maximumMetadataBytes+1))
		if err != nil || count > maximumMetadataBytes {
			return errors.New("normalization")
		}
		return nil
	})
}

func safeUsage(value protocol.Usage) Usage {
	result := Usage{InputTokens: value.InputTokens, OutputTokens: value.OutputTokens, TotalTokens: value.TotalTokens}
	if value.ReportedCost.Present && value.ReportedCost.Known {
		result.ReportedCostNanoUSD = value.ReportedCost.NanoUSD
	}
	return result
}

func invalidPresentCost(value protocol.Usage) bool {
	return value.ReportedCost.Present && !value.ReportedCost.Known
}

func reconcileCosts(rates pricing.Rates, usages ...protocol.Usage) (int64, int64, error) {
	var calculated, reported int64
	for _, usage := range usages {
		if !usage.ReportedCost.Present || !usage.ReportedCost.Known {
			return 0, 0, errors.New("cost")
		}
		value, err := calculateCost(rates, usage.InputTokens, usage.OutputTokens)
		if err != nil {
			return 0, 0, err
		}
		calculated, err = addCosts(calculated, value)
		if err != nil {
			return 0, 0, err
		}
		reported, err = addCosts(reported, usage.ReportedCost.NanoUSD)
		if err != nil {
			return 0, 0, err
		}
	}
	return calculated, reported, nil
}

func calculateCost(rates pricing.Rates, input, output int64) (int64, error) {
	source, err := pricing.NewSource("ephemeral-openrouter", "rev_00000000000000000000000000")
	if err != nil {
		return 0, err
	}
	result, err := pricing.Calculate(rates, pricing.Usage{InputTokens: input, OutputTokens: output}, source)
	if err != nil || !result.Known() {
		return 0, errors.New("cost")
	}
	return result.CostNanoUSD(), nil
}

func addCosts(left, right int64) (int64, error) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, errors.New("overflow")
	}
	return left + right, nil
}

func formatNanoUSD(value int64) string {
	integer := value / 1_000_000_000
	fraction := value % 1_000_000_000
	if fraction == 0 {
		return fmt.Sprintf("%d", integer)
	}
	return fmt.Sprintf("%d.%s", integer, strings.TrimRight(fmt.Sprintf("%09d", fraction), "0"))
}

func passed(name, detail string) Check { return Check{Name: name, Passed: true, Detail: detail} }

func safeError(code string) error { return &Error{Code: code} }

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
