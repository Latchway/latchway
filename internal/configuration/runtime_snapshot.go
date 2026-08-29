package configuration

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/jsonsafe"
	"github.com/latchway/latchway/internal/protocol"
	upstreamtarget "github.com/latchway/latchway/internal/upstream"
)

var (
	runtimeIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	runtimeSecretRefPattern  = regexp.MustCompile(`^secret/[a-z][a-z0-9_-]{0,62}$`)
	runtimeHeaderNamePattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
)

var runtimeRetryConditions = []string{
	"connect_error",
	"timeout_before_headers",
	"first_byte_timeout",
	"status_408",
	"status_429",
	"status_500",
	"status_502",
	"status_503",
	"status_504",
}

const (
	maximumInputAccountingProfiles = 256
	// inputAccountingProtocol remains the original Chat protocol alias for
	// fixtures compiled before structured-protocol accounting was expanded.
	inputAccountingProtocol = "openai_chat"
	inputAccountingMethod   = "utf8_byte_bpe_declared_framing_v1"
)

type compiledUpstream struct {
	ID                         string                         `json:"id"`
	Type                       string                         `json:"type"`
	BaseURL                    string                         `json:"baseUrl"`
	DangerousAllowInsecureHTTP bool                           `json:"dangerousAllowInsecureHttp"`
	Authentication             compiledUpstreamAuthentication `json:"authentication"`
	Timeouts                   compiledUpstreamTimeouts       `json:"timeouts"`
	DestinationPolicy          struct {
		AllowedPorts         []int    `json:"allowedPorts"`
		AllowRedirects       bool     `json:"allowRedirects"`
		AllowPrivateNetworks bool     `json:"allowPrivateNetworks"`
		AllowedCIDRs         []string `json:"allowedCidrs"`
		DNSPinning           bool     `json:"dnsPinning"`
	} `json:"destinationPolicy"`
	StaticHeaders        map[string]string `json:"staticHeaders"`
	ProviderReportedCost *struct {
		Source   string `json:"source"`
		Currency string `json:"currency"`
	} `json:"providerReportedCost,omitempty"`
}

type compiledUpstreamAuthentication struct {
	Type          string
	SecretRef     string
	HeaderName    string
	Username      string
	Headers       []compiledAuthenticationHeader
	hasSecretRef  bool
	hasHeaderName bool
	hasUsername   bool
	hasHeaders    bool
}

type compiledAuthenticationHeader struct {
	HeaderName string
	SecretRef  string
}

func (authentication *compiledUpstreamAuthentication) UnmarshalJSON(encoded []byte) error {
	*authentication = compiledUpstreamAuthentication{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"type": {}, "secretRef": {}, "headerName": {}, "username": {}, "headers": {},
	})
	if err != nil {
		return err
	}
	if _, ok := fields["type"]; !ok {
		return ErrInvalid
	}
	if authentication.Type, err = compiledJSONString(fields["type"]); err != nil {
		return err
	}
	for name, target := range map[string]*string{
		"secretRef":  &authentication.SecretRef,
		"headerName": &authentication.HeaderName,
		"username":   &authentication.Username,
	} {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		if *target, err = compiledJSONString(raw); err != nil {
			return err
		}
		switch name {
		case "secretRef":
			authentication.hasSecretRef = true
		case "headerName":
			authentication.hasHeaderName = true
		case "username":
			authentication.hasUsername = true
		}
	}
	if raw, ok := fields["headers"]; ok {
		authentication.hasHeaders = true
		if err := json.Unmarshal(raw, &authentication.Headers); err != nil || authentication.Headers == nil {
			return ErrInvalid
		}
	}
	return nil
}

func (header *compiledAuthenticationHeader) UnmarshalJSON(encoded []byte) error {
	*header = compiledAuthenticationHeader{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{"headerName": {}, "secretRef": {}})
	if err != nil {
		return err
	}
	if len(fields) != 2 {
		return ErrInvalid
	}
	if header.HeaderName, err = compiledJSONString(fields["headerName"]); err != nil {
		return err
	}
	if header.SecretRef, err = compiledJSONString(fields["secretRef"]); err != nil {
		return err
	}
	return nil
}

type compiledUpstreamTimeouts struct {
	Connect           string
	ResponseHeader    string
	FirstByte         string
	Idle              string
	Total             string
	hasResponseHeader bool
}

func (timeouts *compiledUpstreamTimeouts) UnmarshalJSON(encoded []byte) error {
	*timeouts = compiledUpstreamTimeouts{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"connect": {}, "responseHeader": {}, "firstByte": {}, "idle": {}, "total": {},
	})
	if err != nil {
		return err
	}
	for name, target := range map[string]*string{
		"connect": &timeouts.Connect, "firstByte": &timeouts.FirstByte,
		"idle": &timeouts.Idle, "total": &timeouts.Total,
	} {
		raw, ok := fields[name]
		if !ok {
			return ErrInvalid
		}
		if *target, err = compiledJSONString(raw); err != nil {
			return err
		}
	}
	if raw, ok := fields["responseHeader"]; ok {
		timeouts.hasResponseHeader = true
		if timeouts.ResponseHeader, err = compiledJSONString(raw); err != nil {
			return err
		}
	}
	return nil
}

type compiledModel struct {
	ID                    string   `json:"id"`
	UpstreamID            string   `json:"upstream"`
	UpstreamModel         string   `json:"upstreamModel"`
	PricingRef            string   `json:"pricingRef,omitempty"`
	InputAccountingRef    string   `json:"inputAccountingRef,omitempty"`
	Capabilities          []string `json:"capabilities"`
	hasPricingRef         bool     `json:"-"`
	hasInputAccountingRef bool     `json:"-"`
}

func (model *compiledModel) UnmarshalJSON(encoded []byte) error {
	*model = compiledModel{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"id": {}, "upstream": {}, "upstreamModel": {}, "pricingRef": {},
		"inputAccountingRef": {}, "capabilities": {},
	})
	if err != nil {
		return err
	}
	for _, required := range []string{"id", "upstream", "upstreamModel", "capabilities"} {
		if _, ok := fields[required]; !ok {
			return ErrInvalid
		}
	}
	if model.ID, err = compiledJSONString(fields["id"]); err != nil {
		return err
	}
	if model.UpstreamID, err = compiledJSONString(fields["upstream"]); err != nil {
		return err
	}
	if model.UpstreamModel, err = compiledJSONString(fields["upstreamModel"]); err != nil {
		return err
	}
	if raw, ok := fields["pricingRef"]; ok {
		model.hasPricingRef = true
		if model.PricingRef, err = compiledJSONString(raw); err != nil {
			return err
		}
	}
	if raw, ok := fields["inputAccountingRef"]; ok {
		model.hasInputAccountingRef = true
		if model.InputAccountingRef, err = compiledJSONString(raw); err != nil {
			return err
		}
	}
	trimmedCapabilities := bytes.TrimSpace(fields["capabilities"])
	if len(trimmedCapabilities) == 0 || trimmedCapabilities[0] != '[' ||
		json.Unmarshal(trimmedCapabilities, &model.Capabilities) != nil {
		return ErrInvalid
	}
	return nil
}

type compiledInputAccountingProfile struct {
	InputAccountingProfile
}

func (profile *compiledInputAccountingProfile) UnmarshalJSON(encoded []byte) error {
	*profile = compiledInputAccountingProfile{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"id": {}, "protocol": {}, "method": {}, "physicalModel": {},
		"maximumFramingTokensPerRequest": {}, "maximumFramingTokensPerMessage": {},
		"maximumContextTokens": {},
	})
	if err != nil {
		return err
	}
	for _, required := range []string{
		"id", "protocol", "method", "physicalModel",
		"maximumFramingTokensPerRequest", "maximumFramingTokensPerMessage", "maximumContextTokens",
	} {
		if _, ok := fields[required]; !ok {
			return ErrInvalid
		}
	}
	if profile.ID, err = compiledJSONString(fields["id"]); err != nil {
		return err
	}
	if profile.Protocol, err = compiledJSONString(fields["protocol"]); err != nil {
		return err
	}
	if profile.Method, err = compiledJSONString(fields["method"]); err != nil {
		return err
	}
	if profile.PhysicalModel, err = compiledJSONString(fields["physicalModel"]); err != nil {
		return err
	}
	var ok bool
	profile.MaximumFramingTokensPerRequest, ok = compiledLimitInteger(fields["maximumFramingTokensPerRequest"], true)
	if !ok {
		return ErrInvalid
	}
	profile.MaximumFramingTokensPerMessage, ok = compiledLimitInteger(fields["maximumFramingTokensPerMessage"], true)
	if !ok {
		return ErrInvalid
	}
	profile.MaximumContextTokens, ok = compiledLimitInteger(fields["maximumContextTokens"], true)
	if !ok {
		return ErrInvalid
	}
	return nil
}

func strictRuntimeObject(encoded []byte, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		return nil, ErrInvalid
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	for field := range object {
		if _, ok := allowed[field]; !ok {
			return nil, ErrInvalid
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || fields == nil {
		return nil, ErrInvalid
	}
	return fields, nil
}

func compiledJSONString(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", ErrInvalid
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", ErrInvalid
	}
	return value, nil
}

type compiledLimitPlan struct {
	ID     string          `json:"id"`
	Limits []compiledLimit `json:"limits"`
}

// compiledLimit retains field presence so the active-snapshot boundary can
// independently enforce exact algorithm shapes. Relying only on zero values
// would make an omitted field indistinguishable from a corrupt explicit zero
// or null in compiled JSON.
type compiledLimit struct {
	Limit
	hasWindow            bool
	hasTimezone          bool
	hasMaximum           bool
	hasPerRequestMaximum bool
	hasCapacity          bool
	hasRefillPerSecond   bool
}

func (limit *compiledLimit) UnmarshalJSON(encoded []byte) error {
	*limit = compiledLimit{}
	decodedValue, err := jsonsafe.Decode(encoded)
	if err != nil {
		return ErrInvalid
	}
	if _, ok := decodedValue.(map[string]any); !ok {
		return ErrInvalid
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return err
	}
	for field := range fields {
		switch field {
		case "metric", "algorithm", "scope", "window", "timezone", "maximum", "perRequestMaximum", "capacity", "refillPerSecond", "hard":
		default:
			return ErrInvalid
		}
	}
	var decoded struct {
		Metric    string   `json:"metric"`
		Algorithm string   `json:"algorithm"`
		Scope     []string `json:"scope"`
		Window    string   `json:"window"`
		Timezone  string   `json:"timezone"`
		Hard      bool     `json:"hard"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	_, limit.hasWindow = fields["window"]
	_, limit.hasTimezone = fields["timezone"]
	_, limit.hasMaximum = fields["maximum"]
	_, limit.hasPerRequestMaximum = fields["perRequestMaximum"]
	_, limit.hasCapacity = fields["capacity"]
	_, limit.hasRefillPerSecond = fields["refillPerSecond"]
	maximum, ok := compiledLimitInteger(fields["maximum"], limit.hasMaximum)
	if !ok {
		return ErrInvalid
	}
	perRequestMaximum, ok := compiledLimitInteger(fields["perRequestMaximum"], limit.hasPerRequestMaximum)
	if !ok {
		return ErrInvalid
	}
	capacity, ok := compiledLimitInteger(fields["capacity"], limit.hasCapacity)
	if !ok {
		return ErrInvalid
	}
	refillPerSecond, ok := compiledLimitRefillRate(fields["refillPerSecond"], limit.hasRefillPerSecond)
	if !ok {
		return ErrInvalid
	}
	limit.Limit = Limit{
		Metric: decoded.Metric, Algorithm: decoded.Algorithm,
		Scope: append([]string(nil), decoded.Scope...), Window: decoded.Window, Timezone: decoded.Timezone,
		Maximum: maximum, PerRequestMaximum: perRequestMaximum,
		Capacity: capacity, RefillPerSecond: refillPerSecond,
		Hard: decoded.Hard,
	}
	return nil
}

func compiledLimitInteger(raw json.RawMessage, present bool) (int64, bool) {
	if !present {
		return 0, true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || (trimmed[0] != '-' && !isASCIIDigit(trimmed[0])) {
		return 0, false
	}
	return parseJSONInteger(json.Number(trimmed))
}

func compiledLimitRefillRate(raw json.RawMessage, present bool) (RefillRate, bool) {
	if !present {
		return RefillRate{}, true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || !isASCIIDigit(trimmed[0]) {
		return RefillRate{}, false
	}
	rate, ok := parseJSONRefillRate(json.Number(trimmed))
	if !ok || string(trimmed) != rate.String() {
		return RefillRate{}, false
	}
	return rate, true
}

func (limit compiledLimit) normalizeExecutable() (Limit, immutableLimitIdentity, bool) {
	switch limit.Algorithm {
	case "calendar":
		if !limit.hasWindow || !limit.hasMaximum || limit.hasPerRequestMaximum ||
			limit.hasCapacity || limit.hasRefillPerSecond || limit.hasTimezone && limit.Timezone == "" {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "token_bucket":
		if !limit.hasCapacity || !limit.hasRefillPerSecond || limit.hasWindow || limit.hasTimezone ||
			limit.hasMaximum || limit.hasPerRequestMaximum {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "per_request":
		if !limit.hasPerRequestMaximum || limit.hasWindow || limit.hasTimezone || limit.hasMaximum ||
			limit.hasCapacity || limit.hasRefillPerSecond {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "concurrency":
		if !limit.hasMaximum || limit.hasWindow || limit.hasTimezone || limit.hasPerRequestMaximum ||
			limit.hasCapacity || limit.hasRefillPerSecond {
			return Limit{}, immutableLimitIdentity{}, false
		}
	default:
		return Limit{}, immutableLimitIdentity{}, false
	}
	return normalizeExecutableLimit(limit.Limit)
}

type compiledFeature struct {
	ID                  string `json:"id"`
	Protocol            string `json:"protocol"`
	AttestationPolicyID string `json:"attestationPolicy"`
	Access              struct {
		Expression string `json:"expression"`
	} `json:"access"`
	LimitPlan struct {
		Expression string `json:"expression"`
	} `json:"limitPlan"`
	Output *struct {
		DefaultMaximumTokens  int64 `json:"defaultMaximumTokens"`
		AbsoluteMaximumTokens int64 `json:"absoluteMaximumTokens"`
	} `json:"output"`
	Routes []struct {
		ID                        string                 `json:"id"`
		When                      string                 `json:"when"`
		ModelID                   string                 `json:"model"`
		Priority                  int64                  `json:"priority"`
		Weight                    int64                  `json:"weight"`
		StickyBy                  string                 `json:"stickyBy"`
		FallbackOn                []string               `json:"fallbackOn"`
		RetryPolicy               *compiledRetryPolicy   `json:"retryPolicy"`
		MaximumRequestBodyBytes   int64                  `json:"maxRequestBodyBytes"`
		MaximumRequestHeaderBytes int64                  `json:"maxRequestHeaderBytes"`
		MaximumResponseBytes      int64                  `json:"maxResponseBytes"`
		Timeouts                  *compiledRouteTimeouts `json:"timeouts"`
		StreamingAllowed          bool                   `json:"streamingAllowed"`
		RetryUnsafeMethods        bool                   `json:"retryUnsafeMethods"`
	} `json:"routes"`
	OpaqueHTTP *struct {
		AllowedMethods        []string `json:"allowedMethods"`
		PathPrefixes          []string `json:"pathPrefixes"`
		MaximumBodyBytes      int64    `json:"maxBodyBytes"`
		AllowedRequestHeaders []string `json:"allowedRequestHeaders"`
	} `json:"opaqueHttp"`
}

type compiledRetryPolicy struct {
	MaxAttempts                int64    `json:"maxAttempts"`
	InitialBackoffMilliseconds int64    `json:"initialBackoffMilliseconds"`
	MaximumBackoffMilliseconds int64    `json:"maximumBackoffMilliseconds"`
	JitterRatio                float64  `json:"jitterRatio"`
	RetryOn                    []string `json:"retryOn"`
}

type compiledRouteTimeouts struct {
	Connect           string `json:"connect"`
	ResponseHeader    string `json:"responseHeader"`
	FirstByte         string `json:"firstByte"`
	Idle              string `json:"idle"`
	Total             string `json:"total"`
	hasConnect        bool
	hasResponseHeader bool
	hasFirstByte      bool
	hasIdle           bool
	hasTotal          bool
}

func (timeouts *compiledRouteTimeouts) UnmarshalJSON(encoded []byte) error {
	*timeouts = compiledRouteTimeouts{}
	fields, err := strictRuntimeObject(encoded, map[string]struct{}{
		"connect": {}, "responseHeader": {}, "firstByte": {}, "idle": {}, "total": {},
	})
	if err != nil || len(fields) == 0 {
		return ErrInvalid
	}
	for name, target := range map[string]*string{
		"connect": &timeouts.Connect, "responseHeader": &timeouts.ResponseHeader,
		"firstByte": &timeouts.FirstByte, "idle": &timeouts.Idle, "total": &timeouts.Total,
	} {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		if *target, err = compiledJSONString(raw); err != nil {
			return err
		}
		switch name {
		case "connect":
			timeouts.hasConnect = true
		case "responseHeader":
			timeouts.hasResponseHeader = true
		case "firstByte":
			timeouts.hasFirstByte = true
		case "idle":
			timeouts.hasIdle = true
		case "total":
			timeouts.hasTotal = true
		}
	}
	return nil
}

func (snapshot *ActiveSnapshot) loadRuntimeConfiguration(
	rawUpstreams []compiledUpstream,
	rawInputAccounting []compiledInputAccountingProfile,
	rawModels []compiledModel,
	rawPricing []compiledPricingCatalog,
	rawPlans []compiledLimitPlan,
	rawFeatures []compiledFeature,
) error {
	for _, raw := range rawUpstreams {
		upstream, err := runtimeUpstream(raw)
		if err != nil || !insertUnique(snapshot.upstreams, upstream.ID, upstream) {
			return errorsCorruptSnapshot("upstream")
		}
	}
	if len(rawInputAccounting) > maximumInputAccountingProfiles {
		return errorsCorruptSnapshot("input accounting profile set")
	}
	for _, raw := range rawInputAccounting {
		profile, err := runtimeInputAccountingProfile(raw)
		if err != nil || !insertUnique(snapshot.inputAccounting, profile.ID, profile) {
			return errorsCorruptSnapshot("input accounting profile")
		}
	}
	for _, raw := range rawModels {
		model, err := runtimeModel(raw)
		if err != nil || !insertUnique(snapshot.models, model.ID, model) {
			return errorsCorruptSnapshot("model")
		}
		upstream, ok := snapshot.upstreams[model.UpstreamID]
		if !ok {
			return errorsCorruptSnapshot("model upstream reference")
		}
		for _, capability := range model.Capabilities {
			requiredType, known := protocol.RequiredUpstreamType(capability)
			if !known || upstream.Type != requiredType {
				return errorsCorruptSnapshot("model upstream protocol family")
			}
		}
		if model.InputAccountingRef != "" {
			profile, ok := snapshot.inputAccounting[model.InputAccountingRef]
			if !ok || !runtimeModelInputAccountingCompatible(model, profile) {
				return errorsCorruptSnapshot("model input accounting reference")
			}
		}
	}
	if len(rawPricing) > maximumPricingCatalogs {
		return errorsCorruptSnapshot("pricing catalog set")
	}
	for _, raw := range rawPricing {
		catalog, err := runtimePricingCatalog(raw, snapshot.models)
		if err != nil || !insertUnique(snapshot.pricing, catalog.ID, catalog) {
			return errorsCorruptSnapshot("pricing catalog")
		}
	}
	for _, model := range snapshot.models {
		if model.PricingRef == "" {
			continue
		}
		catalog, ok := snapshot.pricing[model.PricingRef]
		if !ok {
			return errorsCorruptSnapshot("model pricing reference")
		}
		if _, ok := catalog.Entry(model.ID); !ok {
			return errorsCorruptSnapshot("model pricing entry")
		}
	}
	for _, raw := range rawPlans {
		plan, err := runtimeLimitPlan(raw)
		if err != nil || !insertUnique(snapshot.limitPlans, plan.ID, plan) {
			return errorsCorruptSnapshot("limit plan")
		}
	}
	for _, raw := range rawFeatures {
		feature, err := snapshot.runtimeFeature(raw)
		if err != nil || !insertUnique(snapshot.features, feature.ID, feature) {
			return errorsCorruptSnapshot("feature")
		}
	}
	if !snapshot.runtimeQuotaAccountingValid() {
		return errorsCorruptSnapshot("quota accounting activation")
	}
	if len(snapshot.upstreams) == 0 || len(snapshot.models) == 0 || len(snapshot.limitPlans) == 0 || len(snapshot.features) == 0 {
		return errorsCorruptSnapshot("data-plane configuration")
	}
	return nil
}

// runtimeQuotaAccountingValid independently rechecks durable hard-cost
// prerequisites on persisted snapshots. Trusted input proof is deliberately
// enforced later, against the selected plan and selected route, so an
// unrelated rich or opaque feature does not prevent mixed-protocol activation.
func (snapshot ActiveSnapshot) runtimeQuotaAccountingValid() bool {
	requiresCostPricing := runtimePlansRequireCostPricing(snapshot.limitPlans)
	for _, feature := range snapshot.features {
		for _, route := range feature.Routes {
			model, ok := snapshot.models[route.ModelID]
			if !ok {
				return false
			}
			if requiresCostPricing {
				if model.PricingRef == "" {
					return false
				}
				catalog, ok := snapshot.pricing[model.PricingRef]
				if !ok {
					return false
				}
				if _, ok := catalog.Entry(model.ID); !ok {
					return false
				}
			}
		}
	}
	return true
}

func runtimePlansRequireCostPricing(plans map[string]LimitPlan) bool {
	for _, plan := range plans {
		for _, limit := range plan.Limits {
			if limit.Metric == "cost_nano_usd" {
				return true
			}
		}
	}
	return false
}

func runtimeInputAccountingProfile(raw compiledInputAccountingProfile) (InputAccountingProfile, error) {
	profile := raw.InputAccountingProfile
	if !runtimeIdentifierPattern.MatchString(profile.ID) || !inputAccountingProtocolSupported(profile.Protocol) ||
		profile.Method != inputAccountingMethod || !runtimeInputAccountingPhysicalModel(profile.PhysicalModel) ||
		profile.MaximumFramingTokensPerRequest < 0 || profile.MaximumFramingTokensPerMessage < 0 ||
		profile.MaximumContextTokens <= 0 || !inputAccountingProfileContextPossible(profile) {
		return InputAccountingProfile{}, ErrInvalid
	}
	return profile.clone(), nil
}

// inputAccountingProfileContextPossible proves that at least the smallest
// legal request for this method can fit. Counting only one placeholder body
// byte would allow profiles that activate successfully but can never preflight
// the protocol's smallest legal first message or item.
func inputAccountingProfileContextPossible(profile InputAccountingProfile) bool {
	outputTokens := int64(1)
	if profile.Protocol == protocol.OpenAIEmbeddingsID {
		outputTokens = 0
	}
	return inputAccountingContextPossible(profile, outputTokens)
}

// inputAccountingRouteContextPossible proves that the feature's largest
// server-permitted output fits alongside the protocol's exact minimal
// rewritten body and mandatory request plus first message/item framing.
func inputAccountingRouteContextPossible(
	profile InputAccountingProfile,
	absoluteMaximumOutputTokens int64,
) bool {
	if protocolRequiresOutputPolicy(profile.Protocol) && absoluteMaximumOutputTokens <= 0 {
		return false
	}
	if !protocolRequiresOutputPolicy(profile.Protocol) && absoluteMaximumOutputTokens != 0 {
		return false
	}
	return inputAccountingContextPossible(profile, absoluteMaximumOutputTokens)
}

func inputAccountingContextPossible(
	profile InputAccountingProfile,
	outputTokens int64,
) bool {
	minimalRequest, ok := minimumInputAccountingRequest(profile, outputTokens)
	if !ok {
		return false
	}
	minimalBody, err := json.Marshal(minimalRequest)
	if err != nil {
		return false
	}
	required, ok := checkedInputAccountingSum(
		profile.MaximumFramingTokensPerRequest,
		profile.MaximumFramingTokensPerMessage,
		int64(len(minimalBody)),
		outputTokens,
	)
	return ok && required <= profile.MaximumContextTokens
}

func minimumInputAccountingRequest(profile InputAccountingProfile, outputTokens int64) (map[string]any, bool) {
	switch profile.Protocol {
	case protocol.OpenAIChatID:
		return map[string]any{
			"max_tokens": outputTokens,
			"messages":   []any{map[string]any{"content": "", "role": "user"}},
			"model":      profile.PhysicalModel,
		}, outputTokens > 0
	case protocol.OpenAIResponsesID:
		return map[string]any{
			"input": "x", "max_output_tokens": outputTokens,
			"model": profile.PhysicalModel, "store": false,
		}, outputTokens > 0
	case protocol.OpenAIEmbeddingsID:
		return map[string]any{"input": "x", "model": profile.PhysicalModel}, outputTokens == 0
	case protocol.AnthropicMessagesID:
		return map[string]any{
			"max_tokens": outputTokens,
			"messages":   []any{map[string]any{"content": "x", "role": "user"}},
			"model":      profile.PhysicalModel,
		}, outputTokens > 0
	default:
		return nil, false
	}
}

func checkedInputAccountingSum(values ...int64) (int64, bool) {
	total := int64(0)
	for _, value := range values {
		if value < 0 || total > int64Max-value {
			return 0, false
		}
		total += value
	}
	return total, true
}

func runtimeInputAccountingPhysicalModel(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) == -1
}

func runtimeModelInputAccountingCompatible(model Model, profile InputAccountingProfile) bool {
	return model.InputAccountingRef == profile.ID && inputAccountingProtocolSupported(profile.Protocol) &&
		profile.Method == inputAccountingMethod && profile.PhysicalModel == model.UpstreamModel &&
		slices.Contains(model.Capabilities, profile.Protocol)
}

func inputAccountingProtocolSupported(protocolID string) bool {
	switch protocolID {
	case protocol.OpenAIChatID, protocol.OpenAIResponsesID,
		protocol.OpenAIEmbeddingsID, protocol.AnthropicMessagesID:
		return true
	default:
		return false
	}
}

func runtimeUpstream(raw compiledUpstream) (Upstream, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) ||
		!slices.Contains([]string{"openai_compatible", "anthropic", "generic"}, raw.Type) {
		return Upstream{}, ErrInvalid
	}
	parsedURL, issues := validateUpstreamURL(raw.BaseURL, "/baseUrl")
	if len(issues) != 0 || parsedURL == nil ||
		(parsedURL.Scheme == "http" && !raw.DangerousAllowInsecureHTTP) {
		return Upstream{}, ErrInvalid
	}
	authentication := UpstreamAuthentication{
		Type: raw.Authentication.Type, SecretRef: raw.Authentication.SecretRef,
		HeaderName: raw.Authentication.HeaderName, Username: raw.Authentication.Username,
	}
	for _, header := range raw.Authentication.Headers {
		authentication.Headers = append(authentication.Headers, UpstreamAuthenticationHeader{
			HeaderName: header.HeaderName, SecretRef: header.SecretRef,
		})
	}
	switch authentication.Type {
	case "none":
		if raw.Authentication.hasSecretRef || raw.Authentication.hasHeaderName ||
			raw.Authentication.hasUsername || raw.Authentication.hasHeaders {
			return Upstream{}, ErrInvalid
		}
	case "bearer":
		if !raw.Authentication.hasSecretRef || raw.Authentication.hasHeaderName ||
			raw.Authentication.hasUsername || raw.Authentication.hasHeaders ||
			!runtimeSecretRefPattern.MatchString(authentication.SecretRef) {
			return Upstream{}, ErrInvalid
		}
	case "header":
		if !raw.Authentication.hasSecretRef || !raw.Authentication.hasHeaderName ||
			raw.Authentication.hasUsername || raw.Authentication.hasHeaders ||
			!runtimeSecretRefPattern.MatchString(authentication.SecretRef) ||
			len(authentication.HeaderName) > 256 || !runtimeHeaderNamePattern.MatchString(authentication.HeaderName) ||
			runtimeCredentialHeaderForbidden(authentication.HeaderName) {
			return Upstream{}, ErrInvalid
		}
	case "basic":
		if !raw.Authentication.hasSecretRef || raw.Authentication.hasHeaderName ||
			!raw.Authentication.hasUsername || raw.Authentication.hasHeaders ||
			!runtimeSecretRefPattern.MatchString(authentication.SecretRef) ||
			!runtimeBasicUsernameValid(authentication.Username) {
			return Upstream{}, ErrInvalid
		}
	case "headers":
		if raw.Authentication.hasSecretRef || raw.Authentication.hasHeaderName ||
			raw.Authentication.hasUsername || !raw.Authentication.hasHeaders ||
			!runtimeAuthenticationHeadersValid(authentication.Headers) {
			return Upstream{}, ErrInvalid
		}
	default:
		return Upstream{}, ErrInvalid
	}
	timeouts, err := runtimeTimeouts(raw)
	if err != nil {
		return Upstream{}, err
	}
	policy := UpstreamDestinationPolicy{
		AllowedPorts:         append([]int(nil), raw.DestinationPolicy.AllowedPorts...),
		AllowRedirects:       raw.DestinationPolicy.AllowRedirects,
		AllowPrivateNetworks: raw.DestinationPolicy.AllowPrivateNetworks,
		DNSPinning:           raw.DestinationPolicy.DNSPinning,
	}
	privateCIDRs, err := configuredPrivateCIDRs(
		policy.AllowPrivateNetworks,
		append([]string(nil), raw.DestinationPolicy.AllowedCIDRs...),
	)
	if err != nil {
		return Upstream{}, ErrInvalid
	}
	policy.AllowedCIDRs = privateCIDRs
	if policy.AllowRedirects || !policy.DNSPinning || len(policy.AllowedPorts) == 0 ||
		upstreamtarget.ValidateDestination(raw.BaseURL, upstreamtarget.DestinationPolicy{
			AllowPrivate: policy.AllowPrivateNetworks,
			AllowedCIDRs: policy.AllowedCIDRs,
		}) != nil {
		return Upstream{}, ErrInvalid
	}
	seenPorts := make(map[int]struct{}, len(policy.AllowedPorts))
	for _, port := range policy.AllowedPorts {
		if port < 1 || port > 65535 {
			return Upstream{}, ErrInvalid
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return Upstream{}, ErrInvalid
		}
		seenPorts[port] = struct{}{}
	}
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if !slices.Contains(policy.AllowedPorts, mustPort(port)) {
		return Upstream{}, ErrInvalid
	}
	staticHeaders := cloneStringMap(raw.StaticHeaders)
	if len(staticHeaders) > 32 {
		return Upstream{}, ErrInvalid
	}
	seenHeaders := make(map[string]struct{}, len(staticHeaders))
	totalHeaderBytes := 0
	for name, value := range staticHeaders {
		canonical := http.CanonicalHeaderKey(name)
		totalHeaderBytes += len(canonical) + len(value)
		if !runtimeHeaderNamePattern.MatchString(name) || runtimeStaticHeaderForbidden(canonical) ||
			runtimeAuthenticationUsesHeader(authentication, canonical) ||
			!runtimeStaticHeaderValueValid(value) || totalHeaderBytes > 32<<10 {
			return Upstream{}, ErrInvalid
		}
		if _, duplicate := seenHeaders[canonical]; duplicate {
			return Upstream{}, ErrInvalid
		}
		seenHeaders[canonical] = struct{}{}
	}
	reportedCost := ProviderReportedCostPolicy{}
	if raw.ProviderReportedCost != nil {
		reportedCost = ProviderReportedCostPolicy{
			Source: raw.ProviderReportedCost.Source, Currency: raw.ProviderReportedCost.Currency,
		}
		if raw.Type != "openai_compatible" || !reportedCost.Enabled() {
			return Upstream{}, ErrInvalid
		}
	}
	return Upstream{
		ID: raw.ID, Type: raw.Type, BaseURL: raw.BaseURL,
		DangerousAllowInsecureHTTP: raw.DangerousAllowInsecureHTTP,
		Authentication:             authentication, Timeouts: timeouts,
		DestinationPolicy: policy, StaticHeaders: staticHeaders,
		ProviderReportedCost: reportedCost,
	}, nil
}

func runtimeTimeouts(raw compiledUpstream) (UpstreamTimeouts, error) {
	connect, connectErr := parsePositiveRuntimeDuration(raw.Timeouts.Connect)
	legacyFirstByte, firstByteErr := parsePositiveRuntimeDuration(raw.Timeouts.FirstByte)
	idle, idleErr := parsePositiveRuntimeDuration(raw.Timeouts.Idle)
	total, totalErr := parsePositiveRuntimeDuration(raw.Timeouts.Total)
	if connectErr != nil || firstByteErr != nil || idleErr != nil || totalErr != nil {
		return UpstreamTimeouts{}, ErrInvalid
	}
	timeouts := UpstreamTimeouts{
		Connect: connect, FirstByte: legacyFirstByte, Idle: idle, Total: total,
	}
	if raw.Timeouts.hasResponseHeader {
		responseHeader, err := parsePositiveRuntimeDuration(raw.Timeouts.ResponseHeader)
		if err != nil {
			return UpstreamTimeouts{}, ErrInvalid
		}
		timeouts.ResponseHeader = responseHeader
	} else {
		// Compiled revisions created before responseHeader existed used
		// firstByte for the transport's response-header wait and idle for the
		// first body read. Preserve that behavior when loading them.
		timeouts.ResponseHeader = legacyFirstByte
		timeouts.FirstByte = idle
	}
	if !runtimeTimeoutsValid(timeouts) {
		return UpstreamTimeouts{}, ErrInvalid
	}
	return timeouts, nil
}

func parsePositiveRuntimeDuration(value string) (time.Duration, error) {
	duration, err := parseConfigDuration(value)
	if err != nil || duration <= 0 {
		return 0, ErrInvalid
	}
	return duration, nil
}

func runtimeTimeoutsValid(timeouts UpstreamTimeouts) bool {
	return timeouts.Connect > 0 && timeouts.ResponseHeader > 0 && timeouts.FirstByte > 0 &&
		timeouts.Idle > 0 && timeouts.Total > 0 && timeouts.Total <= 10*time.Minute &&
		timeouts.Connect <= timeouts.Total && timeouts.ResponseHeader <= timeouts.Total &&
		timeouts.FirstByte <= timeouts.Total && timeouts.Idle <= timeouts.Total
}

func runtimeRouteTimeouts(raw *compiledRouteTimeouts, inherited UpstreamTimeouts) (*UpstreamTimeouts, error) {
	if raw == nil {
		return nil, nil
	}
	effective := inherited
	values := []struct {
		has    bool
		raw    string
		target *time.Duration
	}{
		{has: raw.hasConnect, raw: raw.Connect, target: &effective.Connect},
		{has: raw.hasResponseHeader, raw: raw.ResponseHeader, target: &effective.ResponseHeader},
		{has: raw.hasFirstByte, raw: raw.FirstByte, target: &effective.FirstByte},
		{has: raw.hasIdle, raw: raw.Idle, target: &effective.Idle},
		{has: raw.hasTotal, raw: raw.Total, target: &effective.Total},
	}
	for _, value := range values {
		if !value.has {
			continue
		}
		parsed, err := parsePositiveRuntimeDuration(value.raw)
		if err != nil {
			return nil, ErrInvalid
		}
		*value.target = parsed
	}
	if !runtimeTimeoutsValid(effective) {
		return nil, ErrInvalid
	}
	return &effective, nil
}

func runtimeModel(raw compiledModel) (Model, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) || !runtimeIdentifierPattern.MatchString(raw.UpstreamID) ||
		!runtimeInputAccountingPhysicalModel(raw.UpstreamModel) ||
		(raw.hasPricingRef && !runtimeIdentifierPattern.MatchString(raw.PricingRef)) ||
		(raw.hasInputAccountingRef && !runtimeIdentifierPattern.MatchString(raw.InputAccountingRef)) ||
		len(raw.Capabilities) == 0 {
		return Model{}, ErrInvalid
	}
	allowed := []string{"openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages", "opaque_http"}
	seen := make(map[string]struct{}, len(raw.Capabilities))
	for _, capability := range raw.Capabilities {
		if !slices.Contains(allowed, capability) {
			return Model{}, ErrInvalid
		}
		if _, duplicate := seen[capability]; duplicate {
			return Model{}, ErrInvalid
		}
		seen[capability] = struct{}{}
	}
	return Model{
		ID: raw.ID, UpstreamID: raw.UpstreamID, UpstreamModel: raw.UpstreamModel,
		PricingRef: raw.PricingRef, InputAccountingRef: raw.InputAccountingRef,
		Capabilities: append([]string(nil), raw.Capabilities...),
	}, nil
}

func runtimeLimitPlan(raw compiledLimitPlan) (LimitPlan, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) || len(raw.Limits) == 0 || len(raw.Limits) > maximumExecutableLimitRules {
		return LimitPlan{}, ErrInvalid
	}
	plan := LimitPlan{ID: raw.ID, Limits: make([]Limit, 0, len(raw.Limits))}
	seenIdentities := make(map[immutableLimitIdentity]struct{}, len(raw.Limits))
	for _, rawLimit := range raw.Limits {
		limit, identity, ok := rawLimit.normalizeExecutable()
		if !ok {
			return LimitPlan{}, ErrInvalid
		}
		if _, duplicate := seenIdentities[identity]; duplicate {
			return LimitPlan{}, ErrInvalid
		}
		seenIdentities[identity] = struct{}{}
		plan.Limits = append(plan.Limits, limit)
	}
	return plan, nil
}

func (snapshot ActiveSnapshot) runtimeFeature(raw compiledFeature) (Feature, error) {
	if !runtimeIdentifierPattern.MatchString(raw.ID) || !protocol.ProtocolExecutable(raw.Protocol) ||
		!runtimeIdentifierPattern.MatchString(raw.AttestationPolicyID) ||
		len(raw.Access.Expression) == 0 || len(raw.Access.Expression) > 4096 ||
		len(raw.LimitPlan.Expression) == 0 || len(raw.LimitPlan.Expression) > 4096 ||
		len(raw.Routes) == 0 || len(raw.Routes) > 32 {
		return Feature{}, ErrInvalid
	}
	if _, ok := snapshot.attestations[raw.AttestationPolicyID]; !ok {
		return Feature{}, ErrInvalid
	}
	feature := Feature{
		ID: raw.ID, Protocol: raw.Protocol, AttestationPolicyID: raw.AttestationPolicyID,
		AccessExpression: raw.Access.Expression, LimitPlanExpression: raw.LimitPlan.Expression,
		Routes: make([]Route, 0, len(raw.Routes)),
	}
	if raw.Output != nil {
		if !protocolRequiresOutputPolicy(raw.Protocol) {
			return Feature{}, ErrInvalid
		}
		if raw.Output.DefaultMaximumTokens <= 0 || raw.Output.AbsoluteMaximumTokens <= 0 || raw.Output.DefaultMaximumTokens > raw.Output.AbsoluteMaximumTokens {
			return Feature{}, ErrInvalid
		}
		feature.Output = &OutputPolicy{
			DefaultMaximumTokens:  raw.Output.DefaultMaximumTokens,
			AbsoluteMaximumTokens: raw.Output.AbsoluteMaximumTokens,
		}
	} else if protocolRequiresOutputPolicy(raw.Protocol) {
		return Feature{}, ErrInvalid
	}
	seenRoutes := make(map[string]struct{}, len(raw.Routes))
	stickyByPriority := make(map[int64]string, len(raw.Routes))
	for _, rawRoute := range raw.Routes {
		if !runtimeIdentifierPattern.MatchString(rawRoute.ID) || !runtimeIdentifierPattern.MatchString(rawRoute.ModelID) ||
			len(rawRoute.When) == 0 || len(rawRoute.When) > 4096 || rawRoute.Priority < 0 ||
			rawRoute.Weight < 1 || rawRoute.Weight > 10_000 ||
			!slices.Contains([]string{"none", "user", "installation"}, rawRoute.StickyBy) {
			return Feature{}, ErrInvalid
		}
		if _, duplicate := seenRoutes[rawRoute.ID]; duplicate {
			return Feature{}, ErrInvalid
		}
		seenRoutes[rawRoute.ID] = struct{}{}
		if existing, ok := stickyByPriority[rawRoute.Priority]; ok && existing != rawRoute.StickyBy {
			return Feature{}, ErrInvalid
		}
		stickyByPriority[rawRoute.Priority] = rawRoute.StickyBy
		model, ok := snapshot.models[rawRoute.ModelID]
		if !ok || !slices.Contains(model.Capabilities, raw.Protocol) {
			return Feature{}, ErrInvalid
		}
		upstream, ok := snapshot.upstreams[model.UpstreamID]
		if !ok {
			return Feature{}, ErrInvalid
		}
		if !runtimeRetryConditionsValid(rawRoute.FallbackOn, false) {
			return Feature{}, ErrInvalid
		}
		if rawRoute.MaximumRequestBodyBytes < 0 || rawRoute.MaximumRequestBodyBytes > 100<<20 ||
			rawRoute.MaximumRequestHeaderBytes < 0 || rawRoute.MaximumRequestHeaderBytes > 32<<10 {
			return Feature{}, ErrInvalid
		}
		if raw.Protocol == "opaque_http" {
			if rawRoute.MaximumResponseBytes <= 0 || rawRoute.MaximumResponseBytes > 100<<20 {
				return Feature{}, ErrInvalid
			}
		} else if rawRoute.MaximumResponseBytes != 0 || rawRoute.StreamingAllowed || rawRoute.RetryUnsafeMethods {
			return Feature{}, ErrInvalid
		}
		retryPolicy, err := runtimeRetryPolicy(rawRoute.RetryPolicy)
		if err != nil {
			return Feature{}, ErrInvalid
		}
		routeTimeouts, err := runtimeRouteTimeouts(rawRoute.Timeouts, upstream.Timeouts)
		if err != nil {
			return Feature{}, ErrInvalid
		}
		feature.Routes = append(feature.Routes, Route{
			ID: rawRoute.ID, When: rawRoute.When, ModelID: rawRoute.ModelID,
			Priority: rawRoute.Priority, Weight: rawRoute.Weight, StickyBy: rawRoute.StickyBy,
			FallbackOn:                append([]string(nil), rawRoute.FallbackOn...),
			RetryPolicy:               retryPolicy,
			MaximumRequestBodyBytes:   rawRoute.MaximumRequestBodyBytes,
			MaximumRequestHeaderBytes: rawRoute.MaximumRequestHeaderBytes,
			MaximumResponseBytes:      rawRoute.MaximumResponseBytes,
			Timeouts:                  routeTimeouts,
			StreamingAllowed:          rawRoute.StreamingAllowed,
			RetryUnsafeMethods:        rawRoute.RetryUnsafeMethods,
		})
	}
	if raw.OpaqueHTTP != nil {
		if raw.Protocol != "opaque_http" || raw.OpaqueHTTP.MaximumBodyBytes < 0 {
			return Feature{}, ErrInvalid
		}
		opaque := OpaqueHTTPPolicy{
			AllowedMethods:        append([]string(nil), raw.OpaqueHTTP.AllowedMethods...),
			PathPrefixes:          append([]string(nil), raw.OpaqueHTTP.PathPrefixes...),
			MaximumBodyBytes:      raw.OpaqueHTTP.MaximumBodyBytes,
			AllowedRequestHeaders: append([]string(nil), raw.OpaqueHTTP.AllowedRequestHeaders...),
		}
		if !runtimeOpaquePolicyValid(opaque) {
			return Feature{}, ErrInvalid
		}
		feature.OpaqueHTTP = &opaque
	} else if raw.Protocol == "opaque_http" {
		return Feature{}, ErrInvalid
	}
	return feature, nil
}

func runtimeRetryPolicy(raw *compiledRetryPolicy) (*RetryPolicy, error) {
	if raw == nil {
		return nil, nil
	}
	if raw.MaxAttempts < 2 || raw.MaxAttempts > 8 ||
		raw.InitialBackoffMilliseconds < 0 || raw.InitialBackoffMilliseconds > 60_000 ||
		raw.MaximumBackoffMilliseconds < raw.InitialBackoffMilliseconds ||
		raw.MaximumBackoffMilliseconds > 60_000 ||
		math.IsNaN(raw.JitterRatio) || math.IsInf(raw.JitterRatio, 0) ||
		raw.JitterRatio < 0 || raw.JitterRatio > 1 ||
		!runtimeRetryConditionsValid(raw.RetryOn, true) {
		return nil, ErrInvalid
	}
	if raw.InitialBackoffMilliseconds == 0 && raw.MaximumBackoffMilliseconds != 0 {
		return nil, ErrInvalid
	}
	return &RetryPolicy{
		MaxAttempts:    raw.MaxAttempts,
		InitialBackoff: time.Duration(raw.InitialBackoffMilliseconds) * time.Millisecond,
		MaximumBackoff: time.Duration(raw.MaximumBackoffMilliseconds) * time.Millisecond,
		JitterRatio:    raw.JitterRatio,
		RetryOn:        append([]string(nil), raw.RetryOn...),
	}, nil
}

func runtimeRetryConditionsValid(conditions []string, requireOne bool) bool {
	if (requireOne && len(conditions) == 0) || len(conditions) > len(runtimeRetryConditions) {
		return false
	}
	seen := make(map[string]struct{}, len(conditions))
	for _, condition := range conditions {
		if !slices.Contains(runtimeRetryConditions, condition) {
			return false
		}
		if _, duplicate := seen[condition]; duplicate {
			return false
		}
		seen[condition] = struct{}{}
	}
	return true
}

func protocolRequiresOutputPolicy(protocol string) bool {
	return slices.Contains([]string{"openai_responses", "openai_chat", "anthropic_messages"}, protocol)
}

func runtimeOpaquePolicyValid(policy OpaqueHTTPPolicy) bool {
	if len(policy.AllowedMethods) == 0 || len(policy.AllowedMethods) > 5 ||
		len(policy.PathPrefixes) == 0 || len(policy.PathPrefixes) > 32 ||
		policy.MaximumBodyBytes < 0 || policy.MaximumBodyBytes > 100<<20 ||
		len(policy.AllowedRequestHeaders) > 32 {
		return false
	}
	seenMethods := make(map[string]struct{}, len(policy.AllowedMethods))
	for _, method := range policy.AllowedMethods {
		if !slices.Contains([]string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}, method) {
			return false
		}
		if _, duplicate := seenMethods[method]; duplicate {
			return false
		}
		seenMethods[method] = struct{}{}
	}
	seenPrefixes := make(map[string]struct{}, len(policy.PathPrefixes))
	for _, prefix := range policy.PathPrefixes {
		if !runtimeCanonicalUpstreamPath(prefix) {
			return false
		}
		if _, duplicate := seenPrefixes[prefix]; duplicate {
			return false
		}
		seenPrefixes[prefix] = struct{}{}
	}
	seenHeaders := make(map[string]struct{}, len(policy.AllowedRequestHeaders))
	for _, header := range policy.AllowedRequestHeaders {
		canonical := http.CanonicalHeaderKey(header)
		if !runtimeHeaderNamePattern.MatchString(header) || runtimeForwardHeaderForbidden(canonical) {
			return false
		}
		if _, duplicate := seenHeaders[canonical]; duplicate {
			return false
		}
		seenHeaders[canonical] = struct{}{}
	}
	return true
}

func runtimeCanonicalUpstreamPath(value string) bool {
	if value == "" || len(value) > 512 || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\%?#") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] >= 0x7f {
			return false
		}
	}
	if (&url.URL{Path: value}).EscapedPath() != value {
		return false
	}
	canonical := path.Clean(value)
	if strings.HasSuffix(value, "/") && canonical != "/" {
		canonical += "/"
	}
	return canonical == value
}

func runtimeForwardHeaderForbidden(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(strings.ToLower(canonical), "x-latchway-") {
		return true
	}
	switch canonical {
	case "Accept-Encoding", "Anthropic-Version", "Authorization", "Connection", "Content-Encoding", "Content-Length", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
		"Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Api-Key", "Api-Key", "Openai-Api-Key", "Openai-Organization", "Anthropic-Api-Key", "X-Auth-Token", "X-Goog-Api-Key",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return true
	default:
		return false
	}
}

func runtimeStaticHeaderForbidden(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(strings.ToLower(canonical), "x-latchway-") {
		return true
	}
	switch canonical {
	case "Accept", "Accept-Encoding", "Anthropic-Version", "Authorization", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host",
		"Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Api-Key", "Api-Key", "Openai-Api-Key", "Openai-Organization", "Anthropic-Api-Key", "X-Auth-Token", "X-Goog-Api-Key",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return true
	default:
		return false
	}
}

func runtimeBasicUsernameValid(username string) bool {
	if len(username) == 0 || len(username) > 256 {
		return false
	}
	for index := 0; index < len(username); index++ {
		character := username[index]
		if character < 0x21 || character > 0x7e || character == ':' {
			return false
		}
	}
	return true
}

func runtimeAuthenticationHeadersValid(headers []UpstreamAuthenticationHeader) bool {
	if len(headers) < 1 || len(headers) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		canonical := http.CanonicalHeaderKey(header.HeaderName)
		if len(header.HeaderName) > 256 || !runtimeHeaderNamePattern.MatchString(header.HeaderName) ||
			runtimeCredentialHeaderForbidden(canonical) ||
			!runtimeSecretRefPattern.MatchString(header.SecretRef) {
			return false
		}
		if _, duplicate := seen[canonical]; duplicate {
			return false
		}
		seen[canonical] = struct{}{}
	}
	return true
}

func runtimeAuthenticationUsesHeader(authentication UpstreamAuthentication, canonical string) bool {
	if authentication.Type == "header" {
		return canonical == http.CanonicalHeaderKey(authentication.HeaderName)
	}
	if authentication.Type == "headers" {
		for _, header := range authentication.Headers {
			if canonical == http.CanonicalHeaderKey(header.HeaderName) {
				return true
			}
		}
	}
	return false
}

func runtimeCredentialHeaderForbidden(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(strings.ToLower(canonical), "x-latchway-") {
		return true
	}
	switch canonical {
	case "Accept", "Accept-Encoding", "Anthropic-Version", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
		"Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return true
	default:
		return false
	}
}

func runtimeStaticHeaderValueValid(value string) bool {
	if len(value) > 2048 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if (value[index] < 0x20 && value[index] != '\t') || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func insertUnique[T any](target map[string]T, identifier string, value T) bool {
	if _, exists := target[identifier]; exists {
		return false
	}
	target[identifier] = value
	return true
}

func mustPort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return port
}
