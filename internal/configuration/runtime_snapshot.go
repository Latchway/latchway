package configuration

import (
	"bytes"
	"encoding/json"
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
)

var (
	runtimeIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	runtimeSecretRefPattern  = regexp.MustCompile(`^secret/[a-z][a-z0-9_-]{0,62}$`)
	runtimeHeaderNamePattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
)

const (
	maximumInputAccountingProfiles = 256
	inputAccountingProtocol        = "openai_chat"
	inputAccountingMethod          = "utf8_byte_bpe_declared_framing_v1"
)

type compiledUpstream struct {
	ID                         string `json:"id"`
	Type                       string `json:"type"`
	BaseURL                    string `json:"baseUrl"`
	DangerousAllowInsecureHTTP bool   `json:"dangerousAllowInsecureHttp"`
	Authentication             struct {
		Type       string `json:"type"`
		SecretRef  string `json:"secretRef"`
		HeaderName string `json:"headerName"`
	} `json:"authentication"`
	Timeouts struct {
		Connect   string `json:"connect"`
		FirstByte string `json:"firstByte"`
		Idle      string `json:"idle"`
		Total     string `json:"total"`
	} `json:"timeouts"`
	DestinationPolicy struct {
		AllowedPorts         []int `json:"allowedPorts"`
		AllowRedirects       bool  `json:"allowRedirects"`
		AllowPrivateNetworks bool  `json:"allowPrivateNetworks"`
		DNSPinning           bool  `json:"dnsPinning"`
	} `json:"destinationPolicy"`
	StaticHeaders map[string]string `json:"staticHeaders"`
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
		case "metric", "algorithm", "scope", "window", "maximum", "perRequestMaximum", "capacity", "refillPerSecond", "hard":
		default:
			return ErrInvalid
		}
	}
	var decoded struct {
		Metric    string   `json:"metric"`
		Algorithm string   `json:"algorithm"`
		Scope     []string `json:"scope"`
		Window    string   `json:"window"`
		Hard      bool     `json:"hard"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	_, limit.hasWindow = fields["window"]
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
		Scope: append([]string(nil), decoded.Scope...), Window: decoded.Window,
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
			limit.hasCapacity || limit.hasRefillPerSecond {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "token_bucket":
		if !limit.hasCapacity || !limit.hasRefillPerSecond || limit.hasWindow ||
			limit.hasMaximum || limit.hasPerRequestMaximum {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "per_request":
		if !limit.hasPerRequestMaximum || limit.hasWindow || limit.hasMaximum ||
			limit.hasCapacity || limit.hasRefillPerSecond {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "concurrency":
		if !limit.hasMaximum || limit.hasWindow || limit.hasPerRequestMaximum ||
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
		ID         string   `json:"id"`
		When       string   `json:"when"`
		ModelID    string   `json:"model"`
		Priority   int64    `json:"priority"`
		Weight     int64    `json:"weight"`
		StickyBy   string   `json:"stickyBy"`
		FallbackOn []string `json:"fallbackOn"`
	} `json:"routes"`
	OpaqueHTTP *struct {
		AllowedMethods        []string `json:"allowedMethods"`
		PathPrefixes          []string `json:"pathPrefixes"`
		MaximumBodyBytes      int64    `json:"maxBodyBytes"`
		AllowedRequestHeaders []string `json:"allowedRequestHeaders"`
	} `json:"opaqueHttp"`
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
		if _, ok := snapshot.upstreams[model.UpstreamID]; !ok {
			return errorsCorruptSnapshot("model upstream reference")
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

// runtimeQuotaAccountingValid independently rechecks the activation boundary
// on persisted compiled snapshots. A server-owned user override may select any
// configured plan for any feature, so input/total-token proof and hard-cost
// pricing reachability are global rather than narrowed by a constant CEL
// expression.
func (snapshot ActiveSnapshot) runtimeQuotaAccountingValid() bool {
	requiresTokenProof := runtimePlansRequireInputAccounting(snapshot.limitPlans)
	requiresCostPricing := runtimePlansRequireCostPricing(snapshot.limitPlans)
	for _, feature := range snapshot.features {
		for _, route := range feature.Routes {
			model, ok := snapshot.models[route.ModelID]
			if !ok {
				return false
			}
			proofValid := snapshot.runtimeRouteInputAccountingCompatible(feature, model)
			if requiresTokenProof && !proofValid {
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
				entry, ok := catalog.Entry(model.ID)
				if !ok || (entry.InputNanoUSDPerMillion != 0 && !proofValid) {
					return false
				}
			}
		}
	}
	return true
}

func runtimePlansRequireInputAccounting(plans map[string]LimitPlan) bool {
	for _, plan := range plans {
		for _, limit := range plan.Limits {
			if limit.Metric == "input_tokens" || limit.Metric == "total_tokens" {
				return true
			}
		}
	}
	return false
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
	if !runtimeIdentifierPattern.MatchString(profile.ID) || profile.Protocol != inputAccountingProtocol ||
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
// even an empty first message.
func inputAccountingProfileContextPossible(profile InputAccountingProfile) bool {
	return inputAccountingContextPossible(profile, 1)
}

// inputAccountingRouteContextPossible proves that the feature's largest
// server-permitted output fits alongside an exact minimal rewritten Chat body
// and the mandatory request and first-message framing.
func inputAccountingRouteContextPossible(
	profile InputAccountingProfile,
	absoluteMaximumOutputTokens int64,
) bool {
	if absoluteMaximumOutputTokens <= 0 {
		return false
	}
	return inputAccountingContextPossible(profile, absoluteMaximumOutputTokens)
}

func inputAccountingContextPossible(
	profile InputAccountingProfile,
	outputTokens int64,
) bool {
	minimalBody, err := json.Marshal(map[string]any{
		"max_tokens": outputTokens,
		"messages": []any{map[string]any{
			"content": "",
			"role":    "user",
		}},
		"model": profile.PhysicalModel,
	})
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
	return model.InputAccountingRef == profile.ID && profile.Protocol == inputAccountingProtocol &&
		profile.Method == inputAccountingMethod && profile.PhysicalModel == model.UpstreamModel &&
		slices.Contains(model.Capabilities, inputAccountingProtocol)
}

func (snapshot ActiveSnapshot) runtimeRouteInputAccountingCompatible(feature Feature, model Model) bool {
	if feature.Protocol != inputAccountingProtocol || feature.Output == nil || model.InputAccountingRef == "" {
		return false
	}
	profile, ok := snapshot.inputAccounting[model.InputAccountingRef]
	if !ok || !runtimeModelInputAccountingCompatible(model, profile) {
		return false
	}
	return inputAccountingRouteContextPossible(profile, feature.Output.AbsoluteMaximumTokens)
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
		HeaderName: raw.Authentication.HeaderName,
	}
	switch authentication.Type {
	case "none":
		if authentication.SecretRef != "" || authentication.HeaderName != "" {
			return Upstream{}, ErrInvalid
		}
	case "bearer":
		if !runtimeSecretRefPattern.MatchString(authentication.SecretRef) || authentication.HeaderName != "" {
			return Upstream{}, ErrInvalid
		}
	case "header":
		if !runtimeSecretRefPattern.MatchString(authentication.SecretRef) ||
			!runtimeHeaderNamePattern.MatchString(authentication.HeaderName) ||
			runtimeCredentialHeaderForbidden(authentication.HeaderName) {
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
	if policy.AllowRedirects || policy.AllowPrivateNetworks || !policy.DNSPinning || len(policy.AllowedPorts) == 0 {
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
			(authentication.Type == "header" && canonical == http.CanonicalHeaderKey(authentication.HeaderName)) ||
			!runtimeStaticHeaderValueValid(value) || totalHeaderBytes > 32<<10 {
			return Upstream{}, ErrInvalid
		}
		if _, duplicate := seenHeaders[canonical]; duplicate {
			return Upstream{}, ErrInvalid
		}
		seenHeaders[canonical] = struct{}{}
	}
	return Upstream{
		ID: raw.ID, Type: raw.Type, BaseURL: raw.BaseURL,
		DangerousAllowInsecureHTTP: raw.DangerousAllowInsecureHTTP,
		Authentication:             authentication, Timeouts: timeouts,
		DestinationPolicy: policy, StaticHeaders: staticHeaders,
	}, nil
}

func runtimeTimeouts(raw compiledUpstream) (UpstreamTimeouts, error) {
	values := []string{raw.Timeouts.Connect, raw.Timeouts.FirstByte, raw.Timeouts.Idle, raw.Timeouts.Total}
	parsed := make([]time.Duration, len(values))
	for index, value := range values {
		duration, err := parseConfigDuration(value)
		if err != nil || duration <= 0 {
			return UpstreamTimeouts{}, ErrInvalid
		}
		parsed[index] = duration
	}
	if parsed[3] > 10*time.Minute || parsed[0] > parsed[3] || parsed[1] > parsed[3] || parsed[2] > parsed[3] {
		return UpstreamTimeouts{}, ErrInvalid
	}
	return UpstreamTimeouts{Connect: parsed[0], FirstByte: parsed[1], Idle: parsed[2], Total: parsed[3]}, nil
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
		seenFallback := make(map[string]struct{}, len(rawRoute.FallbackOn))
		for _, fallback := range rawRoute.FallbackOn {
			if !slices.Contains([]string{"connect_error", "timeout_before_headers", "status_429", "status_500", "status_502", "status_503", "status_504"}, fallback) {
				return Feature{}, ErrInvalid
			}
			if _, duplicate := seenFallback[fallback]; duplicate {
				return Feature{}, ErrInvalid
			}
			seenFallback[fallback] = struct{}{}
		}
		feature.Routes = append(feature.Routes, Route{
			ID: rawRoute.ID, When: rawRoute.When, ModelID: rawRoute.ModelID,
			Priority: rawRoute.Priority, Weight: rawRoute.Weight, StickyBy: rawRoute.StickyBy,
			FallbackOn: append([]string(nil), rawRoute.FallbackOn...),
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

func protocolRequiresOutputPolicy(protocol string) bool {
	return slices.Contains([]string{"openai_responses", "openai_chat", "anthropic_messages"}, protocol)
}

func runtimeOpaquePolicyValid(policy OpaqueHTTPPolicy) bool {
	if len(policy.AllowedMethods) == 0 || len(policy.PathPrefixes) == 0 || policy.MaximumBodyBytes > 100<<20 {
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
	case "Accept-Encoding", "Authorization", "Connection", "Content-Encoding", "Content-Length", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
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
	case "Accept", "Accept-Encoding", "Authorization", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host",
		"Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Api-Key", "Api-Key", "Openai-Api-Key", "Openai-Organization", "Anthropic-Api-Key", "X-Auth-Token", "X-Goog-Api-Key",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return true
	default:
		return false
	}
}

func runtimeCredentialHeaderForbidden(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(strings.ToLower(canonical), "x-latchway-") {
		return true
	}
	switch canonical {
	case "Accept", "Accept-Encoding", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
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
