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

	"github.com/latchway/latchway/internal/jsonsafe"
)

var (
	runtimeIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	runtimeSecretRefPattern  = regexp.MustCompile(`^secret/[a-z][a-z0-9_-]{0,62}$`)
	runtimeHeaderNamePattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
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
	ID            string   `json:"id"`
	UpstreamID    string   `json:"upstream"`
	UpstreamModel string   `json:"upstreamModel"`
	PricingRef    string   `json:"pricingRef"`
	Capabilities  []string `json:"capabilities"`
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
	for _, raw := range rawModels {
		model, err := runtimeModel(raw)
		if err != nil || !insertUnique(snapshot.models, model.ID, model) {
			return errorsCorruptSnapshot("model")
		}
		if _, ok := snapshot.upstreams[model.UpstreamID]; !ok {
			return errorsCorruptSnapshot("model upstream reference")
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
	if !snapshot.runtimeHardCostPricingValid() {
		return errorsCorruptSnapshot("hard cost pricing")
	}
	if len(snapshot.upstreams) == 0 || len(snapshot.models) == 0 || len(snapshot.limitPlans) == 0 || len(snapshot.features) == 0 {
		return errorsCorruptSnapshot("data-plane configuration")
	}
	return nil
}

// runtimeHardCostPricingValid independently rechecks the activation gate on
// persisted compiled snapshots. Limit-plan selection can depend on trusted
// runtime facts, so a dynamic selection is conservatively allowed to reach
// any plan while a constant selection is scoped to its exact plan. Every model
// routed by an applicable feature must carry conservative configured pricing.
// OpenAI Chat cannot preflight all billable input (for example, remote file
// identifiers), therefore this bounded slice permits only a zero input rate.
func (snapshot ActiveSnapshot) runtimeHardCostPricingValid() bool {
	for _, feature := range snapshot.features {
		if !runtimeFeatureCanSelectCostLimit(feature, snapshot.limitPlans) {
			continue
		}
		for _, route := range feature.Routes {
			model, ok := snapshot.models[route.ModelID]
			if !ok || model.PricingRef == "" {
				return false
			}
			catalog, ok := snapshot.pricing[model.PricingRef]
			if !ok {
				return false
			}
			entry, ok := catalog.Entry(model.ID)
			if !ok || entry.InputNanoUSDPerMillion != 0 {
				return false
			}
		}
	}
	return true
}

func runtimeFeatureCanSelectCostLimit(feature Feature, plans map[string]LimitPlan) bool {
	if matches := constantIdentifierExpression.FindStringSubmatch(strings.TrimSpace(feature.LimitPlanExpression)); len(matches) == 2 {
		plan, ok := plans[matches[1]]
		return ok && runtimeLimitPlanHasCost(plan)
	}
	for _, plan := range plans {
		if runtimeLimitPlanHasCost(plan) {
			return true
		}
	}
	return false
}

func runtimeLimitPlanHasCost(plan LimitPlan) bool {
	for _, limit := range plan.Limits {
		if limit.Metric == "cost_nano_usd" {
			return true
		}
	}
	return false
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
		raw.UpstreamModel == "" || len(raw.UpstreamModel) > 256 || strings.ContainsAny(raw.UpstreamModel, "\r\n\x00") ||
		(raw.PricingRef != "" && !runtimeIdentifierPattern.MatchString(raw.PricingRef)) || len(raw.Capabilities) == 0 {
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
		PricingRef: raw.PricingRef, Capabilities: append([]string(nil), raw.Capabilities...),
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
	protocols := []string{"openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages", "opaque_http"}
	if !runtimeIdentifierPattern.MatchString(raw.ID) || !slices.Contains(protocols, raw.Protocol) ||
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
