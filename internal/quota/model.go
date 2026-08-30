// Package quota owns durable quota reservations and request accounting.
//
// The bounded implementation in this package supports hard calendar and
// durable token-bucket logical-request rules, hard calendar and durable
// token-bucket output-token rules, hard concurrent-request and
// concurrent-stream leases, hard per-request output-token enforcement
// metadata, immutable configured-price attribution, and hard server-configured
// IANA-calendar input-token and total-token rules backed by an immutable
// trusted preflight binding.
// One request may resolve to multiple rules, which are reserved and finalized
// atomically. The package does not accept client supplied counters, bucket
// keys, rule hashes, usage totals, costs, or timestamps.
package quota

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/frameworkcompat"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/limitscope"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/requestidentity"
)

const (
	LogicalRequestsMetric     = "logical_requests"
	InputTokensMetric         = "input_tokens"
	OutputTokensMetric        = "output_tokens"
	TotalTokensMetric         = "total_tokens"
	ConcurrentRequestsMetric  = "concurrent_requests"
	ConcurrentStreamsMetric   = "concurrent_streams"
	CostNanoUSDMetric         = "cost_nano_usd"
	RequestBytesMetric        = "request_bytes"
	ImageUnitsMetric          = "image_units"
	ToolCallsMetric           = "tool_calls"
	CalendarAlgorithm         = "calendar"
	TokenBucketAlgorithm      = "token_bucket"
	PerRequestAlgorithm       = "per_request"
	ConcurrencyAlgorithm      = "concurrency"
	maximumRulesPerRequest    = 128
	maximumAttemptsPerRequest = 32
	maximumReservationEntries = maximumRulesPerRequest * maximumAttemptsPerRequest

	ProviderReportedProvenance     = "provider_reported"
	UnknownUsageProvenance         = "unknown"
	USDCurrency                    = "USD"
	CalculatedCostConfidence       = "calculated"
	ProviderReportedCostConfidence = "reported"
	ProviderReportedCostSource     = "openrouter_usage_cost"
	UnknownCostConfidence          = "unknown"

	AttemptSucceeded = "succeeded"
	AttemptFailed    = "failed"
	AttemptCancelled = "cancelled"
	AttemptTimedOut  = "timed_out"

	// UTF8ByteBPEDeclaredFramingV1 identifies the initial conservative input
	// accounting proof. The trusted adapter bounds BPE content by the exact
	// rewritten UTF-8 bytes and adds operator-declared framing maxima.
	UTF8ByteBPEDeclaredFramingV1 = "utf8_byte_bpe_declared_framing_v1"
)

var (
	ErrInvalidInput        = errors.New("invalid quota input")
	ErrExceeded            = errors.New("logical request quota exceeded")
	ErrConcurrencyExceeded = errors.New("concurrency quota exceeded")
	ErrNotFound            = errors.New("quota state not found")
	ErrExpired             = errors.New("quota reservation expired")
	ErrFinalized           = errors.New("quota reservation already finalized")
	ErrInvalidState        = errors.New("quota state is inconsistent")
	ErrDependency          = errors.New("quota persistence unavailable")
	identifierPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	clientRequestPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	failureCodePattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)
	allowedProtocolValues  = []string{
		"openai_responses",
		"openai_chat",
		"openai_embeddings",
		"anthropic_messages",
		"opaque_http",
	}
	allowedPlatformValues = []string{
		"ios", "android", "web", "react_native_ios", "react_native_android", "node",
	}
)

const (
	ruleDigestDomain                = "latchway/quota-rule/v1\x00"
	scopeDigestDomain               = "latchway/quota-scope/v1\x00"
	requestDigestDomain             = "latchway/quota-request/v1\x00"
	reservationPricingBindingDomain = "latchway/quota-reservation-pricing/v1\x00"
	inputPreflightBindingDomain     = "latchway/quota-input-preflight-binding/v2\x00"
	requestMeasurementBindingDomain = "latchway/quota-request-measurement-binding/v1\x00"
	attemptDecisionBindingDomain    = "latchway/quota-attempt-decision/v1\x00"
	componentAttributionDomain      = "latchway/quota-component-attribution/v1\x00"
	frameworkAttributionDomain      = "latchway/quota-framework-attribution/v1\x00"
)

// Rule is a server-resolved limit rule. ReservedUnits is the trusted exact
// token or cost reservation applied to the provider request. It is zero for
// logical-request and concurrency rules, whose one unit is derived by the
// store. A cost reservation may also be zero when trusted configured pricing
// proves that the request is free. Capacity and the reduced
// RefillNumerator/RefillDenominator are populated only for a token_bucket
// rule. Timezone is the canonical server-configured IANA timezone for a
// calendar rule and is rejected on every other algorithm. PerRequestMaximum
// is populated only for input/output/total-token per_request metadata, which
// is fingerprinted but does not create a durable bucket.
type Rule struct {
	Metric            string
	Algorithm         string
	Scope             []string
	Window            string
	Timezone          string
	Maximum           int64
	PerRequestMaximum int64
	ReservedUnits     int64
	Capacity          int64
	RefillNumerator   int64
	RefillDenominator int64
	Hard              bool
}

// PricingSelection is the trusted configured catalog selected for one
// request. Its zero value means that no configured price applies. Price
// revision is deliberately not caller-selectable: the store derives it from
// ReserveInput.ConfigRevisionID.
type PricingSelection struct {
	CatalogID string
	Currency  string
}

// InputPreflightBinding is the server-trusted proof attached after provider
// request rewriting and physical-model selection. The exact body and profile
// digests make the proof request-specific. Store.Reserve defensively copies
// the value before validation and fingerprinting.
type InputPreflightBinding struct {
	Method              string
	Protocol            string
	ProfileID           string
	ProfileDigest       [sha256.Size]byte
	RewrittenBodySHA256 [sha256.Size]byte
	PhysicalModel       string
	InputTokenBound     int64
	OutputTokenBound    int64
	TotalTokenBound     int64
}

// RequestMeasurementBinding is the server-trusted post-rewrite request proof
// used by hard request_bytes, image_units, and tool_calls guards. Optional
// structured counts retain explicit known flags so unsupported protocols
// cannot silently turn unknown into zero.
type RequestMeasurementBinding struct {
	Protocol            string
	RewrittenBodySHA256 [sha256.Size]byte
	RequestBytes        int64
	ImageUnits          int64
	ToolCalls           int64
	ImageUnitsKnown     bool
	ToolCallsKnown      bool
}

// ReserveInput contains only canonical durable identities and server-selected
// policy values. ClientRequestID is correlation-only: it is persisted and
// compared on replay, but never serves as a lookup, authorization, bucket,
// routing, or generated logical-request identity.
type ReserveInput struct {
	LogicalRequestID requestidentity.LogicalID

	OrganizationID        string
	ApplicationID         string
	EnvironmentID         string
	ApplicationUserID     string
	InstallationID        string
	InstallationFamilyID  string
	ClientComponentID     string
	ComponentDefinitionID string
	ComponentKind         string
	TrustSource           string
	SessionGrantID        string
	ConfigRevisionID      string
	Platform              string
	// NormalizedClaimDigests contains only policy-derived, domain-separated
	// values keyed by canonical normalized claim name. Raw claims are never
	// accepted by quota and therefore cannot enter fingerprints or storage.
	NormalizedClaimDigests map[string]string

	FeatureKey          string
	Protocol            string
	ClientRequestID     string
	Framework           string
	FrameworkVersion    string
	LimitPlanKey        string
	RouteKey            string
	UpstreamKey         string
	ModelKey            string
	PhysicalModel       string
	Pricing             PricingSelection
	InputPreflight      *InputPreflightBinding
	RequestMeasurements *RequestMeasurementBinding
	Streaming           bool

	Rules []Rule
}

// Usage is normalized provider usage. Known measurements must carry the
// provider_reported provenance; unknown usage contains no measurements.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
	Known        bool
	Provenance   string
}

// Cost is a trusted charge in integer nano-USD. Known charges are either
// calculated from the selected pricing catalog or reported by an explicitly
// trusted provider integration. Unknown cost has a zero amount and either
// empty or unknown confidence; the store canonicalizes it according to whether
// the attempt has a configured pricing selection.
type Cost struct {
	NanoUSD    int64
	Known      bool
	Confidence string
	Currency   string
	Source     string
}

// Outcome is the trusted terminal result of an upstream attempt. HTTPStatus
// zero means no status was received. FailureCode must be a stable safe code for
// every non-success outcome.
type Outcome struct {
	Status      string
	HTTPStatus  int
	FailureCode string
	Usage       Usage
	Cost        Cost
}

// Reservation is an opaque, immutable handle returned only after the reserve
// transaction commits.
type Reservation struct {
	organizationID      string
	applicationID       string
	environmentID       string
	logicalRequestID    string
	reservationID       string
	entries             []reservationEntry
	routeKey            string
	upstreamKey         string
	modelKey            string
	physicalModel       string
	protocol            string
	pricing             selectedPricing
	inputPreflight      *InputPreflightBinding
	requestMeasurements *RequestMeasurementBinding
	retryPlan           *reservationRetryPlan
	windowResetAt       time.Time
	expiresAt           time.Time
}

// reservationRetryPlan is a defensive copy of the immutable, server-resolved
// rule set and authorization dimensions that produced the logical
// reservation. It is deliberately carried only inside the opaque Reservation
// handle: a retry caller selects a physical target and supplies trusted
// per-attempt units, but cannot replace the rules or scope identities used to
// materialize that target's buckets.
type reservationRetryPlan struct {
	applicationUserID     string
	installationID        string
	installationFamilyID  string
	clientComponentID     string
	componentDefinitionID string
	componentKind         string
	trustSource           string
	sessionGrantID        string
	configRevisionID      string
	featureKey            string
	limitPlanKey          string
	platform              string
	claimDigests          map[string]string
	streaming             bool
	rules                 []Rule
}

// selectedPricing is copied into every opaque reservation and persisted on
// the attempt. source is the configured catalog identity, while revision is
// always the exact configuration revision that produced the decision.
type selectedPricing struct {
	source   string
	currency string
	revision string
}

// reservationEntry is sorted by bucketID. resetAt is derived from the trusted
// rule window and is never loaded from or supplied to PostgreSQL.
type reservationEntry struct {
	bucketID      string
	entryID       string
	leaseID       string
	metric        string
	algorithm     string
	reservedUnits int64
	resetAt       time.Time
}

func (reservation Reservation) LogicalRequestID() string { return reservation.logicalRequestID }
func (reservation Reservation) ID() string               { return reservation.reservationID }
func (reservation Reservation) ResetAt() time.Time       { return reservation.windowResetAt }
func (reservation Reservation) ExpiresAt() time.Time     { return reservation.expiresAt }

// Attempt is an opaque handle returned only after the attempt-start
// transaction commits.
type Attempt struct {
	reservation Reservation
	attemptID   string
	number      int32
}

func (attempt Attempt) ID() string               { return attempt.attemptID }
func (attempt Attempt) LogicalRequestID() string { return attempt.reservation.logicalRequestID }
func (attempt Attempt) Number() int32            { return attempt.number }

// AttemptAllocation is the trusted capacity reserved immediately before one
// retry dispatch. Allocations are permitted only for token and cost metrics;
// a logical request is charged once and its concurrency leases span the whole
// retry sequence.
type AttemptAllocation struct {
	Metric string
	Units  int64
}

// RetryAttemptInput is the immutable server-owned physical decision for the
// attempt after Previous. The store derives the next contiguous attempt
// number and the exact configuration revision used by Pricing.
type RetryAttemptInput struct {
	RouteKey               string
	UpstreamKey            string
	ModelKey               string
	PhysicalModel          string
	Pricing                PricingSelection
	InputNanoUSDPerMillion int64
	InputPreflight         *InputPreflightBinding
	RequestMeasurements    *RequestMeasurementBinding
	Allocations            []AttemptAllocation
}

// ExceededError reports the safe reset boundary for one denied request. It
// deliberately omits bucket and scope hashes.
type ExceededError struct {
	logicalRequestID string
	retryAt          time.Time
	maximum          int64
	used             int64
	reserved         int64
}

func (denial *ExceededError) Error() string { return ErrExceeded.Error() }
func (denial *ExceededError) Unwrap() error { return ErrExceeded }
func (denial *ExceededError) LogicalRequestID() string {
	return denial.logicalRequestID
}
func (denial *ExceededError) RetryAt() time.Time { return denial.retryAt }
func (denial *ExceededError) Maximum() int64     { return denial.maximum }
func (denial *ExceededError) Used() int64        { return denial.used }
func (denial *ExceededError) Reserved() int64    { return denial.reserved }

// ConcurrencyExceededError reports a durable concurrency denial without a
// retry timestamp. Capacity becomes available only when another lease is
// released, so manufacturing a time-based retry boundary would be misleading.
type ConcurrencyExceededError struct {
	logicalRequestID string
	maximum          int64
	active           int64
}

func (denial *ConcurrencyExceededError) Error() string { return ErrConcurrencyExceeded.Error() }
func (denial *ConcurrencyExceededError) Unwrap() error { return ErrConcurrencyExceeded }
func (denial *ConcurrencyExceededError) LogicalRequestID() string {
	return denial.logicalRequestID
}
func (denial *ConcurrencyExceededError) Maximum() int64 { return denial.maximum }
func (denial *ConcurrencyExceededError) Active() int64  { return denial.active }

type preparedRequest struct {
	ReserveInput
	rules []preparedRule
}

type preparedRule struct {
	Rule
	scopeDimensions []string
	scopeType       string
	ruleKey         string
	scopeKey        string
	stateful        bool
}

type rulePreparationMode uint8

const (
	reserveRulePreparation rulePreparationMode = iota
	snapshotRulePreparation
)

func prepareRequest(input ReserveInput) (preparedRequest, error) {
	if id.Validate(input.LogicalRequestID.String(), id.LogicalRequest) != nil ||
		id.Validate(input.OrganizationID, id.Organization) != nil ||
		id.Validate(input.ApplicationID, id.Application) != nil ||
		id.Validate(input.EnvironmentID, id.Environment) != nil ||
		id.Validate(input.ApplicationUserID, id.ApplicationUser) != nil ||
		id.Validate(input.InstallationID, id.Installation) != nil ||
		id.Validate(input.SessionGrantID, id.SessionGrant) != nil ||
		id.Validate(input.ConfigRevisionID, id.ConfigRevision) != nil {
		return preparedRequest{}, ErrInvalidInput
	}
	if !validComponentAttribution(
		input.InstallationFamilyID, input.ClientComponentID,
		input.ComponentDefinitionID, input.ComponentKind, input.TrustSource,
	) || !validFrameworkAttribution(input.Framework, input.FrameworkVersion) {
		return preparedRequest{}, ErrInvalidInput
	}
	for _, value := range []string{
		input.FeatureKey,
		input.LimitPlanKey,
		input.RouteKey,
		input.UpstreamKey,
		input.ModelKey,
	} {
		if !identifierPattern.MatchString(value) {
			return preparedRequest{}, ErrInvalidInput
		}
	}
	if !slices.Contains(allowedProtocolValues, input.Protocol) ||
		!validPhysicalModel(input.PhysicalModel) ||
		(input.ClientRequestID != "" &&
			(len(input.ClientRequestID) < 8 || len(input.ClientRequestID) > 128 ||
				!clientRequestPattern.MatchString(input.ClientRequestID))) ||
		len(input.Rules) < 1 || len(input.Rules) > maximumRulesPerRequest {
		return preparedRequest{}, ErrInvalidInput
	}
	if input.Pricing.CatalogID == "" && input.Pricing.Currency == "" {
		// The all-zero selection is the only unpriced representation.
	} else if !identifierPattern.MatchString(input.Pricing.CatalogID) || input.Pricing.Currency != USDCurrency {
		return preparedRequest{}, ErrInvalidInput
	}

	values, err := quotaScopeValues(map[string]string{
		"organization":                          input.OrganizationID,
		"application":                           input.ApplicationID,
		"environment":                           input.EnvironmentID,
		"user":                                  input.ApplicationUserID,
		"installation":                          input.InstallationID,
		limitscope.InstallationFamilyDimension:  input.InstallationFamilyID,
		limitscope.ClientComponentDimension:     input.ClientComponentID,
		limitscope.ComponentDefinitionDimension: input.ComponentDefinitionID,
		limitscope.ComponentKindDimension:       input.ComponentKind,
		limitscope.TrustSourceDimension:         input.TrustSource,
		"feature":                               input.FeatureKey,
		"route":                                 input.RouteKey,
		"upstream":                              input.UpstreamKey,
		"model":                                 input.ModelKey,
	}, input.Platform, input.NormalizedClaimDigests)
	if err != nil {
		return preparedRequest{}, err
	}
	preparedRules, err := prepareRules(input.Rules, values, reserveRulePreparation)
	if err != nil {
		return preparedRequest{}, err
	}
	for _, rule := range preparedRules {
		if rule.Metric == CostNanoUSDMetric && input.Pricing.CatalogID == "" {
			return preparedRequest{}, ErrInvalidInput
		}
	}

	preflight, err := prepareInputPreflight(
		input.InputPreflight,
		input.Protocol,
		input.PhysicalModel,
		preparedRules,
	)
	if err != nil {
		return preparedRequest{}, err
	}
	measurements, err := prepareRequestMeasurements(
		input.RequestMeasurements, input.Protocol, preparedRules,
	)
	if err != nil || preflight != nil && measurements != nil &&
		preflight.RewrittenBodySHA256 != measurements.RewrittenBodySHA256 {
		return preparedRequest{}, ErrInvalidInput
	}
	// Do not retain the caller's pointer. Fingerprinting and persistence must
	// observe the single validated value even if the caller reuses its input.
	input.InputPreflight = preflight
	input.RequestMeasurements = measurements
	input.NormalizedClaimDigests = cloneStringMap(input.NormalizedClaimDigests)
	prepared := preparedRequest{ReserveInput: input, rules: preparedRules}
	prepared.Rules = clonePreparedRules(preparedRules)
	return prepared, nil
}

func prepareRequestMeasurements(
	input *RequestMeasurementBinding,
	requestProtocol string,
	rules []preparedRule,
) (*RequestMeasurementBinding, error) {
	requiresBytes, requiresImages, requiresTools := false, false, false
	for _, rule := range rules {
		switch rule.Metric {
		case RequestBytesMetric:
			requiresBytes = true
		case ImageUnitsMetric:
			requiresImages = true
		case ToolCallsMetric:
			requiresTools = true
		}
	}
	if !requiresBytes && !requiresImages && !requiresTools {
		if input != nil {
			return nil, ErrInvalidInput
		}
		return nil, nil
	}
	if input == nil {
		return nil, ErrInvalidInput
	}
	binding := *input
	if !validRequestMeasurementBinding(&binding, requestProtocol) ||
		requiresImages && !binding.ImageUnitsKnown || requiresTools && !binding.ToolCallsKnown {
		return nil, ErrInvalidInput
	}
	for _, rule := range rules {
		var expected int64
		switch rule.Metric {
		case RequestBytesMetric:
			expected = binding.RequestBytes
		case ImageUnitsMetric:
			expected = binding.ImageUnits
		case ToolCallsMetric:
			expected = binding.ToolCalls
		default:
			continue
		}
		if rule.ReservedUnits != expected {
			return nil, ErrInvalidInput
		}
	}
	return &binding, nil
}

func validRequestMeasurementBinding(binding *RequestMeasurementBinding, requestProtocol string) bool {
	if binding == nil {
		return false
	}
	var zeroDigest [sha256.Size]byte
	structuredProtocol := slices.Contains([]string{
		"openai_responses", "openai_chat", "openai_embeddings", "anthropic_messages",
	}, binding.Protocol)
	return binding.Protocol == requestProtocol && slices.Contains(allowedProtocolValues, binding.Protocol) &&
		binding.RewrittenBodySHA256 != zeroDigest && binding.RequestBytes >= 0 &&
		binding.RequestBytes <= protocol.MaximumMeasuredRequestBytes && binding.ImageUnits >= 0 &&
		binding.ImageUnits <= protocol.MaximumRequestStructuredUnits && binding.ToolCalls >= 0 &&
		binding.ToolCalls <= protocol.MaximumRequestStructuredUnits &&
		(binding.ImageUnitsKnown || binding.ImageUnits == 0) &&
		(binding.ToolCallsKnown || binding.ToolCalls == 0) &&
		((!binding.ImageUnitsKnown && !binding.ToolCallsKnown) || structuredProtocol)
}

func prepareInputPreflight(
	input *InputPreflightBinding,
	protocol string,
	physicalModel string,
	rules []preparedRule,
) (*InputPreflightBinding, error) {
	requiresBinding := false
	for _, rule := range rules {
		if rule.Metric == InputTokensMetric || rule.Metric == TotalTokensMetric {
			requiresBinding = true
			break
		}
	}
	if input == nil {
		if requiresBinding {
			return nil, ErrInvalidInput
		}
		return nil, nil
	}

	binding := *input
	if !validInputPreflightBinding(&binding, protocol, physicalModel) {
		return nil, ErrInvalidInput
	}
	for _, rule := range rules {
		var expected int64
		switch rule.Metric {
		case InputTokensMetric:
			expected = binding.InputTokenBound
		case OutputTokensMetric:
			expected = binding.OutputTokenBound
		case TotalTokensMetric:
			expected = binding.TotalTokenBound
		default:
			continue
		}
		if rule.ReservedUnits != expected {
			return nil, ErrInvalidInput
		}
	}
	return &binding, nil
}

func validInputPreflightBinding(
	binding *InputPreflightBinding,
	requestProtocol, physicalModel string,
) bool {
	if binding == nil {
		return false
	}
	var zeroDigest [sha256.Size]byte
	usesOutput, supportedProtocol := trustedInputProtocolUsesOutput(binding.Protocol)
	validOutput := binding.OutputTokenBound == 0
	if usesOutput {
		validOutput = binding.OutputTokenBound > 0
	}
	return supportedProtocol && binding.Method == UTF8ByteBPEDeclaredFramingV1 &&
		binding.Protocol == requestProtocol && identifierPattern.MatchString(binding.ProfileID) &&
		binding.ProfileDigest != zeroDigest && binding.RewrittenBodySHA256 != zeroDigest &&
		validPhysicalModel(binding.PhysicalModel) && binding.PhysicalModel == physicalModel &&
		binding.InputTokenBound > 0 && validOutput &&
		binding.InputTokenBound <= math.MaxInt64-binding.OutputTokenBound &&
		binding.TotalTokenBound == binding.InputTokenBound+binding.OutputTokenBound
}

func trustedInputProtocolUsesOutput(protocol string) (usesOutput bool, supported bool) {
	switch protocol {
	case "openai_responses", "openai_chat", "anthropic_messages":
		return true, true
	case "openai_embeddings":
		return false, true
	default:
		return false, false
	}
}

// prepareRules is the single canonical validation and identity path for both
// reservations and read-only snapshots. Snapshot rules describe selected
// policy rather than a provider reservation, so output and cost shapes require
// a zero ReservedUnits while retaining every other executable-policy invariant.
func prepareRules(input []Rule, values map[string]string, mode rulePreparationMode) ([]preparedRule, error) {
	if len(input) < 1 || len(input) > maximumRulesPerRequest ||
		(mode != reserveRulePreparation && mode != snapshotRulePreparation) {
		return nil, ErrInvalidInput
	}
	preparedRules := make([]preparedRule, 0, len(input))
	tokenReservations := make(map[string]int64, 3)
	requestReservations := make(map[string]int64, 3)
	var costReservation int64
	costReservationSet := false
	for _, rule := range input {
		dimensions, err := canonicalScopeDimensions(rule.Scope)
		if err != nil || !rule.Hard {
			return nil, ErrInvalidInput
		}
		for _, dimension := range dimensions {
			if values[dimension] == "" {
				return nil, ErrInvalidInput
			}
		}
		tokenReserved := rule.ReservedUnits > 0
		if mode == snapshotRulePreparation {
			tokenReserved = rule.ReservedUnits == 0
		}
		stateful := false
		switch {
		case rule.Metric == LogicalRequestsMetric && rule.Algorithm == CalendarAlgorithm:
			if rule.Maximum <= 0 || rule.PerRequestMaximum != 0 || rule.ReservedUnits != 0 ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
			stateful = true
		case rule.Metric == LogicalRequestsMetric && rule.Algorithm == TokenBucketAlgorithm:
			if rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum != 0 ||
				rule.ReservedUnits != 0 || validateTokenBucketPolicy(
				rule.Capacity, rule.RefillNumerator, rule.RefillDenominator,
			) != nil {
				return nil, ErrInvalidInput
			}
			stateful = true
		case (rule.Metric == InputTokensMetric || rule.Metric == OutputTokensMetric ||
			rule.Metric == TotalTokensMetric) && rule.Algorithm == TokenBucketAlgorithm:
			if rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum != 0 ||
				!tokenReserved ||
				validateTokenBucketPolicy(
					rule.Capacity, rule.RefillNumerator, rule.RefillDenominator,
				) != nil {
				return nil, ErrInvalidInput
			}
			stateful = true
		case rule.Metric == OutputTokensMetric && rule.Algorithm == CalendarAlgorithm:
			if rule.Maximum <= 0 || rule.PerRequestMaximum != 0 || !tokenReserved ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
			stateful = true
		case (rule.Metric == InputTokensMetric || rule.Metric == OutputTokensMetric ||
			rule.Metric == TotalTokensMetric) && rule.Algorithm == PerRequestAlgorithm:
			if rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum <= 0 ||
				!tokenReserved ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
		case (rule.Metric == RequestBytesMetric || rule.Metric == ImageUnitsMetric ||
			rule.Metric == ToolCallsMetric) && rule.Algorithm == PerRequestAlgorithm:
			requestUnitsValid := rule.ReservedUnits >= 0
			if mode == snapshotRulePreparation {
				requestUnitsValid = rule.ReservedUnits == 0
			}
			if rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum <= 0 ||
				!requestUnitsValid || rule.Capacity != 0 || rule.RefillNumerator != 0 ||
				rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
		case (rule.Metric == InputTokensMetric || rule.Metric == TotalTokensMetric) &&
			rule.Algorithm == CalendarAlgorithm:
			if rule.Maximum <= 0 || rule.PerRequestMaximum != 0 || !tokenReserved ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
			stateful = true
		case rule.Metric == CostNanoUSDMetric && rule.Algorithm == CalendarAlgorithm:
			costReserved := rule.ReservedUnits >= 0
			if mode == snapshotRulePreparation {
				costReserved = rule.ReservedUnits == 0
			}
			if rule.Maximum <= 0 || rule.PerRequestMaximum != 0 || !costReserved ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
			stateful = true
		case (rule.Metric == ConcurrentRequestsMetric || rule.Metric == ConcurrentStreamsMetric) &&
			rule.Algorithm == ConcurrencyAlgorithm:
			if rule.Window != "" || rule.Maximum <= 0 || rule.PerRequestMaximum != 0 ||
				rule.ReservedUnits != 0 || rule.Capacity != 0 ||
				rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
			stateful = true
		default:
			return nil, ErrInvalidInput
		}
		if mode == reserveRulePreparation &&
			(rule.Metric == InputTokensMetric || rule.Metric == OutputTokensMetric ||
				rule.Metric == TotalTokensMetric) {
			reservation, found := tokenReservations[rule.Metric]
			if found && reservation != rule.ReservedUnits {
				return nil, ErrInvalidInput
			}
			tokenReservations[rule.Metric] = rule.ReservedUnits
		}
		if mode == reserveRulePreparation && rule.Metric == CostNanoUSDMetric {
			if !costReservationSet {
				costReservation = rule.ReservedUnits
				costReservationSet = true
			} else if costReservation != rule.ReservedUnits {
				return nil, ErrInvalidInput
			}
		}
		if mode == reserveRulePreparation && (rule.Metric == RequestBytesMetric ||
			rule.Metric == ImageUnitsMetric || rule.Metric == ToolCallsMetric) {
			reservation, found := requestReservations[rule.Metric]
			if found && reservation != rule.ReservedUnits {
				return nil, ErrInvalidInput
			}
			requestReservations[rule.Metric] = rule.ReservedUnits
		}
		timezone := ""
		if stateful && rule.Algorithm == CalendarAlgorithm {
			if _, err := parseCalendarSpec(rule.Window); err != nil {
				return nil, ErrInvalidInput
			}
			var err error
			timezone, _, err = canonicalCalendarTimezone(rule.Timezone)
			if err != nil {
				return nil, ErrInvalidInput
			}
		}
		if (!stateful && rule.Window != "") || rule.Algorithm != CalendarAlgorithm && rule.Timezone != "" {
			return nil, ErrInvalidInput
		}
		ruleParts := []string{rule.Metric, rule.Algorithm, rule.Window}
		// Preserve every historical UTC rule digest. Only a non-UTC calendar
		// rule appends the timezone identity before its canonical dimensions.
		if timezone != "" && timezone != "UTC" {
			ruleParts = append(ruleParts, timezone)
		}
		ruleParts = append(ruleParts, dimensions...)
		scopeParts := make([]string, 0, len(dimensions)*2)
		for _, dimension := range dimensions {
			scopeParts = append(scopeParts, dimension, values[dimension])
		}
		scopeType := limitscope.ScopeType(dimensions)
		preparedRules = append(preparedRules, preparedRule{
			Rule: Rule{
				Metric: rule.Metric, Algorithm: rule.Algorithm,
				Scope: append([]string(nil), dimensions...), Window: rule.Window, Timezone: timezone,
				Maximum: rule.Maximum, PerRequestMaximum: rule.PerRequestMaximum,
				ReservedUnits: rule.ReservedUnits, Capacity: rule.Capacity,
				RefillNumerator:   rule.RefillNumerator,
				RefillDenominator: rule.RefillDenominator, Hard: rule.Hard,
			},
			scopeDimensions: dimensions,
			scopeType:       scopeType,
			ruleKey:         canonicalDigest(ruleDigestDomain, ruleParts),
			scopeKey:        canonicalDigest(scopeDigestDomain, scopeParts),
			stateful:        stateful,
		})
	}
	if !validTokenReservationRelationship(tokenReservations) {
		return nil, ErrInvalidInput
	}
	sort.Slice(preparedRules, func(left, right int) bool {
		if preparedRules[left].ruleKey != preparedRules[right].ruleKey {
			return preparedRules[left].ruleKey < preparedRules[right].ruleKey
		}
		return preparedRules[left].scopeKey < preparedRules[right].scopeKey
	})
	for index := 1; index < len(preparedRules); index++ {
		if preparedRules[index-1].ruleKey == preparedRules[index].ruleKey &&
			preparedRules[index-1].scopeKey == preparedRules[index].scopeKey {
			return nil, ErrInvalidInput
		}
	}
	return preparedRules, nil
}

// validTokenReservationRelationship checks every relationship the generic
// quota model can prove without a separate post-route preflight record. A
// total reservation cannot be smaller than a component that is present. When
// both components are present, the total must be their exact checked sum.
// Total-only and one-component shapes still require the future data-plane
// activation boundary to bind the hidden component explicitly.
func validTokenReservationRelationship(reservations map[string]int64) bool {
	total, hasTotal := reservations[TotalTokensMetric]
	if !hasTotal {
		return true
	}
	input, hasInput := reservations[InputTokensMetric]
	output, hasOutput := reservations[OutputTokensMetric]
	if hasInput && total < input || hasOutput && total < output {
		return false
	}
	if !hasInput || !hasOutput {
		return true
	}
	return input <= math.MaxInt64-output && total == input+output
}

// requestBoundExceededRules returns hard request-local bounds that the trusted
// reservation can never satisfy. A per-request maximum has no mutable state,
// and a token reservation larger than its bucket capacity cannot become
// admissible through refill. Treat both as quota decisions rather than
// malformed input so the store can durably deny the initial logical request.
func requestBoundExceededRules(rules []preparedRule) []preparedRule {
	exceeded := make([]preparedRule, 0, len(rules))
	for _, rule := range rules {
		switch rule.Algorithm {
		case PerRequestAlgorithm:
			if rule.ReservedUnits > rule.PerRequestMaximum {
				exceeded = append(exceeded, rule)
			}
		case TokenBucketAlgorithm:
			if rule.Metric != LogicalRequestsMetric && rule.ReservedUnits > rule.Capacity {
				exceeded = append(exceeded, rule)
			}
		}
	}
	return exceeded
}

func requestBoundExceededError(logicalRequestID string, exceeded []preparedRule) *ExceededError {
	selected := exceeded[0]
	selectedMaximum := selected.PerRequestMaximum
	if selected.Algorithm == TokenBucketAlgorithm {
		selectedMaximum = selected.Capacity
	}
	for _, candidate := range exceeded[1:] {
		candidateMaximum := candidate.PerRequestMaximum
		if candidate.Algorithm == TokenBucketAlgorithm {
			candidateMaximum = candidate.Capacity
		}
		if candidateMaximum < selectedMaximum ||
			(candidateMaximum == selectedMaximum &&
				(candidate.ruleKey < selected.ruleKey ||
					(candidate.ruleKey == selected.ruleKey && candidate.scopeKey < selected.scopeKey))) {
			selected, selectedMaximum = candidate, candidateMaximum
		}
	}
	return &ExceededError{
		logicalRequestID: logicalRequestID,
		maximum:          selectedMaximum,
	}
}

func clonePreparedRules(preparedRules []preparedRule) []Rule {
	rules := make([]Rule, len(preparedRules))
	for index := range preparedRules {
		rules[index] = preparedRules[index].Rule
		rules[index].Scope = append([]string(nil), preparedRules[index].Scope...)
	}
	return rules
}

func canonicalScopeDimensions(input []string) ([]string, error) {
	result, ok := limitscope.CanonicalDimensions(input)
	if !ok {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func quotaScopeValues(
	fixed map[string]string,
	platform string,
	claimDigests map[string]string,
) (map[string]string, error) {
	if len(claimDigests) > maximumRulesPerRequest {
		return nil, ErrInvalidInput
	}
	result := make(map[string]string, len(fixed)+1+len(claimDigests))
	for dimension, value := range fixed {
		result[dimension] = value
	}
	if platform != "" {
		if !slices.Contains(allowedPlatformValues, platform) {
			return nil, ErrInvalidInput
		}
		result[limitscope.PlatformDimension] = platform
	}
	for name, digest := range claimDigests {
		dimension := limitscope.NormalizedClaimPrefix + name
		parsed, ok := limitscope.NormalizedClaimName(dimension)
		if !ok || parsed != name || !limitscope.ValidClaimDigest(digest) {
			return nil, ErrInvalidInput
		}
		result[dimension] = digest
	}
	return result, nil
}

func validComponentAttribution(familyID, componentID, definitionID, kind, trustSource string) bool {
	present := familyID != "" || componentID != "" || definitionID != "" || kind != "" || trustSource != ""
	if !present {
		return true
	}
	return id.Validate(familyID, id.InstallationFamily) == nil &&
		id.Validate(componentID, id.ClientComponent) == nil &&
		identifierPattern.MatchString(definitionID) && identifierPattern.MatchString(kind) &&
		identifierPattern.MatchString(trustSource)
}

func validFrameworkAttribution(framework, version string) bool {
	if framework == "" || version == "" {
		return framework == "" && version == ""
	}
	if len(framework) > 64 || len(version) > 128 || !frameworkcompat.Known(framework) ||
		framework[0] < 'a' || framework[0] > 'z' {
		return false
	}
	for index := range framework {
		character := framework[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return frameworkcompat.ValidVersion(version)
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

// canonicalDigest is SHA-256(domain || uint32be(len(part)) || part ...),
// encoded as unpadded base64url. The immutable rule digest intentionally
// excludes mutable maximum, capacity, and refill values; changing a policy
// does not manufacture a fresh bucket.
func canonicalDigestBytes(domain string, parts []string) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(part))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func canonicalDigest(domain string, parts []string) string {
	digest := canonicalDigestBytes(domain, parts)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// requestFingerprint is persisted on the logical request. It binds every
// retry (including a denial) to the exact server-owned decision and mutable
// policy values without changing bucket identity. LogicalID makes it unique
// per accepted HTTP request.
func requestFingerprint(prepared preparedRequest) string {
	parts := []string{
		prepared.LogicalRequestID.String(),
		prepared.OrganizationID,
		prepared.ApplicationID,
		prepared.EnvironmentID,
		prepared.ApplicationUserID,
		prepared.InstallationID,
		prepared.SessionGrantID,
		prepared.ConfigRevisionID,
		prepared.FeatureKey,
		prepared.Protocol,
		prepared.ClientRequestID,
		prepared.LimitPlanKey,
		prepared.RouteKey,
		prepared.UpstreamKey,
		prepared.ModelKey,
		prepared.PhysicalModel,
	}
	if prepared.InstallationFamilyID != "" {
		parts = append(parts,
			componentAttributionDomain,
			prepared.InstallationFamilyID, prepared.ClientComponentID,
			prepared.ComponentDefinitionID, prepared.ComponentKind, prepared.TrustSource,
		)
	}
	if prepared.Framework != "" {
		parts = append(parts, frameworkAttributionDomain, prepared.Framework, prepared.FrameworkVersion)
	}
	for _, rule := range prepared.rules {
		parts = append(parts, rule.ruleKey, rule.scopeKey, strconv.FormatInt(rule.Maximum, 10))
		if rule.Algorithm == TokenBucketAlgorithm {
			parts = append(parts,
				strconv.FormatInt(rule.Capacity, 10),
				strconv.FormatInt(rule.RefillNumerator, 10),
				strconv.FormatInt(rule.RefillDenominator, 10),
			)
		}
		// Preserve the exact historical logical_requests/calendar serialization.
		// Token and cost reservation shapes bind both their configured per-request
		// maximum and the exact reservation applied to this provider request.
		if rule.Metric == InputTokensMetric || rule.Metric == OutputTokensMetric ||
			rule.Metric == TotalTokensMetric || rule.Metric == CostNanoUSDMetric ||
			rule.Metric == RequestBytesMetric || rule.Metric == ImageUnitsMetric ||
			rule.Metric == ToolCallsMetric {
			parts = append(parts,
				strconv.FormatInt(rule.PerRequestMaximum, 10),
				strconv.FormatInt(rule.ReservedUnits, 10),
			)
		}
	}
	for _, rule := range prepared.rules {
		if rule.Metric == ConcurrentStreamsMetric {
			parts = append(parts, strconv.FormatBool(prepared.Streaming))
			break
		}
	}
	// Preserve the byte-for-byte historical unpriced serialization. A priced
	// decision appends only its catalog identity; currency is fixed to USD and
	// revision is already bound by ConfigRevisionID above.
	if prepared.Pricing.CatalogID != "" {
		parts = append(parts, prepared.Pricing.CatalogID)
	}
	// The absence of a preflight binding preserves every historical
	// fingerprint byte-for-byte. A present proof appends its own versioned
	// domain marker and a canonical fixed-order serialization.
	if binding := prepared.InputPreflight; binding != nil {
		parts = append(parts,
			inputPreflightBindingDomain,
			binding.Method,
			binding.Protocol,
			binding.ProfileID,
			base64.RawURLEncoding.EncodeToString(binding.ProfileDigest[:]),
			base64.RawURLEncoding.EncodeToString(binding.RewrittenBodySHA256[:]),
			binding.PhysicalModel,
			strconv.FormatInt(binding.InputTokenBound, 10),
			strconv.FormatInt(binding.OutputTokenBound, 10),
			strconv.FormatInt(binding.TotalTokenBound, 10),
		)
	}
	if binding := prepared.RequestMeasurements; binding != nil {
		parts = append(parts,
			requestMeasurementBindingDomain,
			binding.Protocol,
			base64.RawURLEncoding.EncodeToString(binding.RewrittenBodySHA256[:]),
			strconv.FormatInt(binding.RequestBytes, 10),
			strconv.FormatInt(binding.ImageUnits, 10),
			strconv.FormatBool(binding.ImageUnitsKnown),
			strconv.FormatInt(binding.ToolCalls, 10),
			strconv.FormatBool(binding.ToolCallsKnown),
		)
	}
	return canonicalDigest(requestDigestDomain, parts)
}

// reservationIdempotencyKey preserves the historical key for every quota
// shape that predates hard-cost reservations. A hard-cost reservation binds
// its configured catalog independently so recovery can validate the attempt's
// immutable pricing source against the logical request fingerprint without
// trusting the attempt row as both the value and its own proof.
func reservationIdempotencyKey(fingerprint string, pricing selectedPricing, bindHardCostPricing bool) string {
	if !bindHardCostPricing {
		return fingerprint
	}
	return canonicalDigest(reservationPricingBindingDomain, []string{
		fingerprint,
		pricing.source,
	})
}

func hasHardCostReservation(rules []preparedRule) bool {
	for _, rule := range rules {
		if rule.Metric == CostNanoUSDMetric && rule.Algorithm == CalendarAlgorithm {
			return true
		}
	}
	return false
}

func (outcome Outcome) validate() error {
	if !slices.Contains([]string{AttemptSucceeded, AttemptFailed, AttemptCancelled, AttemptTimedOut}, outcome.Status) ||
		(outcome.HTTPStatus != 0 && (outcome.HTTPStatus < 100 || outcome.HTTPStatus > 599)) {
		return ErrInvalidInput
	}
	if outcome.Status == AttemptSucceeded {
		if outcome.FailureCode != "" || outcome.HTTPStatus < 200 || outcome.HTTPStatus > 299 {
			return ErrInvalidInput
		}
	} else if !failureCodePattern.MatchString(outcome.FailureCode) {
		return ErrInvalidInput
	}
	if outcome.Usage.validate() != nil || outcome.Cost.validate() != nil ||
		outcome.Cost.Known && outcome.Cost.Confidence == CalculatedCostConfidence && !outcome.Usage.Known {
		return ErrInvalidInput
	}
	return nil
}

func (usage Usage) validate() error {
	if !usage.Known {
		if usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.TotalTokens != 0 ||
			(usage.Provenance != "" && usage.Provenance != UnknownUsageProvenance) {
			return ErrInvalidInput
		}
		return nil
	}
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens < 0 ||
		usage.Provenance != ProviderReportedProvenance {
		return ErrInvalidInput
	}
	if usage.InputTokens > math.MaxInt64-usage.OutputTokens ||
		usage.TotalTokens != usage.InputTokens+usage.OutputTokens {
		return ErrInvalidInput
	}
	return nil
}

func (usage Usage) normalized() Usage {
	if !usage.Known {
		return Usage{Provenance: UnknownUsageProvenance}
	}
	return usage
}

func (cost Cost) validate() error {
	if !cost.Known {
		if cost.NanoUSD != 0 || cost.Currency != "" || cost.Source != "" ||
			cost.Confidence != "" && cost.Confidence != UnknownCostConfidence {
			return ErrInvalidInput
		}
		return nil
	}
	if cost.NanoUSD < 0 {
		return ErrInvalidInput
	}
	switch cost.Confidence {
	case CalculatedCostConfidence:
		if cost.Currency != "" || cost.Source != "" {
			return ErrInvalidInput
		}
	case ProviderReportedCostConfidence:
		if cost.Currency != USDCurrency || cost.Source != ProviderReportedCostSource {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func normalizeOutcomeForPricing(outcome Outcome, pricing selectedPricing) (Outcome, error) {
	if outcome.validate() != nil || pricing.validate() != nil {
		return Outcome{}, ErrInvalidInput
	}
	outcome.Usage = outcome.Usage.normalized()
	if !pricing.present() {
		if outcome.Cost.Known && outcome.Cost.Confidence != ProviderReportedCostConfidence {
			return Outcome{}, ErrInvalidInput
		}
		if !outcome.Cost.Known {
			outcome.Cost = Cost{}
		}
		return outcome, nil
	}
	if !outcome.Cost.Known {
		outcome.Cost = Cost{Confidence: UnknownCostConfidence}
	}
	return outcome, nil
}

func validFailureCode(value string) bool {
	return failureCodePattern.MatchString(value)
}

func validPhysicalModel(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) == -1
}

func prepareRetryAttemptInput(input RetryAttemptInput) (RetryAttemptInput, error) {
	if !identifierPattern.MatchString(input.RouteKey) ||
		!identifierPattern.MatchString(input.UpstreamKey) ||
		!identifierPattern.MatchString(input.ModelKey) ||
		!validPhysicalModel(input.PhysicalModel) ||
		(input.Pricing.CatalogID == "") != (input.Pricing.Currency == "") ||
		(input.Pricing.CatalogID != "" &&
			(!identifierPattern.MatchString(input.Pricing.CatalogID) || input.Pricing.Currency != USDCurrency)) ||
		input.InputNanoUSDPerMillion < 0 ||
		len(input.Allocations) > len(reservedTokenMetricOrder)+1+len(requestMeasurementMetricOrder) {
		return RetryAttemptInput{}, ErrInvalidInput
	}
	result := input
	if input.InputPreflight != nil {
		binding := *input.InputPreflight
		result.InputPreflight = &binding
	}
	result.RequestMeasurements = cloneRequestMeasurementBinding(input.RequestMeasurements)
	result.Allocations = append([]AttemptAllocation(nil), input.Allocations...)
	sort.Slice(result.Allocations, func(left, right int) bool {
		return attemptAllocationOrder(result.Allocations[left].Metric) <
			attemptAllocationOrder(result.Allocations[right].Metric)
	})
	byMetric := make(map[string]int64, len(result.Allocations))
	for index, allocation := range result.Allocations {
		if attemptAllocationOrder(allocation.Metric) == math.MaxInt ||
			(allocation.Metric == CostNanoUSDMetric && allocation.Units < 0) ||
			(isRequestMeasurementMetric(allocation.Metric) && allocation.Units < 0) ||
			(allocation.Metric != CostNanoUSDMetric && !isRequestMeasurementMetric(allocation.Metric) && allocation.Units <= 0) ||
			(index > 0 && result.Allocations[index-1].Metric == allocation.Metric) {
			return RetryAttemptInput{}, ErrInvalidInput
		}
		byMetric[allocation.Metric] = allocation.Units
	}
	if _, hasCost := byMetric[CostNanoUSDMetric]; !hasCost && input.InputNanoUSDPerMillion != 0 {
		return RetryAttemptInput{}, ErrInvalidInput
	}
	tokenReservations := make(map[string]int64, 3)
	for _, metric := range reservedTokenMetricOrder {
		if units, ok := byMetric[metric]; ok {
			tokenReservations[metric] = units
		}
	}
	if !validTokenReservationRelationship(tokenReservations) {
		return RetryAttemptInput{}, ErrInvalidInput
	}
	return result, nil
}

func cloneInputPreflightBinding(input *InputPreflightBinding) *InputPreflightBinding {
	if input == nil {
		return nil
	}
	result := *input
	return &result
}

func cloneRequestMeasurementBinding(input *RequestMeasurementBinding) *RequestMeasurementBinding {
	if input == nil {
		return nil
	}
	result := *input
	return &result
}

func retryPlanForRequest(prepared preparedRequest) *reservationRetryPlan {
	return &reservationRetryPlan{
		applicationUserID:     prepared.ApplicationUserID,
		installationID:        prepared.InstallationID,
		installationFamilyID:  prepared.InstallationFamilyID,
		clientComponentID:     prepared.ClientComponentID,
		componentDefinitionID: prepared.ComponentDefinitionID,
		componentKind:         prepared.ComponentKind,
		trustSource:           prepared.TrustSource,
		sessionGrantID:        prepared.SessionGrantID,
		configRevisionID:      prepared.ConfigRevisionID,
		featureKey:            prepared.FeatureKey,
		limitPlanKey:          prepared.LimitPlanKey,
		platform:              prepared.Platform,
		claimDigests:          cloneStringMap(prepared.NormalizedClaimDigests),
		streaming:             prepared.Streaming,
		rules:                 cloneLimitRules(prepared.Rules),
	}
}

func cloneReservationRetryPlan(input *reservationRetryPlan) *reservationRetryPlan {
	if input == nil {
		return nil
	}
	result := *input
	result.rules = cloneLimitRules(input.rules)
	result.claimDigests = cloneStringMap(input.claimDigests)
	return &result
}

func cloneLimitRules(input []Rule) []Rule {
	result := make([]Rule, len(input))
	for index := range input {
		result[index] = input[index]
		result[index].Scope = append([]string(nil), input[index].Scope...)
	}
	return result
}

func attemptAllocationOrder(metric string) int {
	for index, candidate := range reservedTokenMetricOrder {
		if metric == candidate {
			return index
		}
	}
	if metric == CostNanoUSDMetric {
		return len(reservedTokenMetricOrder)
	}
	for index, candidate := range requestMeasurementMetricOrder {
		if metric == candidate {
			return len(reservedTokenMetricOrder) + 1 + index
		}
	}
	return math.MaxInt
}

var requestMeasurementMetricOrder = [...]string{
	RequestBytesMetric,
	ImageUnitsMetric,
	ToolCallsMetric,
}

func isRequestMeasurementMetric(metric string) bool {
	return slices.Contains(requestMeasurementMetricOrder[:], metric)
}

func pricingForRequest(prepared preparedRequest) selectedPricing {
	if prepared.Pricing.CatalogID == "" {
		return selectedPricing{}
	}
	return selectedPricing{
		source: prepared.Pricing.CatalogID, currency: USDCurrency,
		revision: prepared.ConfigRevisionID,
	}
}

func (pricing selectedPricing) present() bool {
	return pricing.source != "" || pricing.currency != "" || pricing.revision != ""
}

func (pricing selectedPricing) validate() error {
	if !pricing.present() {
		return nil
	}
	if !identifierPattern.MatchString(pricing.source) || pricing.currency != USDCurrency ||
		id.Validate(pricing.revision, id.ConfigRevision) != nil {
		return ErrInvalidInput
	}
	return nil
}

func (reservation Reservation) validate() error {
	if id.Validate(reservation.organizationID, id.Organization) != nil ||
		id.Validate(reservation.applicationID, id.Application) != nil ||
		id.Validate(reservation.environmentID, id.Environment) != nil ||
		id.Validate(reservation.logicalRequestID, id.LogicalRequest) != nil ||
		id.Validate(reservation.reservationID, id.QuotaReservation) != nil ||
		!identifierPattern.MatchString(reservation.routeKey) ||
		!identifierPattern.MatchString(reservation.upstreamKey) ||
		!identifierPattern.MatchString(reservation.modelKey) ||
		!validPhysicalModel(reservation.physicalModel) ||
		reservation.pricing.validate() != nil ||
		reservation.expiresAt.IsZero() || len(reservation.entries) > maximumRulesPerRequest {
		return ErrInvalidInput
	}
	if reservation.inputPreflight != nil {
		binding := reservation.inputPreflight
		if !validInputPreflightBinding(binding, reservation.protocol, reservation.physicalModel) {
			return ErrInvalidInput
		}
	}
	if reservation.requestMeasurements != nil &&
		!validRequestMeasurementBinding(reservation.requestMeasurements, reservation.protocol) {
		return ErrInvalidInput
	}
	if reservation.inputPreflight != nil && reservation.requestMeasurements != nil &&
		reservation.inputPreflight.RewrittenBodySHA256 != reservation.requestMeasurements.RewrittenBodySHA256 {
		return ErrInvalidInput
	}
	if len(reservation.entries) == 0 {
		if !reservation.windowResetAt.IsZero() {
			return ErrInvalidInput
		}
		return nil
	}
	var maximumReset time.Time
	entryIDs := make(map[string]struct{}, len(reservation.entries))
	leaseIDs := make(map[string]struct{}, len(reservation.entries))
	var costReservation int64
	costReservationSet := false
	tokenReservations := make(map[string]int64, 3)
	for index, entry := range reservation.entries {
		concurrency := entry.algorithm == ConcurrencyAlgorithm && isConcurrencyMetric(entry.metric)
		calendar := entry.algorithm == CalendarAlgorithm &&
			(entry.metric == LogicalRequestsMetric || entry.metric == InputTokensMetric ||
				entry.metric == OutputTokensMetric || entry.metric == TotalTokensMetric ||
				entry.metric == CostNanoUSDMetric)
		tokenBucket := entry.algorithm == TokenBucketAlgorithm &&
			(entry.metric == LogicalRequestsMetric || entry.metric == InputTokensMetric ||
				entry.metric == OutputTokensMetric || entry.metric == TotalTokensMetric)
		if id.Validate(entry.bucketID, id.QuotaBucket) != nil ||
			id.Validate(entry.entryID, id.QuotaEntry) != nil ||
			(!calendar && !entry.resetAt.IsZero()) || (calendar && entry.resetAt.IsZero()) ||
			(!calendar && !tokenBucket && !concurrency) ||
			!validReservationEntryUnits(entry.metric, entry.algorithm, entry.reservedUnits) ||
			(concurrency && id.Validate(entry.leaseID, id.ConcurrencyLease) != nil) ||
			(!concurrency && entry.leaseID != "") ||
			(index > 0 && reservation.entries[index-1].bucketID >= entry.bucketID) {
			return ErrInvalidInput
		}
		if _, duplicate := entryIDs[entry.entryID]; duplicate {
			return ErrInvalidInput
		}
		entryIDs[entry.entryID] = struct{}{}
		if entry.metric == InputTokensMetric || entry.metric == OutputTokensMetric ||
			entry.metric == TotalTokensMetric {
			reservedUnits, found := tokenReservations[entry.metric]
			if found && reservedUnits != entry.reservedUnits {
				return ErrInvalidInput
			}
			tokenReservations[entry.metric] = entry.reservedUnits
		}
		if entry.metric == CostNanoUSDMetric {
			if !costReservationSet {
				costReservation = entry.reservedUnits
				costReservationSet = true
			} else if costReservation != entry.reservedUnits {
				return ErrInvalidInput
			}
		}
		if concurrency {
			if _, duplicate := leaseIDs[entry.leaseID]; duplicate {
				return ErrInvalidInput
			}
			leaseIDs[entry.leaseID] = struct{}{}
		}
		if entry.resetAt.After(maximumReset) {
			maximumReset = entry.resetAt
		}
	}
	_, hasInput := tokenReservations[InputTokensMetric]
	_, hasTotal := tokenReservations[TotalTokensMetric]
	if (hasInput || hasTotal) && reservation.inputPreflight == nil {
		return ErrInvalidInput
	}
	if binding := reservation.inputPreflight; binding != nil {
		for metric, units := range tokenReservations {
			var expected int64
			switch metric {
			case InputTokensMetric:
				expected = binding.InputTokenBound
			case OutputTokensMetric:
				expected = binding.OutputTokenBound
			case TotalTokensMetric:
				expected = binding.TotalTokenBound
			}
			if units != expected {
				return ErrInvalidInput
			}
		}
	}
	if !validTokenReservationRelationship(tokenReservations) ||
		!reservation.windowResetAt.Equal(maximumReset) {
		return ErrInvalidInput
	}
	return nil
}

func isConcurrencyMetric(metric string) bool {
	return metric == ConcurrentRequestsMetric || metric == ConcurrentStreamsMetric
}

func isStatefulMetric(metric string) bool {
	return metric == LogicalRequestsMetric || metric == InputTokensMetric ||
		metric == OutputTokensMetric || metric == TotalTokensMetric ||
		metric == CostNanoUSDMetric || isConcurrencyMetric(metric)
}

func isStatefulRule(metric, algorithm string) bool {
	return algorithm == CalendarAlgorithm &&
		(metric == LogicalRequestsMetric || metric == InputTokensMetric ||
			metric == OutputTokensMetric || metric == TotalTokensMetric ||
			metric == CostNanoUSDMetric) ||
		algorithm == TokenBucketAlgorithm &&
			(metric == LogicalRequestsMetric || metric == InputTokensMetric ||
				metric == OutputTokensMetric || metric == TotalTokensMetric) ||
		algorithm == ConcurrencyAlgorithm && isConcurrencyMetric(metric)
}

func validReservationEntryUnits(metric, algorithm string, units int64) bool {
	if !isStatefulRule(metric, algorithm) || units < 0 {
		return false
	}
	if metric == CostNanoUSDMetric {
		return algorithm == CalendarAlgorithm
	}
	if units == 0 {
		return false
	}
	if metric == LogicalRequestsMetric || isConcurrencyMetric(metric) {
		return units == 1
	}
	if algorithm == TokenBucketAlgorithm {
		// Compare against the global representable bound rather than the
		// bucket's current capacity. A valid pending reservation can exceed a
		// capacity selected by a later conservative policy transition.
		return units <= maximumTokenCapacity
	}
	return true
}

func (attempt Attempt) validate() error {
	if attempt.reservation.validate() != nil || id.Validate(attempt.attemptID, id.UpstreamAttempt) != nil ||
		attempt.number < 1 || attempt.number > maximumAttemptsPerRequest {
		return ErrInvalidInput
	}
	return nil
}
