// Package quota owns durable quota reservations and request accounting.
//
// The bounded implementation in this package supports hard calendar and
// durable token-bucket logical-request rules, hard calendar and durable
// token-bucket output-token rules, hard concurrent-request and
// concurrent-stream leases, hard per-request output-token enforcement
// metadata, and immutable
// configured-price attribution. One request may resolve to multiple rules,
// which are reserved and finalized atomically. The package does not accept
// client supplied counters, bucket keys, rule hashes, usage totals, costs, or
// timestamps.
package quota

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

const (
	LogicalRequestsMetric    = "logical_requests"
	OutputTokensMetric       = "output_tokens"
	ConcurrentRequestsMetric = "concurrent_requests"
	ConcurrentStreamsMetric  = "concurrent_streams"
	CostNanoUSDMetric        = "cost_nano_usd"
	CalendarAlgorithm        = "calendar"
	TokenBucketAlgorithm     = "token_bucket"
	PerRequestAlgorithm      = "per_request"
	ConcurrencyAlgorithm     = "concurrency"
	maximumRulesPerRequest   = 128

	ProviderReportedProvenance = "provider_reported"
	UnknownUsageProvenance     = "unknown"
	USDCurrency                = "USD"
	CalculatedCostConfidence   = "calculated"
	UnknownCostConfidence      = "unknown"

	AttemptSucceeded = "succeeded"
	AttemptFailed    = "failed"
	AttemptCancelled = "cancelled"
	AttemptTimedOut  = "timed_out"
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
)

var scopeOrder = []string{
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

const (
	ruleDigestDomain    = "latchway/quota-rule/v1\x00"
	scopeDigestDomain   = "latchway/quota-scope/v1\x00"
	requestDigestDomain = "latchway/quota-request/v1\x00"
)

// Rule is a server-resolved limit rule. ReservedUnits is the trusted exact
// output cap applied to the provider request. It is zero for logical-request
// and concurrency rules, whose one unit is derived by the store. Capacity and
// the reduced RefillNumerator/RefillDenominator are populated only for a
// token_bucket rule. PerRequestMaximum is populated only for
// output_tokens/per_request metadata, which is fingerprinted but does not
// create a durable bucket.
type Rule struct {
	Metric            string
	Algorithm         string
	Scope             []string
	Window            string
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

// ReserveInput contains only canonical durable identities and server-selected
// policy values. ClientRequestID is correlation-only: it is persisted and
// compared on replay, but never serves as a lookup, authorization, bucket,
// routing, or generated logical-request identity.
type ReserveInput struct {
	LogicalRequestID requestidentity.LogicalID

	OrganizationID    string
	ApplicationID     string
	EnvironmentID     string
	ApplicationUserID string
	InstallationID    string
	SessionGrantID    string
	ConfigRevisionID  string

	FeatureKey      string
	Protocol        string
	ClientRequestID string
	LimitPlanKey    string
	RouteKey        string
	UpstreamKey     string
	ModelKey        string
	PhysicalModel   string
	Pricing         PricingSelection
	Streaming       bool

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

// Cost is a trusted calculated charge in integer nano-USD. Unknown cost has a
// zero amount and either empty or unknown confidence; the store canonicalizes
// it according to whether the attempt has a configured pricing selection.
type Cost struct {
	NanoUSD    int64
	Known      bool
	Confidence string
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
	organizationID   string
	applicationID    string
	environmentID    string
	logicalRequestID string
	reservationID    string
	entries          []reservationEntry
	routeKey         string
	upstreamKey      string
	modelKey         string
	physicalModel    string
	pricing          selectedPricing
	windowResetAt    time.Time
	expiresAt        time.Time
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

	values := map[string]string{
		"organization": input.OrganizationID,
		"application":  input.ApplicationID,
		"environment":  input.EnvironmentID,
		"user":         input.ApplicationUserID,
		"installation": input.InstallationID,
		"feature":      input.FeatureKey,
		"route":        input.RouteKey,
		"upstream":     input.UpstreamKey,
		"model":        input.ModelKey,
	}
	preparedRules, err := prepareRules(input.Rules, values, reserveRulePreparation)
	if err != nil {
		return preparedRequest{}, err
	}

	prepared := preparedRequest{ReserveInput: input, rules: preparedRules}
	prepared.Rules = clonePreparedRules(preparedRules)
	return prepared, nil
}

// prepareRules is the single canonical validation and identity path for both
// reservations and read-only snapshots. Snapshot rules describe selected
// policy rather than a provider reservation, so output shapes require a zero
// ReservedUnits while retaining every other executable-policy invariant.
func prepareRules(input []Rule, values map[string]string, mode rulePreparationMode) ([]preparedRule, error) {
	if len(input) < 1 || len(input) > maximumRulesPerRequest ||
		(mode != reserveRulePreparation && mode != snapshotRulePreparation) {
		return nil, ErrInvalidInput
	}
	preparedRules := make([]preparedRule, 0, len(input))
	var outputReservation int64
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
		outputReserved := rule.ReservedUnits > 0
		if mode == snapshotRulePreparation {
			outputReserved = rule.ReservedUnits == 0
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
		case rule.Metric == OutputTokensMetric && rule.Algorithm == TokenBucketAlgorithm:
			if rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum != 0 ||
				!outputReserved || rule.ReservedUnits > rule.Capacity ||
				validateTokenBucketPolicy(
					rule.Capacity, rule.RefillNumerator, rule.RefillDenominator,
				) != nil {
				return nil, ErrInvalidInput
			}
			stateful = true
		case rule.Metric == OutputTokensMetric && rule.Algorithm == CalendarAlgorithm:
			if rule.Maximum <= 0 || rule.PerRequestMaximum != 0 || !outputReserved ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
			stateful = true
		case rule.Metric == OutputTokensMetric && rule.Algorithm == PerRequestAlgorithm:
			if rule.Window != "" || rule.Maximum != 0 || rule.PerRequestMaximum <= 0 ||
				!outputReserved || rule.ReservedUnits > rule.PerRequestMaximum ||
				rule.Capacity != 0 || rule.RefillNumerator != 0 || rule.RefillDenominator != 0 {
				return nil, ErrInvalidInput
			}
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
		if mode == reserveRulePreparation && rule.Metric == OutputTokensMetric {
			if outputReservation == 0 {
				outputReservation = rule.ReservedUnits
			} else if outputReservation != rule.ReservedUnits {
				return nil, ErrInvalidInput
			}
		}
		if stateful && rule.Algorithm == CalendarAlgorithm {
			if _, err := parseCalendarSpec(rule.Window); err != nil {
				return nil, ErrInvalidInput
			}
		}
		if !stateful && rule.Window != "" {
			return nil, ErrInvalidInput
		}
		ruleParts := []string{rule.Metric, rule.Algorithm, rule.Window}
		ruleParts = append(ruleParts, dimensions...)
		scopeParts := make([]string, 0, len(dimensions)*2)
		for _, dimension := range dimensions {
			scopeParts = append(scopeParts, dimension, values[dimension])
		}
		scopeType := dimensions[0]
		if len(dimensions) > 1 {
			scopeType = "composite"
		}
		preparedRules = append(preparedRules, preparedRule{
			Rule: Rule{
				Metric: rule.Metric, Algorithm: rule.Algorithm,
				Scope: append([]string(nil), dimensions...), Window: rule.Window,
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

func clonePreparedRules(preparedRules []preparedRule) []Rule {
	rules := make([]Rule, len(preparedRules))
	for index := range preparedRules {
		rules[index] = preparedRules[index].Rule
		rules[index].Scope = append([]string(nil), preparedRules[index].Scope...)
	}
	return rules
}

func canonicalScopeDimensions(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > len(scopeOrder) {
		return nil, ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(input))
	for _, dimension := range input {
		if !slices.Contains(scopeOrder, dimension) {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[dimension]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[dimension] = struct{}{}
	}
	result := make([]string, 0, len(input))
	for _, dimension := range scopeOrder {
		if _, ok := seen[dimension]; ok {
			result = append(result, dimension)
		}
	}
	return result, nil
}

// canonicalDigest is SHA-256(domain || uint32be(len(part)) || part ...),
// encoded as unpadded base64url. The immutable rule digest intentionally
// excludes mutable maximum, capacity, and refill values; changing a policy
// does not manufacture a fresh bucket.
func canonicalDigest(domain string, parts []string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(domain))
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

// requestFingerprint is persisted on the logical request and, when accepted,
// as the reservation idempotency key. It binds every retry (including a
// denial) to the exact server-owned decision and mutable policy values without
// changing bucket identity. LogicalID makes it unique per accepted HTTP request.
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
		// New output-token shapes bind both their configured per-request maximum
		// and the exact cap applied to this provider request.
		if rule.Metric == OutputTokensMetric {
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
	return canonicalDigest(requestDigestDomain, parts)
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
	if outcome.Usage.validate() != nil || outcome.Cost.validate() != nil || outcome.Cost.Known && !outcome.Usage.Known {
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
		usage.TotalTokens < usage.InputTokens || usage.TotalTokens < usage.OutputTokens ||
		usage.Provenance != ProviderReportedProvenance {
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
		if cost.NanoUSD != 0 || cost.Confidence != "" && cost.Confidence != UnknownCostConfidence {
			return ErrInvalidInput
		}
		return nil
	}
	if cost.NanoUSD < 0 || cost.Confidence != CalculatedCostConfidence {
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
		if outcome.Cost.Known {
			return Outcome{}, ErrInvalidInput
		}
		outcome.Cost = Cost{}
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
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) == -1
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
	if len(reservation.entries) == 0 {
		if !reservation.windowResetAt.IsZero() {
			return ErrInvalidInput
		}
		return nil
	}
	var maximumReset time.Time
	entryIDs := make(map[string]struct{}, len(reservation.entries))
	leaseIDs := make(map[string]struct{}, len(reservation.entries))
	for index, entry := range reservation.entries {
		concurrency := entry.algorithm == ConcurrencyAlgorithm && isConcurrencyMetric(entry.metric)
		calendar := entry.algorithm == CalendarAlgorithm &&
			(entry.metric == LogicalRequestsMetric || entry.metric == OutputTokensMetric)
		tokenBucket := entry.algorithm == TokenBucketAlgorithm &&
			(entry.metric == LogicalRequestsMetric || entry.metric == OutputTokensMetric)
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
	if !reservation.windowResetAt.Equal(maximumReset) {
		return ErrInvalidInput
	}
	return nil
}

func isConcurrencyMetric(metric string) bool {
	return metric == ConcurrentRequestsMetric || metric == ConcurrentStreamsMetric
}

func isStatefulMetric(metric string) bool {
	return metric == LogicalRequestsMetric || metric == OutputTokensMetric || isConcurrencyMetric(metric)
}

func isStatefulRule(metric, algorithm string) bool {
	return algorithm == CalendarAlgorithm &&
		(metric == LogicalRequestsMetric || metric == OutputTokensMetric) ||
		algorithm == TokenBucketAlgorithm &&
			(metric == LogicalRequestsMetric || metric == OutputTokensMetric) ||
		algorithm == ConcurrencyAlgorithm && isConcurrencyMetric(metric)
}

func validReservationEntryUnits(metric, algorithm string, units int64) bool {
	if units <= 0 || !isStatefulRule(metric, algorithm) {
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
	if attempt.reservation.validate() != nil || id.Validate(attempt.attemptID, id.UpstreamAttempt) != nil || attempt.number != 1 {
		return ErrInvalidInput
	}
	return nil
}
