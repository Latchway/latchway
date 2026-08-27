// Package quota owns durable quota reservations and request accounting.
//
// The bounded implementation in this package deliberately supports only one
// hard calendar logical-request rule per request. It does not accept client
// supplied counters, bucket keys, rule hashes, usage totals, or timestamps.
package quota

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

const (
	LogicalRequestsMetric = "logical_requests"
	CalendarAlgorithm     = "calendar"

	AttemptSucceeded = "succeeded"
	AttemptFailed    = "failed"
	AttemptCancelled = "cancelled"
	AttemptTimedOut  = "timed_out"
)

var (
	ErrInvalidInput       = errors.New("invalid quota input")
	ErrExceeded           = errors.New("logical request quota exceeded")
	ErrNotFound           = errors.New("quota state not found")
	ErrExpired            = errors.New("quota reservation expired")
	ErrFinalized          = errors.New("quota reservation already finalized")
	ErrInvalidState       = errors.New("quota state is inconsistent")
	ErrDependency         = errors.New("quota persistence unavailable")
	identifierPattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	clientRequestPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	failureCodePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)
	allowedProtocolValues = []string{
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

// Rule is a server-resolved limit rule. Reserve rejects every shape except one
// hard logical_requests calendar rule with a non-empty unambiguous scope.
type Rule struct {
	Metric    string
	Algorithm string
	Scope     []string
	Window    string
	Maximum   int64
	Hard      bool
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

	Rules []Rule
}

// Outcome is the trusted terminal result of an upstream attempt. HTTPStatus
// zero means no status was received. FailureCode must be a stable safe code for
// every non-success outcome.
type Outcome struct {
	Status      string
	HTTPStatus  int
	FailureCode string
}

// Reservation is an opaque, immutable handle returned only after the reserve
// transaction commits.
type Reservation struct {
	organizationID   string
	applicationID    string
	environmentID    string
	logicalRequestID string
	reservationID    string
	bucketID         string
	entryID          string
	routeKey         string
	upstreamKey      string
	modelKey         string
	physicalModel    string
	windowResetAt    time.Time
	expiresAt        time.Time
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

type preparedRequest struct {
	ReserveInput
	rule            Rule
	scopeDimensions []string
	scopeType       string
	ruleKey         string
	scopeKey        string
}

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
		len(input.Rules) != 1 {
		return preparedRequest{}, ErrInvalidInput
	}

	rule := input.Rules[0]
	dimensions, err := canonicalScopeDimensions(rule.Scope)
	if err != nil || rule.Metric != LogicalRequestsMetric ||
		rule.Algorithm != CalendarAlgorithm || !rule.Hard || rule.Maximum <= 0 {
		return preparedRequest{}, ErrInvalidInput
	}
	if _, err := parseCalendarSpec(rule.Window); err != nil {
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

	prepared := preparedRequest{
		ReserveInput:    input,
		rule:            rule,
		scopeDimensions: dimensions,
		scopeType:       scopeType,
		ruleKey:         canonicalDigest(ruleDigestDomain, ruleParts),
		scopeKey:        canonicalDigest(scopeDigestDomain, scopeParts),
	}
	prepared.Rules = []Rule{{
		Metric: rule.Metric, Algorithm: rule.Algorithm,
		Scope: append([]string(nil), dimensions...), Window: rule.Window,
		Maximum: rule.Maximum, Hard: rule.Hard,
	}}
	return prepared, nil
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
// excludes Maximum; changing a limit does not manufacture a fresh bucket.
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
// denial) to the exact server-owned decision and mutable maximum without
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
		prepared.ruleKey,
		prepared.scopeKey,
		strconv.FormatInt(prepared.rule.Maximum, 10),
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
		return nil
	}
	if !failureCodePattern.MatchString(outcome.FailureCode) {
		return ErrInvalidInput
	}
	return nil
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

func (reservation Reservation) validate() error {
	if id.Validate(reservation.organizationID, id.Organization) != nil ||
		id.Validate(reservation.applicationID, id.Application) != nil ||
		id.Validate(reservation.environmentID, id.Environment) != nil ||
		id.Validate(reservation.logicalRequestID, id.LogicalRequest) != nil ||
		id.Validate(reservation.reservationID, id.QuotaReservation) != nil ||
		id.Validate(reservation.bucketID, id.QuotaBucket) != nil ||
		id.Validate(reservation.entryID, id.QuotaEntry) != nil ||
		!identifierPattern.MatchString(reservation.routeKey) ||
		!identifierPattern.MatchString(reservation.upstreamKey) ||
		!identifierPattern.MatchString(reservation.modelKey) ||
		!validPhysicalModel(reservation.physicalModel) ||
		reservation.windowResetAt.IsZero() || reservation.expiresAt.IsZero() {
		return ErrInvalidInput
	}
	return nil
}

func (attempt Attempt) validate() error {
	if attempt.reservation.validate() != nil || id.Validate(attempt.attemptID, id.UpstreamAttempt) != nil || attempt.number != 1 {
		return ErrInvalidInput
	}
	return nil
}
