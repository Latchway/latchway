package configuration

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/latchway/latchway/internal/limitmetric"
	"github.com/latchway/latchway/internal/limitscope"
)

const (
	maximumExecutableLimitRules                       = 128
	maximumExecutableTokenBucketCapacity        int64 = 9_223_372
	maximumExecutableTokenBucketRefillPerSecond int64 = 1_000_000
	maximumExecutableCalendarTimezoneLength           = 64
)

var (
	executableCalendarWindowPattern   = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d|w|mo)$`)
	executableCalendarTimezonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$`)
	// The initial executable slice deliberately caps one calendar rule at one
	// leap year. This is a deterministic subset of quota.calendarWindow that
	// cannot overflow duration arithmetic or produce impractically distant
	// bucket boundaries during the supported product lifetime.
	executableCalendarWindowMaximum = map[string]int64{
		"m":  366 * 24 * 60,
		"h":  366 * 24,
		"d":  366,
		"w":  52,
		"mo": 12,
	}
	executableLimitScopeOrder = []string{
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
)

// immutableLimitIdentity matches the durable quota rule identity. Maximum is
// deliberately excluded so changing a budget does not manufacture a fresh
// bucket. Scope is canonicalized before it enters the identity.
type immutableLimitIdentity struct {
	metric    string
	algorithm string
	window    string
	timezone  string
	scope     string
}

func normalizeExecutableLimit(limit Limit) (Limit, immutableLimitIdentity, bool) {
	if !limit.Hard || !limitmetric.SupportsEnforcement(limit.Metric, limit.Algorithm) {
		return Limit{}, immutableLimitIdentity{}, false
	}
	switch limit.Algorithm {
	case "calendar":
		timezone, ok := canonicalExecutableCalendarTimezone(limit.Timezone)
		if limit.Maximum <= 0 || limit.PerRequestMaximum != 0 ||
			limit.Capacity != 0 || limit.RefillPerSecond != (RefillRate{}) ||
			!executableCalendarWindow(limit.Window) || !ok {
			return Limit{}, immutableLimitIdentity{}, false
		}
		limit.Timezone = timezone
	case "token_bucket":
		if limit.Timezone != "" || limit.Window != "" ||
			limit.Maximum != 0 || limit.PerRequestMaximum != 0 ||
			limit.Capacity <= 0 || limit.Capacity > maximumExecutableTokenBucketCapacity ||
			!executableTokenBucketRefillRate(limit.RefillPerSecond) {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "per_request":
		if limit.Timezone != "" || limit.Window != "" ||
			limit.Maximum != 0 || limit.PerRequestMaximum <= 0 ||
			limit.Capacity != 0 || limit.RefillPerSecond != (RefillRate{}) {
			return Limit{}, immutableLimitIdentity{}, false
		}
	case "concurrency":
		if limit.Timezone != "" || limit.Window != "" || limit.Maximum <= 0 || limit.PerRequestMaximum != 0 ||
			limit.Capacity != 0 || limit.RefillPerSecond != (RefillRate{}) {
			return Limit{}, immutableLimitIdentity{}, false
		}
	default:
		return Limit{}, immutableLimitIdentity{}, false
	}
	scope, ok := canonicalLimitScope(limit.Scope)
	if !ok {
		return Limit{}, immutableLimitIdentity{}, false
	}
	limit.Scope = scope
	if limit.Metric == limitmetric.CostNanoUSD {
		if limit.CostRetryTreatment == "" {
			limit.CostRetryTreatment = CostRetryTreatmentActualAttempts
		}
		if limit.CostRetryTreatment != CostRetryTreatmentActualAttempts &&
			(limit.CostRetryTreatment != CostRetryTreatmentInitialAttemptOnly ||
				!slices.Contains(scope, "user")) {
			return Limit{}, immutableLimitIdentity{}, false
		}
	} else if limit.CostRetryTreatment != "" {
		return Limit{}, immutableLimitIdentity{}, false
	}
	return limit, immutableLimitIdentity{
		metric: limit.Metric, algorithm: limit.Algorithm,
		window: limit.Window, timezone: limit.Timezone, scope: strings.Join(scope, "\x00"),
	}, true
}

// validCostRetryPlan prevents product-level retry forgiveness from removing
// the durable bound and accounting record for real infrastructure spend.
func validCostRetryPlan(limits []Limit) bool {
	requiresOrganizationAccounting := false
	hasOrganizationAccounting := false
	for _, limit := range limits {
		if limit.Metric != limitmetric.CostNanoUSD {
			continue
		}
		switch limit.CostRetryTreatment {
		case CostRetryTreatmentInitialAttemptOnly:
			requiresOrganizationAccounting = true
		case CostRetryTreatmentActualAttempts:
			if slices.Contains(limit.Scope, "organization") && !slices.Contains(limit.Scope, "user") {
				hasOrganizationAccounting = true
			}
		}
	}
	return !requiresOrganizationAccounting || hasOrganizationAccounting
}

func canonicalExecutableCalendarTimezone(raw string) (string, bool) {
	if raw == "" || raw == "UTC" {
		return "UTC", true
	}
	if raw == "Local" || len(raw) > maximumExecutableCalendarTimezoneLength ||
		!executableCalendarTimezonePattern.MatchString(raw) {
		return "", false
	}
	location, err := time.LoadLocation(raw)
	return raw, err == nil && location.String() == raw
}

func executableTokenBucketRefillRate(rate RefillRate) bool {
	// Valid denominators divide one million, so this exact rational comparison
	// cannot overflow: maximum * denominator is at most one trillion.
	return rate.Valid() &&
		rate.Numerator <= maximumExecutableTokenBucketRefillPerSecond*rate.Denominator
}

func canonicalLimitScope(input []string) ([]string, bool) {
	return limitscope.CanonicalDimensions(input)
}

func executableCalendarWindow(raw string) bool {
	matches := executableCalendarWindowPattern.FindStringSubmatch(raw)
	if len(matches) != 3 {
		return false
	}
	amount, err := strconv.ParseInt(matches[1], 10, 64)
	maximum, ok := executableCalendarWindowMaximum[matches[2]]
	return err == nil && ok && amount > 0 && amount <= maximum
}
