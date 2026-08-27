package configuration

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const maximumExecutableLimitRules = 128

var (
	executableCalendarWindowPattern = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d|mo)$`)
	// The initial executable slice deliberately caps one calendar rule at one
	// leap year. This is a deterministic subset of quota.calendarWindow that
	// cannot overflow duration arithmetic or produce impractically distant
	// bucket boundaries during the supported product lifetime.
	executableCalendarWindowMaximum = map[string]int64{
		"m":  366 * 24 * 60,
		"h":  366 * 24,
		"d":  366,
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
	scope     string
}

func normalizeExecutableLimit(limit Limit) (Limit, immutableLimitIdentity, bool) {
	if limit.Metric != "logical_requests" || limit.Algorithm != "calendar" ||
		!limit.Hard || limit.Maximum <= 0 || limit.PerRequestMaximum != 0 ||
		limit.Capacity != 0 || limit.RefillPerSecond.String() != "" ||
		!executableCalendarWindow(limit.Window) {
		return Limit{}, immutableLimitIdentity{}, false
	}
	scope, ok := canonicalLimitScope(limit.Scope)
	if !ok {
		return Limit{}, immutableLimitIdentity{}, false
	}
	limit.Scope = scope
	return limit, immutableLimitIdentity{
		metric: limit.Metric, algorithm: limit.Algorithm,
		window: limit.Window, scope: strings.Join(scope, "\x00"),
	}, true
}

func canonicalLimitScope(input []string) ([]string, bool) {
	if len(input) == 0 || len(input) > len(executableLimitScopeOrder) {
		return nil, false
	}
	seen := make(map[string]struct{}, len(input))
	for _, dimension := range input {
		if !slices.Contains(executableLimitScopeOrder, dimension) {
			return nil, false
		}
		if _, duplicate := seen[dimension]; duplicate {
			return nil, false
		}
		seen[dimension] = struct{}{}
	}
	result := make([]string, 0, len(input))
	for _, dimension := range executableLimitScopeOrder {
		if _, ok := seen[dimension]; ok {
			result = append(result, dimension)
		}
	}
	return result, true
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
