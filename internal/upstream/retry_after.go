package upstream

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Bound provider-controlled retry hints and reject duplicate/ambiguous values.
func safeRetryAfter(headers http.Header, now time.Time) int {
	var values []string
	for key, candidates := range headers {
		if strings.EqualFold(key, "Retry-After") {
			values = append(values, candidates...)
		}
	}
	if len(values) != 1 || len(values[0]) > 128 {
		return 0
	}
	value := strings.TrimSpace(values[0])
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		return min(int(seconds), 86400)
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		delay := at.Sub(now)
		if delay >= 24*time.Hour {
			return 86400
		}
		return min(int((delay+time.Second-1)/time.Second), 86400)
	}
	return 0
}
