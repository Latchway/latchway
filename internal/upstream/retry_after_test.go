package upstream

import (
	"net/http"
	"testing"
	"time"
)

func TestSafeRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		values []string
		want   int
	}{
		{[]string{"17"}, 17}, {[]string{"999999"}, 86400},
		{[]string{"Fri, 31 Dec 9999 23:59:59 GMT"}, 86400},
		{[]string{"-1"}, 0}, {[]string{"17", "18"}, 0},
		{[]string{"token-secret"}, 0}, {[]string{now.Add(30 * time.Second).Format(http.TimeFormat)}, 30},
	} {
		if got := safeRetryAfter(http.Header{"Retry-After": test.values}, now); got != test.want {
			t.Fatalf("retry = %d, want %d", got, test.want)
		}
	}
}
