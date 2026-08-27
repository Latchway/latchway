package quota

import (
	"testing"
	"time"
)

func TestCalendarWindowUTCBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		now   time.Time
		raw   string
		start time.Time
		end   time.Time
		key   string
	}{
		{
			name: "day", now: time.Date(2026, 8, 28, 17, 42, 11, 999, time.FixedZone("local", 7*60*60)), raw: "1d",
			start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC),
			key:   "utc:v1:1d:20260828T000000Z",
		},
		{
			name: "fifteen minutes", now: time.Date(2026, 8, 28, 12, 29, 59, 0, time.UTC), raw: "15m",
			start: time.Date(2026, 8, 28, 12, 15, 0, 0, time.UTC),
			end:   time.Date(2026, 8, 28, 12, 30, 0, 0, time.UTC),
			key:   "utc:v1:15m:20260828T121500Z",
		},
		{
			name: "exact hour boundary", now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), raw: "2h",
			start: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC),
			key:   "utc:v1:2h:20260828T120000Z",
		},
		{
			name: "quarter", now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), raw: "3mo",
			start: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			key:   "utc:v1:3mo:20260701T000000Z",
		},
		{
			name: "pre epoch floors", now: time.Date(1969, 12, 31, 23, 59, 0, 0, time.UTC), raw: "1h",
			start: time.Date(1969, 12, 31, 23, 0, 0, 0, time.UTC),
			end:   time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			key:   "utc:v1:1h:19691231T230000Z",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			period, err := calendarWindow(test.now, test.raw)
			if err != nil {
				t.Fatalf("calendar window: %v", err)
			}
			if !period.start.Equal(test.start) || !period.end.Equal(test.end) || period.key != test.key {
				t.Fatalf("period = %#v, want start=%s end=%s key=%q", period, test.start, test.end, test.key)
			}
		})
	}
}

func TestCalendarWindowRejectsInvalidOrOverflowingSpecifications(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	for _, raw := range []string{"", "0d", "01d", "1s", "1w", "-1d", "9223372036854775807d", "999999999999999999999mo"} {
		if _, err := calendarWindow(now, raw); err == nil {
			t.Fatalf("invalid calendar specification %q was accepted", raw)
		}
	}
	if _, err := calendarWindow(time.Time{}, "1d"); err == nil {
		t.Fatal("zero clock was accepted")
	}
}
