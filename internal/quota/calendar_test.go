package quota

import (
	"strings"
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
		{
			name: "multi week anchor", now: time.Date(1970, 1, 12, 12, 0, 0, 0, time.UTC), raw: "2w",
			start: time.Date(1970, 1, 5, 0, 0, 0, 0, time.UTC),
			end:   time.Date(1970, 1, 19, 0, 0, 0, 0, time.UTC),
			key:   "utc:v1:2w:19700105T000000Z",
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
	for _, raw := range []string{"", "0d", "01d", "1s", "1y", "-1d", "9223372036854775807d", "9223372036854775807w", "999999999999999999999mo"} {
		if _, err := calendarWindow(now, raw); err == nil {
			t.Fatalf("invalid calendar specification %q was accepted", raw)
		}
	}
	if _, err := calendarWindow(time.Time{}, "1d"); err == nil {
		t.Fatal("zero clock was accepted")
	}
}

func TestCalendarWindowIANAWeekAndDSTBoundaries(t *testing.T) {
	t.Parallel()
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		now      time.Time
		raw      string
		startUTC time.Time
		endUTC   time.Time
		key      string
		duration time.Duration
	}{
		{
			name: "spring day has 23 elapsed hours", raw: "1d",
			now:      time.Date(2026, time.March, 8, 12, 0, 0, 0, location),
			startUTC: time.Date(2026, time.March, 8, 5, 0, 0, 0, time.UTC),
			endUTC:   time.Date(2026, time.March, 9, 4, 0, 0, 0, time.UTC),
			key:      "iana:v1:America/New_York:1d:20260308T050000Z", duration: 23 * time.Hour,
		},
		{
			name: "fall day has 25 elapsed hours", raw: "1d",
			now:      time.Date(2026, time.November, 1, 12, 0, 0, 0, location),
			startUTC: time.Date(2026, time.November, 1, 4, 0, 0, 0, time.UTC),
			endUTC:   time.Date(2026, time.November, 2, 5, 0, 0, 0, time.UTC),
			key:      "iana:v1:America/New_York:1d:20261101T040000Z", duration: 25 * time.Hour,
		},
		{
			name: "spring week begins Monday and has 167 elapsed hours", raw: "1w",
			now:      time.Date(2026, time.March, 8, 12, 0, 0, 0, location),
			startUTC: time.Date(2026, time.March, 2, 5, 0, 0, 0, time.UTC),
			endUTC:   time.Date(2026, time.March, 9, 4, 0, 0, 0, time.UTC),
			key:      "iana:v1:America/New_York:1w:20260302T050000Z", duration: 167 * time.Hour,
		},
		{
			name: "fall week begins Monday and has 169 elapsed hours", raw: "1w",
			now:      time.Date(2026, time.November, 1, 12, 0, 0, 0, location),
			startUTC: time.Date(2026, time.October, 26, 4, 0, 0, 0, time.UTC),
			endUTC:   time.Date(2026, time.November, 2, 5, 0, 0, 0, time.UTC),
			key:      "iana:v1:America/New_York:1w:20261026T040000Z", duration: 169 * time.Hour,
		},
		{
			name: "month follows local civil boundary", raw: "1mo",
			now:      time.Date(2026, time.March, 20, 12, 0, 0, 0, location),
			startUTC: time.Date(2026, time.March, 1, 5, 0, 0, 0, time.UTC),
			endUTC:   time.Date(2026, time.April, 1, 4, 0, 0, 0, time.UTC),
			key:      "iana:v1:America/New_York:1mo:20260301T050000Z", duration: 743 * time.Hour,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			period, windowErr := calendarWindowIn(test.now, test.raw, "America/New_York")
			if windowErr != nil {
				t.Fatalf("calendarWindowIn() error = %v", windowErr)
			}
			if !period.start.Equal(test.startUTC) || !period.end.Equal(test.endUTC) ||
				period.key != test.key || period.end.Sub(period.start) != test.duration {
				t.Fatalf("period = %#v duration=%s, want start=%s end=%s key=%q duration=%s",
					period, period.end.Sub(period.start), test.startUTC, test.endUTC, test.key, test.duration)
			}
		})
	}
}

func TestCalendarWindowTimezoneIdentityAndFoldSafety(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 28, 17, 42, 0, 0, time.UTC)
	legacy, err := calendarWindow(now, "1d")
	if err != nil {
		t.Fatal(err)
	}
	omitted, err := calendarWindowIn(now, "1d", "")
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := calendarWindowIn(now, "1d", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if legacy != omitted || legacy != explicit || legacy.key != "utc:v1:1d:20260828T000000Z" {
		t.Fatalf("UTC compatibility changed: legacy=%#v omitted=%#v explicit=%#v", legacy, omitted, explicit)
	}

	// The repeated 01:30 wall time maps to two non-overlapping elapsed-hour
	// buckets, so a fallback fold can neither merge nor replay bucket identity.
	first, err := calendarWindowIn(time.Date(2026, time.November, 1, 5, 30, 0, 0, time.UTC), "1h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	second, err := calendarWindowIn(time.Date(2026, time.November, 1, 6, 30, 0, 0, time.UTC), "1h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if first.key == second.key || first.end.After(second.start) ||
		first.end.Sub(first.start) != time.Hour || second.end.Sub(second.start) != time.Hour {
		t.Fatalf("fold buckets overlap or alias: first=%#v second=%#v", first, second)
	}
}

func TestCalendarWindowRejectsInvalidTimezones(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	for _, timezone := range []string{
		"Local", "Not/A_Real_Zone", "../UTC", "/UTC", "America//New_York",
		"America/" + strings.Repeat("a", maximumCalendarTimezoneLength),
	} {
		if _, err := calendarWindowIn(now, "1w", timezone); err == nil {
			t.Fatalf("invalid timezone %q was accepted", timezone)
		}
	}
}

func TestCalendarWindowUnusualIANAOffsetsRemainDeterministicAndContaining(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		timezone string
		nowUTC   time.Time
		window   string
	}{
		{name: "half-hour daylight shift", timezone: "Australia/Lord_Howe", nowUTC: time.Date(2026, time.April, 5, 15, 45, 0, 0, time.UTC), window: "2h"},
		{name: "quarter-hour base offset", timezone: "Asia/Kathmandu", nowUTC: time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC), window: "1d"},
		{name: "midnight daylight transition", timezone: "America/Santiago", nowUTC: time.Date(2026, time.September, 6, 6, 0, 0, 0, time.UTC), window: "1w"},
		{name: "skipped civil date", timezone: "Pacific/Apia", nowUTC: time.Date(2011, time.December, 31, 12, 0, 0, 0, time.UTC), window: "2d"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first, err := calendarWindowIn(test.nowUTC, test.window, test.timezone)
			if err != nil {
				t.Fatalf("calendarWindowIn() error = %v", err)
			}
			second, err := calendarWindowIn(test.nowUTC, test.window, test.timezone)
			if err != nil || first != second || !first.end.After(first.start) ||
				test.nowUTC.Before(first.start) || !test.nowUTC.Before(first.end) {
				t.Fatalf("nondeterministic or non-containing period: first=%#v second=%#v err=%v", first, second, err)
			}
		})
	}
}
