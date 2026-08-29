package quota

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
	_ "time/tzdata"
)

const maximumCalendarTimezoneLength = 64

var (
	calendarWindowPattern   = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d|w|mo)$`)
	calendarTimezonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*(/[A-Za-z0-9][A-Za-z0-9._+-]*)*$`)
)

type calendarSpec struct {
	raw    string
	amount int64
	unit   string
}

type calendarPeriod struct {
	key   string
	start time.Time
	end   time.Time
}

func parseCalendarSpec(raw string) (calendarSpec, error) {
	matches := calendarWindowPattern.FindStringSubmatch(raw)
	if len(matches) != 3 {
		return calendarSpec{}, ErrInvalidInput
	}
	amount, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || amount <= 0 {
		return calendarSpec{}, ErrInvalidInput
	}
	return calendarSpec{raw: raw, amount: amount, unit: matches[2]}, nil
}

func calendarWindow(now time.Time, raw string) (calendarPeriod, error) {
	return calendarWindowIn(now, raw, "UTC")
}

// calendarWindowIn resolves a server-configured calendar rule. UTC deliberately
// retains the historical key serialization so an omitted timezone and an
// explicit UTC timezone address exactly the same durable bucket. Non-UTC
// identities include the canonical IANA name as well as the UTC start instant.
func calendarWindowIn(now time.Time, raw, timezone string) (calendarPeriod, error) {
	spec, err := parseCalendarSpec(raw)
	if err != nil || now.IsZero() {
		return calendarPeriod{}, ErrInvalidInput
	}
	timezone, location, err := canonicalCalendarTimezone(timezone)
	if err != nil {
		return calendarPeriod{}, ErrInvalidInput
	}
	now = now.In(location)
	if now.Year() < 1 || now.Year() > 9999 {
		return calendarPeriod{}, ErrInvalidInput
	}

	var start, end time.Time
	switch spec.unit {
	case "m", "h":
		start, end, err = calendarFixedWindow(now, spec, location)
	case "d":
		start, end, err = calendarDayWindow(now, spec.amount, location)
	case "w":
		start, end, err = calendarWeekWindow(now, spec.amount, location)
	case "mo":
		start, end, err = calendarMonthWindowIn(now, spec.amount, location)
	default:
		return calendarPeriod{}, ErrInvalidInput
	}
	if err != nil || !end.After(start) || now.Before(start) || !now.Before(end) {
		return calendarPeriod{}, ErrInvalidInput
	}
	startUTC := start.UTC()
	key := fmt.Sprintf("utc:v1:%s:%s", spec.raw, startUTC.Format("20060102T150405Z"))
	if timezone != "UTC" {
		key = fmt.Sprintf("iana:v1:%s:%s:%s", timezone, spec.raw, startUTC.Format("20060102T150405Z"))
	}
	if len(key) > 128 {
		return calendarPeriod{}, errors.New("calendar window key exceeds storage bound")
	}
	return calendarPeriod{key: key, start: startUTC, end: end.UTC()}, nil
}

func calendarMonthWindow(now time.Time, amount int64) (time.Time, time.Time, error) {
	return calendarMonthWindowIn(now.UTC(), amount, time.UTC)
}

func canonicalCalendarTimezone(raw string) (string, *time.Location, error) {
	if raw == "" || raw == "UTC" {
		return "UTC", time.UTC, nil
	}
	if raw == "Local" || len(raw) > maximumCalendarTimezoneLength || !calendarTimezonePattern.MatchString(raw) {
		return "", nil, ErrInvalidInput
	}
	location, err := time.LoadLocation(raw)
	if err != nil || location.String() != raw {
		return "", nil, ErrInvalidInput
	}
	return raw, location, nil
}

// Minute and hour windows are fixed elapsed-time buckets. Their anchor is
// local 1970-01-01 midnight, which makes their identity deterministic through
// daylight-saving folds while civil day/week/month rules follow wall-clock
// boundaries in the configured location.
func calendarFixedWindow(now time.Time, spec calendarSpec, location *time.Location) (time.Time, time.Time, error) {
	seconds := int64(60)
	if spec.unit == "h" {
		seconds = 60 * 60
	}
	if spec.amount > math.MaxInt64/seconds {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	span := spec.amount * seconds
	anchor := time.Date(1970, time.January, 1, 0, 0, 0, 0, location).Unix()
	delta := now.Unix() - anchor
	index := floorDivision(delta, span)
	offset := index * span
	if offset > 0 && anchor > math.MaxInt64-offset ||
		offset < 0 && anchor < math.MinInt64-offset {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	startUnix := anchor + offset
	if startUnix > math.MaxInt64-span {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	start := time.Unix(startUnix, 0).In(location)
	end := time.Unix(startUnix+span, 0).In(location)
	if start.Year() < 1 || end.Year() > 9999 {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	return start, end, nil
}

func calendarDayWindow(now time.Time, amount int64, location *time.Location) (time.Time, time.Time, error) {
	ordinal := civilDayOrdinal(now)
	startOrdinal := floorDivision(ordinal, amount) * amount
	return calendarCivilDayBounds(startOrdinal, amount, location)
}

func calendarWeekWindow(now time.Time, amount int64, location *time.Location) (time.Time, time.Time, error) {
	if amount > math.MaxInt64/7 {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	spanDays := amount * 7
	ordinal := civilDayOrdinal(now)
	// 1970-01-05 was a Monday. Anchoring multi-week windows here makes the
	// bucket assignment independent of the process clock and tzdata offset.
	const mondayEpochOrdinal int64 = 4
	delta := ordinal - mondayEpochOrdinal
	startOrdinal := mondayEpochOrdinal + floorDivision(delta, spanDays)*spanDays
	return calendarCivilDayBounds(startOrdinal, spanDays, location)
}

func civilDayOrdinal(value time.Time) int64 {
	local := value.In(value.Location())
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC).Unix() / (24 * 60 * 60)
}

func calendarCivilDayBounds(startOrdinal, spanDays int64, location *time.Location) (time.Time, time.Time, error) {
	if spanDays <= 0 || startOrdinal > math.MaxInt64-spanDays {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	endOrdinal := startOrdinal + spanDays
	minimumOrdinal := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC).Unix() / (24 * 60 * 60)
	maximumOrdinal := time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC).Unix()/(24*60*60) + 1
	if startOrdinal < minimumOrdinal || endOrdinal > maximumOrdinal {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	startDate := time.Unix(startOrdinal*24*60*60, 0).UTC()
	endDate := time.Unix(endOrdinal*24*60*60, 0).UTC()
	start := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, location)
	end := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 0, 0, 0, 0, location)
	return start, end, nil
}

func calendarMonthWindowIn(now time.Time, amount int64, location *time.Location) (time.Time, time.Time, error) {
	current := int64(now.Year()-1)*12 + int64(now.Month()-1)
	startIndex := floorDivision(current, amount) * amount
	if startIndex > math.MaxInt64-amount {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	endIndex := startIndex + amount
	maximumIndex := int64(9999 * 12)
	if startIndex < 0 || endIndex > maximumIndex {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	start := time.Date(int(startIndex/12)+1, time.Month(startIndex%12)+1, 1, 0, 0, 0, 0, location)
	end := time.Date(int(endIndex/12)+1, time.Month(endIndex%12)+1, 1, 0, 0, 0, 0, location)
	return start, end, nil
}

func floorDivision(value, divisor int64) int64 {
	quotient := value / divisor
	if value < 0 && value%divisor != 0 {
		quotient--
	}
	return quotient
}
