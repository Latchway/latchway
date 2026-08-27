package quota

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

var calendarWindowPattern = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d|mo)$`)

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
	spec, err := parseCalendarSpec(raw)
	if err != nil || now.IsZero() {
		return calendarPeriod{}, ErrInvalidInput
	}
	now = now.UTC()
	if now.Year() < 1 || now.Year() > 9999 {
		return calendarPeriod{}, ErrInvalidInput
	}

	var start, end time.Time
	if spec.unit == "mo" {
		start, end, err = calendarMonthWindow(now, spec.amount)
	} else {
		seconds := int64(60)
		switch spec.unit {
		case "h":
			seconds = 60 * 60
		case "d":
			seconds = 24 * 60 * 60
		case "m":
		default:
			return calendarPeriod{}, ErrInvalidInput
		}
		if spec.amount > math.MaxInt64/seconds {
			return calendarPeriod{}, ErrInvalidInput
		}
		span := spec.amount * seconds
		unix := now.Unix()
		startUnix := floorDivision(unix, span) * span
		if startUnix > math.MaxInt64-span {
			return calendarPeriod{}, ErrInvalidInput
		}
		start = time.Unix(startUnix, 0).UTC()
		end = time.Unix(startUnix+span, 0).UTC()
		if start.Year() < 1 || end.Year() > 9999 {
			return calendarPeriod{}, ErrInvalidInput
		}
	}
	if err != nil || !end.After(start) || now.Before(start) || !now.Before(end) {
		return calendarPeriod{}, ErrInvalidInput
	}
	key := fmt.Sprintf("utc:v1:%s:%s", spec.raw, start.Format("20060102T150405Z"))
	if len(key) > 128 {
		return calendarPeriod{}, errors.New("calendar window key exceeds storage bound")
	}
	return calendarPeriod{key: key, start: start, end: end}, nil
}

func calendarMonthWindow(now time.Time, amount int64) (time.Time, time.Time, error) {
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
	start := time.Date(int(startIndex/12)+1, time.Month(startIndex%12)+1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(int(endIndex/12)+1, time.Month(endIndex%12)+1, 1, 0, 0, 0, 0, time.UTC)
	return start, end, nil
}

func floorDivision(value, divisor int64) int64 {
	quotient := value / divisor
	if value < 0 && value%divisor != 0 {
		quotient--
	}
	return quotient
}
