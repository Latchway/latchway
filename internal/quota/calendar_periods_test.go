package quota

import (
	"errors"
	"testing"
	"time"
)

func TestCalendarPeriodsFollowEnforcementAlignment(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 7, 22, 30, 0, 0, time.UTC)
	end := time.Date(2026, 10, 9, 1, 0, 0, 0, time.UTC)
	periods, err := CalendarPeriods("1d", "UTC", start, end, 10)
	if err != nil || len(periods) != 3 ||
		!periods[0].Start.Equal(time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)) ||
		!periods[2].End.Equal(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("CalendarPeriods(1d) = %+v err=%v", periods, err)
	}
	for index, period := range periods {
		current, err := calendarWindowIn(period.Start, "1d", "UTC")
		if err != nil || !current.start.Equal(period.Start) || !current.end.Equal(period.End) {
			t.Fatalf("period %d %+v does not match enforcement %+v", index, period, current)
		}
	}
	tokyo, err := CalendarPeriods("1d", "Asia/Tokyo", start, end, 10)
	if err != nil || !tokyo[0].Start.Equal(time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)) {
		t.Fatalf("CalendarPeriods(Asia/Tokyo) = %+v err=%v", tokyo, err)
	}
	if _, err := CalendarPeriods("1h", "UTC", start, end, 5); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CalendarPeriods over its maximum error = %v", err)
	}
	if _, err := CalendarPeriods("1d", "UTC", end, start, 5); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CalendarPeriods with a reversed range error = %v", err)
	}
}
