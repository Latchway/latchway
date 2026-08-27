package configuration

import "testing"

func TestExecutableCalendarWindowUsesDeterministicOneYearBounds(t *testing.T) {
	t.Parallel()

	valid := []string{
		"1m", "15m", "527040m",
		"1h", "8784h",
		"1d", "366d",
		"1mo", "12mo",
	}
	for _, window := range valid {
		window := window
		t.Run("valid_"+window, func(t *testing.T) {
			t.Parallel()
			if !executableCalendarWindow(window) {
				t.Fatalf("expected %q to be executable", window)
			}
		})
	}

	invalid := []string{
		"", "0d", "01d", "1w",
		"527041m", "8785h", "367d", "13mo",
		"9223372036854775808d",
	}
	for _, window := range invalid {
		window := window
		t.Run("invalid_"+window, func(t *testing.T) {
			t.Parallel()
			if executableCalendarWindow(window) {
				t.Fatalf("expected %q to be rejected", window)
			}
		})
	}
}

func TestNormalizeExecutableLimitCanonicalizesScopeAndKeepsMaximumMutable(t *testing.T) {
	t.Parallel()

	first, firstIdentity, ok := normalizeExecutableLimit(Limit{
		Metric:    "logical_requests",
		Algorithm: "calendar",
		Window:    "1d",
		Maximum:   5,
		Hard:      true,
		Scope:     []string{"feature", "environment", "user"},
	})
	if !ok {
		t.Fatal("expected supported rule to normalize")
	}
	wantScope := []string{"environment", "user", "feature"}
	if len(first.Scope) != len(wantScope) {
		t.Fatalf("normalized scope = %#v, want %#v", first.Scope, wantScope)
	}
	for index := range wantScope {
		if first.Scope[index] != wantScope[index] {
			t.Fatalf("normalized scope = %#v, want %#v", first.Scope, wantScope)
		}
	}

	_, changedMaximumIdentity, ok := normalizeExecutableLimit(Limit{
		Metric:    "logical_requests",
		Algorithm: "calendar",
		Window:    "1d",
		Maximum:   99,
		Hard:      true,
		Scope:     []string{"user", "feature", "environment"},
	})
	if !ok {
		t.Fatal("expected reordered rule with changed maximum to normalize")
	}
	if changedMaximumIdentity != firstIdentity {
		t.Fatalf("immutable identity changed with maximum/scope ordering: %#v != %#v", changedMaximumIdentity, firstIdentity)
	}
}
