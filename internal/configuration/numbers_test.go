package configuration

import (
	"encoding/json"
	"math"
	"testing"
)

func TestParseJSONIntegerAcceptsExactIntegralLexicalForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "0", want: 0},
		{raw: "-0.0e999999999999999999999999", want: 0},
		{raw: "1", want: 1},
		{raw: "-1.000", want: -1},
		{raw: "4096.0", want: 4096},
		{raw: "4.096e3", want: 4096},
		{raw: "409600e-2", want: 4096},
		{raw: "0.0004096e7", want: 4096},
		{raw: "9223372036854775807.0", want: math.MaxInt64},
		{raw: "9.223372036854775807e18", want: math.MaxInt64},
		{raw: "-9223372036854775808.0", want: math.MinInt64},
		{raw: "-9.223372036854775808E+18", want: math.MinInt64},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			t.Parallel()
			got, ok := parseJSONInteger(json.Number(test.raw))
			if !ok || got != test.want {
				t.Fatalf("parseJSONInteger(%q) = (%d, %t), want (%d, true)", test.raw, got, ok, test.want)
			}
		})
	}
}

func TestParseJSONIntegerRejectsFractionalMalformedAndOutOfRangeForms(t *testing.T) {
	t.Parallel()

	tests := []string{
		"", "+1", "01", "1.", ".1", "1e", "--1",
		"0.1", "1e-1", "4096.0001", "4.096e2",
		"9223372036854775808", "9.223372036854775808e18",
		"-9223372036854775809", "-9.223372036854775809e18",
		"1e19", "-1e19", "1e999999999999999999999999",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if value, ok := parseJSONInteger(json.Number(raw)); ok {
				t.Fatalf("parseJSONInteger(%q) = (%d, true), want rejection", raw, value)
			}
		})
	}
}

func TestParseJSONRefillRateAcceptsExactScaleSixFormsAndReduces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw       string
		want      RefillRate
		canonical string
	}{
		{raw: "1", want: RefillRate{Numerator: 1, Denominator: 1}, canonical: "1"},
		{raw: "1.000000", want: RefillRate{Numerator: 1, Denominator: 1}, canonical: "1"},
		{raw: "1e0", want: RefillRate{Numerator: 1, Denominator: 1}, canonical: "1"},
		{raw: "0.5", want: RefillRate{Numerator: 1, Denominator: 2}, canonical: "0.5"},
		{raw: "5e-1", want: RefillRate{Numerator: 1, Denominator: 2}, canonical: "0.5"},
		{raw: "0.0000010", want: RefillRate{Numerator: 1, Denominator: 1_000_000}, canonical: "0.000001"},
		{raw: "3.333330e-1", want: RefillRate{Numerator: 333333, Denominator: 1_000_000}, canonical: "0.333333"},
		{
			raw:       "9223372036854.775807",
			want:      RefillRate{Numerator: math.MaxInt64, Denominator: 1_000_000},
			canonical: "9223372036854.775807",
		},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			t.Parallel()
			got, ok := parseJSONRefillRate(json.Number(test.raw))
			if !ok || got != test.want || got.String() != test.canonical || !got.Valid() {
				t.Fatalf("parseJSONRefillRate(%q) = (%+v, %t), canonical %q; want (%+v, true), canonical %q", test.raw, got, ok, got.String(), test.want, test.canonical)
			}
		})
	}
}

func TestParseJSONRefillRateRejectsNonPositiveInexactMalformedAndOutOfRangeForms(t *testing.T) {
	t.Parallel()

	tests := []string{
		"", "+1", "01", "1.", ".1", "1e", "--1",
		"0", "-0", "-0.000001", "-1", "1e-7", "0.0000001", "1.0000001",
		"9223372036854.775808", "9.223372036854775808e12",
		"1e13", "1e999999999999999999999999", "1e-999999999999999999999999",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if rate, ok := parseJSONRefillRate(json.Number(raw)); ok {
				t.Fatalf("parseJSONRefillRate(%q) = (%+v, true), want rejection", raw, rate)
			}
		})
	}
}

func TestRefillRateRejectsDetachedNoncanonicalAndOverflowingValues(t *testing.T) {
	t.Parallel()

	tests := []RefillRate{
		{},
		{Numerator: 1},
		{Denominator: 1},
		{Numerator: -1, Denominator: 1},
		{Numerator: 1, Denominator: -1},
		{Numerator: 2, Denominator: 2},
		{Numerator: 1, Denominator: 3},
		{Numerator: math.MaxInt64, Denominator: 1},
	}
	for _, rate := range tests {
		if rate.Valid() || rate.String() != "" {
			t.Fatalf("invalid detached refill rate accepted: %+v string=%q", rate, rate.String())
		}
	}
}

func FuzzParseJSONRefillRateCanonicalRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"", "0", "1", "1.000000", "5e-1", "0.000001", "1e-7",
		"9223372036854.775807", "9223372036854.775808", "1e999999999999999999999999",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1024 {
			t.Skip()
		}
		rate, ok := parseJSONRefillRate(json.Number(raw))
		if !ok {
			return
		}
		if !rate.Valid() || rate.String() == "" {
			t.Fatalf("accepted %q as invalid rate %+v", raw, rate)
		}
		roundTrip, roundTripOK := parseJSONRefillRate(json.Number(rate.String()))
		if !roundTripOK || roundTrip != rate {
			t.Fatalf("canonical round trip for %q: got (%+v, %t), want %+v", raw, roundTrip, roundTripOK, rate)
		}
	})
}
