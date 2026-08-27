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
