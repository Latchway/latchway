package pricing

import (
	"errors"
	"math"
	"testing"
)

func TestParseUSDDecimalNanoUSDIsExactAndOverflowSafe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  int64
		err   error
	}{
		{value: "0", want: 0},
		{value: "0e999999999999999999999", want: 0},
		{value: "1", want: 1_000_000_000},
		{value: "0.000000001", want: 1},
		{value: "1e-9", want: 1},
		{value: "100e-11", want: 1},
		{value: "1.2300000000", want: 1_230_000_000},
		{value: "9.223372036854775807e9", want: math.MaxInt64},
		{value: "9223372036.854775807", want: math.MaxInt64},
		{value: "0.0000000001", err: ErrInvalidUSDDecimal},
		{value: "1.0000000001", err: ErrInvalidUSDDecimal},
		{value: "9223372036.854775808", err: ErrUSDDecimalOverflow},
		{value: "1e100", err: ErrUSDDecimalOverflow},
		{value: "1e-100", err: ErrInvalidUSDDecimal},
		{value: "-0", err: ErrInvalidUSDDecimal},
		{value: "+1", err: ErrInvalidUSDDecimal},
		{value: "01", err: ErrInvalidUSDDecimal},
		{value: ".1", err: ErrInvalidUSDDecimal},
		{value: "1.", err: ErrInvalidUSDDecimal},
		{value: "1e", err: ErrInvalidUSDDecimal},
		{value: "NaN", err: ErrInvalidUSDDecimal},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, err := ParseUSDDecimalNanoUSD(test.value)
			if got != test.want || !errors.Is(err, test.err) || test.err == nil && err != nil {
				t.Fatalf("ParseUSDDecimalNanoUSD(%q) = (%d, %v), want (%d, %v)", test.value, got, err, test.want, test.err)
			}
		})
	}
}

func FuzzParseUSDDecimalNanoUSD(f *testing.F) {
	for _, seed := range []string{
		"0", "0.01", "1e-9", "9223372036.854775807", "0.0000000001", "-1", "1e99999999999999999999",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got, err := ParseUSDDecimalNanoUSD(value)
		if err == nil && got < 0 {
			t.Fatalf("successful parse returned negative nano-USD: %d", got)
		}
	})
}
