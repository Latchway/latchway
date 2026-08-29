package pricing

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const maximumUSDDecimalBytes = 128

var (
	// ErrInvalidUSDDecimal means a provider monetary value is negative,
	// malformed, or cannot be represented exactly in integer nano-USD.
	ErrInvalidUSDDecimal = errors.New("invalid exact USD decimal")
	// ErrUSDDecimalOverflow means an otherwise valid non-negative USD decimal
	// exceeds the largest integer nano-USD amount Latchway can persist.
	ErrUSDDecimalOverflow = errors.New("USD decimal overflows nano-USD")
)

// ParseUSDDecimalNanoUSD converts one JSON-number-shaped USD decimal to an
// exact non-negative int64 nano-USD amount without binary floating point or
// rounding. Values finer than one nano-USD are accepted only when the excess
// fractional digits are zero. Exponent notation is supported and bounded.
func ParseUSDDecimalNanoUSD(value string) (int64, error) {
	if len(value) == 0 || len(value) > maximumUSDDecimalBytes || value[0] == '-' || value[0] == '+' {
		return 0, ErrInvalidUSDDecimal
	}

	index := 0
	integerStart := index
	switch {
	case value[index] == '0':
		index++
		if index < len(value) && isDecimalDigit(value[index]) {
			return 0, ErrInvalidUSDDecimal
		}
	case value[index] >= '1' && value[index] <= '9':
		for index < len(value) && isDecimalDigit(value[index]) {
			index++
		}
	default:
		return 0, ErrInvalidUSDDecimal
	}
	integerDigits := value[integerStart:index]

	fractionDigits := ""
	if index < len(value) && value[index] == '.' {
		index++
		fractionStart := index
		for index < len(value) && isDecimalDigit(value[index]) {
			index++
		}
		if fractionStart == index {
			return 0, ErrInvalidUSDDecimal
		}
		fractionDigits = value[fractionStart:index]
	}

	exponent := int64(0)
	exponentOverflow := false
	if index < len(value) && (value[index] == 'e' || value[index] == 'E') {
		index++
		negative := false
		if index < len(value) && (value[index] == '+' || value[index] == '-') {
			negative = value[index] == '-'
			index++
		}
		exponentStart := index
		for index < len(value) && isDecimalDigit(value[index]) {
			digit := int64(value[index] - '0')
			if exponent > 1_000 || exponent > (math.MaxInt64-digit)/10 {
				exponentOverflow = true
			} else {
				exponent = exponent*10 + digit
			}
			index++
		}
		if exponentStart == index {
			return 0, ErrInvalidUSDDecimal
		}
		if negative {
			exponent = -exponent
		}
	}
	if index != len(value) {
		return 0, ErrInvalidUSDDecimal
	}

	coefficient := strings.TrimLeft(integerDigits+fractionDigits, "0")
	if coefficient == "" {
		// Exact zero remains zero even when its syntactically valid exponent is
		// far outside the range relevant to nonzero int64 nano-USD values.
		return 0, nil
	}
	if exponentOverflow || exponent > maximumUSDDecimalBytes || exponent < -maximumUSDDecimalBytes {
		if exponent > 0 {
			return 0, ErrUSDDecimalOverflow
		}
		return 0, ErrInvalidUSDDecimal
	}

	scale := exponent - int64(len(fractionDigits)) + 9
	if scale < 0 {
		discard := -scale
		if discard > int64(len(coefficient)) {
			return 0, ErrInvalidUSDDecimal
		}
		cut := len(coefficient) - int(discard)
		for _, digit := range coefficient[cut:] {
			if digit != '0' {
				return 0, ErrInvalidUSDDecimal
			}
		}
		coefficient = strings.TrimLeft(coefficient[:cut], "0")
		if coefficient == "" {
			return 0, nil
		}
		scale = 0
	}
	if scale > 19 || int64(len(coefficient))+scale > 19 {
		return 0, ErrUSDDecimalOverflow
	}
	nanoText := coefficient + strings.Repeat("0", int(scale))
	nano, err := strconv.ParseUint(nanoText, 10, 63)
	if err != nil || nano > math.MaxInt64 {
		return 0, ErrUSDDecimalOverflow
	}
	return int64(nano), nil
}

func isDecimalDigit(value byte) bool { return value >= '0' && value <= '9' }
