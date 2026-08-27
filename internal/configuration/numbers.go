package configuration

import (
	"encoding/json"
	"math"
)

// parseJSONInteger converts every JSON lexical form whose mathematical value
// is an integer into int64 without passing through binary floating point. It
// accepts forms such as 4096.0 and 4.096e3 while rejecting fractional values,
// malformed numbers, and values outside the signed 64-bit range.
func parseJSONInteger(number json.Number) (int64, bool) {
	raw := number.String()
	if raw == "" {
		return 0, false
	}
	index := 0
	negative := false
	if raw[index] == '-' {
		negative = true
		index++
		if index == len(raw) {
			return 0, false
		}
	}

	integerStart := index
	switch {
	case raw[index] == '0':
		index++
		if index < len(raw) && isASCIIDigit(raw[index]) {
			return 0, false
		}
	case raw[index] >= '1' && raw[index] <= '9':
		for index < len(raw) && isASCIIDigit(raw[index]) {
			index++
		}
	default:
		return 0, false
	}
	integerEnd := index

	fractionStart, fractionEnd := index, index
	if index < len(raw) && raw[index] == '.' {
		index++
		fractionStart = index
		for index < len(raw) && isASCIIDigit(raw[index]) {
			index++
		}
		fractionEnd = index
		if fractionStart == fractionEnd {
			return 0, false
		}
	}

	exponentNegative := false
	exponentStart, exponentEnd := index, index
	if index < len(raw) && (raw[index] == 'e' || raw[index] == 'E') {
		index++
		if index < len(raw) && (raw[index] == '+' || raw[index] == '-') {
			exponentNegative = raw[index] == '-'
			index++
		}
		exponentStart = index
		for index < len(raw) && isASCIIDigit(raw[index]) {
			index++
		}
		exponentEnd = index
		if exponentStart == exponentEnd {
			return 0, false
		}
	}
	if index != len(raw) {
		return 0, false
	}

	digits := make([]byte, 0, integerEnd-integerStart+fractionEnd-fractionStart)
	digits = append(digits, raw[integerStart:integerEnd]...)
	digits = append(digits, raw[fractionStart:fractionEnd]...)
	nonzero := false
	for _, digit := range digits {
		if digit != '0' {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return 0, true
	}

	// Any exponent whose magnitude exceeds the significand length plus the
	// int64 decimal width must make a nonzero value fractional or overflowing.
	exponentLimit := len(digits) + 19
	exponent := 0
	for _, digit := range raw[exponentStart:exponentEnd] {
		value := int(digit - '0')
		if exponent > (exponentLimit-value)/10 {
			return 0, false
		}
		exponent = exponent*10 + value
	}
	if exponentNegative {
		exponent = -exponent
	}

	shift := exponent - (fractionEnd - fractionStart)
	if shift < 0 {
		places := -shift
		if places > len(digits) {
			return 0, false
		}
		for _, digit := range digits[len(digits)-places:] {
			if digit != '0' {
				return 0, false
			}
		}
		digits = digits[:len(digits)-places]
		shift = 0
	}

	for len(digits) > 0 && digits[0] == '0' {
		digits = digits[1:]
	}
	if len(digits) == 0 {
		return 0, true
	}
	if len(digits)+shift > 19 {
		return 0, false
	}

	var magnitude uint64
	for _, digit := range digits {
		magnitude = magnitude*10 + uint64(digit-'0')
	}
	for range shift {
		magnitude *= 10
	}
	if negative {
		const minimumMagnitude = uint64(1) << 63
		if magnitude > minimumMagnitude {
			return 0, false
		}
		if magnitude == minimumMagnitude {
			return math.MinInt64, true
		}
		return -int64(magnitude), true
	}
	if magnitude > math.MaxInt64 {
		return 0, false
	}
	return int64(magnitude), true
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}
