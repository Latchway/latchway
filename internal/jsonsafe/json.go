// Package jsonsafe decodes security-sensitive JSON while rejecting duplicate
// members, trailing values, excessive nesting, and oversized documents.
package jsonsafe

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf8"
)

const (
	maxDepth = 64
	maxNodes = 100_000
)

var (
	errNestingLimit = errors.New("JSON input exceeds nesting limit")
	errNodeLimit    = errors.New("JSON input exceeds structural limit")
)

// Decode parses exactly one UTF-8 JSON value and preserves numbers as
// json.Number.
func Decode(input []byte) (any, error) {
	if !utf8.Valid(input) {
		return nil, errors.New("JSON input is not valid UTF-8")
	}
	// The standard decoder owns grammar, duplicate names, and value assembly.
	// This hook only bounds value slots and preserves v1's exact number lexemes.
	nodes := 0
	bounded := jsonv2.UnmarshalFromFunc(func(decoder *jsontext.Decoder, value *any) error {
		if decoder.StackDepth() > maxDepth {
			return errNestingLimit
		}
		nodes++
		if nodes > maxNodes {
			return errNodeLimit
		}
		if decoder.PeekKind() == '0' {
			number, err := decoder.ReadValue()
			if err == nil {
				*value = json.Number(string(number))
			}
			return err
		}
		return errors.ErrUnsupported // Delegate all other values without consuming input.
	})
	// Raw UTF-8 was checked above. This option only preserves v1's treatment of
	// escaped unpaired surrogates as U+FFFD, including duplicate-name collisions.
	var value any
	if err := jsonv2.Unmarshal(input, &value, jsonv2.WithUnmarshalers(bounded),
		jsontext.AllowInvalidUTF8(true)); err != nil {
		for _, limit := range []error{errNestingLimit, errNodeLimit} {
			if errors.Is(err, limit) {
				return nil, limit
			}
		}
		// Decoder diagnostics may contain attacker-controlled member names.
		return nil, errors.New("invalid JSON input")
	}
	return value, nil
}

// DecodeReader reads at most maxBytes and decodes one JSON value.
func DecodeReader(reader io.Reader, maxBytes int64) (any, error) {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return nil, errors.New("positive, bounded JSON size limit required")
	}
	input, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JSON input: %w", err)
	}
	if int64(len(input)) > maxBytes {
		return nil, errors.New("JSON input exceeds size limit")
	}
	return Decode(input)
}
