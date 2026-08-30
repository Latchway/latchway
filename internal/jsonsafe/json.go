// Package jsonsafe decodes security-sensitive JSON while rejecting duplicate
// members, trailing values, excessive nesting, and oversized documents.
package jsonsafe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	maxDepth = 64
	maxNodes = 100_000
)

// Decode parses exactly one UTF-8 JSON value and preserves numbers as
// json.Number.
func Decode(input []byte) (any, error) {
	if !utf8.Valid(input) {
		return nil, errors.New("JSON input is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	state := decodeState{}
	value, err := state.value(decoder, 0)
	if err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON input contains multiple values")
		}
		return nil, err
	}
	return value, nil
}

// DecodeReader reads at most maxBytes and decodes one JSON value.
func DecodeReader(reader io.Reader, maxBytes int64) (any, error) {
	if maxBytes <= 0 {
		return nil, errors.New("positive JSON size limit required")
	}
	limited := io.LimitReader(reader, maxBytes+1)
	input, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read JSON input: %w", err)
	}
	if int64(len(input)) > maxBytes {
		return nil, errors.New("JSON input exceeds size limit")
	}
	return Decode(input)
}

type decodeState struct {
	nodes int
}

func (s *decodeState) value(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON input exceeds nesting limit")
	}
	s.nodes++
	if s.nodes > maxNodes {
		return nil, errors.New("JSON input exceeds structural limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key must be a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON member %q", key)
			}
			value, err := s.value(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("invalid JSON object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := s.value(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("invalid JSON array")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}
