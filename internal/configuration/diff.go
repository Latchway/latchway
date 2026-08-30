package configuration

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/latchway/latchway/internal/jsonsafe"
)

func structuralDiff(fromDocument, toDocument json.RawMessage) ([]PlanChange, error) {
	from, err := jsonsafe.Decode(fromDocument)
	if err != nil {
		return nil, ErrInvalid
	}
	to, err := jsonsafe.Decode(toDocument)
	if err != nil {
		return nil, ErrInvalid
	}
	changes := make([]PlanChange, 0)
	diffValue(&changes, "", from, to, false)
	slices.SortFunc(changes, func(left, right PlanChange) int {
		if comparison := strings.Compare(left.Path, right.Path); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Operation, right.Operation)
	})
	return changes, nil
}

func diffValue(changes *[]PlanChange, path string, from, to any, sensitive bool) {
	fromObject, fromIsObject := from.(map[string]any)
	toObject, toIsObject := to.(map[string]any)
	if fromIsObject && toIsObject {
		diffObject(changes, path, fromObject, toObject, sensitive)
		return
	}
	fromArray, fromIsArray := from.([]any)
	toArray, toIsArray := to.([]any)
	if fromIsArray && toIsArray {
		diffArray(changes, path, fromArray, toArray, sensitive)
		return
	}
	if !equalJSONValue(from, to) {
		appendChange(changes, "replace", safePath(path), sensitive)
	}
}

func diffObject(changes *[]PlanChange, path string, from, to map[string]any, sensitive bool) {
	keys := make(map[string]struct{}, len(from)+len(to))
	for key := range from {
		keys[key] = struct{}{}
	}
	for key := range to {
		keys[key] = struct{}{}
	}
	ordered := sortedMapKeys(keys)
	for _, key := range ordered {
		childSensitive := sensitive || sensitiveConfigurationKey(key)
		childPath := path + "/" + pointerToken(key)
		if sensitive && pathEndsInSensitiveMap(path) {
			childPath = path + "/[redacted]"
		}
		fromValue, fromExists := from[key]
		toValue, toExists := to[key]
		switch {
		case !fromExists:
			appendChange(changes, "add", safePath(childPath), childSensitive)
		case !toExists:
			appendChange(changes, "remove", safePath(childPath), childSensitive)
		default:
			diffValue(changes, childPath, fromValue, toValue, childSensitive)
		}
	}
}

func diffArray(changes *[]PlanChange, path string, from, to []any, sensitive bool) {
	fromIndex, fromIndexed := identifierIndex(from)
	toIndex, toIndexed := identifierIndex(to)
	if fromIndexed && toIndexed {
		keys := make(map[string]struct{}, len(fromIndex)+len(toIndex))
		for key := range fromIndex {
			keys[key] = struct{}{}
		}
		for key := range toIndex {
			keys[key] = struct{}{}
		}
		for _, key := range sortedMapKeys(keys) {
			childPath := path + "/" + pointerToken(key)
			fromValue, fromExists := fromIndex[key]
			toValue, toExists := toIndex[key]
			switch {
			case !fromExists:
				appendChange(changes, "add", safePath(childPath), sensitive)
			case !toExists:
				appendChange(changes, "remove", safePath(childPath), sensitive)
			default:
				diffValue(changes, childPath, fromValue, toValue, sensitive)
			}
		}
		return
	}
	if !equalJSONValue(from, to) {
		appendChange(changes, "replace", safePath(path), sensitive)
	}
}

func identifierIndex(values []any) (map[string]any, bool) {
	result := make(map[string]any, len(values))
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		identifier, ok := object["id"].(string)
		if !ok || identifier == "" {
			return nil, false
		}
		if _, exists := result[identifier]; exists {
			return nil, false
		}
		result[identifier] = value
	}
	return result, true
}

func equalJSONValue(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func appendChange(changes *[]PlanChange, operation, path string, sensitive bool) {
	summary := "Configuration structure changed."
	if sensitive {
		summary = "Sensitive configuration changed; values are redacted."
	}
	*changes = append(*changes, PlanChange{Operation: operation, Path: path, Summary: summary})
}

func safePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func sensitiveConfigurationKey(key string) bool {
	normalized := strings.ToLower(key)
	return strings.Contains(normalized, "secret") || strings.Contains(normalized, "credential") ||
		normalized == "authentication" || normalized == "staticheaders"
}

func pathEndsInSensitiveMap(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), "/staticheaders")
}
