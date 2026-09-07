// Package schemaaccounting bounds expansion of local JSON schemas for token preflight.
package schemaaccounting

import (
	"encoding/json"
	"strings"

	"github.com/latchway/latchway/internal/protocol"
)

// Count adds expanded schema bytes and framing units to the exact wire-body
// accounting. All schemas share one bounded budget; references are local only.
func Count(schemas []any, units int64) (int64, int64, error) {
	var bytes int64
	for _, schema := range schemas {
		if err := accountSchema(schema, schema, 0, map[string]bool{}, &bytes, &units); err != nil {
			return 0, 0, err
		}
	}
	return bytes, units, nil
}

func invalid(detail string) error { return &protocol.Error{Code: "request_invalid", Detail: detail} }

func accountSchema(value, root any, depth int, visiting map[string]bool, bytes, units *int64) error {
	if depth > 64 || *bytes > 4*1024*1024 || *units > 100_000 {
		return invalid("trusted schema expansion exceeds its bound")
	}
	switch node := value.(type) {
	case map[string]any:
		*units++
		*bytes += 2
		for key, child := range node {
			encodedKey, _ := json.Marshal(key)
			*bytes += int64(len(encodedKey)) + 2
			if key == "$ref" {
				reference, ok := child.(string)
				if !ok || visiting[reference] {
					return invalid("recursive schemas require a different trusted accounting profile")
				}
				target, ok := resolveSchemaReference(root, reference)
				if !ok {
					return invalid("trusted schemas require resolvable local JSON pointers")
				}
				visiting[reference] = true
				if err := accountSchema(target, root, depth+1, visiting, bytes, units); err != nil {
					return err
				}
				delete(visiting, reference)
			} else if err := accountSchema(child, root, depth+1, visiting, bytes, units); err != nil {
				return err
			}
		}
	case []any:
		*bytes += int64(len(node)) + 2
		for _, child := range node {
			if err := accountSchema(child, root, depth+1, visiting, bytes, units); err != nil {
				return err
			}
		}
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return invalid("schema cannot be accounted")
		}
		*bytes += int64(len(encoded))
	}
	if *bytes > 4*1024*1024 || *units > 100_000 {
		return invalid("trusted schema expansion exceeds its bound")
	}
	return nil
}

func resolveSchemaReference(root any, reference string) (any, bool) {
	if reference == "#" {
		return root, true
	}
	if !strings.HasPrefix(reference, "#/") {
		return nil, false
	}
	value := root
	for _, component := range strings.Split(reference[2:], "/") {
		component = strings.ReplaceAll(strings.ReplaceAll(component, "~1", "/"), "~0", "~")
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok = object[component]
		if !ok {
			return nil, false
		}
	}
	return value, true
}
