package openairesponses

import (
	"encoding/json"
	"strings"

	"github.com/latchway/latchway/adapters/protocol/internal/schemaaccounting"
)

// These are inference controls, not routing, identity, pricing or credentials.
func validateFoundationModelsControls(root map[string]any) error {
	if value, present := root["top_k"]; present {
		number, ok := value.(json.Number)
		if !ok {
			return requestMalformed("top_k must be a positive bounded integer")
		}
		count, err := number.Int64()
		if err != nil || count <= 0 || count > 1_000_000 {
			return requestMalformed("top_k must be a positive bounded integer")
		}
	}
	if value, present := root["metadata"]; present {
		metadata, ok := value.(map[string]any)
		if !ok || len(metadata) > 16 {
			return requestMalformed("metadata must contain at most 16 string pairs")
		}
		for key, value := range metadata {
			text, ok := value.(string)
			if key == "" || len(key) > 64 || strings.ContainsAny(key, "[]\x00") || !ok || len(text) > 512 || strings.ContainsRune(text, '\x00') {
				return requestMalformed("metadata keys and values must be bounded strings")
			}
		}
	}
	if value, present := root["reasoning"]; present {
		reasoning, ok := value.(map[string]any)
		if !ok || !hasOnlyMembers(reasoning, "effort", "summary") {
			return requestMalformed("reasoning configuration is unsupported")
		}
		if value, present := reasoning["effort"]; present {
			effort, ok := value.(string)
			if !ok || !safeIdentifierValue(effort, 64) {
				return requestMalformed("reasoning effort must be a bounded identifier")
			}
		}
		if value, present := reasoning["summary"]; present {
			if value != "auto" && value != "concise" && value != "detailed" {
				return requestMalformed("reasoning summary is unsupported")
			}
		}
	}
	return nil
}

func validateReasoningItem(item map[string]any) error {
	if !hasOnlyMembers(item, "type", "id", "summary", "encrypted_content") {
		return requestMalformed("reasoning item contains unsupported members")
	}
	id, ok := item["id"].(string)
	if !ok || !safeIdentifierValue(id, 256) {
		return requestMalformed("reasoning item requires a bounded ID")
	}
	summary, ok := item["summary"].([]any)
	if !ok || len(summary) > maximumContentParts {
		return requestMalformed("reasoning summary must be a bounded local array")
	}
	for _, value := range summary {
		part, ok := value.(map[string]any)
		text, textOK := part["text"].(string)
		if !ok || !hasOnlyMembers(part, "type", "text") || part["type"] != "summary_text" || !textOK || strings.ContainsRune(text, '\x00') {
			return requestMalformed("reasoning summary must contain local text")
		}
	}
	if value, present := item["encrypted_content"]; present {
		text, ok := value.(string)
		if !ok || len(text) > 1024*1024 || strings.ContainsRune(text, '\x00') {
			return requestMalformed("encrypted reasoning must be bounded text")
		}
	}
	return nil
}

// Account schema expansion in addition to all original request bytes. This
// deliberately over-reserves rather than assuming that a provider tokenizes a
// compact $ref without expansion. Cycles, remote references and excessive
// expansion cannot obtain a trusted byte-BPE bound.
func trustedSchemaAccounting(root map[string]any) (int64, int64, error) {
	var schemas []any
	var units int64
	if tools, ok := root["tools"].([]any); ok {
		units += int64(len(tools))
		for _, value := range tools {
			tool, _ := value.(map[string]any)
			if parameters, present := tool["parameters"]; present {
				schemas = append(schemas, parameters)
			}
		}
	}
	if text, ok := root["text"].(map[string]any); ok {
		if format, ok := text["format"].(map[string]any); ok {
			if schema, present := format["schema"]; present {
				schemas = append(schemas, schema)
			}
		}
	}
	return schemaaccounting.Count(schemas, units)
}
