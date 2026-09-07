package openaichat

import (
	"strings"
	"unicode/utf8"

	"github.com/latchway/latchway/adapters/protocol/internal/schemaaccounting"
)

func trustedToolAccounting(root map[string]any) (int64, int64, error) {
	if err := validateTools(root["tools"]); err != nil {
		return 0, 0, err
	}
	var schemas []any
	names := map[string]bool{}
	if value, present := root["tools"]; present {
		tools, ok := value.([]any)
		if !ok || len(tools) > 128 {
			return 0, 0, requestMalformed("trusted tools must be a bounded array")
		}
		for _, value := range tools {
			tool, ok := value.(map[string]any)
			if !ok || !onlyMembers(tool, "type", "function") || tool["type"] != "function" {
				return 0, 0, requestMalformed("trusted tools support only local function definitions")
			}
			function, ok := tool["function"].(map[string]any)
			if !ok || !onlyMembers(function, "name", "description", "parameters", "strict") {
				return 0, 0, requestMalformed("trusted function definition contains unsupported members")
			}
			name, _ := function["name"].(string) // validateTools checked names and uniqueness.
			names[name] = true
			if value, present := function["description"]; present {
				if text, ok := value.(string); !ok || !localText(text) {
					return 0, 0, requestMalformed("trusted tool descriptions must be local text")
				}
			}
			if value, present := function["strict"]; present {
				if _, ok := value.(bool); !ok {
					return 0, 0, requestMalformed("trusted tool strict must be a boolean")
				}
			}
			if value, present := function["parameters"]; present {
				if _, ok := value.(map[string]any); !ok {
					return 0, 0, requestMalformed("trusted tool parameters must be an object schema")
				}
				if err := validateSchemaScope(value, 0); err != nil {
					return 0, 0, err
				}
				schemas = append(schemas, value)
			}
		}
	}
	if value, present := root["parallel_tool_calls"]; present {
		if _, ok := value.(bool); !ok {
			return 0, 0, requestMalformed("parallel_tool_calls must be a boolean")
		}
	}
	if value, present := root["tool_choice"]; present {
		if choice, ok := value.(string); ok {
			if !slicesContainsString([]string{"auto", "none", "required"}, choice) || choice == "required" && len(names) == 0 {
				return 0, 0, requestMalformed("tool_choice must select an available local function")
			}
		} else {
			choice, ok := value.(map[string]any)
			function, functionOK := choice["function"].(map[string]any)
			name, nameOK := function["name"].(string)
			if !ok || !onlyMembers(choice, "type", "function") || choice["type"] != "function" ||
				!functionOK || !onlyMembers(function, "name") || !nameOK || !names[name] {
				return 0, 0, requestMalformed("tool_choice must name an available local function")
			}
		}
	}
	return schemaaccounting.Count(schemas, int64(len(names)))
}

// The shared counter resolves document-local JSON pointers only. Reject schema
// constructs that change their scope or require a different reference resolver.
func validateSchemaScope(value any, depth int) error {
	if depth > 64 {
		return requestMalformed("trusted schema nesting exceeds its bound")
	}
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if slicesContainsString([]string{"$id", "$anchor", "$dynamicRef", "$dynamicAnchor", "$recursiveRef", "$recursiveAnchor"}, key) {
				return requestMalformed("trusted schemas require document-local JSON pointer references")
			}
			if err := validateSchemaScope(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range node {
			if err := validateSchemaScope(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTrustedToolMessages(messages []any) (int64, error) {
	if err := validateMessages(messages); err != nil {
		return 0, err
	}
	units := int64(len(messages))
	seen := map[string]bool{}
	pending := map[string]bool{}
	for _, value := range messages {
		message := value.(map[string]any) // validated above
		role := message["role"].(string)
		allowed := []string{"role", "content", "name"}
		if role == "assistant" {
			allowed = append(allowed, "tool_calls")
		} else if role == "tool" {
			allowed = append(allowed, "tool_call_id")
		} else if !slicesContainsString([]string{"developer", "system", "user"}, role) {
			return 0, requestMalformed("trusted messages support text and local function-tool roles only")
		}
		if !onlyMembers(message, allowed...) {
			return 0, requestMalformed("trusted message contains unsupported members")
		}
		if name, present := message["name"]; present {
			if text, ok := name.(string); !ok || !validFunctionName(text) {
				return 0, requestMalformed("trusted message names must be bounded identifiers")
			}
		}
		if role == "tool" {
			callID, _ := message["tool_call_id"].(string)
			if !pending[callID] {
				return 0, requestMalformed("tool results must match one pending assistant call")
			}
			delete(pending, callID)
		} else if len(pending) != 0 {
			return 0, requestMalformed("all pending tool results must precede the next message")
		}
		calls, hasCalls := message["tool_calls"]
		if hasCalls {
			items, ok := calls.([]any)
			if !ok || len(items) == 0 || len(items) > 128 {
				return 0, requestMalformed("trusted assistant calls must be a non-empty bounded array")
			}
			for _, value := range items {
				call := value.(map[string]any) // validateMessages checked shapes.
				function, ok := call["function"].(map[string]any)
				if !onlyMembers(call, "id", "type", "function") || call["type"] != "function" ||
					!ok || !onlyMembers(function, "name", "arguments") {
					return 0, requestMalformed("trusted assistant calls support local functions only")
				}
				arguments, _ := function["arguments"].(string)
				if !localText(arguments) {
					return 0, requestMalformed("trusted function arguments must be local UTF-8 text")
				}
				callID := call["id"].(string)
				if seen[callID] {
					return 0, requestMalformed("tool call IDs must be unique in the transcript")
				}
				seen[callID], pending[callID] = true, true
				units++
			}
		}
		content := message["content"]
		if content == nil && role == "assistant" && hasCalls {
			continue
		}
		switch content := content.(type) {
		case string:
			if !localText(content) {
				return 0, requestMalformed("trusted message content must be local UTF-8 text")
			}
		case []any:
			for _, value := range content {
				part, ok := value.(map[string]any)
				text, textOK := part["text"].(string)
				if !ok || !onlyMembers(part, "type", "text") || part["type"] != "text" || !textOK || !localText(text) {
					return 0, requestMalformed("trusted content parts must contain only local text")
				}
				units++
			}
		default:
			return 0, requestMalformed("trusted message content must be local text or an assistant function call")
		}
	}
	if len(pending) != 0 {
		return 0, requestMalformed("all assistant tool calls require matching results before generation")
	}
	if units > 4096 {
		return 0, requestMalformed("trusted message/tool framing exceeds its bound")
	}
	return units, nil
}

func onlyMembers(object map[string]any, names ...string) bool {
	for name := range object {
		if !slicesContainsString(names, name) {
			return false
		}
	}
	return true
}

func localText(text string) bool {
	return utf8.ValidString(text) && !strings.ContainsRune(text, '\x00')
}
