package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	maximumConfigurationDocumentDepth = 64
	maximumConfigurationDocumentNodes = 100_000
)

// decodeConfigurationDocument accepts the YAML 1.2 JSON-compatible data model.
// Anchors, aliases, merge keys, custom tags, timestamps, duplicate keys, and
// multiple documents are rejected so importing YAML cannot change the bounded
// semantics of the canonical JSON Admin API document.
func decodeConfigurationDocument(reader io.Reader, maximumBytes int64) (map[string]any, error) {
	if maximumBytes <= 0 {
		return nil, errors.New("positive configuration size limit required")
	}
	input, err := io.ReadAll(io.LimitReader(reader, maximumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration input: %w", err)
	}
	if int64(len(input)) > maximumBytes {
		return nil, errors.New("configuration input exceeds size limit")
	}
	if !utf8.Valid(input) {
		return nil, errors.New("configuration input is not valid UTF-8")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode configuration document: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("configuration input contains multiple YAML documents")
		}
		return nil, fmt.Errorf("decode trailing configuration document: %w", err)
	}
	if len(document.Content) != 1 {
		return nil, errors.New("configuration input must contain exactly one document")
	}

	state := configurationNodeState{}
	value, err := state.convert(document.Content[0], 0)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("configuration YAML or JSON must be an object")
	}
	return object, nil
}

type configurationNodeState struct {
	nodes int
}

func (state *configurationNodeState) convert(node *yaml.Node, depth int) (any, error) {
	if node == nil || depth > maximumConfigurationDocumentDepth {
		return nil, errors.New("configuration input exceeds nesting limit")
	}
	state.nodes++
	if state.nodes > maximumConfigurationDocumentNodes {
		return nil, errors.New("configuration input exceeds structural limit")
	}
	if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, errors.New("configuration input cannot contain YAML anchors or aliases")
	}

	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return nil, errors.New("configuration input contains an invalid mapping")
		}
		object := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" || keyNode.Anchor != "" {
				return nil, errors.New("configuration object keys must be plain strings")
			}
			key := keyNode.Value
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate configuration member %q", key)
			}
			value, err := state.convert(node.Content[index+1], depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		return object, nil
	case yaml.SequenceNode:
		values := make([]any, len(node.Content))
		for index, child := range node.Content {
			value, err := state.convert(child, depth+1)
			if err != nil {
				return nil, err
			}
			values[index] = value
		}
		return values, nil
	case yaml.ScalarNode:
		return configurationScalar(node)
	default:
		return nil, errors.New("configuration input contains an unsupported YAML node")
	}
}

func configurationScalar(node *yaml.Node) (any, error) {
	switch node.Tag {
	case "!!str":
		return node.Value, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		var value bool
		if err := node.Decode(&value); err != nil {
			return nil, errors.New("configuration input contains an invalid boolean")
		}
		return value, nil
	case "!!int":
		var signed int64
		if err := node.Decode(&signed); err == nil {
			return json.Number(strconv.FormatInt(signed, 10)), nil
		}
		var unsigned uint64
		if err := node.Decode(&unsigned); err != nil {
			return nil, errors.New("configuration input contains an out-of-range integer")
		}
		return json.Number(strconv.FormatUint(unsigned, 10)), nil
	case "!!float":
		// Retain the exact decimal token. Converting through float64 would silently
		// round exported quota and retry values and could turn an invalid imported
		// precision into a different, valid configuration.
		value := json.Number(node.Value)
		if _, err := json.Marshal(value); err != nil {
			return nil, errors.New("configuration input contains a non-finite number")
		}
		return value, nil
	default:
		return nil, fmt.Errorf("configuration input contains unsupported YAML tag %q", node.Tag)
	}
}

func encodeConfigurationYAML(document map[string]any) ([]byte, error) {
	node, err := configurationYAMLNode(document)
	if err != nil {
		return nil, err
	}
	root := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{node}}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return nil, fmt.Errorf("encode configuration YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close configuration YAML encoder: %w", err)
	}
	return output.Bytes(), nil
}

func configurationYAMLNode(value any) (*yaml.Node, error) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, key := range keys {
			child, err := configurationYAMLNode(typed[key])
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
		}
		return node, nil
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range typed {
			child, err := configurationYAMLNode(item)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		return node, nil
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: typed}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(typed.String(), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: typed.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(typed)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	default:
		return nil, fmt.Errorf("configuration document contains unsupported value %T", value)
	}
}
