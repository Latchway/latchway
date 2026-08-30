package providerverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/latchway/latchway/internal/jsonsafe"
)

// validateProbeResponse proves that a successful verification response is an
// actual one-choice OpenAI Chat completion, not merely a syntactically valid
// usage object. Provider-controlled values never leave this package.
func validateProbeResponse(body []byte, streaming bool) error {
	if streaming {
		return validateStreamingProbeResponse(body)
	}
	value, err := jsonsafe.Decode(body)
	root, ok := value.(map[string]any)
	if err != nil || !ok {
		return errors.New("completion")
	}
	choices, ok := root["choices"].([]any)
	if !ok || len(choices) != 1 {
		return errors.New("completion")
	}
	choice, ok := choices[0].(map[string]any)
	if !ok || !zeroChoiceIndex(choice["index"]) || !nonemptyFinishReason(choice["finish_reason"]) {
		return errors.New("completion")
	}
	message, ok := choice["message"].(map[string]any)
	role, roleOK := message["role"].(string)
	content, contentOK := message["content"].(string)
	if !ok || !roleOK || role != "assistant" || !contentOK || strings.TrimSpace(content) == "" {
		return errors.New("completion")
	}
	return nil
}

func validateStreamingProbeResponse(body []byte) error {
	canonical := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	canonical = bytes.ReplaceAll(canonical, []byte("\r"), []byte("\n"))
	events := bytes.Split(canonical, []byte("\n\n"))
	sawContent := false
	sawFinish := false
	sawDone := false
	for _, event := range events {
		if len(bytes.TrimSpace(event)) == 0 {
			continue
		}
		dataLines := make([][]byte, 0, 1)
		for _, line := range bytes.Split(event, []byte("\n")) {
			if len(line) == 0 || line[0] == ':' {
				continue
			}
			field, value, _ := bytes.Cut(line, []byte(":"))
			if !bytes.Equal(field, []byte("data")) {
				continue
			}
			value = bytes.TrimPrefix(value, []byte(" "))
			dataLines = append(dataLines, value)
		}
		if len(dataLines) == 0 {
			continue
		}
		data := bytes.Join(dataLines, []byte("\n"))
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			if sawDone {
				return errors.New("completion")
			}
			sawDone = true
			continue
		}
		if sawDone {
			return errors.New("completion")
		}
		value, err := jsonsafe.Decode(data)
		root, ok := value.(map[string]any)
		if err != nil || !ok {
			return errors.New("completion")
		}
		choices, ok := root["choices"].([]any)
		if !ok || len(choices) > 1 {
			return errors.New("completion")
		}
		if len(choices) == 0 {
			continue
		}
		choice, ok := choices[0].(map[string]any)
		if !ok || !zeroChoiceIndex(choice["index"]) {
			return errors.New("completion")
		}
		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			return errors.New("completion")
		}
		if contentValue, present := delta["content"]; present && contentValue != nil {
			content, ok := contentValue.(string)
			if !ok {
				return errors.New("completion")
			}
			if content != "" {
				sawContent = true
			}
		}
		if finishValue, present := choice["finish_reason"]; present && finishValue != nil {
			if !nonemptyFinishReason(finishValue) {
				return errors.New("completion")
			}
			sawFinish = true
		}
	}
	if !sawContent || !sawFinish || !sawDone {
		return errors.New("completion")
	}
	return nil
}

func zeroChoiceIndex(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Int64()
	return err == nil && parsed == 0
}

func nonemptyFinishReason(value any) bool {
	text, ok := value.(string)
	return ok && text != "" && len(text) <= 64 && !strings.ContainsAny(text, "\x00\r\n")
}
