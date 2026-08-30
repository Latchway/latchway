// Package useroverride owns the strict durable representation of a
// server-selected application-user limit-plan override.
package useroverride

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
)

const maximumDocumentBytes = 512

var (
	ErrInvalid        = errors.New("invalid user override")
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

// Document is the complete canonical payload stored in
// user_overrides.override_document. No additional fields are supported.
type Document struct {
	LimitPlan string `json:"limit_plan"`
}

// Decode rejects ambiguous JSON, unknown fields, invalid identifiers, and
// every document shape other than exactly {"limit_plan":"<identifier>"}.
func Decode(encoded []byte) (Document, error) {
	if len(encoded) == 0 || len(encoded) > maximumDocumentBytes {
		return Document{}, ErrInvalid
	}
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return Document{}, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 {
		return Document{}, ErrInvalid
	}
	limitPlan, ok := object["limit_plan"].(string)
	if !ok || !identifierPattern.MatchString(limitPlan) {
		return Document{}, ErrInvalid
	}
	return Document{LimitPlan: limitPlan}, nil
}

// Encode returns the deterministic compact JSON representation of a valid
// document.
func Encode(document Document) ([]byte, error) {
	if !identifierPattern.MatchString(document.LimitPlan) {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Selection is the active durable row identity and its decoded plan. Its zero
// value means that no override applied at the authorization instant.
type Selection struct {
	ID        string
	LimitPlan string
}

// Present reports whether the complete non-zero selection is populated.
func (selection Selection) Present() bool {
	return selection.ID != "" && selection.LimitPlan != ""
}

// Validate enforces the only two representations: the all-zero value or a
// complete valid override ID and limit-plan identifier.
func (selection Selection) Validate() error {
	if selection.ID == "" && selection.LimitPlan == "" {
		return nil
	}
	if id.Validate(selection.ID, id.UserOverride) != nil ||
		!identifierPattern.MatchString(selection.LimitPlan) {
		return ErrInvalid
	}
	return nil
}
