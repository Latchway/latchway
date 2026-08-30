// Package requestidentity owns the server-generated identity of an accepted
// HTTP request. It is intentionally separate from client correlation headers
// and from chi's request ID context value.
package requestidentity

import (
	"context"
	"errors"
	"fmt"

	"github.com/latchway/latchway/internal/id"
)

// LogicalID is an opaque, canonical logical-request identifier. Its value can
// only enter a context through NewContext, which generates it on the server.
type LogicalID struct {
	value string
}

// String returns the canonical req_ identifier.
func (identity LogicalID) String() string {
	return identity.value
}

type contextKey struct{}

// NewContext generates a fresh logical-request identity and associates it with
// parent. It never accepts an identity supplied by a caller or request field.
func NewContext(parent context.Context) (context.Context, error) {
	return newContext(parent, func() (string, error) {
		return id.New(id.LogicalRequest)
	})
}

func newContext(parent context.Context, generate func() (string, error)) (context.Context, error) {
	if parent == nil {
		return nil, errors.New("logical request parent context is nil")
	}
	if generate == nil {
		return nil, errors.New("logical request ID generator is nil")
	}
	value, err := generate()
	if err != nil {
		return nil, fmt.Errorf("generate logical request ID: %w", err)
	}
	if err := id.Validate(value, id.LogicalRequest); err != nil {
		return nil, fmt.Errorf("generate logical request ID: %w", err)
	}
	return context.WithValue(parent, contextKey{}, LogicalID{value: value}), nil
}

// FromContext returns the server-generated logical-request identity. A false
// result means request identity middleware did not accept the request.
func FromContext(ctx context.Context) (LogicalID, bool) {
	if ctx == nil {
		return LogicalID{}, false
	}
	identity, ok := ctx.Value(contextKey{}).(LogicalID)
	if !ok || id.Validate(identity.value, id.LogicalRequest) != nil {
		return LogicalID{}, false
	}
	return identity, true
}
