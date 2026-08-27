// Package protocol defines provider-format inspection independently from
// destination routing and credentials.
package protocol

import (
	"context"
	"errors"
	"net/http"
)

// Error is a safe protocol failure with a stable registry code.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// IsCode reports whether err has a protocol error code.
func IsCode(err error, code string) bool {
	var protocolErr *Error
	return errors.As(err, &protocolErr) && protocolErr.Code == code
}

// RequestMetadata is the policy-safe interpretation of a client request.
type RequestMetadata struct {
	ClientModel          string
	Streaming            bool
	RequestedOutputLimit int64
	EstimatedInputTokens int64
	RequestBytes         int64
}

// FeatureDecision contains the server-owned physical request choices.
type FeatureDecision struct {
	PhysicalModel       string
	DefaultOutputTokens int64
	MaximumOutputTokens int64
}

// Usage records normalized provider measurements.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
	Known        bool
	Provenance   string
}

// ResponseObserver receives bytes exactly as they pass through the proxy.
type ResponseObserver interface {
	Observe(chunk []byte) error
	Finalize() (Usage, error)
}

// Capabilities describe safe enforcement features.
type Capabilities struct {
	Streaming           bool
	ModelRewrite        bool
	OutputTokenClamp    bool
	ProviderUsage       bool
	ExactInputPreflight bool
}

// Adapter understands one client/provider wire protocol.
type Adapter interface {
	ID() string
	Match(*http.Request) bool
	InspectRequest(context.Context, *http.Request) (RequestMetadata, error)
	// ApplyFeature returns the exact positive output-token maximum written to
	// the provider request. Callers use that value, not client metadata, for
	// quota reservation and provider-usage consistency checks.
	ApplyFeature(context.Context, *http.Request, FeatureDecision) (int64, error)
	ObserveResponse(context.Context, *http.Response) (ResponseObserver, error)
	Capabilities() Capabilities
}
