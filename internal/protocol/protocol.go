// Package protocol defines provider-format inspection independently from
// destination routing and credentials.
package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
)

const (
	// TrustedInputMethodUTF8ByteBPEDeclaredFramingV1 identifies the first
	// conservative input-accounting proof supported by Latchway. It relies on
	// the byte-level property of the configured BPE tokenizer and adds the
	// operator-declared maximum provider framing for the request and messages.
	TrustedInputMethodUTF8ByteBPEDeclaredFramingV1 = "utf8_byte_bpe_declared_framing_v1"

	trustedInputProfileDigestDomain = "latchway/trusted-input-profile/v1\x00"
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
	// EstimatedInputTokens is an untrusted scheduling hint derived before
	// physical-model selection and provider rewriting. It MUST NOT be used for
	// quota, cost, or context-window enforcement.
	EstimatedInputTokens int64
	RequestBytes         int64
}

// TrustedInputProfile is an operator-owned accounting declaration for one
// exact provider protocol and physical model. Framing maxima are non-negative
// token counts; MaximumContextTokens is a positive, model-specific context
// window. Adapters validate the declaration before using it.
type TrustedInputProfile struct {
	ID                             string
	Protocol                       string
	Method                         string
	PhysicalModel                  string
	MaximumFramingTokensPerRequest int64
	MaximumFramingTokensPerMessage int64
	MaximumContextTokens           int64
}

// Digest returns the domain-separated deterministic identity of every field
// in the profile. Callers must only bind a digest after adapter validation.
func (profile TrustedInputProfile) Digest() [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(trustedInputProfileDigestDomain))
	var length [8]byte
	for _, part := range []string{
		profile.ID,
		profile.Protocol,
		profile.Method,
		profile.PhysicalModel,
		strconv.FormatInt(profile.MaximumFramingTokensPerRequest, 10),
		strconv.FormatInt(profile.MaximumFramingTokensPerMessage, 10),
		strconv.FormatInt(profile.MaximumContextTokens, 10),
	} {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(part))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

// TrustedInputPreflight is a conservative, server-trusted token proof over
// the exact rewritten provider body. InputTokenBound is not a tokenizer
// estimate: the adapter has proved that the restricted request shape and its
// exact physical-model profile cannot consume more input tokens than the
// reported value. TotalTokenBound is the checked sum of the input bound and
// the exact server-applied output-token maximum.
type TrustedInputPreflight struct {
	ProfileID           string
	ProfileDigest       [sha256.Size]byte
	Protocol            string
	Method              string
	PhysicalModel       string
	RewrittenBodySHA256 [sha256.Size]byte
	RequestBytes        int64
	MessageCount        int64
	InputTokenBound     int64
	OutputTokenBound    int64
	TotalTokenBound     int64
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
	Streaming             bool
	ModelRewrite          bool
	OutputTokenClamp      bool
	ProviderUsage         bool
	ExactInputPreflight   bool
	TrustedInputPreflight bool
}

// InputPreflighter is an optional adapter capability. It is deliberately
// separate from Adapter so existing protocols can continue accepting their
// richer request shapes when trusted input accounting is not required.
type InputPreflighter interface {
	PreflightInput(context.Context, *http.Request, TrustedInputProfile) (TrustedInputPreflight, error)
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
