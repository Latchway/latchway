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

	// MaximumMeasuredRequestBytes and MaximumRequestStructuredUnits bound the
	// exact request-measurement proof across adapters, quota, persistence, and
	// administrative projection. They are server limits, never client claims.
	MaximumMeasuredRequestBytes   int64 = 100 << 20
	MaximumRequestStructuredUnits int64 = 1_000_000
	// MaximumPolicyRequestTokens bounds request-derived token context before it
	// enters CEL. The input estimate remains untrusted and this bound does not
	// make it suitable for quota, accounting, pricing, or context enforcement.
	MaximumPolicyRequestTokens int64 = 100_000_000

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
	ClientModel string
	Streaming   bool
	// RequestedOutputLimit is the exact normalized client request value. Zero
	// means omitted (or not applicable for a non-generative protocol). Policy
	// may use it as bounded request context, but the server-owned feature clamp
	// and trusted quota projection remain authoritative.
	RequestedOutputLimit int64
	// EstimatedInputTokens is an untrusted scheduling hint derived before
	// physical-model selection and provider rewriting. Policy may use the
	// bounded value for conservative denial or scheduling, but it MUST NOT be
	// used for quota, accounting, cost, or context-window enforcement.
	EstimatedInputTokens int64
	RequestBytes         int64
}

// TrustedInputProfile is an operator-owned accounting declaration for one
// exact structured provider protocol and physical model. Framing maxima are
// non-negative token counts; the per-message maximum applies to each protocol
// framing unit (message or input item). MaximumContextTokens is a positive,
// model-specific context window. Adapters validate the declaration before use.
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
	// MessageCount is the bounded number of protocol framing units: Chat and
	// Anthropic messages, Responses input items, or Embeddings text inputs.
	// The historical field name is retained in the internal proof contract so
	// existing durable fingerprints remain stable.
	MessageCount int64
	// ExpandedSchemaBytes is additional conservative input accounting for
	// bounded local schema expansion in Responses. It never changes the exact
	// RequestBytes/body digest binding and is zero for other protocols.
	ExpandedSchemaBytes int64
	InputTokenBound     int64
	OutputTokenBound    int64
	TotalTokenBound     int64
}

// RequestMeasurements binds exact request-shape units to the rewritten body
// that will be dispatched. RequestBytes is always exact. ImageUnitsKnown and
// ToolCallsKnown are explicit because an opaque or extensible protocol must
// not turn an unknown structured count into a trusted zero.
type RequestMeasurements struct {
	Protocol            string
	RewrittenBodySHA256 [sha256.Size]byte
	RequestBytes        int64
	ImageUnits          int64
	ToolCalls           int64
	ImageUnitsKnown     bool
	ToolCallsKnown      bool
}

// FeatureDecision contains the server-owned physical request choices.
type FeatureDecision struct {
	PhysicalModel       string
	DefaultOutputTokens int64
	MaximumOutputTokens int64
	OpaqueHTTP          *OpaqueHTTPDecision
}

// OpaqueHTTPDecision is the complete server-owned boundary applied to one
// generic HTTP attempt. ProviderPath is always relative to the selected
// protected target; it can never carry an authority, query, or fragment.
// Exactly one of PathTemplates or compatibility-only PathPrefixes is set.
type OpaqueHTTPDecision struct {
	FeatureID             string
	ProviderPath          string
	AllowedMethods        []string
	PathPrefixes          []string
	PathTemplates         []string
	MaximumBodyBytes      int64
	AllowedRequestHeaders []string
	MaximumResponseBytes  int64
	StreamingAllowed      bool
}

// ProviderReportedCost is an optional monetary measurement extracted from a
// provider's final usage object. Present distinguishes omission from a
// malformed or non-representable value; Known is true only after exact decimal
// conversion to integer nano-USD. Policy decides whether a compatible
// upstream's measurement is trusted for settlement.
type ProviderReportedCost struct {
	NanoUSD int64
	Present bool
	Known   bool
}

// Usage records normalized provider measurements.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
	Known        bool
	Provenance   string
	ReportedCost ProviderReportedCost
}

// ResponseObserver receives bytes exactly as they pass through the proxy.
type ResponseObserver interface {
	Observe(chunk []byte) error
	Finalize() (Usage, error)
}

// FirstTokenObserver is the optional response-observer capability used for
// time-to-first-token telemetry. It becomes true only after protocol parsing
// has observed generated content. Transport lifecycle bytes, usage summaries,
// and other SSE metadata do not satisfy this capability.
type FirstTokenObserver interface {
	ResponseObserver
	FirstTokenObserved() bool
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

// RequestMeasurer is an optional adapter proof over the exact post-rewrite
// request representation. Data-plane activation requires it whenever a hard
// request_bytes, image_units, or tool_calls rule is selected.
type RequestMeasurer interface {
	MeasureRequest(context.Context, *http.Request) (RequestMeasurements, error)
}

// Adapter understands one client/provider wire protocol.
type Adapter interface {
	ID() string
	Match(*http.Request) bool
	InspectRequest(context.Context, *http.Request) (RequestMetadata, error)
	// ApplyFeature returns the exact non-negative output-token maximum written
	// to the provider request. Generative adapters with OutputTokenClamp must
	// return a positive value; non-generative adapters must return zero. Callers
	// use that value, not client metadata, for quota reservation and
	// provider-usage consistency checks.
	ApplyFeature(context.Context, *http.Request, FeatureDecision) (int64, error)
	ObserveResponse(context.Context, *http.Response) (ResponseObserver, error)
	Capabilities() Capabilities
}
