// Package limitmetric owns the closed registry of policy metrics understood by
// the configuration contract. A metric can be registered before this server
// release has a safe enforcement implementation; an empty algorithm set keeps
// that metric schema-visible while activation remains fail-closed.
package limitmetric

import "slices"

const (
	LogicalRequests    = "logical_requests"
	UpstreamAttempts   = "upstream_attempts"
	InputTokens        = "input_tokens"
	OutputTokens       = "output_tokens"
	TotalTokens        = "total_tokens"
	ReasoningTokens    = "reasoning_tokens"
	CachedInputTokens  = "cached_input_tokens"
	CacheWriteTokens   = "cache_write_tokens"
	CostNanoUSD        = "cost_nano_usd"
	ConcurrentRequests = "concurrent_requests"
	ConcurrentStreams  = "concurrent_streams"
	RequestBytes       = "request_bytes"
	ResponseBytes      = "response_bytes"
	ImageUnits         = "image_units"
	AudioSeconds       = "audio_seconds"
	ToolCalls          = "tool_calls"

	CalendarAlgorithm    = "calendar"
	TokenBucketAlgorithm = "token_bucket"
	PerRequestAlgorithm  = "per_request"
	ConcurrencyAlgorithm = "concurrency"
)

// Definition is one immutable policy-metric capability. Algorithms contains
// only enforcement algorithms implemented end to end in this server release.
// Registered metrics with no algorithms are intentionally not enforceable.
type Definition struct {
	Name       string
	Algorithms []string
}

var definitions = []Definition{
	{Name: LogicalRequests, Algorithms: []string{CalendarAlgorithm, TokenBucketAlgorithm}},
	{Name: UpstreamAttempts},
	{Name: InputTokens, Algorithms: []string{CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm}},
	{Name: OutputTokens, Algorithms: []string{CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm}},
	{Name: TotalTokens, Algorithms: []string{CalendarAlgorithm, TokenBucketAlgorithm, PerRequestAlgorithm}},
	{Name: ReasoningTokens},
	{Name: CachedInputTokens},
	{Name: CacheWriteTokens},
	{Name: CostNanoUSD, Algorithms: []string{CalendarAlgorithm}},
	{Name: ConcurrentRequests, Algorithms: []string{ConcurrencyAlgorithm}},
	{Name: ConcurrentStreams, Algorithms: []string{ConcurrencyAlgorithm}},
	{Name: RequestBytes, Algorithms: []string{PerRequestAlgorithm}},
	{Name: ResponseBytes},
	{Name: ImageUnits, Algorithms: []string{PerRequestAlgorithm}},
	{Name: AudioSeconds},
	{Name: ToolCalls, Algorithms: []string{PerRequestAlgorithm}},
}

var definitionsByName = func() map[string]Definition {
	result := make(map[string]Definition, len(definitions))
	for _, definition := range definitions {
		result[definition.Name] = definition
	}
	return result
}()

// Definitions returns the initial metric registry in its stable contract
// order. The returned definitions and algorithm slices are defensive copies.
func Definitions() []Definition {
	result := make([]Definition, len(definitions))
	for index, definition := range definitions {
		result[index] = cloneDefinition(definition)
	}
	return result
}

// Lookup returns a defensive copy of one registered metric definition.
func Lookup(name string) (Definition, bool) {
	definition, ok := definitionsByName[name]
	if !ok {
		return Definition{}, false
	}
	return cloneDefinition(definition), true
}

// SupportsEnforcement reports whether this release implements the complete
// reserve/execute/settle path for the registered metric and algorithm pair.
// Unknown metrics and unsupported algorithms both fail closed.
func SupportsEnforcement(name, algorithm string) bool {
	definition, ok := definitionsByName[name]
	return ok && slices.Contains(definition.Algorithms, algorithm)
}

func cloneDefinition(definition Definition) Definition {
	definition.Algorithms = append([]string(nil), definition.Algorithms...)
	return definition
}
