package dataplane

import (
	"errors"
	"math"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/policy"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
)

// ErrInvalidReservationProjection means the bounded, hypothetical request
// shape cannot produce the same conservative proof required before a real
// dispatch. It is safe for an administrative caller to correct and retry.
var ErrInvalidReservationProjection = errors.New("invalid reservation projection input")

// ReservationProjectionInput is the bounded request shape accepted by the
// administrative simulator. RewrittenRequestBytes and FramingUnitCount model
// the exact values a production adapter proves after rewriting; they are not
// client token estimates and never enter a real reservation.
type ReservationProjectionInput struct {
	RequestedOutputMaximum int64
	RewrittenRequestBytes  int64
	FramingUnitCount       int64
	ImageUnits             int64
	ToolCalls              int64
	Streaming              bool
	EvaluatedAt            time.Time
}

// ReservationProjectionInputAccounting exposes the exact conservative input
// formula selected from the immutable production snapshot.
type ReservationProjectionInputAccounting struct {
	Required                       bool
	ProfileID                      string
	Method                         string
	RewrittenRequestBytes          int64
	FramingUnitCount               int64
	MaximumFramingTokensPerRequest int64
	MaximumFramingTokensPerUnit    int64
	InputTokenBound                int64
	MaximumContextTokens           int64
}

// ReservationProjectionAllocation describes one applicable production limit.
// Durable is false for per-request guards, which are enforced without a quota
// bucket. Applicable is false only for a concurrent-stream rule on a
// non-streaming request.
type ReservationProjectionAllocation struct {
	Metric     string
	Algorithm  string
	Units      int64
	Applicable bool
	Durable    bool
}

// ReservationProjection is a side-effect-free view of the exact conservative
// units production would pass to quota.Store.Reserve for the supplied shape.
type ReservationProjection struct {
	AppliedOutputMaximum int64
	TotalTokenBound      int64
	CostNanoUSDBound     int64
	CostBoundKnown       bool
	PricingCatalog       string
	InputAccounting      ReservationProjectionInputAccounting
	Allocations          []ReservationProjectionAllocation
}

// ProjectReservation validates one selected production decision and computes
// its pre-dispatch units through the same pricing, input-accounting, and unit
// assignment helpers used by Handler.prepareExecutionAttempt. It performs no
// stateful quota operation and no upstream dispatch.
func ProjectReservation(
	snapshot configuration.ActiveSnapshot,
	decision policy.Decision,
	input ReservationProjectionInput,
) (ReservationProjection, error) {
	if input.EvaluatedAt.IsZero() || input.RequestedOutputMaximum < 0 ||
		input.RewrittenRequestBytes < 0 || input.FramingUnitCount < 0 ||
		input.ImageUnits < 0 || input.ToolCalls < 0 {
		return ReservationProjection{}, ErrInvalidReservationProjection
	}
	validated, err := validateDecision(decision.Feature.ID, decision, decision.Feature.Protocol)
	if err != nil {
		return ReservationProjection{}, err
	}
	appliedOutput, ok := projectedOutputMaximum(
		decision.Feature.Protocol, validated, input.RequestedOutputMaximum,
	)
	if !ok {
		return ReservationProjection{}, ErrInvalidReservationProjection
	}
	selectedPricing, err := resolveConfiguredPricing(snapshot, decision.Model, input.EvaluatedAt.UTC())
	if err != nil {
		return ReservationProjection{}, err
	}
	projection := ReservationProjection{
		AppliedOutputMaximum: appliedOutput,
		CostBoundKnown:       false,
		Allocations:          make([]ReservationProjectionAllocation, 0, len(validated.rules)),
	}
	if selectedPricing.configured {
		projection.PricingCatalog = selectedPricing.quotaSelection.CatalogID
	}

	var preflight *protocol.TrustedInputPreflight
	if trustedInputPreflightRequired(validated.rules, selectedPricing) {
		if input.RewrittenRequestBytes <= 0 || input.RewrittenRequestBytes > maximumRequestBodyLimit ||
			input.FramingUnitCount <= 0 || input.FramingUnitCount > 4096 {
			return ReservationProjection{}, ErrInvalidReservationProjection
		}
		profile, profileErr := resolveTrustedInputProfile(snapshot, decision)
		if profileErr != nil {
			return ReservationProjection{}, profileErr
		}
		candidate := protocol.TrustedInputPreflight{
			ProfileID: profile.ID, ProfileDigest: profile.Digest(), Protocol: profile.Protocol,
			Method: profile.Method, PhysicalModel: profile.PhysicalModel,
			RequestBytes: input.RewrittenRequestBytes, MessageCount: input.FramingUnitCount,
			OutputTokenBound: appliedOutput,
		}
		inputBound, boundOK := trustedInputBoundFromProfile(profile, candidate)
		if !boundOK || inputBound > math.MaxInt64-appliedOutput {
			return ReservationProjection{}, ErrInvalidReservationProjection
		}
		candidate.InputTokenBound = inputBound
		candidate.TotalTokenBound = inputBound + appliedOutput
		if err := validateTrustedInputPreflight(profile, decision, appliedOutput, candidate); err != nil {
			return ReservationProjection{}, ErrInvalidReservationProjection
		}
		preflight = &candidate
		projection.TotalTokenBound = candidate.TotalTokenBound
		projection.InputAccounting = ReservationProjectionInputAccounting{
			Required: true, ProfileID: profile.ID, Method: profile.Method,
			RewrittenRequestBytes:          input.RewrittenRequestBytes,
			FramingUnitCount:               input.FramingUnitCount,
			MaximumFramingTokensPerRequest: profile.MaximumFramingTokensPerRequest,
			MaximumFramingTokensPerUnit:    profile.MaximumFramingTokensPerMessage,
			InputTokenBound:                candidate.InputTokenBound,
			MaximumContextTokens:           profile.MaximumContextTokens,
		}
	} else {
		projection.TotalTokenBound = appliedOutput
	}
	var measurements *protocol.RequestMeasurements
	if requestMeasurementsRequired(validated.rules) {
		structured := decision.Feature.Protocol != protocol.OpaqueHTTPID
		candidate := protocol.RequestMeasurements{
			Protocol: decision.Feature.Protocol, RequestBytes: input.RewrittenRequestBytes,
			ImageUnits: input.ImageUnits, ToolCalls: input.ToolCalls,
			ImageUnitsKnown: structured, ToolCallsKnown: structured,
		}
		measurements = &candidate
	}
	if err := assignRequestMeasurementUnits(validated.rules, measurements); err != nil {
		return ReservationProjection{}, ErrInvalidReservationProjection
	}

	costBound, err := assignDecisionReservationUnits(
		validated.rules, selectedPricing, appliedOutput, preflight,
	)
	if err != nil {
		return ReservationProjection{}, err
	}
	projection.CostNanoUSDBound = costBound.nanoUSD
	projection.CostBoundKnown = costBound.active
	for _, rule := range validated.rules {
		units, applicable := quota.ProjectedReservationUnits(rule, input.Streaming)
		projection.Allocations = append(projection.Allocations, ReservationProjectionAllocation{
			Metric: rule.Metric, Algorithm: rule.Algorithm, Units: units,
			Applicable: applicable, Durable: applicable && rule.Algorithm != quota.PerRequestAlgorithm,
		})
	}
	return projection, nil
}

func projectedOutputMaximum(
	protocolID string,
	validated validatedDecision,
	requested int64,
) (int64, bool) {
	if requested < 0 {
		return 0, false
	}
	if !protocolUsesOutputTokens(protocolID) {
		return 0, requested == 0 && validated.defaultOutputTokens == 0 && validated.maximumOutputTokens == 0
	}
	if validated.defaultOutputTokens <= 0 || validated.maximumOutputTokens <= 0 {
		return 0, false
	}
	if requested == 0 {
		return validated.defaultOutputTokens, true
	}
	return min(requested, validated.maximumOutputTokens), true
}
