// Package pricing calculates configured USD charges without floating-point
// arithmetic. All monetary values are integer nano-USD.
package pricing

import (
	"errors"
	"math"
	"math/bits"
	"regexp"
)

const (
	tokensPerMillion = uint64(1_000_000)

	// CurrencyUSD is the only currency accepted by the configuration schema.
	CurrencyUSD = "USD"
	// PricingSourceConfigured identifies a charge calculated from an immutable
	// configured pricing catalog rather than a provider-reported charge.
	PricingSourceConfigured = "configured"
	// CostConfidenceCalculated identifies an exact gateway calculation from
	// provider-reported token counts and configured integer rates.
	CostConfidenceCalculated = "calculated"
)

var (
	// ErrInvalidInput reports a negative numeric value or malformed immutable
	// pricing source. Callers must not treat it as a zero-cost calculation.
	ErrInvalidInput = errors.New("invalid pricing input")
	// ErrOverflow reports a component or final cost that cannot be represented
	// as a nonnegative int64 nano-USD value.
	ErrOverflow = errors.New("pricing cost overflows int64")

	catalogIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	configRevisionPattern = regexp.MustCompile(`^rev_[0-7][0-9A-HJKMNPQRSTVWXYZ]{25}$`)
)

// Rates is one configured pricing entry. Token rates are nano-USD per one
// million tokens; RequestNanoUSD is charged once per upstream request.
type Rates struct {
	InputNanoUSDPerMillion  int64
	OutputNanoUSDPerMillion int64
	RequestNanoUSD          int64
}

// Usage contains trusted, provider-reported token counts for one upstream
// attempt.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
}

// Source identifies the immutable configured catalog and configuration
// revision used for a calculation. Its fields are intentionally private so a
// validated source remains valid when copied between components.
type Source struct {
	catalogID     string
	priceRevision string
}

// NewSource validates source metadata independently from the configuration
// and identifier packages. priceRevision must be the exact rev_ identifier of
// the immutable configuration revision that supplied catalogID.
func NewSource(catalogID, priceRevision string) (Source, error) {
	source := Source{catalogID: catalogID, priceRevision: priceRevision}
	if !source.valid() {
		return Source{}, ErrInvalidInput
	}
	return source, nil
}

// CatalogID returns the configured pricing catalog identifier.
func (source Source) CatalogID() string { return source.catalogID }

// PriceRevision returns the immutable configuration revision identifier.
func (source Source) PriceRevision() string { return source.priceRevision }

func (source Source) valid() bool {
	return catalogIDPattern.MatchString(source.catalogID) &&
		configRevisionPattern.MatchString(source.priceRevision)
}

// Result is an immutable configured charge. Known distinguishes a successful
// zero-cost calculation from the zero value returned alongside an error.
type Result struct {
	source             Source
	requestCostNanoUSD int64
	inputCostNanoUSD   int64
	outputCostNanoUSD  int64
	totalCostNanoUSD   int64
	known              bool
}

// Known reports whether Result was produced by a successful calculation.
func (result Result) Known() bool { return result.known }

// Source returns a value copy of the immutable configured pricing source.
func (result Result) Source() Source { return result.source }

// CatalogID returns the configured pricing catalog identifier.
func (result Result) CatalogID() string { return result.source.CatalogID() }

// PriceRevision returns the immutable configuration revision identifier.
func (result Result) PriceRevision() string { return result.source.PriceRevision() }

// PricingSource reports how the charge was obtained.
func (result Result) PricingSource() string { return PricingSourceConfigured }

// Currency returns the configured pricing currency.
func (result Result) Currency() string { return CurrencyUSD }

// Confidence returns the persistence confidence for this exact calculation.
func (result Result) Confidence() string { return CostConfidenceCalculated }

// RequestCostNanoUSD returns the configured flat request component.
func (result Result) RequestCostNanoUSD() int64 { return result.requestCostNanoUSD }

// InputCostNanoUSD returns the independently rounded input-token component.
func (result Result) InputCostNanoUSD() int64 { return result.inputCostNanoUSD }

// OutputCostNanoUSD returns the independently rounded output-token component.
func (result Result) OutputCostNanoUSD() int64 { return result.outputCostNanoUSD }

// CostNanoUSD returns the complete configured charge.
func (result Result) CostNanoUSD() int64 { return result.totalCostNanoUSD }

// Calculate returns the exact configured charge:
//
//	request fee
//	+ ceil(input tokens * input rate / 1,000,000)
//	+ ceil(output tokens * output rate / 1,000,000)
//
// Input and output components are rounded independently. Calculate uses a
// full-width integer product, so representable results do not fail merely
// because the multiplication would overflow int64.
func Calculate(rates Rates, usage Usage, source Source) (Result, error) {
	if !source.valid() ||
		rates.InputNanoUSDPerMillion < 0 ||
		rates.OutputNanoUSDPerMillion < 0 ||
		rates.RequestNanoUSD < 0 ||
		usage.InputTokens < 0 ||
		usage.OutputTokens < 0 {
		return Result{}, ErrInvalidInput
	}

	inputCost, err := roundedTokenCost(usage.InputTokens, rates.InputNanoUSDPerMillion)
	if err != nil {
		return Result{}, err
	}
	outputCost, err := roundedTokenCost(usage.OutputTokens, rates.OutputNanoUSDPerMillion)
	if err != nil {
		return Result{}, err
	}
	total, ok := checkedAdd(rates.RequestNanoUSD, inputCost)
	if !ok {
		return Result{}, ErrOverflow
	}
	total, ok = checkedAdd(total, outputCost)
	if !ok {
		return Result{}, ErrOverflow
	}

	return Result{
		source:             source,
		requestCostNanoUSD: rates.RequestNanoUSD,
		inputCostNanoUSD:   inputCost,
		outputCostNanoUSD:  outputCost,
		totalCostNanoUSD:   total,
		known:              true,
	}, nil
}

// roundedTokenCost divides an exact 128-bit product by one million. bits.Div64
// requires the high word to be smaller than the divisor; otherwise the
// quotient is wider than uint64 and therefore cannot fit a nonnegative int64.
func roundedTokenCost(tokens, nanoUSDPerMillion int64) (int64, error) {
	if tokens == 0 || nanoUSDPerMillion == 0 {
		return 0, nil
	}
	high, low := bits.Mul64(uint64(tokens), uint64(nanoUSDPerMillion))
	if high >= tokensPerMillion {
		return 0, ErrOverflow
	}
	quotient, remainder := bits.Div64(high, low, tokensPerMillion)
	if remainder != 0 {
		if quotient >= uint64(math.MaxInt64) {
			return 0, ErrOverflow
		}
		quotient++
	}
	if quotient > uint64(math.MaxInt64) {
		return 0, ErrOverflow
	}
	return int64(quotient), nil
}

func checkedAdd(left, right int64) (int64, bool) {
	if left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}
