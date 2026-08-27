package pricing_test

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/latchway/latchway/internal/pricing"
)

const validRevision = "rev_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestCalculateCanonicalConfiguredPrice(t *testing.T) {
	t.Parallel()

	source := mustSource(t, "pricing-fast", validRevision)
	result, err := pricing.Calculate(pricing.Rates{
		InputNanoUSDPerMillion:  2_000_000_001,
		OutputNanoUSDPerMillion: 6_000_000_001,
		RequestNanoUSD:          1_234,
	}, pricing.Usage{InputTokens: 11, OutputTokens: 7}, source)
	if err != nil {
		t.Fatalf("Calculate() error = %v", err)
	}
	if !result.Known() {
		t.Fatal("Known() = false, want true")
	}
	if got := result.RequestCostNanoUSD(); got != 1_234 {
		t.Fatalf("RequestCostNanoUSD() = %d, want 1234", got)
	}
	if got := result.InputCostNanoUSD(); got != 22_001 {
		t.Fatalf("InputCostNanoUSD() = %d, want 22001", got)
	}
	if got := result.OutputCostNanoUSD(); got != 42_001 {
		t.Fatalf("OutputCostNanoUSD() = %d, want 42001", got)
	}
	if got := result.CostNanoUSD(); got != 65_236 {
		t.Fatalf("CostNanoUSD() = %d, want 65236", got)
	}
	if got := result.Currency(); got != pricing.CurrencyUSD {
		t.Fatalf("Currency() = %q, want %q", got, pricing.CurrencyUSD)
	}
	if got := result.PricingSource(); got != pricing.PricingSourceConfigured {
		t.Fatalf("PricingSource() = %q, want %q", got, pricing.PricingSourceConfigured)
	}
	if got := result.Confidence(); got != pricing.CostConfidenceCalculated {
		t.Fatalf("Confidence() = %q, want %q", got, pricing.CostConfidenceCalculated)
	}
	if got := result.CatalogID(); got != "pricing-fast" {
		t.Fatalf("CatalogID() = %q, want pricing-fast", got)
	}
	if got := result.PriceRevision(); got != validRevision {
		t.Fatalf("PriceRevision() = %q, want %q", got, validRevision)
	}
	if result.Source() != source {
		t.Fatalf("Source() = %#v, want %#v", result.Source(), source)
	}
}

func TestCalculateZeroCostIsKnown(t *testing.T) {
	t.Parallel()

	result, err := pricing.Calculate(pricing.Rates{}, pricing.Usage{}, mustSource(t, "free", validRevision))
	if err != nil {
		t.Fatalf("Calculate() error = %v", err)
	}
	if !result.Known() {
		t.Fatal("Known() = false, want successful zero cost to remain known")
	}
	if got := result.CostNanoUSD(); got != 0 {
		t.Fatalf("CostNanoUSD() = %d, want 0", got)
	}
	if (pricing.Result{}).Known() {
		t.Fatal("zero-value Result.Known() = true, want false")
	}
}

func TestCalculateRoundsTokenClassesIndependently(t *testing.T) {
	t.Parallel()

	result, err := pricing.Calculate(
		pricing.Rates{InputNanoUSDPerMillion: 1, OutputNanoUSDPerMillion: 1},
		pricing.Usage{InputTokens: 1, OutputTokens: 1},
		mustSource(t, "rounding", validRevision),
	)
	if err != nil {
		t.Fatalf("Calculate() error = %v", err)
	}
	if got := result.InputCostNanoUSD(); got != 1 {
		t.Fatalf("InputCostNanoUSD() = %d, want 1", got)
	}
	if got := result.OutputCostNanoUSD(); got != 1 {
		t.Fatalf("OutputCostNanoUSD() = %d, want 1", got)
	}
	if got := result.CostNanoUSD(); got != 2 {
		t.Fatalf("CostNanoUSD() = %d, want independently rounded total 2", got)
	}
}

func TestCalculateAvoidsIntermediateMultiplicationOverflow(t *testing.T) {
	t.Parallel()

	result, err := pricing.Calculate(
		pricing.Rates{InputNanoUSDPerMillion: 1_000_000},
		pricing.Usage{InputTokens: math.MaxInt64},
		mustSource(t, "maximum", validRevision),
	)
	if err != nil {
		t.Fatalf("Calculate() error = %v", err)
	}
	if got := result.CostNanoUSD(); got != math.MaxInt64 {
		t.Fatalf("CostNanoUSD() = %d, want MaxInt64", got)
	}
}

func TestCalculateRejectsOverflow(t *testing.T) {
	t.Parallel()

	source := mustSource(t, "overflow", validRevision)
	tests := []struct {
		name  string
		rates pricing.Rates
		usage pricing.Usage
	}{
		{
			name:  "component",
			rates: pricing.Rates{InputNanoUSDPerMillion: math.MaxInt64},
			usage: pricing.Usage{InputTokens: math.MaxInt64},
		},
		{
			name:  "final addition",
			rates: pricing.Rates{InputNanoUSDPerMillion: 1_000_000, RequestNanoUSD: 1},
			usage: pricing.Usage{InputTokens: math.MaxInt64},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := pricing.Calculate(test.rates, test.usage, source)
			if !errors.Is(err, pricing.ErrOverflow) {
				t.Fatalf("Calculate() error = %v, want ErrOverflow", err)
			}
			if result.Known() {
				t.Fatal("failed Result.Known() = true, want false")
			}
		})
	}
}

func TestCalculateRejectsNegativeValues(t *testing.T) {
	t.Parallel()

	source := mustSource(t, "invalid", validRevision)
	tests := []struct {
		name  string
		rates pricing.Rates
		usage pricing.Usage
	}{
		{name: "input rate", rates: pricing.Rates{InputNanoUSDPerMillion: -1}},
		{name: "output rate", rates: pricing.Rates{OutputNanoUSDPerMillion: -1}},
		{name: "request fee", rates: pricing.Rates{RequestNanoUSD: -1}},
		{name: "input tokens", usage: pricing.Usage{InputTokens: -1}},
		{name: "output tokens", usage: pricing.Usage{OutputTokens: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := pricing.Calculate(test.rates, test.usage, source)
			if !errors.Is(err, pricing.ErrInvalidInput) {
				t.Fatalf("Calculate() error = %v, want ErrInvalidInput", err)
			}
			if result.Known() {
				t.Fatal("failed Result.Known() = true, want false")
			}
		})
	}
}

func TestNewSourceValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		catalog  string
		revision string
	}{
		{name: "empty catalog", revision: validRevision},
		{name: "uppercase catalog", catalog: "Pricing", revision: validRevision},
		{name: "catalog too long", catalog: "a123456789012345678901234567890123456789012345678901234567890123", revision: validRevision},
		{name: "empty revision", catalog: "pricing"},
		{name: "wrong revision prefix", catalog: "pricing", revision: "cfg_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		{name: "non canonical revision alphabet", catalog: "pricing", revision: "rev_01ARZ3NDEKTSV4RRFFQ69G5FAI"},
		{name: "revision leading digit out of range", catalog: "pricing", revision: "rev_81ARZ3NDEKTSV4RRFFQ69G5FAV"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source, err := pricing.NewSource(test.catalog, test.revision)
			if !errors.Is(err, pricing.ErrInvalidInput) {
				t.Fatalf("NewSource() error = %v, want ErrInvalidInput", err)
			}
			if source.CatalogID() != "" || source.PriceRevision() != "" {
				t.Fatalf("NewSource() = %#v, want zero source", source)
			}
		})
	}
}

func TestCalculateRejectsZeroValueSource(t *testing.T) {
	t.Parallel()

	result, err := pricing.Calculate(pricing.Rates{}, pricing.Usage{}, pricing.Source{})
	if !errors.Is(err, pricing.ErrInvalidInput) {
		t.Fatalf("Calculate() error = %v, want ErrInvalidInput", err)
	}
	if result.Known() {
		t.Fatal("failed Result.Known() = true, want false")
	}
}

func TestCalculateMatchesBigIntegerReference(t *testing.T) {
	t.Parallel()

	source := mustSource(t, "property", validRevision)
	state := uint64(0x6a09e667f3bcc909)
	next := func() int64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return int64(state & math.MaxInt64)
	}

	for iteration := range 5_000 {
		rates := pricing.Rates{}
		usage := pricing.Usage{}
		switch iteration % 4 {
		case 0:
			usage.InputTokens = next()
			usage.OutputTokens = next()
			rates.InputNanoUSDPerMillion = next() % 1_000_001
			rates.OutputNanoUSDPerMillion = next() % 1_000_001
			rates.RequestNanoUSD = next() % 1_000_000
		case 1:
			usage.InputTokens = next() % 1_000_001
			usage.OutputTokens = next() % 1_000_001
			rates.InputNanoUSDPerMillion = next()
			rates.OutputNanoUSDPerMillion = next()
			rates.RequestNanoUSD = next() % 1_000_000
		case 2:
			usage.InputTokens = next() % 1_000_000_001
			usage.OutputTokens = next() % 1_000_000_001
			rates.InputNanoUSDPerMillion = next() % 1_000_000_001
			rates.OutputNanoUSDPerMillion = next() % 1_000_000_001
			rates.RequestNanoUSD = next() % 1_000_000_001
		case 3:
			usage.InputTokens = next()
			usage.OutputTokens = next()
			rates.InputNanoUSDPerMillion = next()
			rates.OutputNanoUSDPerMillion = next()
			rates.RequestNanoUSD = next()
		}

		wantRequest, wantInput, wantOutput, wantTotal, overflow := referenceCalculation(rates, usage)
		result, err := pricing.Calculate(rates, usage, source)
		if overflow {
			if !errors.Is(err, pricing.ErrOverflow) {
				t.Fatalf("iteration %d: Calculate(%+v, %+v) error = %v, want ErrOverflow", iteration, rates, usage, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("iteration %d: Calculate(%+v, %+v) error = %v", iteration, rates, usage, err)
		}
		if !result.Known() ||
			result.RequestCostNanoUSD() != wantRequest ||
			result.InputCostNanoUSD() != wantInput ||
			result.OutputCostNanoUSD() != wantOutput ||
			result.CostNanoUSD() != wantTotal {
			t.Fatalf(
				"iteration %d: result = {known:%t request:%d input:%d output:%d total:%d}, want {known:true request:%d input:%d output:%d total:%d}",
				iteration,
				result.Known(),
				result.RequestCostNanoUSD(),
				result.InputCostNanoUSD(),
				result.OutputCostNanoUSD(),
				result.CostNanoUSD(),
				wantRequest,
				wantInput,
				wantOutput,
				wantTotal,
			)
		}
	}
}

func mustSource(t *testing.T, catalogID, revision string) pricing.Source {
	t.Helper()
	source, err := pricing.NewSource(catalogID, revision)
	if err != nil {
		t.Fatalf("NewSource(%q, %q) error = %v", catalogID, revision, err)
	}
	return source
}

func referenceCalculation(rates pricing.Rates, usage pricing.Usage) (int64, int64, int64, int64, bool) {
	request := big.NewInt(rates.RequestNanoUSD)
	input := roundedBig(usage.InputTokens, rates.InputNanoUSDPerMillion)
	output := roundedBig(usage.OutputTokens, rates.OutputNanoUSDPerMillion)
	total := new(big.Int).Add(new(big.Int).Add(new(big.Int).Set(request), input), output)
	if !request.IsInt64() || !input.IsInt64() || !output.IsInt64() || !total.IsInt64() {
		return 0, 0, 0, 0, true
	}
	return request.Int64(), input.Int64(), output.Int64(), total.Int64(), false
}

func roundedBig(tokens, rate int64) *big.Int {
	product := new(big.Int).Mul(big.NewInt(tokens), big.NewInt(rate))
	product.Add(product, big.NewInt(999_999))
	return product.Div(product, big.NewInt(1_000_000))
}
