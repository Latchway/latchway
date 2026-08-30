package adminapi

import (
	"math"
	"testing"
)

func TestNewUsageRateUsesExactIntegerPartsPerMillion(t *testing.T) {
	tests := []struct {
		name                   string
		numerator, denominator int64
		want                   int64
	}{
		{name: "zero denominator", numerator: 0, denominator: 0, want: 0},
		{name: "one third floors", numerator: 1, denominator: 3, want: 333_333},
		{name: "complete", numerator: 7, denominator: 7, want: 1_000_000},
		{name: "large avoids multiplication overflow", numerator: 4_611_686_018_427_387_903, denominator: 9_223_372_036_854_775_806, want: 500_000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := newUsageRate(test.numerator, test.denominator)
			if got.Numerator != test.numerator || got.Denominator != test.denominator || got.PartsPerMillion != test.want {
				t.Fatalf("newUsageRate() = %+v, want ppm %d", got, test.want)
			}
		})
	}
}

func TestAddUsageMetricRejectsNegativeUnknownAndOverflowingValues(t *testing.T) {
	values := usageValues{CostNanoUSD: math.MaxInt64 - 1}
	if addUsageMetric(&values, "cost_nano_usd", 2) {
		t.Fatal("overflowing cost aggregation was accepted")
	}
	if values.CostNanoUSD != math.MaxInt64-1 {
		t.Fatalf("overflowing aggregation mutated values: %+v", values)
	}
	if addUsageMetric(&values, "unknown_metric", 1) {
		t.Fatal("unknown usage metric was accepted")
	}
	if addUsageMetric(&values, "logical_requests", -1) {
		t.Fatal("negative usage was accepted")
	}
	if !addUsageMetric(&values, "logical_requests", 1) || values.LogicalRequests != 1 {
		t.Fatalf("valid usage was not added: %+v", values)
	}
}
