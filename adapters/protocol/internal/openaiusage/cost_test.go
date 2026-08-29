package openaiusage

import (
	"encoding/json"
	"math"
	"testing"
)

func TestReportedCostDistinguishesMissingInvalidAndExactZero(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		usage   map[string]any
		present bool
		known   bool
		nanoUSD int64
	}{
		{name: "missing", usage: map[string]any{}},
		{name: "null", usage: map[string]any{"cost": nil}, present: true},
		{name: "string", usage: map[string]any{"cost": "0.1"}, present: true},
		{name: "sub nano", usage: map[string]any{"cost": json.Number("0.0000000001")}, present: true},
		{name: "zero", usage: map[string]any{"cost": json.Number("0")}, present: true, known: true},
		{name: "scientific", usage: map[string]any{"cost": json.Number("4.3235e-5")}, present: true, known: true, nanoUSD: 43_235},
		{name: "maximum", usage: map[string]any{"cost": json.Number("9223372036.854775807")}, present: true, known: true, nanoUSD: math.MaxInt64},
		{name: "details are nonauthoritative", usage: map[string]any{"cost_details": map[string]any{"upstream_inference_cost": json.Number("1")}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := ReportedCost(test.usage)
			if got.Present != test.present || got.Known != test.known || got.NanoUSD != test.nanoUSD {
				t.Fatalf("ReportedCost() = %+v", got)
			}
		})
	}
}
