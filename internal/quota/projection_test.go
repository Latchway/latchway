package quota

import "testing"

func TestProjectedReservationUnitsMatchesRequestShape(t *testing.T) {
	tests := []struct {
		name       string
		rule       Rule
		streaming  bool
		wantUnits  int64
		applicable bool
	}{
		{name: "logical request derives one", rule: Rule{Metric: LogicalRequestsMetric, ReservedUnits: 99}, wantUnits: 1, applicable: true},
		{name: "upstream attempt derives one", rule: Rule{Metric: UpstreamAttemptsMetric, ReservedUnits: 99}, wantUnits: 1, applicable: true},
		{name: "concurrent request derives one", rule: Rule{Metric: ConcurrentRequestsMetric}, wantUnits: 1, applicable: true},
		{name: "stream lease applies", rule: Rule{Metric: ConcurrentStreamsMetric}, streaming: true, wantUnits: 1, applicable: true},
		{name: "stream lease omitted for non-stream", rule: Rule{Metric: ConcurrentStreamsMetric}, wantUnits: 0, applicable: false},
		{name: "trusted token units preserved", rule: Rule{Metric: TotalTokensMetric, ReservedUnits: 1234}, wantUnits: 1234, applicable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			units, applicable := ProjectedReservationUnits(test.rule, test.streaming)
			if units != test.wantUnits || applicable != test.applicable {
				t.Fatalf("ProjectedReservationUnits() = (%d, %t), want (%d, %t)", units, applicable, test.wantUnits, test.applicable)
			}
		})
	}
}
