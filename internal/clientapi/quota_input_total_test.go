package clientapi

import (
	"testing"
	"time"
)

func TestFeatureQuotaDocumentAcceptsInputAndTotalTokenMetrics(t *testing.T) {
	t.Parallel()

	for _, metric := range []string{"input_tokens", "total_tokens"} {
		metric := metric
		t.Run(metric, func(t *testing.T) {
			t.Parallel()
			maximum, used, reserved, remaining := int64(100), int64(24), int64(6), int64(70)
			reset := testInstant.Add(time.Hour)
			result := FeatureQuotaResult{
				Feature: "assistant", ObservedAt: testInstant,
				Limits: []FeatureQuotaLimit{{
					Metric: metric, Maximum: &maximum, Used: &used,
					Reserved: &reserved, Remaining: &remaining,
					ResetsAt: &reset, Hard: true,
				}},
			}

			document, err := featureQuotaDocumentFor(result, "assistant")
			if err != nil {
				t.Fatalf("project %s quota: %v", metric, err)
			}
			if len(document.Limits) != 1 {
				t.Fatalf("%s limits = %#v", metric, document.Limits)
			}
			limit := document.Limits[0]
			if limit.Metric != metric || limit.Maximum == nil || *limit.Maximum != maximum ||
				limit.Used == nil || *limit.Used != used ||
				limit.Reserved == nil || *limit.Reserved != reserved ||
				limit.Remaining == nil || *limit.Remaining != remaining ||
				limit.ResetsAt == nil || !limit.ResetsAt.Equal(reset) || !limit.Hard {
				t.Fatalf("%s limit = %#v", metric, limit)
			}
			if limit.Maximum == result.Limits[0].Maximum ||
				limit.Used == result.Limits[0].Used ||
				limit.Reserved == result.Limits[0].Reserved ||
				limit.Remaining == result.Limits[0].Remaining ||
				limit.ResetsAt == result.Limits[0].ResetsAt {
				t.Fatalf("%s projection retained provider pointers", metric)
			}
		})
	}
}
