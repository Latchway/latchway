package quota

// ProjectedReservationUnits returns the exact units that the durable reserve
// path will apply for one validated limit rule. The boolean is false only when
// a rule is inapplicable to the request shape (currently a non-streaming
// request evaluated against concurrent_streams).
//
// The simulator uses this helper to explain a reservation without creating
// quota state; plannedBucketsAt uses the same function before persistence.
func ProjectedReservationUnits(rule Rule, streaming bool) (int64, bool) {
	if rule.Metric == ConcurrentStreamsMetric && !streaming {
		return 0, false
	}
	if rule.Metric == LogicalRequestsMetric || isConcurrencyMetric(rule.Metric) {
		return 1, true
	}
	return rule.ReservedUnits, true
}
