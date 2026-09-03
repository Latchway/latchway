package quota

import (
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestQueueAttemptQuotaEntriesPreservesOrderAndZeroAllocations(t *testing.T) {
	t.Parallel()
	reservation := lockedReservation{Reservation: Reservation{
		organizationID: "organization", applicationID: "application", environmentID: "environment",
		logicalRequestID: "request", reservationID: "reservation",
	}}
	entries := []lockedEntry{
		{id: "entry-1", bucketID: "bucket-1", metric: LogicalRequestsMetric},
		{id: "entry-2", bucketID: "bucket-2", metric: OutputTokensMetric},
		{id: "entry-3", bucketID: "bucket-3", metric: CostNanoUSDMetric},
		{id: "entry-4", bucketID: "bucket-4", metric: InputTokensMetric},
	}
	batch := &pgx.Batch{}
	batch.Queue("SELECT 1")
	count := queueAttemptQuotaEntries(batch, reservation, "attempt", entries,
		map[string]int64{InputTokensMetric: 140, OutputTokensMetric: 8, CostNanoUSDMetric: 0})
	if count != 3 || batch.Len() != 4 || batch.QueuedQueries[0].SQL != "SELECT 1" {
		t.Fatalf("allocation queue count=%d length=%d, want 3 after the existing prefix", count, batch.Len())
	}
	for index, expected := range []struct {
		entry lockedEntry
		units int64
	}{{entries[1], 8}, {entries[2], 0}, {entries[3], 140}} {
		queued := batch.QueuedQueries[index+1]
		want := []any{"organization", "application", "environment", "request", "attempt",
			"reservation", expected.entry.id, expected.entry.bucketID, expected.entry.metric, expected.units}
		if queued.SQL != insertAttemptQuotaEntrySQL || !reflect.DeepEqual(queued.Arguments, want) {
			t.Fatalf("allocation %d changed order, attribution or zero-unit presence: %#v", index, queued)
		}
	}
	if count := queueAttemptQuotaEntries(batch, reservation, "attempt", entries, nil); count != 0 || batch.Len() != 4 {
		t.Fatalf("empty allocations changed the existing batch: count=%d length=%d", count, batch.Len())
	}
	if count := queueAttemptQuotaEntries(batch, reservation, "attempt", nil, map[string]int64{OutputTokensMetric: 8}); count != 0 || batch.Len() != 4 {
		t.Fatalf("empty reservation entries changed the existing batch: count=%d length=%d", count, batch.Len())
	}
}
