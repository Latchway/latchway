import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { adminRequest, queryPath, UsageSummarySchema, UsageTimeseriesSchema } from "../../api/admin";
import { useAdminRefreshTopic } from "../../app/use-admin-refresh";
import type { RangeValue } from "../../ui";
import { iso, previousWindow, usageWindow, type UsageWindow } from "./usage-model";

/** Reads the wall clock; called when a period is chosen or new usage is announced, never to render. */
const wallClock = (): number => Date.now();

/** The usage API answered for a different interval than the one asked for. */
class UsageContextMismatch extends Error {}

export function isUsageContextMismatch(error: unknown): boolean {
  return error instanceof UsageContextMismatch;
}

function summaryQuery(environmentID: string, window: UsageWindow, breakdownLimit: string, role: "current" | "previous") {
  return {
    enabled: Boolean(environmentID),
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/usage/summary", {
      breakdown_limit: breakdownLimit, end: iso(window.end), environment_id: environmentID, start: iso(window.start)
    }), UsageSummarySchema)).data,
    queryKey: ["usage-summary", environmentID, window.start, window.end, breakdownLimit, role],
    refetchOnWindowFocus: false,
    staleTime: 60_000
  };
}

function seriesQuery(environmentID: string, window: UsageWindow, role: "current" | "previous") {
  return {
    enabled: Boolean(environmentID),
    queryFn: async () => {
      const series = (await adminRequest(queryPath("/admin/v1/usage/timeseries", {
        end: iso(window.end), environment_id: environmentID, interval: window.interval, start: iso(window.start)
      }), UsageTimeseriesSchema)).data;
      if (series.interval !== window.interval) throw new UsageContextMismatch("usage_interval");
      return series;
    },
    queryKey: ["usage-series", environmentID, window.start, window.end, window.interval, role],
    refetchOnWindowFocus: false,
    staleTime: 60_000
  };
}

interface UsageOptions {
  breakdownLimit: string;
  compare: boolean;
  environmentID: string;
  period: RangeValue;
  /** Overview needs only the summary and timeseries; Analytics also fetches the comparison series. */
  previousSeries?: boolean;
}

/**
 * Usage for a period, and for the same number of buckets just before it when comparing. The clock is read once per
 * period choice and again on each refresh hint, so a preset window moves forward only when new usage arrives.
 */
export function useUsage({ breakdownLimit, compare, environmentID, period, previousSeries = true }: UsageOptions) {
  const periodKey = JSON.stringify(period);
  const [clock, setClock] = useState(() => ({ key: periodKey, now: wallClock() }));
  if (clock.key !== periodKey) setClock({ key: periodKey, now: wallClock() });
  const window = usageWindow(period, clock.now);
  const previous = previousWindow(window);

  const summary = useQuery(summaryQuery(environmentID, window, breakdownLimit, "current"));
  const series = useQuery(seriesQuery(environmentID, window, "current"));
  const previousSummary = useQuery({ ...summaryQuery(environmentID, previous, breakdownLimit, "previous"), enabled: Boolean(environmentID) && compare });
  const previousSeriesQuery = useQuery({ ...seriesQuery(environmentID, previous, "previous"), enabled: Boolean(environmentID) && compare && previousSeries });

  useAdminRefreshTopic("usage", () => {
    if (period.id === "custom") {
      // A fixed period keeps its window; only its numbers can change.
      void summary.refetch();
      void series.refetch();
      return;
    }
    setClock({ key: periodKey, now: wallClock() });
  }, Boolean(environmentID));

  return {
    error: summary.error ?? series.error ?? (compare ? previousSummary.error ?? previousSeriesQuery.error : null),
    isPending: summary.isPending || series.isPending,
    previous: compare ? previousSummary.data : undefined,
    previousSeries: compare && previousSeries ? previousSeriesQuery.data : undefined,
    previousWindow: previous,
    series: series.data,
    summary: summary.data,
    updatedAt: summary.dataUpdatedAt,
    window
  };
}
