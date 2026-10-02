import type { ReactNode } from "react";

export type Severity = "critical" | "warning" | "info";

export interface AttentionItem {
  actionLabel?: string;
  detail?: ReactNode;
  group?: string;
  id: string;
  onAction?: () => void;
  severity: Severity;
  source?: ReactNode;
  title: ReactNode;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, info: 2, warning: 1 };

/** Critical first, then warning, then info; items of equal severity keep their given order. */
export function sortAttention<T extends Pick<AttentionItem, "severity">>(items: readonly T[]): T[] {
  return items
    .map((item, index) => [item, index] as const)
    .sort(([a, ai], [b, bi]) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || ai - bi)
    .map(([item]) => item);
}
