import { useEffect, useRef } from "react";

import { subscribeAdminRefreshTopic, type AdminEventTopic } from "../api/admin-events";

export function useAdminRefreshTopic(
  topic: AdminEventTopic,
  refresh: () => void | Promise<void>,
  enabled = true
): void {
  const refreshRef = useRef(refresh);
  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);
  useEffect(() => {
    if (!enabled) return;
    return subscribeAdminRefreshTopic(topic, () => void refreshRef.current());
  }, [enabled, topic]);
}
