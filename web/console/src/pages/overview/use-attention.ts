import { useQuery } from "@tanstack/react-query";

import { adminRequest, APITokenPageSchema } from "../../api/admin";
import { useSystemHealth } from "../../api/health";
import { healthHistory, OPERATIONS_HISTORY } from "../../api/operations-history";
import { latestConfigurationRevisionQueryOptions } from "../../api/workspace";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import type { AttentionInputs } from "./attention-model";

/** Wall-clock reads happen when a query runs, never while rendering. */
const clock = (): number => Date.now();

/**
 * The server records behind "Needs attention" that don't depend on a usage range: the newest revision, API token
 * expiry, gateway readiness and, when the server keeps them, the latest self-check sample. Overview and the header
 * share these queries.
 */
export function useAttentionSources(environmentID: string): Pick<AttentionInputs, "apiTokens" | "healthSample" | "latestRevisionState" | "readiness"> {
  const { readiness } = useSystemHealth();
  const history = useConsoleCompatibility().status?.server_capabilities.includes(OPERATIONS_HISTORY) ?? false;
  const latestRevision = useQuery({ ...latestConfigurationRevisionQueryOptions(environmentID), enabled: Boolean(environmentID) });
  // Token metadata needs a capability some administrators lack; without it, token expiry simply isn't listed.
  const apiTokens = useQuery({
    queryFn: async () => (await adminRequest("/admin/v1/api-tokens", APITokenPageSchema)).data.items,
    queryKey: ["api-tokens", "overview"],
    retry: false
  });
  const latestSample = useQuery({
    enabled: history,
    queryFn: async () => {
      const end = clock();
      return (await healthHistory(new Date(end - 15 * 60_000).toISOString(), new Date(end).toISOString())).samples.at(-1) ?? null;
    },
    queryKey: ["system", "health-history", "latest"],
    refetchInterval: 5 * 60_000,
    retry: false
  });
  return {
    apiTokens: apiTokens.data,
    healthSample: latestSample.data ?? undefined,
    latestRevisionState: latestRevision.data?.items[0]?.state,
    readiness: readiness.data
  };
}
